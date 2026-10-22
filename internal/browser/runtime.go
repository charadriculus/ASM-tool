package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/execution"
	"asmtool/internal/platform"
)

var ErrDownloadableResource = errors.New("downloadable resource detected; page navigation skipped")

const (
	readinessTimeout  = 20 * time.Second
	readinessPoll     = 100 * time.Millisecond
	readinessBodyMax  = 64 << 10
	processOutputMax  = 8 << 20
	processOutputTail = 16 << 10
	processLifetime   = 24 * time.Hour
)

// Options describe controller bounds. Scope and authorization retain the
// existing core contract. Enabling this runtime does not make CDP Fetch a
// pre-connect network authorization barrier; candidate31's external-contact
// failure remains a known risk for owner-directed trials.
type Options struct {
	Scope                                                                                core.ScopeChecker
	Profile                                                                              string
	Authorized                                                                           bool
	UserAgent                                                                            string
	CommandTimeout, NavigationTimeout, PollInterval, SettleDelay                         time.Duration
	MaxResultBytes, MaxHTMLBytes, MaxScreenshotBytes, MaxLinks, MaxPages, MaxEvaluations int
	ViewportWidth, ViewportHeight                                                        int
}

func (o Options) validate() error {
	if err := o.Scope.Policy.Validate(); err != nil {
		return err
	}
	if (o.Profile != "verify" && o.Profile != "full") || !o.Authorized {
		return errors.New("browser requires verify/full and explicit authorization")
	}
	if o.CommandTimeout <= 0 || o.CommandTimeout > 20*time.Second || o.NavigationTimeout <= 0 || o.NavigationTimeout > 20*time.Second || o.PollInterval <= 0 || o.PollInterval > o.NavigationTimeout || o.SettleDelay < 0 || o.SettleDelay > o.NavigationTimeout {
		return errors.New("invalid browser time bounds")
	}
	if o.MaxResultBytes <= 0 || o.MaxResultBytes > 32<<20 || o.MaxHTMLBytes <= 0 || o.MaxHTMLBytes > o.MaxResultBytes || o.MaxScreenshotBytes <= 0 || o.MaxScreenshotBytes > 16<<20 || o.MaxScreenshotBytes > o.MaxResultBytes || o.MaxLinks <= 0 || o.MaxLinks > 10000 || o.MaxPages <= 0 || o.MaxPages > 150 || o.MaxEvaluations <= 0 || o.MaxEvaluations > 10000 {
		return errors.New("invalid browser allocation/request bounds")
	}
	if o.ViewportWidth <= 0 || o.ViewportHeight <= 0 || o.ViewportWidth > 4096 || o.ViewportHeight > 4096 {
		return errors.New("invalid browser viewport")
	}
	if len(o.UserAgent) > 512 || strings.ContainsAny(o.UserAgent, "\r\n\x00") {
		return errors.New("invalid browser user agent")
	}
	return nil
}

// Start launches the verified Obscura bundled in bundle, waits for its bounded
// loopback CDP endpoint, and returns the direct-CDP controller. Browser egress
// is not isolated here: CDP Fetch was shown to allow a connection before the
// request-pause event. Callers must keep the existing authorization/scope
// contract and treat this as a known security limitation.
func Start(ctx context.Context, bundle *platform.Bundle, opts Options) (*Browser, error) {
	if ctx == nil {
		return nil, errors.New("nil browser context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	portReservation, port, err := reserveLoopbackPort()
	if err != nil {
		return nil, fmt.Errorf("browser: allocate loopback CDP port: %w", err)
	}
	defer portReservation.Close()
	plan, err := PrepareLaunch(bundle, port, opts.Scope)
	if err != nil {
		return nil, err
	}
	if err := portReservation.Close(); err != nil {
		return nil, fmt.Errorf("browser: release loopback CDP port reservation: %w", err)
	}
	process := startOwnedProcess(ctx, plan)
	startupCtx, cancelStartup := context.WithTimeout(ctx, readinessTimeout)
	endpoint, readyErr := waitForControlEndpoint(startupCtx, port, process.done)
	cancelStartup()
	if readyErr != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return nil, errors.Join(fmt.Errorf("browser: wait for Obscura CDP readiness: %w", readyErr), process.Close(stopCtx))
	}
	transport, err := connectControl(ctx, endpoint, port, opts)
	if err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return nil, errors.Join(fmt.Errorf("browser: connect to Obscura CDP: %w", err), process.Close(stopCtx))
	}
	browser := newBrowser(transport, opts)
	browser.process = process
	return browser, nil
}

// LaunchPlan is a verified, typed command plan. Preparing a plan performs no
// process launch, network access, or resource-policy changes.
type LaunchPlan struct {
	tool platform.Tool
	args []string
	run  func(context.Context, platform.Tool, []string, execution.Options) (execution.Result, error)
}

func PrepareLaunch(bundle *platform.Bundle, port int, scope core.ScopeChecker) (LaunchPlan, error) {
	if port < 1 || port > 65535 {
		return LaunchPlan{}, errors.New("invalid loopback CDP port")
	}
	if err := scope.Policy.Validate(); err != nil {
		return LaunchPlan{}, err
	}
	if bundle == nil {
		return LaunchPlan{}, errors.New("verified Obscura bundle is required")
	}
	tool, err := bundle.Tool("obscura")
	if err != nil {
		return LaunchPlan{}, err
	}
	if tool.Version() != "0.2.2" {
		return LaunchPlan{}, fmt.Errorf("Obscura version pin mismatch: %s", tool.Version())
	}
	if err := tool.Verify(); err != nil {
		return LaunchPlan{}, err
	}
	args := []string{"serve", "--host", "127.0.0.1", "--port", strconv.Itoa(port)}
	for _, raw := range scope.Policy.AllowedCIDRs {
		normalized, normalizeErr := core.NormalizeCIDR(raw)
		if normalizeErr != nil {
			return LaunchPlan{}, fmt.Errorf("invalid allowed CIDR %q: %w", raw, normalizeErr)
		}
		p, parseErr := netip.ParsePrefix(normalized)
		if parseErr != nil {
			return LaunchPlan{}, fmt.Errorf("normalize allowed CIDR %q: %w", raw, parseErr)
		}
		ip := p.Addr()
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			args = append(args, "--allow-private-network")
			break
		}
	}
	if err := execution.ValidateArgs(append([]string{tool.Path()}, args...)); err != nil {
		return LaunchPlan{}, err
	}
	return LaunchPlan{tool: tool, args: args, run: execution.Run}, nil
}

func (p LaunchPlan) Args() []string { return append([]string(nil), p.args...) }

func (p LaunchPlan) Run(ctx context.Context) (execution.Result, error) {
	if ctx == nil {
		return execution.Result{}, errors.New("nil browser context")
	}
	if err := ctx.Err(); err != nil {
		return execution.Result{}, err
	}
	run := p.run
	if run == nil {
		run = execution.Run
	}
	timeout := processLifetime
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return execution.Result{}, context.DeadlineExceeded
	}
	return run(ctx, p.tool, p.args, execution.Options{
		Timeout: timeout, MaxOutputBytes: processOutputMax, TailBytes: processOutputTail,
	})
}

type processOutcome struct {
	result execution.Result
	err    error
}

type ownedProcess struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	out    processOutcome
}

func startOwnedProcess(ctx context.Context, plan LaunchPlan) *ownedProcess {
	processCtx, cancel := context.WithCancel(ctx)
	p := &ownedProcess{cancel: cancel, done: make(chan struct{})}
	go func() {
		result, err := plan.Run(processCtx)
		p.mu.Lock()
		p.out = processOutcome{result: result, err: err}
		p.mu.Unlock()
		close(p.done)
	}()
	return p
}

func (p *ownedProcess) outcome() processOutcome {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out
}

func (p *ownedProcess) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("nil process cleanup context")
	}
	p.cancel()
	select {
	case <-p.done:
		out := p.outcome()
		return withoutContextCancellation(out.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// withoutContextCancellation removes expected supervisor cancellation while
// retaining independent cleanup or process errors joined with it.
func withoutContextCancellation(err error) error {
	if err == nil {
		return nil
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		var retained []error
		for _, child := range many.Unwrap() {
			if child = withoutContextCancellation(child); child != nil {
				retained = append(retained, child)
			}
		}
		return errors.Join(retained...)
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		child := one.Unwrap()
		if child == nil {
			return nil
		}
		retained := withoutContextCancellation(child)
		if retained == nil {
			return nil
		}
		if retained == child {
			return err
		}
		return fmt.Errorf("%s: %w", err.Error(), retained)
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func reserveLoopbackPort() (net.Listener, int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port < 1 || addr.Port > 65535 {
		return nil, 0, errors.Join(errors.New("invalid ephemeral loopback port"), listener.Close())
	}
	return listener, addr.Port, nil
}

func waitForControlEndpoint(ctx context.Context, port int, processDone <-chan struct{}) (string, error) {
	if ctx == nil || port < 1 || port > 65535 || processDone == nil {
		return "", errors.New("invalid browser readiness parameters")
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" {
				return nil, errors.New("unexpected CDP readiness network")
			}
			if addr != address {
				return nil, errors.New("CDP readiness dial escaped the selected loopback port")
			}
			return (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp4", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   750 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ticker := time.NewTicker(readinessPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-processDone:
			return "", errors.New("Obscura process exited before CDP readiness")
		default:
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/json/version", nil)
		if err != nil {
			return "", err
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, readinessBodyMax+1))
			closeErr := response.Body.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return "", err
			}
			if response.StatusCode >= 300 && response.StatusCode < 400 {
				return "", fmt.Errorf("CDP readiness redirected with status %d", response.StatusCode)
			}
			if response.StatusCode == http.StatusOK {
				if len(body) > readinessBodyMax {
					return "", errors.New("CDP readiness response exceeds byte limit")
				}
				var version struct {
					WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
				}
				if err := json.Unmarshal(body, &version); err != nil {
					return "", fmt.Errorf("decode CDP readiness response: %w", err)
				}
				if _, err := validateControlURL(version.WebSocketDebuggerURL, port); err != nil {
					return "", err
				}
				select {
				case <-processDone:
					return "", errors.New("Obscura process exited during CDP readiness")
				default:
				}
				return version.WebSocketDebuggerURL, nil
			}
		} else if ctx.Err() != nil {
			return "", ctx.Err()
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-processDone:
			return "", errors.New("Obscura process exited before CDP readiness")
		case <-ticker.C:
		}
	}
}

// validateControlURL accepts only an uncredentialed WebSocket endpoint on the
// selected literal loopback port. Port release/bind ownership is not atomic.
func validateControlURL(raw string, port int) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || port < 1 || port > 65535 || u.Scheme != "ws" || u.Host != "127.0.0.1:"+strconv.Itoa(port) || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/devtools/browser/") || len(strings.TrimPrefix(u.Path, "/devtools/browser/")) == 0 {
		return nil, errors.New("CDP endpoint must match the selected literal loopback browser endpoint")
	}
	return u, nil
}
