package http

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/platform"
	"asmtool/internal/version"
	"golang.org/x/net/publicsuffix"
)

const MaxResponseBytes = 2_000_000

var ErrCollection = errors.New("HTTP collection failure")
var ErrEventSink = errors.New("durable HTTP event sink failure")

type Config struct {
	Policy                                                   core.ScopePolicy
	Profile                                                  string
	Authorized                                               bool
	Index                                                    *evidence.DNSRunIndex
	Emit                                                     func(core.Event) error
	UserAgent                                                string
	PerHostRequests, GlobalConcurrency, PerOriginConcurrency int
	GlobalRequestsPerSecond, DelaySeconds                    float64
	StopStatuses                                             []int
	Timeout                                                  time.Duration
	HTTPProbeBackend                                         string
	AllowFallback                                            bool
}
type TLSMode uint8

const (
	VerifiedTLS TLSMode = iota
	SourceProbeUnverifiedTLS
)

type Options struct {
	TLS          TLSMode
	MaxRedirects int
}
type Redirect struct {
	URL      string `json:"url"`
	Status   int    `json:"status_code"`
	Location string `json:"location"`
}
type Response struct {
	RequestedURL       string                     `json:"requested_url"`
	FinalURL           string                     `json:"final_url"`
	StatusCode         int                        `json:"status_code"`
	Headers            map[string]string          `json:"headers"`
	ContentType        string                     `json:"content_type"`
	ContentLength      int64                      `json:"content_length"`
	Location           string                     `json:"location,omitempty"`
	Title              string                     `json:"title"`
	Method             string                     `json:"method"`
	IP                 string                     `json:"ip"`
	Body               []byte                     `json:"-"`
	Text               string                     `json:"-"`
	BodyPreview        string                     `json:"body_preview"`
	BodyTruncated      bool                       `json:"body_truncated"`
	RedirectChain      []Redirect                 `json:"redirect_chain"`
	RedirectOutOfScope bool                       `json:"redirect_out_of_scope"`
	Error              string                     `json:"error,omitempty"`
	ErrorClass         string                     `json:"error_classification,omitempty"`
	TLSVerified        bool                       `json:"tls_verified"`
	TLS                map[string]any             `json:"tls"`
	StopStatus         bool                       `json:"stop_status"`
	BackendResolution  backends.BackendResolution `json:"backend_resolution"`
}
type Client struct {
	c          Config
	backend    backends.BackendResolution
	mu         sync.Mutex
	emitMu     sync.Mutex
	counts     map[string]int
	stopped    map[string]int
	stopStatus map[int]bool
	global     chan struct{}
	origins    map[string]chan struct{}
	nextGlobal time.Time
	nextOrigin map[string]time.Time
	jar        http.CookieJar
}

// BackendResolution returns the immutable constructor decision for run provenance.
func (c *Client) BackendResolution() backends.BackendResolution { return c.backend }

// SetEventSink replaces the durable sink before a pipeline starts sharing this
// client across workers.
func (c *Client) SetEventSink(emit func(core.Event) error) error {
	if emit == nil {
		return errors.New("durable HTTP event sink is required")
	}
	c.emitMu.Lock()
	c.c.Emit = emit
	c.emitMu.Unlock()
	return nil
}

func NewClient(c Config) (*Client, error) {
	if c.Profile != "verify" && c.Profile != "full" || !c.Authorized {
		return nil, errors.New("active HTTP requires verify/full and confirmed authorization")
	}
	if err := c.Policy.Validate(); err != nil {
		return nil, err
	}
	if c.Index == nil {
		return nil, errors.New("confirmed DNS run index is required")
	}
	if c.Emit == nil {
		return nil, errors.New("durable HTTP event sink is required")
	}
	if c.PerHostRequests < 1 || c.GlobalConcurrency < 1 || c.PerOriginConcurrency < 1 || c.Timeout <= 0 || c.GlobalRequestsPerSecond < 0 || c.DelaySeconds < 0 {
		return nil, errors.New("invalid HTTP limits")
	}
	if c.StopStatuses == nil {
		c.StopStatuses = []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests}
	}
	stopStatus := make(map[int]bool, len(c.StopStatuses))
	for _, status := range c.StopStatuses {
		if status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid HTTP stop status: %d", status)
		}
		stopStatus[status] = true
	}
	if c.UserAgent == "" {
		c.UserAgent = version.UserAgent
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("HTTP cookie jar: %w", err)
	}
	backend, resolutionErr := resolveHTTPBackend(c.HTTPProbeBackend, c.AllowFallback)
	client := &Client{c: c, backend: backend, counts: map[string]int{}, stopped: map[string]int{}, stopStatus: stopStatus, global: make(chan struct{}, c.GlobalConcurrency), origins: map[string]chan struct{}{}, nextOrigin: map[string]time.Time{}, jar: jar}
	if backend.Requested == "projectdiscovery_httpx" {
		if err := client.emitBackendLimitation(resolutionErr); err != nil {
			return nil, fmt.Errorf("%w: persist HTTP backend decision: %v", ErrEventSink, err)
		}
	}
	if resolutionErr != nil {
		return nil, resolutionErr
	}
	return client, nil
}

func resolveHTTPBackend(requested string, allowFallback bool) (backends.BackendResolution, error) {
	if requested == "" {
		requested = "go_net_http"
	}
	r := backends.BackendResolution{Category: "http_probe", Requested: requested, Actual: "go_net_http", Status: "available", Available: true, Implementation: "go_net_http", Language: "Go", ExecutionMode: "in_process"}
	switch requested {
	case "go_net_http", "python_requests":
		return r, nil
	case "projectdiscovery_httpx":
		r.PinnedVersion = "1.8.1"
		if err := platform.CheckNativeHTTPX(requested, "1.8.1"); err != nil {
			r.Actual, r.Implementation, r.Language, r.ExecutionMode = "", "", "", ""
			r.Status, r.Available = "blocked", false
			if !allowFallback {
				r.Error = "select backends.fallback_policy: explicit to allow Go HTTP fallback"
				return r, fmt.Errorf("%w: %s", err, r.Error)
			}
			r.Actual, r.Implementation, r.Language, r.ExecutionMode = "go_net_http", "go_net_http", "Go", "in_process"
			r.Status, r.Available = "fallback", true
			r.FallbackUsed = true
			r.FallbackReason = "user_explicit_policy"
			return r, nil
		}
		return r, errors.New("native HTTPX backend policy did not match pinned version")
	default:
		return r, fmt.Errorf("unsupported HTTP probe backend %q", requested)
	}
}

func (c *Client) emitBackendLimitation(cause error) error {
	e, err := core.NewEvent(core.Limitation, "http_probe", "http_backend_policy", c.backend.Requested, c.backend.Actual, core.InScope)
	if err != nil {
		return err
	}
	e.Confidence = 0
	e.Metadata = map[string]any{"terminal": cause != nil, "reason": "native_httpx_blocked", "backend_requested": c.backend.Requested, "backend_actual": c.backend.Actual, "backend_pinned_version": c.backend.PinnedVersion, "fallback_used": c.backend.FallbackUsed, "fallback_reason": c.backend.FallbackReason, "error": c.backend.Error}
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	return c.c.Emit(e)
}

func (c *Client) Fetch(ctx context.Context, raw string, opt Options) (Response, error) {
	if ctx == nil {
		return Response{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if opt.TLS > SourceProbeUnverifiedTLS {
		return Response{}, errors.New("invalid HTTP TLS policy")
	}
	if opt.MaxRedirects < 0 || opt.MaxRedirects > 10 {
		return Response{}, errors.New("redirect limit must be 0..10")
	}
	requested, err := parseURL(raw)
	if err != nil {
		return Response{}, err
	}
	if d := (core.ScopeChecker{Policy: c.c.Policy}).CheckURL(requested.String()); d.Status != core.InScope {
		return Response{}, fmt.Errorf("refusing HTTP request: %s (%s)", d.Status, d.Reason)
	}
	result := Response{RequestedURL: requested.String(), FinalURL: requested.String(), Method: http.MethodGet, RedirectChain: []Redirect{}, TLSVerified: opt.TLS == VerifiedTLS, BackendResolution: c.backend}
	current := requested
	for hop := 0; ; hop++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		ips, err := c.admit(current)
		if err != nil {
			return result, err
		}
		if err = c.acquire(ctx, current); err != nil {
			result.Error = err.Error()
			result.ErrorClass = classify(err)
			if emitErr := c.emit(result); emitErr != nil {
				return result, fmt.Errorf("%w: persist HTTP refusal: %v", ErrEventSink, emitErr)
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return result, fmt.Errorf("%w: %v", ErrCollection, err)
		}
		if status := c.stoppedStatus(current.Hostname()); status != 0 {
			c.release(current)
			c.rollbackQuota(current.Hostname())
			err := fmt.Errorf("HTTP host stopped after status %d", status)
			result.Error, result.ErrorClass = err.Error(), "budget"
			if emitErr := c.emit(result); emitErr != nil {
				return result, fmt.Errorf("%w: persist HTTP refusal: %v", ErrEventSink, emitErr)
			}
			return result, fmt.Errorf("%w: %v", ErrCollection, err)
		}
		resp, ip, fetchErr := c.round(ctx, current, ips, opt.TLS == VerifiedTLS)
		if fetchErr != nil {
			c.release(current)
			result.Error = fetchErr.Error()
			result.ErrorClass = classify(fetchErr)
			if e := c.emit(result); e != nil {
				return result, fmt.Errorf("%w: persist HTTP evidence: %v", ErrEventSink, e)
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return result, fmt.Errorf("%w: %v", ErrCollection, fetchErr)
		}
		if c.stopStatus[resp.StatusCode] {
			result.StopStatus = true
			c.mu.Lock()
			c.stopped[strings.ToLower(current.Hostname())] = resp.StatusCode
			c.mu.Unlock()
		}
		loc := resp.Header.Get("Location")
		if loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.RedirectChain = append(result.RedirectChain, Redirect{current.String(), resp.StatusCode, loc})
		}
		bodyReader, decoders, decodeErr := decodedBody(resp.Body, resp.Header.Get("Content-Encoding"))
		body := []byte{}
		readErr := decodeErr
		if readErr == nil {
			body, readErr = io.ReadAll(io.LimitReader(bodyReader, MaxResponseBytes+1))
		}
		var decoderCloseErr error
		for i := len(decoders) - 1; i >= 0; i-- {
			if e := decoders[i].Close(); decoderCloseErr == nil {
				decoderCloseErr = e
			}
		}
		closeErr := resp.Body.Close()
		if readErr == nil {
			readErr = decoderCloseErr
		}
		result.FinalURL = current.String()
		result.StatusCode = resp.StatusCode
		result.Headers = headerMap(resp.Header)
		result.ContentType = resp.Header.Get("Content-Type")
		result.ContentLength = int64(len(body))
		if n, e := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); e == nil && n >= 0 {
			result.ContentLength = n
		}
		result.Location = loc
		result.IP = ip
		if resp.TLS != nil {
			result.TLS = map[string]any{"version": tls.VersionName(resp.TLS.Version)}
			if len(resp.TLS.PeerCertificates) > 0 {
				result.TLS["issuer"] = resp.TLS.PeerCertificates[0].Issuer.String()
			}
		}
		result.BodyTruncated = len(body) > MaxResponseBytes
		if result.BodyTruncated {
			body = body[:MaxResponseBytes]
		}
		result.Body = body
		displayText := string(body)
		if strings.Contains(strings.ToLower(result.ContentType), "html") {
			if decoded, e := backends.DecodeHTML(body, result.ContentType); e == nil {
				displayText = decoded
			}
		}
		result.Text = displayText
		result.BodyPreview = displayText
		result.BodyPreview = runePrefix(result.BodyPreview, 512)
		if features, e := backends.ParseHTML(displayText); e == nil {
			result.Title = features.Title
		}
		c.release(current)
		if readErr != nil {
			result.Error, result.ErrorClass = readErr.Error(), classify(readErr)
			if e := c.emit(result); e != nil {
				return result, fmt.Errorf("%w: persist partial HTTP evidence: %v", ErrEventSink, e)
			}
			return result, fmt.Errorf("%w: %v", ErrCollection, readErr)
		}
		if closeErr != nil {
			result.Error, result.ErrorClass = closeErr.Error(), classify(closeErr)
			if e := c.emit(result); e != nil {
				return result, fmt.Errorf("%w: persist partial HTTP evidence: %v", ErrEventSink, e)
			}
			return result, fmt.Errorf("%w: %v", ErrCollection, closeErr)
		}
		if loc == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		next, parseErr := current.Parse(loc)
		if parseErr != nil || (next.Scheme != "http" && next.Scheme != "https") || next.User != nil {
			result.RedirectOutOfScope = true
			break
		}
		next.Fragment = ""
		if d := (core.ScopeChecker{Policy: c.c.Policy}).CheckURL(next.String()); d.Status != core.InScope {
			result.RedirectOutOfScope = true
			break
		}
		if _, err := c.admit(next); err != nil {
			result.Error = err.Error()
			result.ErrorClass = "scope"
			result.RedirectOutOfScope = true
			break
		}
		if hop >= opt.MaxRedirects {
			break
		}
		current = next
	}
	if err := c.emit(result); err != nil {
		return result, fmt.Errorf("%w: persist HTTP evidence: %v", ErrEventSink, err)
	}
	return result, nil
}

func parseURL(raw string) (*url.URL, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("invalid HTTP URL")
	}
	u, e := url.Parse(raw)
	if e != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("HTTP target must be an absolute http(s) URL without userinfo")
	}
	if u.Fragment != "" {
		u.Fragment = ""
	}
	if _, e = port(u); e != nil {
		return nil, e
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if net.ParseIP(host) == nil {
		host, e = core.NormalizeDomain(host)
		if e != nil {
			return nil, e
		}
	}
	if host == "" {
		return nil, errors.New("empty HTTP hostname")
	}
	u.Host = hostPort(host, u)
	return u, nil
}
func port(u *url.URL) (string, error) {
	p := u.Port()
	if p == "" {
		if u.Scheme == "https" {
			return "443", nil
		}
		return "80", nil
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return "", errors.New("invalid URL port")
		}
	}
	var n int
	_, e := fmt.Sscan(p, &n)
	if e != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid URL port")
	}
	return p, nil
}
func hostPort(host string, u *url.URL) string {
	p := u.Port()
	if p != "" {
		return net.JoinHostPort(host, p)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + map[bool]string{true: "443", false: "80"}[u.Scheme == "https"]
	}
	return host
}
func (c *Client) admit(u *url.URL) ([]netip.Addr, error) {
	scope := core.ScopeChecker{Policy: c.c.Policy}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	stopStatus := c.stoppedStatus(host)
	if stopStatus != 0 {
		return nil, fmt.Errorf("HTTP host stopped after status %d", stopStatus)
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ip = ip.Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("unspecified and multicast IP targets are never allowed")
		}
		d := scope.CheckIP(ip.String())
		if d.Status != core.InScope {
			return nil, fmt.Errorf("IP target is not authorized: %s", d.Status)
		}
		ips = []netip.Addr{ip}
	} else {
		normalized, err := core.NormalizeDomain(host)
		if err != nil {
			return nil, err
		}
		host = normalized
		if d := scope.CheckDomain(host); d.Status != core.InScope {
			return nil, fmt.Errorf("domain target is not authorized: %s", d.Status)
		}
		v := c.c.Index.ExistingValidation(host)
		if v == nil || !eligibleToken(v["active_eligibility"]) {
			return nil, errors.New("HTTP target lacks eligible confirmed DNS validation")
		}
		ips = terminalIPs(v["terminal_ips"])
		if len(ips) == 0 {
			return nil, errors.New("HTTP target has no confirmed terminal IPs")
		}
	}
	allowed := ips[:0]
	for _, ip := range ips {
		if excluded(ip, c.c.Policy.ExcludedCIDRs) {
			continue
		}
		if !ip.IsUnspecified() && !ip.IsMulticast() && (!specialAddress(ip) || inside(ip, c.c.Policy.AllowedCIDRs)) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("confirmed DNS addresses are excluded or require an explicit allowed CIDR")
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i].Less(allowed[j]) })
	return allowed, nil
}
func (c *Client) stoppedStatus(host string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped[strings.TrimSuffix(strings.ToLower(host), ".")]
}
func (c *Client) rollbackQuota(host string) {
	c.mu.Lock()
	c.counts[strings.ToLower(host)]--
	c.mu.Unlock()
}
func terminalIPs(v any) []netip.Addr {
	var out []netip.Addr
	switch a := v.(type) {
	case []string:
		for _, s := range a {
			if ip, e := netip.ParseAddr(s); e == nil {
				if ip.Zone() == "" {
					out = append(out, ip.Unmap())
				}
			}
		}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				if ip, e := netip.ParseAddr(s); e == nil {
					if ip.Zone() == "" {
						out = append(out, ip.Unmap())
					}
				}
			}
		}
	}
	return out
}
func inside(ip netip.Addr, cs []string) bool {
	for _, s := range cs {
		if p, e := netip.ParsePrefix(s); e == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
func excluded(ip netip.Addr, cs []string) bool { return inside(ip, cs) }
func eligibleToken(v any) bool {
	s, ok := v.(string)
	return ok && (s == "eligible" || s == "eligible_override")
}
func specialAddress(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		p, _ := netip.ParsePrefix(s)
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Client) acquire(ctx context.Context, u *url.URL) error {
	origin, host := originKey(u), strings.ToLower(u.Hostname())
	c.mu.Lock()
	sem := c.origins[origin]
	if sem == nil {
		sem = make(chan struct{}, c.c.PerOriginConcurrency)
		c.origins[origin] = sem
	}
	c.counts[host]++
	if c.counts[host] > c.c.PerHostRequests {
		c.counts[host]--
		c.mu.Unlock()
		return fmt.Errorf("HTTP per-host request quota exhausted: %s", host)
	}
	c.mu.Unlock()
	rollback := func() { c.mu.Lock(); c.counts[host]--; c.mu.Unlock() }
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		rollback()
		return ctx.Err()
	}
	select {
	case c.global <- struct{}{}:
	case <-ctx.Done():
		<-sem
		rollback()
		return ctx.Err()
	}
	if err := c.waitRate(ctx, origin); err != nil {
		<-sem
		<-c.global
		rollback()
		return err
	}
	return nil
}
func (c *Client) release(u *url.URL) {
	origin := originKey(u)
	c.mu.Lock()
	sem := c.origins[origin]
	c.mu.Unlock()
	<-sem
	<-c.global
}
func (c *Client) waitRate(ctx context.Context, origin string) error {
	for {
		c.mu.Lock()
		now := time.Now()
		wait := time.Duration(0)
		step := time.Duration(c.c.DelaySeconds * float64(time.Second))
		if c.c.GlobalRequestsPerSecond > 0 {
			r := time.Duration(float64(time.Second) / c.c.GlobalRequestsPerSecond)
			if r > step {
				step = r
			}
		}
		at := c.nextGlobal
		if x := c.nextOrigin[origin]; x.After(at) {
			at = x
		}
		if at.After(now) {
			wait = at.Sub(now)
		} else {
			next := now.Add(step)
			c.nextGlobal = next
			c.nextOrigin[origin] = next
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
func (c *Client) round(ctx context.Context, u *url.URL, ips []netip.Addr, verify bool) (*http.Response, string, error) {
	if len(ips) == 0 {
		return nil, "", errors.New("no admitted terminal IP")
	}
	// One admission selects one deterministic address. Failures consume quota;
	// silently trying another address would multiply contact per admission.
	for _, ip := range ips[:1] {
		hostport := net.JoinHostPort(ip.String(), mustPort(u))
		// Unverified TLS is reachable only through the explicit source-probe mode; zero-value options verify certificates.
		tr := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: c.c.Timeout}
			return d.DialContext(ctx, network, hostport)
		}}
		client := &http.Client{Transport: tr, Timeout: c.c.Timeout, Jar: c.jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if e != nil {
			return nil, "", e
		}
		req.Header.Set("User-Agent", c.c.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		resp, e := client.Do(req)
		tr.CloseIdleConnections()
		if e == nil {
			return resp, ip.String(), nil
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		return nil, "", e
	}
	return nil, "", errors.New("no admitted terminal IP")
}

func decodedBody(body io.Reader, header string) (io.Reader, []io.Closer, error) {
	reader := body
	var closers []io.Closer
	encodings := strings.Split(strings.ToLower(strings.TrimSpace(header)), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		switch strings.TrimSpace(encodings[i]) {
		case "", "identity":
		case "gzip", "x-gzip":
			decoder, err := gzip.NewReader(reader)
			if err != nil {
				return reader, closers, err
			}
			reader = decoder
			closers = append(closers, decoder)
		case "deflate":
			buffered := bufio.NewReader(reader)
			prefix, err := buffered.Peek(2)
			if err != nil {
				return reader, closers, err
			}
			var decoder io.ReadCloser
			if prefix[0]&0x0f == 8 && (int(prefix[0])<<8|int(prefix[1]))%31 == 0 {
				decoder, err = zlib.NewReader(buffered)
			} else {
				decoder = flate.NewReader(buffered)
			}
			if err != nil {
				return reader, closers, err
			}
			reader = decoder
			closers = append(closers, decoder)
		default:
			return reader, closers, fmt.Errorf("unsupported HTTP content encoding %q", strings.TrimSpace(encodings[i]))
		}
	}
	return reader, closers, nil
}
func mustPort(u *url.URL) string { p, _ := port(u); return p }
func originKey(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + net.JoinHostPort(u.Hostname(), mustPort(u)))
}
func headerMap(h http.Header) map[string]string {
	m := map[string]string{}
	for k, v := range h {
		m[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return m
}
func runePrefix(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}
func classify(e error) string {
	s := strings.ToLower(e.Error())
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out"):
		return "timeout"
	case strings.Contains(s, "certificate") || strings.Contains(s, "tls"):
		return "tls"
	case strings.Contains(s, "refused"):
		return "connection_refused"
	case strings.Contains(s, "reset"):
		return "connection_reset"
	case strings.Contains(s, "no such host") || strings.Contains(s, "lookup ") || strings.Contains(s, "name resolution"):
		return "dns"
	case strings.Contains(s, "quota"):
		return "budget"
	default:
		return "other"
	}
}
func (c *Client) emit(r Response) error {
	e, err := core.NewEvent(core.HTTPProbeResult, "http_probe", "go_net_http", r.RequestedURL, r.FinalURL, core.InScope)
	if err != nil {
		return err
	}
	var statusCode, contentLength any
	if r.StatusCode != 0 {
		statusCode = r.StatusCode
		contentLength = r.ContentLength
	}
	tlsInfo := r.TLS
	if tlsInfo == nil {
		tlsInfo = map[string]any{}
	}
	headers := make(map[string]string, len(r.Headers))
	for name, value := range r.Headers {
		headers[name] = core.RedactText(value)
	}
	e.Metadata = map[string]any{"status_code": statusCode, "headers": headers, "content_type": r.ContentType, "content_length": contentLength, "location": r.Location, "title": core.RedactText(r.Title), "method": r.Method, "ip": r.IP, "body_preview": core.RedactText(r.BodyPreview), "body_truncated": r.BodyTruncated, "redirect_chain": r.RedirectChain, "redirect_out_of_scope": r.RedirectOutOfScope, "error": r.Error, "error_classification": r.ErrorClass, "transport": "confirmed_terminal_ip_pinned", "tls_verified": r.TLSVerified, "tls": tlsInfo, "technologies": []string{}, "backend_requested": c.backend.Requested, "backend_actual": c.backend.Actual, "backend_pinned_version": c.backend.PinnedVersion, "fallback_used": c.backend.FallbackUsed, "fallback_reason": c.backend.FallbackReason}
	if r.StatusCode != 0 {
		e.Confidence = 0.75
	} else {
		e.Confidence = 0.2
	}
	if r.StopStatus {
		e.Metadata["stop_status"] = true
	}
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	return c.c.Emit(e)
}
