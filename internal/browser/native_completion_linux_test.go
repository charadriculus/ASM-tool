//go:build linux && phase6native

package browser

// Developer-only functional stand. Never included in normal product builds.
// It must be invoked inside the reviewed existing cgroup/namespace harness.
import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/execution"
	"asmtool/internal/platform"
)

func TestNativeCDPCompletion(t *testing.T) {
	// No public runtime bypass exists. The dedicated tag and namespace proof are
	// both necessary; a test binary invoked on the host stops before opening sockets.
	var proof struct {
		Result string          `json:"result"`
		Checks map[string]bool `json:"checks"`
	}
	data, err := os.ReadFile("/poc/sandbox-report.json")
	if err != nil || json.Unmarshal(data, &proof) != nil || proof.Result != "PASS" || len(proof.Checks) != 12 {
		t.Fatal("missing exact namespace preflight")
	}
	for _, pass := range proof.Checks {
		if !pass {
			t.Fatal("namespace preflight failed")
		}
	}
	for _, item := range []struct{ key, name string }{{"USER", "user"}, {"NET", "net"}, {"PID", "pid"}, {"MNT", "mnt"}} {
		observed, err := os.Readlink("/proc/self/ns/" + item.name)
		if err != nil || observed == os.Getenv("PHASE6_HOST_"+item.key+"_NS") || os.Getenv("PHASE6_HOST_"+item.key+"_NS") == "" {
			t.Fatal("host namespace or absent identity")
		}
	}
	// Marker is issued only by the entry after verifying inherited manager policy.
	cg, err := os.ReadFile("/proc/self/cgroup")
	expected := os.Getenv("PHASE6_EXPECTED_CGROUP")
	if err != nil || !strings.HasSuffix(expected, ".service") || !strings.Contains(string(cg), "0::"+expected+"\n") {
		t.Fatal("controller cgroup mismatch")
	}
	bundle, err := platform.NewBundle("/bundle", "7578d993c39a2e68f803dc07a119e82c4186a8307dbde8403fc4d245fa9ed4be")
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Scope: core.ScopeChecker{Policy: core.ScopePolicy{AllowedCIDRs: []string{"127.0.0.1/32"}}}, Profile: "verify", Authorized: true, CommandTimeout: 2 * time.Second, NavigationTimeout: 8 * time.Second, PollInterval: 50 * time.Millisecond, SettleDelay: 200 * time.Millisecond, MaxResultBytes: 8 << 20, MaxHTMLBytes: 1 << 20, MaxScreenshotBytes: 1 << 20, MaxLinks: 20, MaxPages: 2, MaxEvaluations: 300, ViewportWidth: 1440, ViewportHeight: 900}
	const controlPort = 19555
	const fixtureURL = "http://127.0.0.1:19600/page"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var requests atomic.Int64
	listener, err := net.Listen("tcp4", "127.0.0.1:19600")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page" {
			requests.Add(1)
		}
		if r.URL.Path != "/page" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>Русский ✓</title><style>body{margin:0}#long{height:2500px}</style><div id="long">offline</div><a href="/данные">данные</a><script>document.querySelector('#long').dataset.changed='yes';history.replaceState(null,'','/spa');</script>`)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	plan, err := PrepareLaunch(bundle, controlPort, opts.Scope)
	if err != nil {
		t.Fatal(err)
	}
	processCtx, stopProcess := context.WithCancel(ctx)
	type outcome struct {
		result execution.Result
		err    error
	}
	processDone := make(chan outcome, 1)
	go func() {
		r, e := execution.Run(processCtx, plan.tool, plan.args, execution.Options{Timeout: 25 * time.Second, MaxOutputBytes: 1 << 20, TailBytes: 4096})
		processDone <- outcome{r, e}
	}()
	defer func() {
		stopProcess()
		select {
		case result := <-processDone:
			encoded, _ := json.Marshal(map[string]any{"stage": "process_cleanup", "exit_code": result.result.ExitCode, "error": fmt.Sprint(result.err), "timed_out": result.result.TimedOut, "output_limit": result.result.OutputLimitExceeded, "stderr_tail": result.result.Stderr})
			fmt.Println("PHASE6_FUNCTIONAL=" + string(encoded))
			// Cancellation is expected. Outer cgroup capture independently proves the tree.
			if result.result.OutputLimitExceeded {
				t.Error("process output limit")
			}
			if result.result.TimedOut {
				t.Error("browser process timed out")
			}
		case <-time.After(3 * time.Second):
			t.Error("process cleanup did not settle")
		}
	}()
	transportHTTP := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transportHTTP.CloseIdleConnections()
	client := &http.Client{Transport: transportHTTP, Timeout: 500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(8 * time.Second)
	endpoint := ""
	for time.Now().Before(deadline) && ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/json/version", controlPort), nil)
		response, e := client.Do(req)
		if e == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
			response.Body.Close()
			if readErr != nil || len(body) > 64<<10 || response.StatusCode != 200 {
				t.Fatal("malformed readiness response")
			}
			var version struct {
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			if json.Unmarshal(body, &version) != nil {
				t.Fatal("invalid readiness JSON")
			}
			endpoint = version.WebSocketDebuggerURL
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if endpoint == "" {
		t.Fatal("owned browser readiness timeout")
	}
	fmt.Println(`PHASE6_FUNCTIONAL={"stage":"readiness","status":"PASS"}`)
	transport, err := connectControl(ctx, endpoint, controlPort, opts)
	if err != nil {
		t.Fatal(err)
	}
	browser := newBrowser(transport, opts)
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if e := browser.Close(closeCtx); e != nil {
			t.Error(e)
		}
	}()
	page, err := browser.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(`PHASE6_FUNCTIONAL={"stage":"page_create","status":"PASS"}`)
	if err = page.Navigate(ctx, fixtureURL); err != nil {
		t.Fatal(err)
	}
	response, err := page.Response()
	if err != nil || response.Status != 200 || !response.Complete || response.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("document metadata: %+v %v", response, err)
	}
	dom, err := page.DOM(ctx)
	if err != nil || !strings.Contains(dom, `data-changed="yes"`) {
		t.Fatalf("DOM mutation: %v", err)
	}
	title, err := page.Title(ctx)
	if err != nil || title != "Русский ✓" {
		t.Fatalf("Unicode title %q %v", title, err)
	}
	current, err := page.URL(ctx)
	if err != nil || current != "http://127.0.0.1:19600/spa" {
		t.Fatalf("SPA URL %q %v", current, err)
	}
	links, err := page.Links(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("links: %v %v", links, err)
	}
	fmt.Println(`PHASE6_FUNCTIONAL={"stage":"navigation_dom_js_spa_unicode_headers","status":"PASS"}`)
	before := requests.Load()
	image, err := page.Screenshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	file, err := SaveScreenshot(ctx, "/poc", "результат/полный.png", image, opts.MaxScreenshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file.Path)
	if err != nil {
		t.Fatal(err)
	}
	config, err := png.DecodeConfig(f)
	f.Close()
	if err != nil || config.Height <= opts.ViewportHeight || config.Height < 2500 || config.Width != 1440 {
		t.Fatalf("full-page PNG %v %v", config, err)
	}
	if before != requests.Load() || before != 1 {
		t.Fatalf("screenshot revisited page: %d -> %d", before, requests.Load())
	}
	sum := sha256.Sum256(image)
	encoded, _ := json.Marshal(map[string]any{"stage": "full_page_png", "status": "PASS", "width": config.Width, "height": config.Height, "bytes": len(image), "data_base64": base64.StdEncoding.EncodeToString(image), "sha256": hex.EncodeToString(sum[:]), "relative_path": filepath.Base(file.Path), "fixture_requests": requests.Load()})
	fmt.Println("PHASE6_FUNCTIONAL=" + string(encoded))
	if err = page.Close(ctx); err != nil {
		t.Fatal(err)
	}
	fmt.Println(`PHASE6_FUNCTIONAL={"stage":"target_close","status":"PASS","security_candidate31":"FAIL_UNCHANGED"}`)
}
