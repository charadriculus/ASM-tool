package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/platform"
)

func adapterOptions() Options {
	return Options{Scope: core.ScopeChecker{Policy: core.ScopePolicy{AllowedDomains: []string{"example.test"}}}, Profile: "verify", Authorized: true, CommandTimeout: 100 * time.Millisecond, NavigationTimeout: 200 * time.Millisecond, PollInterval: time.Millisecond, MaxResultBytes: 1 << 20, MaxHTMLBytes: 1 << 16, MaxScreenshotBytes: 1 << 16, MaxLinks: 10, MaxPages: 4, MaxEvaluations: 100, ViewportWidth: 1440, ViewportHeight: 900}
}

type fakeCDP struct {
	mu      sync.Mutex
	methods []string
	handler func(context.Context, string, any) (any, error)
	next    int
}

func (f *fakeCDP) Call(ctx context.Context, session, method string, params any) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.methods = append(f.methods, method)
	handler := f.handler
	var result any = map[string]any{}
	switch method {
	case "Target.createTarget":
		f.next++
		result = map[string]any{"targetId": string(rune('a' + f.next))}
	case "Target.attachToTarget":
		result = map[string]any{"sessionId": "session"}
	case "Target.closeTarget":
		result = map[string]any{"success": true}
	}
	f.mu.Unlock()
	if handler != nil {
		v, e := handler(ctx, method, params)
		if e != nil {
			return nil, e
		}
		if v != nil {
			result = v
		}
	}
	return json.Marshal(result)
}
func (f *fakeCDP) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.methods {
		if m == method {
			n++
		}
	}
	return n
}
func value(v any) any { return map[string]any{"result": map[string]any{"type": "object", "value": v}} }
func fixturePNG() []byte {
	var b bytes.Buffer
	_ = png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 2, 3)))
	return b.Bytes()
}
func loadedClient() *fakeCDP {
	return &fakeCDP{handler: func(ctx context.Context, m string, p any) (any, error) {
		switch m {
		case "Runtime.evaluate":
			e := p.(map[string]any)["expression"].(string)
			switch {
			case strings.Contains(e, "readyState"):
				return value(map[string]any{"state": "complete", "url": "https://example.test/start"}), nil
			case strings.Contains(e, "outerHTML"):
				return value(map[string]any{"url": "https://example.test/start", "html": `<html><title>Русский 😀</title><a href="/данные">one</a><a href="/данные#x">dup</a><a href="https://evil.test/">bad</a><a href="https://sub.example.test/">other-origin</a><a href="javascript:alert(1)">script</a></html>`}), nil
			case strings.Contains(e, "document.title"):
				return value(map[string]any{"url": "https://example.test/start", "title": "Русский 😀"}), nil
			case e == "location.href":
				return value("https://example.test/start"), nil
			default:
				return value(map[string]any{"unicode": "✓"}), nil
			}
		case "Page.getLayoutMetrics":
			return map[string]any{"contentSize": map[string]any{"width": 2, "height": 3}}, nil
		case "Page.captureScreenshot":
			return map[string]any{"data": base64.StdEncoding.EncodeToString(fixturePNG())}, nil
		}
		return nil, nil
	}}
}
func pageFor(t *testing.T, f *fakeCDP, opts Options) (*Browser, *Page) {
	t.Helper()
	b := newBrowser(f, opts)
	p, e := b.NewPage(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = b.Close(context.Background()) })
	return b, p
}

func TestAdapterFunctionalOffline(t *testing.T) {
	f := loadedClient()
	_, p := pageFor(t, f, adapterOptions())
	ctx := context.Background()
	if e := p.Navigate(ctx, "https://example.test/start"); e != nil {
		t.Fatal(e)
	}
	title, e := p.Title(ctx)
	if e != nil || title != "Русский 😀" {
		t.Fatalf("title %q %v", title, e)
	}
	dom, e := p.DOM(ctx)
	if e != nil || !strings.Contains(dom, "Русский") {
		t.Fatalf("dom %q %v", dom, e)
	}
	links, e := p.Links(ctx)
	if e != nil || !reflect.DeepEqual(links, []string{"https://example.test/%D0%B4%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5"}) {
		t.Fatalf("links %#v %v", links, e)
	}
	screenshot, e := p.Screenshot(ctx)
	if e != nil || !bytes.Equal(screenshot, fixturePNG()) {
		t.Fatalf("PNG %v", e)
	}
	if f.count("Page.navigate") != 1 {
		t.Fatal("screenshot revisited page")
	}
	if _, e = p.Evaluate(ctx, "1+1"); e != nil {
		t.Fatal(e)
	}
	if e = p.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if f.count("Target.closeTarget") != 1 {
		t.Fatal("target cleanup")
	}
	for _, method := range []string{"Page.close", "Page.stopLoading", "Browser.close", "Runtime.callFunctionOn", "Fetch.enable"} {
		if f.count(method) != 0 {
			t.Fatalf("unsupported/security-claim command %s", method)
		}
	}
}
func TestAdapterScopeAndDownloadBeforeNavigate(t *testing.T) {
	for _, raw := range []string{"https://evil.test/", "file:///etc/passwd", "https://user:pass@example.test/", "https://example.test/file.pdf"} {
		t.Run(raw, func(t *testing.T) {
			f := loadedClient()
			_, p := pageFor(t, f, adapterOptions())
			if e := p.Navigate(context.Background(), raw); e == nil {
				t.Fatal("accepted")
			}
			if f.count("Page.navigate") != 0 {
				t.Fatal("contact preceded rejection")
			}
		})
	}
}
func TestAdapterOptionsFailClosed(t *testing.T) {
	for _, change := range []func(*Options){func(o *Options) { o.Authorized = false }, func(o *Options) { o.Profile = "passive" }, func(o *Options) { o.MaxPages = 0 }, func(o *Options) { o.MaxResultBytes = 33 << 20 }, func(o *Options) { o.CommandTimeout = 0 }, func(o *Options) { o.UserAgent = "x\r\ny" }} {
		o := adapterOptions()
		change(&o)
		if _, e := Start(context.Background(), nil, o); e == nil {
			t.Fatal("invalid options accepted")
		}
	}
	if _, e := Start(context.Background(), nil, adapterOptions()); e == nil || strings.Contains(e.Error(), "security blocked") {
		t.Fatalf("missing verified payload was not reported directly: %v", e)
	}
	if _, e := (LaunchPlan{}).Run(context.Background()); e == nil || strings.Contains(e.Error(), "security blocked") {
		t.Fatalf("invalid launch plan was not rejected: %v", e)
	}
	if _, e := PrepareLaunch(nil, 9222, adapterOptions().Scope); e == nil {
		t.Fatal("unverified bundle accepted")
	}
}
func TestAdapterRedirectFailureIsExplicit(t *testing.T) {
	for _, dest := range []string{"https://evil.test/", "https://sub.example.test/"} {
		f := loadedClient()
		old := f.handler
		f.handler = func(ctx context.Context, m string, p any) (any, error) {
			if m == "Runtime.evaluate" {
				return value(map[string]any{"state": "complete", "url": dest}), nil
			}
			return old(ctx, m, p)
		}
		_, p := pageFor(t, f, adapterOptions())
		e := p.Navigate(context.Background(), "https://example.test/start")
		if e == nil || !strings.Contains(e.Error(), "may already have reached") {
			t.Fatal(e)
		}
	}
}
func TestAdapterJavaScriptErrorsAndLimits(t *testing.T) {
	for name, result := range map[string]any{"exception": map[string]any{"exceptionDetails": map[string]any{"text": "boom"}}, "missing": map[string]any{"result": map[string]any{"type": "undefined"}}, "oversized": value(strings.Repeat("x", 1<<20))} {
		t.Run(name, func(t *testing.T) {
			f := loadedClient()
			_, p := pageFor(t, f, adapterOptions())
			if err := p.Navigate(context.Background(), "https://example.test/start"); err != nil {
				t.Fatal(err)
			}
			f.handler = func(ctx context.Context, m string, p any) (any, error) {
				if m == "Runtime.evaluate" {
					return result, nil
				}
				return nil, nil
			}
			if _, err := p.Evaluate(context.Background(), "x"); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
	o := adapterOptions()
	o.MaxEvaluations = 3
	f := loadedClient()
	_, p := pageFor(t, f, o)
	if err := p.Navigate(context.Background(), "https://example.test/start"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Evaluate(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Evaluate(context.Background(), "x"); err == nil {
		t.Fatal("quota ignored")
	}
	if f.count("Runtime.evaluate") != 3 {
		t.Fatal("quota contacted CDP")
	}
}
func TestAdapterCancellationClosesTarget(t *testing.T) {
	f := loadedClient()
	old := f.handler
	started := make(chan struct{})
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Page.navigate" {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return old(ctx, m, p)
	}
	_, p := pageFor(t, f, adapterOptions())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Navigate(ctx, "https://example.test/start") }()
	<-started
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation hung")
	}
	if f.count("Target.closeTarget") != 1 {
		t.Fatal("cancel omitted target closure")
	}
}
func TestAdapterPageQuotaAndSetupCleanup(t *testing.T) {
	o := adapterOptions()
	o.MaxPages = 1
	f := loadedClient()
	b, p := pageFor(t, f, o)
	_ = p.Close(context.Background())
	if _, e := b.NewPage(context.Background()); e == nil {
		t.Fatal("run-wide quota reset")
	}
	f = &fakeCDP{handler: func(ctx context.Context, m string, p any) (any, error) {
		if m == "Page.enable" {
			return nil, errors.New("enable failed")
		}
		if m == "Target.closeTarget" {
			return nil, errors.New("cleanup failed")
		}
		return nil, nil
	}}
	b = newBrowser(f, adapterOptions())
	if _, e := b.NewPage(context.Background()); e == nil || !strings.Contains(e.Error(), "cleanup failed") {
		t.Fatal(e)
	}
}
func TestAdapterScreenshotErrors(t *testing.T) {
	for _, mode := range []string{"metrics", "encoding", "dimensions", "protocol"} {
		t.Run(mode, func(t *testing.T) {
			f := loadedClient()
			old := f.handler
			f.handler = func(ctx context.Context, m string, p any) (any, error) {
				if m == "Page.getLayoutMetrics" && mode == "metrics" {
					return map[string]any{"contentSize": map[string]any{"width": 10001, "height": 3}}, nil
				}
				if m == "Page.captureScreenshot" {
					switch mode {
					case "encoding":
						return map[string]any{"data": "!!"}, nil
					case "dimensions":
						return map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("PNG"))}, nil
					case "protocol":
						return nil, errors.New("unsupported")
					}
				}
				return old(ctx, m, p)
			}
			_, p := pageFor(t, f, adapterOptions())
			if e := p.Navigate(context.Background(), "https://example.test/start"); e != nil {
				t.Fatal(e)
			}
			if _, e := p.Screenshot(context.Background()); e == nil {
				t.Fatal("invalid screenshot accepted")
			}
		})
	}
}
func TestScreenshotAtomicUnicodePreservation(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	data := fixturePNG()
	a, e := SaveScreenshot(ctx, root, "скриншоты/страница😀.png", data, 1<<16)
	if e != nil {
		t.Fatal(e)
	}
	if a.Bytes != len(data) || len(a.SHA256) != 64 {
		t.Fatal(a)
	}
	if _, e = SaveScreenshot(ctx, root, "скриншоты/страница😀.png", data, 1<<16); e == nil {
		t.Fatal("overwrote previous result")
	}
	got, e := os.ReadFile(a.Path)
	if e != nil || !bytes.Equal(got, data) {
		t.Fatal("previous result damaged")
	}
	for _, bad := range [][]byte{nil, []byte("bad"), data[:len(data)-2], append(append([]byte(nil), data[:len(data)-1]...), 0)} {
		if _, e = SaveScreenshot(ctx, root, "broken.png", bad, 1<<16); e == nil {
			t.Fatal("corrupted PNG accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = SaveScreenshot(cancelled, root, "cancelled.png", data, 1<<16); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = SaveScreenshot(ctx, root, "../escape.png", data, 1<<16); e == nil {
		t.Fatal("escape")
	}
	entries, e := os.ReadDir(filepath.Dir(a.Path))
	if e != nil || len(entries) != 1 {
		t.Fatalf("staging leaked %v %v", entries, e)
	}
}
func TestScreenshotSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(root, "link")); e != nil {
		t.Skip(e)
	}
	if _, e := SaveScreenshot(context.Background(), root, "link/x.png", fixturePNG(), 1<<16); e == nil {
		t.Fatal("symlink escape")
	}
}

// This socket is memory-only: no net.Dial, listeners, native process or CDP
// browser is involved. It tests the pinned Rod client's actual wire decoder.
type memorySocket struct {
	packets chan []byte
	done    chan struct{}
	once    sync.Once
	reply   bool
	sends   atomic.Int64
}

func newMemorySocket(reply bool) *memorySocket {
	return &memorySocket{packets: make(chan []byte, 8), done: make(chan struct{}), reply: reply}
}
func (s *memorySocket) Send(data []byte) error {
	s.sends.Add(1)
	if !s.reply {
		return nil
	}
	var r struct {
		ID int `json:"id"`
	}
	if e := json.Unmarshal(data, &r); e != nil {
		return e
	}
	packet, _ := json.Marshal(map[string]any{"id": r.ID, "result": map[string]any{"ok": true}})
	select {
	case s.packets <- packet:
		return nil
	case <-s.done:
		return io.EOF
	}
}
func (s *memorySocket) Read() ([]byte, error) {
	select {
	case p := <-s.packets:
		return p, nil
	case <-s.done:
		return nil, io.EOF
	}
}
func (s *memorySocket) Close() error { s.once.Do(func() { close(s.done) }); return nil }
func TestRodMemoryTransportAndEventDrain(t *testing.T) {
	s := newMemorySocket(true)
	r, e := newRodTransport(context.Background(), s, 4096, 100*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	s.packets <- []byte(`{"method":"Page.loadEventFired","params":{}}`)
	out, e := r.Call(context.Background(), "session", "Runtime.evaluate", map[string]any{})
	if e != nil || string(out) != `{"ok":true}` {
		t.Fatalf("%s %v", out, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Call(context.Background(), "", "x", nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestRodTransportTimeoutAndMalformedPackets(t *testing.T) {
	for _, packet := range []string{"", `{"id":"bad"}`, `{"id":1,"result":[]}`, `{"id":0}`, `{"method":1}`, `{"id":-1}`, `{"method":"x","params":true}`, strings.Repeat("x", 4097)} {
		t.Run(packet[:min(len(packet), 25)], func(t *testing.T) {
			s := newMemorySocket(false)
			r, e := newRodTransport(context.Background(), s, 4096, 50*time.Millisecond)
			if e != nil {
				t.Fatal(e)
			}
			s.packets <- []byte(packet)
			if _, e = r.Call(context.Background(), "", "x", nil); e == nil {
				t.Fatal("invalid packet accepted")
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
	s := newMemorySocket(false)
	r, e := newRodTransport(context.Background(), s, 4096, 5*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Call(context.Background(), "", "x", nil); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	_ = r.Close()
}
func TestCDPEndpointStrictLoopback(t *testing.T) {
	if _, e := validateControlURL("ws://127.0.0.1:9222/devtools/browser/x", 9222); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"ws://evil.test:9222/a", "ws://localhost:9222/a", "ws://127.0.0.1:9223/a", "ws://user@127.0.0.1:9222/a", "ws://127.0.0.1:9222/a?x=1", "wss://127.0.0.1:9222/a", "ws://127.0.0.1:9222/"} {
		if _, e := validateControlURL(raw, 9222); e == nil {
			t.Fatal(raw)
		}
	}
}

func TestRodAlreadyCancelledDoesNotSend(t *testing.T) {
	s := newMemorySocket(true)
	r, err := newRodTransport(context.Background(), s, 4096, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Call(ctx, "", "x", nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.sends.Load() != 0 {
		t.Fatal("already-cancelled command sent")
	}
	// A malformed command parameter must return an error, not Rod's panic.
	if _, err = r.Call(context.Background(), "", "x", func() {}); err == nil {
		t.Fatal("bad parameter accepted")
	}
}

type blockedSocket struct {
	*memorySocket
	entered chan struct{}
}

func (s *blockedSocket) Send([]byte) error { close(s.entered); <-s.done; return io.EOF }
func TestRodCancelledBlockedSendSettles(t *testing.T) {
	s := &blockedSocket{newMemorySocket(false), make(chan struct{})}
	r, err := newRodTransport(context.Background(), s, 4096, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Call(ctx, "", "x", nil); done <- err }()
	<-s.entered
	cancel()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("cancelled send succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("send stayed blocked")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestAdapterConcurrentCloseWaitsForFailure(t *testing.T) {
	f := loadedClient()
	old := f.handler
	entered := make(chan struct{})
	release := make(chan struct{})
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Target.closeTarget" {
			close(entered)
			select {
			case <-release:
				return nil, errors.New("closure failed")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return old(ctx, m, p)
	}
	b := newBrowser(f, adapterOptions())
	if _, err := b.NewPage(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- b.Close(context.Background()) }()
	<-entered
	go func() { second <- b.Close(context.Background()) }()
	select {
	case e := <-second:
		t.Fatalf("premature close result %v", e)
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	for _, done := range []chan error{first, second} {
		select {
		case e := <-done:
			if e == nil || !strings.Contains(e.Error(), "closure failed") {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("close hung")
		}
	}
}
func TestAdapterFailedNavigateInvalidatesPage(t *testing.T) {
	f := loadedClient()
	old := f.handler
	failed := false
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Page.navigate" && failed {
			return map[string]any{"errorText": "failed"}, nil
		}
		return old(ctx, m, p)
	}
	_, p := pageFor(t, f, adapterOptions())
	if err := p.Navigate(context.Background(), "https://example.test/start"); err != nil {
		t.Fatal(err)
	}
	failed = true
	if err := p.Navigate(context.Background(), "https://example.test/next"); err == nil {
		t.Fatal("navigate success")
	}
	if _, err := p.DOM(context.Background()); err == nil {
		t.Fatal("returned stale DOM after failed navigation")
	}
}
func TestAdapterScreenshotCorruptTail(t *testing.T) {
	f := loadedClient()
	old := f.handler
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Page.captureScreenshot" {
			data := fixturePNG()
			data = data[:len(data)-2]
			return map[string]any{"data": base64.StdEncoding.EncodeToString(data)}, nil
		}
		return old(ctx, m, p)
	}
	_, p := pageFor(t, f, adapterOptions())
	if err := p.Navigate(context.Background(), "https://example.test/start"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Screenshot(context.Background()); err == nil {
		t.Fatal("valid IHDR with corrupt IEND accepted")
	}
}

func TestVerifiedLaunchPlanUsesTypedServeArguments(t *testing.T) {
	root := t.TempDir()
	relative := "tools/Обскура with spaces"
	path := filepath.Join(root, filepath.FromSlash(relative))
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	payload := []byte("not an executable: must never be run")
	if e := os.WriteFile(path, payload, 0700); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(payload)
	m, e := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": relative, "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "obscura", "executable": relative, "version": "0.2.2"}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "bundle.json"), m, 0600); e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256(m)
	bundle, e := platform.NewBundle(root, hex.EncodeToString(d[:]))
	if e != nil {
		t.Fatal(e)
	}
	scope := adapterOptions().Scope
	plan, e := PrepareLaunch(bundle, 9222, scope)
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"serve", "--host", "127.0.0.1", "--port", "9222"}
	if !reflect.DeepEqual(plan.Args(), want) {
		t.Fatal(plan.Args())
	}
	mutated := plan.Args()
	mutated[0] = "bad"
	if plan.Args()[0] != "serve" {
		t.Fatal("args not copied")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = plan.Run(canceled); !errors.Is(e, context.Canceled) {
		t.Fatalf("pre-canceled launch plan result = %v", e)
	}
	scope.Policy.AllowedCIDRs = []string{"127.0.0.0/8"}
	plan, e = PrepareLaunch(bundle, 9222, scope)
	if e != nil || plan.Args()[len(want)] != "--allow-private-network" {
		t.Fatalf("%v %v", plan.Args(), e)
	}
	scope.Policy.AllowedCIDRs = []string{"192.168.1.4"} // core accepts a bare host CIDR.
	plan, e = PrepareLaunch(bundle, 9222, scope)
	if e != nil || plan.Args()[len(want)] != "--allow-private-network" {
		t.Fatalf("bare private host CIDR was not normalized: %v %v", plan.Args(), e)
	}
	scope.Policy.AllowedCIDRs = []string{"192.0.2.4"}
	plan, e = PrepareLaunch(bundle, 9222, scope)
	if e != nil || !reflect.DeepEqual(plan.Args(), want) {
		t.Fatalf("documentation-only IP unexpectedly enabled private network: %v %v", plan.Args(), e)
	}
	if e = os.WriteFile(path, []byte("tampered"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = PrepareLaunch(bundle, 9222, scope); e == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestAdapterSnapshotUsesMatchingURLAndDOM(t *testing.T) {
	f := loadedClient()
	old := f.handler
	_, p := pageFor(t, f, adapterOptions())
	if err := p.Navigate(context.Background(), "https://example.test/start"); err != nil {
		t.Fatal(err)
	}
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Runtime.evaluate" && strings.Contains(p.(map[string]any)["expression"].(string), "outerHTML") {
			return value(map[string]any{"url": "https://example.test/new/path/", "html": `<a href="child">link</a>`}), nil
		}
		return old(ctx, m, p)
	}
	links, err := p.Links(context.Background())
	if err != nil || !reflect.DeepEqual(links, []string{"https://example.test/new/path/child"}) {
		t.Fatalf("stale base: %v %v", links, err)
	}
}
func TestAdapterPageCleanupFailureSticky(t *testing.T) {
	f := loadedClient()
	old := f.handler
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Target.closeTarget" {
			return nil, errors.New("target cleanup failed")
		}
		return old(ctx, m, p)
	}
	b := newBrowser(f, adapterOptions())
	p, err := b.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Close(context.Background()); err == nil {
		t.Fatal("close failure lost")
	}
	if err = p.Close(context.Background()); err == nil {
		t.Fatal("repeat close failure lost")
	}
	if err = b.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "target cleanup failed") {
		t.Fatalf("browser forgot cleanup failure: %v", err)
	}
}
func TestAdapterDOMScopeDriftTerminal(t *testing.T) {
	f := loadedClient()
	old := f.handler
	_, p := pageFor(t, f, adapterOptions())
	if err := p.Navigate(context.Background(), "https://example.test/start"); err != nil {
		t.Fatal(err)
	}
	f.handler = func(ctx context.Context, m string, p any) (any, error) {
		if m == "Runtime.evaluate" {
			return value(map[string]any{"url": "https://evil.test/", "html": "<html>private</html>"}), nil
		}
		return old(ctx, m, p)
	}
	if _, err := p.DOM(context.Background()); err == nil {
		t.Fatal("scope drift returnedDOM")
	}
	if _, err := p.DOM(context.Background()); err == nil {
		t.Fatal("scope drift not terminal")
	}
	if f.count("Target.closeTarget") != 1 {
		t.Fatal("drift cleanup")
	}
}

func TestAdapterUncertainSetupStopsAdmission(t *testing.T) {
	f := &fakeCDP{handler: func(ctx context.Context, m string, p any) (any, error) {
		if m == "Page.enable" || m == "Target.closeTarget" {
			return nil, errors.New("fixture failure")
		}
		return nil, nil
	}}
	b := newBrowser(f, adapterOptions())
	if _, e := b.NewPage(context.Background()); e == nil {
		t.Fatal("setup accepted")
	}
	if _, e := b.NewPage(context.Background()); e == nil {
		t.Fatal("uncertain cleanup allowed more targets")
	}
	if f.count("Target.createTarget") != 1 {
		t.Fatal("continued creation after uncertain cleanup")
	}
	if e := b.Close(context.Background()); e == nil {
		t.Fatal("cleanup uncertainty forgotten")
	}
}
