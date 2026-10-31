package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/core"
)

func captureRequest(sink EventSink) CaptureRequest {
	return CaptureRequest{
		URL: "https://example.test/files/brief.pdf?download=1", Module: "crawler", Phase: "verify",
		Depth: 2, TargetDomains: []string{"example.test", "example.test"}, Sink: sink,
	}
}

func TestBrowserCaptureClassifiesURLBeforeCreatingPage(t *testing.T) {
	b := newBrowser(nil, adapterOptions())
	var got []core.Event
	result, err := b.Capture(context.Background(), captureRequest(func(event core.Event) error {
		got = append(got, event)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.DownloadDetected || result.NetworkContacted || len(result.Events) != 1 || len(got) != 1 || result.PersistedEvents != 1 {
		t.Fatalf("unexpected precontact result: result=%+v events=%d", result, len(got))
	}
	event := got[0]
	if event.EventType != core.CrawlerResult || event.Metadata["network_contacted"] != false ||
		event.Metadata["detection_reason"] != "url_extension" || event.Metadata["status_code"] != nil ||
		event.Metadata["downloaded"] != false || event.Metadata["screenshot_expected"] != false {
		t.Fatalf("unexpected URL extension event: %+v", event)
	}
	if len(b.pages) != 0 {
		t.Fatal("URL extension detection created a page or attempted navigation")
	}
}

func TestBrowserCaptureReportsSinkFailureWithoutClaimingPersistence(t *testing.T) {
	b := newBrowser(nil, adapterOptions())
	want := errors.New("evidence sink unavailable")
	result, err := b.Capture(context.Background(), captureRequest(func(core.Event) error { return want }))
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "persist crawler_result") {
		t.Fatalf("sink failure not propagated: %v", err)
	}
	if len(result.Events) != 1 || result.PersistedEvents != 0 || !result.DownloadDetected || result.NetworkContacted {
		t.Fatalf("sink failure was reported as persisted/successful: %+v", result)
	}
}

func TestBrowserCaptureRejectsOutOfScopeAndMalformedTargetsBeforeSink(t *testing.T) {
	for _, raw := range []string{"https://outside.test/file.pdf", "https://user@example.test/file.pdf"} {
		t.Run(raw, func(t *testing.T) {
			b := newBrowser(nil, adapterOptions())
			called := false
			req := captureRequest(func(core.Event) error { called = true; return nil })
			req.URL = raw
			_, err := b.Capture(context.Background(), req)
			if err == nil || called {
				t.Fatalf("invalid/unauthorized target reached sink: err=%v called=%v", err, called)
			}
		})
	}
	{
		b := newBrowser(nil, adapterOptions())
		called := false
		req := captureRequest(func(core.Event) error { called = true; return nil })
		req.TargetDomains = []string{"outside.test"}
		if _, err := b.Capture(context.Background(), req); err == nil || called {
			t.Fatal("out-of-scope target-domain provenance was accepted")
		}
	}
}

func TestCaptureEventsDoNotClaimSubresourceBlocking(t *testing.T) {
	req := captureRequest(func(core.Event) error { return nil })
	response := DocumentResponse{URL: "https://example.test/start", Status: 200, ContentType: "text/html", Complete: true}
	event, err := screenshotEvent(req, []string{"example.test"},
		"https://example.test/app", "title", response, ScreenshotArtifact{Path: "shot.png", SHA256: "abc", Bytes: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := event.Metadata["out_of_scope_subresources_blocked"]; exists {
		t.Fatal("candidate31 disproved this assertion")
	}
	htmlEvent, err := htmlAnalyzedEvent(req, []string{"example.test"}, "https://example.test/start", "https://example.test/app", "title", backends.HTMLFeatures{}, response, 0, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if htmlEvent.Metadata["page_loaded"] != true || htmlEvent.Metadata["network_contacted"] != true || htmlEvent.Metadata["phase"] != req.Phase || htmlEvent.Metadata["out_of_scope_subresources_blocked"] != false || !strings.Contains(htmlEvent.Metadata["scope_limitation"].(string), "candidate31") {
		t.Fatalf("HTML evidence omitted observed state or candidate31 limitation: %#v", htmlEvent.Metadata)
	}
}

func TestBrowserCaptureUsesOnePageAndAttributesFinalSPAURL(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "text/html"}
	old := f.handler
	f.handler = func(ctx context.Context, method string, params any) (any, error) {
		if method == "Runtime.evaluate" {
			expression := params.(map[string]any)["expression"].(string)
			switch {
			case strings.Contains(expression, "outerHTML"):
				return value(map[string]any{"url": "https://example.test/app", "html": `<html><title>SPA</title><a href="/next">next</a></html>`}), nil
			case strings.Contains(expression, "document.title"):
				return value(map[string]any{"url": "https://example.test/app", "title": "SPA"}), nil
			case expression == "location.href":
				return value("https://example.test/app"), nil
			case strings.Contains(expression, "readyState"):
				return value(map[string]any{"state": "complete", "url": "https://example.test/app"}), nil
			}
		}
		return old(ctx, method, params)
	}
	b := newBrowser(f, adapterOptions())
	var persisted []core.Event
	req := captureRequest(func(event core.Event) error { persisted = append(persisted, event); return nil })
	req.URL = "https://example.test/start"
	result, err := b.Capture(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalURL != "https://example.test/app" || result.Response.URL != "https://example.test/start" || len(result.Links) != 1 || result.Links[0] != "https://example.test/next" {
		t.Fatalf("SPA URL/response/link attribution = %+v", result)
	}
	if len(persisted) != 1 || persisted[0].EventType != core.HTMLAnalyzed || persisted[0].NormalizedValue != "https://example.test/app" {
		t.Fatalf("HTML event did not use current SPA URL: %#v", persisted)
	}
	if f.count("Page.navigate") != 1 || f.count("Page.captureScreenshot") != 0 || f.count("Target.closeTarget") != 1 {
		t.Fatal("capture revisited page, captured unrequested screenshot or leaked target")
	}
}

func TestBrowserCaptureRetainsScreenshotWhenSinkFails(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "text/html"}
	b := newBrowser(f, adapterOptions())
	want := errors.New("screenshot evidence sink failed")
	root := t.TempDir()
	req := captureRequest(func(event core.Event) error {
		if event.EventType == core.ScreenshotSaved {
			return want
		}
		return nil
	})
	req.URL = "https://example.test/start"
	req.ScreenshotRoot, req.ScreenshotRelativePath = root, filepath.Join("screenshots", "capture.png")
	result, err := b.Capture(context.Background(), req)
	if !errors.Is(err, want) || result.Screenshot == nil || result.PersistedEvents != 0 || len(result.Events) != 1 || result.Events[0].EventType != core.ScreenshotSaved {
		t.Fatalf("screenshot sink failure accounting = result:%+v err:%v", result, err)
	}
	if _, err := os.Stat(result.Screenshot.Path); err != nil {
		t.Fatalf("published screenshot was removed after sink failure: %v", err)
	}
	if f.count("Page.navigate") != 1 || f.count("Target.closeTarget") != 1 {
		t.Fatal("capture revisited page or failed to clean target")
	}
}

func TestBrowserCaptureCancellationDuringScreenshotEmitsNoLoadedEvent(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "text/html"}
	old := f.handler
	entered := make(chan struct{})
	f.handler = func(ctx context.Context, method string, params any) (any, error) {
		if method == "Page.captureScreenshot" {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return old(ctx, method, params)
	}
	b := newBrowser(f, adapterOptions())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := captureRequest(func(core.Event) error { return nil })
	req.URL = "https://example.test/start"
	req.ScreenshotRoot, req.ScreenshotRelativePath = t.TempDir(), "capture.png"
	done := make(chan struct {
		result CaptureResult
		err    error
	}, 1)
	go func() {
		result, err := b.Capture(ctx, req)
		done <- struct {
			result CaptureResult
			err    error
		}{result, err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("capture did not reach screenshot")
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("cancellation was not propagated: %v", got.err)
		}
		for _, event := range got.result.Events {
			if event.EventType == core.HTMLAnalyzed {
				t.Fatal("cancelled capture emitted a success-shaped HTML event")
			}
		}
	case <-time.After(time.Second):
		t.Fatal("capture did not stop after cancellation")
	}
}

func TestBrowserCaptureKeepsCleanupFailureAlongsideDownloadEvent(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "application/pdf"}
	closeErr := errors.New("target close failed")
	old := f.handler
	f.handler = func(ctx context.Context, method string, params any) (any, error) {
		if method == "Target.closeTarget" {
			return nil, closeErr
		}
		return old(ctx, method, params)
	}
	b := newBrowser(f, adapterOptions())
	var persisted []core.Event
	req := captureRequest(func(event core.Event) error { persisted = append(persisted, event); return nil })
	req.URL = "https://example.test/start"
	result, err := b.Capture(context.Background(), req)
	if !errors.Is(err, ErrDownloadableResource) || !errors.Is(err, closeErr) {
		t.Fatalf("download/cleanup errors were hidden: %v", err)
	}
	if !result.DownloadDetected || !result.NetworkContacted || result.Response.Status != 203 || len(persisted) != 1 || persisted[0].Metadata["detection_reason"] != "response_headers" {
		t.Fatalf("observed response download event missing: result=%+v events=%#v", result, persisted)
	}
	if f.count("Runtime.evaluate") != 0 || f.count("Page.captureScreenshot") != 0 {
		t.Fatal("download path executed DOM or screenshot commands")
	}
}

type parallelCaptureClient struct {
	fake       *fakeCDP
	mu         sync.Mutex
	collectors map[string]*documentResponseCollector
}

func newParallelCaptureClient() *parallelCaptureClient {
	fake := loadedClient()
	old := fake.handler
	var seqMu sync.Mutex
	seq := 0
	fake.handler = func(ctx context.Context, method string, params any) (any, error) {
		if method == "Target.attachToTarget" {
			seqMu.Lock()
			defer seqMu.Unlock()
			seq++
			return map[string]any{"sessionId": fmt.Sprintf("session-%d", seq)}, nil
		}
		return old(ctx, method, params)
	}
	return &parallelCaptureClient{fake: fake, collectors: make(map[string]*documentResponseCollector)}
}

func (f *parallelCaptureClient) observeDocument(session string) (*documentResponseCollector, func(), error) {
	c, err := newDocumentResponseCollector(EventLimits{20, 4096, 16384, 2048})
	if err != nil {
		return nil, nil, err
	}
	if err := c.SetSession(session); err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	f.collectors[session] = c
	f.mu.Unlock()
	return c, func() {}, nil
}

func (f *parallelCaptureClient) Call(ctx context.Context, session, method string, params any) ([]byte, error) {
	if method != "Page.navigate" {
		return f.fake.Call(ctx, session, method, params)
	}
	if _, err := f.fake.Call(ctx, session, method, params); err != nil {
		return nil, err
	}
	f.mu.Lock()
	c := f.collectors[session]
	f.mu.Unlock()
	if c == nil {
		return nil, errors.New("navigation has no session collector")
	}
	loader, request := "loader-"+session, "request-"+session
	for _, event := range []struct{ method, params string }{
		{"Network.requestWillBeSent", fmt.Sprintf(`{"requestId":%q,"loaderId":%q,"frameId":"main","type":"Document","request":{"url":"https://example.test/start"}}`, request, loader)},
		{"Network.responseReceived", fmt.Sprintf(`{"requestId":%q,"loaderId":%q,"frameId":"main","type":"Document","response":{"url":"https://example.test/start","status":200,"headers":{"content-type":"text/html"}}}`, request, loader)},
		{"Network.loadingFinished", fmt.Sprintf(`{"requestId":%q}`, request)},
	} {
		if err := c.Ingest(session, event.method, []byte(event.params)); err != nil {
			return nil, err
		}
	}
	return []byte(fmt.Sprintf(`{"frameId":"main","loaderId":%q}`, loader)), nil
}

func TestConcurrentBrowserCapturesOwnSeparatePagesAndCollectors(t *testing.T) {
	f := newParallelCaptureClient()
	b := newBrowser(f, adapterOptions())
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := captureRequest(func(core.Event) error { return nil })
			req.URL = "https://example.test/start"
			result, err := b.Capture(context.Background(), req)
			if err == nil && (result.FinalURL != "https://example.test/start" || result.Response.Status != 200 || len(result.Links) != 1) {
				err = fmt.Errorf("incomplete concurrent capture: %+v", result)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.fake.count("Page.navigate") != 2 || f.fake.count("Target.createTarget") != 2 || f.fake.count("Target.closeTarget") != 2 {
		t.Fatal("concurrent captures did not own and clean separate page targets")
	}
}
