package browser

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type observedFake struct {
	*fakeCDP
	collector   *documentResponseCollector
	contentType string
	missing     bool
}

func (f *observedFake) observeDocument(session string) (*documentResponseCollector, func(), error) {
	c, e := newDocumentResponseCollector(EventLimits{20, 4096, 16384, 2048})
	if e != nil {
		return nil, nil, e
	}
	_ = c.SetSession(session)
	f.collector = c
	return c, func() {}, nil
}
func (f *observedFake) Call(ctx context.Context, session, method string, params any) ([]byte, error) {
	if method != "Page.navigate" {
		return f.fakeCDP.Call(ctx, session, method, params)
	}
	raw, _ := f.fakeCDP.Call(ctx, session, method, params)
	if f.missing {
		return raw, nil
	}
	for _, event := range []struct {
		method string
		data   any
	}{
		{"Network.requestWillBeSent", map[string]any{"requestId": "r", "loaderId": "l", "frameId": "f", "type": "Document", "request": map[string]any{"url": "https://example.test/start"}}},
		{"Network.responseReceived", map[string]any{"requestId": "r", "loaderId": "l", "frameId": "f", "type": "Document", "response": map[string]any{"url": "https://example.test/start", "status": 203, "headers": map[string]any{"content-type": f.contentType}}}},
		{"Network.loadingFinished", map[string]any{"requestId": "r"}},
	} {
		data, _ := json.Marshal(event.data)
		_ = f.collector.Ingest(session, event.method, data)
	}
	return json.Marshal(map[string]any{"frameId": "f", "loaderId": "l"})
}
func TestNavigateObservedResponse(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "text/html"}
	b := newBrowser(f, adapterOptions())
	defer b.Close(context.Background())
	p, e := b.NewPage(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Navigate(context.Background(), "https://example.test/start"); e != nil {
		t.Fatal(e)
	}
	response, e := p.Response()
	if e != nil || response.Status != 203 || response.ContentType != "text/html" || !response.Complete {
		t.Fatalf("response %+v %v", response, e)
	}
}
func TestNavigateHeaderDownloadNoDOMOrScreenshot(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "application/pdf"}
	b := newBrowser(f, adapterOptions())
	defer b.Close(context.Background())
	p, e := b.NewPage(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Navigate(context.Background(), "https://example.test/start"); !errors.Is(e, ErrDownloadableResource) {
		t.Fatal(e)
	}
	response, e := p.Response()
	if e != nil || response.Status != 203 || response.ContentType != "application/pdf" {
		t.Fatalf("response %+v %v", response, e)
	}
	if f.count("Runtime.evaluate") != 0 || f.count("Page.captureScreenshot") != 0 || f.count("Target.closeTarget") != 1 {
		t.Fatal("download should close before DOM/PNG")
	}
}
func TestNavigateMissingIdentityFailsClosed(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), missing: true}
	b := newBrowser(f, adapterOptions())
	defer b.Close(context.Background())
	p, e := b.NewPage(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Navigate(context.Background(), "https://example.test/start"); e == nil || !strings.Contains(e.Error(), "identity") {
		t.Fatal(e)
	}
	if f.count("Target.closeTarget") != 1 {
		t.Fatal("missing metadata target not closed")
	}
}
func TestResponseDoesNotInventMetadata(t *testing.T) {
	_, p := pageFor(t, loadedClient(), adapterOptions())
	if _, e := p.Response(); e == nil {
		t.Fatal("metadata invented")
	}
}

func TestNavigateMetadataCorruptionDuringSettle(t *testing.T) {
	f := &observedFake{fakeCDP: loadedClient(), contentType: "text/html"}
	old := f.handler
	once := false
	f.handler = func(ctx context.Context, method string, params any) (any, error) {
		if method == "Runtime.evaluate" && !once && strings.Contains(params.(map[string]any)["expression"].(string), "readyState") {
			once = true
			// Corruption arrives after the initial metadata-ready check.
			_ = f.collector.Ingest("session", "Network.responseReceived", json.RawMessage(`{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://evil.test/","status":200,"headers":{"content-type":"text/html"}}}`))
		}
		return old(ctx, method, params)
	}
	opts := adapterOptions()
	opts.SettleDelay = 1
	b := newBrowser(f, opts)
	defer b.Close(context.Background())
	p, e := b.NewPage(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Navigate(context.Background(), "https://example.test/start"); e == nil {
		t.Fatal("settled metadata drift accepted")
	}
	if f.count("Target.closeTarget") != 1 {
		t.Fatal("drift target not closed")
	}
}

func TestTransportDocumentObservationMemoryOnly(t *testing.T) {
	socket := newMemorySocket(true)
	transport, err := newRodTransport(context.Background(), socket, 1<<20, adapterOptions().CommandTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	collector, release, err := transport.observeDocument("owned")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err = collector.ConfigureNavigation("owned", "f", "l"); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{"sessionId":"owned","method":"Network.requestWillBeSent","params":{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/start"}}}`,
		`{"sessionId":"owned","method":"Network.responseReceived","params":{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://example.test/start","status":203,"headers":{"content-type":"text/html"}}}}`,
		`{"sessionId":"owned","method":"Network.loadingFinished","params":{"requestId":"r"}}`,
	} {
		socket.packets <- []byte(data)
	}
	deadline := time.After(time.Second)
	for {
		if response, e := collector.Result(); e == nil {
			if response.Status != 203 {
				t.Fatal(response)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("CDP reader dropped document observations")
		case <-time.After(time.Millisecond):
		}
	}
	release()
	if _, nextRelease, e := transport.observeDocument("owned"); e != nil {
		t.Fatal(e)
	} else {
		nextRelease()
	}
}
