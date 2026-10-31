package browser

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testCollector(t *testing.T, limits EventLimits) *documentResponseCollector {
	t.Helper()
	c, err := newDocumentResponseCollector(limits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testEvent(t *testing.T, c *documentResponseCollector, session, method, params string) error {
	t.Helper()
	return c.Ingest(session, method, json.RawMessage(params))
}

func TestDocumentResponseCollectorCorrelatesFinalMainDocument(t *testing.T) {
	c := testCollector(t, EventLimits{MaxEvents: 16, MaxEventBytes: 4096, MaxTotalBytes: 16384, MaxHeaderBytes: 2048})
	// These arrive before Page.navigate returns its loader identity. The stale
	// session, stale loader and image subresource must not become the document.
	for _, e := range []struct{ session, method, params string }{
		{"old-session", "Network.requestWillBeSent", `{"requestId":"old","loaderId":"loader-1","frameId":"main","type":"Document","request":{"url":"https://example.test/old"}}`},
		{"session-1", "Network.requestWillBeSent", `{"requestId":"sub","loaderId":"loader-2","frameId":"main","type":"Image","request":{"url":"https://example.test/image.png"}}`},
		{"session-1", "Network.requestWillBeSent", `{"requestId":"main-request","loaderId":"loader-2","frameId":"main","type":"Document","request":{"url":"https://example.test/start","headers":{}}}`},
		{"session-1", "Network.responseReceived", `{"requestId":"main-request","loaderId":"loader-2","frameId":"main","type":"Document","response":{"url":"https://example.test/日本語","status":203.0,"headers":{"Content-Type":"text/html; charset=utf-8","Content-Disposition":"inline","Set-Cookie":"a=1\nb=2"},"mimeType":"text/html"}}`},
		{"session-1", "Network.loadingFinished", `{"requestId":"main-request","encodedDataLength":42}`},
	} {
		if err := testEvent(t, c, e.session, e.method, e.params); err != nil {
			t.Fatalf("Ingest %s: %v", e.method, err)
		}
	}
	if err := c.ConfigureNavigation("session-1", "main", "loader-2"); err != nil {
		t.Fatal(err)
	}
	got, err := c.Result()
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "main-request" || got.Status != 203 || got.URL != "https://example.test/日本語" ||
		got.ContentType != "text/html; charset=utf-8" || got.ContentDisposition != "inline" || !got.Complete {
		t.Fatalf("unexpected document response: %+v", got)
	}
}

func TestDocumentResponseCollectorDoesNotInventMissingMetadata(t *testing.T) {
	c := testCollector(t, EventLimits{MaxEvents: 8, MaxEventBytes: 2048, MaxTotalBytes: 8192, MaxHeaderBytes: 1024})
	if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Result(); err == nil || !strings.Contains(err.Error(), "headers unavailable") {
		t.Fatalf("missing headers must be incomplete: %v", err)
	}
	for _, e := range []struct{ method, params string }{
		{"Network.requestWillBeSent", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/"}}`},
		{"Network.responseReceived", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://example.test/","status":200,"headers":{}}}`},
		{"Network.loadingFinished", `{"requestId":"r"}`},
	} {
		if err := testEvent(t, c, "s", e.method, e.params); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.Result()
	if err != nil {
		t.Fatalf("an observed empty headers object is valid: %v", err)
	}
	if got.Status != 200 || got.ContentType != "" || got.ContentDisposition != "" || !got.Complete {
		t.Fatalf("empty observed headers were defaulted or lost: %+v", got)
	}
	for name, headers := range map[string]string{"omitted": "", "null": `,"headers":null`} {
		t.Run(name, func(t *testing.T) {
			c := testCollector(t, EventLimits{MaxEvents: 8, MaxEventBytes: 2048, MaxTotalBytes: 8192, MaxHeaderBytes: 1024})
			if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
				t.Fatal(err)
			}
			if err := testEvent(t, c, "s", "Network.requestWillBeSent", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/"}}`); err != nil {
				t.Fatal(err)
			}
			response := `"url":"https://example.test/","status":200,"headers":{}`
			if name == "omitted" {
				response = `"url":"https://example.test/","status":200`
			} else {
				response = `"url":"https://example.test/","status":200` + headers
			}
			params := `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{` + response + `}}`
			if err := testEvent(t, c, "s", "Network.responseReceived", params); err == nil {
				t.Fatal("missing or null headers accepted")
			}
		})
	}
}

func TestDocumentResponseCollectorRequiresLoadCompletion(t *testing.T) {
	c := testCollector(t, EventLimits{MaxEvents: 8, MaxEventBytes: 2048, MaxTotalBytes: 8192, MaxHeaderBytes: 1024})
	if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct{ method, params string }{
		{"Network.requestWillBeSent", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/"}}`},
		{"Network.responseReceived", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://example.test/","status":200,"headers":{"content-type":"text/html"}}}`},
	} {
		if err := testEvent(t, c, "s", e.method, e.params); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Result(); err == nil || !strings.Contains(err.Error(), "completion unavailable") {
		t.Fatalf("pending load must remain incomplete: %v", err)
	}
}

func TestDocumentResponseCollectorSnapshotPreservesIncompleteMetadata(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "pending"
		if failure {
			name = "failed after headers"
		}
		t.Run(name, func(t *testing.T) {
			c := testCollector(t, EventLimits{MaxEvents: 8, MaxEventBytes: 2048, MaxTotalBytes: 8192, MaxHeaderBytes: 1024})
			if err := c.SetSession("s"); err != nil {
				t.Fatal(err)
			}
			if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
				t.Fatal(err)
			}
			for _, e := range []struct{ method, params string }{
				{"Network.requestWillBeSent", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/file.pdf"}}`},
				{"Network.responseReceived", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://example.test/file.pdf","status":206,"headers":{"content-type":"application/pdf","content-disposition":"attachment"}}}`},
			} {
				if err := testEvent(t, c, "s", e.method, e.params); err != nil {
					t.Fatal(err)
				}
			}
			// Valid worker events without frame/loader identity must not poison
			// the main-document capture.
			if err := testEvent(t, c, "s", "Network.requestWillBeSent", `{"requestId":"worker","type":"Fetch","request":{"url":"https://example.test/worker"}}`); err != nil {
				t.Fatalf("unrelated worker request rejected: %v", err)
			}
			if failure {
				if err := testEvent(t, c, "s", "Network.loadingFailed", `{"requestId":"r","errorText":"net::ERR_ABORTED"}`); err != nil {
					t.Fatal(err)
				}
			}
			got, err := c.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != 206 || got.ContentType != "application/pdf" || got.ContentDisposition != "attachment" || got.Complete {
				t.Fatalf("incomplete response metadata lost or marked complete: %+v", got)
			}
			if _, err := c.Result(); err == nil || !strings.Contains(err.Error(), "incomplete") {
				t.Fatalf("Result accepted pending/failed document: %v", err)
			}
		})
	}
}

func TestDocumentResponseCollectorIgnoresOtherSessionsBeforeBudget(t *testing.T) {
	c := testCollector(t, EventLimits{MaxEvents: 1, MaxEventBytes: 512, MaxTotalBytes: 1024, MaxHeaderBytes: 256})
	if err := c.SetSession("owned"); err != nil {
		t.Fatal(err)
	}
	if err := testEvent(t, c, "other", "Network.responseReceived", `not-json`); err != nil {
		t.Fatalf("other session should be ignored before validation: %v", err)
	}
	if err := testEvent(t, c, "owned", "Network.loadingFinished", `{"requestId":"r"}`); err != nil {
		t.Fatal(err)
	}
	if err := testEvent(t, c, "owned", "Network.loadingFinished", `{"requestId":"r"}`); err == nil {
		t.Fatal("owned session event budget was not enforced")
	}
}

func TestDocumentResponseCollectorRejectsMalformedAndDuplicateHeadersSticky(t *testing.T) {
	for name, headers := range map[string]string{
		"malformed value": `{"Content-Type":7}`,
		"case duplicate":  `{"Content-Type":"text/html","content-type":"text/plain"}`,
		"control":         `{"Content-Type":"text/html\r\nX-Evil: y"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := testCollector(t, EventLimits{MaxEvents: 8, MaxEventBytes: 2048, MaxTotalBytes: 8192, MaxHeaderBytes: 1024})
			if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
				t.Fatal(err)
			}
			_ = testEvent(t, c, "s", "Network.requestWillBeSent", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/"}}`)
			params := `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://example.test/","status":200,"headers":` + headers + `}}`
			err := testEvent(t, c, "s", "Network.responseReceived", params)
			if err == nil {
				t.Fatal("malformed headers accepted")
			}
			_, again := c.Result()
			if !errors.Is(again, err) {
				t.Fatalf("collector error was not sticky: %v then %v", err, again)
			}
		})
	}
}

func TestDocumentResponseCollectorEnforcesEventAndHeaderBounds(t *testing.T) {
	t.Run("event count", func(t *testing.T) {
		c := testCollector(t, EventLimits{MaxEvents: 1, MaxEventBytes: 512, MaxTotalBytes: 1024, MaxHeaderBytes: 256})
		if err := testEvent(t, c, "s", "Network.loadingFinished", `{"requestId":"other"}`); err != nil {
			t.Fatal(err)
		}
		if err := testEvent(t, c, "s", "Network.loadingFinished", `{"requestId":"other"}`); err == nil {
			t.Fatal("event limit was not enforced")
		}
	})
	t.Run("header bytes", func(t *testing.T) {
		_, err := parseResponseHeaders(json.RawMessage(`{"content-type":"`+strings.Repeat("x", 80)+`"}`), "", 64)
		if err == nil {
			t.Fatal("oversized headers accepted")
		}
	})
}

func TestDocumentResponseHeadersDiscardUnretainedCookies(t *testing.T) {
	got, err := parseResponseHeaders(json.RawMessage(`{"content-type":"text/html","set-cookie":"a=1\nb=2"}`), "", 1024)
	if err != nil {
		t.Fatalf("CDP-joined Set-Cookie values should not poison retained metadata: %v", err)
	}
	if got["content-type"] != "text/html" || len(got) != 1 {
		t.Fatalf("collector retained more than allowed headers: %#v", got)
	}
}

func TestDocumentResponseStatusRequiresIntegralHTTPNumber(t *testing.T) {
	if got, err := parseHTTPStatus(json.RawMessage(`200.0`)); err != nil || got != 200 {
		t.Fatalf("integral decimal CDP status = %d, %v", got, err)
	}
	for _, raw := range []string{`200.5`, `99`, `600`, `"200"`, `1e999`} {
		if _, err := parseHTTPStatus(json.RawMessage(raw)); err == nil {
			t.Errorf("invalid HTTP status %s accepted", raw)
		}
	}
}

func TestDocumentResponseRequiresEstablishedRequestIdentity(t *testing.T) {
	for _, identity := range []string{``, `,"requestId":""`} {
		c := testCollector(t, EventLimits{8, 2048, 8192, 1024})
		if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
			t.Fatal(err)
		}
		raw := `{"loaderId":"l","frameId":"f","type":"Document"` + identity + `,"response":{"url":"https://example.test/download","status":200,"headers":{"content-type":"application/pdf"}}}`
		if err := testEvent(t, c, "s", "Network.responseReceived", raw); err == nil {
			t.Fatal("uncorrelated response accepted")
		}
		if response, err := c.Snapshot(); err == nil || response.Status != 0 {
			t.Fatalf("metadata exposed without request identity: %+v %v", response, err)
		}
	}
}

func TestDocumentFailedLoadCannotBecomeComplete(t *testing.T) {
	c := testCollector(t, EventLimits{8, 2048, 8192, 1024})
	if err := c.ConfigureNavigation("s", "f", "l"); err != nil {
		t.Fatal(err)
	}
	for _, event := range []struct{ method, data string }{
		{"Network.requestWillBeSent", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","request":{"url":"https://example.test/start"}}`},
		{"Network.responseReceived", `{"requestId":"r","loaderId":"l","frameId":"f","type":"Document","response":{"url":"https://example.test/start","status":200,"headers":{}}}`},
		{"Network.loadingFailed", `{"requestId":"r"}`},
		{"Network.loadingFinished", `{"requestId":"r"}`},
	} {
		if err := testEvent(t, c, "s", event.method, event.data); err != nil {
			t.Fatal(err)
		}
	}
	if response, err := c.Snapshot(); err != nil || response.Complete || response.Status != 200 {
		t.Fatalf("failed load snapshot %+v %v", response, err)
	}
	if _, err := c.Result(); err == nil {
		t.Fatal("failed load became successful")
	}
}
