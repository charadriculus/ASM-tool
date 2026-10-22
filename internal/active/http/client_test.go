package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"golang.org/x/text/encoding/charmap"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server, *int, string) {
	t.Helper()
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; handler(w, r) }))
	u, _ := url.Parse(s.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}})
	ev := map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}}
	idx.Ingest(ev)
	var emitted int
	c, err := NewClient(Config{Policy: core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { emitted++; return nil }, UserAgent: "test", PerHostRequests: 10, GlobalConcurrency: 2, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return c, s, &emitted, fmt.Sprintf("http://example.test:%s/", port)
}
func TestFetchPinsConfirmedIPAndRejectsRedirectBeforeContact(t *testing.T) {
	c, s, emitted, target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "example.test:") {
			t.Errorf("Host=%q", r.Host)
		}
		if r.URL.Path == "/" {
			http.Redirect(w, r, "http://outside.test/", http.StatusFound)
			return
		}
		http.Error(w, "unexpected", 500)
	})
	r, err := c.Fetch(context.Background(), target, Options{MaxRedirects: 3, TLS: VerifiedTLS})
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusFound || !r.RedirectOutOfScope || len(r.RedirectChain) != 1 {
		t.Fatalf("unexpected redirect record: %+v", r)
	}
	if got := strings.TrimSpace(s.URL); got == "" {
		t.Fatal("loopback server missing")
	}
	if *emitted != 1 {
		t.Fatalf("durable event count=%d", *emitted)
	}
}
func TestFetchRequiresEligibleDNSAndAuthorization(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	u, _ := url.Parse(s.URL)
	c, _, _, _ := testClient(t, func(_ http.ResponseWriter, _ *http.Request) {})
	if _, err := c.Fetch(context.Background(), "http://outside.test/", Options{}); err == nil {
		t.Fatal("out-of-scope target accepted")
	}
	if _, err := NewClient(Config{Policy: core.ScopePolicy{AllowedDomains: []string{"example.test"}}, Profile: "passive", Index: evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}}), Emit: func(core.Event) error { return nil }, PerHostRequests: 1, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second}); err == nil {
		t.Fatal("passive profile accepted active HTTP")
	}
	_ = u
}

func TestNativeHTTPXRequiresExplicitFallbackAndRecordsDecision(t *testing.T) {
	var contacts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	index := evidence.NewDNSRunIndex(policy)
	index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	var events []core.Event
	base := Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: func(e core.Event) error { events = append(events, e); return nil }, PerHostRequests: 1, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second, HTTPProbeBackend: "projectdiscovery_httpx"}
	if _, err := NewClient(base); err == nil || !strings.Contains(err.Error(), "explicit") {
		t.Fatalf("native backend without consent error=%v", err)
	}
	if contacts.Load() != 0 || len(events) != 1 || events[0].EventType != core.Limitation || events[0].Metadata["fallback_used"] != false {
		t.Fatalf("blocked backend contacted target or failed to persist decision: contacts=%d events=%+v", contacts.Load(), events)
	}

	events = nil
	base.AllowFallback = true
	c, err := NewClient(base)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Fetch(context.Background(), "http://example.test:"+port+"/", Options{})
	if err != nil || r.StatusCode != http.StatusNoContent || contacts.Load() != 1 {
		t.Fatalf("explicit local fallback result=%+v err=%v contacts=%d", r, err, contacts.Load())
	}
	if r.BackendResolution.Requested != "projectdiscovery_httpx" || r.BackendResolution.Actual != "go_net_http" || r.BackendResolution.Status != "fallback" || !r.BackendResolution.Available || !r.BackendResolution.FallbackUsed || r.BackendResolution.FallbackReason != "user_explicit_policy" || r.BackendResolution.ActualVersion != "" || r.BackendResolution.PinnedVersion != "1.8.1" {
		t.Fatalf("response backend resolution=%+v", r.BackendResolution)
	}
	if len(events) != 2 || events[0].EventType != core.Limitation || events[0].Metadata["fallback_reason"] != "user_explicit_policy" || events[0].Metadata["backend_pinned_version"] != "1.8.1" || events[1].Metadata["backend_requested"] != "projectdiscovery_httpx" || events[1].Metadata["backend_actual"] != "go_net_http" || events[1].Metadata["backend_pinned_version"] != "1.8.1" || events[1].Metadata["fallback_used"] != true || events[1].Metadata["fallback_reason"] != "user_explicit_policy" {
		t.Fatalf("fallback provenance missing: %+v", events)
	}
	if _, err := c.Fetch(context.Background(), "http://example.test:"+port+"/", Options{}); err == nil || contacts.Load() != 1 {
		t.Fatalf("fallback bypassed host quota: err=%v contacts=%d", err, contacts.Load())
	}
	if _, err := c.Fetch(context.Background(), "http://outside.test/", Options{}); err == nil || contacts.Load() != 1 {
		t.Fatalf("fallback bypassed scope: err=%v contacts=%d", err, contacts.Load())
	}
}

func TestNativeHTTPXFallbackRequiresDurableDecisionEvent(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	_, err := NewClient(Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return errors.New("disk failure") }, PerHostRequests: 1, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second, HTTPProbeBackend: "projectdiscovery_httpx", AllowFallback: true})
	if !errors.Is(err, ErrEventSink) {
		t.Fatalf("sink error=%v", err)
	}
}

func TestHTTPBackendAliasesAndUnknownNames(t *testing.T) {
	for _, name := range []string{"", "go_net_http", "python_requests"} {
		r, err := resolveHTTPBackend(name, false)
		if err != nil || r.Actual != "go_net_http" || r.FallbackUsed {
			t.Errorf("ordinary backend %q: resolution=%+v err=%v", name, r, err)
		}
	}
	if _, err := resolveHTTPBackend("made_up", true); err == nil {
		t.Fatal("unknown backend silently fell back")
	}
}
func TestFetchBodyLimitAndSinkFailure(t *testing.T) {
	c, _, emitted, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+32)))
	})
	r, err := c.Fetch(context.Background(), target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Body) != MaxResponseBytes || !r.BodyTruncated {
		t.Fatalf("body len=%d truncated=%v", len(r.Body), r.BodyTruncated)
	}
	if *emitted != 1 {
		t.Fatalf("emitted=%d", *emitted)
	}
	c.c.Emit = func(core.Event) error { return errors.New("disk full") }
	if _, err := c.Fetch(context.Background(), target, Options{}); err == nil || !strings.Contains(err.Error(), "persist HTTP evidence") {
		t.Fatalf("sink failure was not returned: %v", err)
	}
}

func TestFetchDecodesCompressedBodiesAndPreservesWireHeaders(t *testing.T) {
	plain := []byte("<title>compressed evidence</title>")
	for _, tc := range []struct {
		name, encoding string
		compress       func([]byte) ([]byte, error)
	}{
		{"gzip", "gzip", func(src []byte) ([]byte, error) {
			var b bytes.Buffer
			w := gzip.NewWriter(&b)
			if _, err := w.Write(src); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return b.Bytes(), nil
		}},
		{"deflate", "deflate", func(src []byte) ([]byte, error) {
			var b bytes.Buffer
			w := zlib.NewWriter(&b)
			if _, err := w.Write(src); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return b.Bytes(), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compressed, err := tc.compress(plain)
			if err != nil {
				t.Fatal(err)
			}
			c, _, _, target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Accept-Encoding"); got != "gzip, deflate" {
					t.Errorf("Accept-Encoding=%q", got)
				}
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
				_, _ = w.Write(compressed)
			})
			got, err := c.Fetch(context.Background(), target, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Body, plain) || got.Title != "compressed evidence" {
				t.Fatalf("decoded body/title = %q / %q", got.Body, got.Title)
			}
			if got.Headers["content-encoding"] != tc.encoding || got.Headers["content-length"] != strconv.Itoa(len(compressed)) {
				t.Fatalf("wire headers not preserved: %#v", got.Headers)
			}
		})
	}
}

func TestFetchLimitsDecodedCompressedBody(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(bytes.Repeat([]byte("x"), MaxResponseBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	c, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	})
	got, err := c.Fetch(context.Background(), target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Body) != MaxResponseBytes || !got.BodyTruncated {
		t.Fatalf("decoded length=%d truncated=%v", len(got.Body), got.BodyTruncated)
	}
}

func TestFetchMalformedCompressedBodyPersistsResponseEvidence(t *testing.T) {
	c, _, emitted, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("not a gzip stream"))
	})
	got, err := c.Fetch(context.Background(), target, Options{})
	if err == nil || got.Error == "" || got.StatusCode != http.StatusOK {
		t.Fatalf("malformed compressed response not reported: response=%+v err=%v", got, err)
	}
	if *emitted != 1 {
		t.Fatalf("partial response evidence events=%d", *emitted)
	}
}

func TestPerHostQuotaSpansPortAndEmitsRefusal(t *testing.T) {
	c, _, emitted, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	c.c.PerHostRequests = 1
	if _, err := c.Fetch(context.Background(), target, Options{}); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(target)
	port, _ := strconv.Atoi(u.Port())
	u.Host = net.JoinHostPort("example.test", strconv.Itoa(port+1))
	if _, err := c.Fetch(context.Background(), u.String(), Options{}); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("second scheme/port bypassed hostname quota: %v", err)
	}
	if *emitted != 2 {
		t.Fatalf("HTTP result/refusal events=%d", *emitted)
	}
}

func TestStopStatusPreventsLaterHostContact(t *testing.T) {
	c, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	if r, err := c.Fetch(context.Background(), target, Options{}); err != nil || r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first response: status=%d err=%v", r.StatusCode, err)
	}
	if _, err := c.Fetch(context.Background(), target, Options{}); err == nil || !strings.Contains(err.Error(), "stopped after status 429") {
		t.Fatalf("subsequent host request was not stopped: %v", err)
	}
}

func TestConfiguredStopStatusesDriveHTTPAndWebStopPolicy(t *testing.T) {
	base, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	cfg := base.c
	cfg.StopStatuses = []int{http.StatusServiceUnavailable}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Fetch(context.Background(), target, Options{})
	if err != nil || !first.StopStatus {
		t.Fatalf("configured 503 stop result=%+v err=%v", first, err)
	}
	if _, err = client.Fetch(context.Background(), target, Options{}); err == nil || !strings.Contains(err.Error(), "stopped after status 503") {
		t.Fatalf("configured stop status did not block later contact: %v", err)
	}

	var calls atomic.Int32
	base, _, _, target = testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	cfg = base.c
	cfg.StopStatuses = []int{} // Explicit empty policy disables the legacy defaults.
	client, err = NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err = client.Fetch(context.Background(), target, Options{})
	if err != nil || first.StopStatus {
		t.Fatalf("explicit empty policy acquired implicit default: response=%+v err=%v", first, err)
	}
	second, err := client.Fetch(context.Background(), target, Options{})
	if err != nil || second.StatusCode != http.StatusOK {
		t.Fatalf("explicit empty policy stopped after 429: response=%+v err=%v", second, err)
	}
}

func TestNewClientRejectsInvalidStopStatus(t *testing.T) {
	base, _, _, _ := testClient(t, func(http.ResponseWriter, *http.Request) {})
	cfg := base.c
	cfg.StopStatuses = []int{99}
	if _, err := NewClient(cfg); err == nil {
		t.Fatal("invalid stop status accepted")
	}
}

func TestAdmissionRejectsNearMatchEligibilityAndUnspecifiedEvenWithCIDR(t *testing.T) {
	c, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	idx := evidence.NewDNSRunIndex(c.c.Policy)
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "2", "metadata": map[string]any{"active_eligibility": "eligible_but_not_eligible", "terminal_ips": []any{"127.0.0.1"}}})
	c.c.Index = idx
	if _, err := c.Fetch(context.Background(), target, Options{}); err == nil || !strings.Contains(err.Error(), "lacks eligible") {
		t.Fatalf("near-match eligibility accepted: %v", err)
	}
	c.c.Policy.AllowedCIDRs = []string{"0.0.0.0/0"}
	if _, err := c.Fetch(context.Background(), "http://0.0.0.0/", Options{}); err == nil || !strings.Contains(err.Error(), "unspecified") {
		t.Fatalf("unspecified address admitted by CIDR: %v", err)
	}
	if _, err := c.Fetch(context.Background(), "http://[::ffff:0.0.0.0]/", Options{}); err == nil {
		t.Fatalf("IPv4-mapped unspecified address admitted by CIDR: %v", err)
	}
}

func TestRoundUsesOnlyFirstAdmittedTerminalAddress(t *testing.T) {
	c, server, _, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	u, _ := url.Parse(server.URL)
	u.Host = "example.test:" + u.Port()
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}
	resp, ip, err := c.round(context.Background(), u, ips, false)
	if err == nil || resp != nil || ip != "" {
		t.Fatalf("round retried another terminal address: resp=%v ip=%q err=%v", resp, ip, err)
	}
}

func TestPartialBodyReadFailurePersistsResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var hits int
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 2048)
		_, _ = conn.Read(buf)
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\npartial")
	}()
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}})
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	var event core.Event
	c, err := NewClient(Config{Policy: core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}, Profile: "verify", Authorized: true, Index: idx, Emit: func(e core.Event) error { event = e; hits++; return nil }, PerHostRequests: 2, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	r, err := c.Fetch(context.Background(), "http://example.test:"+port+"/", Options{})
	if err == nil || r.StatusCode != http.StatusOK || string(r.Body) != "partial" || hits != 1 || event.Metadata["status_code"] != http.StatusOK || event.Metadata["error"] == nil {
		t.Fatalf("partial response was not persisted: response=%+v event=%+v err=%v emits=%d", r, event, err, hits)
	}
}

func TestBodyPreviewLimitCountsUnicodeCharacters(t *testing.T) {
	c, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("é", 520))) })
	r, err := c.Fetch(context.Background(), target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := len([]rune(r.BodyPreview)); got != 512 || strings.ContainsRune(r.BodyPreview, '\uFFFD') {
		t.Fatalf("preview must retain 512 complete characters: runes=%d bytes=%d", got, len(r.BodyPreview))
	}
	if r.BodyTruncated {
		t.Fatal("preview-only cap incorrectly marked response body truncated")
	}
}

func TestStopStatusPublishedBeforeQueuedRequestContactsHost(t *testing.T) {
	var hits atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	base, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			close(started)
			<-release
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	cfg := base.c
	cfg.StopStatuses = []int{http.StatusServiceUnavailable}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var emitted atomic.Int32
	if err := c.SetEventSink(func(core.Event) error { emitted.Add(1); return nil }); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { _, err := c.Fetch(context.Background(), target, Options{}); firstDone <- err }()
	<-started
	secondDone := make(chan error, 1)
	go func() { _, err := c.Fetch(context.Background(), target, Options{}); secondDone <- err }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		queued := c.counts["example.test"] == 2
		c.mu.Unlock()
		if queued {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	queued := c.counts["example.test"] == 2
	c.mu.Unlock()
	if !queued {
		close(release)
		t.Fatal("second request did not reach the queued admission")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := <-secondDone; err == nil || !strings.Contains(err.Error(), "stopped after status 503") {
		t.Fatalf("queued request result=%v", err)
	}
	if hits.Load() != 1 || emitted.Load() != 2 {
		t.Fatalf("host contacts=%d event records=%d, want 1/2", hits.Load(), emitted.Load())
	}
	c.mu.Lock()
	quotaUsed := c.counts["example.test"]
	c.mu.Unlock()
	if quotaUsed != 1 {
		t.Fatalf("queued no-contact stop refusal consumed quota: used=%d want=1", quotaUsed)
	}
}

func TestStopStatusIsPublishedAtHeadersBeforeBodyFinishesAcrossOrigins(t *testing.T) {
	headers, release := make(chan struct{}), make(chan struct{})
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.(http.Flusher).Flush()
		close(headers)
		<-release
	}))
	defer first.Close()
	var secondHits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()
	base, _, _, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cfg := base.c
	cfg.StopStatuses = []int{http.StatusTooManyRequests}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstURL := "http://example.test:" + strings.TrimPrefix(first.URL, "http://127.0.0.1:") + "/"
	secondURL := "http://example.test:" + strings.TrimPrefix(second.URL, "http://127.0.0.1:") + "/"
	firstDone := make(chan error, 1)
	go func() { _, e := c.Fetch(context.Background(), firstURL, Options{}); firstDone <- e }()
	select {
	case <-headers:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first response headers were not served")
	}
	deadline := time.Now().Add(time.Second)
	for c.stoppedStatus("example.test") == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.stoppedStatus("example.test") != http.StatusTooManyRequests {
		close(release)
		t.Fatal("stop status was not recorded before response body completed")
	}
	_, err = c.Fetch(context.Background(), secondURL, Options{})
	if err == nil || !strings.Contains(err.Error(), "stopped after status 429") || secondHits.Load() != 0 {
		close(release)
		t.Fatalf("cross-origin queued request escaped stop status: err=%v contacts=%d", err, secondHits.Load())
	}
	close(release)
	if err = <-firstDone; err != nil {
		t.Fatalf("first response: %v", err)
	}
}

func TestOriginPermitWaitDoesNotOccupyGlobalRequestSlot(t *testing.T) {
	firstStarted, otherStarted, releaseFirst := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasPrefix(r.Host, "a.example.test:") {
			if r.URL.Path == "/one" {
				close(firstStarted)
				<-releaseFirst
			}
		} else if strings.HasPrefix(r.Host, "b.example.test:") {
			close(otherStarted)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port := u.Port()
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	index := evidence.NewDNSRunIndex(policy)
	for i, name := range []string{"a.example.test", "b.example.test"} {
		index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": name, "observed_at": strconv.Itoa(i + 1), "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	}
	c, err := NewClient(Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: func(core.Event) error { return nil }, PerHostRequests: 4, GlobalConcurrency: 2, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	targetA := "http://a.example.test:" + port
	targetB := "http://b.example.test:" + port
	firstDone := make(chan error, 1)
	go func() { _, e := c.Fetch(context.Background(), targetA+"/one", Options{}); firstDone <- e }()
	<-firstStarted
	secondDone := make(chan error, 1)
	go func() { _, e := c.Fetch(context.Background(), targetA+"/two", Options{}); secondDone <- e }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		waiting := c.counts["a.example.test"] == 2
		c.mu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	otherDone := make(chan error, 1)
	go func() {
		_, e := c.Fetch(context.Background(), targetB+"/fast", Options{})
		otherDone <- e
	}()
	select {
	case <-otherStarted:
	case <-time.After(500 * time.Millisecond):
		close(releaseFirst)
		t.Fatal("same-origin waiter occupied the free global request slot")
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if err := <-otherDone; err != nil {
		t.Fatalf("independent origin request: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("contacts=%d want=3", hits.Load())
	}
}

func TestHTMLCharsetDecodingPreservesRawEvidenceAndTitle(t *testing.T) {
	body := []byte("<meta charset=windows-1251><title>Привет</title>")
	encoded, err := charmap.Windows1251.NewEncoder().Bytes(body)
	if err != nil {
		t.Fatal(err)
	}
	c, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1251")
		_, _ = w.Write(encoded)
	})
	got, err := c.Fetch(context.Background(), target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Привет" || !strings.Contains(got.BodyPreview, "Привет") {
		t.Fatalf("charset text lost: title=%q preview=%q", got.Title, got.BodyPreview)
	}
	if !bytes.Equal(got.Body, encoded) {
		t.Fatal("raw response evidence was decoded or modified")
	}
	if got.ContentLength != int64(len(encoded)) {
		t.Fatalf("wire Content-Length=%d want %d", got.ContentLength, len(encoded))
	}

	features, err := backends.ParseHTML("İ<title>X</title>")
	if err != nil || features.Title != "X" {
		t.Fatalf("Unicode before title broke extraction: %+v err=%v", features, err)
	}
}

func TestAdmissionAllowsExplicitIPv6CIDRRoot(t *testing.T) {
	base, _, _, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	base.c.Policy.AllowedCIDRs = []string{"::1/128"}
	u, err := parseURL("http://[::1]:8443/")
	if err != nil {
		t.Fatal(err)
	}
	ips, err := base.admit(u)
	if err != nil || len(ips) != 1 || ips[0].String() != "::1" {
		t.Fatalf("explicit IPv6 CIDR admission: ips=%v err=%v", ips, err)
	}
}

func TestFailedRequestHasSourceRecordProvenanceAndNullStatus(t *testing.T) {
	c, server, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server.Close()
	var event core.Event
	if err := c.SetEventSink(func(e core.Event) error { event = e; return nil }); err != nil {
		t.Fatal(err)
	}
	_, err := c.Fetch(context.Background(), target, Options{})
	if !errors.Is(err, ErrCollection) {
		t.Fatalf("connection failure classification: %v", err)
	}
	if event.Metadata["status_code"] != nil || event.Metadata["content_length"] != nil || event.Metadata["backend_actual"] != "go_net_http" || event.Metadata["fallback_used"] != false || event.Confidence != 0.2 {
		t.Fatalf("failed request record lost source-shaped metadata: %+v", event.Metadata)
	}
	if len(event.Metadata["technologies"].([]string)) != 0 || len(event.Metadata["tls"].(map[string]any)) != 0 {
		t.Fatalf("unexpected enrichment for failed transport: %+v", event.Metadata)
	}
}

func TestSuccessfulHTTPEventUsesSourceConfidence(t *testing.T) {
	c, _, _, target := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	var event core.Event
	if err := c.SetEventSink(func(e core.Event) error { event = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(context.Background(), target, Options{}); err != nil {
		t.Fatal(err)
	}
	if event.EventType != core.HTTPProbeResult || event.Confidence != 0.75 {
		t.Fatalf("successful HTTP event confidence=%v type=%s", event.Confidence, event.EventType)
	}
}

func TestPhase5HTTPErrorClassificationFixture(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Groups struct {
			HTTP struct {
				Expected struct {
					Records map[string]json.RawMessage `json:"records"`
					Classes map[string]string          `json:"error_classes"`
				} `json:"expected"`
			} `json:"http_records_redirects"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Groups.HTTP.Expected.Records) != 4 || len(fixture.Groups.HTTP.Expected.Classes) != 6 {
		t.Fatalf("HTTP source oracle cases: records=%d errors=%d, want 4/6", len(fixture.Groups.HTTP.Expected.Records), len(fixture.Groups.HTTP.Expected.Classes))
	}
	for input, want := range fixture.Groups.HTTP.Expected.Classes {
		if got := classify(errors.New(input)); got != want {
			t.Errorf("classify(%q)=%q want %q", input, got, want)
		}
	}
}

func TestPhase5HTTPRedirectOracleAllFourCases(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups struct {
			HTTP struct {
				Expected struct {
					Redirects map[string]struct {
						Candidate any `json:"candidate"`
						Record    struct {
							Status     int        `json:"status_code"`
							Location   string     `json:"location"`
							ErrorClass string     `json:"error_classification"`
							OutOfScope bool       `json:"redirect_out_of_scope"`
							Chain      []Redirect `json:"redirect_chain"`
						} `json:"record"`
					} `json:"redirects"`
				} `json:"expected"`
			} `json:"http_records_redirects"`
		} `json:"groups"`
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Groups.HTTP.Expected.Redirects) != 4 {
		t.Fatalf("source redirect cases=%d want=4", len(f.Groups.HTTP.Expected.Redirects))
	}
	for name, want := range f.Groups.HTTP.Expected.Redirects {
		loc := want.Record.Location
		c, server, _, target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		if name == "budget_exhausted" {
			c.c.PerHostRequests = 1
		}
		got, fetchErr := c.Fetch(context.Background(), target, Options{MaxRedirects: 3})
		if len(got.RedirectChain) != len(want.Record.Chain)+1 && len(want.Record.Chain) > 0 {
			t.Fatalf("%s redirect chain=%+v fixture=%+v", name, got.RedirectChain, want.Record.Chain)
		}
		if len(got.RedirectChain) == 0 || got.RedirectChain[0].Status != want.Record.Status || got.RedirectChain[0].Location != want.Record.Location {
			t.Errorf("%s redirect record=%+v want status/location=%d/%q", name, got.RedirectChain, want.Record.Status, want.Record.Location)
		}
		switch name {
		case "relative":
			if fetchErr != nil || got.FinalURL != strings.TrimSuffix(target, "/")+"/next" || got.RedirectOutOfScope {
				t.Errorf("relative redirect result=%+v err=%v", got, fetchErr)
			}
		case "offscope", "invalid_scheme":
			if fetchErr != nil || !got.RedirectOutOfScope || got.StatusCode != http.StatusFound {
				t.Errorf("rejected redirect result=%+v err=%v", got, fetchErr)
			}
		case "budget_exhausted":
			if !errors.Is(fetchErr, ErrCollection) || got.ErrorClass != want.Record.ErrorClass || got.ErrorClass != "budget" {
				t.Errorf("budget redirect result=%+v err=%v", got, fetchErr)
			}
		}
		_ = server
	}
}

// Verify the transmitted identity, including preservation of explicit overrides.
func TestHTTPUserAgentCurrentVersionAndOverride(t *testing.T) {
	for _, tc := range []struct{ name, configured, want string }{
		{"default", "", config.UserAgent}, {"override", "Owner custom agent", "Owner custom agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := make(chan string, 1)
			base, _, _, target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				observed <- r.UserAgent()
				w.WriteHeader(http.StatusNoContent)
			})
			cfg := base.c
			cfg.UserAgent = tc.configured
			c, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			response, err := c.Fetch(context.Background(), target, Options{})
			if err != nil || response.StatusCode != http.StatusNoContent {
				t.Fatalf("local response=%+v error=%v", response, err)
			}
			select {
			case got := <-observed:
				if got != tc.want {
					t.Fatalf("User-Agent=%q, want %q", got, tc.want)
				}
			default:
				t.Fatal("no local request was recorded")
			}
		})
	}
}
