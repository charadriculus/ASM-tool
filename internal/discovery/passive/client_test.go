package passive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testHTTPClient(t *testing.T, transport http.RoundTripper, retries int) *Client {
	t.Helper()
	c, e := NewClient(HTTPPolicy{RequestsPerSecond: 10000, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: retries, CacheDir: t.TempDir(), CacheTTL: time.Hour, MaxResponseBytes: 128, MaxCacheBytes: 512, UserAgent: "ASM-test"}, &http.Client{Transport: transport})
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestGetJSONRetriesPerProviderAndBoundsBody(t *testing.T) {
	var calls atomic.Int32
	c := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		status, body := http.StatusOK, `{"ok":true}`
		if n == 1 {
			status, body = http.StatusTooManyRequests, `busy`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}), 2)
	if _, _, e := c.GetJSON(context.Background(), "crt.name", values("apex", "example.test"), "", nil); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 2 {
		t.Fatalf("attempts=%d, want retry after 429", calls.Load())
	}
	oversize := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 129))), Request: r}, nil
	}), 1)
	if _, _, e := oversize.GetJSON(context.Background(), "crt.name", nil, "", nil); e == nil {
		t.Fatal("oversized provider response accepted")
	}
}

func TestGetJSONUsesMarkedStaleCacheAfterFailure(t *testing.T) {
	first := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`[{"name":"x.example.test"}]`)), Request: r}, nil
	}), 1)
	params := values("q", "%.example.test")
	if _, _, e := first.GetJSON(context.Background(), "crt.sh", params, "same", nil); e != nil {
		t.Fatal(e)
	}
	first.policy.CacheTTL = 0
	second := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded }), 1)
	second.policy.CacheDir = first.policy.CacheDir
	second.policy.CacheTTL = 0
	b, m, e := second.GetJSON(context.Background(), "crt.sh", params, "same", nil)
	if e != nil || !m.CacheStale || m.ErrorType != "timeout" || !strings.Contains(string(b), "x.example.test") {
		t.Fatalf("stale fallback: body=%s meta=%+v err=%v", b, m, e)
	}
}

func TestStaleCacheNeverOverridesCancellation(t *testing.T) {
	seed := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	}), 1)
	params := values("apex", "example.test")
	if _, _, err := seed.GetJSON(context.Background(), "crt.name", params, "cancel", nil); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	c := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}), 1)
	c.policy.CacheDir = seed.policy.CacheDir
	c.policy.CacheTTL = 0
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := c.GetJSON(ctx, "crt.name", params, "cancel", nil); done <- err }()
	<-entered
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation replaced by cached result: %v", err)
	}
}

func TestRetryAfterParsingDistinguishesAbsentHeader(t *testing.T) {
	if _, ok := parseRetryAfter("", time.Now()); ok {
		t.Fatal("absent Retry-After parsed as valid")
	}
	if _, ok := parseRetryAfter("not-a-date", time.Now()); ok {
		t.Fatal("invalid Retry-After parsed as valid")
	}
	if d, ok := parseRetryAfter("3", time.Now()); !ok || d != 3*time.Second {
		t.Fatalf("delta Retry-After: %v %v", d, ok)
	}
	if d, ok := parseRetryAfter("999999999999999999999999999999", time.Now()); !ok || d != 20*time.Second {
		t.Fatalf("large Retry-After: %v %v", d, ok)
	}
}

func TestRetryAfterActuallyDelaysNextAttempt(t *testing.T) {
	var calls atomic.Int32
	c := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"2"}}, Body: io.NopCloser(strings.NewReader("slow down")), Request: r}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	}), 2)
	started := time.Now()
	if _, _, err := c.GetJSON(context.Background(), "crt.name", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if got := time.Since(started); got < 1900*time.Millisecond {
		t.Fatalf("Retry-After was not honored: %v", got)
	}
}

func TestGetJSONRejectsUnknownProviderAndCrossHostRedirect(t *testing.T) {
	c := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://elsewhere.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}), 1)
	if _, _, e := c.GetJSON(context.Background(), "user-url", nil, "", nil); e == nil {
		t.Fatal("unknown provider accepted")
	}
	if _, _, e := c.GetJSON(context.Background(), "crt.name", nil, "", nil); e == nil {
		t.Fatal("cross-host redirect accepted")
	}
	down := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://crt.name/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}), 1)
	if _, _, e := down.GetJSON(context.Background(), "crt.name", nil, "", nil); e == nil || !strings.Contains(e.Error(), "downgrade") {
		t.Fatalf("HTTPS downgrade accepted, err=%v", e)
	}
}

func TestNewClientDoesNotMutateCallerAndAllowsConfiguredRetryCount(t *testing.T) {
	called := false
	supplied := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { called = true; return nil }}
	client, err := NewClient(HTTPPolicy{RequestsPerSecond: 1, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: 11, MaxResponseBytes: 128, MaxCacheBytes: 512, UserAgent: "ASM-test"}, supplied)
	if err != nil {
		t.Fatal(err)
	}
	if client.http == supplied || client.http.CheckRedirect == nil {
		t.Fatal("provider client policy was not isolated")
	}
	if err := supplied.CheckRedirect(nil, nil); err != nil || !called {
		t.Fatalf("caller redirect policy changed: called=%v err=%v", called, err)
	}
}

func TestRedirectContactIsRateLimitedPerProvider(t *testing.T) {
	var calls atomic.Int32
	c := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		header := make(http.Header)
		status, body := http.StatusOK, `{"ok":true}`
		if n == 1 {
			status, body = http.StatusFound, ""
			header.Set("Location", "/redirected")
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}), 1)
	c.policy.RequestsPerSecond = 3
	started := time.Now()
	if _, _, err := c.GetJSON(context.Background(), "crt.sh", values("q", "example.test"), "", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("contacts=%d, want redirect and final response", calls.Load())
	}
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond {
		t.Fatalf("redirect bypassed provider limiter: %v", elapsed)
	}
}

func TestLogicalRequestTelemetrySeparatesCacheNetworkAndRetryAttempts(t *testing.T) {
	var calls atomic.Int32
	c := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		status, body := http.StatusOK, `{"ok":true}`
		if n == 1 {
			status, body = http.StatusTooManyRequests, `busy`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}), 2)
	params := values("q", "example.test")
	body, network, err := c.GetJSON(context.Background(), "crt.sh", params, "logical-telemetry", nil)
	if err != nil || string(body) != `{"ok":true}` {
		t.Fatalf("network result=%s meta=%+v err=%v", body, network, err)
	}
	if network.LogicalRequests != 1 || network.Attempts != 2 || calls.Load() != 2 {
		t.Fatalf("network request/retry counters: meta=%+v calls=%d", network, calls.Load())
	}
	_, cached, err := c.GetJSON(context.Background(), "crt.sh", params, "logical-telemetry", nil)
	if err != nil || !cached.CacheHit || cached.LogicalRequests != 0 || cached.Attempts != 0 || calls.Load() != 2 {
		t.Fatalf("cache counters: meta=%+v calls=%d err=%v", cached, calls.Load(), err)
	}
}

func TestStaleFallbackKeepsOneLogicalRequestAndAllAttempts(t *testing.T) {
	var seedCalls atomic.Int32
	seed := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seedCalls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"cached":true}`)), Request: r}, nil
	}), 1)
	params := values("q", "example.test")
	if _, _, err := seed.GetJSON(context.Background(), "crt.sh", params, "stale-telemetry", nil); err != nil {
		t.Fatal(err)
	}
	seed.policy.CacheTTL = 0
	var calls atomic.Int32
	stale := testHTTPClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("busy")), Request: r}, nil
	}), 2)
	stale.policy.CacheDir = seed.policy.CacheDir
	stale.policy.CacheTTL = 0
	body, meta, err := stale.GetJSON(context.Background(), "crt.sh", params, "stale-telemetry", nil)
	if err != nil || string(body) != `{"cached":true}` || !meta.CacheStale || meta.FallbackAfterError == "" {
		t.Fatalf("stale response=%s meta=%+v err=%v", body, meta, err)
	}
	if meta.LogicalRequests != 1 || meta.Attempts != 2 || calls.Load() != 2 {
		t.Fatalf("stale retry counters: meta=%+v calls=%d", meta, calls.Load())
	}
}
