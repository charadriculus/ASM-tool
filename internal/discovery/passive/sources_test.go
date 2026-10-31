package passive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sourceFixture struct {
	Inputs  map[string]json.RawMessage `json:"inputs"`
	Outputs map[string]json.RawMessage `json:"outputs"`
}

func loadSourceFixture(t *testing.T) sourceFixture {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/phase4/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f sourceFixture
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func fixtureClient(t *testing.T, response func(*http.Request) (int, any)) *Client {
	t.Helper()
	c, err := NewClient(HTTPPolicy{RequestsPerSecond: 10000, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: 1, CacheDir: t.TempDir(), CacheTTL: time.Hour, MaxResponseBytes: 1 << 20, MaxCacheBytes: 2 << 20, UserAgent: "ASM local fixture"}, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status, data := response(r)
		body, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fixtureCase(t *testing.T, f sourceFixture, name string, out any) json.RawMessage {
	t.Helper()
	if err := json.Unmarshal(f.Inputs[name], out); err != nil {
		t.Fatalf("input %s: %v", name, err)
	}
	return f.Outputs[name]
}

func TestPassiveProviderParsersMatchSourceFixtures(t *testing.T) {
	f := loadSourceFixture(t)
	t.Run("crt.name envelopes and mapping", func(t *testing.T) {
		for _, key := range []string{"crtname_envelopes", "crtname_mapping"} {
			t.Run(key, func(t *testing.T) {
				var in struct {
					Responses []any `json:"responses"`
				}
				want := fixtureCase(t, f, key, &in)
				c := fixtureClient(t, func(*http.Request) (int, any) { return http.StatusOK, in.Responses[0] })
				got, err := CRTName(context.Background(), c, "example.test", "example.test", 0)
				if err != nil {
					t.Fatal(err)
				}
				var expected struct {
					Value []map[string]any `json:"value"`
				}
				if err = json.Unmarshal(want, &expected); err != nil {
					t.Fatal(err)
				}
				rows := make([]map[string]any, 0, len(got.Observations))
				for _, o := range got.Observations {
					var first any
					if o.FirstSeen != "" {
						first = o.FirstSeen
					}
					rows = append(rows, map[string]any{"hostname": o.Hostname, "first_seen_by_crt_name": first})
				}
				if !reflect.DeepEqual(rows, expected.Value) {
					t.Fatalf("rows=%v want=%v", rows, expected.Value)
				}
			})
		}
	})
	t.Run("crt.name malformed envelope remains incomplete", func(t *testing.T) {
		c := fixtureClient(t, func(*http.Request) (int, any) { return http.StatusOK, "unexpected scalar" })
		got, err := CRTName(context.Background(), c, "example.test", "example.test", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "partial" || got.Completeness != "pagination_incomplete" || got.Error == "" || len(got.Observations) != 0 {
			t.Fatalf("malformed response was reported as complete/no-data: %+v", got)
		}
	})
	t.Run("crt.name numeric first-seen and earliest selection", func(t *testing.T) {
		c := fixtureClient(t, func(*http.Request) (int, any) {
			return http.StatusOK, map[string]any{"results": []any{
				map[string]any{"name": "n.example.test", "first_seen": json.Number("1700000000")},
				map[string]any{"name": "n.example.test", "first_seen": json.Number("1600000000")},
			}}
		})
		got, err := CRTName(context.Background(), c, "example.test", "example.test", 0)
		if err != nil || len(got.Observations) != 1 || got.Observations[0].FirstSeen != "1600000000" {
			t.Fatalf("numeric first-seen lost: %+v err=%v", got, err)
		}
	})
	t.Run("crt.sh", func(t *testing.T) {
		for _, key := range []string{"crtsh", "crtsh_zero"} {
			t.Run(key, func(t *testing.T) {
				var in struct {
					Cap       int     `json:"cap"`
					Responses [][]any `json:"responses"`
				}
				want := fixtureCase(t, f, key, &in)
				c := fixtureClient(t, func(*http.Request) (int, any) { return http.StatusOK, in.Responses[0] })
				got, err := CRTSh(context.Background(), c, "example.test", in.Cap)
				if err != nil {
					t.Fatal(err)
				}
				var expected struct {
					Value []string `json:"value"`
				}
				if err = json.Unmarshal(want, &expected); err != nil {
					t.Fatal(err)
				}
				names := make([]string, 0, len(got.Observations))
				for _, o := range got.Observations {
					names = append(names, o.Hostname)
				}
				if !reflect.DeepEqual(names, expected.Value) {
					t.Fatalf("names=%v want=%v", names, expected.Value)
				}
			})
		}
	})
	for _, key := range []string{"certspotter_pages", "certspotter_repeat_cursor", "certspotter_cap", "certspotter_malformed"} {
		t.Run(key, func(t *testing.T) {
			var in struct {
				Cap       int               `json:"cap"`
				Responses []json.RawMessage `json:"responses"`
			}
			want := fixtureCase(t, f, key, &in)
			var calls []string
			index := 0
			c := fixtureClient(t, func(req *http.Request) (int, any) {
				calls = append(calls, req.URL.Query().Get("after"))
				var data any
				if index < len(in.Responses) {
					_ = json.Unmarshal(in.Responses[index], &data)
				}
				index++
				return http.StatusOK, data
			})
			got, err := CertSpotter(context.Background(), c, "example.test", in.Cap)
			if err != nil {
				t.Fatal(err)
			}
			var expected struct {
				Value []string         `json:"value"`
				Calls []map[string]any `json:"calls"`
			}
			if err = json.Unmarshal(want, &expected); err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(got.Observations))
			for _, o := range got.Observations {
				names = append(names, o.Hostname)
			}
			if !reflect.DeepEqual(names, expected.Value) {
				t.Fatalf("names=%v want=%v status=%s completeness=%s error=%s", names, expected.Value, got.Status, got.Completeness, got.Error)
			}
			if len(calls) != len(expected.Calls) {
				t.Fatalf("cursors=%v want calls=%d", calls, len(expected.Calls))
			}
			for i, call := range expected.Calls {
				params, _ := call["params"].(map[string]any)
				wantAfter, _ := params["after"].(string)
				if calls[i] != wantAfter {
					t.Fatalf("cursor[%d]=%q want %q", i, calls[i], wantAfter)
				}
			}
			switch key {
			case "certspotter_cap":
				if got.Status != "partial" || got.Completeness != "pagination_incomplete" || !got.Truncated || got.TruncationReason == "" {
					t.Fatalf("cap was not marked incomplete: %+v", got)
				}
			case "certspotter_repeat_cursor":
				if got.Status != "partial" || got.Completeness != "pagination_incomplete" || got.Truncated || !strings.Contains(got.Error, "repeated pagination cursor") {
					t.Fatalf("repeated cursor not marked incomplete: %+v", got)
				}
			case "certspotter_malformed":
				if got.Status != "partial" || got.Completeness != "pagination_incomplete" || got.Truncated || got.Error == "" {
					t.Fatalf("malformed page was not marked incomplete: %+v", got)
				}
			case "certspotter_pages":
				if got.Status != "ok" || got.Completeness != "complete" || got.Truncated {
					t.Fatalf("exhausted pages not marked complete: %+v", got)
				}
			}
		})
	}
}

func TestCertSpotterNumericMixedCaseCursorIsPreserved(t *testing.T) {
	var after string
	calls := 0
	c := fixtureClient(t, func(req *http.Request) (int, any) {
		calls++
		after = req.URL.Query().Get("after")
		if calls == 1 {
			return http.StatusOK, []any{map[string]any{"id": json.Number("123456789"), "dns_names": []string{"one.example.test"}}}
		}
		return http.StatusOK, []any{}
	})
	got, err := CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || calls != 2 || after != "123456789" || got.Status != "ok" || got.Completeness != "complete" {
		t.Fatalf("numeric cursor mishandled: calls=%d after=%q result=%+v err=%v", calls, after, got, err)
	}

	after = ""
	calls = 0
	c = fixtureClient(t, func(req *http.Request) (int, any) {
		calls++
		after = req.URL.Query().Get("after")
		if calls == 1 {
			return http.StatusOK, []any{map[string]any{"id": "AbC-9", "dns_names": []string{"one.example.test"}}}
		}
		return http.StatusOK, []any{}
	})
	if _, err = CertSpotter(context.Background(), c, "example.test", 0); err != nil || after != "AbC-9" {
		t.Fatalf("case-sensitive cursor altered: after=%q err=%v", after, err)
	}
}

func TestCertSpotterPageFailureKeepsPartialNamesWithoutReturningError(t *testing.T) {
	calls := 0
	c := fixtureClient(t, func(*http.Request) (int, any) {
		calls++
		if calls == 1 {
			return http.StatusOK, []any{map[string]any{"id": "page-1", "dns_names": []string{"kept.example.test"}}}
		}
		return http.StatusServiceUnavailable, map[string]any{"error": "local fixture failure"}
	})
	got, err := CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || got.Status != "partial" || got.Completeness != "partial_transport_failure" || got.Error == "" || len(got.Observations) != 1 || got.Observations[0].Hostname != "kept.example.test" {
		t.Fatalf("page failure lost partial result: result=%+v err=%v", got, err)
	}
}

func TestCertSpotterMergesStaleAndFreshPageMetadata(t *testing.T) {
	calls := 0
	c, err := NewClient(HTTPPolicy{RequestsPerSecond: 10000, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: 1, CacheDir: t.TempDir(), CacheTTL: time.Hour, MaxResponseBytes: 1 << 20, MaxCacheBytes: 2 << 20, UserAgent: "ASM local fixture"}, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		status, body := http.StatusOK, `[{"id":"p1","dns_names":["cached.example.test"]}]`
		if calls == 2 {
			status, body = http.StatusServiceUnavailable, `{"error":"fixture outage"}`
		}
		if calls >= 3 {
			status, body = http.StatusOK, `[]`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	params := values("domain", "example.test", "include_subdomains", "true", "match_wildcards", "true", "expand", "dns_names")
	if _, _, err = c.GetJSON(context.Background(), "certspotter", params, "certspotter:example.test:cursor:", nil); err != nil {
		t.Fatal(err)
	}
	c.policy.CacheTTL = 0
	got, err := CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || got.Meta.StatusCode != http.StatusOK || !got.Meta.CacheStale || got.Meta.FallbackAfterError == "" || len(got.Observations) != 1 || got.Observations[0].Hostname != "cached.example.test" {
		t.Fatalf("stale/fresh metadata merge lost state: result=%+v err=%v", got, err)
	}
	if got.Meta.LogicalRequests != 2 || got.Meta.Attempts != 2 {
		t.Fatalf("mixed stale/fresh pages must count logical requests and attempts independently: %+v", got.Meta)
	}
	c.policy.CacheTTL = time.Hour
	contactsBefore := calls
	got, err = CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || got.Status != "ok" || len(got.Observations) != 1 || !got.Meta.CacheHit || got.Meta.LogicalRequests != 0 || got.Meta.Attempts != 0 || got.PagesAttempted != 2 || calls != contactsBefore {
		t.Fatalf("fully cached multi-page replay counters: result=%+v contacts=%d err=%v", got, calls-contactsBefore, err)
	}
}

func TestCertSpotterLiteralFirstCursorHasDistinctCacheEntry(t *testing.T) {
	calls := 0
	c := fixtureClient(t, func(r *http.Request) (int, any) {
		calls++
		switch r.URL.Query().Get("after") {
		case "":
			return http.StatusOK, []any{map[string]any{"id": "first", "dns_names": []string{"apex-page.example.test"}}}
		case "first":
			return http.StatusOK, []any{map[string]any{"id": "next", "dns_names": []string{"cursor-page.example.test"}}}
		default:
			return http.StatusOK, []any{}
		}
	})
	got, err := CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || calls != 3 || len(got.Observations) != 2 || got.Observations[0].Hostname != "apex-page.example.test" || got.Observations[1].Hostname != "cursor-page.example.test" {
		t.Fatalf("literal first cursor pages collided: calls=%d result=%+v err=%v", calls, got, err)
	}
	callsBefore := calls
	got, err = CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || calls != callsBefore || !got.Meta.CacheHit || got.Meta.LogicalRequests != 0 || got.Meta.Attempts != 0 || len(got.Observations) != 2 {
		t.Fatalf("literal first cursor did not replay two distinct cached pages: calls=%d result=%+v err=%v", calls, got, err)
	}
}

func TestCertSpotterCancellationPreservesPartialNamesAndError(t *testing.T) {
	entered := make(chan struct{})
	var calls int
	c := fixtureClient(t, func(r *http.Request) (int, any) {
		calls++
		if calls == 1 {
			return http.StatusOK, []any{map[string]any{"id": "c1", "dns_names": []string{"one.example.test"}}}
		}
		close(entered)
		<-r.Context().Done()
		return http.StatusServiceUnavailable, map[string]any{"error": "cancelled"}
	})
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		result FetchResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() { r, e := CertSpotter(ctx, c, "example.test", 0); done <- outcome{r, e} }()
	<-entered
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || got.result.Status != "partial" || len(got.result.Observations) != 1 || got.result.Observations[0].Hostname != "one.example.test" {
		t.Fatalf("partial cancellation lost: result=%+v err=%v", got.result, got.err)
	}
}

func TestCertSpotterUsesOnlyFinalRowCursor(t *testing.T) {
	calls := 0
	c := fixtureClient(t, func(*http.Request) (int, any) {
		calls++
		return http.StatusOK, []any{map[string]any{"id": "early", "dns_names": []string{"one.example.test"}}, map[string]any{"dns_names": []string{"two.example.test"}}}
	})
	got, err := CertSpotter(context.Background(), c, "example.test", 0)
	if err != nil || calls != 1 || got.Status != "partial" || len(got.Observations) != 2 || got.Completeness != "pagination_incomplete" {
		t.Fatalf("final-row cursor handling: calls=%d result=%+v err=%v", calls, got, err)
	}
}

func TestCertSpotterLogicalRequestsCountPagesNotRetriesOrCacheHits(t *testing.T) {
	var contacts atomic.Int32
	client, err := NewClient(HTTPPolicy{RequestsPerSecond: 10000, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: 2, CacheDir: t.TempDir(), CacheTTL: time.Hour, MaxResponseBytes: 1 << 20, MaxCacheBytes: 1 << 20, UserAgent: "fixture"}, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n := contacts.Add(1)
		status, body := http.StatusOK, `[]`
		switch n {
		case 1:
			body = `[{"id":"p1","dns_names":["one.example.test"]}]`
		case 2:
			status, body = http.StatusTooManyRequests, "busy"
		case 3:
			body = `[{"id":"p2","dns_names":["two.example.test"]}]`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	result, err := CertSpotter(context.Background(), client, "example.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.PagesAttempted != 3 || result.PagesCompleted != 3 || result.Meta.LogicalRequests != 3 || result.Meta.Attempts != 4 || contacts.Load() != 4 {
		t.Fatalf("page/retry telemetry: pages=%d/%d meta=%+v contacts=%d", result.PagesAttempted, result.PagesCompleted, result.Meta, contacts.Load())
	}
}

func TestPassiveProviderPlanMatchesSourceFixtures(t *testing.T) {
	f := loadSourceFixture(t)
	var in struct {
		ProviderFlags map[string]bool `json:"provider_flags"`
	}
	want := fixtureCase(t, f, "passive.plan", &in)
	var expected map[string][]string
	if err := json.Unmarshal(want, &expected); err != nil {
		t.Fatal(err)
	}
	for profile, wantNames := range expected {
		p := PlanPolicy{Profile: profile, CRTName: in.ProviderFlags["crt_name_enabled"], THC: in.ProviderFlags["thc_enabled"], CRTSh: in.ProviderFlags["crtsh_enabled"], CertSpotter: in.ProviderFlags["certspotter_enabled"]}
		if profile == "toggles" {
			p.Profile = "deep"
			p.CRTName = false
			p.THC = false
			p.CRTSh = true
			p.CertSpotter = false
		}
		got, err := ProviderPlan(p)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, wantNames) {
			t.Fatalf("%s plan=%v want=%v", profile, got, wantNames)
		}
	}
}

func TestProviderFixtureTransportDoesNotUseNetwork(t *testing.T) {
	contacts := 0
	c := fixtureClient(t, func(r *http.Request) (int, any) {
		contacts++
		if r.URL.Host != "crt.sh" {
			t.Fatalf("unexpected host %s", r.URL.Host)
		}
		if r.URL.Query().Get("q") != "%.example.test" {
			t.Fatalf("unexpected query %s", r.URL.RawQuery)
		}
		return http.StatusOK, []any{map[string]any{"name_value": "api.example.test"}}
	})
	got, err := CRTSh(context.Background(), c, "example.test", 10)
	if err != nil || contacts != 1 || len(got.Observations) != 1 {
		t.Fatalf("fixture result=%+v contacts=%d err=%v", got, contacts, err)
	}
}

func TestInternetDBEndpointAndInputAreConstrained(t *testing.T) {
	var seen string
	c := fixtureClient(t, func(r *http.Request) (int, any) {
		seen = r.URL.Host + r.URL.Path
		return http.StatusNotFound, map[string]any{"error": "not found"}
	})
	if _, _, err := InternetDB(context.Background(), c, "not-an-ip"); err == nil {
		t.Fatal("invalid IP accepted")
	}
	if _, _, err := InternetDB(context.Background(), c, "192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	if seen != "internetdb.shodan.io/192.0.2.9" {
		t.Fatalf("InternetDB endpoint=%q", seen)
	}
}
