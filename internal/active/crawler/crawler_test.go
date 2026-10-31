package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

func TestPhase5RobotsFixtureMatchesRobotFileParser(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Groups struct {
			Robots struct {
				Input struct {
					Text   string   `json:"text"`
					Paths  []string `json:"paths"`
					Agents []string `json:"user_agents"`
				} `json:"input"`
				Expected struct {
					CanFetch map[string][]bool `json:"can_fetch"`
				} `json:"expected"`
			} `json:"robots_policy"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, agent := range fixture.Groups.Robots.Input.Agents {
		rules := parseRobots(fixture.Groups.Robots.Input.Text, agent)
		want := fixture.Groups.Robots.Expected.CanFetch[agent]
		if len(want) != len(fixture.Groups.Robots.Input.Paths) {
			t.Fatalf("fixture decisions have inconsistent lengths for %q", agent)
		}
		for i, target := range fixture.Groups.Robots.Input.Paths {
			if got := rules.allowed(target); got != want[i] {
				t.Errorf("can_fetch(%q,%q)=%v want %v", agent, target, got, want[i])
			}
		}
	}
}

func TestRobotsQueryMatchingAndWholeDocumentEvidence(t *testing.T) {
	text := "User-agent: OtherBot\nDisallow: /agent-secret\nUser-agent: *\nDisallow: /search?token=\n"
	rules := parseRobots(text, "testbot/1")
	if rules.allowed("http://example.test/search?token=abc") || !rules.allowed("http://example.test/search?q=abc") {
		t.Fatal("robots query-specific rule did not distinguish query values")
	}
	var events []core.Event
	if err := emitRobots(func(e core.Event) error { events = append(events, e); return nil }, "http://example.test", "http://example.test/robots.txt", rules); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].EventType != core.RobotsRuleFound || events[0].RawValue != text || events[0].NormalizedValue != "http://example.test/robots.txt" || events[0].Confidence != 1.0 {
		t.Fatalf("whole robots document evidence missing: %+v", events)
	}
	if events[1].EventType != core.RobotsDisallowedURLFound || events[1].NormalizedValue != "http://example.test/agent-secret" || events[1].Metadata["visited"] != false || events[1].Confidence != 0.8 {
		t.Fatalf("nonselected-agent Disallow evidence missing: %+v", events[1])
	}
}

func TestCrawlReportsAndBlocksQuerySpecificRobotsURLBeforeContact(t *testing.T) {
	var requested []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.RequestURI())
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /search?token=\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/search?token=secret">blocked</a><a href="/search?q=allowed">allowed</a>`))
	})
	c, s, policy := crawlerClient(t, []string{"example.test"}, h)
	port := mustURLPort(t, s.URL)
	var events []core.Event
	_, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(e core.Event) error { events = append(events, e); return nil }, UserAgent: "testbot", ObeyRobots: true, MaxPagesPerOrigin: 3, MaxTotalPages: 3, MaxDepth: 1}, []string{"http://example.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(requested, "\n"), "token=secret") {
		t.Fatalf("robots-disallowed query contacted: %v", requested)
	}
	if !strings.Contains(strings.Join(requested, "\n"), "q=allowed") {
		t.Fatalf("allowed query was not crawled: %v", requested)
	}
	var fullDocument, refused bool
	for _, e := range events {
		if e.EventType == core.RobotsRuleFound && e.Confidence == 1.0 && strings.Contains(e.RawValue.(string), "Disallow: /search?token=") {
			fullDocument = true
		}
		if e.EventType == core.RobotsDisallowedURLFound && e.Confidence == 0.8 && e.NormalizedValue == "http://example.test:"+port+"/search?token=secret" && e.Metadata["visited"] == false {
			refused = true
		}
	}
	if !fullDocument || !refused {
		t.Fatalf("robots evidence missing full=%v refused=%v events=%+v", fullDocument, refused, events)
	}
}

func TestCrawlRobotsSinkFailureReturnsPartialWithoutPageContact(t *testing.T) {
	var requests atomic.Int32
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	port := mustURLPort(t, s.URL)
	sinkErr := errors.New("robots evidence disk failure")
	results, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(core.Event) error { return sinkErr }, ObeyRobots: true, MaxPagesPerOrigin: 1, MaxTotalPages: 1}, []string{"http://example.test:" + port + "/"})
	if !errors.Is(err, activehttp.ErrEventSink) || !errors.Is(err, sinkErr) {
		t.Fatalf("robots sink failure=%v", err)
	}
	if requests.Load() != 1 || len(results) != 1 || !results[0].Partial || results[0].Reason != "event_sink_failure" || len(results[0].Pages) != 0 {
		t.Fatalf("fatal robots failure continued contacts or lost partial outcome: requests=%d results=%+v", requests.Load(), results)
	}
}

func TestCrawlDoesNotTrustTruncatedRobotsDocument(t *testing.T) {
	var requests atomic.Int32
	robots := "User-agent: *\nAllow: /\n" + strings.Repeat("x", activehttp.MaxResponseBytes) + "\nDisallow: /\n"
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte(robots))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	port := mustURLPort(t, s.URL)
	results, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(core.Event) error { return nil }, ObeyRobots: true, MaxPagesPerOrigin: 1, MaxTotalPages: 1}, []string{"http://example.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || len(results) != 1 || !results[0].Partial || results[0].Reason != "robots_body_truncated" || len(results[0].Pages) != 0 {
		t.Fatalf("partial robots document was trusted: requests=%d results=%+v", requests.Load(), results)
	}
}

func TestCrawlIPv6AuthorityAndRobotsMetadata(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	probe, err := net.DialTimeout("tcp6", listener.Addr().String(), 250*time.Millisecond)
	if err != nil {
		listener.Close()
		t.Skipf("IPv6 loopback connection unavailable: %v", err)
	}
	probe.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/private">private</a>`))
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	policy := core.ScopePolicy{AllowedCIDRs: []string{"::1/128"}}
	index := evidence.NewDNSRunIndex(policy)
	client, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: func(core.Event) error { return nil }, PerHostRequests: 5, GlobalConcurrency: 2, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var events []core.Event
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(e core.Event) error { events = append(events, e); return nil }, UserAgent: "testbot", ObeyRobots: true, MaxPagesPerOrigin: 2, MaxTotalPages: 2, MaxDepth: 1}, []string{server.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	port := server.Listener.Addr().(*net.TCPAddr).Port
	wantOrigin := "http://[::1]:" + strconv.Itoa(port)
	if len(results) != 1 || results[0].Origin != wantOrigin {
		t.Fatalf("IPv6 origin=%+v want %s", results, wantOrigin)
	}
	var robots, disallowed bool
	for _, e := range events {
		if e.EventType == core.RobotsRuleFound && e.NormalizedValue == wantOrigin+"/robots.txt" && e.Metadata["origin"] == wantOrigin {
			robots = true
		}
		if e.EventType == core.RobotsDisallowedURLFound && e.NormalizedValue == wantOrigin+"/private" && e.Metadata["target_domains"].([]string)[0] == "::1" {
			disallowed = true
		}
	}
	if !robots || !disallowed {
		t.Fatalf("IPv6 robots metadata missing: server=%s listener=%s robots=%v disallowed=%v events=%+v", server.URL, server.Listener.Addr(), robots, disallowed, events)
	}
}

func TestIPv6RootAdmissionAndRobotsAuthorityProjection(t *testing.T) {
	org := origin("http://[::1]:8443/")
	if org != "http://[::1]:8443" {
		t.Fatalf("IPv6 authority=%q", org)
	}
	var events []core.Event
	if err := emitRobots(func(e core.Event) error { events = append(events, e); return nil }, org, org+"/robots.txt", parseRobots("User-agent: *\nDisallow: /private\n", "testbot")); err != nil {
		t.Fatal(err)
	}
	if events[0].NormalizedValue != org+"/robots.txt" || events[0].Metadata["origin"] != org || events[1].NormalizedValue != org+"/private" {
		t.Fatalf("IPv6 robots authority projection: %+v", events)
	}
}

func crawlerClient(t *testing.T, domains []string, handler http.Handler) (*activehttp.Client, *httptest.Server, core.ScopePolicy) {
	return crawlerClientWithRequestLimit(t, domains, handler, 50)
}

func crawlerClientWithRequestLimit(t *testing.T, domains []string, handler http.Handler, perHostRequests int) (*activehttp.Client, *httptest.Server, core.ScopePolicy) {
	return crawlerClientWithSinks(t, domains, handler, perHostRequests, func(core.Event) error { return nil })
}

func crawlerClientWithSinks(t *testing.T, domains []string, handler http.Handler, perHostRequests int, emit func(core.Event) error) (*activehttp.Client, *httptest.Server, core.ScopePolicy) {
	t.Helper()
	s := httptest.NewServer(handler)
	u, _ := url.Parse(s.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	_ = port
	policy := core.ScopePolicy{AllowedDomains: domains, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	for _, d := range domains {
		idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": d, "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	}
	c, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: emit, UserAgent: "testbot", PerHostRequests: perHostRequests, GlobalConcurrency: 4, PerOriginConcurrency: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return c, s, policy
}

func TestCrawlPageRedirectsStayAtNavigationDepthAndResolveLinksAtFinalURL(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var requests []string
			client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.URL.Path)
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", status)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/final" {
					_, _ = w.Write([]byte(`<a href="child">child</a>`))
					return
				}
				_, _ = w.Write([]byte(`<title>child</title>`))
			}))
			root := "http://example.test:" + mustURLPort(t, server.URL) + "/start"
			var events []core.Event
			results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(ev core.Event) error { events = append(events, ev); return nil }, MaxPagesPerOrigin: 2, MaxTotalPages: 2, MaxDepth: 1}, []string{root})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(requests, []string{"/start", "/final", "/child"}) {
				t.Fatalf("requests=%v, want redirect terminal and depth-1 child", requests)
			}
			if len(results) != 1 || len(results[0].Pages) != 2 || results[0].Pages[0].Depth != 0 || results[0].Pages[0].URL != root || !strings.HasSuffix(results[0].Pages[0].FinalURL, "/final") || len(results[0].Pages[0].RedirectChain) != 1 || results[0].Pages[0].RedirectChain[0].Status != status || results[0].Pages[1].Depth != 1 {
				t.Fatalf("redirect page accounting/provenance=%+v", results)
			}
			foundFinalSource := false
			for _, ev := range events {
				if ev.EventType == core.URLFound && ev.Metadata["source_url"] == results[0].Pages[0].FinalURL {
					foundFinalSource = true
				}
			}
			if !foundFinalSource {
				t.Fatalf("links were not attributed to terminal page URL: %+v", events)
			}
		})
	}
}

func TestCrawlPageRedirectCycleIsBoundedAndIncomplete(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		dest := map[string]string{"/a": "/b", "/b": "/a"}[r.URL.Path]
		http.Redirect(w, r, dest, http.StatusFound)
	}))
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/a"
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(requests, []string{"/a", "/b"}) || len(results) != 1 || !results[0].Partial || results[0].Reason != "redirect_cycle" || len(results[0].Pages) != 1 || len(results[0].Pages[0].RedirectChain) != 2 {
		t.Fatalf("cycle was not bounded/reported: requests=%v results=%+v", requests, results)
	}
}

func TestCrawlPageRedirectChainRetainsAllHops(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", http.StatusMovedPermanently)
		case "/middle":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		case "/final":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="child">child</a>`))
		default:
			w.Header().Set("Content-Type", "text/html")
		}
	}))
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/start"
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 2, MaxTotalPages: 2, MaxDepth: 1}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(requests, []string{"/start", "/middle", "/final", "/child"}) || len(results) != 1 || len(results[0].Pages) != 2 || results[0].Pages[0].FinalURL != "http://example.test:"+mustURLPort(t, server.URL)+"/final" || len(results[0].Pages[0].RedirectChain) != 2 || results[0].Pages[0].RedirectChain[0].Status != http.StatusMovedPermanently || results[0].Pages[0].RedirectChain[1].Status != http.StatusTemporaryRedirect || results[0].Pages[1].Depth != 1 {
		t.Fatalf("redirect chain/depth mismatch: requests=%v results=%+v", requests, results)
	}
}

func TestCrawlPageRedirectTerminalAliasIsNotFetchedTwice(t *testing.T) {
	for _, tc := range []struct {
		name      string
		roots     []string
		wantCalls []string
		wantPages []string
	}{
		{name: "alias-first", roots: []string{"/start", "/final"}, wantCalls: []string{"/start", "/final", "/child"}, wantPages: []string{"/start", "/child"}},
		{name: "terminal-first", roots: []string{"/final", "/start"}, wantCalls: []string{"/final", "/start", "/child"}, wantPages: []string{"/final", "/child"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			var httpEvents, crawlEvents []core.Event
			client, server, policy := crawlerClientWithSinks(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.URL.Path)
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/final" {
					_, _ = w.Write([]byte(`<a href="/final">same terminal page</a><a href="/child">child</a>`))
					return
				}
				_, _ = w.Write([]byte(`<html><title>child</title></html>`))
			}), 50, func(ev core.Event) error { httpEvents = append(httpEvents, ev); return nil })
			port := mustURLPort(t, server.URL)
			roots := []string{"http://example.test:" + port + tc.roots[0], "http://example.test:" + port + tc.roots[1]}
			results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(ev core.Event) error { crawlEvents = append(crawlEvents, ev); return nil }, MaxPagesPerOrigin: 2, MaxTotalPages: 2, MaxDepth: 1}, roots)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("unexpected result count: %+v", results)
			}
			var gotPages []string
			for _, page := range results[0].Pages {
				u, _ := url.Parse(page.URL)
				gotPages = append(gotPages, u.Path)
			}
			crawlerPageEvents := 0
			for _, ev := range crawlEvents {
				if ev.EventType == core.CrawlerResult {
					crawlerPageEvents++
				}
			}
			if !reflect.DeepEqual(requests, tc.wantCalls) || results[0].Partial || !reflect.DeepEqual(gotPages, tc.wantPages) || crawlerPageEvents != len(tc.wantPages) || len(httpEvents) != len(tc.wantCalls) {
				t.Fatalf("terminal alias duplicated or falsely incomplete: requests=%v pages=%v results=%+v", requests, gotPages, results)
			}
			for _, ev := range httpEvents {
				if ev.EventType != core.HTTPProbeResult {
					t.Fatalf("missing redirect HTTP evidence: %+v", httpEvents)
				}
			}
		})
	}
	t.Run("completed-queue-item-does-not-fail-page-budget", func(t *testing.T) {
		var requests []string
		var httpEvents, crawlEvents []core.Event
		client, server, policy := crawlerClientWithSinks(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, r.URL.Path)
			if r.URL.Path == "/start" {
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><title>terminal</title></html>`))
		}), 50, func(ev core.Event) error { httpEvents = append(httpEvents, ev); return nil })
		port := mustURLPort(t, server.URL)
		start, final := "http://example.test:"+port+"/start", "http://example.test:"+port+"/final"
		results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(ev core.Event) error { crawlEvents = append(crawlEvents, ev); return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{start, final})
		if err != nil {
			t.Fatal(err)
		}
		crawlerPageEvents := 0
		for _, ev := range crawlEvents {
			if ev.EventType == core.CrawlerResult {
				crawlerPageEvents++
			}
		}
		if !reflect.DeepEqual(requests, []string{"/start", "/final"}) || len(results) != 1 || results[0].Partial || len(results[0].Pages) != 1 || results[0].Pages[0].FinalURL != final || len(httpEvents) != 2 || crawlerPageEvents != 1 {
			t.Fatalf("completed queue alias caused false page-budget partial: requests=%v results=%+v", requests, results)
		}
	})
	t.Run("two-aliases-converge", func(t *testing.T) {
		var requests []string
		var httpEvents []core.Event
		client, server, policy := crawlerClientWithSinks(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, r.URL.Path)
			switch r.URL.Path {
			case "/alias-a", "/alias-b":
				http.Redirect(w, r, "/final", http.StatusFound)
			case "/final":
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<a href="/child">child</a>`))
			default:
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<html><title>child</title></html>`))
			}
		}), 50, func(ev core.Event) error { httpEvents = append(httpEvents, ev); return nil })
		port := mustURLPort(t, server.URL)
		base := "http://example.test:" + port
		results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 3, MaxTotalPages: 3, MaxDepth: 1}, []string{base + "/alias-a", base + "/alias-b", base + "/final"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(requests, []string{"/alias-a", "/final", "/alias-b", "/child"}) || len(results) != 1 || results[0].Partial || len(results[0].Pages) != 2 || !strings.HasSuffix(results[0].Pages[0].FinalURL, "/final") || len(httpEvents) != len(requests) {
			t.Fatalf("convergent aliases fetched/count terminal multiple times: requests=%v results=%+v", requests, results)
		}
		for _, ev := range httpEvents {
			if ev.EventType != core.HTTPProbeResult {
				t.Fatalf("missing redirect HTTP evidence: %+v", httpEvents)
			}
		}
	})
}

func TestCrawlPageRedirectRejectsDifferentOriginEvenWhenInScope(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClient(t, []string{"example.test", "child.example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Host+r.URL.Path)
		if r.URL.Path == "/start" {
			_, port, err := net.SplitHostPort(r.Host)
			if err != nil {
				t.Errorf("split request host: %v", err)
				return
			}
			http.Redirect(w, r, "http://child.example.test:"+port+"/never", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/start"
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || !strings.HasPrefix(requests[0], "example.test:") || len(results) != 1 || !results[0].Partial || results[0].Reason != "redirect_target_rejected" {
		t.Fatalf("cross-origin redirect was contacted or hidden: requests=%v results=%+v", requests, results)
	}
}

func TestCrawlPageRedirectHopsShareExistingHTTPRequestBudget(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClientWithRequestLimit(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		http.Redirect(w, r, "/final", http.StatusFound)
	}), 1)
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/start"
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(requests, []string{"/start"}) || len(results) != 1 || !results[0].Partial || results[0].Reason != "page_fetch_error" || len(results[0].Pages) != 1 || results[0].Pages[0].Error == "" {
		t.Fatalf("redirect hop escaped shared HTTP request budget: requests=%v results=%+v", requests, results)
	}
}

func TestCrawlPageRedirectCancellationStopsBeforeNextHop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	var requests []string
	var requestMu sync.Mutex
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requests = append(requests, r.URL.Path)
		requestMu.Unlock()
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/middle", http.StatusFound)
			return
		}
		close(entered)
		<-r.Context().Done()
	}))
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/start"
	type outcome struct {
		results []Result
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := Crawl(ctx, client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{root})
		done <- outcome{results: results, err: err}
	}()
	select {
	case <-entered:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("redirect second hop was not reached")
	}
	var got outcome
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("crawler did not stop after cancellation")
	}
	requestMu.Lock()
	observed := append([]string(nil), requests...)
	requestMu.Unlock()
	if !errors.Is(got.err, context.Canceled) || !reflect.DeepEqual(observed, []string{"/start", "/middle"}) || len(got.results) != 1 || !got.results[0].Partial || got.results[0].Reason != "cancelled" {
		t.Fatalf("redirect cancellation was not propagated: requests=%v results=%+v err=%v", observed, got.results, got.err)
	}
}

func TestCrawlPageRedirectChainHasFixedHopBound(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if err != nil {
			t.Errorf("invalid hop path %q", r.URL.Path)
			return
		}
		http.Redirect(w, r, "/hop/"+strconv.Itoa(n+1), http.StatusFound)
	}))
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/hop/0"
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != maxPageRedirects+1 || len(results) != 1 || !results[0].Partial || results[0].Reason != "redirect_limit" || len(results[0].Pages) != 1 || len(results[0].Pages[0].RedirectChain) != maxPageRedirects+1 {
		t.Fatalf("redirect chain bound mismatch: requests=%d results=%+v", len(requests), results)
	}
}
func TestCrawlRoundRobinRobotsAndPageBudget(t *testing.T) {
	var requests []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Host+r.URL.Path)
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\nAllow: /private/open\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		switch {
		case strings.HasPrefix(r.Host, "a.example.test:"):
			_, _ = w.Write([]byte(`<meta name="robots" content="index,follow"><a href="/private">blocked</a><a href="/private/open">also blocked by first matching rule</a><a href="/a-child">child</a><a href="/a-other">child</a>`))
		case strings.HasPrefix(r.Host, "b.example.test:"):
			_, _ = w.Write([]byte(`<a href="/b-child">child</a>`))
		}
	})
	c, s, policy := crawlerClient(t, []string{"example.test", "a.example.test", "b.example.test"}, h)
	baseURL, _ := url.Parse(s.URL)
	port := baseURL.Port()
	roots := []string{"http://a.example.test:" + port + "/", "http://b.example.test:" + port + "/"}
	var events []core.Event
	results, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(e core.Event) error { events = append(events, e); return nil }, UserAgent: "testbot", ObeyRobots: true, MaxPagesPerOrigin: 2, MaxTotalPages: 4, MaxDepth: 2}, roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || !results[0].Partial || results[1].Partial {
		t.Fatalf("page budgets not reported: %+v", results)
	}
	if len(requests) < 6 || !strings.Contains(requests[2], "a.example.test:"+port+"/") || !strings.Contains(requests[3], "b.example.test:"+port+"/") || !strings.Contains(requests[4], "b.example.test:"+port+"/b-child") || !strings.Contains(requests[5], "a.example.test:"+port+"/a-child") {
		t.Fatalf("origins were not scheduled round-robin: %v", requests)
	}
	if strings.Contains(strings.Join(requests, "\n"), "/private ") || strings.Contains(strings.Join(requests, "\n"), "/private\n") {
		t.Fatalf("robots-disallowed URL contacted: %v", requests)
	}
	if !reflect.DeepEqual([]string{results[0].Origin, results[1].Origin}, []string{"http://a.example.test:" + port, "http://b.example.test:" + port}) {
		t.Fatalf("unstable result order: %+v", results)
	}
	var metaFound, queuedLink, childResult bool
	for i, e := range events {
		if e.EventType == core.RobotsDisallowedURLFound && e.NormalizedValue == "http://a.example.test:"+port+"/private" {
			queuedLink = true
		}
		if e.EventType == core.MetaRobotsFound && e.Metadata["content"] == "index,follow" && e.Metadata["browser_dom"] == false {
			metaFound = true
		}
		if e.EventType == core.URLFound && e.RawValue == "/a-child" && e.Metadata["source_url"] == "http://a.example.test:"+port+"/" {
			queuedLink = true
			for _, later := range events[i+1:] {
				if later.EventType == core.CrawlerResult && later.NormalizedValue == "http://a.example.test:"+port+"/a-child" {
					childResult = true
					break
				}
			}
		}
	}
	if !queuedLink || !metaFound || !childResult {
		t.Fatalf("missing or incorrectly ordered durable crawler events: meta=%v link=%v child=%v events=%+v", metaFound, queuedLink, childResult, events)
	}
}

func TestCrawlMetaNoFollowAndCancellation(t *testing.T) {
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<meta name="robots" content="noindex,nofollow"><a href="/never">next</a>`))
	}))
	u, _ := url.Parse(s.URL)
	root := "http://example.test:" + u.Port() + "/"
	var hits int
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<meta name="robots" content="noindex,nofollow"><a href="/never">next</a>`))
	})
	out, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(core.Event) error { return nil }, UserAgent: "testbot", ObeyRobots: false, MaxPagesPerOrigin: 5, MaxTotalPages: 5, MaxDepth: 3}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || len(out[0].Pages) != 1 || hits != 1 {
		t.Fatalf("meta nofollow did not stop traversal: %+v hits=%d", out, hits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Crawl(ctx, c, Config{Policy: policy, Emit: func(core.Event) error { return nil }, UserAgent: "testbot", ObeyRobots: false, MaxPagesPerOrigin: 1, MaxTotalPages: 1}, []string{root}); err == nil {
		t.Fatal("cancellation was swallowed")
	}
}

func TestCrawlerPersistsDiscoveredURLBeforeQueueAdmission(t *testing.T) {
	var requests int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/child">child</a>`))
	})
	c, s, policy := crawlerClient(t, []string{"example.test", "a.example.test"}, h)
	port := mustURLPort(t, s.URL)
	sinkErr := errors.New("durable URL event failure")
	results, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(e core.Event) error {
		if e.EventType == core.URLFound {
			return sinkErr
		}
		return nil
	}, MaxPagesPerOrigin: 3, MaxTotalPages: 3, MaxDepth: 2}, []string{"http://a.example.test:" + port + "/"})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("URL sink failure=%v want wrapped durable error", err)
	}
	if len(results) != 1 || len(results[0].Pages) != 1 || !strings.Contains(results[0].Pages[0].URL, "/") || !results[0].Partial || results[0].Reason != "event_sink_failure" {
		t.Fatalf("durable sink failure lost committed page results: %+v", results)
	}
	if requests != 1 {
		t.Fatalf("crawler contacted child before durable URL commit: requests=%d", requests)
	}
}

func TestCrawlTreatsHTTPEventSinkFailureAsFatalAndReturnsPartialPages(t *testing.T) {
	var requests atomic.Int32
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/never">next</a>`))
	}))
	port := mustURLPort(t, s.URL)
	sinkErr := errors.New("HTTP evidence disk failure")
	if err := c.SetEventSink(func(core.Event) error { return sinkErr }); err != nil {
		t.Fatal(err)
	}
	results, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(core.Event) error { return nil }, MaxPagesPerOrigin: 3, MaxTotalPages: 3, MaxDepth: 2}, []string{"http://example.test:" + port + "/"})
	if !errors.Is(err, activehttp.ErrEventSink) {
		t.Fatalf("HTTP sink error was hidden: %v", err)
	}
	if requests.Load() != 1 || len(results) != 1 || len(results[0].Pages) != 0 {
		t.Fatalf("fatal fetch continued/lost results: requests=%d results=%+v", requests.Load(), results)
	}
}

func TestCrawlReportsCancellationOnLastPage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>last</title>"))
	}))
	defer cancel()
	port := mustURLPort(t, s.URL)
	results, err := Crawl(ctx, c, Config{Policy: policy, Emit: func(e core.Event) error {
		if e.EventType == core.CrawlerResult && e.Metadata["body_sha256"] != nil {
			cancel()
		}
		return nil
	}, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{"http://example.test:" + port + "/"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("last-page cancellation swallowed: results=%+v err=%v", results, err)
	}
	if len(results) != 1 || len(results[0].Pages) != 1 || !results[0].Partial || results[0].Reason != "cancelled" {
		t.Fatalf("committed page lost on cancellation: %+v", results)
	}
}

func TestCrawlerRedactsAndCapsPersistedComments(t *testing.T) {
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!-- password=abcdefghi " + strings.Repeat("x", 600) + " -->" + strings.Repeat("<!-- ordinary -->", 21)))
	}))
	port := mustURLPort(t, s.URL)
	var page core.Event
	_, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(e core.Event) error {
		if e.EventType == core.CrawlerResult && e.Metadata["body_sha256"] != nil {
			page = e
		}
		return nil
	}, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 0}, []string{"http://example.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	comments := page.Metadata["comments"].([]string)
	if len(comments) != 20 || len([]rune(comments[0])) != 500 || strings.Contains(comments[0], "abcdefghi") || !strings.Contains(comments[0], "[REDACTED_SECRET]") {
		t.Fatalf("crawler comment redaction/limits: count=%d first=%q", len(comments), comments[0])
	}
}

func TestCrawlerMarksActualBodyCapPartialAndPreservesHashSemantics(t *testing.T) {
	body := `<title>before cap</title>` + strings.Repeat("x", activehttp.MaxResponseBytes) + `<a href="/after-cap">after</a>`
	c, s, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}))
	port := mustURLPort(t, s.URL)
	var pageEvent, limitationEvent core.Event
	results, err := Crawl(context.Background(), c, Config{Policy: policy, Emit: func(e core.Event) error {
		switch e.EventType {
		case core.CrawlerResult:
			pageEvent = e
		case core.Limitation:
			limitationEvent = e
		}
		return nil
	}, MaxPagesPerOrigin: 1, MaxTotalPages: 1, MaxDepth: 1}, []string{"http://example.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Pages) != 1 || !results[0].Partial || results[0].Reason != "body_truncated" || !results[0].Pages[0].BodyTruncated {
		t.Fatalf("crawler hid actual body cap: %+v", results)
	}
	rawHash := sha256.Sum256([]byte(body[:activehttp.MaxResponseBytes]))
	htmlHash := sha256.Sum256([]byte(body[:activehttp.MaxResponseBytes]))
	page := results[0].Pages[0]
	if page.BodySHA256 != hex.EncodeToString(rawHash[:]) || page.HTMLSHA256 != hex.EncodeToString(htmlHash[:]) || pageEvent.Metadata["body_truncated"] != true || pageEvent.Metadata["partial"] != true || pageEvent.Confidence != 0.82 {
		t.Fatalf("crawler page evidence hash/completeness mismatch: page=%+v event=%+v", page, pageEvent)
	}
	if limitationEvent.EventType != core.Limitation || limitationEvent.Confidence != 0 || limitationEvent.Metadata["reason"] != "body_truncated" {
		t.Fatalf("missing source-compatible incomplete terminal event: %+v", limitationEvent)
	}
}

func mustURLPort(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}
