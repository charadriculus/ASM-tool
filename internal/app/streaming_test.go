package app

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
	"asmtool/internal/portable"
	"asmtool/internal/storage"
)

func streamingFixture(t *testing.T) (Plan, stages, *map[string]any) {
	t.Helper()
	p := integrationPipelinePlan(t, "disabled")
	p.cfg.CollectionPolicy.StreamingPipelineEnabled = true
	p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML = false
	p.cfg.Modules.Subdomains = true
	p.cfg.Modules.Crawler = true
	p.cfg.RateLimits.DNSWorkerCount = 2
	p.cfg.CollectionPolicy.DNSCandidateBudget = 10
	p.cfg.RateLimits.CrawlerMaxTotalPages = 50
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 5
	p.active = makeActiveSettings(p)
	var seen map[string]any
	stage := integrationPipelineStages(t, integrationPipelineOps(t, "success", nil), &seen)
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, _ *dns.WildcardAnalyzer, name string) (dns.QuickValidationResult, error) {
		ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "offline_fixture", name, name, core.InScope)
		if err != nil {
			return dns.QuickValidationResult{}, err
		}
		ev.Metadata = map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.55"}, "input_target": name == p.target}
		err = cfg.Emit(ev)
		return dns.QuickValidationResult{Domain: name, Validated: true, Eligible: true}, err
	}
	stage.expand = func(ctx context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
		for name := range cfg.Inventory {
			if cfg.Index.ExistingValidation(name) == nil {
				return dns.ExpansionResult{}, fmt.Errorf("final expansion would repeat %s", name)
			}
		}
		return dns.ExpansionResult{}, ctx.Err()
	}
	return p, stage, &seen
}

func streamDiscovery(ctx context.Context, req passive.CollectRequest, names ...string) (passive.CollectResult, error) {
	inv := map[string]evidence.ProviderInventoryEntry{}
	for i, name := range names {
		ev, err := core.NewEvent(core.DomainFound, "subdomains", fmt.Sprintf("fixture_provider_%d", i), name, name, (core.ScopeChecker{Policy: req.Config.ScopePolicy}).CheckDomain(name).Status)
		if err != nil {
			return passive.CollectResult{Inventory: inv}, err
		}
		ev.Metadata = map[string]any{"provider": ev.SourceTool, "collector_tool": "fixture", "evidence_family": "certificate", "target_service_contacted": false}
		if err = req.Sink(ctx, ev); err != nil {
			return passive.CollectResult{Inventory: inv}, err
		}
		inv[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{ev.SourceTool}, Observations: 1}
	}
	return passive.CollectResult{Inventory: inv}, nil
}

func TestStreamingDiscoveryDNSHTTPAndCrawlerBeforeProviderEOF(t *testing.T) {
	p, stage, seen := streamingFixture(t)
	var callsMu sync.Mutex
	dnsCalls, probes := map[string]int{}, map[string]int{}
	quick := stage.quick
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, a *dns.WildcardAnalyzer, n string) (dns.QuickValidationResult, error) {
		callsMu.Lock()
		dnsCalls[n]++
		callsMu.Unlock()
		return quick(ctx, cfg, a, n)
	}
	crawled := make(chan struct{})
	var once sync.Once
	stage.ops.crawl = func(ctx context.Context, _ *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		for _, raw := range roots {
			if hostFromURL(raw) == "a.example.test" {
				once.Do(func() { close(crawled) })
			}
		}
		return nil, nil
	}
	probe := stage.ops.probe
	stage.ops.probe = func(ctx context.Context, c *activehttp.Client, cfg web.ProbeConfig, target web.Target, raw string) (web.Result, error) {
		callsMu.Lock()
		probes[raw]++
		callsMu.Unlock()
		return probe(ctx, c, cfg, target, raw)
	}
	clients := 0
	makeHTTP := stage.ops.newHTTP
	stage.ops.newHTTP = func(cfg activehttp.Config) (*activehttp.Client, error) { clients++; return makeHTTP(cfg) }
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		result, err := streamDiscovery(ctx, req, p.target, "a.example.test", "a.example.test", "b.example.test", "outside.test")
		if err != nil {
			return result, err
		}
		select {
		case <-crawled:
			return result, nil
		case <-ctx.Done():
			return result, ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := executePassive(ctx, p, portable.Payload{}, nil, stage)
	if err != nil {
		t.Fatal(err)
	}
	if result.Incomplete || clients != 1 {
		t.Fatalf("incomplete=%t clients=%d", result.Incomplete, clients)
	}
	for _, name := range []string{p.target, "a.example.test", "b.example.test"} {
		if dnsCalls[name] != 1 {
			t.Fatalf("DNS %s calls=%d", name, dnsCalls[name])
		}
	}
	if dnsCalls["outside.test"] != 0 {
		t.Fatal("out-of-scope DNS")
	}
	for raw, count := range probes {
		if count != 1 || hostFromURL(raw) == "outside.test" {
			t.Fatalf("duplicate/outscope probe %s=%d", raw, count)
		}
	}
	coverage := asPipelineMap((*seen)["coverage"])
	if coverage["pipeline_schedule"] != "bounded_streaming" || coverage["dns_selection_policy"] != "arrival_order" || coverage["streaming_schedule_status"] != "implemented" {
		t.Fatalf("coverage=%#v", coverage)
	}
	assertStreamingDurability(t, p)
}

func assertStreamingDurability(t *testing.T, p Plan) []map[string]any {
	t.Helper()
	db, err := storage.OpenImmutable(p.cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := storage.IterEvents(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, row := range rows {
		id := fmt.Sprint(row["event_id"])
		if ids[id] {
			t.Fatalf("duplicate SQLite event %s", id)
		}
		ids[id] = true
	}
	count := 0
	err = evidence.IterJSONL(filepath.Join(p.cfg.EventsDir(), "run.jsonl"), func(r evidence.JSONLRecord) error {
		if r.Err != nil {
			return r.Err
		}
		count++
		if !ids[fmt.Sprint(r.Event["event_id"])] {
			return errors.New("JSONL event missing in SQLite")
		}
		return nil
	})
	if err != nil || count != len(rows) {
		t.Fatalf("JSONL/SQLite mismatch jsonl=%d sqlite=%d err=%v", count, len(rows), err)
	}
	return rows
}

func TestStreamingArrivalBudgetDoesNotRerankOrRevalidate(t *testing.T) {
	p, stage, seen := streamingFixture(t)
	p.cfg.CollectionPolicy.DNSCandidateBudget = 2
	var namesMu sync.Mutex
	names := map[string]int{}
	quick := stage.quick
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, a *dns.WildcardAnalyzer, n string) (dns.QuickValidationResult, error) {
		namesMu.Lock()
		names[n]++
		namesMu.Unlock()
		return quick(ctx, cfg, a, n)
	}
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		return streamDiscovery(ctx, req, p.target, "z.example.test", "z.example.test", "a.example.test")
	}
	finalCalls := 0
	stage.expand = func(ctx context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
		finalCalls++
		if len(cfg.Inventory) != 2 || cfg.Inventory["z.example.test"].Hostname == "" || !cfg.SkipPrevalidated {
			t.Errorf("final DNS set changed %#v", cfg.Inventory)
		}
		return dns.ExpansionResult{}, ctx.Err()
	}
	result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Incomplete || names[p.target] != 1 || names["z.example.test"] != 1 || names["a.example.test"] != 0 || finalCalls != 1 {
		t.Fatalf("admission=%v final=%d incomplete=%t", names, finalCalls, result.Incomplete)
	}
	if asPipelineMap((*seen)["coverage"])["deferred_by_dns_budget"] != 1 {
		t.Fatalf("coverage=%v", (*seen)["coverage"])
	}
	deferred, observations := 0, 0
	for _, r := range assertStreamingDurability(t, p) {
		if r["event_type"] == string(core.DomainFound) {
			observations++
		}
		if asPipelineMap(r["metadata"])["dns_state"] == "deferred_by_dns_budget" {
			deferred++
			if r["normalized_value"] != "a.example.test" {
				t.Fatal("admitted target marked deferred")
			}
		}
	}
	if deferred != 1 || observations != 4 {
		t.Fatalf("deferred=%d provider observations=%d", deferred, observations)
	}
}

func TestStreamingBackpressureCancellationJoinsAndPreservesPartial(t *testing.T) {
	p, stage, _ := streamingFixture(t)
	p.cfg.CollectionPolicy.DNSCandidateBudget = 100
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstProbe := make(chan struct{})
	var once sync.Once
	stage.ops.probe = func(ctx context.Context, _ *activehttp.Client, _ web.ProbeConfig, _ web.Target, _ string) (web.Result, error) {
		once.Do(func() { close(firstProbe) })
		<-ctx.Done()
		return web.Result{}, ctx.Err()
	}
	var emitted, validating atomic.Int32
	quick := stage.quick
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, a *dns.WildcardAnalyzer, n string) (dns.QuickValidationResult, error) {
		validating.Add(1)
		defer validating.Add(-1)
		return quick(ctx, cfg, a, n)
	}
	collectorDone := make(chan struct{})
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		defer close(collectorDone)
		for i := 0; i < 100; i++ {
			_, err := streamDiscovery(ctx, req, fmt.Sprintf("d%d.example.test", i))
			if err != nil {
				return passive.CollectResult{}, err
			}
			emitted.Add(1)
		}
		return passive.CollectResult{}, nil
	}
	done := make(chan error, 1)
	go func() { _, err := executePassive(ctx, p, portable.Payload{}, nil, stage); done <- err }()
	select {
	case <-firstProbe:
	case <-time.After(5 * time.Second):
		t.Fatal("active pipeline never started")
	}
	select {
	case <-collectorDone:
		t.Fatal("discovery escaped bounded pipeline")
	case <-time.After(50 * time.Millisecond):
	}
	if n := emitted.Load(); n > 12 {
		t.Errorf("backpressure did not bound discovery lead: %d", n)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not join after cancellation")
	}
	if validating.Load() != 0 {
		t.Fatal("DNS worker survived return")
	}
	select {
	case <-collectorDone:
	default:
		t.Fatal("collector survived return")
	}
	rows := assertStreamingDurability(t, p)
	if len(rows) == 0 {
		t.Fatal("partial events lost")
	}
	b, err := os.ReadFile(filepath.Join(p.cfg.OutputDir, "run_status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"interrupted"`) || !strings.Contains(string(b), `"incomplete": true`) {
		t.Fatalf("partial status: %s", b)
	}
}

func TestStreamingFatalStagesStopJoinAndKeepEvidence(t *testing.T) {
	for _, failure := range []string{"source", "dns", "active", "enrichment"} {
		t.Run(failure, func(t *testing.T) {
			p, stage, _ := streamingFixture(t)
			want := errors.New("fixture " + failure + " failure")
			stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
				r, err := streamDiscovery(ctx, req, p.target, "a.example.test")
				if err != nil {
					return r, err
				}
				if failure == "source" {
					return r, want
				}
				return r, nil
			}
			quick := stage.quick
			var working atomic.Int32
			stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, a *dns.WildcardAnalyzer, n string) (dns.QuickValidationResult, error) {
				working.Add(1)
				defer working.Add(-1)
				r, err := quick(ctx, cfg, a, n)
				if err == nil && failure == "dns" {
					return r, want
				}
				return r, err
			}
			if failure == "active" {
				stage.ops.probe = func(context.Context, *activehttp.Client, web.ProbeConfig, web.Target, string) (web.Result, error) {
					return web.Result{}, want
				}
			}
			if failure == "enrichment" {
				stage.expand = func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error) {
					return dns.ExpansionResult{}, want
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := executePassive(ctx, p, portable.Payload{}, nil, stage)
			if !errors.Is(err, want) || !result.Incomplete || working.Load() != 0 {
				t.Fatalf("cause lost/leaked workers: result=%+v err=%v working=%d", result, err, working.Load())
			}
			if len(assertStreamingDurability(t, p)) == 0 {
				t.Fatal("persisted events lost")
			}
		})
	}
}

func TestStreamingAuthorizationRejectsBeforeStages(t *testing.T) {
	t.Run("authorization", func(t *testing.T) {
		p, stage, _ := streamingFixture(t)
		p.cfg.AuthorizationConfirmed = false
		called := false
		stage.dnsClient = func(time.Duration, float64) (*dns.Client, error) {
			called = true
			return nil, errors.New("must not run")
		}
		result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
		if err == nil || called || result.RunDir != "" {
			t.Fatalf("authorization failure reached stages result=%+v err=%v", result, err)
		}
		if _, err := os.Stat(p.cfg.OutputDir); !os.IsNotExist(err) {
			t.Fatalf("unauthorized request wrote output: %v", err)
		}
	})
}

func TestStreamingUsesRealDNSHTTPAndCrawlerWithSharedRequestQuota(t *testing.T) {
	p, stage, _ := streamingFixture(t)
	var hits atomic.Int32
	visited := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		once.Do(func() { close(visited) })
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><title>Пример</title><a href='/document.pdf'>Документ</a></html>")
	}))
	defer server.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	p.cfg.Ports = []int{port}
	p.cfg.ScopePolicy.AllowedCIDRs = []string{"127.0.0.1/32"}
	p.cfg.CollectionPolicy.WildcardEnabled = false
	p.cfg.CollectionPolicy.ObeyRobots = false
	p.cfg.RateLimits.HTTPMaxRequestsPerHost = 1
	p.cfg.RateLimits.HTTPDelaySeconds = 0
	p.cfg.RateLimits.GlobalMaxRequestsPerSecond = 1000
	p.active = makeActiveSettings(p)

	resolver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	defer func() { resolver.Close(); <-stopped }()
	go func() {
		defer close(stopped)
		buf := make([]byte, 4096)
		for {
			n, addr, e := resolver.ReadFrom(buf)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			if q.Questions[0].Type == dnsmessage.TypeA {
				answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			}
			packet, e := answer.Pack()
			if e == nil {
				_, _ = resolver.WriteTo(packet, addr)
			}
		}
	}()
	stage.dnsClient = func(time.Duration, float64) (*dns.Client, error) {
		return dns.NewClientWithRate([]string{resolver.LocalAddr().String()}, time.Second, 1000)
	}
	stage.quick = dns.ValidateQuick
	stage.expand = dns.Expand
	stage.ops = defaultActiveOps()
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		r, e := streamDiscovery(ctx, req, p.target, p.target)
		if e != nil {
			return r, e
		}
		select {
		case <-visited:
			return r, nil
		case <-ctx.Done():
			return r, ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := executePassive(ctx, p, portable.Payload{}, nil, stage)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || !result.Incomplete {
		t.Fatalf("shared web/crawler request quota reset: hits=%d incomplete=%t", hits.Load(), result.Incomplete)
	}
	rows := assertStreamingDurability(t, p)
	dnsValidations, webResults := 0, 0
	for _, r := range rows {
		if r["event_type"] == string(core.DNSValidation) {
			dnsValidations++
		}
		if r["event_type"] == string(core.WebTargetStatus) && asPipelineMap(r["metadata"])["status"] == "loaded" {
			webResults++
		}
	}
	if dnsValidations != 1 || webResults != 1 {
		t.Fatalf("actual stages lost/duplicated: DNS=%d web=%d", dnsValidations, webResults)
	}
}

func TestStreamingFullDynamicDNSAfterEOFBeforeTCPUsesRemainingBudgets(t *testing.T) {
	p, stage, seen := streamingFixture(t)
	p.cfg.Profile = "full"
	p.cfg.Modules.PortScan = true
	p.cfg.CollectionPolicy.InternetdbEnabled = false
	p.cfg.ScopePolicy.AllowedCIDRs = []string{"192.0.2.0/24"}
	p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML = true
	p.cfg.CollectionPolicy.DynamicDiscoveryMaxRounds = 1
	p.cfg.CollectionPolicy.DynamicDiscoveryMaxNewDomains = 10
	p.cfg.CollectionPolicy.DNSCandidateBudget = 2 // root plus one HTML candidate
	p.cfg.RateLimits.CrawlerMaxTotalPages = 2
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 1
	p.cfg.Ports = []int{80, 443}
	p.active = makeActiveSettings(p)
	var providerEOF, dynamicFinished atomic.Bool
	var dnsMu sync.Mutex
	dnsNames := map[string]int{}
	quick := stage.quick
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, a *dns.WildcardAnalyzer, n string) (dns.QuickValidationResult, error) {
		dnsMu.Lock()
		dnsNames[n]++
		dnsMu.Unlock()
		return quick(ctx, cfg, a, n)
	}
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		r, e := streamDiscovery(ctx, req, p.target)
		providerEOF.Store(true)
		return r, e
	}
	stage.expand = func(ctx context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
		selected := []string{p.target}
		for name := range cfg.Inventory {
			if cfg.Index.ExistingValidation(name) != nil {
				continue
			}
			if !providerEOF.Load() {
				return dns.ExpansionResult{}, errors.New("dynamic DNS ran before passive EOF")
			}
			if _, e := stage.quick(ctx, cfg, cfg.Analyzer, name); e != nil {
				return dns.ExpansionResult{}, e
			}
			selected = append(selected, name)
			dynamicFinished.Store(true)
		}
		return dns.ExpansionResult{Selected: selected}, nil
	}
	var shared *activehttp.Client
	checkClient := func(c *activehttp.Client) {
		if shared == nil {
			shared = c
		} else if shared != c {
			t.Error("HTTP client/budgets reset")
		}
	}
	stage.ops.probe = func(_ context.Context, c *activehttp.Client, _ web.ProbeConfig, target web.Target, _ string) (web.Result, error) {
		checkClient(c)
		r := web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}}
		if target.Domain == p.target {
			r.DiscoveredDomains = []string{"a.example.test", "b.example.test", "outside.test"}
		}
		return r, nil
	}
	crawlCalls := 0
	stage.ops.crawl = func(_ context.Context, c *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		checkClient(c)
		crawlCalls++
		if cfg.MaxTotalPages != 3-crawlCalls || cfg.MaxPagesPerOrigin != 1 {
			t.Errorf("crawler limits reset at batch %d: total=%d origin=%d", crawlCalls, cfg.MaxTotalPages, cfg.MaxPagesPerOrigin)
		}
		return []crawler.Result{{Origin: crawlOrigin(roots[0]), Pages: []crawler.Page{{URL: roots[0], Status: 200}}}}, nil
	}
	tcpCalls := 0
	stage.ops.tcp = func(_ context.Context, plan network.TCPPlan, _ []int, cfg network.TCPConfig) (network.TCPResult, error) {
		tcpCalls++
		if !providerEOF.Load() || !dynamicFinished.Load() || !cfg.Authorized || len(plan.IPs()) != 1 {
			t.Errorf("TCP before complete DNS/auth: EOF=%t dynamic=%t ips=%v", providerEOF.Load(), dynamicFinished.Load(), plan.IPs())
		}
		row := network.Observation{Domains: plan.Domains("192.0.2.55"), IP: "192.0.2.55", Protocol: "tcp", Port: 80, State: "open", Attempted: true, StartedAt: time.Now()}
		if err := cfg.Emit(row); err != nil {
			return network.TCPResult{}, err
		}
		return network.TCPResult{Rows: []network.Observation{row}, Attempted: 1, Planned: 1}, nil
	}
	result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Incomplete || tcpCalls != 1 || crawlCalls != 2 || dnsNames[p.target] != 1 || dnsNames["a.example.test"] != 1 || dnsNames["b.example.test"] != 0 || dnsNames["outside.test"] != 0 {
		t.Fatalf("budget/order violated: run=%+v tcp=%d crawl=%d DNS=%v", result, tcpCalls, crawlCalls, dnsNames)
	}
	coverage := asPipelineMap((*seen)["coverage"])
	if coverage["dynamic_discovery_added"] != 1 || coverage["dynamic_discovery_deferred"] != 1 || coverage["crawler"] != "partial" {
		t.Fatalf("coverage lost deferred/follow-up: %#v", coverage)
	}
	assertStreamingDurability(t, p)
}

func TestAcceptedEventCompletesSQLiteCommitAfterSiblingCancellation(t *testing.T) {
	p, _, _ := streamingFixture(t)
	sink, closeSink := activeTestSink(t, evidence.NewDNSRunIndex(p.cfg.ScopePolicy), filepath.Join(t.TempDir(), "events.jsonl"))
	defer closeSink()
	sink.db.SetMaxOpenConns(1)
	conn, err := sink.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ev, err := core.NewEvent(core.DomainFound, "fixture", "offline", "example.test", "example.test", core.InScope)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sink.emit(ctx, ev) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	waiting := false
	for !waiting {
		select {
		case <-tick.C:
			waiting = sink.db.Stats().WaitCount > 0
		case err := <-done:
			t.Fatalf("event did not wait on occupied SQLite connection: %v", err)
		case <-deadline.C:
			t.Fatal("event never reached SQLite after JSONL acceptance")
		}
	}
	// The event has already passed JSONL acceptance and is waiting for SQLite.
	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("accepted event split on cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accepted event commit did not finish")
	}
	if err := sink.writer.Flush(sink.path); err != nil {
		t.Fatal(err)
	}
	rows, err := storage.IterEvents(context.Background(), sink.db, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("SQLite event lost: %v %#v", err, rows)
	}
	count := 0
	err = evidence.IterJSONL(sink.path, func(r evidence.JSONLRecord) error { count++; return r.Err })
	if err != nil || count != 1 {
		t.Fatalf("JSONL event lost: count=%d err=%v", count, err)
	}
	if err := sink.emit(ctx, ev); !errors.Is(err, context.Canceled) {
		t.Fatalf("new event accepted after cancellation: %v", err)
	}
}
