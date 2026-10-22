package app

import (
	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/portable"
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func TestExecuteActiveStreamsDurableDNSBatchesAndSharesRunBudgets(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	index := evidence.NewDNSRunIndex(policy)
	for _, domain := range []string{"example.test", "api.example.test"} {
		index.Ingest(map[string]any{
			"event_type": string(core.DNSValidation), "normalized_value": domain, "observed_at": "2026-10-14T00:00:00Z",
			"metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"192.0.2.8"}},
		})
	}
	p := activeTestPlan("verify", "disabled", config.Modules{WebProbe: true, Crawler: true})
	p.cfg.RateLimits.CrawlerMaxTotalPages = 2
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 1
	p.active = makeActiveSettings(p)

	batches := make(chan []web.Target, 1)
	probeStarted := make(chan struct{})
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		batches <- []web.Target{{Domain: "example.test"}}
		<-probeStarted // The producer cannot finish until the consumer starts work.
		batches <- []web.Target{{Domain: "api.example.test"}, {Domain: "example.test"}}
		close(batches)
	}()

	ops := activeTestOps()
	ops.targetBatches = batches
	var mu sync.Mutex
	probed := map[string]int{}
	crawlLimits := [][2]int{}
	ops.probe = func(_ context.Context, _ *activehttp.Client, _ web.ProbeConfig, target web.Target, raw string) (web.Result, error) {
		mu.Lock()
		probed[target.Domain]++
		mu.Unlock()
		select {
		case <-probeStarted:
		default:
			close(probeStarted)
		}
		return web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}}, nil
	}
	ops.crawl = func(_ context.Context, _ *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		if len(roots) != 1 {
			t.Fatalf("expected each origin to be scheduled once, roots=%v", roots)
		}
		crawlLimits = append(crawlLimits, [2]int{cfg.MaxTotalPages, cfg.MaxPagesPerOrigin})
		origin := crawlOrigin(roots[0])
		return []crawler.Result{{Origin: origin, Pages: []crawler.Page{{URL: roots[0], Status: 200}}}}, nil
	}
	ops.tcp = func(context.Context, network.TCPPlan, []int, network.TCPConfig) (network.TCPResult, error) {
		return network.TCPResult{}, nil
	}

	sink, closeSink := activeTestSink(t, index, filepath.Join(t.TempDir(), "events", "run.jsonl"))
	defer closeSink()
	out, err := executeActive(context.Background(), p, portable.Payload{}, sink, func(string) error { return nil }, ops)
	if err != nil {
		t.Fatal(err)
	}
	<-producerDone
	if len(out.Targets) != 2 || out.Coverage["streaming_batches"] != 2 || out.Coverage["target_contacted"] != true {
		t.Fatalf("stream outcome lost or duplicated targets: %+v", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if probed["example.test"] != 1 || probed["api.example.test"] != 1 {
		t.Fatalf("duplicate or missing probes: %#v", probed)
	}
	if len(crawlLimits) != 2 || crawlLimits[0] != [2]int{2, 1} || crawlLimits[1] != [2]int{1, 1} {
		t.Fatalf("run-wide page quota was not decremented: %#v", crawlLimits)
	}
}

func TestExecuteActiveStreamingCancellationReturnsPartialTargets(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	index := activeDNSIndex(policy, "192.0.2.8")
	p := activeTestPlan("verify", "disabled", config.Modules{WebProbe: true})
	batches := make(chan []web.Target, 1)
	batches <- []web.Target{{Domain: "example.test"}}
	ctx, cancel := context.WithCancel(context.Background())
	ops := activeTestOps()
	ops.targetBatches = batches
	ops.probe = func(_ context.Context, _ *activehttp.Client, _ web.ProbeConfig, _ web.Target, _ string) (web.Result, error) {
		cancel()
		return web.Result{Status: "loaded"}, nil
	}
	sink, closeSink := activeTestSink(t, index, filepath.Join(t.TempDir(), "events", "run.jsonl"))
	defer closeSink()
	out, err := executeActive(ctx, p, portable.Payload{}, sink, func(string) error { return nil }, ops)
	close(batches)
	if err == nil || len(out.Targets) != 1 {
		t.Fatalf("partial stream result was not retained on cancellation: targets=%+v err=%v", out.Targets, err)
	}
}
