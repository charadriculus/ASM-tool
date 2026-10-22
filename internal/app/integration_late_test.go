package app

import (
	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/storage"
	"context"
	"path/filepath"
	"testing"
)

func TestTCPLateDiscoveryOverflowCannotReportComplete(t *testing.T) {
	p := activeTestPlan("full", "disabled", config.Modules{Crawler: true})
	p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML = true
	p.cfg.CollectionPolicy.DynamicDiscoveryMaxNewDomains = 1
	p.cfg.CollectionPolicy.DNSCandidateBudget = 10
	p.cfg.RateLimits.CrawlerMaxTotalPages = 10
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 10
	p.active = makeActiveSettings(p)
	index := activeDNSIndex(p.cfg.ScopePolicy, "192.0.2.10")
	index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "a.example.test", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.10"}}})
	index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "b.example.test", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.10"}}})
	sink, close := activeTestSink(t, index, filepath.Join(t.TempDir(), "events.jsonl"))
	defer close()
	ops := activeTestOps()
	ops.crawl = func(ctx context.Context, _ *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		for _, url := range []string{"https://a.example.test/", "https://b.example.test/", "https://c.example.test/"} {
			ev, err := core.NewEvent(core.URLFound, "crawler", "go_net_http", url, url, core.InScope)
			if err != nil {
				return nil, err
			}
			if err := cfg.Emit(ev); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	out := activeOutcome{Coverage: map[string]any{"crawler": "complete"}}
	pages := 0
	if err := followupTCPCrawler(context.Background(), p, nil, sink, ops, map[string]web.Target{"https://example.test/": {Domain: "example.test"}}, map[string]bool{}, &pages, map[string]int{}, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Incomplete || out.Coverage["crawler"] != "partial" {
		t.Fatalf("overflow reported complete: %+v", out)
	}
	rows, err := storage.IterEvents(context.Background(), sink.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range rows {
		meta, _ := ev["metadata"].(map[string]any)
		if meta["reason"] == "dynamic_candidate_collection_limit" && meta["severity"] == "warning" {
			found = true
		}
	}
	if !found {
		t.Fatal("overflow evidence missing")
	}
}
