package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/backends"
	"asmtool/internal/browser"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/platform"
	"asmtool/internal/portable"
	"asmtool/internal/storage"
)

func activeDNSIndex(policy core.ScopePolicy, ips ...string) *evidence.DNSRunIndex {
	index := evidence.NewDNSRunIndex(policy)
	terminal := make([]any, len(ips))
	for i, ip := range ips {
		terminal[i] = ip
	}
	index.Ingest(map[string]any{"event_type": string(core.DNSValidation), "normalized_value": "example.test", "observed_at": "2026-10-14T00:00:00Z", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": terminal}})
	return index
}

func activeTestPlan(profile, browserMode string, modules config.Modules) Plan {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	p := Plan{target: "example.test", browserMode: browserMode, timeout: time.Minute}
	p.allowHTTPFallback = true // Isolated fixtures explicitly opt into the Go HTTP backend.
	p.cfg = config.ToolConfig{Profile: profile, ScopePolicy: policy, AuthorizationConfirmed: true, Modules: modules,
		Ports: []int{80, 443}, RateLimits: config.RateLimits{HTTPMaxRequestsPerHost: 2, HTTPMaxConcurrency: 1, HTTPMaxConcurrencyPerOrigin: 1, GlobalMaxRequestsPerSecond: 1, HTTPStartIntervalSeconds: 0, BrowserNavigationTimeoutSeconds: 10, BrowserScreenshotTimeoutSeconds: 10, BrowserTargetTotalTimeoutSeconds: 20, BrowserDomSettleMilliseconds: 500, CrawlerMaxTotalPages: 150, TCPMaxRate: 10, TCPMaxTargets: 10, TCPMaxConcurrency: 1, TCPConnectTimeoutSeconds: 10},
		CollectionPolicy: config.CollectionPolicy{WebPrimaryDomainOnly: false, ObeyRobots: false},
		Backends:         config.BackendsConfig{HTTPProbeBackend: "projectdiscovery_httpx", NativeSubprocessTimeoutSeconds: 30}}
	p.active = makeActiveSettings(p)
	return p
}

func activeTestOps() activeOps {
	return activeOps{
		newBrowser: func(context.Context, *platform.Bundle, browser.Options) (browserController, error) {
			return &activeFixtureBrowser{}, nil
		},
		newHTTP: activehttp.NewClient,
		probe: func(_ context.Context, _ *activehttp.Client, _ web.ProbeConfig, _ web.Target, _ string) (web.Result, error) {
			return web.Result{Status: "loaded"}, nil
		},
		crawl: func(context.Context, *activehttp.Client, crawler.Config, []string) ([]crawler.Result, error) {
			return nil, nil
		},
		tcp: func(context.Context, network.TCPPlan, []int, network.TCPConfig) (network.TCPResult, error) {
			return network.TCPResult{}, nil
		},
	}
}

type activeFixtureBrowser struct{}

func (*activeFixtureBrowser) Capture(_ context.Context, req browser.CaptureRequest) (browser.CaptureResult, error) {
	return browser.CaptureResult{RequestedURL: req.URL, FinalURL: req.URL, DOM: "<html><title>fixture</title></html>", NetworkContacted: true}, nil
}
func (*activeFixtureBrowser) Close(context.Context) error { return nil }

type failedFixtureBrowser struct{}

func (*failedFixtureBrowser) Capture(context.Context, browser.CaptureRequest) (browser.CaptureResult, error) {
	return browser.CaptureResult{}, errors.New("fixture browser failure")
}
func (*failedFixtureBrowser) Close(context.Context) error { return nil }

func activeTestSink(t *testing.T, index *evidence.DNSRunIndex, eventPath string) (*durableSink, func()) {
	t.Helper()
	db, err := storage.Connect(context.Background(), filepath.Join(t.TempDir(), "run.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	writer := evidence.NewWriter(16, 4, time.Millisecond)
	return &durableSink{writer: writer, db: db, path: eventPath, index: index}, func() { _ = writer.Close(); _ = db.Close() }
}

func runActiveTest(t *testing.T, p Plan, index *evidence.DNSRunIndex, payload portable.Payload, ops activeOps, eventPath string) (activeOutcome, []map[string]any) {
	t.Helper()
	sink, closeSink := activeTestSink(t, index, eventPath)
	defer closeSink()
	out, err := executeActive(context.Background(), p, payload, sink, func(string) error { return nil }, ops)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := storage.IterEvents(context.Background(), sink.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out, rows
}

func TestExecuteActiveBrowserModesAndCurrentDNSTargets(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	index := activeDNSIndex(policy, "192.0.2.8")
	for _, tc := range []struct {
		mode, status string
		incomplete   bool
	}{{"required", "loaded", false}, {"disabled", "not_requested", false}} {
		t.Run(tc.mode, func(t *testing.T) {
			p := activeTestPlan("verify", tc.mode, config.Modules{WebProbe: true})
			p.cfg.OutputDir = t.TempDir()
			p.allowHTTPFallback = true
			ops := activeTestOps()
			probed, captured := 0, 0
			ops.newBrowser = func(context.Context, *platform.Bundle, browser.Options) (browserController, error) {
				captured++
				return &activeFixtureBrowser{}, nil
			}
			ops.probe = func(ctx context.Context, _ *activehttp.Client, cfg web.ProbeConfig, target web.Target, raw string) (web.Result, error) {
				probed++
				if target.Domain != "example.test" || raw != "https://example.test/" {
					t.Fatalf("probe target=%+v URL=%q", target, raw)
				}
				ev, err := core.NewEvent(core.WebTargetStatus, "web_probe", "go_net_http", target.Domain, target.Domain, core.InScope)
				if err != nil {
					return web.Result{}, err
				}
				ev.Metadata = map[string]any{"stage": "root_verification", "status": "loaded", "terminal": true, "page_loaded": true}
				if err := cfg.Emit(ev); err != nil {
					return web.Result{}, err
				}
				return web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}}, nil
			}
			out, events := runActiveTest(t, p, index, portable.Payload{}, ops, filepath.Join(t.TempDir(), "events", "run.jsonl"))
			wantCapture := 1
			if tc.mode == "disabled" {
				wantCapture = 0
			}
			if out.Incomplete != tc.incomplete || len(out.Targets) != 1 || probed != 1 || captured != wantCapture || out.Coverage["target_contacted"] != true {
				t.Fatalf("outcome=%+v probed=%d captured=%d", out, probed, captured)
			}
			foundBrowser, foundRoot := false, false
			for _, event := range events {
				if event["event_type"] != string(core.WebTargetStatus) {
					continue
				}
				meta, _ := event["metadata"].(map[string]any)
				switch meta["stage"] {
				case "browser":
					foundBrowser = meta["status"] == tc.status
					if tc.status == "loaded" {
						foundBrowser = foundBrowser && meta["page_loaded"] == true && meta["target_service_contacted"] == true
					} else {
						foundBrowser = foundBrowser && meta["page_loaded"] == false && meta["target_service_contacted"] == false
					}
				case "root_verification":
					foundRoot = true
				}
			}
			if !foundBrowser || !foundRoot {
				t.Fatalf("missing browser/root states: %#v", events)
			}
			prov, ok := out.BackendProvenance[0].(backends.BackendResolution)
			if !ok || prov.Status != "fallback" || prov.FallbackReason != "user_explicit_policy" || prov.Actual != "go_net_http" {
				t.Fatalf("HTTP fallback provenance=%#v", out.BackendProvenance)
			}
		})
	}
}

func TestRequestedBrowserCaptureFailureIsIncomplete(t *testing.T) {
	p := activeTestPlan("verify", "required", config.Modules{})
	p.cfg.OutputDir = t.TempDir()
	ops := activeTestOps()
	ops.newBrowser = func(context.Context, *platform.Bundle, browser.Options) (browserController, error) {
		return &failedFixtureBrowser{}, nil
	}
	out, events := runActiveTest(t, p, activeDNSIndex(p.cfg.ScopePolicy, "192.0.2.8"), portable.Payload{}, ops, filepath.Join(t.TempDir(), "events", "run.jsonl"))
	if !out.Incomplete || out.Coverage["browser"] != "partial" || out.Coverage["browser_pages_failed"] != 1 {
		t.Fatalf("failed requested browser was success-shaped: outcome=%+v", out)
	}
	foundFailed := false
	for _, event := range events {
		if event["event_type"] != string(core.WebTargetStatus) {
			continue
		}
		meta, _ := event["metadata"].(map[string]any)
		if meta["stage"] == "browser" && meta["status"] == "failed" {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Fatalf("missing browser failure event: %#v", events)
	}
}

func TestExecuteActiveTCPEmptyPlanAndCancellation(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	p := activeTestPlan("full", "disabled", config.Modules{PortScan: true})
	ops := activeTestOps()
	called := false
	ops.tcp = func(context.Context, network.TCPPlan, []int, network.TCPConfig) (network.TCPResult, error) {
		called = true
		return network.TCPResult{}, nil
	}
	out, _ := runActiveTest(t, p, activeDNSIndex(policy), portable.Payload{}, ops, filepath.Join(t.TempDir(), "events", "empty.jsonl"))
	if called || out.Coverage["tcp"] != "no_eligible_targets" || out.Incomplete || out.Coverage["target_contacted"] != false || out.Coverage["active_operations_attempted"] != nil {
		t.Fatalf("empty TCP plan marked successful or invoked: called=%t outcome=%+v", called, out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sink, closeSink := activeTestSink(t, activeDNSIndex(policy), filepath.Join(t.TempDir(), "events", "cancel.jsonl"))
	defer closeSink()
	_, err := executeActive(ctx, p, portable.Payload{}, sink, func(string) error { return nil }, ops)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
}

func TestExecuteActiveTCPLocalTimeoutRetainsPartialOpenRows(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"192.0.2.0/24"}}
	index := activeDNSIndex(policy, "192.0.2.10")
	p := activeTestPlan("full", "disabled", config.Modules{PortScan: true})
	p.cfg.ScopePolicy = policy
	p.cfg.Backends.NativeSubprocessTimeoutSeconds = 1
	p.cfg.OutputDir = t.TempDir()
	p.active = makeActiveSettings(p)
	ops := activeTestOps()
	ops.tcp = func(ctx context.Context, plan network.TCPPlan, _ []int, cfg network.TCPConfig) (network.TCPResult, error) {
		row := network.Observation{Domains: plan.Domains("192.0.2.10"), IP: "192.0.2.10", Port: 80, Protocol: "tcp", State: "open", Attempted: true, StartedAt: time.Now()}
		<-ctx.Done()
		if err := cfg.Emit(row); err != nil {
			return network.TCPResult{}, err
		}
		return network.TCPResult{Rows: []network.Observation{row}, Planned: 2, Attempted: 1, Unattempted: 1, Partial: true}, ctx.Err()
	}
	out, events := runActiveTest(t, p, index, portable.Payload{}, ops, filepath.Join(t.TempDir(), "events", "timeout.jsonl"))
	if !out.Incomplete || out.Coverage["tcp"] != "partial" || out.Coverage["target_contacted"] != true || out.Coverage["tcp_scan_attempted"] != true {
		t.Fatalf("timeout outcome=%+v", out)
	}
	foundRow, foundTimeout := false, false
	for _, event := range events {
		if event["event_type"] == string(core.PortScanResult) {
			foundRow = true
		}
		if event["event_type"] == string(core.Limitation) {
			if event["metadata"].(map[string]any)["reason"] == "tcp_scan_timeout" {
				foundTimeout = true
			}
		}
	}
	if !foundRow || !foundTimeout {
		t.Fatalf("timeout did not retain row and timeout limitation: %#v", events)
	}
}

func TestExecuteActiveDynamicAdmissionIsBoundedAndCrawlerPagesAreGlobal(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	index := activeDNSIndex(policy, "192.0.2.8")
	p := activeTestPlan("verify", "disabled", config.Modules{WebProbe: true, Crawler: true})
	p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML = true
	p.cfg.CollectionPolicy.DynamicDiscoveryMaxRounds = 1
	p.cfg.CollectionPolicy.DynamicDiscoveryMaxNewDomains = 4
	p.cfg.CollectionPolicy.DNSCandidateBudget = 10
	p.cfg.RateLimits.CrawlerMaxTotalPages = 3
	p.active = makeActiveSettings(p)
	p.allowHTTPFallback = true
	ops := activeTestOps()
	probed := []string{}
	crawlLimits := []int{}
	admissionCalls := 0
	ops.probe = func(_ context.Context, _ *activehttp.Client, _ web.ProbeConfig, target web.Target, _ string) (web.Result, error) {
		probed = append(probed, target.Domain)
		if target.Domain == "example.test" {
			return web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}, DiscoveredDomains: []string{"deep.example.test"}}, nil
		}
		return web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}, DiscoveredDomains: []string{"later.example.test"}}, nil
	}
	ops.crawl = func(_ context.Context, _ *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		crawlLimits = append(crawlLimits, cfg.MaxTotalPages)
		if len(roots) != 1 {
			t.Fatalf("crawler roots=%v", roots)
		}
		if len(crawlLimits) == 1 {
			ev, err := core.NewEvent(core.URLFound, "crawler", "fixture", "https://crawl.example.test/path", "https://crawl.example.test/path", core.InScope)
			if err != nil {
				return nil, err
			}
			if err := cfg.Emit(ev); err != nil {
				return nil, err
			}
			return []crawler.Result{{Origin: "https://example.test", Pages: []crawler.Page{{}, {}}}}, nil
		}
		return []crawler.Result{{Origin: "https://deep.example.test", Pages: []crawler.Page{{}}}}, nil
	}
	ops.admitDomains = func(_ context.Context, candidates []string) (dynamicAdmissionResult, error) {
		admissionCalls++
		if admissionCalls == 1 {
			if !containsString(candidates, "deep.example.test") || !containsString(candidates, "crawl.example.test") {
				t.Fatalf("HTTP/crawler candidates not accumulated: %v", candidates)
			}
			return dynamicAdmissionResult{Targets: []web.Target{{Domain: "deep.example.test", TerminalIPs: []string{"192.0.2.20"}, DNSEvidence: []string{"dns_validation"}}}, Added: 1, Round: 1}, nil
		}
		if !containsString(candidates, "later.example.test") {
			t.Fatalf("last-round discovery was dropped: %v", candidates)
		}
		return dynamicAdmissionResult{Deferred: 1, Round: 1, RoundLimit: true}, nil
	}
	sink, closeSink := activeTestSink(t, index, filepath.Join(t.TempDir(), "events", "dynamic.jsonl"))
	defer closeSink()
	out, err := executeActive(context.Background(), p, portable.Payload{}, sink, func(string) error { return nil }, ops)
	if err != nil {
		t.Fatal(err)
	}
	if admissionCalls != 2 || len(probed) != 2 || probed[0] != "example.test" || probed[1] != "deep.example.test" {
		t.Fatalf("admissions=%d probed=%v", admissionCalls, probed)
	}
	if len(crawlLimits) != 2 || crawlLimits[0] != 3 || crawlLimits[1] != 1 {
		t.Fatalf("crawler per-round page caps=%v", crawlLimits)
	}
	if !out.Incomplete || out.Coverage["dynamic_discovery_deferred"] != 1 || out.Coverage["crawler"] != "partial" || len(out.Targets) != 2 {
		t.Fatalf("dynamic outcome=%+v", out)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestExecuteActiveCrawlerOnlyPreservesPartialCoverage(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	p := activeTestPlan("verify", "disabled", config.Modules{Crawler: true})
	p.cfg.RateLimits.CrawlerMaxTotalPages = 4
	p.active = makeActiveSettings(p)
	p.allowHTTPFallback = true
	ops := activeTestOps()
	ops.crawl = func(_ context.Context, _ *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		if cfg.MaxTotalPages != 4 || len(roots) != 1 {
			t.Fatalf("crawler config max=%d roots=%v", cfg.MaxTotalPages, roots)
		}
		return []crawler.Result{{Origin: "https://example.test", Pages: []crawler.Page{{}}, Partial: true, Reason: "body_truncated"}}, nil
	}
	out, _ := runActiveTest(t, p, activeDNSIndex(policy, "192.0.2.1"), portable.Payload{}, ops, filepath.Join(t.TempDir(), "events", "crawler-only.jsonl"))
	if out.Coverage["crawler"] != "partial" || !out.Incomplete || out.Coverage["active_operations_attempted"] != true || out.Coverage["target_contacted"] != "unknown" {
		t.Fatalf("partial crawler result was reported complete: %+v", out)
	}
}

func TestExecuteActiveIgnoresDiscoveredDomainsWhenDynamicPolicyIsDisabled(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	p := activeTestPlan("verify", "disabled", config.Modules{WebProbe: true})
	p.allowHTTPFallback = true
	ops := activeTestOps()
	ops.probe = func(context.Context, *activehttp.Client, web.ProbeConfig, web.Target, string) (web.Result, error) {
		return web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}, DiscoveredDomains: []string{"child.example.test"}}, nil
	}
	out, _ := runActiveTest(t, p, activeDNSIndex(policy, "192.0.2.10"), portable.Payload{}, ops, filepath.Join(t.TempDir(), "events", "dynamic-disabled.jsonl"))
	if out.Coverage["dynamic_discovery_added"] != nil || len(out.Targets) != 1 {
		t.Fatalf("disabled dynamic policy admitted a candidate: %+v", out)
	}
}

func TestExecuteActivePropagatesDurableSinkFailure(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	p := activeTestPlan("verify", "disabled", config.Modules{})
	sink, _ := activeTestSink(t, activeDNSIndex(policy), filepath.Join(t.TempDir(), "events", "run.jsonl"))
	if err := sink.db.Close(); err != nil {
		t.Fatal(err)
	}
	defer sink.writer.Close()
	_, err := executeActive(context.Background(), p, portable.Payload{}, sink, func(string) error { return nil }, activeTestOps())
	if err == nil {
		t.Fatal("durable sink failure was swallowed")
	}
}

func TestRenderedLinksRespectScopeExclusions(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, ExcludedDomains: []string{"secret.example.test"}}
	sink, closeSink := activeTestSink(t, activeDNSIndex(policy), filepath.Join(t.TempDir(), "events.jsonl"))
	defer closeSink()
	capture := browser.CaptureResult{FinalURL: "https://example.test/", Links: []string{"https://secret.example.test/private", "https://example.test/allowed", "https://outside.test/"}}
	if err := emitBrowserLinks(context.Background(), sink, capture, "example.test", core.ScopeChecker{Policy: policy}); err != nil {
		t.Fatal(err)
	}
	rows, err := storage.IterEvents(context.Background(), sink.db, []string{string(core.URLFound)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["normalized_value"] != "https://example.test/allowed" || rows[0]["scope_status"] != "in_scope" {
		t.Fatalf("excluded/outside links were saved in scope: %#v", rows)
	}
}
