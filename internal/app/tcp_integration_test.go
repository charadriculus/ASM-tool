package app

import (
	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/portable"
	"asmtool/internal/storage"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTCPResultsPersistEveryStateAndOnlyOpenWebPortsBecomeCandidates(t *testing.T) {
	p := activeTestPlan("full", "disabled", config.Modules{PortScan: true, WebProbe: true, Crawler: true})
	p.cfg.AllowedCIDRs = []string{"192.0.2.0/24"}
	p.cfg.Ports = []int{80, 443, 8080}
	p.cfg.RateLimits.CrawlerMaxTotalPages = 6
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 4
	p.cfg.RateLimits.CrawlerMaxDepth = 1
	p.active = makeActiveSettings(p)
	idx := activeDNSIndex(p.cfg.ScopePolicy, "192.0.2.1")
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "a.example.test", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"192.0.2.2"}}})
	ops := activeTestOps()
	var probed []string
	var shared *activehttp.Client
	var limits []int
	ops.probe = func(_ context.Context, c *activehttp.Client, _ web.ProbeConfig, _ web.Target, url string) (web.Result, error) {
		if shared != nil && shared != c {
			t.Fatal("HTTP followup reset shared transport/budgets")
		}
		shared = c
		probed = append(probed, url)
		return web.Result{Status: "loaded"}, nil
	}
	ops.crawl = func(_ context.Context, c *activehttp.Client, cfg crawler.Config, urls []string) ([]crawler.Result, error) {
		if shared != nil && shared != c {
			t.Fatal("crawler got different transport")
		}
		limits = append(limits, cfg.MaxTotalPages)
		result := []crawler.Result{}
		for _, u := range urls {
			result = append(result, crawler.Result{Origin: crawlOrigin(u), Pages: []crawler.Page{{URL: u, Status: 200}}})
		}
		return result, nil
	}
	ops.tcp = func(_ context.Context, plan network.TCPPlan, _ []int, cfg network.TCPConfig) (network.TCPResult, error) {
		rows := []network.Observation{{IP: "192.0.2.2", Port: 8080, Protocol: "tcp", State: "open", Attempted: true, StartedAt: time.Now()}, {IP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "closed", Attempted: true, StartedAt: time.Now()}, {IP: "192.0.2.1", Port: 443, Protocol: "tcp", State: "unknown", Attempted: true, Reason: "timeout", Error: "fixture timeout", StartedAt: time.Now()}}
		for _, row := range rows {
			row.Domains = plan.Domains(row.IP)
			if err := cfg.Emit(row); err != nil {
				return network.TCPResult{}, err
			}
		}
		return network.TCPResult{Rows: rows, Planned: 3, Attempted: 3, Partial: true}, nil
	}
	sink, closeSink := activeTestSink(t, idx, filepath.Join(t.TempDir(), "events.jsonl"))
	defer closeSink()
	out, err := executeActive(context.Background(), p, portable.Payload{}, sink, func(string) error { return nil }, ops)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Incomplete || out.Coverage["tcp"] != "partial" {
		t.Fatalf("unknown hidden: %+v", out)
	}
	if !containsString(probed, "http://a.example.test:8080/") {
		t.Fatalf("open DNS-associated web candidate missing: %v", probed)
	}
	events, err := storage.IterEvents(context.Background(), sink.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]int{}
	for _, ev := range events {
		if ev["source_tool"] == "nmap" {
			t.Fatal("Nmap provenance retained")
		}
		if ev["event_type"] == "port_scan_result" {
			m := ev["metadata"].(map[string]any)
			states[m["state"].(string)]++
			if m["service"] != nil {
				t.Fatal("service guessed")
			}
		}
	}
	if states["open"] != 1 || states["closed"] != 1 || states["unknown"] != 1 {
		t.Fatalf("lost observations: %v", states)
	}
	var count int
	if err := sink.db.QueryRow("SELECT COUNT(*) FROM objects WHERE object_type='port_scan_result'").Scan(&count); err != nil || count != 3 {
		t.Fatalf("SQLite results %d: %v", count, err)
	}
	if len(limits) < 2 || limits[len(limits)-1] >= limits[0] {
		t.Fatalf("followup reset page budget: %v", limits)
	}
}

func TestTCPFullUsesLiteralLoopbackAndNoExternalScannerPayload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan struct{})
	go func() {
		c, err := listener.Accept()
		if err == nil {
			c.Close()
		}
		close(accepted)
	}()
	p := activeTestPlan("full", "disabled", config.Modules{PortScan: true})
	p.cfg.AllowedCIDRs = []string{"127.0.0.1/32"}
	p.cfg.Ports = []int{port}
	p.active = makeActiveSettings(p)
	out, events := runActiveTest(t, p, activeDNSIndex(p.cfg.ScopePolicy, "127.0.0.1"), portable.Payload{}, defaultActiveOps(), filepath.Join(t.TempDir(), "events.jsonl"))
	if out.Incomplete || out.Coverage["tcp"] != "complete" || out.Coverage["tcp_attempted"] != 1 {
		t.Fatalf("result %+v", out)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("connect not observed")
	}
	found := false
	for _, ev := range events {
		if ev["event_type"] == "port_scan_result" {
			found = true
			if ev["metadata"].(map[string]any)["state"] != "open" {
				t.Fatal(ev)
			}
		}
	}
	if !found {
		t.Fatal("missing connect evidence")
	}
}

func TestRemovedServiceFlagIsOrdinaryUnknownAndTCPIPv6URLIsBracketed(t *testing.T) {
	_, err := ParseOptions([]string{"--service-detection"})
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("removed flag was handled specially: %v", err)
	}
	if got := tcpWebURL("2001:db8::10", 8080); got != "http://[2001:db8::10]:8080/" {
		t.Fatal(got)
	}
}

func TestTCPCancellationPersistsCompletedObservationBeforeReturning(t *testing.T) {
	p := activeTestPlan("full", "disabled", config.Modules{PortScan: true})
	p.cfg.AllowedCIDRs = []string{"192.0.2.0/24"}
	p.active = makeActiveSettings(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops := activeTestOps()
	ops.tcp = func(_ context.Context, plan network.TCPPlan, _ []int, cfg network.TCPConfig) (network.TCPResult, error) {
		row := network.Observation{Domains: plan.Domains("192.0.2.1"), IP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "open", Attempted: true, StartedAt: time.Now()}
		cancel()
		if err := cfg.Emit(row); err != nil {
			return network.TCPResult{}, err
		}
		return network.TCPResult{Attempted: 1, Planned: 2, Unattempted: 1, Partial: true}, context.Canceled
	}
	sink, closeSink := activeTestSink(t, activeDNSIndex(p.cfg.ScopePolicy, "192.0.2.1"), filepath.Join(t.TempDir(), "events.jsonl"))
	defer closeSink()
	_, err := executeActive(ctx, p, portable.Payload{}, sink, func(string) error { return nil }, ops)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel %v", err)
	}
	events, err := storage.IterEvents(context.Background(), sink.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev["event_type"] == string(core.PortScanResult) {
			found = true
		}
	}
	if !found {
		t.Fatal("completed TCP result lost on cancellation")
	}
}

func TestTCPDenialPersistsEmptyAuthorityArrayInSQLiteAndJSONL(t *testing.T) {
	p := activeTestPlan("full", "disabled", config.Modules{PortScan: true})
	p.cfg.AllowedCIDRs = []string{"192.0.2.0/24"}
	p.active = makeActiveSettings(p)
	idx := activeDNSIndex(p.cfg.ScopePolicy, "192.0.2.1")
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, closeSink := activeTestSink(t, idx, path)
	defer closeSink()
	plan, err := network.BuildTCPPlan(idx, p.target, p.cfg.ScopePolicy, 500)
	if err != nil {
		t.Fatal(err)
	}
	row := network.Observation{IP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "unknown", Attempted: false, Reason: "latest_dns_or_scope_admission_denied"}
	contacted, url, domain, err := emitTCPRow(context.Background(), sink, p, plan, []int{80}, row)
	if err != nil {
		t.Fatal(err)
	}
	if contacted || url != "" || domain != "" {
		t.Fatal("denied pair became a contact/follow-up")
	}
	rows, err := storage.IterEvents(context.Background(), sink.db, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("SQLite observations %v: %v", rows, err)
	}
	for _, ev := range rows {
		meta := ev["metadata"].(map[string]any)
		domains, ok := meta["validated_domains"].([]any)
		if !ok || len(domains) != 0 || meta["attempted"] != false || meta["state"] != "unknown" {
			t.Fatalf("invalid denial evidence %v", ev)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &persisted); err != nil {
		t.Fatal(err)
	}
	meta := persisted["metadata"].(map[string]any)
	domains, ok := meta["validated_domains"].([]any)
	if !ok || len(domains) != 0 {
		t.Fatalf("JSONL authority is not an empty array: %s", data)
	}
}
