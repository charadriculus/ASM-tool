package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
	"asmtool/internal/portable"
)

var (
	g16Approval = flag.String("g16-native-approval", "", "explicit approval token for the local-fixtures-only G16 kit")
	g16Payload  = flag.String("g16-native-payload", "", "read-only portable payload root for G16 manifest verification")
	g16Evidence = flag.String("g16-native-evidence", "", "fresh evidence directory for G16 local fixture results")
)

const g16ApprovalToken = "local-fixtures-only"

// TestG16NativeCheckKit is explicitly opt-in. It verifies payload identity but
// never executes a bundled tool; all active network traffic is loopback fixture
// traffic. This does not qualify TCP, PDF/Typst, browser isolation, or providers.
func TestG16NativeCheckKit(t *testing.T) {
	provided := *g16Approval != "" || *g16Payload != "" || *g16Evidence != ""
	if !provided {
		t.Skip("G16 kit is opt-in; pass approval, payload, and fresh evidence flags")
	}
	if *g16Approval != g16ApprovalToken {
		t.Fatalf("invalid G16 approval token")
	}
	if *g16Payload == "" || *g16Evidence == "" {
		t.Fatal("G16 payload and evidence flags are both required")
	}
	if runtime.GOARCH != "amd64" || (runtime.GOOS != "linux" && runtime.GOOS != "windows") {
		t.Fatalf("unsupported native G16 platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if !strings.EqualFold(BundleManifestSHA256, g16PlatformManifestPin()) {
		t.Fatalf("embedded bundle trust anchor does not match approved %s payload pin", runtime.GOOS)
	}
	if err := createFreshEvidenceRoot(*g16Evidence); err != nil {
		t.Fatalf("evidence root must be fresh: %v", err)
	}
	previousProcs := runtime.GOMAXPROCS(2)
	previousMemoryLimit := debug.SetMemoryLimit(512 << 20)
	defer func() {
		runtime.GOMAXPROCS(previousProcs)
		debug.SetMemoryLimit(previousMemoryLimit)
	}()

	result := g16Result{
		SchemaVersion: 1, Status: "RUNNING", Platform: runtime.GOOS + "/" + runtime.GOARCH,
		BundleManifestSHA256: strings.ToLower(BundleManifestSHA256), VerifiedComponents: map[string]g16Component{},
		ExecutionBoundary: "local loopback fixtures and synthetic DNS evidence only",
		Scenarios:         map[string]g16Scenario{}, NotRun: g16NotRun(), ArtifactPreservation: true, Historical: map[string]string{
			"browser": "BLOCKED; candidate31 FAIL preserved", "linux_strict_network_gate": "FAIL preserved; not repeated",
		},
	}
	checkpoints := []map[string]string{}
	defer func() {
		if result.Status == "RUNNING" || t.Failed() {
			result.Status = "FAIL"
		}
		if files, err := g16EvidenceFiles(*g16Evidence); err == nil {
			result.Artifacts = files
		} else {
			result.Status = "FAIL"
			result.ArtifactPreservation = false
			t.Errorf("hash partial G16 evidence: %v", err)
		}
		if err := g16WriteResult(filepath.Join(*g16Evidence, "g16-result.json"), result); err != nil {
			t.Errorf("write G16 result: %v", err)
		}
	}()
	payload, err := portable.Verify(*g16Payload, BundleManifestSHA256, true, false)
	if err != nil {
		t.Fatalf("read-only portable identity verification: %v", err)
	}
	if payload.Subfaster == nil || payload.Typst.Path() == "" {
		t.Fatal("verified payload lacks an expected tool identity")
	}
	for _, tool := range []platformTool{{"typst", payload.Typst.Path(), payload.Typst.Version()}, {"subfaster", payload.Subfaster.Path(), payload.Subfaster.Version()}} {
		digest, err := g16FileSHA256(tool.path)
		if err != nil {
			t.Fatalf("hash verified %s: %v", tool.name, err)
		}
		result.VerifiedComponents[tool.name] = g16Component{Version: tool.version, SHA256: digest}
	}
	all := []struct {
		name string
		fn   func(*testing.T, string) g16Scenario
	}{
		{"streaming_pipeline", g16StreamingScenario},
		{"batch_ranked_pipeline", g16BatchRankedScenario},
		{"arrival_budget", g16ArrivalBudgetScenario},
		{"shared_http_page_budgets", g16SharedBudgetsScenario},
		{"loopback_http_crawler", g16LoopbackScenario},
		{"backpressure_cancel_partial_persistence", g16CancelScenario},
	}
	for _, scenario := range all {
		scenario := scenario
		passed := t.Run(scenario.name, func(t *testing.T) {
			caseDir := filepath.Join(*g16Evidence, "runs", scenario.name)
			if err := os.MkdirAll(filepath.Dir(caseDir), 0700); err != nil {
				t.Fatal(err)
			}
			doc := scenario.fn(t, caseDir)
			if t.Failed() {
				doc.Status = "FAIL"
			}
			result.Scenarios[scenario.name] = doc
			if doc.Status != "PASS" {
				t.Errorf("scenario status %s: %s", doc.Status, doc.Error)
			}
		})
		if !passed {
			if _, exists := result.Scenarios[scenario.name]; !exists {
				result.Scenarios[scenario.name] = g16Scenario{Status: "FAIL", Error: "scenario aborted before producing a result"}
			}
			return
		}
		files, err := g16EvidenceFiles(*g16Evidence)
		if err != nil {
			result.Scenarios[scenario.name] = g16Scenario{Status: "FAIL", Error: "could not checkpoint evidence: " + err.Error()}
			result.Status = "FAIL"
			t.Error("could not checkpoint evidence: " + err.Error())
			return
		}
		for _, previous := range checkpoints {
			for rel, want := range previous {
				path := filepath.Join(filepath.Dir(*g16Evidence), filepath.FromSlash(rel))
				got, hashErr := g16FileSHA256(path)
				if hashErr != nil || got != want {
					result.ArtifactPreservation = false
					result.Scenarios[scenario.name] = g16Scenario{Status: "FAIL", Error: "earlier scenario evidence changed: " + rel}
					result.Status = "FAIL"
					t.Error("earlier scenario evidence changed: " + rel)
					return
				}
			}
		}
		snapshot := map[string]string{}
		for rel, artifact := range files {
			snapshot[rel] = artifact.SHA256
		}
		checkpoints = append(checkpoints, snapshot)
	}

	t.Run("payload_identity_only", func(t *testing.T) {
		result.Scenarios["payload_identity_only"] = g16Scenario{Status: "PASS", ExecutionMode: "portable.Verify read-only hashing; no child processes", DNS: "NOT_RUN", Probe: "NOT_RUN", HTTP: "NOT_RUN", Crawler: "NOT_RUN", NetworkScope: "no network", RunStatus: "identity_verified", Details: map[string]any{"bundle_manifest_sha256": BundleManifestSHA256, "tool_execution": "none"}}
	})
	allPass := len(result.Scenarios) == 7 && result.ArtifactPreservation
	for _, row := range result.Scenarios {
		allPass = allPass && row.Status == "PASS"
	}
	if allPass {
		result.Status = "PASS_FUNCTIONAL_ONLY"
	} else {
		result.Status = "FAIL"
		t.Error("one or more required G16 scenarios did not complete")
	}
}

type platformTool struct{ name, path, version string }
type g16Component struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type g16Scenario struct {
	Status        string         `json:"status"`
	ExecutionMode string         `json:"execution_mode"`
	DNS           string         `json:"dns"`
	Probe         string         `json:"probe"`
	HTTP          string         `json:"http"`
	Crawler       string         `json:"crawler"`
	NetworkScope  string         `json:"network_scope"`
	RunStatus     string         `json:"run_status"`
	Details       map[string]any `json:"details"`
	Error         string         `json:"error,omitempty"`
}
type g16Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type g16Result struct {
	SchemaVersion        int                     `json:"schema_version"`
	Status               string                  `json:"status"`
	Platform             string                  `json:"platform"`
	BundleManifestSHA256 string                  `json:"bundle_manifest_sha256"`
	ExecutionBoundary    string                  `json:"execution_boundary"`
	VerifiedComponents   map[string]g16Component `json:"verified_components"`
	Scenarios            map[string]g16Scenario  `json:"scenarios"`
	NotRun               map[string]string       `json:"not_run"`
	Historical           map[string]string       `json:"historical"`
	Artifacts            map[string]g16Artifact  `json:"artifacts"`
	ArtifactPreservation bool                    `json:"artifact_preservation"`
}

func g16PlatformManifestPin() string {
	if runtime.GOOS == "linux" {
		return "86c83b34d7d62caae5f1a7e8fb54b8163b8df05e7009ef4993ae446296fd2e41"
	}
	return "c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479"
}

func g16NotRun() map[string]string {
	return map[string]string{
		"tcp_runtime":            "NOT_RUN: payload identity only; no scan or subprocess",
		"typst_pdf":              "NOT_RUN: payload identity only; no PDF generation",
		"subfaster_runtime":      "NOT_RUN: no version probe or subprocess",
		"obscura_browser":        "BLOCKED: candidate31 FAIL preserved; no browser launch",
		"external_dns_providers": "NOT_RUN: synthetic local DNS evidence only",
		"strict_network_gate": func() string {
			if runtime.GOOS == "linux" {
				return "FAIL_PRESERVED: no retry"
			}
			return "NOT_RUN: not part of G16 local kit"
		}(),
	}
}

func g16FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func g16EvidenceFiles(root string) (map[string]g16Artifact, error) {
	out := map[string]g16Artifact{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence contains non-regular file %s", path)
		}
		rel, err := filepath.Rel(filepath.Dir(root), path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		digest, err := g16FileSHA256(path)
		if err != nil {
			return err
		}
		out[rel] = g16Artifact{Path: rel, SHA256: digest}
		return nil
	})
	return out, err
}
func g16WriteResult(path string, result g16Result) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, path)
}

// TestG16CheckHarnessOffline exercises the same scenarios without payload
// verification or child processes; its only network activity is loopback fixtures.
func TestG16CheckHarnessOffline(t *testing.T) {
	if *g16Approval != "" || *g16Payload != "" || *g16Evidence != "" {
		t.Skip("native opt-in flags were supplied")
	}
	dir := t.TempDir()
	for _, scenario := range []struct {
		name string
		fn   func(*testing.T, string) g16Scenario
	}{
		{"streaming_pipeline", g16StreamingScenario},
		{"batch_ranked_pipeline", g16BatchRankedScenario},
		{"arrival_budget", g16ArrivalBudgetScenario},
		{"shared_http_page_budgets", g16SharedBudgetsScenario},
		{"loopback_http_crawler", g16LoopbackScenario},
		{"backpressure_cancel_partial_persistence", g16CancelScenario},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			out := filepath.Join(dir, scenario.name, "run")
			if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
				t.Fatal(err)
			}
			doc := scenario.fn(t, out)
			if doc.Status != "PASS" {
				t.Fatalf("offline helper scenario failed: %+v", doc)
			}
		})
	}
	path := filepath.Join(dir, "g16-result.json")
	doc := g16Result{SchemaVersion: 1, Status: "NOT_RUN", Platform: runtime.GOOS + "/" + runtime.GOARCH, NotRun: g16NotRun(), Scenarios: map[string]g16Scenario{"example": {Status: "NOT_RUN"}}}
	if err := g16WriteResult(path, doc); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded g16Result
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "NOT_RUN" || decoded.Scenarios["example"].Status != "NOT_RUN" {
		t.Fatalf("offline harness fabricated a pass: %+v", decoded)
	}
}

func g16BasePlan(t *testing.T, outDir string, streaming bool, budget, workers int) (Plan, stages) {
	t.Helper()
	p, stage, _ := streamingFixture(t)
	p.cfg.OutputDir = outDir
	p.cfg.DatabasePath = filepath.Join(outDir, "asm.sqlite3")
	p.cfg.AuthorizationConfirmed = true
	p.browserMode = "disabled"
	p.cfg.Profile = "verify"
	p.cfg.Modules.Subdomains, p.cfg.Modules.DomainExpansion = true, true
	p.cfg.Modules.WebProbe, p.cfg.Modules.Crawler, p.cfg.Modules.Screenshots = true, true, false
	p.cfg.CollectionPolicy.StreamingPipelineEnabled = streaming
	p.cfg.CollectionPolicy.DNSCandidateBudget = budget
	p.cfg.RateLimits.DNSWorkerCount = workers
	p.cfg.RateLimits.CrawlerMaxTotalPages = 8
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 4
	p.cfg.RateLimits.CrawlerMaxDepth = 1
	p.cfg.RateLimits.HTTPMaxRequestsPerHost = 4
	p.cfg.RateLimits.HTTPDelaySeconds = 0
	p.cfg.RateLimits.GlobalMaxRequestsPerSecond = 1000
	p.active = makeActiveSettings(p)
	return p, stage
}
func g16FixtureValidation(cfg dns.ExpansionConfig, name, root string) error {
	ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "g16_local_fixture", name, name, core.InScope)
	if err != nil {
		return err
	}
	ev.Metadata = map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.55"}, "input_target": name == root, "g16_fixture": true, "target_service_contacted": false}
	return cfg.Emit(ev)
}
func g16FixtureCollector(root string, names ...string) func(context.Context, passive.CollectRequest) (passive.CollectResult, error) {
	return func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		return streamDiscovery(ctx, req, names...)
	}
}
func g16FakeOps(probe func(context.Context, *activehttp.Client, web.Target, string) web.Result, crawl func(context.Context, *activehttp.Client, crawler.Config, []string) []crawler.Result) activeOps {
	ops := activeTestOps()
	ops.probe = func(ctx context.Context, client *activehttp.Client, cfg web.ProbeConfig, target web.Target, raw string) (web.Result, error) {
		if err := ctx.Err(); err != nil {
			return web.Result{}, err
		}
		r := probe(ctx, client, target, raw)
		if r.Status == "" {
			r.Status = "loaded"
		}
		return r, nil
	}
	ops.crawl = func(ctx context.Context, client *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return crawl(ctx, client, cfg, roots), nil
	}
	return ops
}
func g16Run(t *testing.T, p Plan, stage stages, timeout time.Duration) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return executePassive(ctx, p, portable.Payload{}, nil, stage)
}
func g16Rows(t *testing.T, p Plan) []map[string]any {
	t.Helper()
	return assertStreamingDurability(t, p)
}
func g16Doc(status, mode, dnsStatus, probeStatus, httpStatus, crawlerStatus, scope, runStatus string, details map[string]any, err error) g16Scenario {
	doc := g16Scenario{Status: status, ExecutionMode: mode, DNS: dnsStatus, Probe: probeStatus, HTTP: httpStatus, Crawler: crawlerStatus, NetworkScope: scope, RunStatus: runStatus, Details: details}
	if err != nil {
		doc.Error = err.Error()
	}
	return doc
}

func g16StreamingScenario(t *testing.T, out string) g16Scenario {
	p, stage := g16BasePlan(t, out, true, 10, 2)
	probeEntered, crawlEntered := make(chan struct{}, 1), make(chan struct{}, 1)
	var collectOverlap atomic.Bool
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		inventory, err := streamDiscovery(ctx, req, p.target, "a.example.test", "b.example.test")
		if err != nil {
			return inventory, err
		}
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		seenProbe, seenCrawl := false, false
		for !seenProbe || !seenCrawl {
			select {
			case <-probeEntered:
				seenProbe = true
			case <-crawlEntered:
				seenCrawl = true
			case <-ctx.Done():
				return inventory, ctx.Err()
			case <-deadline.C:
				return inventory, errors.New("active probe/crawler did not overlap provider collection")
			}
		}
		collectOverlap.Store(true)
		return inventory, nil
	}
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, _ *dns.WildcardAnalyzer, name string) (dns.QuickValidationResult, error) {
		err := g16FixtureValidation(cfg, name, p.target)
		return dns.QuickValidationResult{Domain: name, Validated: err == nil, Eligible: err == nil}, err
	}
	stage.expand = func(ctx context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
		return dns.ExpansionResult{}, nil
	}
	var probes atomic.Int32
	seenDomains := map[string]int{}
	var seenMu sync.Mutex
	stage.ops = g16FakeOps(func(_ context.Context, _ *activehttp.Client, target web.Target, _ string) web.Result {
		probes.Add(1)
		seenMu.Lock()
		seenDomains[target.Domain]++
		seenMu.Unlock()
		select {
		case probeEntered <- struct{}{}:
		default:
		}
		return web.Result{Status: "loaded"}
	}, func(_ context.Context, _ *activehttp.Client, _ crawler.Config, roots []string) []crawler.Result {
		select {
		case crawlEntered <- struct{}{}:
		default:
		}
		out := make([]crawler.Result, 0, len(roots))
		for _, root := range roots {
			out = append(out, crawler.Result{Origin: crawlOrigin(root), Pages: []crawler.Page{{URL: root, Status: 200}}})
		}
		return out
	})
	res, err := g16Run(t, p, stage, 10*time.Second)
	rows := g16Rows(t, p)
	coverageBytes, coverageReadErr := os.ReadFile(filepath.Join(out, "run_summary.json"))
	var summary struct {
		Coverage map[string]any `json:"coverage"`
	}
	coverageDecodeErr := json.Unmarshal(coverageBytes, &summary)
	seenMu.Lock()
	domains := map[string]int{}
	for domain, n := range seenDomains {
		domains[domain] = n
	}
	seenMu.Unlock()
	if err != nil || res.Incomplete || !collectOverlap.Load() || probes.Load() != 3 || len(domains) != 3 || len(rows) == 0 || coverageReadErr != nil || coverageDecodeErr != nil || summary.Coverage["pipeline_schedule"] != "bounded_streaming" || summary.Coverage["dns_selection_policy"] != "arrival_order" {
		return g16Doc("FAIL", "streaming Go pipeline", "synthetic DNS evidence", "fake HTTP probe", "fake ops; no network", "fake crawler", "no external network", "failed", map[string]any{"events": len(rows), "probe_calls": probes.Load(), "domains": domains, "provider_overlapped_active": collectOverlap.Load(), "run_summary": string(coverageBytes)}, err)
	}
	return g16Doc("PASS", "streaming Go pipeline", "synthetic durable validation", "fake Go probe", "fake ops; no network", "fake crawler", "no external network", "complete", map[string]any{"events": len(rows), "probe_calls": probes.Load(), "domains": domains, "provider_overlapped_active": true, "run_schedule": "bounded_streaming/arrival_order"}, nil)
}

func g16BatchRankedScenario(t *testing.T, out string) g16Scenario {
	p, stage := g16BasePlan(t, out, false, 2, 1)
	stage.collect = g16FixtureCollector(p.target, p.target, "z.example.test", "a.example.test")
	var selected []string
	stage.expand = func(ctx context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
		names, err := dns.RankedInventoryNames(cfg.Inventory, cfg.Root, cfg.Budget, cfg.Policy)
		if err != nil {
			return dns.ExpansionResult{}, err
		}
		ranked, deferredEntries := evidence.RankProviderInventory(cfg.Inventory, cfg.Root, cfg.Budget)
		deferred := make([]string, 0, len(deferredEntries))
		for _, item := range deferredEntries {
			deferred = append(deferred, item.Hostname)
			ev, eventErr := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_budget", item.Hostname, item.Hostname, core.InScope)
			if eventErr != nil {
				return dns.ExpansionResult{}, eventErr
			}
			ev.Metadata = map[string]any{"dns_state": "deferred_by_dns_budget", "active_eligibility": "not_selected", "dns_validated": false, "target_service_contacted": false, "reason": "configured dns_candidate_budget", "dns_candidate_budget": cfg.Budget}
			if eventErr = cfg.Emit(ev); eventErr != nil {
				return dns.ExpansionResult{}, eventErr
			}
		}
		selected = append([]string(nil), names...)
		if len(ranked) != len(names) {
			return dns.ExpansionResult{}, errors.New("ranked inventory selection disagrees with expansion selector")
		}
		for i, item := range ranked {
			if item.Hostname != names[i] {
				return dns.ExpansionResult{}, errors.New("ranked inventory order disagrees with expansion selector")
			}
		}
		for _, name := range names {
			if err := g16FixtureValidation(cfg, name, p.target); err != nil {
				return dns.ExpansionResult{}, err
			}
		}
		return dns.ExpansionResult{Selected: names, Deferred: deferred}, nil
	}
	stage.ops = g16FakeOps(func(context.Context, *activehttp.Client, web.Target, string) web.Result {
		return web.Result{Status: "loaded"}
	}, func(context.Context, *activehttp.Client, crawler.Config, []string) []crawler.Result { return nil })
	res, err := g16Run(t, p, stage, 10*time.Second)
	rows := g16Rows(t, p)
	ok := err == nil && len(selected) == 2 && selected[0] == p.target && selected[1] == "a.example.test" && res.Incomplete && len(rows) > 0
	if !ok {
		return g16Doc("FAIL", "batch ranked Go pipeline", "synthetic DNS validations", "fake probe", "fake ops; no network", "fake crawler", "no external network", "failed", map[string]any{"selected": selected, "events": len(rows), "incomplete": res.Incomplete}, err)
	}
	return g16Doc("PASS", "batch ranked Go pipeline", "synthetic DNS validations", "fake probe", "fake ops; no network", "fake crawler", "no external network", "degraded_expected_budget_deferred", map[string]any{"selected": selected, "events": len(rows), "incomplete": true}, nil)
}

func g16ArrivalBudgetScenario(t *testing.T, out string) g16Scenario {
	p, stage := g16BasePlan(t, out, true, 2, 1)
	stage.collect = g16FixtureCollector(p.target, p.target, "z.example.test", "a.example.test")
	var starts []string
	var mu sync.Mutex
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, _ *dns.WildcardAnalyzer, name string) (dns.QuickValidationResult, error) {
		mu.Lock()
		starts = append(starts, name)
		mu.Unlock()
		err := g16FixtureValidation(cfg, name, p.target)
		return dns.QuickValidationResult{Domain: name, Validated: err == nil, Eligible: err == nil}, err
	}
	stage.expand = func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error) {
		return dns.ExpansionResult{}, nil
	}
	stage.ops = g16FakeOps(func(context.Context, *activehttp.Client, web.Target, string) web.Result {
		return web.Result{Status: "loaded"}
	}, func(context.Context, *activehttp.Client, crawler.Config, []string) []crawler.Result { return nil })
	res, err := g16Run(t, p, stage, 10*time.Second)
	rows := g16Rows(t, p)
	want := []string{p.target, "z.example.test"}
	ok := err == nil && len(starts) == 2 && starts[0] == want[0] && starts[1] == want[1] && res.Incomplete && len(rows) > 0
	if !ok {
		return g16Doc("FAIL", "streaming arrival-order budget; one DNS worker", "synthetic validation start sequence", "fake probe", "fake ops; no network", "fake crawler", "no external network", "failed", map[string]any{"validation_start_sequence": starts, "expected_prefix": want}, err)
	}
	return g16Doc("PASS", "streaming arrival-order budget; one DNS worker", "synthetic validation start sequence", "fake probe", "fake ops; no network", "fake crawler", "no external network", "degraded_expected_budget_deferred", map[string]any{"validation_start_sequence": starts, "selected_by_arrival": want, "ranked_would_select": []string{p.target, "a.example.test"}}, nil)
}

func g16SharedBudgetsScenario(t *testing.T, out string) g16Scenario {
	p, stage := g16BasePlan(t, out, true, 10, 1)
	stage.collect = g16FixtureCollector(p.target, p.target, "a.example.test", "b.example.test")
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, _ *dns.WildcardAnalyzer, name string) (dns.QuickValidationResult, error) {
		err := g16FixtureValidation(cfg, name, p.target)
		return dns.QuickValidationResult{Domain: name, Validated: err == nil, Eligible: err == nil}, err
	}
	stage.expand = func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error) {
		return dns.ExpansionResult{}, nil
	}
	var clientCount atomic.Int32
	var shared atomic.Pointer[activehttp.Client]
	var seenPages atomic.Int32
	var probes atomic.Int32
	var limitsMu sync.Mutex
	var limits []int
	ops := g16FakeOps(func(_ context.Context, c *activehttp.Client, _ web.Target, _ string) web.Result {
		probes.Add(1)
		if old := shared.Load(); old == nil {
			shared.CompareAndSwap(nil, c)
		} else if old != c {
			t.Errorf("HTTP client changed across stream batches")
		}
		return web.Result{Status: "loaded"}
	}, func(_ context.Context, c *activehttp.Client, cfg crawler.Config, roots []string) []crawler.Result {
		if old := shared.Load(); old == nil {
			shared.CompareAndSwap(nil, c)
		} else if old != c {
			t.Errorf("crawler client changed across batches")
		}
		limitsMu.Lock()
		limits = append(limits, cfg.MaxTotalPages)
		limitsMu.Unlock()
		out := []crawler.Result{}
		for _, raw := range roots {
			if seenPages.Add(1) > 8 {
				t.Errorf("global crawler budget exceeded")
			}
			out = append(out, crawler.Result{Origin: crawlOrigin(raw), Pages: []crawler.Page{{URL: raw, Status: 200}}})
		}
		return out
	})
	baseNew := ops.newHTTP
	ops.newHTTP = func(cfg activehttp.Config) (*activehttp.Client, error) { clientCount.Add(1); return baseNew(cfg) }
	stage.ops = ops
	res, err := g16Run(t, p, stage, 10*time.Second)
	rows := g16Rows(t, p)
	limitsMu.Lock()
	gotLimits := append([]int(nil), limits...)
	limitsMu.Unlock()
	wantLimits := []int{8, 7, 6}
	limitsMatch := len(gotLimits) == len(wantLimits)
	for i, want := range wantLimits {
		if i >= len(gotLimits) || gotLimits[i] != want {
			limitsMatch = false
		}
	}
	ok := err == nil && clientCount.Load() == 1 && seenPages.Load() == 3 && probes.Load() == 3 && limitsMatch && len(rows) > 0 && !res.Incomplete
	if !ok {
		return g16Doc("FAIL", "streaming shared client and page accounting", "synthetic DNS", "fake probe", "shared in-process HTTP client; no network", "fake bounded crawler", "no external network", "failed", map[string]any{"client_constructors": clientCount.Load(), "probe_calls": probes.Load(), "pages": seenPages.Load(), "remaining_total_page_limits": gotLimits, "incomplete": res.Incomplete}, err)
	}
	return g16Doc("PASS", "streaming shared client and page accounting", "synthetic DNS", "fake probe", "shared in-process HTTP client; no network", "fake bounded crawler", "no external network", "complete", map[string]any{"client_constructors": clientCount.Load(), "probe_calls": probes.Load(), "pages": seenPages.Load(), "remaining_total_page_limits": gotLimits, "incomplete": false}, nil)
}

func g16LoopbackScenario(t *testing.T, out string) g16Scenario {
	p, stage := g16BasePlan(t, out, true, 2, 1)
	p.cfg.Modules.Crawler = true
	p.cfg.ScopePolicy.AllowedCIDRs = []string{"127.0.0.1/32"}
	p.cfg.Backends.HTTPProbeBackend = "go_net_http"
	p.allowHTTPFallback = false
	p.cfg.RateLimits.HTTPMaxRequestsPerHost = 3
	p.cfg.RateLimits.CrawlerMaxTotalPages = 4
	p.cfg.RateLimits.CrawlerMaxPagesPerOrigin = 2
	p.cfg.CollectionPolicy.WildcardEnabled = false
	p.cfg.CollectionPolicy.ObeyRobots = false
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, "<html><title>G16 local</title><a href='/next'>next</a></html>")
	}))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	p.cfg.Ports = []int{port}
	p.active = makeActiveSettings(p)
	stage.collect = g16FixtureCollector(p.target, p.target)
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, _ *dns.WildcardAnalyzer, name string) (dns.QuickValidationResult, error) {
		ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "g16_loopback_fixture", name, name, core.InScope)
		if err != nil {
			return dns.QuickValidationResult{}, err
		}
		ev.Metadata = map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"127.0.0.1"}, "input_target": true, "g16_fixture": true, "target_service_contacted": false}
		err = cfg.Emit(ev)
		return dns.QuickValidationResult{Domain: name, Validated: err == nil, Eligible: err == nil}, err
	}
	stage.expand = func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error) {
		return dns.ExpansionResult{}, nil
	}
	stage.ops = defaultActiveOps()
	baseCrawl := stage.ops.crawl
	var crawledPages atomic.Int32
	stage.ops.crawl = func(ctx context.Context, client *activehttp.Client, cfg crawler.Config, roots []string) ([]crawler.Result, error) {
		results, err := baseCrawl(ctx, client, cfg, roots)
		if err == nil {
			for _, result := range results {
				crawledPages.Add(int32(len(result.Pages)))
			}
		}
		return results, err
	}
	res, err := g16Run(t, p, stage, 10*time.Second)
	rows := g16Rows(t, p)
	urlEvents := 0
	for _, row := range rows {
		if row["event_type"] == string(core.URLFound) {
			urlEvents++
		}
	}
	server.Close()
	conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portText), 100*time.Millisecond)
	listenerClosed := dialErr != nil
	if conn != nil {
		_ = conn.Close()
	}
	ok := err == nil && listenerClosed && hits.Load() == 3 && crawledPages.Load() == 2 && urlEvents >= 1 && len(rows) > 0 && !res.Incomplete
	if !ok {
		return g16Doc("FAIL", "real Go HTTP/crawler against loopback only", "synthetic DNS 127.0.0.1", "real Go web.Probe", "actual HTTP to httptest loopback", "actual Go crawler bounded to local origin", "127.0.0.1 loopback only", "failed", map[string]any{"loopback_requests": hits.Load(), "crawler_pages": crawledPages.Load(), "url_events": urlEvents, "events": len(rows), "listener_closed": listenerClosed, "incomplete": res.Incomplete}, errors.Join(err, dialErrIfOpen(listenerClosed)))
	}
	return g16Doc("PASS", "real Go HTTP/crawler against loopback only", "synthetic DNS 127.0.0.1", "real Go web.Probe", "actual HTTP to httptest loopback", "actual Go crawler bounded to local origin", "127.0.0.1 loopback only", "complete", map[string]any{"loopback_requests": hits.Load(), "crawler_pages": crawledPages.Load(), "url_events": urlEvents, "events": len(rows), "listener_closed": true, "incomplete": false}, nil)
}

func dialErrIfOpen(closed bool) error {
	if closed {
		return nil
	}
	return errors.New("loopback fixture listener remained open")
}

func g16CancelScenario(t *testing.T, out string) g16Scenario {
	p, stage := g16BasePlan(t, out, true, 16, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	collectorDone := make(chan struct{})
	var emitted, dnsActive atomic.Int32
	var namesMu sync.Mutex
	validated := map[string]int{}
	var once sync.Once
	stage.ops = g16FakeOps(func(ctx context.Context, _ *activehttp.Client, _ web.Target, _ string) web.Result {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return web.Result{}
	}, func(context.Context, *activehttp.Client, crawler.Config, []string) []crawler.Result { return nil })
	stage.collect = func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
		defer close(collectorDone)
		inv := map[string]evidence.ProviderInventoryEntry{}
		for i := -1; i < 128; i++ {
			name := p.target
			if i >= 0 {
				name = fmt.Sprintf("x%d.example.test", i)
			}
			ev, err := core.NewEvent(core.DomainFound, "subdomains", "g16_cancel_fixture", name, name, core.InScope)
			if err != nil {
				return passive.CollectResult{}, err
			}
			ev.Metadata = map[string]any{"provider": "g16_fixture", "target_service_contacted": false}
			if err = req.Sink(ctx, ev); err != nil {
				return passive.CollectResult{Inventory: inv}, err
			}
			emitted.Add(1)
			inv[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{"g16_fixture"}, Observations: 1}
		}
		return passive.CollectResult{Inventory: inv}, nil
	}
	stage.quick = func(ctx context.Context, cfg dns.ExpansionConfig, _ *dns.WildcardAnalyzer, name string) (dns.QuickValidationResult, error) {
		dnsActive.Add(1)
		defer dnsActive.Add(-1)
		namesMu.Lock()
		validated[name]++
		namesMu.Unlock()
		err := g16FixtureValidation(cfg, name, p.target)
		return dns.QuickValidationResult{Domain: name, Validated: err == nil, Eligible: err == nil}, err
	}
	stage.expand = func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error) {
		return dns.ExpansionResult{}, nil
	}
	done := make(chan struct{})
	var res Result
	var runErr error
	go func() { res, runErr = executePassive(ctx, p, portable.Payload{}, nil, stage); close(done) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		return g16Doc("FAIL", "bounded streaming cancellation", "synthetic DNS", "fake blocking probe", "fake operations; no network", "fake crawler", "no external network", "failed", nil, errors.New("probe was never admitted"))
	}
	select {
	case <-collectorDone:
		cancel()
		<-done
		return g16Doc("FAIL", "bounded streaming cancellation", "synthetic DNS", "fake blocking probe", "fake operations; no network", "fake crawler", "no external network", "failed", map[string]any{"emitted_before_release": emitted.Load()}, errors.New("producer escaped bounded backpressure while active probe was blocked"))
	case <-time.After(50 * time.Millisecond):
	}
	blockedLead := emitted.Load()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return g16Doc("FAIL", "bounded streaming cancellation", "synthetic DNS", "fake blocking probe", "fake operations; no network", "fake crawler", "no external network", "failed", nil, errors.New("pipeline failed to join after cancellation"))
	}
	rows := g16Rows(t, p)
	statusBytes, _ := os.ReadFile(filepath.Join(p.cfg.OutputDir, "run_status.json"))
	state := "interrupted_expected"
	joined := false
	select {
	case <-collectorDone:
		joined = true
	default:
	}
	namesMu.Lock()
	duplicates := []string{}
	for name, count := range validated {
		if count != 1 {
			duplicates = append(duplicates, name)
		}
	}
	namesMu.Unlock()
	incompleteStatus := strings.Contains(string(statusBytes), `"incomplete": true`)
	ok := errors.Is(runErr, context.Canceled) && len(rows) > 0 && strings.Contains(string(statusBytes), `"interrupted"`) && incompleteStatus && res.Incomplete && res.RunDir != "" && joined && dnsActive.Load() == 0 && blockedLead <= 12 && len(duplicates) == 0
	if !ok {
		return g16Doc("FAIL", "bounded streaming cancellation", "synthetic DNS", "fake blocking probe", "fake operations; no network", "fake crawler", "no external network", "failed", map[string]any{"events": len(rows), "status": string(statusBytes), "result_incomplete": res.Incomplete, "emitted_before_cancel": blockedLead, "producer_joined": joined, "active_dns_workers": dnsActive.Load(), "duplicate_dns": duplicates}, runErr)
	}
	return g16Doc("PASS", "bounded streaming cancellation", "synthetic DNS", "fake blocking probe", "fake operations; no network", "fake crawler", "no external network", state, map[string]any{"persisted_partial_events": len(rows), "status": "interrupted/incomplete", "workers_joined": true, "producer_backpressure_observed": true, "emitted_before_cancel": blockedLead, "active_dns_workers_after_return": 0, "duplicate_dns": duplicates}, nil)
}
