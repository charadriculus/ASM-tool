package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/backends"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
	"asmtool/internal/platform"
	"asmtool/internal/portable"
	"asmtool/internal/report"
	"asmtool/internal/storage"
)

func integrationPipelinePlan(t *testing.T, browserMode string) Plan {
	t.Helper()
	p := fixturePlan(t)
	p.cfg.Profile = "verify"
	p.cfg.AuthorizationConfirmed = true
	p.cfg.Modules = config.Modules{DomainExpansion: true, WebProbe: true, Screenshots: false, PDFReport: true}
	p.cfg.Modules.Subdomains = false
	p.cfg.CollectionPolicy.StreamingPipelineEnabled = false // These fixtures cover the batch compatibility path.
	p.cfg.Modules.PortScan = false
	p.cfg.CollectionPolicy.InternetdbEnabled = false
	p.browserMode = browserMode
	p.allowHTTPFallback = true
	p.active = makeActiveSettings(p)
	return p
}

func integrationPipelineStages(t *testing.T, ops activeOps, seen *map[string]any) stages {
	t.Helper()
	return stages{
		ops: ops,
		collect: func(context.Context, passive.CollectRequest) (passive.CollectResult, error) {
			return passive.CollectResult{Inventory: map[string]evidence.ProviderInventoryEntry{}}, nil
		},
		dnsClient: func(time.Duration, float64) (*dns.Client, error) { return &dns.Client{}, nil },
		expand: func(ctx context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
			ev, err := core.NewEvent(core.DNSValidation, "public_dns", "go_dns", "example.test", "example.test", core.InScope)
			if err != nil {
				return dns.ExpansionResult{}, err
			}
			ev.Metadata = map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.55"}}
			if err := cfg.Emit(ev); err != nil {
				return dns.ExpansionResult{}, err
			}
			return dns.ExpansionResult{}, nil
		},
		generate: func(ctx context.Context, in report.Input, _ portable.Payload) (report.Outputs, error) {
			got, _, err := report.Load(ctx, in)
			if err != nil {
				return report.Outputs{}, err
			}
			*seen = got
			return report.Outputs{JSON: filepath.Join(in.OutputDir, "fixture-report.json")}, nil
		},
	}
}

func integrationPipelineOps(t *testing.T, probeMode string, cancel context.CancelFunc) activeOps {
	t.Helper()
	ops := activeTestOps()
	ops.probe = func(ctx context.Context, _ *activehttp.Client, cfg web.ProbeConfig, target web.Target, raw string) (web.Result, error) {
		ev, err := core.NewEvent(core.WebTargetStatus, "web_probe", "go_net_http", target.Domain, target.Domain, core.InScope)
		if err != nil {
			return web.Result{}, err
		}
		ev.Metadata = map[string]any{"stage": "root_verification", "status": "loaded", "terminal": true, "requested_url": raw, "final_url": raw, "status_code": 200, "page_loaded": true}
		if err := cfg.Emit(ev); err != nil {
			return web.Result{}, err
		}
		if cancel != nil {
			cancel()
			return web.Result{}, ctx.Err()
		}
		result := web.Result{Status: "loaded", HTTP: activehttp.Response{StatusCode: 200}}
		if probeMode == "partial" {
			result.Partial, result.Limitation = true, "fixture partial response"
		}
		return result, nil
	}
	return ops
}

func TestExecutePassiveActiveBrowserPolicyFlowsIntoPersistedReport(t *testing.T) {
	for _, tc := range []struct {
		mode                string
		incomplete          bool
		browser, screenshot string
	}{
		{"required", false, "loaded", "not_requested"},
		{"disabled", false, "not_requested", "not_requested"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			p := integrationPipelinePlan(t, tc.mode)
			var seen map[string]any
			stage := integrationPipelineStages(t, integrationPipelineOps(t, "success", nil), &seen)
			result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
			if err != nil {
				t.Fatal(err)
			}
			if result.Incomplete != tc.incomplete {
				t.Fatalf("incomplete=%t, want %t", result.Incomplete, tc.incomplete)
			}
			rows := asPipelineList(seen["web_coverage"])
			if len(rows) != 1 {
				t.Fatalf("report coverage rows=%d, want 1", len(rows))
			}
			row := asPipelineMap(rows[0])
			if row["browser_status"] != tc.browser || row["screenshot_status"] != tc.screenshot || row["root_status"] != "loaded" {
				t.Fatalf("persisted report lost policy or HTTP result: %#v", row)
			}
			if asPipelineMap(seen["summary"])["screenshot_coverage_complete"] != !tc.incomplete {
				t.Fatalf("report screenshot completeness disagrees with run: %#v", seen["summary"])
			}
			statusBytes, err := os.ReadFile(filepath.Join(result.RunDir, "run_status.json"))
			if err != nil {
				t.Fatal(err)
			}
			status, err := backends.DecodeJSON(statusBytes)
			if err != nil {
				t.Fatal(err)
			}
			wantState := "complete"
			if tc.incomplete {
				wantState = "complete"
			}
			if asPipelineMap(status)["completion"] != completion(tc.incomplete) || asPipelineMap(status)["incomplete"] != tc.incomplete {
				t.Fatalf("completeness lost in terminal status: %#v", status)
			}
			if asPipelineMap(status)["state"] != wantState {
				t.Fatalf("terminal status=%v, want %s", asPipelineMap(status)["state"], wantState)
			}
		})
	}
}

func TestExecutePassivePartialHTTPFailureRemainsIncomplete(t *testing.T) {
	p := integrationPipelinePlan(t, "disabled")
	var seen map[string]any
	stage := integrationPipelineStages(t, integrationPipelineOps(t, "partial", nil), &seen)
	result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Incomplete || asPipelineMap(seen["coverage"])["incomplete"] != true {
		t.Fatalf("partial active result reported complete: run=%+v coverage=%#v", result, seen["coverage"])
	}
	if asPipelineMap(seen["summary"])["web_pages_loaded"] != 1 {
		t.Fatalf("partial HTTP page evidence lost: %#v", seen["summary"])
	}
}

func TestExecutePassiveCancellationKeepsDurableActiveEvidence(t *testing.T) {
	p := integrationPipelinePlan(t, "required")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	generated := false
	stage := integrationPipelineStages(t, integrationPipelineOps(t, "success", cancel), &map[string]any{})
	stage.generate = func(context.Context, report.Input, portable.Payload) (report.Outputs, error) {
		generated = true
		return report.Outputs{}, nil
	}
	result, err := executePassive(ctx, p, portable.Payload{}, nil, stage)
	if !errors.Is(err, context.Canceled) || generated {
		t.Fatalf("cancel=%v report_generated=%t", err, generated)
	}
	db, err := storage.OpenImmutable(p.cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, err := storage.IterEvents(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	stages := map[string]bool{}
	for _, event := range events {
		if event["event_type"] != string(core.WebTargetStatus) {
			continue
		}
		meta := asPipelineMap(event["metadata"])
		stages[fmt.Sprint(meta["stage"])] = true
	}
	if !stages["browser"] || !stages["root_verification"] {
		t.Fatalf("durable browser/HTTP evidence missing after cancellation: %#v", stages)
	}
	statusBytes, err := os.ReadFile(filepath.Join(result.RunDir, "run_status.json"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := backends.DecodeJSON(statusBytes)
	if err != nil {
		t.Fatal(err)
	}
	if asPipelineMap(status)["state"] != "interrupted" {
		t.Fatalf("cancel status=%v", asPipelineMap(status)["state"])
	}
}

func TestPrepareActiveBrowserYAMLPriorityAndRequiredPreEffects(t *testing.T) {
	prepare := func(t *testing.T, disableScreenshots bool, browser string) Plan {
		t.Helper()
		dir := t.TempDir()
		output := filepath.Join(dir, "run")
		text := "allowed_domains: [example.test]\ntarget_domain: example.test\nprofile: verify\nauthorization_confirmed: true\noutput_dir: " + output + "\ndatabase_path: " + filepath.Join(output, "asm.sqlite3") + "\n"
		if disableScreenshots {
			text += "modules:\n  screenshots: false\n"
		}
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--config", path, "--non-interactive"}
		if browser != "" {
			args = append(args, "--browser", browser)
		}
		opts, err := ParseOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Prepare(opts)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	defaultPlan := prepare(t, false, "")
	if defaultPlan.browserMode != "enabled" || !defaultPlan.cfg.Modules.WebProbe || !defaultPlan.cfg.Modules.Crawler {
		t.Fatalf("active defaults lost priority: mode=%s modules=%+v", defaultPlan.browserMode, defaultPlan.cfg.Modules)
	}
	requiredPlan := prepare(t, false, "required")
	if requiredPlan.browserMode != "required" {
		t.Fatalf("explicit required mode ignored: %s", requiredPlan.browserMode)
	}
	_, err := Execute(context.Background(), requiredPlan, nil)
	if err == nil || strings.Contains(err.Error(), "security-blocked") {
		t.Fatalf("required browser should pass its former blanket gate and fail trusted payload preflight: %v", err)
	}
	if _, err := os.Stat(requiredPlan.cfg.OutputDir); !os.IsNotExist(err) {
		t.Fatalf("required browser created output: %v", err)
	}

	disabledPlan := prepare(t, true, "")
	if disabledPlan.browserMode != "disabled" || disabledPlan.cfg.Modules.Screenshots {
		t.Fatalf("YAML screenshot opt-out ignored: mode=%s modules=%+v", disabledPlan.browserMode, disabledPlan.cfg.Modules)
	}
	requiredDOMPlan := prepare(t, true, "required")
	if requiredDOMPlan.browserMode != "required" || requiredDOMPlan.cfg.Modules.Screenshots {
		t.Fatalf("explicit browser required must enable DOM without overriding YAML screenshot opt-out: mode=%s modules=%+v", requiredDOMPlan.browserMode, requiredDOMPlan.cfg.Modules)
	}
}

func TestExecuteHTTPXFallbackRequiresExplicitOptInBeforeEffects(t *testing.T) {
	p := integrationPipelinePlan(t, "disabled")
	p.cfg.Modules.Screenshots = false
	p.cfg.Backends.HTTPProbeBackend = "projectdiscovery_httpx"
	p.allowHTTPFallback = false
	_, err := Execute(context.Background(), p, nil)
	if !errors.Is(err, platform.ErrNativeHTTPXBlocked) {
		t.Fatalf("HTTPX guard error=%v", err)
	}
	if _, err := os.Stat(p.cfg.OutputDir); !os.IsNotExist(err) {
		t.Fatalf("blocked HTTPX run created output: %v", err)
	}
	p.allowHTTPFallback = true
	_, err = Execute(context.Background(), p, nil)
	if err == nil || errors.Is(err, platform.ErrNativeHTTPXBlocked) {
		t.Fatalf("explicit opt-in did not pass policy guard: %v", err)
	}
	if _, err := os.Stat(p.cfg.OutputDir); !os.IsNotExist(err) {
		t.Fatalf("preflight failure created output: %v", err)
	}
}

func asPipelineMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func asPipelineList(value any) []any {
	if result, ok := value.([]any); ok {
		return result
	}
	return nil
}
