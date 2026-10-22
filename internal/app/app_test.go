package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/core"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
	"asmtool/internal/portable"
	"asmtool/internal/report"
	"asmtool/internal/storage"
)

func fixturePlan(t *testing.T) Plan {
	t.Helper()
	opts, err := ParseOptions([]string{"--domain", "example.test", "--non-interactive", "--output-dir", filepath.Join(t.TempDir(), "результат"), "--bundle-dir", filepath.Join(t.TempDir(), "payload")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestBrowserRequiredReachesTrustedPayloadPreflightBeforeEffects(t *testing.T) {
	for _, profile := range []string{"verify", "full"} {
		t.Run(profile, func(t *testing.T) {
			p := fixturePlan(t)
			p.cfg.Profile = profile
			p.cfg.AuthorizationConfirmed = true
			p.browserMode = "required"
			// A required browser is no longer categorically blocked; the absent
			// trusted payload must still fail before output creation.
			_, err := Execute(context.Background(), p, nil)
			if err == nil || strings.Contains(err.Error(), "security-blocked") {
				t.Fatalf("expected trusted payload preflight failure, got %v", err)
			}
			if _, err := os.Stat(p.cfg.OutputDir); !os.IsNotExist(err) {
				t.Fatalf("run directory created: %v", err)
			}
		})
	}
}
func TestPrepareRejectsOutsideScopeUnknownAndUnsupportedSettings(t *testing.T) {
	for _, tail := range []string{
		"target_domain: outside.test\n",
		"ai_review: false\n",
		"collection_policy:\n  invented_mode: true\n",
		"modules:\n  pdf_report: false\n",
		"modules:\n  crawler: true\n",
		"backends:\n  ollama: disabled\n",
	} {
		t.Run(strings.ReplaceAll(tail, "\n", " "), func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "config.yaml")
			output := filepath.Join(dir, "run")
			data := "allowed_domains: [example.test]\ntarget_domain: example.test\noutput_dir: " + output + "\ndatabase_path: " + filepath.Join(output, "asm.sqlite3") + "\n" + tail
			// Use only one target_domain field for the out-of-scope scenario.
			if strings.HasPrefix(tail, "target_domain") {
				data = strings.Replace(data, "target_domain: example.test\n", "", 1)
			}
			if err := os.WriteFile(cfg, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			opts, err := ParseOptions([]string{"--config", cfg, "--non-interactive"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Prepare(opts); err == nil {
				t.Fatal("unsafe setting accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("validation wrote output")
			}
		})
	}
}
func TestCLIConfigOverrideDoesNotWidenScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("allowed_domains: [example.test]\ntarget_domain: example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := ParseOptions([]string{"--config", path, "--domain", "outside.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(o); err == nil {
		t.Fatal("scope widened")
	}
}

func TestActiveYAMLAuthorizationOverlayAndDocumentRejection(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "run")
	text := "allowed_domains: [example.test]\ntarget_domain: example.test\nprofile: full\noutput_dir: " + output + "\ndatabase_path: " + filepath.Join(output, "asm.sqlite3") + "\n"
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := ParseOptions([]string{"--config", path, "--non-interactive", "--bundle-dir", filepath.Join(dir, "payload")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(o); !errors.Is(err, ErrAuthorizationRequired) {
		t.Fatalf("pending authorization=%v", err)
	}
	o.Authorized = true
	o.Set["yes"] = true
	p, err := Prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), p, nil); err == nil {
		t.Fatalf("active path must reach trusted payload preflight rather than the old whole-profile gate: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("active plan created output")
	}
	for _, suffix := range []string{"---\nai_review: true\n", "allowed_domains: [outside.test]\n"} {
		if _, err := parseRunConfig([]byte(text+suffix), o); err == nil {
			t.Fatal("extra document or duplicate key accepted")
		}
	}
	override := Options{Profile: "passive", Set: map[string]bool{"profile": true}}
	for _, invalid := range []string{"profile: !custom passive\n", "owner: &name passive\nprofile: *name\n", "profile: full\nprofile: passive\n"} {
		if _, err := parseRunConfig([]byte("allowed_domains: [example.test]\n"+invalid), override); err == nil {
			t.Fatal("CLI overlay erased forbidden YAML syntax")
		}
	}
	legacy, err := parseRunConfig([]byte(text+"authorization_confirmed: yes\ncollection_policy:\n  obey_robots: on\n"), Options{Set: map[string]bool{}})
	if err != nil || !legacy.AuthorizationConfirmed || !legacy.CollectionPolicy.ObeyRobots {
		t.Fatalf("legacy bool=%+v %v", legacy, err)
	}
	if _, err := parseRunConfig([]byte(text+"authorization_confirmed: \"true\"\n"), Options{Set: map[string]bool{}}); err == nil {
		t.Fatal("quoted authorization accepted")
	}
}
func TestInventoryClientPolicyIsAcceptedBeforeIO(t *testing.T) {
	p := fixturePlan(t)
	if _, err := newInventoryClient(p.cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.cfg.OutputDir); !os.IsNotExist(err) {
		t.Fatal("HTTP policy creation wrote output")
	}
}
func TestPreparedFallbackRequiresSuppliedOptIn(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		p := fixturePlan(t)
		p.cfg.Profile = "full"
		p.cfg.AuthorizationConfirmed = true
		p.allowHTTPFallback = allowed
		settings := makeActiveSettings(p)
		if settings.HTTP.AllowFallback != allowed {
			t.Fatal("implicit HTTP fallback")
		}
		if settings.HTTP.HTTPProbeBackend != p.cfg.Backends.HTTPProbeBackend {
			t.Fatal("backend silently changed")
		}
	}
}
func TestPrepareRequiresAuthorizationAndMapsReportOptions(t *testing.T) {
	p := fixturePlan(t)
	o, err := ParseOptions([]string{"--domain", "https://пример.рф/path", "--profile", "verify", "--non-interactive", "--bundle-dir", p.bundleDir, "--output-dir", p.cfg.OutputDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(o); !errors.Is(err, ErrAuthorizationRequired) {
		t.Fatalf("authorization=%v", err)
	}
	o.Profile = "passive"
	o.Language = "ru"
	o.FullReport = true
	o.Set["language"] = true
	o.Set["full-report"] = true
	prepared, err := Prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	input, err := reportInput(prepared, time.Now().UTC(), "events.jsonl", "fonts", true, 7)
	if err != nil {
		t.Fatal(err)
	}
	if input.Language != "ru" || !input.FullReport || input.Version != Version || input.Coverage["deferred_by_dns_budget"] != 7 || input.Coverage["incomplete"] != true {
		t.Fatalf("report mapping=%+v", input)
	}
	if !strings.HasPrefix(prepared.target, "xn--") {
		t.Fatal("IDN not canonicalized")
	}
}

func fixtureStages(t *testing.T, generated *bool) stages {
	t.Helper()
	return stages{
		collect: func(ctx context.Context, req passive.CollectRequest) (passive.CollectResult, error) {
			ev, err := core.NewEvent(core.DomainFound, "input", "user_input", "example.test", "example.test", core.InScope)
			if err != nil {
				return passive.CollectResult{}, err
			}
			ev.Confidence = 1
			ev.Metadata = map[string]any{"input_target": true}
			if err := req.Sink(ctx, ev); err != nil {
				return passive.CollectResult{}, err
			}
			return passive.CollectResult{Inventory: map[string]evidence.ProviderInventoryEntry{}, Providers: []evidence.ProviderResult{{Status: "ok", CompletenessState: evidence.Complete}}}, nil
		},
		generate: func(ctx context.Context, in report.Input, _ portable.Payload) (report.Outputs, error) {
			// OpenImmutable rejects live WAL. JSONL and SQLite must contain the event
			// before any presentation code observes this stopped run.
			db, err := storage.OpenImmutable(in.DatabasePath)
			if err != nil {
				return report.Outputs{}, err
			}
			defer db.Close()
			events, err := storage.IterEvents(ctx, db, nil)
			if err != nil {
				return report.Outputs{}, err
			}
			if len(events) != 1 {
				t.Fatalf("persisted events=%d", len(events))
			}
			count := 0
			if err := evidence.IterJSONL(in.EventFiles[0], func(r evidence.JSONLRecord) error { count++; return r.Err }); err != nil {
				return report.Outputs{}, err
			}
			if count != 1 {
				t.Fatalf("durable JSONL lines=%d", count)
			}
			*generated = true
			return report.Outputs{JSON: filepath.Join(in.OutputDir, "report.json")}, nil
		},
	}
}
func TestPassivePersistsBeforeReportAndKeepsPreviousRun(t *testing.T) {
	p := fixturePlan(t)
	p.cfg.Modules.DomainExpansion = false
	p.cfg.Modules.PortScan = false
	generated := false
	stage := fixtureStages(t, &generated)
	result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
	if err != nil {
		t.Fatal(err)
	}
	if !generated || result.Incomplete {
		t.Fatalf("generated=%v incomplete=%v", generated, result.Incomplete)
	}
	statusBytes, err := os.ReadFile(filepath.Join(result.RunDir, "run_status.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(statusBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.(map[string]any)["state"] != "complete" {
		t.Fatalf("terminal=%s", statusBytes)
	}
	oldLog, err := os.ReadFile(filepath.Join(result.RunDir, "run.log"))
	if err != nil {
		t.Fatal(err)
	}
	generated = false
	if _, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage); err == nil {
		t.Fatal("existing run reused")
	}
	newLog, err := os.ReadFile(filepath.Join(result.RunDir, "run.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(newLog) != string(oldLog) || generated {
		t.Fatal("previous result modified")
	}
}
func TestCancellationJoinsWritersAndDoesNotGenerateReport(t *testing.T) {
	p := fixturePlan(t)
	p.cfg.Modules.DomainExpansion = false
	p.cfg.Modules.PortScan = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	generated := false
	stage := fixtureStages(t, &generated)
	original := stage.collect
	stage.collect = func(ctx context.Context, r passive.CollectRequest) (passive.CollectResult, error) {
		value, err := original(ctx, r)
		if err != nil {
			return value, err
		}
		cancel()
		return value, ctx.Err()
	}
	result, err := executePassive(ctx, p, portable.Payload{}, nil, stage)
	if !errors.Is(err, context.Canceled) || generated {
		t.Fatalf("cancel=%v generated=%v", err, generated)
	}
	data, err := os.ReadFile(filepath.Join(result.RunDir, "run_status.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.(map[string]any)["state"] != "interrupted" {
		t.Fatalf("status=%s", data)
	}
	db, err := storage.OpenImmutable(p.cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, err := storage.IterEvents(context.Background(), db, nil)
	if err != nil || len(events) != 1 {
		t.Fatalf("cancelled evidence=%d %v", len(events), err)
	}
}
func TestReportFailureProducesErrorStatus(t *testing.T) {
	p := fixturePlan(t)
	p.cfg.Modules.DomainExpansion = false
	p.cfg.Modules.PortScan = false
	generated := false
	stage := fixtureStages(t, &generated)
	sentinel := errors.New("fixture PDF failure")
	stage.generate = func(context.Context, report.Input, portable.Payload) (report.Outputs, error) {
		return report.Outputs{}, sentinel
	}
	result, err := executePassive(context.Background(), p, portable.Payload{}, nil, stage)
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(result.RunDir, "run_status.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.(map[string]any)["state"] != "error" {
		t.Fatalf("false successful state=%s", data)
	}
}

func TestBrowserOnlyRequiresCurrentRunDNS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	output := filepath.Join(dir, "run")
	data := "target_domain: example.test\nallowed_domains: [example.test]\nprofile: verify\nauthorization_confirmed: true\noutput_dir: " + output + "\ndatabase_path: " + filepath.Join(output, "asm.sqlite3") + "\nmodules:\n  domain_expansion: false\n  web_probe: false\n  crawler: false\n  port_scan: false\n  screenshots: false\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseOptions([]string{"--config", path, "--browser", "required", "--non-interactive"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(opts); err == nil || !strings.Contains(err.Error(), "current-run affirmative DNS") {
		t.Fatalf("browser-only without DNS accepted: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("validation created output")
	}
}

func TestBrowserBoundsRejectedDuringPrepare(t *testing.T) {
	for _, rate := range []string{"browser_navigation_timeout_seconds: 21", "browser_navigation_timeout_seconds: 0.01", "browser_screenshot_timeout_seconds: 21", "browser_dom_settle_milliseconds: 11000"} {
		t.Run(rate, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			output := filepath.Join(dir, "run")
			data := "target_domain: example.test\nallowed_domains: [example.test]\nprofile: verify\nauthorization_confirmed: true\noutput_dir: " + output + "\ndatabase_path: " + filepath.Join(output, "asm.sqlite3") + "\nrate_limits:\n  " + rate + "\n"
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			opts, err := ParseOptions([]string{"--config", path, "--browser", "required", "--non-interactive"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Prepare(opts); err == nil || !strings.Contains(err.Error(), "browser CDP bounds") {
				t.Fatalf("unsupported browser bound accepted: %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("validation created output")
			}
		})
	}
}
