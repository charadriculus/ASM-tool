package config

import (
	"asmtool/internal/core"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := "../../testdata/phase1/" + name
	if name == "config_operational_without_ai.yml" {
		path = "../../testdata/corrective1-ai/" + name
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestSourceDefaults(t *testing.T) {
	cfg, e := Default()
	if e != nil {
		t.Fatal(e)
	}
	var expected map[string]json.RawMessage
	if e = json.Unmarshal(fixture(t, "source_defaults.json"), &expected); e != nil {
		t.Fatal(e)
	}
	// The historical source oracle names the retired Nmap limits. Project those
	// values onto the current TCP limits without retaining the removed config API.
	var rateProjection map[string]any
	if e = json.Unmarshal(expected["RateLimits"], &rateProjection); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"nmap_max_parallel_processes", "nmap_max_rate_per_process", "nmap_max_targets", "masscan_rate"} {
		delete(rateProjection, key)
	}
	rateProjection["tcp_max_concurrency"] = float64(1)
	rateProjection["tcp_max_rate"] = float64(10)
	rateProjection["tcp_max_targets"] = float64(500)
	rateProjection["tcp_connect_timeout_seconds"] = float64(10)
	expected["RateLimits"], e = json.Marshal(rateProjection)
	if e != nil {
		t.Fatal(e)
	}
	var policyProjection map[string]any
	if e = json.Unmarshal(expected["CollectionPolicy"], &policyProjection); e != nil {
		t.Fatal(e)
	}
	delete(policyProjection, "nmap_service_detection")
	expected["CollectionPolicy"], e = json.Marshal(policyProjection)
	if e != nil {
		t.Fatal(e)
	}
	// The historical source oracle includes AI defaults; compare the approved non-AI projection only.
	var moduleProjection map[string]any
	if e = json.Unmarshal(expected["Modules"], &moduleProjection); e != nil {
		t.Fatal(e)
	}
	delete(moduleProjection, "ai_review")
	expected["Modules"], e = json.Marshal(moduleProjection)
	if e != nil {
		t.Fatal(e)
	}
	serializedConfig, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(serializedConfig), `"ai_review"`) {
		t.Fatal("removed AI setting leaked into the current configuration model")
	}
	for name, value := range map[string]any{"RateLimits": cfg.RateLimits, "CollectionPolicy": cfg.CollectionPolicy, "Modules": cfg.Modules, "ReportingConfig": cfg.Reporting, "BackendsConfig": cfg.Backends} {
		var want, got any
		if e = json.Unmarshal(expected[name], &want); e != nil {
			t.Fatal(e)
		}
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, &got); e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("source defaults differ: %s\nwant %s\ngot %s", name, expected[name], b)
		}
	}
	if cfg.Profile != "passive" || cfg.AuthorizationConfirmed || cfg.AuditMode != "authorized_audit" || !reflect.DeepEqual(cfg.Ports, []int{80, 443}) || len(cfg.ExternalTools) != 0 || cfg.TargetDomain != nil {
		t.Fatal("top-level default contract differs")
	}
	if runtime.GOOS == "linux" && (cfg.OutputDir != "runs/default" || cfg.DatabasePath != "runs/default/asm.sqlite3") {
		t.Fatalf("Linux defaults: %+v", cfg)
	}
	parsed, e := Parse([]byte("allowed_domains: [example.com]\n"))
	if e != nil {
		t.Fatal(e)
	}
	cfg.ScopePolicy = core.ScopePolicy{AllowedDomains: []string{"example.com"}}
	if !reflect.DeepEqual(parsed, cfg) {
		t.Fatalf("parsing changes defaults: %+v", parsed)
	}
}
func TestOperationalLegacyConfiguration(t *testing.T) {
	// The archived fixture contains inert fields for excluded research collectors
	// and resource telemetry. Remove those unsupported fields in-memory; no legacy
	// compatibility is provided for them by the current parser.
	legacy := string(fixture(t, "config_operational_without_ai.yml"))
	for _, unsupported := range []string{
		"  research_collectors: [subfinder, amass]\n",
		"  research_include_bbot: false\n",
		"  research_collector_timeout_seconds: 600\n",
		"resource_monitor: {enabled: FALSE}\n",
	} {
		legacy = strings.Replace(legacy, unsupported, "", 1)
	}
	c, e := Parse([]byte(legacy))
	if e != nil {
		t.Fatal(e)
	}
	if c.Profile != "full" || !c.AuthorizationConfirmed || c.Owner != "Владелец" || c.TicketOrContractID != "TEST-123" || !c.AggressiveCrawlEnabled || c.AggressiveCrawlAuthorization != "Separate written permission" || c.TargetDomain == nil || *c.TargetDomain != "example.com" || c.OutputDir != "Проверка output" || c.DatabasePath != "База данных/asm.sqlite3" || c.UserAgent != "Test Agent" || c.ExternalTools["subfaster"] != "tools/subfaster" || !reflect.DeepEqual(c.Ports, []int{80, 443, 8080}) {
		t.Fatalf("top-level operational fields lost: %+v", c)
	}
	if c.RateLimits.DNSWorkerCount != 4 || c.RateLimits.HTTPDelaySeconds != 0 || c.RateLimits.HTTPStartIntervalSeconds != 0 || c.RateLimits.CrawlerMaxPagesPerOrigin != 8 || c.CollectionPolicy.PassiveProviderProfile != "deep" || c.CollectionPolicy.DNSCandidateBudget != 2000 || c.CollectionPolicy.DynamicDiscoveryMaxRounds != 3 || !reflect.DeepEqual(c.CollectionPolicy.StopOnHTTPStatuses, []int{401, 403, 429, 503}) {
		t.Fatal("policy overrides lost")
	}
	if !c.Modules.WebProbe || !c.Modules.Crawler || !c.Modules.Screenshots || c.Reporting.Language != "ru" || !c.Reporting.FullReport || c.Reporting.DomainRows != 0 || c.Backends.FallbackPolicy != "disabled" {
		t.Fatal("module/report/backend overrides lost")
	}
	if _, e = c.RequireActiveAllowed("https://example.com/path", "url"); e != nil {
		t.Fatal(e)
	}
	if _, e = c.RequireActiveAllowed("192.0.2.130", "ip"); e == nil {
		t.Fatal("excluded IP authorized")
	}
	if c.EventsDir() != "Проверка output/events" || c.ArtifactsDir() != "Проверка output/artifacts" {
		t.Fatal("artifact paths lost")
	}
}

func TestHTTPFallbackRequiresPresentExplicitPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       bool
	}{
		{"omitted", "", false},
		{"compatibility default is not consent", "backends: {http_probe_backend: projectdiscovery_httpx}", false},
		{"explicit opt in", "backends: {fallback_policy: explicit}", true},
		{"disabled", "backends: {fallback_policy: disabled}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte("allowed_domains: [example.com]\n" + tc.yaml + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Backends.HTTPFallbackAllowed(); got != tc.want {
				t.Fatalf("HTTPFallbackAllowed()=%v want %v", got, tc.want)
			}
		})
	}
	if _, err := Parse([]byte("allowed_domains: [example.com]\nbackends: {fallback_policy: null}\n")); err == nil {
		t.Fatal("null fallback policy accepted")
	}
}
func TestRejectRemovedAIConfiguration(t *testing.T) {
	if _, err := Parse(fixture(t, "config_operational.yml")); err == nil || !strings.Contains(err.Error(), "ai_review") {
		t.Fatalf("historical operational fixture did not clearly reject AI settings: %v", err)
	}
	for _, body := range []string{
		"ai_review: null", "ai_review: false", "ai_review: ''", "ai_review: {}", "ai_review: {mode: balanced}",
		"modules: {ai_review: null}", "modules: {ai_review: false}", "modules: {ai_review: ''}", "modules: {ai_review: {}}",
	} {
		t.Run(body, func(t *testing.T) {
			if _, err := Parse([]byte("allowed_domains: [example.com]\n" + body + "\n")); err == nil || !strings.Contains(err.Error(), "ai_review") {
				t.Fatalf("removed AI setting was not clearly rejected: %v", err)
			}
		})
	}
}
func TestRejectUnsafeConfiguration(t *testing.T) {
	base := "allowed_domains: [example.com]\n"
	cases := []string{
		"profile: research", "profile: verify", "profile: full", "authorization_confirmed: 'true'", "authorization_confirmed: 'false'", "authorization_confirmed: 'yes'", "authorization_confirmed: 1", "authorization_confirmed: null", "aggressive_crawl_enabled: 'false'", "aggressive_crawl_enabled: null",
		"collection_policy: {nmap_service_detection: true}", "rate_limits: {nmap_max_parallel_processes: 2}", "rate_limits: {nmap_max_rate_per_process: 10}", "rate_limits: {nmap_max_targets: 1}", "rate_limits: {masscan_rate: 100}",
		"profile: full\nauthorization_confirmed: true\ncollection_policy: {block_out_of_scope_browser_requests: false}",
		"profile: full\nauthorization_confirmed: true\naggressive_crawl_enabled: true", "aggressive_crawl_enabled: true\naggressive_crawl_authorization: permission",
		"collection_policy: {passive_provider_profile: research}", "resource_monitor: {enabled: true}", "resource_monitor: {enabled: 'false'}", "resource_monitor: []", "collection_policy: [a]", "rate_limits: x", "modules: {masscan: true}", "modules: {screenshots: 'true'}",
		"backends: {dns_backend: projectdiscovery_dnsx}", "backends: {crawler_backend: katana}", "backends: {dns_backend: unknown}", "backends: {pdf_backend: weasyprint}", "backends: {fallback_policy: silent}", "backends: {native_subprocess_timeout_seconds: 0}",
		"ports: [0]", "ports: [65536]", "ports: [-1]", "allowed_cidrs: [bad]", "excluded_domains: ['.example.com']", "allowed_domains: ['example.com.']", "allowed_domains: ['_example.com']",
		"rate_limits: {dns_queries_per_second: .nan}", "rate_limits: {http_delay_seconds: .inf}", "rate_limits: {http_delay_seconds: -1}", "rate_limits: {dns_worker_count: 65}", "rate_limits: {crawler_max_depth: -1}", "rate_limits: {global_max_requests_per_second: 0}", "rate_limits: {tcp_max_concurrency: 0}", "rate_limits: {tcp_max_concurrency: 33}", "rate_limits: {tcp_max_rate: 2.5}", "rate_limits: {tcp_max_rate: 0}", "rate_limits: {tcp_max_rate: 1001}", "rate_limits: {tcp_max_targets: 0}", "rate_limits: {tcp_max_targets: 501}", "rate_limits: {tcp_connect_timeout_seconds: .inf}", "rate_limits: {tcp_connect_timeout_seconds: 121}", "rate_limits: {screenshot_max_concurrency: 0}",
		"collection_policy: {dns_candidate_budget: 0}", "collection_policy: {wildcard_probes_per_parent: 2}", "collection_policy: {passive_cache_ttl_hours: -1}", "collection_policy: {crt_name_read_timeout_seconds: .inf}", "collection_policy: {stop_on_http_statuses: [999]}",
		"reporting: {language: de}", "reporting: {language: ''}", "reporting: {domain_rows: 10001}", "reporting: {web_rows: -1}", "output_dir: ''", "database_path: ''",
		"profile: passive\nprofile: full", "---\nprofile: passive\n---\nprofile: full", "allowed_domains: &a [example.com]\nexcluded_domains: *a",
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			input := base + body + "\n"
			if strings.HasPrefix(body, "allowed_domains:") {
				input = body + "\n"
			}
			if _, e := Parse([]byte(input)); e == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
	for _, body := range []string{"[example.com]", "true", "null", "{}", "", "a: [broken", strings.Repeat(" ", MaxConfigBytes+1), string([]byte{0xff})} {
		if _, e := Parse([]byte(body)); e == nil {
			t.Errorf("invalid top-level accepted: %q", body[:min(30, len(body))])
		}
	}
}
func TestValidationHasNoIO(t *testing.T) {
	destination := t.TempDir() + "/must-not-exist"
	c, e := Parse([]byte("allowed_domains: [example.com]\noutput_dir: " + destination + "\ndatabase_path: " + destination + "/db.sqlite3\n"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(c.OutputDir); !os.IsNotExist(e) {
		t.Fatal("parse created output directory")
	}
	if _, e = os.Stat(c.DatabasePath); !os.IsNotExist(e) {
		t.Fatal("parse created database")
	}
}
func TestTCPRateLimitDefaultsAndOverrides(t *testing.T) {
	c, e := Parse([]byte("allowed_domains: [example.com]\n"))
	if e != nil {
		t.Fatal(e)
	}
	if c.RateLimits.TCPMaxConcurrency != 1 || c.RateLimits.TCPMaxRate != 10 || c.RateLimits.TCPMaxTargets != 500 || c.RateLimits.TCPConnectTimeoutSeconds != 10 {
		t.Fatalf("unexpected TCP defaults: %+v", c.RateLimits)
	}
	c, e = Parse([]byte("allowed_domains: [example.com]\nrate_limits: {tcp_max_concurrency: 4, tcp_max_rate: 2, tcp_max_targets: 12, tcp_connect_timeout_seconds: 3}\n"))
	if e != nil {
		t.Fatal(e)
	}
	if c.RateLimits.TCPMaxConcurrency != 4 || c.RateLimits.TCPMaxRate != 2 || c.RateLimits.TCPMaxTargets != 12 || c.RateLimits.TCPConnectTimeoutSeconds != 3 {
		t.Fatalf("TCP limits were not applied: %+v", c.RateLimits)
	}
	for _, body := range []string{"rate_limits: {dns_queries_per_second: null}", "output_dir: null", "reporting: {language: null}", "ignored: !custom value"} {
		if _, e := Parse([]byte("allowed_domains: [example.com]\n" + body + "\n")); e == nil {
			t.Errorf("unsafe null/tag accepted: %s", body)
		}
	}
}

func TestLegacyPlainBooleans(t *testing.T) {
	for _, token := range []string{"yes", "Yes", "YES", "on", "On", "ON", "true", "True", "TRUE"} {
		c, e := Parse([]byte("allowed_domains: [example.com]\nprofile: full\nauthorization_confirmed: " + token + "\n"))
		if e != nil || !c.AuthorizationConfirmed {
			t.Errorf("legacy bool %s rejected: %v", token, e)
		}
	}
	for _, token := range []string{"no", "No", "NO", "off", "Off", "OFF", "false", "False", "FALSE"} {
		c, e := Parse([]byte("allowed_domains: [example.com]\nauthorization_confirmed: " + token + "\n"))
		if e != nil || c.AuthorizationConfirmed {
			t.Errorf("legacy false %s changed: %v", token, e)
		}
	}
	for _, token := range []string{"yes", "on", "no", "off", "true", "false"} {
		if _, e := Parse([]byte("allowed_domains: [example.com]\nauthorization_confirmed: '" + token + "'\n")); e == nil {
			t.Errorf("quoted bool %s accepted", token)
		}
	}
}

func TestIntegerBudgetsCannotTruncate(t *testing.T) {
	for _, body := range []string{"collection_policy: {dynamic_discovery_max_rounds: -0.5}", "collection_policy: {passive_cache_ttl_hours: -0.5}", "rate_limits: {dns_worker_count: 64.9}", "rate_limits: {tcp_max_concurrency: 1.5}", "rate_limits: {tcp_max_targets: 4.1}", "ports: [80.5]", "ports: [9.223372036854776e18]", "reporting: {domain_rows: 2.2}"} {
		if _, e := Parse([]byte("allowed_domains: [example.com]\n" + body + "\n")); e == nil {
			t.Errorf("fractional integer budget accepted: %s", body)
		}
	}
	c, e := Parse([]byte("allowed_domains: [example.com]\nrate_limits: {dns_worker_count: 4.0}\n"))
	if e != nil || c.RateLimits.DNSWorkerCount != 4 {
		t.Errorf("valid integral budget rejected: %+v %v", c, e)
	}
}

func TestNullListEntriesCannotDisappear(t *testing.T) {
	for _, body := range []string{"ports: [null]", "ports: [80, null]", "excluded_domains: [null]", "allowed_domains: [example.com, null]", "collection_policy: {stop_on_http_statuses: [null]}"} {
		input := "allowed_domains: [example.com]\n" + body + "\n"
		if strings.HasPrefix(body, "allowed_domains:") {
			input = body + "\n"
		}
		if _, e := Parse([]byte(input)); e == nil {
			t.Errorf("null list entry disappeared: %s", body)
		}
	}
	if _, e := Parse([]byte("allowed_domains: [example.com]\nexcluded_domains: null\nrate_limits: null\nports: null\n")); e != nil {
		t.Errorf("legacy nullable optional section/list rejected: %v", e)
	}
}
