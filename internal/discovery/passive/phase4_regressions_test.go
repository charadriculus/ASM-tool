package passive

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

func TestCertSpotterCompletenessReflectsFailureAndEmptyExhaustion(t *testing.T) {
	t.Run("first page rate limit", func(t *testing.T) {
		client := fixtureClient(t, func(*http.Request) (int, any) { return http.StatusTooManyRequests, map[string]any{"error": "busy"} })
		got, err := CertSpotter(context.Background(), client, "example.test", 0)
		if err == nil || got.Status != "rate_limited" || got.Completeness != "collector_failed" {
			t.Fatalf("first-page failure reported as complete: result=%+v err=%v", got, err)
		}
	})
	t.Run("empty exhaustion", func(t *testing.T) {
		client := fixtureClient(t, func(*http.Request) (int, any) { return http.StatusOK, []any{} })
		got, err := CertSpotter(context.Background(), client, "example.test", 0)
		if err != nil || got.Status != "no_data" || got.Completeness != evidence.CompleteEmpty {
			t.Fatalf("empty page exhaustion=%+v err=%v", got, err)
		}
	})
	for _, tc := range []struct {
		name           string
		status         int
		completeness   string
		transportError error
	}{
		{name: "timeout", completeness: evidence.PartialTimeout, transportError: context.DeadlineExceeded},
		{name: "rate limit", status: http.StatusTooManyRequests, completeness: evidence.PartialRateLimited},
	} {
		t.Run("later-page "+tc.name+" retains cause", func(t *testing.T) {
			calls := 0
			client, err := NewClient(HTTPPolicy{RequestsPerSecond: 10000, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: 1, CacheDir: t.TempDir(), CacheTTL: time.Hour, MaxResponseBytes: 1 << 20, MaxCacheBytes: 1 << 20, UserAgent: "fixture"}, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return jsonResponse(r, http.StatusOK, `[{"id":"page-1","dns_names":["one.example.test"]}]`)
				}
				if tc.transportError != nil {
					return nil, tc.transportError
				}
				return jsonResponse(r, tc.status, `{"error":"busy"}`)
			})})
			if err != nil {
				t.Fatal(err)
			}
			got, err := CertSpotter(context.Background(), client, "example.test", 0)
			if err != nil || got.Status != "partial" || got.Completeness != tc.completeness || len(got.Observations) != 1 {
				t.Fatalf("later-page cause lost: result=%+v err=%v", got, err)
			}
		})
	}
}

func TestCertSpotterFailureAndEmptyStateReachHealthAndArtifact(t *testing.T) {
	for _, tc := range []struct {
		name, completeness                     string
		status                                 int
		body                                   string
		providerStatus                         string
		healthTermination, artifactTermination string
		telemetry                              string
	}{
		{name: "rate limit", completeness: evidence.CollectorFailed, status: http.StatusTooManyRequests, body: `{"error":"busy"}`, providerStatus: "rate_limited", healthTermination: "rate_limited", artifactTermination: "rate_limited", telemetry: "partial"},
		{name: "empty exhaustion", completeness: evidence.CompleteEmpty, status: http.StatusOK, body: `[]`, providerStatus: "no_data", artifactTermination: "collector_exit_observed", telemetry: "complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := collectFixtureConfig(t, "certspotter")
			client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return jsonResponse(r, tc.status, tc.body)
			}))
			var events []core.Event
			result, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, event core.Event) error {
				events = append(events, event)
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Providers) != 1 || result.Providers[0].CompletenessState != tc.completeness {
				t.Fatalf("provider result=%+v", result.Providers)
			}
			var health *core.Event
			for i := range events {
				if events[i].EventType == core.SourceHealth && events[i].SourceTool == "certspotter" {
					health = &events[i]
				}
			}
			if health == nil || health.Metadata["status"] != tc.providerStatus || health.Metadata["completeness_state"] != tc.completeness || health.Metadata["termination_reason"] != nullableString(tc.healthTermination) || health.Metadata["pagination_telemetry_status"] != tc.telemetry {
				t.Fatalf("health did not preserve status/completeness: %+v", health)
			}
			data, err := os.ReadFile(filepath.Join(cfg.ArtifactsDir(), completenessArtifactName))
			if err != nil {
				t.Fatal(err)
			}
			var artifact struct {
				Providers []map[string]any `json:"providers"`
			}
			if err = json.Unmarshal(data, &artifact); err != nil || len(artifact.Providers) != 1 || artifact.Providers[0]["completeness_state"] != tc.completeness || artifact.Providers[0]["termination"] != tc.artifactTermination {
				t.Fatalf("artifact=%s err=%v", data, err)
			}
			pages, ok := artifact.Providers[0]["pages"].(map[string]any)
			if !ok || pages["telemetry_status"] != tc.telemetry {
				t.Fatalf("health/artifact page telemetry differs: %s", data)
			}
		})
	}
}

func TestPassiveRootProviderProjectionExcludesOnlySyntheticInput(t *testing.T) {
	t.Run("root returned by crt.sh", func(t *testing.T) {
		cfg := collectFixtureConfig(t, "crt.sh")
		client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return jsonResponse(r, http.StatusOK, `[{"name_value":"example.test"}]`)
		}))
		var events []core.Event
		result, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, event core.Event) error {
			events = append(events, event)
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		root := result.Inventory["example.test"]
		if !containsString(root.Providers, "user_input") || !containsString(root.Providers, "crt.sh") {
			t.Fatalf("canonical inventory lost input/provider attribution: %+v", root)
		}
		var aggregate *core.Event
		for i := range events {
			if events[i].Metadata["collection"] == "passive_inventory_summary" && events[i].NormalizedValue == "example.test" {
				aggregate = &events[i]
			}
		}
		if aggregate == nil || !sameStrings(aggregate.Metadata["providers"], []string{"crt.sh"}) || aggregate.Metadata["unique_provider_count"] != 1 {
			t.Fatalf("root aggregate=%+v", aggregate)
		}
		data, err := os.ReadFile(filepath.Join(cfg.ArtifactsDir(), completenessArtifactName))
		if err != nil {
			t.Fatal(err)
		}
		var artifact struct {
			Providers []map[string]any `json:"providers"`
		}
		if err = json.Unmarshal(data, &artifact); err != nil || len(artifact.Providers) != 1 || artifact.Providers[0]["unique"] != float64(1) {
			t.Fatalf("root unique contribution artifact=%s err=%v", data, err)
		}
	})
	t.Run("input-only root is omitted; unknown root collector remains", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			addUnknown bool
		}{
			{name: "input only"},
			{name: "unknown root", addUnknown: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				inventory, err := evidence.NewProviderInventoryAccumulator("example.test")
				if err != nil {
					t.Fatal(err)
				}
				if tc.addUnknown {
					ev, e := core.NewEvent(core.DomainFound, "subdomains", "submd", "example.test", "example.test", core.InScope)
					if e != nil {
						t.Fatal(e)
					}
					ev.Metadata = map[string]any{"provider": UnknownAggregate, "collector_tool": "submd", "evidence_family": UnknownAggregate}
					if e = inventory.AddEvent(ev); e != nil {
						t.Fatal(e)
					}
				}
				var events []core.Event
				s := &collectState{ctx: context.Background(), req: CollectRequest{Sink: func(_ context.Context, event core.Event) error { events = append(events, event); return nil }}, target: "example.test", inventory: inventory}
				if err = s.emitSummary(); err != nil {
					t.Fatal(err)
				}
				var aggregate *core.Event
				for i := range events {
					if events[i].Metadata["collection"] == "passive_inventory_summary" {
						aggregate = &events[i]
					}
				}
				if !tc.addUnknown && aggregate != nil {
					t.Fatalf("synthetic input alone emitted provider aggregate: %+v", aggregate)
				}
				if tc.addUnknown && (aggregate == nil || !sameStrings(aggregate.Metadata["providers"], []string{}) || !sameStrings(aggregate.Metadata["collectors"], []string{"submd"})) {
					t.Fatalf("unknown-provider actual collector was dropped: %+v", aggregate)
				}
			})
		}
	})
}

func TestCRTNameEmitsUpstreamAndPSLProvenanceForNarrowScope(t *testing.T) {
	target := "api.example.co.uk"
	cfg := collectFixtureConfig(t, "crt.name")
	cfg.TargetDomain, cfg.AllowedDomains = &target, []string{target}
	cfg.ScopePolicy.AllowedDomains = []string{target}
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusOK, `["api.example.co.uk"]`)
	}))
	var observations []core.Event
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, event core.Event) error {
		if event.SourceTool == "crt.name" && (event.EventType == core.DomainFound || event.EventType == core.SubdomainFound) {
			observations = append(observations, event)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("crt.name observations=%+v", observations)
	}
	metadata, ok := observations[0].Metadata["provider_metadata"].(map[string]any)
	psl, pslOK := metadata["psl"].(map[string]any)
	if !ok || metadata["query_apex"] != "example.co.uk" || metadata["provider_query_scope_differs_from_authorized_scope"] != true || metadata["provider_may_include_active_upstream_collection"] != true || !pslOK || psl["suffix_source"] != "bundled_snapshot" || psl["network_update_disabled"] != true {
		t.Fatalf("crt.name provenance missing: %+v", observations[0].Metadata["provider_metadata"])
	}
}

func TestDisabledCRTNameFallbackExplainsTrigger(t *testing.T) {
	cfg := collectFixtureConfig(t)
	cfg.CollectionPolicy.SubMDFallbackEnabled = true
	tool := behaviorSubfaster(t, `package main
import("fmt";"os")
func main(){if len(os.Args)>1 && os.Args[1]=="-version" {fmt.Println("Subfaster v2.18.0");return};fmt.Println("{\"host\":\"fallback.example.test\",\"sources\":[\"submd\"]}")}
`)
	var health *core.Event
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, Subfaster: &tool, Sink: func(_ context.Context, event core.Event) error {
		if event.EventType == core.SourceHealth && event.SourceTool == "submd" {
			health = &event
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if health == nil || !strings.Contains(health.Metadata["message"].(string), "triggered_by=crt.name:disabled") {
		t.Fatalf("disabled-source fallback reason missing: %+v", health)
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

func sameStrings(got any, want []string) bool {
	var values []string
	switch x := got.(type) {
	case []string:
		values = x
	case []any:
		for _, value := range x {
			text, ok := value.(string)
			if !ok {
				return false
			}
			values = append(values, text)
		}
	default:
		return false
	}
	if len(values) != len(want) {
		return false
	}
	for i := range want {
		if values[i] != want[i] {
			return false
		}
	}
	return true
}
