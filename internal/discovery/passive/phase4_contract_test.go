package passive

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

func TestPassiveHealthSourceOracleFourCasesSevenEvents(t *testing.T) {
	fixture := loadSourceFixture(t)
	var inputs map[string]json.RawMessage
	var expected map[string][]json.RawMessage
	if err := json.Unmarshal(fixture.Inputs["passive.health"], &inputs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.Outputs["passive.health"], &expected); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 4 || len(expected) != 4 {
		t.Fatalf("health cases input=%d output=%d, want 4", len(inputs), len(expected))
	}
	count := 0
	for name, raw := range inputs {
		t.Run(name, func(t *testing.T) {
			var in struct {
				Target string `json:"target"`
				Counts struct {
					Returned   int `json:"returned_total"`
					Accepted   int `json:"accepted_in_scope"`
					Duplicates int `json:"duplicate_existing"`
					New        int `json:"new_to_inventory_at_ingest"`
					Deferred   int `json:"deferred_by_inventory_safety_cap"`
				} `json:"count_overrides"`
				Result struct {
					Provider, Collector, Role, Status string
					Completeness                      string     `json:"completeness_state"`
					Family                            string     `json:"evidence_family"`
					Started                           string     `json:"started_at"`
					Finished                          string     `json:"finished_at"`
					Elapsed                           float64    `json:"elapsed_seconds"`
					Returned                          *int       `json:"returned_total_count"`
					TransportErrors                   int        `json:"transport_errors"`
					Termination                       string     `json:"termination_reason"`
					Truncated                         bool       `json:"truncated"`
					Message                           string     `json:"message"`
					ErrorType                         string     `json:"error_type"`
					TechnicalError                    string     `json:"technical_error"`
					StatusCode                        *int       `json:"last_http_status"`
					CacheHit                          bool       `json:"cache_hit"`
					CacheStale                        bool       `json:"cache_stale"`
					CacheAge                          *float64   `json:"cache_age_seconds"`
					Fallback                          string     `json:"fallback_after_error"`
					Attempts                          *int       `json:"http_attempts"`
					Logical                           *int       `json:"http_logical_requests"`
					PagesTried                        *int       `json:"pages_attempted"`
					PagesDone                         *int       `json:"pages_completed"`
					Pagination                        string     `json:"pagination_telemetry_status"`
					ReturnCode                        *int       `json:"returncode"`
					Stdout                            *int       `json:"stdout_lines"`
					Stderr                            *int       `json:"stderr_lines"`
					Malformed                         *int       `json:"malformed_output_lines"`
					Version                           string     `json:"tool_version"`
					VersionWarning                    string     `json:"version_warning"`
					Binary                            string     `json:"binary_path"`
					ExpectedVersion                   string     `json:"expected_version"`
					Environment                       string     `json:"environment_mode"`
					Observations                      []struct{} `json:"observations"`
				} `json:"provider_result"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				t.Fatal(err)
			}
			start, err := time.Parse(time.RFC3339Nano, in.Result.Started)
			if err != nil {
				t.Fatal(err)
			}
			finish, err := time.Parse(time.RFC3339Nano, in.Result.Finished)
			if err != nil {
				t.Fatal(err)
			}
			finish = start.Add(time.Duration(in.Result.Elapsed * float64(time.Second)))
			warning := in.Result.Message
			var sourceErr error
			if in.Result.ErrorType != "" {
				sourceErr = &SourceError{StatusCode: derefInt(in.Result.StatusCode), Kind: in.Result.ErrorType, Message: warning}
			}
			out := providerOutcome{result: evidence.ProviderResult{Provider: in.Result.Provider, Collector: in.Result.Collector, Role: in.Result.Role, Family: in.Result.Family, Status: in.Result.Status, CompletenessState: in.Result.Completeness, TerminationReason: in.Result.Termination, ReturnedTotal: in.Counts.Returned, Truncated: in.Result.Truncated, TransportErrors: in.Result.TransportErrors, Warning: in.Result.Message}, err: sourceErr, start: in.Result.Started, finish: in.Result.Finished, started: start, finished: finish, accepted: in.Counts.Accepted, duplicates: in.Counts.Duplicates, newToInventory: in.Counts.New, deferred: in.Counts.Deferred, httpAttempts: derefInt(in.Result.Attempts), httpLogical: derefInt(in.Result.Logical), pagesAttempted: derefInt(in.Result.PagesTried), pagesCompleted: derefInt(in.Result.PagesDone), returnCode: derefInt(in.Result.ReturnCode), stdoutLines: derefInt(in.Result.Stdout), stderrLines: derefInt(in.Result.Stderr), malformed: derefInt(in.Result.Malformed), version: in.Result.Version, versionWarning: in.Result.VersionWarning, binaryPath: in.Result.Binary, expectedVersion: in.Result.ExpectedVersion, environmentMode: in.Result.Environment, httpTelemetryPresent: in.Result.Attempts != nil || in.Result.Logical != nil}
			out.meta = HTTPMeta{ErrorType: in.Result.ErrorType, StatusCode: derefInt(in.Result.StatusCode), CacheHit: in.Result.CacheHit, CacheStale: in.Result.CacheStale, CacheAgeSeconds: derefFloat(in.Result.CacheAge), FallbackAfterError: in.Result.Fallback}
			cfg := collectFixtureConfig(t)
			inv, err := evidence.NewProviderInventoryAccumulator(in.Target)
			if err != nil {
				t.Fatal(err)
			}
			var actual []core.Event
			state := &collectState{ctx: context.Background(), req: CollectRequest{Config: cfg, Sink: func(_ context.Context, event core.Event) error { actual = append(actual, event); return nil }}, target: in.Target, inventory: inv}
			if err := state.emitHealth(context.Background(), in.Result.Provider, out); err != nil {
				t.Fatal(err)
			}
			wantEvents := expected[name]
			if len(actual) != len(wantEvents) {
				t.Fatalf("events=%d want=%d", len(actual), len(wantEvents))
			}
			count += len(actual)
			for i, event := range actual {
				gotBytes, _ := json.Marshal(event)
				var got map[string]any
				_ = json.Unmarshal(gotBytes, &got)
				delete(got, "event_id")
				delete(got, "observed_at")
				delete(got, "observed_at_local")
				var want map[string]any
				if err := json.Unmarshal(wantEvents[i], &want); err != nil {
					t.Fatal(err)
				}
				delete(want, "event_id")
				delete(want, "observed_at")
				delete(want, "observed_at_local")
				if !reflect.DeepEqual(got, want) {
					t.Errorf("event[%d] differs from source oracle\ngot=%s\nwant=%s", i, gotBytes, wantEvents[i])
				}
			}
		})
	}
	if count != 7 {
		t.Fatalf("health emitted %d events, want 7", count)
	}
}

func TestPassiveConfidenceMatchesSourceOracle(t *testing.T) {
	fixture := loadSourceFixture(t)
	var expected []float64
	if err := json.Unmarshal(fixture.Outputs["passive.confidence"], &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 4 {
		t.Fatalf("confidence cases=%d, want 4", len(expected))
	}
	for i, tc := range []struct {
		providers, families int
		ct                  bool
	}{{0, 0, false}, {1, 1, false}, {2, 2, true}, {10, 10, true}} {
		if got := passiveConfidence(tc.providers, tc.families, tc.ct); got != expected[i] {
			t.Errorf("confidence[%d]=%.2f want %.2f", i, got, expected[i])
		}
	}
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}
func derefFloat(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func TestCollectLiveInventoryEqualsJSONLReplayIncludingAggregateEvents(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.sh", "certspotter")
	cfg.CollectionPolicy.PassiveInventorySafetyCap = 4
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "crt.sh" {
			return jsonResponse(r, http.StatusOK, `[{"name_value":"shared.example.test\nct.example.test\ncapper.example.test"},{"name_value":"shared.example.test"}]`)
		}
		after := r.URL.Query().Get("after")
		if after == "" {
			return jsonResponse(r, http.StatusOK, `[{"id":"page-one","dns_names":["shared.example.test","spotter.example.test"]}]`)
		}
		return jsonResponse(r, http.StatusOK, `[]`)
	}))
	var events []core.Event
	got, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, event core.Event) error { events = append(events, event); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("Collect emitted no events")
	}
	var jsonl bytes.Buffer
	for _, event := range events {
		b, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		jsonl.Write(b)
		jsonl.WriteByte('\n')
	}
	jsonlPath := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(jsonlPath, jsonl.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	replay := make([]map[string]any, 0, len(events))
	if err := evidence.IterJSONL(jsonlPath, func(record evidence.JSONLRecord) error {
		if record.Err != nil {
			return record.Err
		}
		replay = append(replay, record.Event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want, err := evidence.ProviderInventory(replay, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Inventory, want) {
		t.Fatalf("live inventory differs from durable event replay\nlive=%s\nreplay=%s", mustJSON(got.Inventory), mustJSON(want))
	}
	for _, name := range []string{"example.test", "shared.example.test"} {
		if _, ok := got.Inventory[name]; !ok {
			t.Errorf("expected inventory name %q absent", name)
		}
	}
	if got.Inventory["shared.example.test"].Observations < 2 {
		t.Errorf("cross-provider evidence was not represented: %+v", got.Inventory["shared.example.test"])
	}
	if !got.Truncated {
		t.Fatal("safety cap was not exercised")
	}
	if !strings.Contains(mustJSON(events), "passive_inventory_summary") {
		t.Fatal("fixture did not exercise aggregate summary events")
	}
	artifactPath := filepath.Join(cfg.ArtifactsDir(), completenessArtifactName)
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("live completeness artifact missing at ArtifactsDir: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(artifact, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["domain"] != "example.test" || payload["academic_purpose"] == nil || !strings.Contains(string(artifact), "collector_exit_observed") {
		t.Fatalf("live completeness payload lost contract fields: %s", artifact)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
