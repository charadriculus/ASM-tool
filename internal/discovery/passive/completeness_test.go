package passive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"asmtool/internal/evidence"
)

func TestPassiveCompletenessSourceOracle(t *testing.T) {
	fixture := loadSourceFixture(t)
	var input struct {
		ArtifactName string `json:"artifact_name"`
		Version      string `json:"asm_version"`
		Target       string `json:"target"`
		Cases        map[string]struct {
			Results []struct {
				Provider     string  `json:"provider"`
				Collector    string  `json:"collector"`
				Version      string  `json:"tool_version"`
				Status       string  `json:"status"`
				Completeness string  `json:"completeness_state"`
				Returned     int     `json:"returned_total_count"`
				Elapsed      float64 `json:"elapsed_seconds"`
				Errors       int     `json:"transport_errors"`
				Truncated    bool    `json:"truncated"`
				Termination  string  `json:"termination_reason"`
				PagesTried   *int    `json:"pages_attempted"`
				PagesDone    *int    `json:"pages_completed"`
			} `json:"provider_results"`
			Counts []struct {
				Provider   string `json:"provider"`
				Collector  string `json:"collector"`
				Accepted   int    `json:"accepted_in_scope"`
				Duplicates int    `json:"duplicate_existing"`
			} `json:"provider_counts"`
			Provenance map[string]struct {
				Providers []string `json:"providers"`
			} `json:"provenance"`
			History []struct {
				Returned int      `json:"returned"`
				Elapsed  *float64 `json:"elapsed"`
			} `json:"historical_runs"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(fixture.Inputs["passive.completeness"], &input); err != nil {
		t.Fatal(err)
	}
	var expected struct {
		ArtifactName string                     `json:"artifact_name"`
		Cases        map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(fixture.Outputs["passive.completeness"], &expected); err != nil {
		t.Fatal(err)
	}
	if input.ArtifactName != completenessArtifactName || len(input.Cases) != 4 || len(expected.Cases) != 4 {
		t.Fatalf("fixture case count or artifact name changed: input=%d output=%d artifact=%q", len(input.Cases), len(expected.Cases), input.ArtifactName)
	}
	for name, tc := range input.Cases {
		t.Run(name, func(t *testing.T) {
			unique := map[string]int{}
			for _, item := range tc.Provenance {
				if len(item.Providers) == 1 {
					unique[item.Providers[0]]++
				}
			}
			counts := map[completenessKey]struct{ accepted, duplicates int }{}
			for _, count := range tc.Counts {
				counts[completenessKey{count.Provider, count.Collector}] = struct{ accepted, duplicates int }{count.Accepted, count.Duplicates}
			}
			rows := make([]completenessProvider, 0, len(tc.Results))
			for _, result := range tc.Results {
				count := counts[completenessKey{result.Provider, result.Collector}]
				rows = append(rows, completenessProvider{Provider: result.Provider, Collector: result.Collector, Version: result.Version, Environment: "sanitized", Returned: result.Returned, Accepted: count.accepted, Duplicates: count.duplicates, PagesAttempted: result.PagesTried, PagesCompleted: result.PagesDone, Termination: result.Termination, Status: result.Status, Completeness: result.Completeness, TransportErrors: result.Errors, Elapsed: result.Elapsed, Truncated: result.Truncated})
			}
			history := map[completenessKey][]historicalProvider{}
			for _, result := range tc.Results {
				for _, row := range tc.History {
					history[completenessKey{result.Provider, result.Collector}] = append(history[completenessKey{result.Provider, result.Collector}], historicalProvider{Returned: row.Returned, Elapsed: row.Elapsed})
				}
			}
			got := buildPassiveCompletenessArtifact(input.Version, input.Target, rows, unique, history)
			var gotBytes, wantBytes []byte
			var err error
			if gotBytes, err = json.Marshal(got); err != nil {
				t.Fatal(err)
			}
			var want any
			if err = json.Unmarshal(expected.Cases[name], &want); err != nil {
				t.Fatal(err)
			}
			if wantBytes, err = json.Marshal(want); err != nil {
				t.Fatal(err)
			}
			var gotValue, wantValue any
			_ = json.Unmarshal(gotBytes, &gotValue)
			_ = json.Unmarshal(wantBytes, &wantValue)
			if !reflect.DeepEqual(gotValue, wantValue) {
				t.Fatalf("artifact differs from source oracle\ngot: %s\nwant:%s", gotBytes, wantBytes)
			}
			if stringsContainsBytes(gotBytes, []byte("legacy-")) {
				t.Fatal("historical hostname leaked into current artifact")
			}
		})
	}
}

func TestDiscoverPassiveHistoryUsesNewestTwentyComparableSiblingRuns(t *testing.T) {
	parent := t.TempDir()
	current := filepath.Join(parent, "current")
	if err := os.MkdirAll(filepath.Join(current, "artifacts"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		run := filepath.Join(parent, fmt.Sprintf("run-%02d", i))
		artifactDir := filepath.Join(run, "artifacts")
		if err := os.MkdirAll(artifactDir, 0700); err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{"domain": "example.test", "providers": []any{
			map[string]any{"provider": "crt.sh", "collector": "asm_http", "returned": i, "elapsed": float64(i)},
			map[string]any{"provider": "crt.sh", "collector": "subfaster", "returned": i + 100, "elapsed": float64(i)},
			map[string]any{"provider": "other", "collector": "asm_http", "returned": i + 200, "elapsed": float64(i)},
		}}
		b, _ := json.Marshal(payload)
		path := filepath.Join(artifactDir, completenessArtifactName)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		stamp := time.Unix(int64(i+1), 0)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	wrong := filepath.Join(parent, "wrong-target", "artifacts")
	if err := os.MkdirAll(wrong, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrong, completenessArtifactName), []byte(`{"domain":"other.test","providers":[{"provider":"crt.sh","collector":"asm_http","returned":999}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(0, 0)
	if err := os.Chtimes(filepath.Join(wrong, completenessArtifactName), old, old); err != nil {
		t.Fatal(err)
	}
	history := discoverPassiveHistory(current, "example.test", maxHistoryFiles)
	rows := history[completenessKey{"crt.sh", "asm_http"}]
	if len(rows) != 20 {
		t.Fatalf("comparable history rows=%d, want 20", len(rows))
	}
	for i, row := range rows {
		if row.Returned != 24-i {
			t.Fatalf("history[%d]=%d, want newest-first %d", i, row.Returned, 24-i)
		}
	}
	otherCollector := history[completenessKey{"crt.sh", "subfaster"}]
	if len(otherCollector) != 20 || otherCollector[0].Returned != 124 {
		t.Fatalf("collector identity was not kept separate: %#v", otherCollector)
	}
	otherProvider := history[completenessKey{"other", "asm_http"}]
	if len(otherProvider) != 20 || otherProvider[0].Returned != 224 {
		t.Fatalf("provider identity was not kept separate: %#v", otherProvider)
	}
	if got := discoverPassiveHistory(current, "example.test", 0); len(got) != 0 {
		t.Fatalf("zero history limit read data: %#v", got)
	}
}

func TestDiscoverPassiveHistorySkipsInvalidAndOversizedArtifacts(t *testing.T) {
	parent := t.TempDir()
	current := filepath.Join(parent, "current")
	if err := os.MkdirAll(filepath.Join(current, "artifacts"), 0700); err != nil {
		t.Fatal(err)
	}
	writeRun := func(name, body string) string {
		t.Helper()
		dir := filepath.Join(parent, name, "artifacts")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, completenessArtifactName)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := writeRun("valid", `{"domain":"example.test","providers":[{"provider":"crt.sh","collector":"asm_http","returned":7,"elapsed":2.5},{"provider":"crt.sh","collector":"asm_http","returned":-1},{"provider":"","collector":"asm_http","returned":2}]}`)
	writeRun("bad-json", `{malformed`)
	writeRun("wrong-target", `{"domain":"other.test","providers":[{"provider":"crt.sh","collector":"asm_http","returned":999}]}`)
	oversized := writeRun("oversized", `{"domain":"example.test"}`)
	if err := os.WriteFile(oversized, make([]byte, int(maxHistoryArtifactBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked", "artifacts")
	if err := os.MkdirAll(linked, 0700); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(linked, completenessArtifactName)
	if err := os.Symlink(valid, linkPath); err != nil {
		t.Logf("symlink fixture unavailable on this platform: %v", err)
	}
	history := discoverPassiveHistory(current, "example.test", maxHistoryFiles)
	rows := history[completenessKey{"crt.sh", "asm_http"}]
	if len(rows) != 1 || rows[0].Returned != 7 || rows[0].Elapsed == nil || *rows[0].Elapsed != 2.5 {
		t.Fatalf("invalid history artifacts or rows were accepted: %#v", history)
	}
}

func TestWriteCompletenessReturnsAtomicWriteFailure(t *testing.T) {
	cfg := collectFixtureConfig(t)
	if err := os.MkdirAll(cfg.ArtifactsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.ArtifactsDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.ArtifactsDir(), []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	inv, err := evidence.NewProviderInventoryAccumulator("example.test")
	if err != nil {
		t.Fatal(err)
	}
	s := &collectState{req: CollectRequest{Config: cfg}, target: "example.test", inventory: inv, providerOutcomes: map[string]providerOutcome{}}
	if err := s.writeCompleteness(); err == nil {
		t.Fatal("artifact write failure was ignored")
	}
}

func stringsContainsBytes(value, part []byte) bool { return bytes.Contains(value, part) }
