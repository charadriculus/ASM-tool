package passive

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"asmtool/internal/backends"
	"asmtool/internal/evidence"
	"asmtool/internal/version"
)

const completenessArtifactName = "passive_provider_completeness.json"
const maxHistoryFiles = 20
const maxHistoryArtifactBytes = 8 << 20

type completenessKey struct{ provider, collector string }
type historicalProvider struct {
	Returned int      `json:"returned"`
	Elapsed  *float64 `json:"elapsed"`
}
type historyArtifact struct {
	Domain    string `json:"domain"`
	Providers []struct {
		Provider  string   `json:"provider"`
		Collector string   `json:"collector"`
		Returned  int      `json:"returned"`
		Elapsed   *float64 `json:"elapsed"`
	} `json:"providers"`
}

type completenessProvider struct {
	Provider, Collector                                    string
	Version, Environment                                   string
	Returned, Accepted, Duplicates                         int
	PagesAttempted, PagesCompleted                         *int
	PaginationTelemetry, Termination, Status, Completeness string
	TransportErrors                                        int
	Elapsed                                                float64
	RequestsAttempted                                      any
	Truncated                                              bool
}

func discoverPassiveHistory(outputDir, target string, maxFiles int) map[completenessKey][]historicalProvider {
	history := map[completenessKey][]historicalProvider{}
	if maxFiles <= 0 {
		return history
	}
	current, err := filepath.Abs(outputDir)
	if err != nil {
		return history
	}
	if resolved, e := filepath.EvalSymlinks(current); e == nil {
		current = resolved
	}
	parent := filepath.Dir(current)
	paths, err := filepath.Glob(filepath.Join(parent, "*", "artifacts", completenessArtifactName))
	if err != nil {
		return history
	}
	type candidate struct {
		path     string
		modified int64
	}
	candidates := make([]candidate, 0, len(paths))
	for _, path := range paths {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() {
			continue
		}
		root, e := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(path)))
		if e != nil || filepath.Clean(root) == filepath.Clean(current) || filepath.Dir(root) != filepath.Clean(parent) {
			continue
		}
		candidates = append(candidates, candidate{path: path, modified: info.ModTime().UnixNano()})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modified == candidates[j].modified {
			return candidates[i].path < candidates[j].path
		}
		return candidates[i].modified > candidates[j].modified
	})
	if len(candidates) > maxFiles {
		candidates = candidates[:maxFiles]
	}
	for _, candidate := range candidates {
		file, e := os.Open(candidate.path)
		if e != nil {
			continue
		}
		info, e := file.Stat()
		if e != nil || info.Size() > maxHistoryArtifactBytes {
			_ = file.Close()
			continue
		}
		data, e := io.ReadAll(io.LimitReader(file, maxHistoryArtifactBytes+1))
		_ = file.Close()
		if e != nil || len(data) > maxHistoryArtifactBytes {
			continue
		}
		var payload historyArtifact
		if json.Unmarshal(data, &payload) != nil || payload.Domain != target {
			continue
		}
		for _, row := range payload.Providers {
			if row.Provider == "" || row.Collector == "" || row.Returned < 0 {
				continue
			}
			key := completenessKey{row.Provider, row.Collector}
			history[key] = append(history[key], historicalProvider{Returned: row.Returned, Elapsed: row.Elapsed})
		}
	}
	return history
}

func (s *collectState) writeCompleteness() error {
	history := discoverPassiveHistory(s.req.Config.OutputDir, s.target, maxHistoryFiles)
	inventory := s.inventory.Snapshot()
	unique := map[string]int{}
	for name, item := range inventory {
		item = passiveAttribution(item)
		if name == s.target && len(item.Providers)+len(item.EvidenceFamilies)+len(item.Collectors) == 0 {
			continue
		}
		if len(item.Providers) == 1 {
			unique[item.Providers[0]]++
		}
	}
	s.mu.Lock()
	inputs := make([]completenessProvider, 0, len(s.providerOutcomes))
	for _, out := range s.providerOutcomes {
		elapsed := 0.0
		if !out.started.IsZero() && !out.finished.IsZero() {
			elapsed = out.finished.Sub(out.started).Seconds()
		}
		completeness := out.result.CompletenessState
		if !validCompleteness(completeness) {
			completeness = evidence.ClassifyCompleteness(out.result.Status, intPointer(out.returnCode), out.result.Status == "timeout", out.rateLimited, out.result.TransportErrors, false, out.truncated, out.result.ReturnedTotal, out.truncated)
		}
		var attempted, completed *int
		if out.pagesAttempted > 0 {
			attempted, completed = intPointer(out.pagesAttempted), intPointer(out.pagesCompleted)
		}
		telemetry := "not_exposed_by_collector_cli"
		if out.result.Collector == "subfaster" {
			telemetry = "not_exposed_by_subfaster_cli_v2_18_0"
		}
		if result := paginationTelemetry(out); result != "" {
			telemetry = result
		}
		termination := out.result.TerminationReason
		if termination == "" {
			termination = "collector_exit_observed"
		}
		environment := "sanitized"
		inputs = append(inputs, completenessProvider{Provider: out.result.Provider, Collector: out.result.Collector, Version: out.version, Environment: environment, Returned: out.result.ReturnedTotal, Accepted: out.accepted, Duplicates: out.duplicates, PagesAttempted: attempted, PagesCompleted: completed, PaginationTelemetry: telemetry, Termination: termination, Status: out.result.Status, Completeness: completeness, TransportErrors: out.result.TransportErrors, Elapsed: elapsed, RequestsAttempted: nil, Truncated: out.truncated})
	}
	s.mu.Unlock()
	payload := buildPassiveCompletenessArtifact(version.Version, s.target, inputs, unique, history)
	return backends.WriteJSONAtomic(filepath.Join(s.req.Config.ArtifactsDir(), completenessArtifactName), payload, true, true, true, false)
}

// passiveAttribution removes the synthetic caller input from provider statistics
// while retaining the canonical inventory entry used by replay and DNS ranking.
func passiveAttribution(item evidence.ProviderInventoryEntry) evidence.ProviderInventoryEntry {
	if !item.InputTarget {
		return item
	}
	item.Providers = without(item.Providers, "user_input")
	item.Collectors = without(item.Collectors, "input")
	item.EvidenceFamilies = without(item.EvidenceFamilies, "user_input")
	firstSeen := make(map[string]string, len(item.FirstSeenByProvider))
	for provider, value := range item.FirstSeenByProvider {
		if provider != "user_input" {
			firstSeen[provider] = value
		}
	}
	item.FirstSeenByProvider = firstSeen
	return item
}

func without(values []string, excluded string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != excluded {
			result = append(result, value)
		}
	}
	return result
}

func buildPassiveCompletenessArtifact(version, target string, inputs []completenessProvider, unique map[string]int, history map[completenessKey][]historicalProvider) map[string]any {
	rows := make([]map[string]any, 0, len(inputs))
	for _, item := range inputs {
		rowsForKey := history[completenessKey{item.Provider, item.Collector}]
		historical := make([]evidence.HistoricalRun, 0, len(rowsForKey))
		for _, row := range rowsForKey {
			historical = append(historical, evidence.HistoricalRun{Returned: row.Returned, Elapsed: row.Elapsed})
		}
		assessment := evidence.AssessOutput(item.Returned, historical, item.Elapsed)
		completeness := item.Completeness
		if !validCompleteness(completeness) {
			completeness = evidence.CompletenessUnknown
		}
		telemetry := item.PaginationTelemetry
		if telemetry == "" {
			telemetry = "not_exposed_by_collector_cli"
		}
		termination := item.Termination
		if termination == "" {
			termination = "collector_exit_observed"
		}
		version, environment := nullableText(item.Version), item.Environment
		if environment == "" {
			environment = "sanitized"
		}
		rows = append(rows, map[string]any{
			"collector": item.Collector, "collector_version": version, "provider": item.Provider, "domain": target,
			"environment_mode": environment, "returned": max(0, item.Returned), "accepted": max(0, item.Accepted),
			"unique": max(0, unique[item.Provider]), "duplicates": max(0, item.Duplicates),
			"pages":              map[string]any{"attempted": item.PagesAttempted, "completed": item.PagesCompleted, "telemetry_status": telemetry},
			"requests_attempted": item.RequestsAttempted, "termination": termination,
			"transport_errors": max(0, item.TransportErrors), "elapsed": roundSeconds(item.Elapsed),
			"collector_status": item.Status, "completeness_state": completeness,
			"historical_comparison": map[string]any{"status": assessment.Status, "anomalous": assessment.Anomalous, "current_returned": assessment.CurrentReturned, "historical_median_returned": assessment.HistoricalMedian, "relative_to_historical_median": assessment.Ratio, "historical_median_elapsed_seconds": assessment.HistoricalMedianElapsed, "elapsed_ratio": assessment.ElapsedRatio, "reasons": assessment.Reasons, "comparable_runs": len(historical), "note": "historical cardinality is diagnostic context only, never a normative asset count"},
			"anomaly_status":        assessment.Status, "retry_status": "not_attempted",
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a["provider"] == b["provider"] {
			return a["collector"].(string) < b["collector"].(string)
		}
		return a["provider"].(string) < b["provider"].(string)
	})
	return map[string]any{"schema_version": 1, "academic_purpose": "diagnose passive-provider completeness without treating collector success as completeness proof", "asm_version": version, "domain": target, "providers": rows, "methodology": map[string]any{"collector_success_is_not_completeness_proof": true, "historical_cardinality_is_anomaly_context_only": true, "automatic_retry_changes_inventory": false, "page_level_telemetry_required_for_confirmed_pagination_completeness": true}}
}

func validCompleteness(value string) bool {
	switch value {
	case evidence.Complete, evidence.CompleteEmpty, evidence.PartialTransport, evidence.PartialTimeout, evidence.PartialRateLimited, evidence.PaginationIncomplete, evidence.CollectorFailed, evidence.CompletenessUnknown:
		return true
	default:
		return false
	}
}

func nullableText(value string) any {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return nil
}

func roundSeconds(value float64) float64 { return math.Round(value*1e6) / 1e6 }
