package evidence

import (
	"sort"
	"strings"
)

const (
	Complete             = "complete"
	CompleteEmpty        = "complete_empty"
	PartialTransport     = "partial_transport_failure"
	PartialTimeout       = "partial_timeout"
	PartialRateLimited   = "partial_rate_limited"
	PaginationIncomplete = "pagination_incomplete"
	CollectorFailed      = "collector_failed"
	CompletenessUnknown  = "collector_success_completeness_unknown"
)

func ClassifyCompleteness(status string, returncode *int, timedOut, rateLimited bool, transportErrors int, paginationComplete, paginationIncomplete bool, returned int, truncated bool) string {
	status = strings.ToLower(status)
	if timedOut || status == "timeout" {
		if returned > 0 {
			return PartialTimeout
		}
		return CollectorFailed
	}
	if rateLimited || status == "rate_limited" {
		if returned > 0 {
			return PartialRateLimited
		}
		return CollectorFailed
	}
	if paginationIncomplete || truncated {
		return PaginationIncomplete
	}
	if transportErrors > 0 || status == "partial" {
		if returned > 0 {
			return PartialTransport
		}
		return CollectorFailed
	}
	if status == "failed" || status == "unavailable" || (returncode != nil && *returncode != 0) {
		if returned > 0 {
			return PartialTransport
		}
		return CollectorFailed
	}
	if paginationComplete {
		if returned > 0 {
			return Complete
		}
		return CompleteEmpty
	}
	if status == "ok" || status == "no_data" || status == "fallback_not_needed" || status == "skipped" || (returncode != nil && *returncode == 0) {
		return CompletenessUnknown
	}
	return CollectorFailed
}

type HistoricalRun struct {
	Returned int
	Elapsed  *float64
}
type Anomaly struct {
	Status                  string   `json:"status"`
	Anomalous               bool     `json:"anomalous"`
	CurrentReturned         int      `json:"current_returned"`
	HistoricalMedian        *float64 `json:"historical_median_returned"`
	Ratio                   *float64 `json:"relative_to_historical_median"`
	HistoricalMedianElapsed *float64 `json:"historical_median_elapsed_seconds"`
	ElapsedRatio            *float64 `json:"elapsed_ratio"`
	Reasons                 []string `json:"reasons"`
}

// AssessOutput preserves source anomaly thresholds. Optional elapsed time is the current run duration.
func AssessOutput(current int, history []HistoricalRun, currentElapsed ...float64) Anomaly {
	a := Anomaly{CurrentReturned: max(0, current), Reasons: []string{}}
	if len(history) == 0 {
		a.Status = "not_evaluated_no_comparable_history"
		a.Reasons = []string{"no_comparable_historical_runs"}
		return a
	}
	counts := []int{}
	comparable := []HistoricalRun{}
	for _, h := range history {
		if h.Returned >= 0 {
			counts = append(counts, h.Returned)
			comparable = append(comparable, h)
		}
	}
	if len(counts) == 0 {
		a.Status = "not_evaluated_no_comparable_history"
		a.Reasons = []string{"no_comparable_historical_runs"}
		return a
	}
	sort.Ints(counts)
	n := len(counts)
	median := float64(counts[n/2])
	if n%2 == 0 {
		median = float64(counts[n/2-1]+counts[n/2]) / 2
	}
	a.HistoricalMedian = &median
	if median <= 0 {
		a.Status = "not_evaluated_nonpositive_history"
		a.Reasons = []string{"historical_median_nonpositive"}
		return a
	}
	ratio := float64(a.CurrentReturned) / median
	a.Ratio = &ratio
	elapsed := []float64{}
	for _, h := range comparable {
		if h.Elapsed != nil && *h.Elapsed >= 0 {
			elapsed = append(elapsed, *h.Elapsed)
		}
	}
	if len(elapsed) > 0 {
		sort.Float64s(elapsed)
		var m float64
		if len(elapsed)%2 == 1 {
			m = elapsed[len(elapsed)/2]
		} else {
			m = (elapsed[len(elapsed)/2-1] + elapsed[len(elapsed)/2]) / 2
		}
		a.HistoricalMedianElapsed = &m
		if len(currentElapsed) > 0 && m > 0 {
			er := max(0, currentElapsed[0]) / m
			a.ElapsedRatio = &er
		}
	}
	drop := median - float64(a.CurrentReturned)
	collapse := median >= 100 && ratio <= .25 && drop >= 100
	extreme := median >= 1000 && ratio <= .10 && drop >= 1000
	runtimeCollapse := a.ElapsedRatio != nil && *a.ElapsedRatio <= .35
	a.Reasons = []string{}
	if collapse {
		a.Reasons = append(a.Reasons, "cardinality_collapse")
	}
	if extreme {
		a.Reasons = append(a.Reasons, "extreme_cardinality_collapse")
	}
	if runtimeCollapse {
		a.Reasons = append(a.Reasons, "runtime_collapse")
	}
	a.Anomalous = extreme || (collapse && runtimeCollapse)
	if a.Anomalous {
		a.Status = "provider_output_anomaly"
	} else {
		a.Status = "within_expected_variability"
	}
	return a
}
