package evidence

import (
	"asmtool/internal/backends"
	"time"
)

type BackendResolution struct {
	Category   string `json:"category"`
	Requested  string `json:"requested"`
	Actual     string `json:"actual"`
	Status     string `json:"status"`
	Workload   string `json:"workload,omitempty"`
	ResolvedAt string `json:"resolved_at_utc"`
}

func ResolveBackend(category, requested, workload string) BackendResolution {
	actual, available := map[string]string{"serialization": "go_stdlib", "schema": "go_jsonschema_v6", "storage": "modernc_sqlite"}[category]
	status := "unavailable"
	if available {
		status = "available"
	}
	return BackendResolution{Category: category, Requested: requested, Actual: actual, Status: status, Workload: workload, ResolvedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}
func WriteBackendProvenance(path string, rows []BackendResolution) error {
	payload := map[string]any{"schema_version": 1, "runtime": "go", "generated_at_utc": time.Now().UTC().Format(time.RFC3339Nano), "backends": rows}
	return backends.WriteJSONAtomic(path, payload, true, true, true, false)
}
