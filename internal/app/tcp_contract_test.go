package app

import (
	"asmtool/internal/backends"
	"asmtool/internal/core"
	"path/filepath"
	"testing"
)

func TestTCPEventSchemaRejectsFalseReachability(t *testing.T) {
	base := func() map[string]any {
		ev, _ := core.NewEvent(core.PortScanResult, "port_scan", "tcp_connect", nil, "127.0.0.1:80", core.InScope)
		ev.Metadata = map[string]any{"ip": "127.0.0.1", "protocol": "tcp", "port": 80, "state": "open", "attempted": true, "started_at": "2026-10-20T00:00:00Z", "duration_ms": 1, "validated_domains": []string{"example.test"}, "reason": "", "error": ""}
		v, err := object(ev)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err := backends.ValidateEvent(base()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(map[string]any){func(m map[string]any) { m["state"] = "filtered" }, func(m map[string]any) { m["attempted"] = false }, func(m map[string]any) { m["port"] = 0 }, func(m map[string]any) { m["validated_domains"] = []any{} }} {
		ev := base()
		bad(ev["metadata"].(map[string]any))
		if err := backends.ValidateEvent(ev); err == nil {
			t.Fatalf("invalid reachability accepted: %v", ev)
		}
	}
}
func TestCurrentConfigurationExampleValidatesWithoutCollection(t *testing.T) {
	path, err := filepath.Abs("../../assets/examples/config.example.yml")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := ParseOptions([]string{"validate-config", "--config", path, "--domain", "example.com", "--non-interactive"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(opts); err != nil {
		t.Fatal(err)
	}
	// Prepare is filesystem/configuration only; no target or payload process is invoked.
}
