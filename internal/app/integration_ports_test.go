package app

import (
	"asmtool/internal/config"
	"asmtool/internal/core"
	"reflect"
	"testing"
)

func TestConfiguredNonstandardPortsMatchLegacyWebSelection(t *testing.T) {
	p := activeTestPlan("verify", "disabled", config.Modules{WebProbe: true})
	p.cfg.Ports = []int{80, 443, 8080, 8443, 9443}
	p.cfg.RateLimits.HTTPMaxRequestsPerHost = 2
	p.active = makeActiveSettings(p)
	_, targets, err := planActiveTargets(p, activeDNSIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}}, "192.0.2.10"), func(core.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://example.test:8443/", "https://example.test:9443/"}
	if !reflect.DeepEqual(targets.URLs, want) {
		t.Fatalf("URLs=%v want=%v", targets.URLs, want)
	}
	p.cfg.Ports = []int{80, 443}
	_, targets, err = planActiveTargets(p, activeDNSIndex(p.cfg.ScopePolicy, "192.0.2.10"), func(core.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(targets.URLs, []string{"https://example.test/"}) {
		t.Fatalf("fallback=%v", targets.URLs)
	}
}
