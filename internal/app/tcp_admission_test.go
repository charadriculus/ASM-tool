package app

import (
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/storage"
	"context"
	"path/filepath"
	"testing"
)

func TestIntegrationTCPSpecialIPAndBudgetAdmission(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		ips, cidrs             []string
		max, want, limitations int
	}{
		{"private_refused", []string{"127.0.0.1", "10.0.0.8", "169.254.169.254", "::1", "2001:db8::1"}, nil, 10, 0, 1},
		{"explicit_private", []string{"10.0.0.8"}, []string{"10.0.0.0/24"}, 10, 1, 0},
		{"never_unspecified_multicast", []string{"0.0.0.0", "224.0.0.1"}, []string{"0.0.0.0/0"}, 10, 0, 1},
		{"public_budget", []string{"8.8.8.8", "9.9.9.9"}, nil, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := activeTestPlan("full", "disabled", config.Modules{PortScan: true})
			p.cfg.AllowedCIDRs = tc.cidrs
			p.active.TCPTargets = tc.max
			index := activeDNSIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}}, tc.ips...)
			sink, close := activeTestSink(t, index, filepath.Join(t.TempDir(), "events.jsonl"))
			defer close()
			plan, err := buildSafeTCPPlan(context.Background(), p, index, sink)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.IPs()) != tc.want {
				t.Fatalf("ips=%v", plan.IPs())
			}
			rows, err := storage.IterEvents(context.Background(), sink.db, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != tc.limitations {
				t.Fatalf("limitations=%v", rows)
			}
		})
	}
}
