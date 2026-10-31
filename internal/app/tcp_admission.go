package app

import (
	"asmtool/internal/active/network"
	"asmtool/internal/evidence"
	"context"
)

func buildSafeTCPPlan(ctx context.Context, p Plan, index *evidence.DNSRunIndex, sink *durableSink) (network.TCPPlan, error) {
	plan, err := network.BuildTCPPlan(index, p.target, p.cfg.ScopePolicy, p.active.TCPTargets)
	if err != nil {
		return network.TCPPlan{}, err
	}
	if blocked := plan.BlockedSpecialIPs(); len(blocked) > 0 {
		if err := emitLimitation(ctx, sink, "port_scan", "scope_blocked", "warning", "special_address_requires_explicit_allowed_cidr", len(blocked), blocked); err != nil {
			return network.TCPPlan{}, err
		}
	}
	if deferred := plan.DeferredIPs(); deferred > 0 {
		if err := emitLimitation(ctx, sink, "port_scan", "partial", "warning", "tcp_target_budget", deferred, nil); err != nil {
			return network.TCPPlan{}, err
		}
	}
	return plan, nil
}
