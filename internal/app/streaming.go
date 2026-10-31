package app

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
	"asmtool/internal/portable"
)

// executeStreaming connects existing collectors/validators/active operations.
// Admission is arrival ordered (an explicit user-approved streaming policy),
// while the batch path retains full-inventory ranking. Only this owner closes
// queues; all consumers are joined before the caller can close durable stores.
func executeStreaming(ctx context.Context, p Plan, payload portable.Payload, sink *durableSink, stage stages, announce func(string) error, progress func(string, string, string) error) (out activeOutcome, deferred int, incomplete bool, retErr error) {
	if !p.cfg.DirectTargetInteraction() || !p.cfg.AuthorizationConfirmed {
		return out, 0, true, ErrAuthorizationRequired
	}
	if stage.quick == nil {
		return out, 0, true, errors.New("streaming DNS validator is required")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var errMu sync.Mutex
	var firstErr error
	fail := func(err error) {
		if err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			cancel()
		}
	}
	client, err := stage.dnsClient(5*time.Second, p.cfg.RateLimits.DNSQueriesPerSecond)
	if err != nil {
		return out, 0, true, err
	}
	cfg := dns.ExpansionConfig{Root: p.target, Policy: p.cfg.ScopePolicy, Client: client, Index: sink.index,
		Budget: p.cfg.CollectionPolicy.DNSCandidateBudget, Workers: p.cfg.RateLimits.DNSWorkerCount,
		WildcardProbes: p.cfg.CollectionPolicy.WildcardProbesPerParent, WildcardParentBudget: p.cfg.CollectionPolicy.WildcardMaxParentZones,
		MaxEnrichmentIPs: p.cfg.CollectionPolicy.PassiveMaxIPs, WildcardEnabled: p.cfg.CollectionPolicy.WildcardEnabled,
		IncludeWildcardAmbiguous: p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive,
		Emit:                     func(ev core.Event) error { return sink.emit(child, ev) }}
	analyzer, err := dns.NewWildcardAnalyzer(p.target, client, cfg.WildcardProbes, cfg.WildcardParentBudget, cfg.WildcardEnabled, []string{p.target})
	if err != nil {
		return out, 0, true, err
	}
	cfg.Analyzer = analyzer
	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > cfg.Budget {
		workers = cfg.Budget
	}
	if workers < 1 {
		return out, 0, true, errors.New("positive streaming DNS budget is required")
	}
	candidates := make(chan string, workers)
	targets := make(chan []web.Target, workers)
	var dnsWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		dnsWG.Add(1)
		go func() {
			defer dnsWG.Done()
			for name := range candidates {
				if err := child.Err(); err != nil {
					return
				}
				if _, err := stage.quick(child, cfg, analyzer, name); err != nil {
					fail(err)
					return
				}
				if sink.index.ExistingValidation(name) == nil {
					fail(errors.New("streaming DNS validator returned without durable validation"))
					return
				}
				eligible, err := web.EligibleTargets(sink.index, p.target, p.cfg.ScopePolicy, p.cfg.CollectionPolicy.WebPrimaryDomainOnly, p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive)
				if err != nil {
					fail(err)
					return
				}
				for _, target := range eligible {
					if target.Domain == name {
						select {
						case targets <- []web.Target{target}:
						case <-child.Done():
							return
						}
						break
					}
				}
			}
		}()
	}
	activeDone := make(chan struct{})
	stage.ops.targetBatches = targets
	// Late HTML admission is installed before publication of EOF, so the active
	// consumer never observes a partially constructed admission controller.
	var admission *dynamicDomainAdmission
	if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
		stage.ops.admitDomains = func(callCtx context.Context, names []string) (dynamicAdmissionResult, error) {
			if admission == nil {
				return dynamicAdmissionResult{}, errors.New("streaming DNS admission barrier not reached")
			}
			return admission.Admit(callCtx, names)
		}
	}
	go func() {
		defer close(activeDone)
		var e error
		out, e = executeActive(child, p, payload, sink, announce, stage.ops)
		fail(e)
	}()
	var admitMu sync.Mutex
	selected := map[string]bool{}
	seen := map[string]bool{}
	admit := func(name string) error {
		name, e := core.NormalizeDomain(name)
		if e != nil || !core.DomainMatches(name, p.target) || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(name).Status != core.InScope {
			return nil
		}
		if seen[name] {
			return nil
		}
		seen[name] = true
		if len(selected) >= cfg.Budget {
			return nil
		}
		selected[name] = true
		select {
		case candidates <- name:
			return nil
		case <-child.Done():
			return child.Err()
		}
	}
	seeded := false
	discoverySink := func(callCtx context.Context, ev core.Event) error {
		if err := sink.emit(callCtx, ev); err != nil {
			return err
		}
		if ev.EventType != core.DomainFound {
			return nil
		}
		admitMu.Lock()
		defer admitMu.Unlock()
		if !seeded {
			seeded = true
			if err := admit(p.target); err != nil {
				return err
			}
			explicit := append([]string(nil), p.cfg.ScopePolicy.AllowedDomains...)
			sort.Strings(explicit)
			for _, name := range explicit {
				if err := admit(name); err != nil {
					return err
				}
			}
		}
		raw, _ := ev.NormalizedValue.(string)
		return admit(raw)
	}
	if err := announce("streaming_discovery_dns_web"); err != nil {
		fail(err)
	}
	schedule, err := core.NewEvent(core.Limitation, "pipeline", "go_streaming", "bounded discovery DNS HTTP crawler pipeline", p.target, core.InScope)
	if err == nil {
		schedule.Metadata = map[string]any{"severity": "info", "pipeline_schedule": "bounded_streaming", "dns_selection_policy": "arrival_order", "dns_workers": workers, "candidate_queue_capacity": cap(candidates), "target_queue_capacity": cap(targets), "active_consumers": 1, "target_service_contacted": false}
		err = sink.emit(child, schedule)
	}
	fail(err)
	collected := passive.CollectResult{Inventory: map[string]evidence.ProviderInventoryEntry{}}
	if child.Err() == nil {
		if p.cfg.Modules.Subdomains {
			collected, err = stage.collect(child, passive.CollectRequest{Config: p.cfg, Subfaster: payload.Subfaster, Sink: discoverySink, OnProgress: func(provider, state, message string) { fail(progress(provider, state, message)) }})
		} else {
			var ev core.Event
			ev, err = core.NewEvent(core.DomainFound, "input", "user_input", p.target, p.target, core.InScope)
			if err == nil {
				ev.Confidence = 1
				ev.Metadata = map[string]any{"input_target": true, "collection": "user_input", "target_service_contacted": false}
				err = discoverySink(child, ev)
			}
		}
		fail(err)
	}
	// Collector callbacks have returned. No producer can race closure.
	close(candidates)
	dnsWG.Wait()
	incomplete = collectionIncomplete(collected)
	if child.Err() == nil {
		// Final Expand handles root records/enrichment once and reuses exactly the
		// admitted set. Never re-rank the original inventory and spend budget twice.
		cfg.Inventory = map[string]evidence.ProviderInventoryEntry{}
		for name := range selected {
			item := collected.Inventory[name]
			item.Hostname = name
			cfg.Inventory[name] = item
		}
		cfg.SkipPrevalidated = true
		cfg.Policy.AllowedDomains = []string{p.target}
		_, err = stage.expand(child, cfg)
		fail(err)
	}
	if child.Err() == nil {
		deferredNames := make([]string, 0, len(seen))
		for name := range seen {
			if !selected[name] {
				deferredNames = append(deferredNames, name)
			}
		}
		sort.Strings(deferredNames)
		for _, name := range deferredNames {
			if selected[name] {
				continue
			}
			deferred++
			ev, e := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_budget", name, name, core.InScope)
			if e != nil {
				fail(e)
				break
			}
			ev.Metadata = map[string]any{"dns_state": "deferred_by_dns_budget", "active_eligibility": "not_selected", "dns_validated": false, "target_service_contacted": false, "collection": "public_dns", "dns_candidate_budget": cfg.Budget, "selection_policy": "arrival_order", "reason": "configured dns_candidate_budget"}
			if e = sink.emit(child, ev); e != nil {
				fail(e)
				break
			}
		}
		incomplete = incomplete || deferred > 0
	}
	if child.Err() == nil && p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
		admission, err = newDynamicDomainAdmission(p.target, p.cfg.CollectionPolicy, p.cfg.ScopePolicy, len(selected), cfg, stage.expand)
		fail(err)
	}
	if child.Err() == nil && p.cfg.Modules.PortScan && p.cfg.CollectionPolicy.InternetdbEnabled {
		if err = announce("passive_port_inventory"); err == nil {
			var c *passive.Client
			c, err = newInventoryClient(p.cfg)
			if err == nil {
				var partial bool
				partial, err = collectPortInventory(child, p.cfg, sink.index, c, sink.emit)
				incomplete = incomplete || partial
			}
		}
		fail(err)
	}
	close(targets)
	<-activeDone
	errMu.Lock()
	retErr = firstErr
	errMu.Unlock()
	if retErr == nil {
		retErr = ctx.Err()
	}
	if out.Coverage == nil {
		out.Coverage = map[string]any{}
	}
	out.Coverage["dns_workers"] = workers
	out.Coverage["candidate_queue_capacity"] = cap(candidates)
	out.Coverage["target_queue_capacity"] = cap(targets)
	out.Coverage["active_consumers"] = 1
	out.Coverage["discovery_delivery"] = "live_subfaster_and_http_provider_batches"
	incomplete = incomplete || out.Incomplete || retErr != nil
	return out, deferred, incomplete, retErr
}

func collectionIncomplete(collected passive.CollectResult) bool {
	if collected.Truncated {
		return true
	}
	for _, p := range collected.Providers {
		if p.Truncated || p.TransportErrors > 0 || (p.CompletenessState != "" && p.CompletenessState != evidence.Complete && p.CompletenessState != evidence.CompleteEmpty) {
			return true
		}
		switch p.Status {
		case "error", "failed", "timeout", "unavailable", "rate_limited", "partial":
			return true
		}
	}
	return false
}
