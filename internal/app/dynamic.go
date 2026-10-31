package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"asmtool/internal/active/web"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/evidence"
)

type dynamicAdmissionResult struct {
	Targets         []web.Target
	Added           int
	Deferred        int
	Round           int
	BudgetExhausted bool
	RoundLimit      bool
}

type dynamicDomainAdmission struct {
	mu          sync.Mutex
	root        string
	policy      core.ScopePolicy
	collection  config.CollectionPolicy
	initialUsed int
	newDomains  int
	rounds      int
	seen        map[string]bool
	base        dns.ExpansionConfig
	expand      func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error)
}

func newDynamicDomainAdmission(root string, collection config.CollectionPolicy, policy core.ScopePolicy, initialSelected int, base dns.ExpansionConfig, expand func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error)) (*dynamicDomainAdmission, error) {
	normalized, err := core.NormalizeDomain(root)
	if err != nil {
		return nil, err
	}
	if base.Index == nil || base.Client == nil || base.Emit == nil {
		return nil, errors.New("dynamic DNS admission requires the current index, DNS client, and durable event sink")
	}
	if base.Analyzer == nil && collection.WildcardEnabled {
		return nil, errors.New("dynamic DNS admission requires the run's shared wildcard analyzer")
	}
	if expand == nil {
		expand = dns.Expand
	}
	base.Root = normalized
	return &dynamicDomainAdmission{root: normalized, policy: policy, collection: collection, initialUsed: max(initialSelected, 0), seen: map[string]bool{}, base: base, expand: expand}, nil
}

// Admit validates HTML-discovered names using the existing DNS expansion path.
// The shared analyzer preserves the run's wildcard-parent query budget/cache.
func (a *dynamicDomainAdmission) Admit(ctx context.Context, candidates []string) (dynamicAdmissionResult, error) {
	out := dynamicAdmissionResult{Targets: []web.Target{}}
	if a == nil || ctx == nil {
		return out, errors.New("dynamic DNS admission requires an initialized admission and context")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	fresh := make([]string, 0, len(candidates))
	batchSeen := map[string]bool{}
	scope := core.ScopeChecker{Policy: a.policy}
	for _, raw := range candidates {
		name, err := core.NormalizeDomain(raw)
		if err != nil || name == a.root || !core.DomainMatches(name, a.root) || scope.CheckDomain(name).Status != core.InScope || batchSeen[name] || a.seen[name] || a.base.Index.ExistingValidation(name) != nil {
			continue
		}
		batchSeen[name] = true
		fresh = append(fresh, name)
	}
	sort.Strings(fresh)
	if len(fresh) == 0 || !a.collection.DynamicDiscoveryFromHTML {
		return out, nil
	}
	if a.rounds >= a.collection.DynamicDiscoveryMaxRounds {
		out.RoundLimit = true
		out.Deferred = len(fresh)
		return out, a.limit(ctx, fresh, "dynamic_discovery_round_limit", "configured HTML discovery round limit reached")
	}
	remainingDNS := a.collection.DNSCandidateBudget - a.initialUsed - a.newDomains
	remainingNew := a.collection.DynamicDiscoveryMaxNewDomains - a.newDomains
	limit := min(len(fresh), min(remainingDNS, remainingNew))
	if limit <= 0 {
		out.BudgetExhausted = true
		out.Deferred = len(fresh)
		return out, a.limit(ctx, fresh, "dynamic_discovery_budget_exhausted", "configured DNS candidate or HTML discovery domain budget exhausted")
	}
	selected := fresh[:limit]
	for _, name := range fresh {
		a.seen[name] = true
	}
	out.Round = a.rounds + 1
	out.Deferred = len(fresh) - len(selected)
	if out.Deferred > 0 {
		out.BudgetExhausted = true
	}
	inventory := make(map[string]evidence.ProviderInventoryEntry, len(selected))
	for _, name := range selected {
		inventory[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{"html_anchor"}, Collectors: []string{"active_http"}, EvidenceFamilies: []string{"active_html"}, FirstSeenByProvider: map[string]string{}, Observations: 1}
	}
	cfg := a.base
	// Admit only this round's HTML names. Keep scope checks, but prevent older
	// deferred inventory entries from consuming this round's DNS budget.
	cfg.Policy.AllowedDomains = []string{a.root}
	cfg.Inventory = inventory
	cfg.Budget = len(selected) + 1 // dns.Expand includes the already validated root.
	cfg.SkipPrevalidated = true
	if cfg.Analyzer != nil {
		for _, parent := range dns.PrioritizedParents(selected, a.root, cfg.WildcardParentBudget) {
			if err := cfg.Analyzer.AllowParent(parent); err != nil {
				return out, err
			}
		}
	}
	result, err := a.expand(ctx, cfg)
	if err != nil {
		return out, fmt.Errorf("admit HTML-discovered domains through DNS: %w", err)
	}
	a.rounds++
	out.Round = a.rounds
	selectedSet := make(map[string]bool, len(selected))
	for _, name := range result.Selected {
		if name != a.root {
			selectedSet[name] = true
		}
	}
	out.Added = len(selectedSet)
	a.newDomains += out.Added
	if len(result.Deferred) > out.Deferred {
		out.Deferred += len(result.Deferred)
		out.BudgetExhausted = true
	}
	eligible, err := web.EligibleTargets(a.base.Index, a.root, a.policy, a.collection.WebPrimaryDomainOnly, a.collection.IncludeWildcardAmbiguousActive)
	if err != nil {
		return out, err
	}
	for _, target := range eligible {
		if selectedSet[target.Domain] {
			out.Targets = append(out.Targets, target)
		}
	}
	if out.Deferred > 0 {
		if err := a.limit(ctx, fresh[limit:], "dynamic_discovery_budget_exhausted", "some HTML-discovered domains were not DNS-validated because a configured discovery budget was reached"); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (a *dynamicDomainAdmission) limit(ctx context.Context, names []string, status, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	names = append([]string(nil), names...)
	if len(names) > 100 {
		names = names[:100]
	}
	ev, err := core.NewEvent(core.Limitation, "domain_expansion", "go_runtime", reason, status, core.InScope)
	if err != nil {
		return err
	}
	ev.Metadata = map[string]any{"terminal": true, "status": status, "severity": "warning", "reason": reason, "count": len(names), "affected_targets": names, "collection": "public_dns", "target_service_contacted": false}
	return a.base.Emit(ev)
}
