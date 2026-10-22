package app

import (
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/evidence"
)

// Preserve initial parent selection using the canonical inventory ranker.
func wildcardParents(root string, policy core.ScopePolicy, inventory map[string]evidence.ProviderInventoryEntry, budget, parentBudget int) []string {
	inv := make(map[string]evidence.ProviderInventoryEntry, len(inventory)+len(policy.AllowedDomains)+1)
	checker := core.ScopeChecker{Policy: policy}
	for raw, item := range inventory {
		name, err := core.NormalizeDomain(raw)
		if err == nil && core.DomainMatches(name, root) && checker.CheckDomain(name).Status == core.InScope {
			item.Hostname = name
			inv[name] = item
		}
	}
	for _, raw := range policy.AllowedDomains {
		name, err := core.NormalizeDomain(raw)
		if err == nil && name != root && core.DomainMatches(name, root) && checker.CheckDomain(name).Status == core.InScope {
			if _, exists := inv[name]; !exists {
				inv[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{"user_scope"}, Collectors: []string{"input"}, EvidenceFamilies: []string{"user_input"}, FirstSeenByProvider: map[string]string{}, Observations: 1}
			}
		}
	}
	if _, exists := inv[root]; !exists {
		inv[root] = evidence.ProviderInventoryEntry{Hostname: root, Providers: []string{"user_input"}, Collectors: []string{"input"}, EvidenceFamilies: []string{"user_input"}, FirstSeenByProvider: map[string]string{}, Observations: 1, InputTarget: true}
	}
	selected, _ := evidence.RankProviderInventory(inv, root, budget)
	names := make([]string, 0, len(selected))
	for _, item := range selected {
		names = append(names, item.Hostname)
	}
	return dns.PrioritizedParents(names, root, parentBudget)
}
