package evidence

import (
	"asmtool/internal/core"
	"sort"
	"strings"
)

const UnknownAggregate = "unknown_aggregate"

type ProviderResult struct {
	Provider, Collector, Family, Role, Status, CompletenessState, TerminationReason string
	Observations                                                                    []ProviderObservation
	ReturnedTotal                                                                   int
	Truncated                                                                       bool
	TransportErrors                                                                 int
	Warning                                                                         string
}
type ProviderObservation struct {
	Hostname, Provider, Collector, Family, FirstSeen string
	Raw                                              any
	Metadata                                         map[string]any
}

func Inventory(paths []string, root string) (map[string]map[string]any, error) {
	root, err := core.NormalizeDomain(root)
	if err != nil {
		return nil, err
	}
	acc := newProviderInventoryAccumulator(root)
	for _, path := range paths {
		err = IterJSONL(path, func(r JSONLRecord) error {
			if r.Err != nil {
				return r.Err
			}
			acc.add(r.Event)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return acc.legacy(), nil
}
func text(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}
func add(dst any, v any, ignore string) {
	s := text(v)
	if s != "" && s != ignore {
		if m, ok := dst.(map[string]bool); ok {
			m[s] = true
		}
	}
}

type inventoryState struct {
	providers, collectors, families map[string]bool
	firstSeen                       map[string]string
	observations                    int
}
type providerInventoryAccumulator struct {
	root  string
	items map[string]*inventoryState
}

func newProviderInventoryAccumulator(root string) *providerInventoryAccumulator {
	return &providerInventoryAccumulator{root: root, items: map[string]*inventoryState{}}
}

func (a *providerInventoryAccumulator) add(event map[string]any) {
	typ, _ := event["event_type"].(string)
	if (typ != "domain_found" && typ != "subdomain_found") || event["scope_status"] != string(core.InScope) {
		return
	}
	raw, ok := event["normalized_value"].(string)
	if !ok {
		return
	}
	host, err := core.NormalizeDomain(raw)
	if err != nil || (host != a.root && !strings.HasSuffix(host, "."+a.root)) {
		return
	}
	item := a.items[host]
	if item == nil {
		item = &inventoryState{providers: map[string]bool{}, collectors: map[string]bool{}, families: map[string]bool{}, firstSeen: map[string]string{}}
		a.items[host] = item
	}
	item.observations++
	meta, _ := event["metadata"].(map[string]any)
	add(item.providers, meta["provider"], UnknownAggregate)
	add(item.collectors, meta["collector_tool"], "")
	add(item.families, meta["evidence_family"], UnknownAggregate)
	for _, list := range []struct {
		key    string
		dst    map[string]bool
		ignore string
	}{{"providers", item.providers, UnknownAggregate}, {"collectors", item.collectors, ""}, {"evidence_families", item.families, UnknownAggregate}} {
		for _, v := range anySlice(meta[list.key]) {
			add(list.dst, v, list.ignore)
		}
	}
	provider, first := text(meta["provider"]), text(meta["first_seen_by_provider"])
	if provider != "" && provider != UnknownAggregate && first != "" && (item.firstSeen[provider] == "" || first < item.firstSeen[provider]) {
		item.firstSeen[provider] = first
	}
}
func anySlice(value any) []any {
	switch x := value.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = v
		}
		return out
	default:
		return nil
	}
}
func (a *providerInventoryAccumulator) ensureRoot() {
	if a.items[a.root] != nil {
		return
	}
	a.items[a.root] = &inventoryState{providers: map[string]bool{"user_input": true}, collectors: map[string]bool{"input": true}, families: map[string]bool{"user_input": true}, firstSeen: map[string]string{}, observations: 1}
}
func (a *providerInventoryAccumulator) legacy() map[string]map[string]any {
	a.ensureRoot()
	out := make(map[string]map[string]any, len(a.items))
	for name, x := range a.items {
		seen := map[string]string{}
		for k, v := range x.firstSeen {
			seen[k] = v
		}
		out[name] = map[string]any{"hostname": name, "providers": x.providers, "collectors": x.collectors, "evidence_families": x.families, "first_seen_by_provider": seen, "observations": x.observations, "input_target": name == a.root}
	}
	return out
}
func (a *providerInventoryAccumulator) typed() map[string]ProviderInventoryEntry {
	a.ensureRoot()
	out := make(map[string]ProviderInventoryEntry, len(a.items))
	for name, x := range a.items {
		seen := map[string]string{}
		for k, v := range x.firstSeen {
			seen[k] = v
		}
		out[name] = ProviderInventoryEntry{Hostname: name, Providers: sortedSet(x.providers), Collectors: sortedSet(x.collectors), EvidenceFamilies: sortedSet(x.families), FirstSeenByProvider: seen, Observations: x.observations, InputTarget: name == a.root}
	}
	return out
}
func RankForDNS(in map[string]map[string]any, root string, budget int) (selected, deferred []map[string]any) {
	items := []map[string]any{}
	for n, x := range in {
		if n != root {
			items = append(items, x)
		}
	}
	sort.Slice(items, func(i, j int) bool { return before(items[i], items[j]) })
	take := budget - 1
	if take < 0 {
		take = 0
	}
	if take > len(items) {
		take = len(items)
	}
	selected = append(selected, in[root])
	selected = append(selected, items[:take]...)
	deferred = items[take:]
	return
}

// RankProviderInventory applies the same DNS budget ordering to the typed inventory
// used by discovery. Keeping ranking here makes evidence attribution and
// ordering policy shared by both inventory representations.
func RankProviderInventory(in map[string]ProviderInventoryEntry, root string, budget int) (selected, deferred []ProviderInventoryEntry) {
	items := make([]ProviderInventoryEntry, 0, len(in))
	for name, item := range in {
		if name != root {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return beforeTyped(items[i], items[j]) })
	take := max(min(budget-1, len(items)), 0)
	if item, ok := in[root]; ok {
		selected = append(selected, item)
	}
	selected = append(selected, items[:take]...)
	deferred = append(deferred, items[take:]...)
	return selected, deferred
}
func before(a, b map[string]any) bool {
	pa, pb := a["providers"].(map[string]bool), b["providers"].(map[string]bool)
	fa, fb := a["evidence_families"].(map[string]bool), b["evidence_families"].(map[string]bool)
	return compareRank(rankFacts{hostname: text(a["hostname"]), providers: len(pa), families: len(fa), ct: has(pa, "crt.sh", "certspotter"), aggregate: fa["mixed_third_party_index"], firstSeen: len(a["first_seen_by_provider"].(map[string]string)) > 0}, rankFacts{hostname: text(b["hostname"]), providers: len(pb), families: len(fb), ct: has(pb, "crt.sh", "certspotter"), aggregate: fb["mixed_third_party_index"], firstSeen: len(b["first_seen_by_provider"].(map[string]string)) > 0})
}

func beforeTyped(a, b ProviderInventoryEntry) bool {
	return compareRank(rankFacts{hostname: a.Hostname, providers: len(a.Providers), families: len(a.EvidenceFamilies), ct: containsAny(a.Providers, "crt.sh", "certspotter"), aggregate: contains(a.EvidenceFamilies, "mixed_third_party_index"), firstSeen: len(a.FirstSeenByProvider) > 0}, rankFacts{hostname: b.Hostname, providers: len(b.Providers), families: len(b.EvidenceFamilies), ct: containsAny(b.Providers, "crt.sh", "certspotter"), aggregate: contains(b.EvidenceFamilies, "mixed_third_party_index"), firstSeen: len(b.FirstSeenByProvider) > 0})
}

type rankFacts struct {
	hostname                 string
	providers, families      int
	ct, aggregate, firstSeen bool
}

func compareRank(a, b rankFacts) bool {
	if a.providers != b.providers {
		return a.providers > b.providers
	}
	if a.families != b.families {
		return a.families > b.families
	}
	if a.ct != b.ct {
		return a.ct
	}
	if a.aggregate != b.aggregate {
		return a.aggregate
	}
	if a.firstSeen != b.firstSeen {
		return a.firstSeen
	}
	return a.hostname < b.hostname
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func containsAny(values []string, wants ...string) bool {
	for _, value := range values {
		for _, want := range wants {
			if value == want {
				return true
			}
		}
	}
	return false
}
func has(m map[string]bool, keys ...string) bool {
	for _, k := range keys {
		if m[k] {
			return true
		}
	}
	return false
}
