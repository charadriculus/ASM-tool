package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

type ExpansionConfig struct {
	Root                                                                    string
	Policy                                                                  core.ScopePolicy
	Client                                                                  *Client
	Analyzer                                                                *WildcardAnalyzer
	Index                                                                   *evidence.DNSRunIndex
	Inventory                                                               map[string]evidence.ProviderInventoryEntry
	Budget, Workers, WildcardProbes, WildcardParentBudget, MaxEnrichmentIPs int
	WildcardEnabled, IncludeWildcardAmbiguous, SkipPrevalidated             bool
	Emit                                                                    func(core.Event) error
	OnValidationIndexed                                                     func(context.Context, core.Event) error
	emitMu                                                                  *sync.Mutex
}
type ExpansionResult struct {
	Inventory          map[string]evidence.ProviderInventoryEntry
	Selected, Deferred []string
	Validations        map[string]HostResolution
	Reused             map[string]map[string]any
}

func PrioritizedParents(domains []string, root string, max int) []string {
	r, e := core.NormalizeDomain(root)
	if e != nil {
		return nil
	}
	counts := map[string]int{}
	for _, d := range domains {
		n, e := core.NormalizeDomain(d)
		if e == nil && n != r {
			parent := immediateParent(n, r)
			if parent != r {
				counts[parent]++
			}
		}
	}
	parents := make([]string, 0, len(counts))
	for p := range counts {
		parents = append(parents, p)
	}
	sort.Slice(parents, func(i, j int) bool {
		if counts[parents[i]] != counts[parents[j]] {
			return counts[parents[i]] > counts[parents[j]]
		}
		return parents[i] < parents[j]
	})
	out := []string{r}
	out = append(out, parents...)
	if max < 1 {
		max = 1
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}
func selectInventory(input map[string]evidence.ProviderInventoryEntry, root string, budget int, policy core.ScopePolicy) (map[string]evidence.ProviderInventoryEntry, []string, []string, error) {
	inv := make(map[string]evidence.ProviderInventoryEntry, len(input)+len(policy.AllowedDomains)+1)
	scope := core.ScopeChecker{Policy: policy}
	for raw, item := range input {
		name, err := core.NormalizeDomain(raw)
		if err != nil || !core.DomainMatches(name, root) || scope.CheckDomain(name).Status != core.InScope {
			continue
		}
		item.Hostname = name
		inv[name] = item
	}
	for _, raw := range policy.AllowedDomains {
		name, err := core.NormalizeDomain(raw)
		if err != nil || name == root || !core.DomainMatches(name, root) || scope.CheckDomain(name).Status != core.InScope {
			continue
		}
		if _, exists := inv[name]; !exists {
			inv[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{"user_scope"}, Collectors: []string{"input"}, EvidenceFamilies: []string{"user_input"}, FirstSeenByProvider: map[string]string{}, Observations: 1}
		}
	}
	if _, ok := inv[root]; !ok {
		inv[root] = evidence.ProviderInventoryEntry{Hostname: root, Providers: []string{"user_input"}, Collectors: []string{"input"}, EvidenceFamilies: []string{"user_input"}, FirstSeenByProvider: map[string]string{}, Observations: 1, InputTarget: true}
	}
	selected, deferred := evidence.RankProviderInventory(inv, root, budget)
	toNames := func(items []evidence.ProviderInventoryEntry) []string {
		names := make([]string, 0, len(items))
		for _, item := range items {
			names = append(names, item.Hostname)
		}
		return names
	}
	return inv, toNames(selected), toNames(deferred), nil
}

// RankedInventoryNames exposes the expansion owner's deterministic selection
// to streaming admission without maintaining a second ranking implementation.
func RankedInventoryNames(input map[string]evidence.ProviderInventoryEntry, root string, budget int, policy core.ScopePolicy) ([]string, error) {
	_, selected, _, err := selectInventory(input, root, budget, policy)
	return selected, err
}
func (c ExpansionConfig) emit(ctx context.Context, e core.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Emit == nil {
		return fmt.Errorf("DNS event sink is required")
	}
	locked := false
	if c.emitMu != nil {
		c.emitMu.Lock()
		locked = true
	}
	defer func() {
		if locked {
			c.emitMu.Unlock()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	if e.EventID == "" {
		var err error
		original := e
		e, err = core.NewEvent(original.EventType, original.Module, original.SourceTool, original.RawValue, original.NormalizedValue, original.ScopeStatus)
		if err != nil {
			return err
		}
		e.Confidence, e.Evidence, e.Relations, e.Metadata = original.Confidence, original.Evidence, original.Relations, original.Metadata
	}
	var eventMap map[string]any
	if c.Index != nil {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &eventMap); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.Emit(e); err != nil {
		return err
	}
	if c.Index != nil {
		c.Index.Ingest(eventMap)
	}
	if c.OnValidationIndexed != nil && c.Index != nil && e.EventType == core.DNSValidation {
		if err := ctx.Err(); err != nil {
			return err
		}
		if locked {
			c.emitMu.Unlock()
			locked = false
		}
		if err := c.OnValidationIndexed(ctx, e); err != nil {
			return fmt.Errorf("DNS validation observer: %w", err)
		}
	}
	return ctx.Err()
}
func Expand(ctx context.Context, c ExpansionConfig) (ExpansionResult, error) {
	if err := ctx.Err(); err != nil {
		return ExpansionResult{}, err
	}
	root, e := core.NormalizeDomain(c.Root)
	if e != nil {
		return ExpansionResult{}, e
	}
	c.emitMu = &sync.Mutex{}
	if c.Client == nil {
		return ExpansionResult{}, fmt.Errorf("DNS client is required")
	}
	if c.Index == nil {
		return ExpansionResult{}, fmt.Errorf("DNS evidence index is required")
	}
	scope := core.ScopeChecker{Policy: c.Policy}
	if d := scope.CheckDomain(root); d.Status != core.InScope {
		return ExpansionResult{}, fmt.Errorf("root is not in scope: %s", d.Status)
	}
	inv, selected, deferred, e := selectInventory(c.Inventory, root, c.Budget, c.Policy)
	if e != nil {
		return ExpansionResult{}, e
	}
	res := ExpansionResult{Inventory: inv, Selected: selected, Deferred: deferred, Validations: map[string]HostResolution{}, Reused: map[string]map[string]any{}}
	parents := PrioritizedParents(selected, root, c.WildcardParentBudget)
	a := c.Analyzer
	if a == nil {
		a, e = NewWildcardAnalyzer(root, c.Client, c.WildcardProbes, c.WildcardParentBudget, c.WildcardEnabled, parents)
		if e != nil {
			return res, e
		}
	}
	for _, name := range deferred {
		d := scope.CheckDomain(name)
		ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_budget", name, name, d.Status)
		if err != nil {
			return res, err
		}
		ev.Confidence = 0
		ev.Metadata = map[string]any{"dns_state": "deferred_by_dns_budget", "active_eligibility": "not_selected", "dns_validated": false, "target_service_contacted": false, "collection": "public_dns", "reason": "configured dns_candidate_budget", "dns_candidate_budget": c.Budget}
		if err = c.emit(ctx, ev); err != nil {
			return res, err
		}
	}
	pending := []string{}
	for _, n := range selected {
		if c.SkipPrevalidated {
			if existing := c.Index.ExistingValidation(n); existing != nil {
				res.Reused[n] = existing
				continue
			}
		}
		pending = append(pending, n)
	}
	if c.Workers < 1 {
		c.Workers = 1
	}
	if c.Workers > len(pending) {
		c.Workers = len(pending)
	}
	if len(pending) > 0 {
		jobs := make(chan string)
		var wg sync.WaitGroup
		var resultMu sync.Mutex
		var once sync.Once
		var firstErr error
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		worker := func() {
			defer wg.Done()
			for n := range jobs {
				r, err := validateOne(child, c, scope, a, root, n)
				if err != nil {
					if len(r.Queries) > 0 {
						resultMu.Lock()
						res.Validations[n] = r
						resultMu.Unlock()
					}
					once.Do(func() { firstErr = err; cancel() })
					continue
				}
				resultMu.Lock()
				res.Validations[n] = r
				resultMu.Unlock()
			}
		}
		for i := 0; i < c.Workers; i++ {
			wg.Add(1)
			go worker()
		}
	sendLoop:
		for _, n := range pending {
			select {
			case <-child.Done():
				break sendLoop
			case jobs <- n:
			}
		}
		close(jobs)
		wg.Wait()
		if firstErr != nil {
			return res, firstErr
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
	}
	rootHasRecords, err := collectRootAndEnrichment(ctx, c, scope, root)
	if err != nil {
		return res, err
	}
	if !rootHasRecords {
		rootIPs := []string(nil)
		if rootRun, ok := res.Validations[root]; ok {
			rootIPs = rootRun.IPs
		} else if prior := res.Reused[root]; prior != nil {
			if vals, ok := prior["terminal_ips"].([]any); ok {
				for _, v := range vals {
					if ip, ok := v.(string); ok {
						rootIPs = append(rootIPs, ip)
					}
				}
			}
		}
		if len(rootIPs) == 0 {
			ev, err := core.NewEvent(core.Limitation, "domain_expansion", "dns", "No public DNS records were found for the root domain", root, core.InScope)
			if err != nil {
				return res, err
			}
			ev.Confidence = 1
			ev.Metadata = map[string]any{"severity": "error", "collection": "public_dns", "target_service_contacted": false, "action": "check_target_spelling"}
			if err = c.emit(ctx, ev); err != nil {
				return res, err
			}
		}
	}
	if len(deferred) > 0 {
		ev, err := core.NewEvent(core.Limitation, "domain_expansion", "dns_budget", fmt.Sprintf("%d passive candidate(s) were not DNS-validated because dns_candidate_budget=%d", len(deferred), c.Budget), "dns_candidate_budget", core.InScope)
		if err != nil {
			return res, err
		}
		ev.Confidence = 1
		ev.Metadata = map[string]any{"severity": "info", "inventory_total": len(inv), "dns_selected": len(selected), "deferred_by_dns_budget": len(deferred), "dns_candidate_budget": c.Budget}
		if err = c.emit(ctx, ev); err != nil {
			return res, err
		}
	}
	return res, ctx.Err()
}
func validateOne(ctx context.Context, c ExpansionConfig, scope core.ScopeChecker, a *WildcardAnalyzer, root, name string) (HostResolution, error) {
	if err := ctx.Err(); err != nil {
		return HostResolution{}, err
	}
	d := scope.CheckDomain(name)
	if d.Status != core.InScope {
		return HostResolution{}, fmt.Errorf("candidate out of scope: %s", name)
	}
	if c.SkipPrevalidated && c.Index.ExistingValidation(name) != nil {
		return HostResolution{}, ctx.Err()
	}
	r, e := ResolveHost(ctx, c.Client, name, 8)
	if e != nil {
		return r, e
	}
	fallback := false
	if name == root && !r.Resolved && !r.DNSError {
		if len(c.Client.Resolvers) == 0 {
			return r, fmt.Errorf("DNS client has no configured resolver")
		}
		fallbackCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		sys := net.Resolver{PreferGo: true, Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
			if err := c.Client.wait(dctx); err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(dctx, network, c.Client.Resolvers[0])
		}}
		ips, err := sys.LookupNetIP(fallbackCtx, "ip", name)
		parentErr := ctx.Err()
		cancel()
		if parentErr != nil {
			return r, parentErr
		}
		if err == nil {
			r.SystemFallbackResolver = c.Client.Resolvers[0]
			for _, ip := range ips {
				canonical := ip.String()
				r.IPs = append(r.IPs, canonical)
				r.SystemFallbackIPs = append(r.SystemFallbackIPs, canonical)
			}
			sort.Strings(r.IPs)
			sort.Strings(r.SystemFallbackIPs)
			r.Resolved = len(r.IPs) > 0
			fallback = r.Resolved
		}
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	state, parent, e := a.Classify(ctx, name, r, name == root)
	if parent != nil {
		r.WildcardAnalysis = parent
	}
	if e != nil {
		return r, e
	}
	elig := ActiveEligibility(state, r, name == root, c.IncludeWildcardAmbiguous)
	for _, q := range r.Queries {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		for _, v := range q.Values {
			var ev core.Event
			recordMeta := map[string]any{"collection": "public_dns", "resolver": q.Resolver, "resolver_backend": q.Backend, "ttl": q.TTL, "rcode": q.RCode, "dns_status": q.Status, "target_service_contacted": false}
			ipMeta := map[string]any{"collection": "public_dns", "resolver": q.Resolver, "resolver_backend": q.Backend, "ttl": q.TTL, "rcode": q.RCode, "dns_status": q.Status, "target_service_contacted": false}
			domainMeta := map[string]any(nil)
			switch q.RType {
			case "A", "AAAA":
				ip, err := netip.ParseAddr(v)
				if err != nil {
					continue
				}
				norm := ip.String()
				ev, e = core.NewEvent(core.IPFound, "domain_expansion", "dns", norm, norm, d.Status)
				ipMeta["domain"] = q.Name
				ipMeta["record_type"] = q.RType
			case "CNAME":
				norm, err := core.NormalizeDomain(v)
				if err != nil {
					continue
				}
				ev, e = core.NewEvent(core.DomainFound, "domain_expansion", "dns_cname", norm, norm, scope.CheckDomain(norm).Status)
				toDecision := scope.CheckDomain(v)
				domainMeta = map[string]any{"collection": "public_dns", "context_only": toDecision.Status != core.InScope, "not_added_to_active_scope": true, "related_via": name, "provider": "current_dns", "collector_tool": "asm_dns", "evidence_family": "current_dns", "cname_context_only": true}
			default:
				continue
			}
			if e != nil {
				return r, e
			}
			if q.RType == "A" || q.RType == "AAAA" {
				ev.Metadata = ipMeta
				ev.Confidence = .88
				ev.Relations = []map[string]any{{"source_id": "domain:" + q.Name, "target_id": "ip:" + v, "relation_type": "resolves_to", "evidence": map[string]any{"record_type": q.RType, "resolver": q.Resolver}}}
			} else {
				toDecision := scope.CheckDomain(v)
				ev.Confidence = .55
				if toDecision.Status == core.InScope {
					ev.Confidence = .82
				}
				ev.Relations = []map[string]any{{"source_id": "domain:" + q.Name, "target_id": "domain:" + v, "relation_type": "cname_to", "evidence": map[string]any{"record_type": "CNAME", "resolver": q.Resolver}}}
				ev.Metadata = domainMeta
			}
			if e = c.emit(ctx, ev); e != nil {
				return r, e
			}
			record := map[string]any{"name": q.Name, "type": q.RType, "value": v}
			ev, e = core.NewEvent(core.DNSRecordFound, "domain_expansion", "dns", record, record, d.Status)
			if e != nil {
				return r, e
			}
			if q.RType == "A" || q.RType == "AAAA" {
				ev.Relations = []map[string]any{{"source_id": "domain:" + q.Name, "target_id": "ip:" + v, "relation_type": "resolves_to", "evidence": map[string]any{"record_type": q.RType, "resolver": q.Resolver}}}
			} else {
				ev.Relations = []map[string]any{{"source_id": "domain:" + q.Name, "target_id": "domain:" + v, "relation_type": "cname_to", "evidence": map[string]any{"record_type": "CNAME", "resolver": q.Resolver}}}
			}
			ev.Metadata = recordMeta
			ev.Confidence = .88
			if e = c.emit(ctx, ev); e != nil {
				return r, e
			}
		}
	}
	if fallback {
		for _, ip := range r.IPs {
			ev, e := core.NewEvent(core.IPFound, "domain_expansion", "system_resolver", ip, ip, d.Status)
			if e != nil {
				return r, e
			}
			ev.Confidence = .8
			ev.Relations = []map[string]any{{"source_id": "domain:" + name, "target_id": "ip:" + ip, "relation_type": "resolves_to", "evidence": map[string]any{"record_type": "system_resolver"}}}
			ev.Metadata = map[string]any{"domain": name, "record_type": "system_resolver", "collection": "public_dns_or_hosts", "target_service_contacted": false, "resolver_backend": ResolverBackend}
			if e = c.emit(ctx, ev); e != nil {
				return r, e
			}
		}
	}
	records := validationRecords(r)
	wildcardState := any(nil)
	if name == root {
		wildcardState = "input_root"
	}
	metadata := map[string]any{"collection": "public_dns", "resolver_backend": ResolverBackend, "target_service_contacted": false, "dns_state": state, "active_eligibility": elig, "operationally_resolvable": r.Resolved, "terminal_ips": r.IPs, "terminal_name": r.TerminalName, "cname_chain": r.CNAMEChain, "validation_records": records, "structured_resolution": r.ToMap(), "parent_zone": nil, "wildcard_parent_state": wildcardState, "wildcard_analysis": parent, "input_target": name == root, "reused": false}
	if parent != nil {
		metadata["parent_zone"] = parent.Parent
		metadata["wildcard_parent_state"] = parent.State
		metadata["wildcard_analysis"] = parent
	}
	ev, e := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_validation", name, name, d.Status)
	if e != nil {
		return r, e
	}
	ev.Confidence = .55
	if elig == "eligible" || elig == "eligible_override" {
		ev.Confidence = .92
	}
	if name == root && r.Resolved {
		ev.Confidence = 1
	}
	if name != root {
		ev.Relations = []map[string]any{{"source_id": "domain:" + name, "target_id": "domain:" + root, "relation_type": "subdomain_of", "evidence": map[string]any{"validation": "wildcard_aware_public_dns"}}}
	}
	ev.Metadata = metadata
	if e = c.emit(ctx, ev); e != nil {
		return r, e
	}
	if r.DNSError {
		msg := "DNS validation could not resolve the hostname after resolver attempts"
		lim, err := core.NewEvent(core.Limitation, "domain_expansion", "dns", msg, name, d.Status)
		if err != nil {
			return r, err
		}
		lim.Confidence = 0
		lim.Metadata = map[string]any{"severity": "warning", "collection": "public_dns", "dns_state": state, "target_service_contacted": false}
		if err = c.emit(ctx, lim); err != nil {
			return r, err
		}
	}
	return r, nil
}

func collectRootAndEnrichment(ctx context.Context, c ExpansionConfig, scope core.ScopeChecker, root string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	d := scope.CheckDomain(root)
	foundRoot := false
	for _, typ := range []string{"MX", "NS", "SOA"} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		q := queryRR(ctx, c.Client, root, typ)
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if q.Error != "" {
			lim, err := core.NewEvent(core.Limitation, "domain_expansion", "dns", typ+": "+q.Error, root, d.Status)
			if err != nil {
				return false, err
			}
			lim.Confidence = 0
			lim.Metadata = map[string]any{"severity": "warning", "collection": "public_dns", "record_type": typ, "target_service_contacted": false}
			if err = c.emit(ctx, lim); err != nil {
				return false, err
			}
		}
		for _, v := range q.Values {
			foundRoot = true
			record := map[string]any{"name": root, "type": typ, "value": v}
			ev, e := core.NewEvent(core.DNSRecordFound, "domain_expansion", "dns", record, record, d.Status)
			if e != nil {
				return false, e
			}
			ev.Metadata = map[string]any{"collection": "public_dns", "resolver": q.Resolver, "ttl": q.TTL, "rcode": q.RCode, "dns_status": q.Status, "target_service_contacted": false}
			ev.Confidence = .82
			if e = c.emit(ctx, ev); e != nil {
				return false, e
			}
		}
	}
	ips := c.Index.IPs()
	limit := c.MaxEnrichmentIPs
	if limit <= 0 {
		limit = 100
	}
	if len(ips) > limit {
		ips = ips[:limit]
	}
	for _, raw := range ips {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		ip, e := netip.ParseAddr(raw)
		if e != nil {
			continue
		}
		ptrName := reverseName(ip)
		q := queryRR(ctx, c.Client, ptrName, "PTR")
		if err := ctx.Err(); err != nil {
			return false, err
		}
		for _, v := range q.Values {
			rec := map[string]any{"name": raw, "type": "PTR", "value": strings.TrimSuffix(strings.ToLower(v), ".")}
			ev, e := core.NewEvent(core.DNSRecordFound, "domain_expansion", "dns", rec, rec, scope.CheckDomain(v).Status)
			if e != nil {
				return false, e
			}
			ev.Confidence = .55
			ev.Relations = []map[string]any{{"source_id": "ip:" + raw, "target_id": "domain:" + strings.TrimSuffix(strings.ToLower(v), "."), "relation_type": "reverse_dns", "evidence": map[string]any{"record_type": "PTR", "resolver": q.Resolver}}}
			ev.Metadata = map[string]any{"collection": "public_dns", "resolver": q.Resolver, "target_service_contacted": false}
			if e = c.emit(ctx, ev); e != nil {
				return false, e
			}
			ptr := strings.TrimSuffix(strings.ToLower(v), ".")
			pd := scope.CheckDomain(ptr)
			found, err := core.NewEvent(core.DomainFound, "domain_expansion", "reverse_dns", ptr, ptr, pd.Status)
			if err != nil {
				return false, err
			}
			found.Confidence = .25
			if pd.Status == core.InScope {
				found.Confidence = .5
			}
			found.Relations = []map[string]any{{"source_id": "ip:" + raw, "target_id": "domain:" + ptr, "relation_type": "reverse_dns", "evidence": map[string]any{"record_type": "PTR", "resolver": q.Resolver}}}
			found.Metadata = map[string]any{"collection": "public_dns", "context_only": pd.Status != core.InScope, "not_added_to_active_scope": true, "related_via_ip": raw, "provider": "current_dns", "collector_tool": "asm_dns", "evidence_family": "current_dns"}
			if err = c.emit(ctx, found); err != nil {
				return false, err
			}
		}
		cymru := cymruName(ip)
		tq := queryRR(ctx, c.Client, cymru, "TXT")
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if len(tq.Values) == 0 {
			continue
		}
		asn, prefix, meta, ok := parseCymruRecord(tq.Values[0], tq.Resolver)
		if !ok {
			continue
		}
		desc := queryRR(ctx, c.Client, asn+".asn.cymru.com", "TXT")
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if len(desc.Values) > 0 {
			dp := strings.Split(strings.Trim(desc.Values[0], "\""), "|")
			if len(dp) >= 5 {
				meta["as_name"] = strings.TrimSpace(dp[4])
			}
		}
		asnMetadata := make(map[string]any, len(meta)+4)
		for k, v := range meta {
			asnMetadata[k] = v
		}
		asnMetadata["ip"] = raw
		asnMetadata["collection"] = "passive_osint"
		asnMetadata["target_contacted"] = false
		asnMetadata["interpretation"] = "routing/provider context; not proof of target ownership"
		ev, e := core.NewEvent(core.ASNFound, "domain_expansion", "team_cymru_dns", meta, asn, core.NeedsManualReview)
		if e != nil {
			return false, e
		}
		ev.Confidence = .7
		ev.Relations = []map[string]any{{"source_id": "ip:" + raw, "target_id": "asn:" + asn, "relation_type": "announced_by", "evidence": map[string]any{"prefix": prefix}}}
		ev.Metadata = asnMetadata
		if e = c.emit(ctx, ev); e != nil {
			return false, e
		}
		if prefix != "" {
			ev, e = core.NewEvent(core.CIDRFound, "domain_expansion", "team_cymru_dns", prefix, prefix, core.NeedsManualReview)
			if e != nil {
				return false, e
			}
			ev.Confidence = .65
			ev.Relations = []map[string]any{{"source_id": "ip:" + raw, "target_id": "cidr:" + prefix, "relation_type": "contained_in", "evidence": map[string]any{"asn": asn}}}
			ev.Metadata = map[string]any{"asn": asn, "ip": raw, "collection": "passive_osint", "target_contacted": false, "routing_context_not_ownership": true}
			if e = c.emit(ctx, ev); e != nil {
				return false, e
			}
		}
	}
	return foundRoot, ctx.Err()
}

func parseCymruRecord(raw, resolver string) (asn, prefix string, metadata map[string]any, ok bool) {
	text := strings.Trim(raw, "\"")
	parts := strings.Split(text, "|")
	if len(parts) < 2 {
		return "", "", map[string]any{"raw": text, "resolver": resolver}, false
	}
	fields := strings.Fields(strings.TrimSpace(parts[0]))
	if len(fields) == 0 {
		return "", "", nil, false
	}
	identifier := strings.TrimPrefix(fields[0], "AS")
	prefix = strings.TrimSpace(parts[1])
	if identifier == "" || prefix == "" {
		return "", "", nil, false
	}
	metadata = map[string]any{
		"country": "", "registry": "", "allocated": "", "raw": text,
		"resolver": resolver, "routing_context_not_ownership": true,
	}
	if len(parts) > 2 {
		metadata["country"] = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 {
		metadata["registry"] = strings.TrimSpace(parts[3])
	}
	if len(parts) > 4 {
		metadata["allocated"] = strings.TrimSpace(parts[4])
	}
	return "AS" + identifier, prefix, metadata, true
}
func reverseName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	s := make([]byte, 0, 72)
	const h = "0123456789abcdef"
	for i := len(b) - 1; i >= 0; i-- {
		s = append(s, h[b[i]&15], '.', h[b[i]>>4], '.')
	}
	return string(s) + "ip6.arpa"
}
func cymruName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var s strings.Builder
	const h = "0123456789abcdef"
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&s, "%c.%c.", h[b[i]&15], h[b[i]>>4])
	}
	return s.String() + "origin6.asn.cymru.com"
}
