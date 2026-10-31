package evidence

import (
	"net/netip"
	"sort"
	"strings"
	"sync"

	"asmtool/internal/core"
)

type DNSRunIndex struct {
	mu                                         sync.RWMutex
	scope                                      core.ScopeChecker
	validations                                map[string]dnsValidation
	ips, ptrs                                  map[string]map[string]bool
	domainsByIP, ipsByDomain, cnames, asnNames map[string]map[string]bool
	EventsIndexed                              int
}
type dnsValidation struct {
	observed string
	metadata map[string]any
}

func NewDNSRunIndex(policy core.ScopePolicy) *DNSRunIndex {
	return &DNSRunIndex{scope: core.ScopeChecker{Policy: policy}, validations: map[string]dnsValidation{}, ips: map[string]map[string]bool{}, ptrs: map[string]map[string]bool{}, domainsByIP: map[string]map[string]bool{}, ipsByDomain: map[string]map[string]bool{}, cnames: map[string]map[string]bool{}, asnNames: map[string]map[string]bool{}}
}
func addSet(m map[string]map[string]bool, k, v string) {
	if k == "" || v == "" {
		return
	}
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}
func (x *DNSRunIndex) Ingest(ev map[string]any) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.EventsIndexed++
	typ, _ := ev["event_type"].(string)
	value := ev["normalized_value"]
	meta, _ := ev["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	observed := text(ev["observed_at"])
	switch typ {
	case "dns_validation":
		name, ok := value.(string)
		if ok {
			if n, e := core.NormalizeDomain(name); e == nil && meta["dns_state"] != nil && meta["dns_state"] != "deferred_by_dns_budget" {
				old, exists := x.validations[n]
				if !exists || observed >= old.observed {
					m := map[string]any{}
					for k, v := range meta {
						m[k] = v
					}
					x.validations[n] = dnsValidation{observed, m}
				}
			}
		}
	case "ip_found":
		raw, ok := value.(string)
		if ok {
			if ip, e := netip.ParseAddr(raw); e == nil {
				ipstr := ip.String()
				addSet(x.ips, ipstr, ipstr)
				domain, ok := meta["domain"].(string)
				if ok && x.scope.CheckDomain(domain).Status == core.InScope {
					name, _ := core.NormalizeDomain(domain)
					addSet(x.domainsByIP, ipstr, name)
					addSet(x.ipsByDomain, name, ipstr)
				}
			}
		}
	case "dns_record_found":
		m, ok := value.(map[string]any)
		if ok {
			typ := strings.ToUpper(text(m["type"]))
			name, val := text(m["name"]), text(m["value"])
			if typ == "PTR" {
				if ip, e := netip.ParseAddr(name); e == nil {
					addSet(x.ptrs, ip.String(), strings.TrimSuffix(strings.ToLower(val), "."))
				}
			} else if typ == "CNAME" {
				src, e := core.NormalizeDomain(name)
				if e != nil {
					src = strings.TrimSuffix(strings.ToLower(name), ".")
				}
				dst, e := core.NormalizeDomain(val)
				if e != nil {
					dst = strings.TrimSuffix(strings.ToLower(val), ".")
				}
				addSet(x.cnames, src, dst)
			}
		}
	case "asn_found":
		raw := text(meta["ip"])
		if ip, e := netip.ParseAddr(raw); e == nil {
			addSet(x.asnNames, ip.String(), strings.ToLower(strings.TrimSpace(text(meta["as_name"]))))
		}
	}
}
func (x *DNSRunIndex) LoadJSONL(paths []string) error {
	for _, p := range paths {
		if e := IterJSONL(p, func(r JSONLRecord) error {
			if r.Err != nil {
				return r.Err
			}
			x.Ingest(r.Event)
			return nil
		}); e != nil {
			return e
		}
	}
	return nil
}

// LoadStore adapts the legacy SQLite read projection without creating a package cycle.
func (x *DNSRunIndex) LoadStore(rows func(func(map[string]any) error) error) error {
	return rows(func(ev map[string]any) error { x.Ingest(ev); return nil })
}
func (x *DNSRunIndex) ExistingValidation(name string) map[string]any {
	n, e := core.NormalizeDomain(name)
	if e != nil {
		return nil
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	v, ok := x.validations[n]
	if !ok {
		return nil
	}
	m := map[string]any{}
	for k, v := range v.metadata {
		m[k] = v
	}
	return m
}
func (x *DNSRunIndex) CleanSubdomains(root string) []string {
	root, e := core.NormalizeDomain(root)
	if e != nil {
		return nil
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := []string{}
	for n, v := range x.validations {
		st := text(v.metadata["dns_state"])
		if n != root && strings.HasSuffix(n, "."+root) && (st == "resolved_clean_parent" || st == "resolved_wildcard_distinct") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
func (x *DNSRunIndex) ConfirmedTargets(root string, primaryOnly bool) map[string]map[string]bool {
	root, e := core.NormalizeDomain(root)
	if e != nil {
		return nil
	}
	out := map[string]map[string]bool{}
	x.mu.RLock()
	defer x.mu.RUnlock()
	for name, v := range x.validations {
		if x.scope.CheckDomain(name).Status != core.InScope || !strings.HasPrefix(text(v.metadata["active_eligibility"]), "eligible") {
			continue
		}
		state := text(v.metadata["dns_state"])
		if state == "" {
			state = "dns_validation"
		}
		out[name] = map[string]bool{"public_dns": true, state: true}
	}
	if primaryOnly {
		if v, ok := out[root]; ok {
			return map[string]map[string]bool{root: v}
		}
		return map[string]map[string]bool{}
	}
	return out
}
func (x *DNSRunIndex) IPsForDomain(domain string) []string {
	n, e := core.NormalizeDomain(domain)
	if e != nil {
		return nil
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	return keys(x.ipsByDomain[n])
}
func (x *DNSRunIndex) IPs() []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make([]string, 0, len(x.ips))
	for ip := range x.ips {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
func (x *DNSRunIndex) DomainsForIP(ip string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return keys(x.domainsByIP[ip])
}
func (x *DNSRunIndex) PTRNamesForIP(ip string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return keys(x.ptrs[ip])
}
func (x *DNSRunIndex) CNAMETargets(domain string) []string {
	n, err := core.NormalizeDomain(domain)
	if err != nil {
		return nil
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	return keys(x.cnames[n])
}
func (x *DNSRunIndex) ASNNamesForIP(ip string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return keys(x.asnNames[ip])
}
func keys(m map[string]bool) []string {
	o := []string{}
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}
