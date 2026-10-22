package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"asmtool/internal/core"
)

type WildcardParentResult struct {
	Parent         string              `json:"parent"`
	State          string              `json:"state"`
	Probes         []HostResolution    `json:"probes"`
	WildcardValues map[string][]string `json:"wildcard_values"`
	Reason         string              `json:"reason"`
}
type parentFlight struct {
	done   chan struct{}
	result WildcardParentResult
	err    error
}
type WildcardAnalyzer struct {
	Root                            string
	Client                          *Client
	ProbesPerParent, MaxParentZones int
	Enabled                         bool
	mu                              sync.Mutex
	cache                           map[string]WildcardParentResult
	flights                         map[string]*parentFlight
	allowed                         map[string]bool
}

func NewWildcardAnalyzer(root string, c *Client, probes, budget int, enabled bool, parents []string) (*WildcardAnalyzer, error) {
	r, e := coreNormalize(root)
	if e != nil {
		return nil, e
	}
	if c == nil {
		return nil, fmt.Errorf("DNS client is required")
	}
	if probes < 3 {
		probes = 3
	}
	if budget < 1 {
		budget = 1
	}
	a := &WildcardAnalyzer{Root: r, Client: c, ProbesPerParent: probes, MaxParentZones: budget, Enabled: enabled, cache: map[string]WildcardParentResult{}, flights: map[string]*parentFlight{}, allowed: map[string]bool{}}
	for _, p := range parents {
		if n, e := coreNormalize(p); e == nil {
			a.allowed[n] = true
		}
	}
	return a, nil
}
func coreNormalize(s string) (string, error) { return core.NormalizeDomain(s) }
func (a *WildcardAnalyzer) AllowParent(p string) error {
	n, e := core.NormalizeDomain(p)
	if e != nil {
		return e
	}
	a.mu.Lock()
	a.allowed[n] = true
	if cached, ok := a.cache[n]; ok && cached.State == "untested" {
		delete(a.cache, n)
	}
	a.mu.Unlock()
	return nil
}
func (a *WildcardAnalyzer) AnalyzeParent(ctx context.Context, parent string) (WildcardParentResult, error) {
	if err := ctx.Err(); err != nil {
		return WildcardParentResult{}, err
	}
	p, e := core.NormalizeDomain(parent)
	if e != nil {
		return WildcardParentResult{}, e
	}
	for {
		a.mu.Lock()
		if err := ctx.Err(); err != nil {
			a.mu.Unlock()
			return WildcardParentResult{}, err
		}
		if x, ok := a.cache[p]; ok {
			a.mu.Unlock()
			return x, ctx.Err()
		}
		if f := a.flights[p]; f != nil {
			done := f.done
			a.mu.Unlock()
			select {
			case <-ctx.Done():
				return WildcardParentResult{}, ctx.Err()
			case <-done:
			}
			if err := ctx.Err(); err != nil {
				return WildcardParentResult{}, err
			}
			if f.err != nil {
				return WildcardParentResult{}, f.err
			}
			return f.result, nil
		}
		if !a.Enabled || !a.allowed[p] || a.usedLocked() >= a.MaxParentZones {
			x := WildcardParentResult{Parent: p, State: "untested", Reason: "wildcard disabled, parent not selected, or budget exhausted"}
			a.cache[p] = x
			a.mu.Unlock()
			return x, nil
		}
		f := &parentFlight{done: make(chan struct{})}
		a.flights[p] = f
		a.mu.Unlock()
		x, err := a.probe(ctx, p)
		a.mu.Lock()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		f.result = x
		f.err = err
		if err == nil {
			a.cache[p] = x
		}
		delete(a.flights, p)
		close(f.done)
		a.mu.Unlock()
		if err != nil {
			return x, err
		}
		return x, ctx.Err()
	}
}
func (a *WildcardAnalyzer) usedLocked() int {
	n := len(a.flights)
	for _, r := range a.cache {
		if r.State != "untested" {
			n++
		}
	}
	return n
}
func (a *WildcardAnalyzer) probe(ctx context.Context, p string) (WildcardParentResult, error) {
	x := WildcardParentResult{Parent: p, Probes: []HostResolution{}, WildcardValues: map[string][]string{}}
	sig := map[string]map[string]bool{"A": {}, "AAAA": {}, "CNAME": {}}
	resolved, clean, errors := 0, 0, 0
	for i := 0; i < a.ProbesPerParent; i++ {
		var b [10]byte
		if _, e := rand.Read(b[:]); e != nil {
			return x, e
		}
		name := "asmw-" + hex.EncodeToString(b[:]) + "." + p
		r, e := ResolveHost(ctx, a.Client, name, 8)
		if e != nil {
			if ctx.Err() != nil {
				return x, ctx.Err()
			}
			errors++
			continue
		}
		x.Probes = append(x.Probes, r)
		if r.Resolved {
			resolved++
			for k, vs := range r.Signature() {
				for _, v := range vs {
					sig[k][v] = true
				}
			}
		} else if r.DNSError {
			errors++
		} else {
			clean++
		}
	}
	majority := a.ProbesPerParent/2 + 1
	switch {
	case resolved >= majority:
		x.State = "wildcard"
		x.Reason = fmt.Sprintf("%d/%d random sibling probes resolved", resolved, a.ProbesPerParent)
	case clean == a.ProbesPerParent:
		x.State = "clean"
		x.Reason = "all random sibling probes returned clean negative outcomes"
	default:
		x.State = "inconclusive"
		x.Reason = fmt.Sprintf("mixed/uncertain probes: resolving=%d, clean=%d, errors=%d", resolved, clean, errors)
	}
	for k, set := range sig {
		for v := range set {
			x.WildcardValues[k] = append(x.WildcardValues[k], v)
		}
		sort.Strings(x.WildcardValues[k])
	}
	return x, nil
}
func (a *WildcardAnalyzer) Classify(ctx context.Context, host string, r HostResolution, isRoot bool) (string, *WildcardParentResult, error) {
	result := func(state string, parent *WildcardParentResult) (string, *WildcardParentResult, error) {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		return state, parent, nil
	}
	if !r.Resolved {
		if r.DNSError {
			return result("dns_error", nil)
		}
		return result("not_resolved", nil)
	}
	if isRoot {
		return result("resolved_input_root", nil)
	}
	p := immediateParent(host, a.Root)
	x, e := a.AnalyzeParent(ctx, p)
	if e != nil {
		return "", &x, e
	}
	switch x.State {
	case "untested":
		return result("resolved_parent_untested", &x)
	case "inconclusive":
		return result("resolved_parent_inconclusive", &x)
	case "clean":
		return result("resolved_clean_parent", &x)
	}
	candidate := r.Signature()
	candidateValues, wildcardValues := map[string]bool{}, map[string]bool{}
	for _, values := range candidate {
		for _, v := range values {
			candidateValues[v] = true
		}
	}
	for _, values := range x.WildcardValues {
		for _, v := range values {
			wildcardValues[v] = true
		}
	}
	all, overlap := len(candidateValues) > 0, false
	for v := range candidateValues {
		if wildcardValues[v] {
			overlap = true
		} else {
			all = false
		}
	}
	if overlap && all {
		return result("resolved_wildcard_match", &x)
	}
	if overlap {
		return result("resolved_wildcard_overlap", &x)
	}
	return result("resolved_wildcard_distinct", &x)
}
func ActiveEligibility(state string, r HostResolution, isRoot, override bool) string {
	if len(r.IPs) == 0 {
		return "not_eligible_unresolvable"
	}
	if isRoot && state == "resolved_input_root" {
		return "eligible"
	}
	switch state {
	case "resolved_clean_parent", "resolved_wildcard_distinct":
		return "eligible"
	case "resolved_wildcard_match", "resolved_wildcard_overlap":
		if override {
			return "eligible_override"
		}
		return "ambiguous_excluded"
	case "resolved_parent_untested", "resolved_parent_inconclusive":
		return "uncertain_excluded"
	}
	return "not_eligible"
}
