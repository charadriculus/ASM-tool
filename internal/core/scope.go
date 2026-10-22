package core

import (
	"fmt"
	"net/netip"
	"strings"
)

type ScopePolicy struct {
	AllowedDomains  []string `json:"allowed_domains" yaml:"allowed_domains"`
	AllowedCIDRs    []string `json:"allowed_cidrs" yaml:"allowed_cidrs"`
	ExcludedDomains []string `json:"excluded_domains" yaml:"excluded_domains"`
	ExcludedCIDRs   []string `json:"excluded_cidrs" yaml:"excluded_cidrs"`
}
type ScopeChecker struct{ Policy ScopePolicy }

func (p ScopePolicy) Validate() error {
	if len(p.AllowedDomains) == 0 && len(p.AllowedCIDRs) == 0 {
		return fmt.Errorf("at least one allowed domain or CIDR must be configured")
	}
	for _, list := range [][]string{p.AllowedDomains, p.ExcludedDomains} {
		for _, raw := range list {
			if invalidScopeDomain(raw) {
				return fmt.Errorf("invalid scope domain: %q", raw)
			}
			if _, e := NormalizeDomain(raw); e != nil {
				return e
			}
		}
	}
	for _, list := range [][]string{p.AllowedCIDRs, p.ExcludedCIDRs} {
		for _, raw := range list {
			if _, e := NormalizeCIDR(raw); e != nil {
				return fmt.Errorf("invalid scope CIDR: %w", e)
			}
		}
	}
	return nil
}
func invalidScopeDomain(raw string) bool {
	raw = strings.TrimSpace(raw)
	return raw == "" || strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") || strings.Contains(raw, "..")
}
func (s ScopeChecker) CheckDomain(raw string) ScopeDecision {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if invalidScopeDomain(raw) {
		return ScopeDecision{OutOfScope, "invalid domain syntax", raw}
	}
	d, e := NormalizeDomain(raw)
	if e != nil {
		return ScopeDecision{OutOfScope, e.Error(), raw}
	}
	for _, x := range s.Policy.ExcludedDomains {
		if DomainMatches(d, x) {
			return ScopeDecision{Excluded, "matches excluded domain " + x, d}
		}
	}
	for _, x := range s.Policy.AllowedDomains {
		if DomainMatches(d, x) {
			return ScopeDecision{InScope, "matches allowed domain " + x, d}
		}
	}
	for _, x := range []string{"cloudfront", "amazonaws", "azure", "googleusercontent", "cloudflare", "fastly", "akamai"} {
		if strings.Contains(d, x) {
			return ScopeDecision{NeedsManualReview, "shared/cloud/CDN-like domain", d}
		}
	}
	return ScopeDecision{OutOfScope, "domain is not within allowed_domains", d}
}
func (s ScopeChecker) CheckIP(raw string) ScopeDecision {
	ip, e := NormalizeIP(raw)
	if e != nil {
		return ScopeDecision{OutOfScope, e.Error(), strings.TrimSpace(raw)}
	}
	for _, x := range s.Policy.ExcludedCIDRs {
		if IPInCIDR(ip, x) {
			return ScopeDecision{Excluded, "matches excluded CIDR " + x, ip}
		}
	}
	if len(s.Policy.AllowedCIDRs) == 0 {
		return ScopeDecision{NeedsManualReview, "no allowed_cidrs configured for IP", ip}
	}
	for _, x := range s.Policy.AllowedCIDRs {
		if IPInCIDR(ip, x) {
			return ScopeDecision{InScope, "matches allowed CIDR " + x, ip}
		}
	}
	return ScopeDecision{OutOfScope, "IP is not within allowed_cidrs", ip}
}
func (s ScopeChecker) CheckURL(raw string) ScopeDecision {
	u, e := ParseHTTPURL(raw)
	if e != nil {
		return ScopeDecision{OutOfScope, "invalid URL: " + e.Error(), strings.TrimSpace(raw)}
	}
	if _, e := netip.ParseAddr(u.Hostname()); e == nil {
		return s.CheckIP(u.Hostname())
	}
	return s.CheckDomain(u.Hostname())
}
func (s ScopeChecker) CheckTarget(raw string) ScopeDecision {
	if _, e := netip.ParseAddr(strings.TrimSpace(raw)); e == nil {
		return s.CheckIP(raw)
	}
	return s.CheckDomain(raw)
}

// RequireActiveAllowed is the common authorization gate for every future active consumer.
func (s ScopeChecker) RequireActiveAllowed(profile string, authorized bool, target, kind string) (ScopeDecision, error) {
	if (profile != "verify" && profile != "full") || !authorized {
		return ScopeDecision{}, fmt.Errorf("active action requires verify/full and confirmed authorization")
	}
	var d ScopeDecision
	switch kind {
	case "domain":
		d = s.CheckDomain(target)
	case "ip":
		d = s.CheckIP(target)
	case "url":
		d = s.CheckURL(target)
	default:
		return d, fmt.Errorf("unknown target kind: %s", kind)
	}
	if d.Status != InScope {
		return d, fmt.Errorf("refusing active action: %s (%s)", d.Status, d.Reason)
	}
	return d, nil
}
