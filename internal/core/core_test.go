package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizationGolden(t *testing.T) {
	b, e := os.ReadFile("../../testdata/phase1/normalization.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases map[string][]struct {
		Input, Expected string
		Error           bool
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	for name, fn := range map[string]func(string) (string, error){"domain": NormalizeDomain, "ip": NormalizeIP, "cidr": NormalizeCIDR, "url": NormalizeURL} {
		for _, c := range cases[name] {
			t.Run(name+"/"+c.Input, func(t *testing.T) {
				got, e := fn(c.Input)
				if (e != nil) != c.Error || !c.Error && got != c.Expected {
					t.Fatalf("got %q, %v; want %q, error=%v", got, e, c.Expected, c.Error)
				}
			})
		}
	}
}
func TestDomainBoundaries(t *testing.T) {
	for _, v := range []string{strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 126) + "aa", "a b.com", "a\x00.com"} {
		if _, e := NormalizeDomain(v); e == nil {
			t.Errorf("accepted invalid %q", v)
		}
	}
	for _, c := range []struct {
		Domain, Base string
		Matches      bool
	}{{"a.example.com", "example.com", true}, {"evil-example.com", "example.com", false}, {"example.com.evil", "example.com", false}, {"Пример.рф", "xn--e1afmkfd.xn--p1ai", true}} {
		if got := DomainMatches(c.Domain, c.Base); got != c.Matches {
			t.Errorf("match %v: %v", c, got)
		}
	}
}
func TestScopeAndAuthorization(t *testing.T) {
	s := ScopeChecker{ScopePolicy{AllowedDomains: []string{"example.com", "xn--e1afmkfd.xn--p1ai"}, AllowedCIDRs: []string{"192.0.2.7/24", "2001:db8::/32"}, ExcludedDomains: []string{"private.example.com"}, ExcludedCIDRs: []string{"192.0.2.128/25"}}}
	if e := s.Policy.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		Kind, Input string
		Status      ScopeStatus
	}{{"domain", "www.example.com", InScope}, {"domain", "PRIVATE.EXAMPLE.COM", Excluded}, {"domain", "cloudfront.other.test", NeedsManualReview}, {"domain", "example.com.evil", OutOfScope}, {"domain", "example.com.", OutOfScope}, {"domain", "Пример.РФ", InScope}, {"ip", "192.0.2.127", InScope}, {"ip", "192.0.2.128", Excluded}, {"ip", "2001:db8::1", InScope}, {"ip", "::ffff:192.0.2.1", OutOfScope}, {"url", "https://example.com/path", InScope}, {"url", "https://private.example.com/path", Excluded}, {"url", "http://192.0.2.130/", Excluded}, {"url", "ftp://example.com/", OutOfScope}, {"url", "http://example.com:99999/", OutOfScope}} {
		var d ScopeDecision
		switch c.Kind {
		case "domain":
			d = s.CheckDomain(c.Input)
		case "ip":
			d = s.CheckIP(c.Input)
		case "url":
			d = s.CheckURL(c.Input)
		}
		if d.Status != c.Status {
			t.Errorf("%s %q: %+v", c.Kind, c.Input, d)
		}
		for _, profile := range []string{"passive", "verify", "full", "research"} {
			for _, auth := range []bool{false, true} {
				_, e := s.RequireActiveAllowed(profile, auth, c.Input, c.Kind)
				allowed := (profile == "verify" || profile == "full") && auth && c.Status == InScope
				if (e == nil) != allowed {
					t.Errorf("gate %s/%v %v err=%v", profile, auth, c, e)
				}
			}
		}
	}
	noIP := ScopeChecker{ScopePolicy{AllowedDomains: []string{"example.com"}}}
	if d := noIP.CheckIP("192.0.2.1"); d.Status != NeedsManualReview {
		t.Fatalf("domain scope widened to IP: %+v", d)
	}
	if _, e := s.RequireActiveAllowed("full", true, "example.com", "unknown"); e == nil {
		t.Fatal("unknown target kind accepted")
	}
}
func TestCIDRMembership(t *testing.T) {
	for _, c := range []struct {
		IP, CIDR string
		Want     bool
	}{{"192.0.2.255", "192.0.2.1/24", true}, {"192.0.3.0", "192.0.2.0/24", false}, {"192.0.2.1", "192.0.2.1", true}, {"::ffff:192.0.2.1", "192.0.2.0/24", false}, {"::ffff:192.0.2.1", "::ffff:192.0.2.0/120", true}} {
		if got := IPInCIDR(c.IP, c.CIDR); got != c.Want {
			t.Errorf("%v got %v", c, got)
		}
	}
}
func TestRegisteredApex(t *testing.T) {
	for _, c := range []struct{ Host, Apex, Implementation string }{{"a.b.example.co.uk", "example.co.uk", "golang.org/x/net/publicsuffix"}, {"a.b.blogspot.com", "blogspot.com", "golang.org/x/net/publicsuffix"}, {"a.city.kawasaki.jp", "city.kawasaki.jp", "golang.org/x/net/publicsuffix"}, {"a.b.ck", "a.b.ck", "golang.org/x/net/publicsuffix"}, {"a.www.ck", "www.ck", "golang.org/x/net/publicsuffix"}, {"foo.github.io", "github.io", "golang.org/x/net/publicsuffix"}, {"a.b.unknowninvalidsuffix", "b.unknowninvalidsuffix", "builtin_degraded_fallback"}, {"localhost", "localhost", "builtin_degraded_fallback"}, {"Пример.рф", "xn--e1afmkfd.xn--p1ai", "golang.org/x/net/publicsuffix"}} {
		got, p, e := RegisteredApex(c.Host)
		if e != nil || got != c.Apex || p.Implementation != c.Implementation || p.NetworkFetch != "disabled" || !p.NetworkUpdateDisabled || p.IncludePrivateDomains {
			t.Errorf("%q -> %q %+v %v", c.Host, got, p, e)
		}
	}
	var suffixes []string
	b, e := os.ReadFile("../../testdata/phase1/source_suffix_fallback.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &suffixes); e != nil {
		t.Fatal(e)
	}
	if len(suffixes) != len(commonTwoLabelSuffixes) {
		t.Fatal("fallback table size differs")
	}
	for _, suffix := range suffixes {
		if fallbackApex("a.example."+suffix) != "example."+suffix {
			t.Errorf("fallback missing %s", suffix)
		}
	}
}
func TestEventDefaults(t *testing.T) {
	e, err := NewEvent(DNSValidation, "dns", "resolver", "raw", "normalized", InScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.EventID) != 36 || e.EventID[14] != '4' || e.Confidence != 0.5 || e.Evidence == nil || e.Metadata == nil || e.Relations == nil {
		t.Fatalf("invalid event defaults: %+v", e)
	}
	for _, stamp := range []string{e.ObservedAt, e.ObservedAtLocal} {
		if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 13 || m["event_type"] != "dns_validation" || m["scope_status"] != "in_scope" {
		t.Fatalf("event contract: %s", b)
	}
}

func TestBracketedURLHosts(t *testing.T) {
	for _, raw := range []string{"http://[example.com]/", "http://[127.0.0.1]/"} {
		if _, e := ParseHTTPURL(raw); e == nil {
			t.Errorf("invalid bracketed host accepted: %s", raw)
		}
	}
}
