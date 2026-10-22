package core

import (
	"golang.org/x/net/publicsuffix"
	"strings"
)

type SuffixProvenance struct {
	Implementation        string `json:"implementation"`
	Version               string `json:"version"`
	SuffixSource          string `json:"suffix_source"`
	NetworkFetch          string `json:"network_fetch"`
	NetworkUpdateDisabled bool   `json:"network_update_disabled"`
	IncludePrivateDomains bool   `json:"include_private_domains"`
}

// RegisteredApex ignores private suffixes, matching the source's ICANN-only tldextract policy.
func RegisteredApex(hostname string) (string, SuffixProvenance, error) {
	host, e := NormalizeDomain(hostname)
	if e != nil {
		return "", SuffixProvenance{}, e
	}
	current := host
	for {
		suffix, icann := publicsuffix.PublicSuffix(current)
		if icann {
			labels := strings.Split(host, ".")
			suffixLabels := len(strings.Split(suffix, "."))
			apex := host
			if len(labels) > suffixLabels {
				apex = strings.Join(labels[len(labels)-suffixLabels-1:], ".")
			}
			return apex, SuffixProvenance{"golang.org/x/net/publicsuffix", "v0.55.0", "bundled_snapshot", "disabled", true, false}, nil
		}
		_, next, ok := strings.Cut(current, ".")
		if !ok {
			break
		}
		current = next
	}
	return fallbackApex(host), SuffixProvenance{"builtin_degraded_fallback", "builtin-fallback-v1", "limited_common_suffix_table", "disabled", true, false}, nil
}

var commonTwoLabelSuffixes = map[string]bool{
	"ac.uk": true, "co.uk": true, "gov.uk": true, "ltd.uk": true, "me.uk": true, "net.uk": true, "nhs.uk": true, "org.uk": true, "plc.uk": true, "police.uk": true, "sch.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "asn.au": true, "id.au": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "ac.nz": true, "govt.nz": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"co.in": true, "firm.in": true, "net.in": true, "org.in": true, "gen.in": true, "ind.in": true,
	"co.za": true, "net.za": true, "org.za": true, "gov.za": true,
	"com.sg": true, "net.sg": true, "org.sg": true, "gov.sg": true,
	"com.tr": true, "net.tr": true, "org.tr": true, "gov.tr": true,
}

func fallbackApex(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	suffix := strings.Join(labels[len(labels)-2:], ".")
	if commonTwoLabelSuffixes[suffix] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return suffix
}
