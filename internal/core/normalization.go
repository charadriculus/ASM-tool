package core

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Transitional UTS46 preserves the common IDNA2003 mappings used by Python.
var domainIDNA = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.CheckHyphens(false), idna.BidiRule(), idna.VerifyDNSLength(true))

func NormalizeDomain(raw string) (string, error) {
	value := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
	if value == "" {
		return "", fmt.Errorf("empty domain")
	}
	value, err := domainIDNA.ToASCII(value)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %w", err)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain character")
			}
		}
	}
	if len(value) > 253 {
		return "", fmt.Errorf("domain too long")
	}
	return value, nil
}
func DomainMatches(domain, base string) bool {
	d, e := NormalizeDomain(domain)
	if e != nil {
		return false
	}
	b, e := NormalizeDomain(base)
	return e == nil && (d == b || strings.HasSuffix(d, "."+b))
}
func NormalizeIP(value string) (string, error) {
	a, e := netip.ParseAddr(strings.TrimSpace(value))
	if e != nil || a.Zone() != "" {
		return "", fmt.Errorf("invalid IP address: %q", value)
	}
	return a.String(), nil
}
func NormalizeCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if p, e := netip.ParsePrefix(value); e == nil {
		return p.Masked().String(), nil
	}
	host, mask, hasMask := strings.Cut(value, "/")
	a, e := netip.ParseAddr(host)
	if e != nil || a.Zone() != "" {
		return "", fmt.Errorf("invalid CIDR: %q", value)
	}
	if !hasMask {
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	m, e := netip.ParseAddr(mask)
	if e != nil || !m.Is4() || !a.Is4() {
		return "", fmt.Errorf("invalid CIDR mask: %q", mask)
	}
	bits := m.As4()
	ones, total := net.IPMask(bits[:]).Size()
	if total == 0 {
		for i := range bits {
			bits[i] = ^bits[i]
		}
		ones, total = net.IPMask(bits[:]).Size()
	}
	if total != 32 {
		return "", fmt.Errorf("noncontiguous CIDR mask")
	}
	return netip.PrefixFrom(a, ones).Masked().String(), nil
}
func IPInCIDR(value, cidr string) bool {
	a, e := netip.ParseAddr(strings.TrimSpace(value))
	if e != nil || a.Zone() != "" {
		return false
	}
	normalized, e := NormalizeCIDR(cidr)
	if e != nil {
		return false
	}
	p, e := netip.ParsePrefix(normalized)
	return e == nil && p.Contains(a)
}

// ParseHTTPURL is also the scope boundary: malformed ports, controls and non-HTTP schemes are rejected.
func ParseHTTPURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if strings.ContainsAny(raw, "\\") || strings.IndexFunc(raw, func(c rune) bool { return unicode.IsControl(c) }) >= 0 {
		return nil, fmt.Errorf("invalid URL character")
	}
	u, e := url.Parse(raw)
	if e != nil {
		return nil, e
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL must use http or https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return nil, fmt.Errorf("invalid URL host syntax")
	}
	if strings.HasPrefix(u.Host, "[") {
		a, e := netip.ParseAddr(host)
		if e != nil || !a.Is6() {
			return nil, fmt.Errorf("bracketed URL host must be IPv6")
		}
	}
	if _, e := NormalizeIP(host); e != nil {
		if _, e = NormalizeDomain(host); e != nil {
			return nil, e
		}
	}
	if strings.Contains(host, "%") {
		return nil, fmt.Errorf("URL IP zones are unsupported")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("empty URL port")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid URL port")
		}
	}
	return u, nil
}
func NormalizeURL(raw string) (string, error) {
	u, e := ParseHTTPURL(raw)
	if e != nil {
		return "", e
	}
	u.User = nil
	u.Host = strings.ToLower(u.Host)
	if !strings.HasPrefix(u.Host, "[") && (u.Scheme == "http" && u.Port() == "80" || u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	if u.Path == "" {
		u.Path = "/"
	}
	// Python sorts pairs, including repeated values; Go's Encode only sorts keys.
	pairs := make([][2]string, 0)
	for _, part := range strings.Split(u.RawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, e = url.QueryUnescape(k)
		if e != nil {
			return "", e
		}
		v, e = url.QueryUnescape(v)
		if e != nil {
			return "", e
		}
		pairs = append(pairs, [2]string{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] == pairs[j][0] {
			return pairs[i][1] < pairs[j][1]
		}
		return pairs[i][0] < pairs[j][0]
	})
	query := make([]string, len(pairs))
	for i, p := range pairs {
		query[i] = url.QueryEscape(p[0]) + "=" + url.QueryEscape(p[1])
	}
	u.RawQuery = strings.Join(query, "&")
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	// Keep the source representation of paths (including literal Unicode/spaces and percent escapes).
	_, rest, _ := strings.Cut(strings.TrimSpace(raw), "://")
	path := "/"
	if start := strings.IndexAny(rest, "/?#"); start >= 0 && rest[start] == '/' {
		path = rest[start:]
		if end := strings.IndexAny(path, "?#"); end >= 0 {
			path = path[:end]
		}
	}
	result := u.Scheme + "://" + u.Host + path
	if u.RawQuery != "" {
		result += "?" + u.RawQuery
	}
	return result, nil
}
