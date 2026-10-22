package passive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"asmtool/internal/core"
)

type Observation struct {
	Hostname  string
	Provider  string
	Family    string
	FirstSeen string
	Raw       any
	Metadata  map[string]any
}
type FetchResult struct {
	Provider, Family, Status, Error, Completeness, TruncationReason string
	Observations                                                    []Observation
	Meta                                                            HTTPMeta
	Truncated                                                       bool
	PagesAttempted, PagesCompleted                                  int
}

var families = map[string]string{"crt.name": "mixed_third_party_index", "crt.sh": "certificate_transparency", "certspotter": "certificate_transparency", "thc": "passive_dns_or_asset_index", "submd": UnknownAggregate, "shodanct": "certificate_transparency", "rapiddns": "public_index", "hackertarget": "public_index", "sitedossier": "public_index"}

func Family(provider string) string {
	if v := families[provider]; v != "" {
		return v
	}
	return UnknownAggregate
}

type PlanPolicy struct {
	Profile                                         string
	CRTName, THC, CRTSh, CertSpotter, SubMDFallback bool
}

func ProviderPlan(p PlanPolicy) ([]string, error) {
	if p.Profile == "research" {
		return nil, errors.New("research passive profile is not implemented")
	}
	if p.Profile != "standard" && p.Profile != "deep" {
		return nil, fmt.Errorf("unsupported passive profile %q", p.Profile)
	}
	out := []string{}
	if p.CRTName {
		out = append(out, "crt.name")
	}
	if p.THC {
		out = append(out, "thc")
	}
	if p.CRTSh {
		out = append(out, "crt.sh")
	}
	if p.CertSpotter {
		out = append(out, "certspotter")
	}
	if p.Profile == "deep" {
		for _, name := range []string{"submd", "shodanct", "rapiddns", "hackertarget", "sitedossier"} {
			if !contains(out, name) {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
func ShouldSubMDFallback(enabled, scheduled bool, crtNameEnabled bool, status string, stale bool) (bool, string) {
	if !enabled || scheduled {
		return false, ""
	}
	if !crtNameEnabled {
		return true, "crt.name:disabled"
	}
	if stale {
		return true, "crt.name:stale_cache"
	}
	if status != "ok" {
		return true, "crt.name:" + status
	}
	return false, ""
}
func contains(xs []string, value string) bool {
	for _, x := range xs {
		if x == value {
			return true
		}
	}
	return false
}

func normalizeProviderName(raw, scope string) (string, bool) {
	value := strings.TrimSpace(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "*.")))
	value = strings.TrimSuffix(value, ".")
	host, e := core.NormalizeDomain(value)
	if e != nil || host != scope && !strings.HasSuffix(host, "."+scope) {
		return "", false
	}
	return host, true
}
func decode(raw json.RawMessage, out any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if e := d.Decode(out); e != nil {
		return e
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func CRTName(ctx context.Context, c *Client, apex, scope string, limit int) (FetchResult, error) {
	r := FetchResult{Provider: "crt.name", Family: Family("crt.name")}
	normalizedScope, err := core.NormalizeDomain(scope)
	if err != nil || normalizedScope != scope {
		return r, errors.New("crt.name scope must be normalized")
	}
	registered, psl, err := core.RegisteredApex(scope)
	if err != nil || registered != apex {
		return r, errors.New("crt.name query apex must be the registered apex for the authorized scope")
	}
	body, meta, e := c.GetJSON(ctx, r.Provider, values("apex", apex, "format", "json", "dates", "1"), "crt.name:"+apex, nil)
	r.Meta = meta
	if e != nil {
		return r, e
	}
	var data any
	if e = decode(body, &data); e != nil {
		return r, e
	}
	rows := data
	if obj, ok := data.(map[string]any); ok {
		found := false
		for _, key := range []string{"results", "data", "subdomains", "items"} {
			if list, ok := obj[key].([]any); ok {
				rows = list
				found = true
				break
			}
		}
		if !found {
			list := make([]any, 0, len(obj))
			keys := make([]string, 0, len(obj))
			for name := range obj {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			for _, name := range keys {
				seen := obj[name]
				list = append(list, map[string]any{"subdomain": name, "first_seen": seen})
			}
			rows = list
		}
	}
	list, ok := rows.([]any)
	if !ok {
		r.Status = "partial"
		r.Completeness = "pagination_incomplete"
		r.Error = "malformed crt.name response envelope"
		return r, nil
	}
	best := map[string]Observation{}
	for _, row := range list {
		var rawName, first string
		switch v := row.(type) {
		case string:
			rawName = v
		case map[string]any:
			for _, k := range []string{"subdomain", "hostname", "name", "domain"} {
				if s, ok := v[k].(string); ok && s != "" {
					rawName = s
					break
				}
			}
			for _, k := range []string{"first_seen", "first-seen", "firstSeen", "date"} {
				if firstSeen, truthy := pythonTruthyString(v[k]); truthy {
					first = firstSeen
					break
				}
			}
		}
		host, ok := normalizeProviderName(rawName, scope)
		if !ok {
			continue
		}
		o := Observation{Hostname: host, Provider: r.Provider, Family: r.Family, FirstSeen: first, Raw: row, Metadata: map[string]any{
			"query_apex": apex,
			"provider_query_scope_differs_from_authorized_scope": apex != scope,
			"provider_may_include_active_upstream_collection":    true,
			"psl": map[string]any{"implementation": psl.Implementation, "version": psl.Version, "suffix_source": psl.SuffixSource, "network_fetch": psl.NetworkFetch, "network_update_disabled": psl.NetworkUpdateDisabled},
		}}
		if old, exists := best[host]; !exists || first != "" && (old.FirstSeen == "" || first < old.FirstSeen) {
			best[host] = o
		}
		if limit > 0 && len(best) >= limit {
			r.Truncated = true
			r.TruncationReason = "provider output reached passive inventory safety cap"
			break
		}
	}
	for _, host := range sortedObservationNames(best) {
		r.Observations = append(r.Observations, best[host])
	}
	r.Status = "ok"
	if len(r.Observations) == 0 {
		r.Status = "no_data"
	}
	if r.Truncated {
		r.Status = "partial"
		r.Completeness = "pagination_incomplete"
	}
	return r, nil
}

func CRTSh(ctx context.Context, c *Client, scope string, limit int) (FetchResult, error) {
	r := FetchResult{Provider: "crt.sh", Family: Family("crt.sh")}
	body, meta, e := c.GetJSON(ctx, r.Provider, values("q", "%."+scope, "output", "json"), "crtsh:"+scope, map[int]bool{404: true})
	r.Meta = meta
	if e != nil {
		return r, e
	}
	var rows []any
	if e = decode(body, &rows); e != nil {
		return r, e
	}
	names := map[string]Observation{}
	for _, row := range rows {
		v, ok := row.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"name_value", "common_name"} {
			text, _ := v[key].(string)
			for _, line := range strings.Split(text, "\n") {
				host, ok := normalizeProviderName(line, scope)
				if !ok {
					continue
				}
				names[host] = Observation{Hostname: host, Provider: r.Provider, Family: r.Family, Raw: row, Metadata: map[string]any{}}
				if limit > 0 && len(names) >= limit {
					r.Truncated = true
					r.TruncationReason = "provider output reached passive inventory safety cap"
					break
				}
			}
			if r.Truncated {
				break
			}
		}
		if r.Truncated {
			break
		}
	}
	for _, host := range sortedObservationNames(names) {
		r.Observations = append(r.Observations, names[host])
	}
	r.Status = "ok"
	if len(names) == 0 {
		r.Status = "no_data"
	}
	if r.Truncated {
		r.Status = "partial"
		r.Completeness = "pagination_incomplete"
	}
	return r, nil
}

func CertSpotter(ctx context.Context, c *Client, scope string, limit int) (FetchResult, error) {
	r := FetchResult{Provider: "certspotter", Family: Family("certspotter")}
	names := map[string]Observation{}
	after := ""
	seenCursor := map[string]bool{}
	for {
		params := values("domain", scope, "include_subdomains", "true", "match_wildcards", "true", "expand", "dns_names")
		if after != "" {
			params.Set("after", after)
		}
		key := "certspotter:" + scope + ":cursor:" + after
		body, meta, e := c.GetJSON(ctx, r.Provider, params, key, nil)
		r.Meta = mergeHTTPMeta(r.Meta, meta)
		r.PagesAttempted++
		if e != nil {
			r.Error = e.Error()
			if len(names) == 0 {
				r.Status = meta.ErrorType
				if r.Status == "" {
					r.Status = "failed"
				}
				r.Completeness = certSpotterFailureCompleteness(meta.ErrorType, 0)
				return r, e
			}
			if len(names) > 0 {
				r.Status = "partial"
				r.Completeness = certSpotterFailureCompleteness(meta.ErrorType, len(names))
				r.Observations = sortedObservations(names)
				if ctx.Err() != nil {
					return r, ctx.Err()
				}
				break
			}
			return r, e
		}
		var rows []any
		if e = decode(body, &rows); e != nil {
			r.Status = "partial"
			r.Completeness = "pagination_incomplete"
			r.Error = e.Error()
			break
		}
		if len(rows) == 0 {
			r.PagesCompleted++
			if r.Status == "" {
				if len(names) == 0 {
					r.Completeness = "complete_empty"
				} else {
					r.Completeness = "complete"
				}
			}
			break
		}
		r.PagesCompleted++
		for _, row := range rows {
			obj, ok := row.(map[string]any)
			if !ok {
				r.Status = "partial"
				r.Completeness = "pagination_incomplete"
				r.Error = "CertSpotter page contains malformed row"
				continue
			}
			rawNames, ok := obj["dns_names"].([]any)
			if !ok {
				r.Status = "partial"
				r.Completeness = "pagination_incomplete"
				r.Error = "CertSpotter row lacks dns_names"
				continue
			}
			for _, raw := range rawNames {
				candidate, ok := raw.(string)
				if !ok {
					continue
				}
				host, ok := normalizeProviderName(candidate, scope)
				if ok {
					names[host] = Observation{Hostname: host, Provider: r.Provider, Family: r.Family, Raw: row, Metadata: map[string]any{}}
				}
				if limit > 0 && len(names) >= limit {
					r.Truncated = true
					r.Status = "partial"
					r.Completeness = "pagination_incomplete"
					r.TruncationReason = "provider output reached passive inventory safety cap"
					break
				}
			}
			if r.Truncated {
				break
			}
		}
		if r.Truncated {
			break
		}
		if r.Status == "partial" && r.Error != "" {
			break
		}
		lastID := ""
		if last, ok := rows[len(rows)-1].(map[string]any); ok {
			lastID, _ = pythonTruthyString(last["id"])
		}
		if lastID == "" {
			r.Status = "partial"
			r.Completeness = "pagination_incomplete"
			r.Error = "CertSpotter page has no continuation id"
			break
		}
		if seenCursor[lastID] || lastID == after {
			r.Status = "partial"
			r.Completeness = "pagination_incomplete"
			r.Error = "CertSpotter repeated pagination cursor"
			break
		}
		seenCursor[lastID] = true
		after = lastID
	}
	r.Observations = sortedObservations(names)
	if r.Status == "" {
		r.Status = "ok"
		if len(names) == 0 {
			r.Status = "no_data"
		}
	}
	if r.Completeness == "" {
		if len(names) == 0 {
			r.Completeness = "complete_empty"
		} else {
			r.Completeness = "complete"
		}
	}
	return r, nil
}

func certSpotterFailureCompleteness(kind string, returned int) string {
	switch kind {
	case "timeout":
		if returned > 0 {
			return "partial_timeout"
		}
	case "rate_limited":
		if returned > 0 {
			return "partial_rate_limited"
		}
	case "failed", "unavailable":
		if returned > 0 {
			return "partial_transport_failure"
		}
	}
	return "collector_failed"
}

func mergeHTTPMeta(a, b HTTPMeta) HTTPMeta {
	a.Attempts += b.Attempts
	a.LogicalRequests += b.LogicalRequests
	a.CacheHit = a.CacheHit || b.CacheHit
	a.CacheStale = a.CacheStale || b.CacheStale
	if b.CacheAgeSeconds > a.CacheAgeSeconds {
		a.CacheAgeSeconds = b.CacheAgeSeconds
	}
	if b.StatusCode != 0 {
		a.StatusCode = b.StatusCode
	}
	if b.URL != "" {
		a.URL = b.URL
	}
	if b.ErrorType != "" {
		a.ErrorType = b.ErrorType
	}
	if b.TimeoutPhase != "" {
		a.TimeoutPhase = b.TimeoutPhase
	}
	if b.FallbackAfterError != "" {
		if a.FallbackAfterError != "" {
			a.FallbackAfterError += "; "
		}
		a.FallbackAfterError += b.FallbackAfterError
	}
	return a
}

func pythonTruthyString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, x != ""
	case bool:
		if !x {
			return "", false
		}
		return "True", true
	case json.Number:
		if n, e := x.Float64(); e == nil && n == 0 {
			return "", false
		}
		return string(x), true
	case float64:
		if x == 0 {
			return "", false
		}
		return fmt.Sprint(x), true
	default:
		return fmt.Sprint(v), true
	}
}

func InternetDB(ctx context.Context, c *Client, ip string) (json.RawMessage, HTTPMeta, error) {
	addr, e := netip.ParseAddr(ip)
	if e != nil {
		return nil, HTTPMeta{}, errors.New("InternetDB requires a valid IP address")
	}
	body, meta, e := c.GetJSON(ctx, "internetdb", url.Values{"_ip": {addr.String()}}, "internetdb:"+addr.String(), nil)
	var sourceErr *SourceError
	if errors.As(e, &sourceErr) && sourceErr.StatusCode == 404 {
		return nil, meta, nil
	}
	return body, meta, e
}
func sortedObservationNames(m map[string]Observation) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
func sortedObservations(m map[string]Observation) []Observation {
	names := sortedObservationNames(m)
	out := make([]Observation, 0, len(names))
	for _, name := range names {
		out = append(out, m[name])
	}
	return out
}

var _ = json.Number("")
