package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/backends"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/resource"
)

type Target struct {
	Domain      string   `json:"domain"`
	TerminalIPs []string `json:"terminal_ips"`
	InputTarget bool     `json:"input_target"`
	DNSEvidence []string `json:"dns_evidence"`
}
type Result struct {
	Target            Target
	URL               string
	Status            string
	HTTP              activehttp.Response
	Features          *backends.HTMLFeatures
	DiscoveredDomains []string
	Partial           bool
	Limitation        string
}

// EligibleTargets uses only current affirmative DNS-index entries. The root is
// scheduled first; remaining names are stable lexical order.
func EligibleTargets(index *evidence.DNSRunIndex, root string, policy core.ScopePolicy, primaryOnly bool, includeWildcardAmbiguous ...bool) ([]Target, error) {
	if index == nil {
		return nil, fmt.Errorf("DNS evidence index required")
	}
	normalized, err := core.NormalizeDomain(root)
	if err != nil {
		return nil, err
	}
	confirmed := index.ConfirmedTargets(normalized, primaryOnly)
	out := make([]Target, 0, len(confirmed))
	for name, reasons := range confirmed {
		d := core.ScopeChecker{Policy: policy}.CheckDomain(name)
		if d.Status != core.InScope {
			continue
		}
		meta := index.ExistingValidation(name)
		if meta == nil {
			continue
		}
		eligibility, _ := meta["active_eligibility"].(string)
		allowOverride := len(includeWildcardAmbiguous) > 0 && includeWildcardAmbiguous[0]
		if eligibility != "eligible" && !(allowOverride && eligibility == "eligible_override") {
			continue
		}
		ips := stringList(meta["terminal_ips"])
		if len(ips) == 0 {
			continue
		}
		out = append(out, Target{Domain: name, TerminalIPs: ips, InputTarget: meta["input_target"] == true, DNSEvidence: mapKeys(reasons)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain == normalized {
			return true
		}
		if out[j].Domain == normalized {
			return false
		}
		return out[i].Domain < out[j].Domain
	})
	return out, nil
}
func stringList(v any) []string {
	var out []string
	switch a := v.(type) {
	case []string:
		out = append(out, a...)
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}
func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PlanURLs chooses at most the configured per-host number of known web services;
// when no service observation exists it probes one HTTPS root URL.
func PlanURLs(targets []Target, knownURLs []string, policy core.ScopePolicy, perHost int) []string {
	if perHost < 1 {
		return nil
	}
	scope := core.ScopeChecker{Policy: policy}
	domains := map[string]bool{}
	for _, t := range targets {
		domains[t.Domain] = true
	}
	known := map[string]map[string]bool{}
	for _, raw := range knownURLs {
		normalized, err := core.NormalizeURL(raw)
		if err != nil {
			continue
		}
		u, err := url.Parse(normalized)
		if err != nil || scope.CheckURL(normalized).Status != core.InScope {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if !domains[host] {
			continue
		}
		if known[host] == nil {
			known[host] = map[string]bool{}
		}
		known[host][normalized] = true
	}
	var out []string
	for _, t := range targets {
		urls := mapKeys(known[t.Domain])
		sort.Slice(urls, func(i, j int) bool { return urlRank(urls[i]) < urlRank(urls[j]) })
		if len(urls) == 0 {
			urls = []string{"https://" + t.Domain + "/"}
		}
		if len(urls) > perHost {
			urls = urls[:perHost]
		}
		out = append(out, urls...)
	}
	return out
}
func urlRank(raw string) string {
	u, _ := url.Parse(raw)
	port := u.Port()
	rank := "1"
	if port == "" || port == "80" || port == "443" {
		rank = "0"
	}
	scheme := "1"
	if u.Scheme == "https" {
		scheme = "0"
	}
	return rank + scheme + raw
}

type ProbeConfig struct {
	Policy       core.ScopePolicy
	Emit         func(core.Event) error
	TLS          activehttp.TLSMode
	MaxRedirects int
}

func Probe(ctx context.Context, client *activehttp.Client, cfg ProbeConfig, target Target, rawURL string) (Result, error) {
	if client == nil || cfg.Emit == nil {
		return Result{}, fmt.Errorf("HTTP client and durable web sink required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	normalized, err := core.NormalizeURL(rawURL)
	if err != nil {
		return Result{}, err
	}
	d := (core.ScopeChecker{Policy: cfg.Policy}).CheckURL(normalized)
	if d.Status != core.InScope {
		return Result{}, fmt.Errorf("web target is out of scope: %s", d.Status)
	}
	r := Result{Target: target, URL: normalized}
	response, err := client.Fetch(ctx, normalized, activehttp.Options{TLS: cfg.TLS, MaxRedirects: cfg.MaxRedirects})
	r.HTTP = response
	r.Partial = response.BodyTruncated
	if err != nil {
		r.Status = "http_error"
		r.Partial = true
		if statusErr := emitStatus(cfg.Emit, r); statusErr != nil {
			return r, fmt.Errorf("%w: persist web status: %v", activehttp.ErrEventSink, statusErr)
		}
		return r, err
	}
	r.Status = "loaded"
	if response.RedirectOutOfScope {
		r.Status = "redirect_out_of_scope"
		r.Partial = true
	} else if response.StopStatus {
		r.Status = "blocked_response"
	} else if !strings.Contains(strings.ToLower(response.ContentType), "html") {
		r.Status = "non_html_loaded"
	}
	if r.Status == "loaded" && strings.Contains(strings.ToLower(response.ContentType), "html") {
		features, parseErr := backends.ParseHTML(response.Text)
		if parseErr != nil {
			r.Status = "partial"
			r.Partial = true
		} else {
			r.Features = &features
			if err = emitFeatures(cfg.Emit, cfg.Policy, r, features); err != nil {
				return r, fmt.Errorf("%w: persist web features: %v", activehttp.ErrEventSink, err)
			}
			baseURL := r.HTTP.FinalURL
			if baseURL == "" {
				baseURL = normalized
			}
			r.DiscoveredDomains = discoverDomains(cfg.Policy, baseURL, features)
		}
	}
	if _, downloadable := resource.DownloadableResourceInfo(response.FinalURL, response.ContentType, response.Headers["content-disposition"]); downloadable && !response.RedirectOutOfScope {
		status := response.StatusCode
		event, eventErr := resource.NewDownloadEvent(resource.DownloadEventInput{Module: "web_probe", SourceTool: "go_net_http", URL: response.FinalURL, TargetDomains: []string{target.Domain}, Phase: "root_verification", StatusCode: &status, ContentType: response.ContentType, ContentDisposition: response.Headers["content-disposition"], NetworkContacted: true, DetectionReason: "response_headers"})
		if eventErr == nil {
			eventErr = cfg.Emit(event)
		}
		if eventErr != nil {
			return r, fmt.Errorf("%w: persist downloadable resource: %v", activehttp.ErrEventSink, eventErr)
		}
	}
	if err = emitStatus(cfg.Emit, r); err != nil {
		return r, fmt.Errorf("%w: persist web status: %v", activehttp.ErrEventSink, err)
	}
	return r, nil
}
func discoverDomains(policy core.ScopePolicy, base string, f backends.HTMLFeatures) []string {
	hosts := map[string]bool{}
	baseURL, _ := url.Parse(base)
	for _, raw := range f.AnchorHrefs {
		u, e := url.Parse(raw)
		if e != nil {
			continue
		}
		u = baseURL.ResolveReference(u)
		if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		name, e := core.NormalizeDomain(u.Hostname())
		if e == nil && name != baseURL.Hostname() && (core.ScopeChecker{Policy: policy}).CheckDomain(name).Status == core.InScope {
			hosts[name] = true
		}
	}
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
func emitFeatures(emit func(core.Event) error, policy core.ScopePolicy, r Result, f backends.HTMLFeatures) error {
	normalized, _ := url.Parse(r.HTTP.FinalURL)
	digest := sha256.Sum256(r.HTTP.Body)
	bodyHash := hex.EncodeToString(digest[:])
	textDigest := sha256.Sum256([]byte(r.HTTP.Text))
	htmlHash := hex.EncodeToString(textDigest[:])
	comments := make([]string, 0, min(len(f.Comments), 20))
	for _, comment := range f.Comments[:min(len(f.Comments), 20)] {
		comments = append(comments, truncateRunes(core.RedactText(comment), 500))
	}
	headers := make(map[string]string, len(r.HTTP.Headers))
	for name, value := range r.HTTP.Headers {
		headers[name] = core.RedactText(value)
	}
	events := []struct {
		kind      core.EventType
		raw, norm any
		status    core.ScopeStatus
		meta      map[string]any
	}{{core.HTMLAnalyzed, r.HTTP.RequestedURL, r.HTTP.FinalURL, core.InScope, map[string]any{"title": f.Title, "anchor_count": len(f.AnchorHrefs), "links_count": len(f.AnchorHrefs), "script_count": len(f.ScriptSrcs), "scripts_count": len(f.ScriptSrcs), "form_count": len(f.Forms), "canonical_url": f.CanonicalURL, "extracted_text": f.ExtractedText, "comments": comments, "status_code": r.HTTP.StatusCode, "content_type": r.HTTP.ContentType, "content_length": r.HTTP.ContentLength, "headers": headers, "html_sha256": htmlHash, "body_sha256": bodyHash, "body_truncated": r.HTTP.BodyTruncated, "partial": r.Partial, "origin": origin(r.HTTP.FinalURL), "target_domain": r.Target.Domain, "target_domains": []string{r.Target.Domain}, "requested_url": r.HTTP.RequestedURL, "final_url": r.HTTP.FinalURL, "depth": 0, "screenshot_saved": false, "observation_type": "active_low_noise_validation", "browser_dom": false, "limitation": "response HTML only; browser DOM rendering remains phase 6"}}}
	for _, meta := range f.MetaRobots {
		events = append(events, struct {
			kind      core.EventType
			raw, norm any
			status    core.ScopeStatus
			meta      map[string]any
		}{core.MetaRobotsFound, meta, r.HTTP.FinalURL, core.InScope, map[string]any{"name": meta["name"], "content": meta["content"], "origin": origin(r.HTTP.FinalURL), "target_domain": r.Target.Domain, "target_domains": []string{r.Target.Domain}, "browser_dom": false}})
	}
	for _, href := range f.AnchorHrefs {
		resolved, ok := resolve(normalized, href)
		if !ok {
			continue
		}
		dec := (core.ScopeChecker{Policy: policy}).CheckURL(resolved)
		events = append(events, struct {
			kind      core.EventType
			raw, norm any
			status    core.ScopeStatus
			meta      map[string]any
		}{core.URLFound, href, resolved, dec.Status, map[string]any{"source_url": r.HTTP.FinalURL, "origin": origin(r.HTTP.FinalURL), "target_domain": r.Target.Domain, "target_domains": []string{r.Target.Domain}, "scope_reason": dec.Reason, "depth": 1, "browser_dom": false}})
	}
	for _, raw := range backends.DynamicCandidates(f) {
		resolved, ok := resolve(normalized, raw)
		if !ok {
			continue
		}
		dec := (core.ScopeChecker{Policy: policy}).CheckURL(resolved)
		events = append(events, struct {
			kind      core.EventType
			raw, norm any
			status    core.ScopeStatus
			meta      map[string]any
		}{core.JSEndpointFound, raw, resolved, dec.Status, map[string]any{"source_url": r.HTTP.FinalURL, "origin": origin(r.HTTP.FinalURL), "target_domain": r.Target.Domain, "target_domains": []string{r.Target.Domain}, "scope_reason": dec.Reason}})
	}
	for _, x := range events {
		e, err := core.NewEvent(x.kind, "web_probe", "go_net_html", x.raw, x.norm, x.status)
		if err != nil {
			return err
		}
		e.Metadata = x.meta
		switch x.kind {
		case core.HTMLAnalyzed:
			e.Confidence = 0.9
		case core.MetaRobotsFound:
			e.Confidence = 0.8
		case core.URLFound:
			e.Confidence = 0.6
		case core.JSEndpointFound:
			e.Confidence = 0.35
		}
		if err = emit(e); err != nil {
			return err
		}
	}
	return nil
}
func truncateRunes(s string, limit int) string {
	r := []rune(s)
	if len(r) > limit {
		r = r[:limit]
	}
	return string(r)
}
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
func resolve(base *url.URL, raw string) (string, bool) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return "", false
	}
	u = base.ResolveReference(u)
	if u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	u.Fragment = ""
	v, e := core.NormalizeURL(u.String())
	return v, e == nil
}
func emitStatus(emit func(core.Event) error, r Result) error {
	e, err := core.NewEvent(core.WebTargetStatus, "web_probe", "go_net_http", r.Target.Domain, r.Target.Domain, core.InScope)
	if err != nil {
		return err
	}
	var statusCode any
	if r.HTTP.StatusCode != 0 {
		statusCode = r.HTTP.StatusCode
	}
	e.Metadata = map[string]any{"stage": "root_verification", "terminal": true, "status": r.Status, "requested_url": r.URL, "final_url": r.HTTP.FinalURL, "status_code": statusCode, "page_loaded": r.Status == "loaded" || r.Status == "blocked_response", "partial": r.Partial, "body_truncated": r.HTTP.BodyTruncated, "browser_dom": false, "limitation": "browser DOM rendering remains phase 6", "reason": r.HTTP.Error, "dns_evidence": r.Target.DNSEvidence, "input_target": r.Target.InputTarget}
	if r.Status == "loaded" || r.Status == "blocked_response" || r.Status == "non_html_loaded" {
		e.Confidence = 0.9
	} else {
		e.Confidence = 0.45
	}
	return emit(e)
}
