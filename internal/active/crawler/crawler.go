package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/backends"
	"asmtool/internal/core"
	"asmtool/internal/resource"
)

// Navigator is the typed boundary for a future browser-DOM consumer. Phase 5
// crawls only response HTML and never labels it as rendered DOM.
type Navigator interface {
	Navigate(context.Context, string) (Navigation, error)
}
type Navigation struct {
	URL        string
	DOM        string
	PageLoaded bool
}
type Config struct {
	Policy                                     core.ScopePolicy
	Emit                                       func(core.Event) error
	UserAgent                                  string
	ObeyRobots, FollowMetaNofollow             bool
	MaxPagesPerOrigin, MaxTotalPages, MaxDepth int
}
type Page struct {
	URL           string                `json:"url"`
	FinalURL      string                `json:"final_url,omitempty"`
	Depth         int                   `json:"depth"`
	Status        int                   `json:"status_code"`
	ContentType   string                `json:"content_type,omitempty"`
	RedirectChain []activehttp.Redirect `json:"redirect_chain,omitempty"`
	BodySHA256    string                `json:"body_sha256,omitempty"`
	HTMLSHA256    string                `json:"html_sha256,omitempty"`
	BodyTruncated bool                  `json:"body_truncated"`
	Error         string                `json:"error,omitempty"`
}
type Result struct {
	Origin     string   `json:"origin"`
	Pages      []Page   `json:"pages"`
	Disallowed []string `json:"disallowed"`
	Partial    bool     `json:"partial"`
	Reason     string   `json:"reason,omitempty"`
	BrowserDOM bool     `json:"browser_dom"`
	Limitation string   `json:"limitation"`
}
type item struct {
	url   string
	depth int
}
type crawlPlan struct {
	origin     string
	queue      []item
	seen       map[string]bool
	completed  map[string]bool
	disallowed map[string]bool
	robots     robotsRules
	result     Result
}

// Crawl uses one round-robin queue per exact scheme/host/port origin, with
// robots fetched and admitted through the same pinned, authorized transport.
func Crawl(ctx context.Context, client *activehttp.Client, cfg Config, roots []string) ([]Result, error) {
	if client == nil || cfg.Emit == nil {
		return nil, fmt.Errorf("HTTP client and durable crawler sink required")
	}
	if cfg.MaxPagesPerOrigin < 1 || cfg.MaxTotalPages < 1 || cfg.MaxDepth < 0 {
		return nil, fmt.Errorf("invalid crawler bounds")
	}
	if err := (core.ScopePolicy(cfg.Policy)).Validate(); err != nil {
		return nil, err
	}
	plansByOrigin := map[string]*crawlPlan{}
	var origins []string
	for _, raw := range roots {
		u, err := normalURL(raw)
		if err != nil {
			continue
		}
		if (core.ScopeChecker{Policy: cfg.Policy}).CheckURL(u).Status != core.InScope {
			continue
		}
		org := origin(u)
		p := plansByOrigin[org]
		if p == nil {
			p = &crawlPlan{origin: org, seen: map[string]bool{}, completed: map[string]bool{}, disallowed: map[string]bool{}, result: Result{Origin: org, Pages: []Page{}, Disallowed: []string{}, BrowserDOM: false, Limitation: "browser DOM rendering remains phase 6"}}
			plansByOrigin[org] = p
			origins = append(origins, org)
		}
		if !p.seen[u] {
			p.seen[u] = true
			p.queue = append(p.queue, item{u, 0})
		}
	}
	sort.Strings(origins)
	if cfg.ObeyRobots {
		for _, org := range origins {
			p := plansByOrigin[org]
			robotsURL := org + "/robots.txt"
			r, e := client.Fetch(ctx, robotsURL, activehttp.Options{TLS: activehttp.VerifiedTLS})
			if errors.Is(e, activehttp.ErrEventSink) {
				return finishError(plansByOrigin, origins, e), e
			}
			if ctx.Err() != nil {
				err := ctx.Err()
				return finishError(plansByOrigin, origins, err), err
			}
			if e != nil && !errors.Is(e, activehttp.ErrCollection) {
				return finishError(plansByOrigin, origins, e), e
			}
			if e == nil && r.StatusCode < 400 && r.BodyTruncated {
				p.result.Partial = true
				p.result.Reason = "robots_body_truncated"
				p.queue = nil
			} else if e == nil && r.StatusCode < 400 {
				p.robots = parseRobots(r.Text, cfg.UserAgent)
				if err := emitRobots(cfg.Emit, org, robotsURL, p.robots); err != nil {
					err = crawlerSinkError(err)
					return finishError(plansByOrigin, origins, err), err
				}
			} else {
				p.result.Partial = true
				p.result.Reason = "robots_unavailable"
			}
		}
	}
	total := 0
	active := append([]string{}, origins...)
	for len(active) > 0 && total < cfg.MaxTotalPages {
		if err := ctx.Err(); err != nil {
			return finishError(plansByOrigin, origins, err), err
		}
		next := active[:0]
		for _, org := range active {
			if total >= cfg.MaxTotalPages {
				break
			}
			p := plansByOrigin[org]
			if p == nil {
				continue
			}
			pruneCompleted(p)
			if len(p.queue) == 0 || len(p.result.Pages) >= cfg.MaxPagesPerOrigin {
				continue
			}
			it := p.queue[0]
			p.queue = p.queue[1:]
			if p.completed[it.url] {
				if len(p.queue) > 0 && len(p.result.Pages) < cfg.MaxPagesPerOrigin {
					next = append(next, org)
				}
				continue
			}
			if cfg.ObeyRobots && !p.robots.allowed(it.url) {
				if !p.disallowed[it.url] {
					p.disallowed[it.url] = true
					p.result.Disallowed = append(p.result.Disallowed, it.url)
					if err := emitDisallowed(cfg.Emit, org, it.url); err != nil {
						err = crawlerSinkError(err)
						return finishError(plansByOrigin, origins, err), err
					}
				}
				if len(p.queue) > 0 {
					next = append(next, org)
				}
				continue
			}
			if _, downloadable := resource.DownloadableResourceInfo(it.url, "", ""); downloadable {
				ev, e := resource.NewDownloadEvent(resource.DownloadEventInput{Module: "crawler", SourceTool: "go_net_http", URL: it.url, TargetDomains: []string{hostName(it.url)}, Phase: "crawl", Depth: it.depth})
				if e == nil {
					e = cfg.Emit(ev)
				}
				if e != nil {
					e = crawlerSinkError(e)
					return finishError(plansByOrigin, origins, e), e
				}
				p.completed[it.url] = true
				if len(p.queue) > 0 && len(p.result.Pages) < cfg.MaxPagesPerOrigin {
					next = append(next, org)
				} else if len(p.queue) > 0 {
					p.result.Partial = true
					p.result.Reason = "origin_page_budget"
				}
				continue
			}
			resp, redirectChain, redirectReason, redirectBlockedURL, e := fetchPage(ctx, client, cfg.Policy, org, it.url, cfg.ObeyRobots, p.robots, p.completed)
			p.completed[it.url] = true
			for _, hop := range redirectChain {
				if origin(hop.URL) == org {
					p.completed[hop.URL] = true
				}
			}
			if resp.FinalURL != "" && origin(resp.FinalURL) == org {
				p.completed[resp.FinalURL] = true
			}
			pruneCompleted(p)
			if redirectReason == "redirect_duplicate_terminal" {
				if len(p.queue) > 0 && len(p.result.Pages) < cfg.MaxPagesPerOrigin {
					next = append(next, org)
				} else if len(p.queue) > 0 {
					p.result.Partial = true
					p.result.Reason = "origin_page_budget"
				}
				continue
			}
			total++
			page := Page{URL: it.url, FinalURL: resp.FinalURL, Depth: it.depth, RedirectChain: redirectChain}
			if e != nil {
				if errors.Is(e, activehttp.ErrEventSink) {
					return finishError(plansByOrigin, origins, e), e
				}
				if ctx.Err() != nil {
					err := ctx.Err()
					return finishError(plansByOrigin, origins, err), err
				}
				if !errors.Is(e, activehttp.ErrCollection) {
					return finishError(plansByOrigin, origins, e), e
				}
				page.Error = e.Error()
				p.result.Partial = true
				p.result.Reason = "page_fetch_error"
				p.result.Pages = append(p.result.Pages, page)
				if len(p.queue) > 0 {
					next = append(next, org)
				}
				continue
			}
			if redirectReason != "" {
				p.result.Partial = true
				p.result.Reason = redirectReason
				page.Status = resp.StatusCode
				page.ContentType = resp.ContentType
				if redirectReason == "redirect_robots_disallowed" && redirectBlockedURL != "" && !p.disallowed[redirectBlockedURL] {
					p.disallowed[redirectBlockedURL] = true
					p.result.Disallowed = append(p.result.Disallowed, redirectBlockedURL)
					if err := emitDisallowed(cfg.Emit, org, redirectBlockedURL); err != nil {
						err = crawlerSinkError(err)
						return finishError(plansByOrigin, origins, err), err
					}
				}
				p.result.Pages = append(p.result.Pages, page)
				if len(p.queue) > 0 && len(p.result.Pages) < cfg.MaxPagesPerOrigin {
					next = append(next, org)
				}
				continue
			}
			if _, downloadable := resource.DownloadableResourceInfo(it.url, resp.ContentType, resp.Headers["content-disposition"]); downloadable {
				status := resp.StatusCode
				ev, e := resource.NewDownloadEvent(resource.DownloadEventInput{Module: "crawler", SourceTool: "go_net_http", URL: it.url, TargetDomains: []string{hostName(it.url)}, Phase: "crawl", Depth: it.depth, StatusCode: &status, ContentType: resp.ContentType, ContentDisposition: resp.Headers["content-disposition"], NetworkContacted: true, DetectionReason: "response_headers"})
				if e == nil {
					e = cfg.Emit(ev)
				}
				if e != nil {
					e = crawlerSinkError(e)
					return finishError(plansByOrigin, origins, e), e
				}
				p.result.Pages = append(p.result.Pages, Page{URL: it.url, FinalURL: resp.FinalURL, Depth: it.depth, Status: resp.StatusCode, ContentType: resp.ContentType, RedirectChain: redirectChain, BodyTruncated: resp.BodyTruncated})
				if resp.BodyTruncated {
					p.result.Partial = true
					p.result.Reason = "body_truncated"
				}
				if len(p.queue) > 0 && len(p.result.Pages) < cfg.MaxPagesPerOrigin {
					next = append(next, org)
				} else if len(p.queue) > 0 {
					p.result.Partial = true
					p.result.Reason = "origin_page_budget"
				}
				continue

			}
			page.Status = resp.StatusCode
			page.ContentType = resp.ContentType
			page.BodyTruncated = resp.BodyTruncated
			digest := sha256.Sum256(resp.Body)
			page.BodySHA256 = hex.EncodeToString(digest[:])
			if resp.BodyTruncated {
				p.result.Partial = true
				p.result.Reason = "body_truncated"
			}
			p.result.Pages = append(p.result.Pages, page)
			if ctx.Err() != nil {
				err := ctx.Err()
				return finishError(plansByOrigin, origins, err), err
			}
			if strings.Contains(strings.ToLower(resp.ContentType), "html") {
				decoded, decodeErr := backends.DecodeHTML(resp.Body, resp.ContentType)
				features, parseErr := backends.ParseHTML(decoded)
				if decodeErr != nil {
					parseErr = decodeErr
				}
				if parseErr != nil {
					p.result.Partial = true
					p.result.Reason = "html_parse_error"
				} else {
					htmlDigest := sha256.Sum256([]byte(decoded))
					page.HTMLSHA256 = hex.EncodeToString(htmlDigest[:])
					p.result.Pages[len(p.result.Pages)-1].HTMLSHA256 = page.HTMLSHA256
					if err := emitCrawlerPage(cfg.Emit, p.result.Origin, page, features); err != nil {
						err = crawlerSinkError(err)
						return finishError(plansByOrigin, origins, err), err
					}
					finalURL := page.FinalURL
					if finalURL == "" {
						finalURL = it.url
					}
					if err := emitMetaRobots(cfg.Emit, p.result.Origin, finalURL, features.MetaRobots); err != nil {
						err = crawlerSinkError(err)
						return finishError(plansByOrigin, origins, err), err
					}
					if resp.BodyTruncated {
						p.result.Partial = true
						p.result.Reason = "body_truncated"
					}
					nofollow := containsNofollow(features.MetaRobots)
					if it.depth < cfg.MaxDepth && (!nofollow || cfg.FollowMetaNofollow) {
						for _, href := range features.AnchorHrefs {
							nextURL, ok := resolve(finalURL, href)
							if !ok || p.seen[nextURL] || p.completed[nextURL] || (core.ScopeChecker{Policy: cfg.Policy}).CheckURL(nextURL).Status != core.InScope {
								continue
							}
							if err := emitCrawlURL(cfg.Emit, href, finalURL, org, nextURL, it.depth+1); err != nil {
								err = crawlerSinkError(err)
								return finishError(plansByOrigin, origins, err), err
							}
							p.seen[nextURL] = true
							if origin(nextURL) != org {
								continue
							}
							if cfg.ObeyRobots && !p.robots.allowed(nextURL) {
								p.disallowed[nextURL] = true
								p.result.Disallowed = append(p.result.Disallowed, nextURL)
								// Keep a non-contact queue entry so refusal preserves the
								// origin's round-robin scheduling turn.
								p.queue = append(p.queue, item{nextURL, it.depth + 1})
								if err := emitDisallowed(cfg.Emit, org, nextURL); err != nil {
									err = crawlerSinkError(err)
									return finishError(plansByOrigin, origins, err), err
								}
								continue
							}
							p.queue = append(p.queue, item{nextURL, it.depth + 1})
						}
					}
				}
			}
			if err := ctx.Err(); err != nil {
				return finishError(plansByOrigin, origins, err), err
			}
			if len(p.queue) > 0 && len(p.result.Pages) < cfg.MaxPagesPerOrigin {
				next = append(next, org)
			} else if len(p.queue) > 0 {
				p.result.Partial = true
				p.result.Reason = "origin_page_budget"
			}
		}
		active = next
	}
	if total >= cfg.MaxTotalPages {
		for _, p := range plansByOrigin {
			pruneCompleted(p)
			if len(p.queue) > 0 {
				p.result.Partial = true
				p.result.Reason = "total_page_budget"
			}
		}
	}
	results := finish(plansByOrigin, origins)
	for i := range results {
		if !results[i].Partial {
			continue
		}
		if err := emitResult(cfg.Emit, results[i]); err != nil {
			err = crawlerSinkError(err)
			return finishErrorFrom(results, err), err
		}
	}
	return results, nil
}

const maxPageRedirects = 10

// fetchPage follows redirects only within the crawler's exact scheme/host/port
// origin. Each hop is a separate call through the authorized HTTP client, so
// its DNS admission, request quotas, cancellation and durable HTTP evidence
// apply independently. The page depth belongs to the original navigation.
func fetchPage(ctx context.Context, client *activehttp.Client, policy core.ScopePolicy, org, raw string, obeyRobots bool, robots robotsRules, completed map[string]bool) (activehttp.Response, []activehttp.Redirect, string, string, error) {
	current := raw
	seen := map[string]bool{current: true}
	chain := make([]activehttp.Redirect, 0)
	for redirects := 0; ; redirects++ {
		if err := ctx.Err(); err != nil {
			return activehttp.Response{}, chain, "", "", err
		}
		resp, err := client.Fetch(ctx, current, activehttp.Options{TLS: activehttp.VerifiedTLS, MaxRedirects: 0})
		chain = append(chain, resp.RedirectChain...)
		if err != nil {
			return resp, chain, "", "", err
		}
		if resp.Location == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, chain, "", "", nil
		}
		if resp.RedirectOutOfScope {
			return resp, chain, "redirect_target_rejected", "", nil
		}
		next, ok := resolve(current, resp.Location)
		if !ok || origin(next) != org || (core.ScopeChecker{Policy: policy}).CheckURL(next).Status != core.InScope {
			return resp, chain, "redirect_target_rejected", "", nil
		}
		if obeyRobots && !robots.allowed(next) {
			return resp, chain, "redirect_robots_disallowed", next, nil
		}
		if seen[next] {
			return resp, chain, "redirect_cycle", "", nil
		}
		if completed[next] {
			return resp, chain, "redirect_duplicate_terminal", "", nil
		}
		if redirects >= maxPageRedirects {
			return resp, chain, "redirect_limit", "", nil
		}
		seen[next] = true
		current = next
	}
}

func pruneCompleted(p *crawlPlan) {
	queue := p.queue[:0]
	for _, item := range p.queue {
		if !p.completed[item.url] {
			queue = append(queue, item)
		}
	}
	p.queue = queue
}

func crawlerSinkError(err error) error { return fmt.Errorf("%w: %w", activehttp.ErrEventSink, err) }
func finish(m map[string]*crawlPlan, origins []string) []Result {
	out := make([]Result, 0, len(origins))
	for _, o := range origins {
		out = append(out, m[o].result)
	}
	return out
}
func finishError(m map[string]*crawlPlan, origins []string, err error) []Result {
	return finishErrorFrom(finish(m, origins), err)
}
func finishErrorFrom(results []Result, err error) []Result {
	reason := "fatal_error"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		reason = "cancelled"
	} else if errors.Is(err, activehttp.ErrEventSink) {
		reason = "event_sink_failure"
	}
	for i := range results {
		results[i].Partial = true
		results[i].Reason = reason
	}
	return results
}
func normalURL(raw string) (string, error) { return core.NormalizeURL(raw) }
func origin(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port)
}
func resolve(base, raw string) (string, bool) {
	b, e := url.Parse(base)
	if e != nil {
		return "", false
	}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return "", false
	}
	u = b.ResolveReference(u)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	u.Fragment = ""
	v, e := core.NormalizeURL(u.String())
	return v, e == nil
}
func containsNofollow(rows []map[string]string) bool {
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r["content"]), "nofollow") {
			return true
		}
	}
	return false
}

type robotsRules struct {
	groups   []robotsGroup // all parsed groups, retained for evidence
	selected []robotRule   // rules applied to the configured user agent
	document string
}
type robotsGroup struct {
	agents []string
	rules  []robotRule
}
type robotRule struct {
	path  string
	allow bool
}

func parseRobots(text, agent string) robotsRules {
	var out robotsRules
	var group *robotsGroup
	seenRule := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "user-agent":
			if group == nil || seenRule {
				out.groups = append(out.groups, robotsGroup{})
				group = &out.groups[len(out.groups)-1]
				seenRule = false
			}
			group.agents = append(group.agents, strings.ToLower(val))
		case "allow", "disallow":
			if group == nil {
				continue
			}
			if key == "allow" || val != "" {
				group.rules = append(group.rules, robotRule{normalizeRobotPath(val), key == "allow"})
			}
			seenRule = true
		}
	}
	ua := strings.ToLower(strings.SplitN(agent, "/", 2)[0])
	var selected, defaultRules []robotRule
	selectedGroup := false
	for _, g := range out.groups {
		matched := false
		for _, a := range g.agents {
			if a == "*" {
				if defaultRules == nil {
					defaultRules = g.rules
				}
				continue
			}
			if strings.Contains(ua, strings.ToLower(a)) {
				matched = true
				break
			}
		}
		if matched {
			selected = g.rules
			selectedGroup = true
			break
		}
	}
	if !selectedGroup {
		selected = defaultRules
	}
	return robotsRules{groups: out.groups, selected: selected, document: text}
}
func (r robotsRules) allowed(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil {
		return false
	}
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	path = normalizeRobotPath(path)
	if path == "" {
		path = "/"
	}
	for _, rule := range r.selected {
		if rule.path == "*" || rule.path != "" && strings.HasPrefix(path, rule.path) {
			return rule.allow
		}
	}
	return true
}
func normalizeRobotPath(raw string) string {
	path, query, hasQuery := strings.Cut(raw, "?")
	decoded, err := url.PathUnescape(path)
	if err == nil {
		path = (&url.URL{Path: decoded}).EscapedPath()
	}
	if hasQuery {
		return path + "?" + query
	}
	return path
}

func emitRobots(emit func(core.Event) error, org, u string, r robotsRules) error {
	domains := []string{originHost(org)}
	e, err := core.NewEvent(core.RobotsRuleFound, "crawler", "robots.txt", r.document, u, core.InScope)
	if err != nil {
		return err
	}
	e.Metadata = map[string]any{"origin": org, "target_domains": domains}
	e.Confidence = 1.0
	if err = emit(e); err != nil {
		return err
	}
	for _, g := range r.groups {
		for _, x := range g.rules {
			if x.allow || x.path == "" {
				continue
			}
			blocked, ok := resolve(org+"/", x.path)
			if !ok {
				continue
			}
			e, err := core.NewEvent(core.RobotsDisallowedURLFound, "crawler", "robots.txt", x.path, blocked, core.InScope)
			if err != nil {
				return err
			}
			e.Metadata = map[string]any{"visited": false, "origin": org, "target_domains": domains, "robots_url": u, "path": x.path}
			e.Confidence = 0.8
			if err = emit(e); err != nil {
				return err
			}
		}
	}
	return nil
}
func emitDisallowed(emit func(core.Event) error, org, u string) error {
	e, err := core.NewEvent(core.RobotsDisallowedURLFound, "crawler", "robots.txt", u, u, core.InScope)
	if err != nil {
		return err
	}
	e.Metadata = map[string]any{"visited": false, "origin": org, "target_domains": []string{originHost(org)}}
	e.Confidence = 0.8
	return emit(e)
}
func emitCrawlerPage(emit func(core.Event) error, org string, p Page, f backends.HTMLFeatures) error {
	e, err := core.NewEvent(core.CrawlerResult, "crawler", "go_net_http", p.URL, p.URL, core.InScope)
	if err != nil {
		return err
	}
	comments := make([]string, 0, min(len(f.Comments), 20))
	for _, comment := range f.Comments[:min(len(f.Comments), 20)] {
		comments = append(comments, truncateRunes(core.RedactText(comment), 500))
	}
	finalURL := p.FinalURL
	if finalURL == "" {
		finalURL = p.URL
	}
	e.Metadata = map[string]any{"origin": org, "target_domain": originHost(org), "target_domains": []string{originHost(org)}, "requested_url": p.URL, "final_url": finalURL, "redirect_chain": p.RedirectChain, "depth": p.Depth, "status_code": p.Status, "content_type": p.ContentType, "body_sha256": p.BodySHA256, "html_sha256": p.HTMLSHA256, "body_truncated": p.BodyTruncated, "partial": p.BodyTruncated, "title": f.Title, "link_count": len(f.AnchorHrefs), "script_count": len(f.ScriptSrcs), "comments": comments, "browser_dom": false, "page_loaded": true, "category": "allowed_processed", "limitation": "browser DOM rendering remains phase 6"}
	e.Confidence = 0.82
	return emit(e)
}
func truncateRunes(s string, limit int) string {
	r := []rune(s)
	if len(r) > limit {
		r = r[:limit]
	}
	return string(r)
}
func emitMetaRobots(emit func(core.Event) error, org, finalURL string, rows []map[string]string) error {
	for _, row := range rows {
		e, err := core.NewEvent(core.MetaRobotsFound, "crawler", "go_net_html", row, finalURL, core.InScope)
		if err != nil {
			return err
		}
		e.Metadata = map[string]any{"name": row["name"], "content": row["content"], "origin": org, "target_domains": []string{originHost(org)}, "browser_dom": false}
		e.Confidence = 0.8
		if err := emit(e); err != nil {
			return fmt.Errorf("persist crawler meta robots: %w", err)
		}
	}
	return nil
}
func emitCrawlURL(emit func(core.Event) error, rawHref, sourceURL, org, target string, depth int) error {
	e, err := core.NewEvent(core.URLFound, "crawler", "go_net_html", rawHref, target, core.InScope)
	if err != nil {
		return err
	}
	e.Metadata = map[string]any{"source_url": sourceURL, "origin": org, "target_domain": originHost(org), "target_domains": []string{originHost(org)}, "depth": depth, "browser_dom": false}
	e.Confidence = 0.6
	if err := emit(e); err != nil {
		return fmt.Errorf("persist crawler link before enqueue: %w", err)
	}
	return nil
}
func originHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
func emitResult(emit func(core.Event) error, r Result) error {
	e, err := core.NewEvent(core.Limitation, "crawler", "go_net_http", r.Origin, r.Origin, core.InScope)
	if err != nil {
		return err
	}
	e.Metadata = map[string]any{"terminal": true, "pages_processed": len(r.Pages), "pages": r.Pages, "disallowed_urls": r.Disallowed, "partial": r.Partial, "reason": r.Reason, "browser_dom": false, "limitation": r.Limitation}
	e.Confidence = 0
	return emit(e)
}

func hostName(raw string) string {
	u, _ := url.Parse(raw)
	if u == nil {
		return ""
	}
	return u.Hostname()
}
