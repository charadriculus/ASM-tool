package app

import (
	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/report"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

type streamingActiveResult struct {
	targets              []report.ConfirmedWebTarget
	probedURLs           map[string]bool
	crawledURLs          map[string]bool
	crawlerPages         int
	crawlerPagesByOrigin map[string]int
	batches              int
	dynamicRounds        int
	dynamicAdded         int
	dynamicDeferred      int
	attempted            bool
	contacted            bool
	incomplete           bool
	httpStatus           string
	crawlerStatus        string
}

// runStreamingActiveTargets consumes the bounded DNS producer channel on the
// active execution goroutine. Serial crawler calls keep the configured global
// page budget meaningful; the shared HTTP client carries request/rate limits
// across all batches and dynamic rounds.
func runStreamingActiveTargets(
	ctx context.Context,
	p Plan,
	client *activehttp.Client,
	sink *durableSink,
	announce func(string) error,
	ops activeOps,
	browserStatus, screenshotStatus, browserReason string,
) (streamingActiveResult, error) {
	r := streamingActiveResult{
		targets: []report.ConfirmedWebTarget{}, probedURLs: map[string]bool{}, crawledURLs: map[string]bool{}, crawlerPagesByOrigin: map[string]int{},
		httpStatus: "not_requested", crawlerStatus: "not_requested",
	}
	if ctx == nil || sink == nil || announce == nil {
		return r, errors.New("streaming active execution requires context, durable sink, and stage announcer")
	}
	if (p.cfg.Modules.WebProbe || p.cfg.Modules.Crawler) && client == nil {
		return r, errors.New("streaming HTTP client is required for requested active modules")
	}
	if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML && (p.cfg.Modules.WebProbe || p.cfg.Modules.Crawler) && ops.admitDomains == nil {
		return r, errors.New("dynamic HTML discovery requires bounded DNS admission")
	}

	seenDomains, seenURLs := map[string]bool{}, map[string]bool{}
	knownURLs := configuredWebURLs(p)
	candidateLimit := dynamicCandidateLimit(p.cfg.CollectionPolicy, p.cfg.CollectionPolicy.DNSCandidateBudget)
	candidates := boundedDomains{seen: map[string]bool{}, limit: candidateLimit}
	allTargets := []web.Target{}
	webStarted, crawlerStarted := false, false
	if p.cfg.Modules.WebProbe {
		r.httpStatus = "complete"
	}
	if p.cfg.Modules.Crawler {
		r.crawlerStatus = "complete"
	}

	processBatch := func(batchTargets []web.Target, batchURLs []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.cfg.Modules.WebProbe {
			if !webStarted {
				if err := announce("active_http"); err != nil {
					return err
				}
				webStarted = true
			}
			for _, target := range batchTargets {
				for _, rawURL := range batchURLs {
					if hostFromURL(rawURL) != strings.ToLower(target.Domain) || r.probedURLs[rawURL] {
						continue
					}
					r.probedURLs[rawURL] = true
					markStreamingAttempt(&r)
					result, probeErr := ops.probe(ctx, client, web.ProbeConfig{Policy: p.cfg.ScopePolicy, Emit: func(ev core.Event) error { return sink.emit(ctx, ev) }, TLS: activehttp.VerifiedTLS, MaxRedirects: 10}, target, rawURL)
					if probeErr != nil {
						if isActiveFatal(probeErr, ctx) || !errors.Is(probeErr, activehttp.ErrCollection) {
							return probeErr
						}
						r.incomplete, r.httpStatus = true, "partial"
						if err := emitLimitation(ctx, sink, "web_probe", "partial", "warning", "http_collection_error", 1, []string{target.Domain}); err != nil {
							return err
						}
					}
					if result.HTTP.StatusCode != 0 || result.HTTP.IP != "" {
						r.contacted = true
					}
					if result.Partial || result.Status == "http_error" || result.Status == "redirect_out_of_scope" || result.Status == "partial" {
						r.incomplete, r.httpStatus = true, "partial"
					}
					if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
						candidates.add(result.DiscoveredDomains)
					}
				}
			}
		} else {
			for _, target := range batchTargets {
				if err := emitTargetStage(ctx, sink, target, "root_verification", "not_requested", "not_requested", "web_probe_disabled_by_policy", false); err != nil {
					return err
				}
			}
		}

		if p.cfg.Modules.Crawler {
			crawlRoots := make([]string, 0, len(batchURLs))
			for _, rawURL := range batchURLs {
				if !r.crawledURLs[rawURL] {
					r.crawledURLs[rawURL] = true
					crawlRoots = append(crawlRoots, rawURL)
				}
			}
			if len(crawlRoots) > 0 {
				if !crawlerStarted {
					if err := announce("active_crawler"); err != nil {
						return err
					}
					crawlerStarted = true
				}
				remaining := p.cfg.RateLimits.CrawlerMaxTotalPages - r.crawlerPages
				if remaining <= 0 {
					r.incomplete, r.crawlerStatus = true, "partial"
					if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_total_page_limit", 0, domainsOf(batchTargets)); err != nil {
						return err
					}
				} else {
					crawlSettings := p.active.Crawler
					crawlSettings.MaxTotalPages = remaining
					crawlSettings.Emit = func(ev core.Event) error {
						if err := sink.emit(ctx, ev); err != nil {
							return err
						}
						if ev.EventType == core.URLFound && p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
							if raw, ok := ev.NormalizedValue.(string); ok {
								if host := hostFromURL(raw); host != "" && (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(host).Status == core.InScope && core.DomainMatches(host, p.target) {
									candidates.add([]string{host})
								}
							}
						}
						return nil
					}
					groups := map[string][]string{}
					for _, root := range crawlRoots {
						key := crawlOrigin(root)
						groups[key] = append(groups[key], root)
					}
					origins := make([]string, 0, len(groups))
					for key := range groups {
						origins = append(origins, key)
					}
					sort.Strings(origins)
					for _, origin := range origins {
						if r.crawlerPages >= p.cfg.RateLimits.CrawlerMaxTotalPages {
							r.incomplete, r.crawlerStatus = true, "partial"
							if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_total_page_limit", 0, domainsOf(batchTargets)); err != nil {
								return err
							}
							break
						}
						perOriginRemaining := p.cfg.RateLimits.CrawlerMaxPagesPerOrigin - r.crawlerPagesByOrigin[origin]
						if perOriginRemaining <= 0 {
							r.incomplete, r.crawlerStatus = true, "partial"
							if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_origin_page_limit", 0, domainsOf(batchTargets)); err != nil {
								return err
							}
							continue
						}
						crawlSettings.MaxPagesPerOrigin = perOriginRemaining
						crawlSettings.MaxTotalPages = p.cfg.RateLimits.CrawlerMaxTotalPages - r.crawlerPages
						markStreamingAttempt(&r)
						results, crawlErr := ops.crawl(ctx, client, crawlSettings, groups[origin])
						if crawlErr != nil {
							if isActiveFatal(crawlErr, ctx) || !errors.Is(crawlErr, activehttp.ErrCollection) {
								return crawlErr
							}
							r.incomplete, r.crawlerStatus = true, "partial"
							if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_collection_error", 1, nil); err != nil {
								return err
							}
						}
						for _, result := range results {
							accumulateCrawlerPageCounts(r.crawlerPagesByOrigin, result)
							r.crawlerPages += len(result.Pages)
							for _, page := range result.Pages {
								if normalized, err := core.NormalizeURL(page.URL); err == nil {
									r.crawledURLs[normalized] = true
								}
								if page.Status != 0 {
									r.contacted = true
								}
							}
							status, reason := "complete", ""
							if result.Partial {
								r.incomplete, r.crawlerStatus, status, reason = true, "partial", "partial", result.Reason
							}
							if err := emitTargetStage(ctx, sink, web.Target{Domain: hostFromOrigin(result.Origin)}, "crawl", status, "", reason, false); err != nil {
								return err
							}
							if result.Partial {
								if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", result.Reason, len(result.Pages), []string{hostFromOrigin(result.Origin)}); err != nil {
									return err
								}
							}
						}
					}
				}
			}
		} else {
			for _, target := range batchTargets {
				if err := emitTargetStage(ctx, sink, target, "crawl", "not_requested", "", "crawler_disabled_by_policy", false); err != nil {
					return err
				}
			}
		}
		return nil
	}

	acceptBatch := func(batch []web.Target) ([]web.Target, []string, error) {
		if len(batch) == 0 {
			return nil, nil, nil
		}
		// Re-derive eligibility from the durable current index. The channel is
		// an optimization seam, never an authorization or DNS evidence source.
		eligible, err := web.EligibleTargets(sink.index, p.target, p.cfg.ScopePolicy, p.cfg.CollectionPolicy.WebPrimaryDomainOnly, p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive)
		if err != nil {
			return nil, nil, err
		}
		byDomain := make(map[string]web.Target, len(eligible))
		for _, target := range eligible {
			domain, normErr := core.NormalizeDomain(target.Domain)
			if normErr == nil {
				byDomain[domain] = target
			}
		}
		accepted := make([]web.Target, 0, len(batch))
		for _, proposed := range batch {
			domain, normErr := core.NormalizeDomain(proposed.Domain)
			if normErr != nil || !core.DomainMatches(domain, p.target) || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(domain).Status != core.InScope {
				return nil, nil, fmt.Errorf("streamed DNS target %q failed scope validation", proposed.Domain)
			}
			canonical, ok := byDomain[domain]
			if !ok {
				return nil, nil, fmt.Errorf("streamed target %q lacks current affirmative DNS eligibility", domain)
			}
			if seenDomains[domain] {
				continue
			}
			seenDomains[domain] = true
			accepted = append(accepted, canonical)
			r.targets = append(r.targets, report.ConfirmedWebTarget{Domain: domain, InputTarget: canonical.InputTarget, DNSEvidence: append([]string(nil), canonical.DNSEvidence...)})
			if err := emitTargetStage(ctx, sink, canonical, "browser", browserStatus, screenshotStatus, browserReason, p.browserMode != "disabled"); err != nil {
				return nil, nil, err
			}
		}
		if len(accepted) == 0 {
			return nil, nil, nil
		}
		r.batches++
		allTargets = append(allTargets, accepted...)
		urls := web.PlanURLs(accepted, knownURLs, p.cfg.ScopePolicy, p.cfg.RateLimits.HTTPMaxRequestsPerHost)
		uniqueURLs := make([]string, 0, len(urls))
		for _, rawURL := range urls {
			if !seenURLs[rawURL] {
				seenURLs[rawURL] = true
				uniqueURLs = append(uniqueURLs, rawURL)
			}
		}
		return accepted, uniqueURLs, nil
	}

	for {
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case batch, ok := <-ops.targetBatches:
			if !ok {
				goto initialDNSComplete
			}
			batchTargets, batchURLs, err := acceptBatch(batch)
			if err != nil {
				return r, err
			}
			if len(batchTargets) > 0 {
				if err := processBatch(batchTargets, batchURLs); err != nil {
					return r, err
				}
			}
		}
	}

initialDNSComplete:
	if r.batches == 0 {
		if p.cfg.Modules.WebProbe {
			r.httpStatus = "no_eligible_targets"
			if err := emitLimitation(ctx, sink, "web_probe", "no_eligible_targets", "info", "no_current_dns_eligible_web_target", 0, nil); err != nil {
				return r, err
			}
		}
		if p.cfg.Modules.Crawler {
			r.crawlerStatus = "no_eligible_targets"
			if err := emitLimitation(ctx, sink, "crawler", "no_eligible_targets", "info", "no_current_dns_eligible_web_target", 0, nil); err != nil {
				return r, err
			}
		}
	}

	maxRounds := 1
	if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
		maxRounds += p.cfg.CollectionPolicy.DynamicDiscoveryMaxRounds
	}
	for round := 0; round < maxRounds && len(candidates.values) > 0; round++ {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		admission, err := ops.admitDomains(ctx, candidates.values)
		if err != nil {
			return r, err
		}
		if candidates.overflow > 0 {
			r.incomplete = true
			if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_candidate_collection_limit", candidates.overflow, nil); err != nil {
				return r, err
			}
		}
		candidates = boundedDomains{seen: map[string]bool{}, limit: candidateLimit}
		if admission.Round > r.dynamicRounds {
			r.dynamicRounds = admission.Round
		}
		r.dynamicAdded += admission.Added
		r.dynamicDeferred += admission.Deferred
		if admission.Deferred > 0 || admission.RoundLimit || admission.BudgetExhausted {
			r.incomplete = true
			if p.cfg.Modules.WebProbe {
				r.httpStatus = "partial"
			}
			if p.cfg.Modules.Crawler {
				r.crawlerStatus = "partial"
			}
		}
		batchTargets := make([]web.Target, 0, len(admission.Targets))
		for _, target := range admission.Targets {
			domain, normErr := core.NormalizeDomain(target.Domain)
			if normErr != nil || seenDomains[domain] || !core.DomainMatches(domain, p.target) || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(domain).Status != core.InScope {
				continue
			}
			target.Domain = domain
			seenDomains[domain] = true
			batchTargets = append(batchTargets, target)
			r.targets = append(r.targets, report.ConfirmedWebTarget{Domain: domain, InputTarget: target.InputTarget, DNSEvidence: append([]string(nil), target.DNSEvidence...)})
			allTargets = append(allTargets, target)
			if err := emitTargetStage(ctx, sink, target, "browser", browserStatus, screenshotStatus, browserReason, p.browserMode != "disabled"); err != nil {
				return r, err
			}
		}
		if admission.Added == 0 || len(batchTargets) == 0 {
			break
		}
		urls := web.PlanURLs(batchTargets, nil, p.cfg.ScopePolicy, p.cfg.RateLimits.HTTPMaxRequestsPerHost)
		batchURLs := urls[:0]
		for _, rawURL := range urls {
			if !seenURLs[rawURL] {
				seenURLs[rawURL] = true
				batchURLs = append(batchURLs, rawURL)
			}
		}
		if len(batchURLs) == 0 {
			break
		}
		if err := processBatch(batchTargets, batchURLs); err != nil {
			return r, err
		}
	}
	if candidates.overflow > 0 {
		r.incomplete = true
		if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_candidate_collection_limit", candidates.overflow, nil); err != nil {
			return r, err
		}
	}
	if p.cfg.Modules.WebProbe && r.httpStatus == "complete" && len(allTargets) == 0 {
		r.httpStatus = "no_eligible_targets"
	}
	if p.cfg.Modules.Crawler && r.crawlerStatus == "complete" && len(allTargets) == 0 {
		r.crawlerStatus = "no_eligible_targets"
	}
	return r, nil
}

func markStreamingAttempt(r *streamingActiveResult) { r.attempted = true }

func crawlOrigin(raw string) string {
	normalized, err := core.NormalizeURL(raw)
	if err != nil {
		return ""
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port)
}

func accumulateCrawlerPageCounts(counts map[string]int, result crawler.Result) {
	counts[crawlOrigin(result.Origin)] += len(result.Pages)
}
