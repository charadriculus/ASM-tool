package app

import (
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"context"
	"errors"
	"sort"
)

func followupTCPWebServices(ctx context.Context, p Plan, client *activehttp.Client, sink *durableSink, ops activeOps, services map[string]web.Target, probed map[string]bool, out *activeOutcome) error {
	urls := make([]string, 0, len(services))
	for raw := range services {
		urls = append(urls, raw)
	}
	sort.Strings(urls)
	for _, raw := range urls {
		if err := ctx.Err(); err != nil {
			return err
		}
		if probed[raw] {
			continue
		}
		target := services[raw]
		if (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckURL(raw).Status != core.InScope {
			out.Incomplete = true
			out.Coverage["http"] = "partial"
			if err := emitLimitation(ctx, sink, "web_probe", "partial", "warning", "tcp_service_http_followup_scope_blocked", 1, []string{target.Domain}); err != nil {
				return err
			}
			continue
		}
		if target.Domain == "" || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(target.Domain).Status != core.InScope {
			out.Incomplete = true
			out.Coverage["http"] = "partial"
			if err := emitLimitation(ctx, sink, "web_probe", "partial", "warning", "tcp_service_http_followup_missing_dns_scope", 1, nil); err != nil {
				return err
			}
			continue
		}
		probed[raw] = true
		markActiveAttempt(out)
		result, probeErr := ops.probe(ctx, client, web.ProbeConfig{Policy: p.cfg.ScopePolicy, Emit: func(ev core.Event) error { return sink.emit(ctx, ev) }, TLS: activehttp.VerifiedTLS, MaxRedirects: 10}, target, raw)
		if probeErr != nil {
			if isActiveFatal(probeErr, ctx) {
				return probeErr
			}
			if !errors.Is(probeErr, activehttp.ErrCollection) {
				return probeErr
			}
			out.Incomplete = true
			out.Coverage["http"] = "partial"
			if err := emitLimitation(ctx, sink, "web_probe", "partial", "warning", "tcp_service_http_followup_error", 1, []string{target.Domain}); err != nil {
				return err
			}
		}
		if result.HTTP.StatusCode != 0 || result.HTTP.IP != "" {
			out.Coverage["target_contacted"] = true
		}
		if result.Partial || result.Status == "http_error" || result.Status == "redirect_out_of_scope" || result.Status == "partial" {
			out.Incomplete = true
			out.Coverage["http"] = "partial"
		}
		if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
			late := make([]string, 0, len(result.DiscoveredDomains))
			for _, rawDomain := range result.DiscoveredDomains {
				domain, err := core.NormalizeDomain(rawDomain)
				if err == nil && domain != p.target && core.DomainMatches(domain, p.target) && (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(domain).Status == core.InScope && sink.index.ExistingValidation(domain) == nil {
					late = append(late, domain)
				}
			}
			if len(late) > 0 {
				out.Incomplete = true
				out.Coverage["http"] = "partial"
				if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_discovery_after_tcp", len(late), late); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func followupTCPCrawler(ctx context.Context, p Plan, client *activehttp.Client, sink *durableSink, ops activeOps, services map[string]web.Target, crawled map[string]bool, pages *int, pagesByOrigin map[string]int, out *activeOutcome) error {
	if pagesByOrigin == nil {
		pagesByOrigin = map[string]int{}
	}
	urls := make([]string, 0, len(services))
	for raw := range services {
		normalized, err := core.NormalizeURL(raw)
		if err == nil && !crawled[normalized] {
			urls = append(urls, raw)
		}
	}
	sort.Strings(urls)
	if len(urls) == 0 {
		return nil
	}
	allowed := make([]string, 0, len(urls))
	blocked := []string{}
	for _, raw := range urls {
		target := services[raw]
		if (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckURL(raw).Status != core.InScope || target.Domain == "" || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(target.Domain).Status != core.InScope {
			blocked = append(blocked, target.Domain)
			continue
		}
		allowed = append(allowed, raw)
	}
	if len(blocked) > 0 {
		out.Incomplete = true
		out.Coverage["crawler"] = "partial"
		if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "tcp_service_crawler_scope_blocked", len(blocked), blocked); err != nil {
			return err
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	settings := p.active.Crawler
	// A literal-IP service URL may only inherit a report domain from the
	// affirmative DNS association that admitted that exact TCP service URL.
	// PTR/reverse names are deliberately absent from this mapping.
	domainByIP := map[string]web.Target{}
	ambiguousIP := map[string]bool{}
	for raw, target := range services {
		if target.Domain == "" || len(target.DNSEvidence) == 0 {
			continue
		}
		ip, err := core.NormalizeIP(hostFromURL(raw))
		if err != nil {
			continue
		}
		if previous, exists := domainByIP[ip]; exists && previous.Domain != target.Domain {
			ambiguousIP[ip] = true
			continue
		}
		domainByIP[ip] = target
	}
	lateCandidates := boundedDomains{seen: map[string]bool{}, limit: dynamicCandidateLimit(p.cfg.CollectionPolicy, p.cfg.CollectionPolicy.DNSCandidateBudget)}
	settings.Emit = func(ev core.Event) error {
		// Crawler metadata is copied before changing its attribution so the
		// original event and network URL remain intact.
		if ev.Metadata != nil {
			origin, _ := ev.Metadata["origin"].(string)
			if ip, err := core.NormalizeIP(hostFromOrigin(origin)); err == nil && !ambiguousIP[ip] {
				if target, ok := domainByIP[ip]; ok && (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(target.Domain).Status == core.InScope {
					metadata := make(map[string]any, len(ev.Metadata)+2)
					for key, value := range ev.Metadata {
						metadata[key] = value
					}
					metadata["target_domain"] = target.Domain
					metadata["target_domains"] = []string{target.Domain}
					metadata["source_dns_provenance"] = append([]string(nil), target.DNSEvidence...)
					ev.Metadata = metadata
				}
			}
		}
		if err := sink.emit(ctx, ev); err != nil {
			return err
		}
		if ev.EventType == core.URLFound && p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
			if raw, ok := ev.NormalizedValue.(string); ok {
				if host := hostFromURL(raw); host != "" && (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(host).Status == core.InScope && core.DomainMatches(host, p.target) {
					lateCandidates.add([]string{host})
				}
			}
		}
		return nil
	}
	crawlDomain := func(origin string) string {
		host := hostFromOrigin(origin)
		ip, err := core.NormalizeIP(host)
		if err == nil && !ambiguousIP[ip] {
			if target, ok := domainByIP[ip]; ok && (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(target.Domain).Status == core.InScope {
				return target.Domain
			}
		}
		return host
	}
	groups := map[string][]string{}
	for _, raw := range allowed {
		if normalized, err := core.NormalizeURL(raw); err == nil {
			crawled[normalized] = true
		}
		groups[crawlOrigin(raw)] = append(groups[crawlOrigin(raw)], raw)
	}
	origins := make([]string, 0, len(groups))
	for origin := range groups {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	for _, origin := range origins {
		remainingTotal := p.cfg.RateLimits.CrawlerMaxTotalPages - *pages
		if remainingTotal < 1 {
			out.Incomplete = true
			out.Coverage["crawler"] = "partial"
			return emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_total_page_limit", len(allowed), nil)
		}
		remainingOrigin := p.cfg.RateLimits.CrawlerMaxPagesPerOrigin - pagesByOrigin[origin]
		if remainingOrigin < 1 {
			out.Incomplete = true
			out.Coverage["crawler"] = "partial"
			if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_origin_page_limit", len(groups[origin]), nil); err != nil {
				return err
			}
			continue
		}
		settings.MaxTotalPages = remainingTotal
		settings.MaxPagesPerOrigin = remainingOrigin
		markActiveAttempt(out)
		results, crawlErr := ops.crawl(ctx, client, settings, groups[origin])
		if crawlErr != nil {
			if isActiveFatal(crawlErr, ctx) {
				return crawlErr
			}
			if !errors.Is(crawlErr, activehttp.ErrCollection) {
				return crawlErr
			}
			out.Incomplete = true
			out.Coverage["crawler"] = "partial"
			if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "tcp_service_crawler_error", 1, nil); err != nil {
				return err
			}
		}
		for _, result := range results {
			*pages += len(result.Pages)
			accumulateCrawlerPageCounts(pagesByOrigin, result)
			for _, page := range result.Pages {
				if normalized, err := core.NormalizeURL(page.URL); err == nil {
					crawled[normalized] = true
				}
				if page.Status != 0 {
					out.Coverage["target_contacted"] = true
				}
			}
			status, reason := "complete", ""
			if result.Partial {
				status, reason = "partial", result.Reason
				out.Incomplete = true
				out.Coverage["crawler"] = "partial"
			}
			domain := crawlDomain(result.Origin)
			if err := emitTargetStage(ctx, sink, web.Target{Domain: domain}, "crawl", status, "", reason, false); err != nil {
				return err
			}
			if result.Partial {
				if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", result.Reason, len(result.Pages), []string{domain}); err != nil {
					return err
				}
			}
		}
	}
	if lateCandidates.overflow > 0 {
		out.Incomplete = true
		out.Coverage["crawler"] = "partial"
		if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_candidate_collection_limit", lateCandidates.overflow, nil); err != nil {
			return err
		}
	}
	if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
		late := make([]string, 0, len(lateCandidates.values))
		for _, domain := range lateCandidates.values {
			if domain != p.target && sink.index.ExistingValidation(domain) == nil {
				late = append(late, domain)
			}
		}
		if len(late) > 0 {
			out.Incomplete = true
			out.Coverage["crawler"] = "partial"
			if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_discovery_after_tcp", len(late), late); err != nil {
				return err
			}
		}
	}
	return nil
}
