package app

import (
	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/browser"
	"asmtool/internal/core"
	"asmtool/internal/platform"
	"asmtool/internal/portable"
	"asmtool/internal/report"
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

type activeOps struct {
	newBrowser   func(context.Context, *platform.Bundle, browser.Options) (browserController, error)
	newHTTP      func(activehttp.Config) (*activehttp.Client, error)
	probe        func(context.Context, *activehttp.Client, web.ProbeConfig, web.Target, string) (web.Result, error)
	crawl        func(context.Context, *activehttp.Client, crawler.Config, []string) ([]crawler.Result, error)
	tcp          func(context.Context, network.TCPPlan, []int, network.TCPConfig) (network.TCPResult, error)
	admitDomains func(context.Context, []string) (dynamicAdmissionResult, error)
	// targetBatches is closed by the DNS/discovery producer only after all
	// indexed validations have been durably persisted. A nil channel preserves
	// the bounded-sequential compatibility path.
	targetBatches <-chan []web.Target
}

func defaultActiveOps() activeOps {
	return activeOps{
		newBrowser: func(ctx context.Context, bundle *platform.Bundle, opts browser.Options) (browserController, error) {
			return browser.Start(ctx, bundle, opts)
		},
		newHTTP: activehttp.NewClient, probe: web.Probe, crawl: crawler.Crawl, tcp: network.ScanTCP,
	}
}

type activeOutcome struct {
	Targets           []report.ConfirmedWebTarget
	Coverage          map[string]any
	BackendProvenance []any
	Incomplete        bool
}

func executeActive(ctx context.Context, p Plan, payload portable.Payload, sink *durableSink, announce func(string) error, ops activeOps) (activeOutcome, error) {
	out := activeOutcome{Targets: []report.ConfirmedWebTarget{}, Coverage: map[string]any{}, BackendProvenance: []any{}}
	if ctx == nil || sink == nil || announce == nil || ops.newHTTP == nil || ops.probe == nil || ops.crawl == nil || ops.tcp == nil {
		return out, errors.New("active execution requires context, durable sink, stage announcer, and complete operations")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	settings, targets, err := planActiveTargets(p, sink.index, func(ev core.Event) error { return sink.emit(ctx, ev) })
	if err != nil {
		return out, err
	}
	if ops.targetBatches != nil {
		// In streaming mode the DNS producer owns initial target delivery. The
		// current index can already contain early validations, so using this
		// snapshot as roots would race with and duplicate the channel batches.
		targets.Web, targets.URLs, targets.Reports = nil, nil, nil
	}
	out.Targets = append(out.Targets, targets.Reports...)

	browserStatus, screenshotStatus, browserReason := "not_requested", "not_requested", ""
	if p.browserMode != "disabled" {
		browserStatus, screenshotStatus = "deferred", "not_requested"
		if p.cfg.Modules.Screenshots {
			screenshotStatus = "deferred"
		}
	}
	out.Coverage["target_contacted"] = false
	out.Coverage["browser_mode"] = p.browserMode
	out.Coverage["browser_required"] = p.browserMode != "disabled"
	out.Coverage["browser_availability"] = "not_requested"
	out.Coverage["screenshots_status"] = screenshotStatus
	out.Coverage["browser_dom"] = false
	out.Coverage["browser_security_status"] = "NOT_QUALIFIED"
	out.Coverage["browser_known_network_risk"] = "candidate31_preconnect_security_failure"
	out.Coverage["browser_request_scope"] = "top_level_navigation_only; subresource egress is not counted by Go HTTP budgets"
	probedURLs := map[string]bool{}
	crawledURLs := map[string]bool{}
	crawlerPages := 0
	crawlerPagesByOrigin := map[string]int{}
	for _, target := range targets.Web {
		if err := emitTargetStage(ctx, sink, target, "browser", browserStatus, screenshotStatus, browserReason, p.browserMode != "disabled"); err != nil {
			return out, err
		}
	}
	if p.browserMode == "disabled" {
		if err := emitLimitation(ctx, sink, "browser", "disabled_by_policy", "info", "browser_disabled_by_policy", 0, nil); err != nil {
			return out, err
		}
	}

	needHTTP := p.cfg.Modules.WebProbe || p.cfg.Modules.Crawler
	var client *activehttp.Client
	if needHTTP {
		if err := announce("active_http"); err != nil {
			return out, err
		}
		settings.HTTP.Index = sink.index
		settings.HTTP.Emit = func(ev core.Event) error { return sink.emit(ctx, ev) }
		client, err = ops.newHTTP(settings.HTTP)
		if err != nil {
			return out, err
		}
		if client == nil {
			return out, errors.New("HTTP client constructor returned nil")
		}
		out.BackendProvenance = append(out.BackendProvenance, client.BackendResolution())
	}

	if ops.targetBatches != nil {
		streamResult, streamErr := runStreamingActiveTargets(ctx, p, client, sink, announce, ops, browserStatus, screenshotStatus, browserReason)
		out.Targets = append(out.Targets, streamResult.targets...)
		out.Incomplete = out.Incomplete || streamResult.incomplete
		probedURLs, crawledURLs, crawlerPages = streamResult.probedURLs, streamResult.crawledURLs, streamResult.crawlerPages
		crawlerPagesByOrigin = streamResult.crawlerPagesByOrigin
		if streamResult.contacted {
			out.Coverage["target_contacted"] = true
		}
		if p.cfg.Modules.WebProbe {
			out.Coverage["http"] = streamResult.httpStatus
		} else {
			out.Coverage["http"] = "not_requested"
		}
		if p.cfg.Modules.Crawler {
			out.Coverage["crawler"] = streamResult.crawlerStatus
		} else {
			out.Coverage["crawler"] = "not_requested"
		}
		out.Coverage["streaming_batches"] = streamResult.batches
		out.Coverage["dynamic_discovery_rounds"] = streamResult.dynamicRounds
		out.Coverage["dynamic_discovery_added"] = streamResult.dynamicAdded
		out.Coverage["dynamic_discovery_deferred"] = streamResult.dynamicDeferred
		if streamResult.attempted {
			markActiveAttempt(&out)
		}
		if streamErr != nil {
			return out, streamErr
		}
	} else {
		if p.cfg.Modules.WebProbe {
			if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML && ops.admitDomains == nil {
				return out, errors.New("dynamic HTML discovery requires bounded DNS admission")
			}
			if len(targets.Web) == 0 {
				out.Coverage["http"] = "no_eligible_targets"
				if err := emitLimitation(ctx, sink, "web_probe", "no_eligible_targets", "info", "no_current_dns_eligible_web_target", 0, nil); err != nil {
					return out, err
				}
				if p.cfg.Modules.Crawler {
					out.Coverage["crawler"] = "no_eligible_targets"
					if err := emitLimitation(ctx, sink, "crawler", "no_eligible_targets", "info", "no_current_dns_eligible_web_target", 0, nil); err != nil {
						return out, err
					}
				}
			} else {
				seenDomains := map[string]bool{}
				seenURLs := map[string]bool{}
				for _, target := range targets.Web {
					seenDomains[target.Domain] = true
				}
				for _, rawURL := range targets.URLs {
					seenURLs[rawURL] = true
				}
				candidateLimit := dynamicCandidateLimit(p.cfg.CollectionPolicy, p.cfg.CollectionPolicy.DNSCandidateBudget)
				candidates := boundedDomains{seen: map[string]bool{}, limit: candidateLimit}
				allTargets := append([]web.Target(nil), targets.Web...)
				batchTargets, batchURLs := append([]web.Target(nil), targets.Web...), append([]string(nil), targets.URLs...)
				httpIncomplete, crawlIncomplete := false, false
				maxRounds := 1
				if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
					maxRounds += p.cfg.CollectionPolicy.DynamicDiscoveryMaxRounds
				}
				for round := 0; round < maxRounds; round++ {
					for _, target := range batchTargets {
						for _, rawURL := range batchURLs {
							if hostFromURL(rawURL) != strings.ToLower(target.Domain) {
								continue
							}
							if err := ctx.Err(); err != nil {
								return out, err
							}
							probedURLs[rawURL] = true
							markActiveAttempt(&out)
							result, probeErr := ops.probe(ctx, client, web.ProbeConfig{Policy: p.cfg.ScopePolicy, Emit: func(ev core.Event) error { return sink.emit(ctx, ev) }, TLS: activehttp.VerifiedTLS, MaxRedirects: 10}, target, rawURL)
							if probeErr != nil {
								if isActiveFatal(probeErr, ctx) {
									return out, probeErr
								}
								if !errors.Is(probeErr, activehttp.ErrCollection) {
									return out, probeErr
								}
								out.Incomplete, httpIncomplete = true, true
								if err := emitLimitation(ctx, sink, "web_probe", "partial", "warning", "http_collection_error", 1, []string{target.Domain}); err != nil {
									return out, err
								}
							}
							if result.HTTP.StatusCode != 0 || result.HTTP.IP != "" {
								out.Coverage["target_contacted"] = true
							}
							if result.Partial || result.Status == "http_error" || result.Status == "redirect_out_of_scope" || result.Status == "partial" {
								out.Incomplete, httpIncomplete = true, true
							}
							if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
								candidates.add(result.DiscoveredDomains)
							}
						}
					}
					if p.cfg.Modules.Crawler {
						if err := announce("active_crawler"); err != nil {
							return out, err
						}
						remaining := p.cfg.RateLimits.CrawlerMaxTotalPages - crawlerPages
						if remaining < 0 {
							remaining = 0
						}
						if remaining == 0 && len(batchURLs) > 0 {
							out.Incomplete, crawlIncomplete = true, true
							if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_total_page_limit", 0, domainsOf(batchTargets)); err != nil {
								return out, err
							}
						} else if len(batchURLs) > 0 {
							crawlSettings := settings.Crawler
							crawlSettings.MaxTotalPages = remaining
							for _, rawURL := range batchURLs {
								crawledURLs[rawURL] = true
							}
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
							markActiveAttempt(&out)
							results, crawlErr := ops.crawl(ctx, client, crawlSettings, batchURLs)
							if crawlErr != nil {
								if isActiveFatal(crawlErr, ctx) {
									return out, crawlErr
								}
								if !errors.Is(crawlErr, activehttp.ErrCollection) {
									return out, crawlErr
								}
								out.Incomplete, crawlIncomplete = true, true
								if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_collection_error", 1, nil); err != nil {
									return out, err
								}
							}
							for _, result := range results {
								accumulateCrawlerPageCounts(crawlerPagesByOrigin, result)
								crawlerPages += len(result.Pages)
								for _, page := range result.Pages {
									if normalized, err := core.NormalizeURL(page.URL); err == nil {
										crawledURLs[normalized] = true
									}
									if page.Status != 0 {
										out.Coverage["target_contacted"] = true
									}
								}
								if result.Partial {
									out.Incomplete, crawlIncomplete = true, true
								}
								status, reason := "complete", ""
								if result.Partial {
									status, reason = "partial", result.Reason
								}
								if err := emitTargetStage(ctx, sink, web.Target{Domain: hostFromOrigin(result.Origin)}, "crawl", status, "", reason, false); err != nil {
									return out, err
								}
								if result.Partial {
									if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", result.Reason, len(result.Pages), []string{hostFromOrigin(result.Origin)}); err != nil {
										return out, err
									}
								}
							}
						}
					}
					if candidates.overflow > 0 {
						out.Incomplete = true
						httpIncomplete = true
						if p.cfg.Modules.Crawler {
							crawlIncomplete = true
						}
						if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_candidate_collection_limit", candidates.overflow, nil); err != nil {
							return out, err
						}
					}
					if !p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML || len(candidates.values) == 0 {
						break
					}
					if err := ctx.Err(); err != nil {
						return out, err
					}
					admission, admitErr := ops.admitDomains(ctx, candidates.values)
					if admitErr != nil {
						if isActiveFatal(admitErr, ctx) {
							return out, admitErr
						}
						return out, admitErr
					}
					candidates = boundedDomains{seen: map[string]bool{}, limit: candidateLimit}
					if admission.Round > intValue(out.Coverage["dynamic_discovery_rounds"]) {
						out.Coverage["dynamic_discovery_rounds"] = admission.Round
					}
					out.Coverage["dynamic_discovery_added"] = intValue(out.Coverage["dynamic_discovery_added"]) + admission.Added
					out.Coverage["dynamic_discovery_deferred"] = intValue(out.Coverage["dynamic_discovery_deferred"]) + admission.Deferred
					if admission.Deferred > 0 || admission.RoundLimit || admission.BudgetExhausted {
						out.Incomplete, httpIncomplete = true, true
						if p.cfg.Modules.Crawler {
							crawlIncomplete = true
						}
					}
					newTargets := make([]web.Target, 0, len(admission.Targets))
					for _, target := range admission.Targets {
						domain, normErr := core.NormalizeDomain(target.Domain)
						if normErr != nil || seenDomains[domain] || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(domain).Status != core.InScope || !core.DomainMatches(domain, p.target) {
							continue
						}
						target.Domain = domain
						seenDomains[domain] = true
						newTargets = append(newTargets, target)
						out.Targets = append(out.Targets, report.ConfirmedWebTarget{Domain: domain, InputTarget: target.InputTarget, DNSEvidence: append([]string(nil), target.DNSEvidence...)})
						if err := emitTargetStage(ctx, sink, target, "browser", browserStatus, screenshotStatus, browserReason, p.browserMode != "disabled"); err != nil {
							return out, err
						}
					}
					if admission.Added == 0 || len(newTargets) == 0 {
						break
					}
					newURLs := web.PlanURLs(newTargets, nil, p.cfg.ScopePolicy, p.cfg.RateLimits.HTTPMaxRequestsPerHost)
					filtered := newURLs[:0]
					for _, raw := range newURLs {
						if !seenURLs[raw] {
							seenURLs[raw] = true
							filtered = append(filtered, raw)
						}
					}
					if len(filtered) == 0 {
						break
					}
					allTargets = append(allTargets, newTargets...)
					batchTargets, batchURLs = newTargets, filtered
				}
				if len(targets.Web) > 0 {
					out.Coverage["http"] = "complete"
					if httpIncomplete {
						out.Coverage["http"] = "partial"
					}
				}
				if p.cfg.Modules.Crawler {
					if len(allTargets) == 0 {
						out.Coverage["crawler"] = "no_eligible_targets"
					} else {
						out.Coverage["crawler"] = "complete"
						if crawlIncomplete {
							out.Coverage["crawler"] = "partial"
						}
					}
				}
			}
		} else {
			for _, target := range targets.Web {
				if err := emitTargetStage(ctx, sink, target, "root_verification", "not_requested", "not_requested", "web_probe_disabled_by_policy", false); err != nil {
					return out, err
				}
			}
			out.Coverage["http"] = "not_requested"
		}

		if !p.cfg.Modules.Crawler {
			for _, target := range targets.Web {
				if err := emitTargetStage(ctx, sink, target, "crawl", "not_requested", "", "crawler_disabled_by_policy", false); err != nil {
					return out, err
				}
			}
			out.Coverage["crawler"] = "not_requested"
		} else if !p.cfg.Modules.WebProbe {
			if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML && ops.admitDomains == nil {
				return out, errors.New("dynamic HTML discovery requires bounded DNS admission")
			}
			if len(targets.URLs) == 0 {
				out.Coverage["crawler"] = "no_eligible_targets"
				if err := emitLimitation(ctx, sink, "crawler", "no_eligible_targets", "info", "no_current_dns_eligible_web_target", 0, nil); err != nil {
					return out, err
				}
			} else {
				seenDomains, seenURLs := map[string]bool{}, map[string]bool{}
				for _, target := range targets.Web {
					seenDomains[target.Domain] = true
				}
				for _, raw := range targets.URLs {
					seenURLs[raw] = true
				}
				batchTargets, batchURLs := append([]web.Target(nil), targets.Web...), append([]string(nil), targets.URLs...)
				candidates := boundedDomains{seen: map[string]bool{}, limit: dynamicCandidateLimit(p.cfg.CollectionPolicy, p.cfg.CollectionPolicy.DNSCandidateBudget)}
				crawlIncomplete := false
				maxRounds := 1
				if p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
					maxRounds += p.cfg.CollectionPolicy.DynamicDiscoveryMaxRounds
				}
				for round := 0; round < maxRounds && len(batchURLs) > 0; round++ {
					if err := announce("active_crawler"); err != nil {
						return out, err
					}
					remaining := p.cfg.RateLimits.CrawlerMaxTotalPages - crawlerPages
					if remaining <= 0 {
						out.Incomplete, crawlIncomplete = true, true
						if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_total_page_limit", 0, domainsOf(batchTargets)); err != nil {
							return out, err
						}
						break
					}
					crawlSettings := settings.Crawler
					crawlSettings.MaxTotalPages = remaining
					for _, rawURL := range batchURLs {
						crawledURLs[rawURL] = true
					}
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
					markActiveAttempt(&out)
					results, crawlErr := ops.crawl(ctx, client, crawlSettings, append([]string(nil), batchURLs...))
					if crawlErr != nil {
						if isActiveFatal(crawlErr, ctx) || !errors.Is(crawlErr, activehttp.ErrCollection) {
							return out, crawlErr
						}
						out.Incomplete, crawlIncomplete = true, true
						if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", "crawler_collection_error", 1, nil); err != nil {
							return out, err
						}
					}
					for _, result := range results {
						accumulateCrawlerPageCounts(crawlerPagesByOrigin, result)
						crawlerPages += len(result.Pages)
						for _, page := range result.Pages {
							if normalized, err := core.NormalizeURL(page.URL); err == nil {
								crawledURLs[normalized] = true
							}
							if page.Status != 0 {
								out.Coverage["target_contacted"] = true
							}
						}
						if result.Partial {
							out.Incomplete, crawlIncomplete = true, true
						}
						status, reason := "complete", ""
						if result.Partial {
							status, reason = "partial", result.Reason
						}
						if err := emitTargetStage(ctx, sink, web.Target{Domain: hostFromOrigin(result.Origin)}, "crawl", status, "", reason, false); err != nil {
							return out, err
						}
						if result.Partial {
							if err := emitLimitation(ctx, sink, "crawler", "partial", "warning", result.Reason, len(result.Pages), []string{hostFromOrigin(result.Origin)}); err != nil {
								return out, err
							}
						}
					}
					if candidates.overflow > 0 {
						out.Incomplete, crawlIncomplete = true, true
						if err := emitLimitation(ctx, sink, "domain_expansion", "partial", "warning", "dynamic_candidate_collection_limit", candidates.overflow, nil); err != nil {
							return out, err
						}
					}
					if len(candidates.values) == 0 {
						break
					}
					admission, admitErr := ops.admitDomains(ctx, candidates.values)
					if admitErr != nil {
						return out, admitErr
					}
					candidates = boundedDomains{seen: map[string]bool{}, limit: dynamicCandidateLimit(p.cfg.CollectionPolicy, p.cfg.CollectionPolicy.DNSCandidateBudget)}
					if admission.Round > intValue(out.Coverage["dynamic_discovery_rounds"]) {
						out.Coverage["dynamic_discovery_rounds"] = admission.Round
					}
					out.Coverage["dynamic_discovery_added"] = intValue(out.Coverage["dynamic_discovery_added"]) + admission.Added
					out.Coverage["dynamic_discovery_deferred"] = intValue(out.Coverage["dynamic_discovery_deferred"]) + admission.Deferred
					if admission.Deferred > 0 || admission.RoundLimit || admission.BudgetExhausted {
						out.Incomplete, crawlIncomplete = true, true
					}
					newTargets := []web.Target{}
					for _, target := range admission.Targets {
						domain, normErr := core.NormalizeDomain(target.Domain)
						if normErr != nil || seenDomains[domain] || (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(domain).Status != core.InScope || !core.DomainMatches(domain, p.target) {
							continue
						}
						target.Domain = domain
						seenDomains[domain] = true
						newTargets = append(newTargets, target)
						out.Targets = append(out.Targets, report.ConfirmedWebTarget{Domain: domain, InputTarget: target.InputTarget, DNSEvidence: append([]string(nil), target.DNSEvidence...)})
						if err := emitTargetStage(ctx, sink, target, "browser", browserStatus, screenshotStatus, browserReason, p.browserMode != "disabled"); err != nil {
							return out, err
						}
						if err := emitTargetStage(ctx, sink, target, "root_verification", "not_requested", "not_requested", "web_probe_disabled_by_policy", false); err != nil {
							return out, err
						}
					}
					if admission.Added == 0 || len(newTargets) == 0 {
						break
					}
					newURLs := web.PlanURLs(newTargets, nil, p.cfg.ScopePolicy, p.cfg.RateLimits.HTTPMaxRequestsPerHost)
					filtered := newURLs[:0]
					for _, raw := range newURLs {
						if !seenURLs[raw] {
							seenURLs[raw] = true
							filtered = append(filtered, raw)
						}
					}
					batchTargets, batchURLs = newTargets, filtered
				}
				out.Coverage["crawler"] = "complete"
				if crawlIncomplete {
					out.Coverage["crawler"] = "partial"
				}
			}
		}

	}

	if p.cfg.Profile == "full" && p.cfg.Modules.PortScan {
		if err := announce("active_tcp"); err != nil {
			return out, err
		}
		out.Coverage["tcp"] = "not_run"
		out.BackendProvenance = append(out.BackendProvenance, map[string]any{"category": "port_scan", "requested": "tcp_connect", "actual": "tcp_connect", "status": "available", "available": true, "execution_mode": "go_net_dialer"})
		targets.TCP, err = buildSafeTCPPlan(ctx, p, sink.index, sink)
		if err != nil {
			return out, err
		}
		if len(targets.TCP.IPs()) == 0 {
			out.Coverage["tcp"] = "no_eligible_targets"
			if err := emitLimitation(ctx, sink, "port_scan", "no_eligible_targets", "info", "no_current_dns_eligible_ip", 0, nil); err != nil {
				return out, err
			}
		} else {
			tcpServices := map[string]web.Target{}
			tcpCtx, cancelTCP := context.WithTimeout(ctx, settings.HTTP.Timeout)
			markActiveAttempt(&out)
			emitted := map[string]bool{}
			scan, scanErr := ops.tcp(tcpCtx, targets.TCP, settings.Ports, network.TCPConfig{
				Profile: p.cfg.Profile, Authorized: p.cfg.AuthorizationConfirmed,
				Concurrency: settings.TCPConcurrency, Rate: settings.TCPRate, DialTimeout: settings.TCPDialTimeout,
				Emit: func(row network.Observation) error {
					key := row.IP + ":" + strconv.Itoa(row.Port)
					if emitted[key] {
						return errors.New("duplicate TCP scan result")
					}
					emitted[key] = true
					persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					contacted, serviceURL, serviceDomain, err := emitTCPRow(persistCtx, sink, p, targets.TCP, settings.Ports, row)
					if err != nil {
						return err
					}
					if contacted {
						out.Coverage["target_contacted"] = true
					}
					if serviceURL != "" && serviceDomain != "" && !probedURLs[serviceURL] {
						sources := []string{}
						for source := range sink.index.ConfirmedTargets(p.target, false)[serviceDomain] {
							sources = append(sources, source)
						}
						sort.Strings(sources)
						tcpServices[serviceURL] = web.Target{Domain: serviceDomain, DNSEvidence: sources}
					}
					return nil
				},
			})
			localTimeout := errors.Is(tcpCtx.Err(), context.DeadlineExceeded)
			cancelTCP()
			out.Coverage["tcp_scan_attempted"] = scan.Attempted > 0
			out.Coverage["tcp_planned"] = scan.Planned
			out.Coverage["tcp_attempted"] = scan.Attempted
			out.Coverage["tcp_denied"] = scan.Denied
			out.Coverage["tcp_unattempted"] = scan.Unattempted
			out.Coverage["tcp"] = "complete"
			if scan.Partial || scanErr != nil || localTimeout {
				out.Incomplete = true
				out.Coverage["tcp"] = "partial"
				if ctx.Err() == nil {
					reason := "tcp_scan_incomplete"
					if localTimeout {
						reason = "tcp_scan_timeout"
					}
					if err := emitLimitation(ctx, sink, "port_scan", "partial", "warning", reason, scan.Unattempted+scan.Denied, nil); err != nil {
						return out, err
					}
				}
			}
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			if scanErr != nil && !errors.Is(scanErr, context.DeadlineExceeded) && !errors.Is(scanErr, context.Canceled) {
				return out, scanErr
			}

			if len(tcpServices) > 0 {
				if p.cfg.Modules.WebProbe {
					if err := announce("active_http"); err != nil {
						return out, err
					}
					if err := followupTCPWebServices(ctx, p, client, sink, ops, tcpServices, probedURLs, &out); err != nil {
						return out, err
					}
				}
				if p.cfg.Modules.Crawler {
					if err := announce("active_crawler"); err != nil {
						return out, err
					}
					if err := followupTCPCrawler(ctx, p, client, sink, ops, tcpServices, crawledURLs, &crawlerPages, crawlerPagesByOrigin, &out); err != nil {
						return out, err
					}
				}
			}
		}
	} else {
		out.Coverage["tcp"] = "not_requested"
	}
	if err := runBrowserStage(ctx, p, payload.Bundle, sink.index, sink, announce, ops, &out); err != nil {
		return out, err
	}
	if out.Incomplete {
		out.Coverage["incomplete"] = true
	}
	if out.Coverage["active_operations_attempted"] == true && out.Coverage["target_contacted"] == false {
		out.Coverage["target_contacted"] = "unknown"
	}
	return out, nil
}
