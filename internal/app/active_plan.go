package app

import (
	"errors"
	"strconv"
	"time"

	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/report"
)

// Typed settings and plans reuse phase-5 scope/DNS contracts independently
// of browser execution. Construction performs no target contact.
type activeSettings struct {
	HTTP                activehttp.Config
	Crawler             crawler.Config
	Ports               []int
	TCPRate, TCPTargets int
	TCPConcurrency      int
	TCPDialTimeout      time.Duration
}

func makeActiveSettings(p Plan) activeSettings {
	c := p.cfg
	return activeSettings{
		HTTP: activehttp.Config{Policy: c.ScopePolicy, Profile: c.Profile, Authorized: c.AuthorizationConfirmed, UserAgent: c.UserAgent,
			PerHostRequests: c.RateLimits.HTTPMaxRequestsPerHost, GlobalConcurrency: c.RateLimits.HTTPMaxConcurrency,
			PerOriginConcurrency: c.RateLimits.HTTPMaxConcurrencyPerOrigin, GlobalRequestsPerSecond: c.RateLimits.GlobalMaxRequestsPerSecond,
			DelaySeconds: c.RateLimits.HTTPDelaySeconds, StopStatuses: append([]int(nil), c.CollectionPolicy.StopOnHTTPStatuses...),
			Timeout:          time.Duration(c.Backends.NativeSubprocessTimeoutSeconds) * time.Second,
			HTTPProbeBackend: c.Backends.HTTPProbeBackend, AllowFallback: p.allowHTTPFallback},
		Crawler: crawler.Config{Policy: c.ScopePolicy, UserAgent: c.UserAgent, ObeyRobots: c.CollectionPolicy.ObeyRobots, FollowMetaNofollow: c.CollectionPolicy.FollowMetaNofollow,
			MaxPagesPerOrigin: c.RateLimits.CrawlerMaxPagesPerOrigin, MaxTotalPages: c.RateLimits.CrawlerMaxTotalPages, MaxDepth: c.RateLimits.CrawlerMaxDepth},
		Ports: append([]int(nil), c.Ports...), TCPRate: c.RateLimits.TCPMaxRate, TCPTargets: c.RateLimits.TCPMaxTargets, TCPConcurrency: c.RateLimits.TCPMaxConcurrency, TCPDialTimeout: time.Duration(c.RateLimits.TCPConnectTimeoutSeconds * float64(time.Second)),
	}
}

type activeTargets struct {
	Web     []web.Target
	URLs    []string
	TCP     network.TCPPlan
	Reports []report.ConfirmedWebTarget
}

// Selection reuses phase-5 affirmative DNS eligibility and shared-host checks.
// It never treats passive InternetDB observations as live confirmation.
func planActiveTargets(p Plan, index *evidence.DNSRunIndex, emit func(core.Event) error) (activeSettings, activeTargets, error) {
	if !p.cfg.DirectTargetInteraction() || !p.cfg.AuthorizationConfirmed {
		return activeSettings{}, activeTargets{}, ErrAuthorizationRequired
	}
	if index == nil || emit == nil {
		return activeSettings{}, activeTargets{}, errors.New("current DNS index and durable event sink are required")
	}
	settings := p.active
	settings.HTTP.Index, settings.HTTP.Emit = index, emit
	settings.Crawler.Emit = emit
	targets, err := web.EligibleTargets(index, p.target, p.cfg.ScopePolicy, p.cfg.CollectionPolicy.WebPrimaryDomainOnly, p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive)
	if err != nil {
		return activeSettings{}, activeTargets{}, err
	}
	planned := activeTargets{Web: targets, URLs: web.PlanURLs(targets, configuredWebURLs(p), p.cfg.ScopePolicy, p.cfg.RateLimits.HTTPMaxRequestsPerHost), Reports: []report.ConfirmedWebTarget{}}
	for _, target := range targets {
		planned.Reports = append(planned.Reports, report.ConfirmedWebTarget{Domain: target.Domain, InputTarget: target.InputTarget, DNSEvidence: append([]string(nil), target.DNSEvidence...)})
	}
	if p.cfg.Profile == "full" && p.cfg.Modules.PortScan {
		planned.TCP, err = network.BuildTCPPlan(index, p.target, p.cfg.ScopePolicy, p.cfg.RateLimits.TCPMaxTargets)
		if err != nil {
			return activeSettings{}, activeTargets{}, err
		}
	}
	return settings, planned, nil
}

// Historical root nonstandard-port candidates; plan selection still enforces
// exact affirmative-DNS hosts, URL scope and per-host request bounds.
func configuredWebURLs(p Plan) []string {
	urls := []string{}
	for _, port := range p.cfg.Ports {
		if port == 80 || port == 443 {
			continue
		}
		scheme := "http"
		if port == 8443 || port == 9443 {
			scheme = "https"
		}
		urls = append(urls, scheme+"://"+p.target+":"+strconv.Itoa(port)+"/")
	}
	return urls
}
