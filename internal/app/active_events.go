package app

import (
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/network"
	"asmtool/internal/active/web"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var tcpWebPorts = map[int]struct{}{80: {}, 443: {}, 3000: {}, 5000: {}, 8000: {}, 8080: {}, 8443: {}, 8888: {}, 9443: {}}
var tcpHTTPSPorts = map[int]struct{}{443: {}, 8443: {}, 9443: {}}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

func hostFromOrigin(raw string) string { return hostFromURL(raw) }

func isActiveFatal(err error, ctx context.Context) bool {
	return ctx.Err() != nil || errors.Is(err, activehttp.ErrEventSink)
}

func markActiveAttempt(out *activeOutcome) {
	if out != nil {
		out.Coverage["active_operations_attempted"] = true
	}
}

func emitTargetStage(ctx context.Context, sink *durableSink, target web.Target, stage, status, screenshot, reason string, browserRequired bool) error {
	contacted := stage == "browser" && (status == "loaded" || status == "download_detected")
	return emitTargetStageContact(ctx, sink, target, stage, status, screenshot, reason, browserRequired, contacted)
}

func emitTargetStageContact(ctx context.Context, sink *durableSink, target web.Target, stage, status, screenshot, reason string, browserRequired, contacted bool) error {
	if target.Domain == "" {
		return errors.New("active target status requires a domain")
	}
	tool := "go_net_http"
	if stage == "browser" {
		tool = "direct_cdp"
	}
	ev, err := core.NewEvent(core.WebTargetStatus, "web_probe", tool, target.Domain, target.Domain, core.InScope)
	if err != nil {
		return err
	}
	meta := map[string]any{"stage": stage, "status": status, "terminal": status != "deferred", "page_loaded": stage == "browser" && status == "loaded"}
	if stage == "browser" || status == "not_requested" || status == "no_eligible_targets" {
		meta["target_service_contacted"] = stage == "browser" && contacted
	}
	if screenshot != "" {
		meta["screenshot_status"] = screenshot
	}
	if reason != "" {
		meta["reason"] = reason
	}
	if stage == "browser" {
		meta["browser_required"] = browserRequired
	}
	return sink.emit(ctx, evWithMetadata(ev, meta))
}

func evWithMetadata(ev core.Event, m map[string]any) core.Event {
	ev.Metadata = m
	ev.Confidence = 0
	return ev
}

func emitLimitation(ctx context.Context, sink *durableSink, module, status, severity, reason string, count int, targets []string) error {
	ev, err := core.NewEvent(core.Limitation, module, "go_runtime", reason, reason, core.InScope)
	if err != nil {
		return err
	}
	bounded := append([]string(nil), targets...)
	if len(bounded) > 100 {
		bounded = bounded[:100]
	}
	ev.Confidence = 0
	ev.Metadata = map[string]any{"terminal": true, "status": status, "severity": severity, "reason": reason, "count": count, "affected_targets": bounded}
	return sink.emit(ctx, ev)
}

type boundedDomains struct {
	seen            map[string]bool
	values          []string
	limit, overflow int
}

func (b *boundedDomains) add(names []string) {
	if b == nil || b.limit < 1 {
		return
	}
	for _, raw := range names {
		name, err := core.NormalizeDomain(raw)
		if err != nil || b.seen[name] {
			continue
		}
		if len(b.values) >= b.limit {
			b.overflow++
			continue
		}
		b.seen[name] = true
		b.values = append(b.values, name)
	}
}

func dynamicCandidateLimit(policy config.CollectionPolicy, dnsBudget int) int {
	limit := policy.DynamicDiscoveryMaxNewDomains + 1
	if dnsBudget > 0 && limit > dnsBudget+1 {
		limit = dnsBudget + 1
	}
	if limit < 1 {
		return 1
	}
	if limit > 1001 {
		return 1001
	}
	return limit
}

func intValue(value any) int { n, _ := value.(int); return n }

func domainsOf(targets []web.Target) []string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, target.Domain)
	}
	return values
}

// Every completed connect decision is durable; open alone is not a verified web service.
func emitTCPRow(ctx context.Context, sink *durableSink, p Plan, plan network.TCPPlan, requestedPorts []int, row network.Observation) (bool, string, string, error) {
	ip, err := core.NormalizeIP(row.IP)
	if err != nil || !containsScanIP(plan.IPs(), ip) || row.Protocol != "tcp" || !containsInt(requestedPorts, row.Port) {
		return false, "", "", errors.New("TCP result outside admitted plan")
	}
	if row.State != "open" && row.State != "closed" && row.State != "unknown" {
		return false, "", "", errors.New("invalid TCP result state")
	}
	plannedDomains := plan.Domains(ip)
	domains := append([]string{}, row.Domains...)
	if row.Attempted && len(domains) == 0 {
		return false, "", "", errors.New("attempted TCP result lacks contact-time DNS authority")
	}
	for _, domain := range domains {
		if !containsScanIP(plannedDomains, domain) {
			return false, "", "", errors.New("TCP result domain outside admitted plan")
		}
	}
	if len(plannedDomains) == 0 {
		return false, "", "", errors.New("TCP result has no admitted domain")
	}
	status := core.InScope
	if !row.Attempted {
		status = core.NeedsManualReview
	}
	value := net.JoinHostPort(ip, strconv.Itoa(row.Port))
	ev, err := core.NewEvent(core.PortScanResult, "port_scan", "tcp_connect", row, value, status)
	if err != nil {
		return false, "", "", err
	}
	ev.Metadata = map[string]any{"ip": ip, "protocol": "tcp", "port": row.Port, "state": row.State, "attempted": row.Attempted, "reason": row.Reason, "error": row.Error, "started_at": row.StartedAt.UTC().Format(time.RFC3339Nano), "duration_ms": float64(row.Duration) / float64(time.Millisecond), "validated_domains": domains, "planned_domains": plannedDomains, "observation_type": "active_tcp_connect", "target_service_contacted": row.Attempted}
	if row.State == "unknown" {
		ev.Confidence = 0
	}
	if err := sink.emit(ctx, ev); err != nil {
		return false, "", "", err
	}
	if !row.Attempted || row.State != "open" {
		return row.Attempted, "", "", nil
	}
	if _, ok := tcpWebPorts[row.Port]; !ok {
		return true, "", "", nil
	}
	// Reuse only the exact DNS domain admitted for this IP. HTTP itself will
	// revalidate/pin DNS, scope and authorization before each request.
	domain := domains[0]
	for _, name := range domains {
		if name == p.target {
			domain = name
			break
		}
	}
	if (core.ScopeChecker{Policy: p.cfg.ScopePolicy}).CheckDomain(domain).Status != core.InScope {
		return true, "", "", nil
	}
	return true, tcpWebURL(domain, row.Port), domain, nil
}
func containsScanIP(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func tcpWebURL(host string, port int) string {
	scheme := "http"
	if _, ok := tcpHTTPSPorts[port]; ok {
		scheme = "https"
	}
	authority := host
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		authority = "[" + host + "]"
	}
	defaultPort := scheme == "http" && port == 80 || scheme == "https" && port == 443
	if !defaultPort {
		authority = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return scheme + "://" + authority + "/"
}

func containsInt(a []int, n int) bool {
	for _, v := range a {
		if n == v {
			return true
		}
	}
	return false
}
