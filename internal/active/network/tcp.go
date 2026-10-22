package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

// TCPPlan is an immutable, DNS-backed list of addresses authorized by the
// current scope policy. Its contents cannot be constructed by callers.
type TCPPlan struct {
	index       *evidence.DNSRunIndex
	root        string
	policy      core.ScopePolicy
	ips         []string
	domainsByIP map[string][]string
	blocked     []string
	deferred    int
}

func (p TCPPlan) IPs() []string { return append([]string(nil), p.ips...) }

func (p TCPPlan) Domains(ip string) []string {
	return append([]string(nil), p.domainsByIP[ip]...)
}

// BlockedSpecialIPs returns special-use DNS addresses refused because policy
// did not explicitly authorize their CIDR.
func (p TCPPlan) BlockedSpecialIPs() []string { return append([]string(nil), p.blocked...) }

// DeferredIPs reports eligible addresses omitted by maxTargets.
func (p TCPPlan) DeferredIPs() int { return p.deferred }

// Admitted rechecks current run-local DNS evidence, exact eligibility, and
// scope. It does not perform DNS or any other network operation.
func (p TCPPlan) Admitted(ip string) bool { return len(latestAuthorizedDomains(p, ip)) > 0 }

// BuildTCPPlan includes only exact affirmative DNS eligibility and terminal
// address evidence. Special-use addresses require an explicit allowed CIDR.
func BuildTCPPlan(index *evidence.DNSRunIndex, root string, policy core.ScopePolicy, maxTargets int) (TCPPlan, error) {
	if index == nil || maxTargets < 1 {
		return TCPPlan{}, errors.New("DNS evidence index and positive TCP target limit are required")
	}
	if err := policy.Validate(); err != nil {
		return TCPPlan{}, err
	}
	normalizedRoot, err := core.NormalizeDomain(root)
	if err != nil {
		return TCPPlan{}, fmt.Errorf("invalid TCP plan root: %w", err)
	}
	policy = cloneScopePolicy(policy)
	allowed := index.ConfirmedTargets(normalizedRoot, false)
	checker := core.ScopeChecker{Policy: policy}
	ipDomains := make(map[string]map[string]struct{})
	blockedSpecial := make(map[string]struct{})
	for domain := range allowed {
		decision := checker.CheckDomain(domain)
		if decision.Status != core.InScope || sharedDomain(index, domain) {
			continue
		}
		validation := index.ExistingValidation(domain)
		if !exactActiveEligibility(validation) {
			continue
		}
		domainIPs := terminalIPs(validation)
		sharedInfrastructureIP := false
		for _, ip := range domainIPs {
			if sharedASN(index, ip) {
				sharedInfrastructureIP = true
				break
			}
		}
		if sharedInfrastructureIP {
			continue
		}
		for _, ip := range domainIPs {
			addr, err := netip.ParseAddr(ip)
			addr = addr.Unmap()
			if err != nil || excludedTCPAddress(addr, policy) {
				continue
			}
			if addr.IsUnspecified() || addr.IsMulticast() || (specialTCPAddress(addr) && !explicitAllowedCIDR(addr, policy)) {
				blockedSpecial[ip] = struct{}{}
				continue
			}
			if ipDomains[ip] == nil {
				ipDomains[ip] = make(map[string]struct{})
			}
			ipDomains[ip][decision.NormalizedValue] = struct{}{}
		}
	}

	ips := make([]string, 0, len(ipDomains))
	for ip := range ipDomains {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	deferred := 0
	if len(ips) > maxTargets {
		deferred = len(ips) - maxTargets
		ips = ips[:maxTargets]
	}
	blocked := make([]string, 0, len(blockedSpecial))
	for ip := range blockedSpecial {
		blocked = append(blocked, ip)
	}
	sort.Strings(blocked)
	plan := TCPPlan{index: index, root: normalizedRoot, policy: policy, ips: ips, domainsByIP: make(map[string][]string, len(ips)), blocked: blocked, deferred: deferred}
	for _, ip := range ips {
		for domain := range ipDomains[ip] {
			plan.domainsByIP[ip] = append(plan.domainsByIP[ip], domain)
		}
		sort.Strings(plan.domainsByIP[ip])
	}
	return plan, nil
}

func cloneScopePolicy(p core.ScopePolicy) core.ScopePolicy {
	p.AllowedDomains = append([]string(nil), p.AllowedDomains...)
	p.AllowedCIDRs = append([]string(nil), p.AllowedCIDRs...)
	p.ExcludedDomains = append([]string(nil), p.ExcludedDomains...)
	p.ExcludedCIDRs = append([]string(nil), p.ExcludedCIDRs...)
	return p
}

func exactActiveEligibility(validation map[string]any) bool {
	if validation == nil {
		return false
	}
	value, ok := validation["active_eligibility"].(string)
	return ok && (value == "eligible" || value == "eligible_override")
}

func terminalIPs(validation map[string]any) []string {
	raw, ok := validation["terminal_ips"].([]any)
	if !ok {
		return nil
	}
	ips := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		ip, err := core.NormalizeIP(fmt.Sprint(value))
		if err != nil {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips
}

func tcpAddressPermitted(ip netip.Addr, policy core.ScopePolicy) bool {
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || excludedTCPAddress(ip, policy) {
		return false
	}
	return !specialTCPAddress(ip) || explicitAllowedCIDR(ip, policy)
}

func excludedTCPAddress(ip netip.Addr, policy core.ScopePolicy) bool {
	ip = ip.Unmap()
	for _, raw := range policy.ExcludedCIDRs {
		if core.IPInCIDR(ip.String(), raw) {
			return true
		}
	}
	return false
}

func explicitAllowedCIDR(ip netip.Addr, policy core.ScopePolicy) bool {
	ip = ip.Unmap()
	for _, raw := range policy.AllowedCIDRs {
		if core.IPInCIDR(ip.String(), raw) {
			return true
		}
	}
	return false
}

func specialTCPAddress(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, raw := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return true
		}
	}
	return false
}

func sharedDomain(index *evidence.DNSRunIndex, domain string) bool {
	for _, cname := range index.CNAMETargets(domain) {
		if sharedTCPCNAME(cname) {
			return true
		}
	}
	return false
}

func sharedASN(index *evidence.DNSRunIndex, ip string) bool {
	for _, name := range index.ASNNamesForIP(ip) {
		if sharedTCPASNName(name) {
			return true
		}
	}
	return false
}

func sharedTCPCNAME(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"cloudfront", "amazonaws", "azure", "googleusercontent", "cloudflare", "fastly", "akamai"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func sharedTCPASNName(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"cloudflare", "amazon", "akamai", "fastly", "google", "microsoft", "azure", "cloudfront", "digitalocean", "ovh", "hetzner", "hosting", "ru-center", "nic.ru"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

// Observation is one attempted or explicitly denied TCP target/port pair.
// It reports reachability only; it never infers a service from a port number.
type Observation struct {
	IP        string        `json:"ip"`
	Domains   []string      `json:"domains,omitempty"`
	Port      int           `json:"port"`
	Protocol  string        `json:"protocol"`
	State     string        `json:"state"`
	Attempted bool          `json:"attempted"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	Reason    string        `json:"reason,omitempty"`
}

type TCPConfig struct {
	Profile     string
	Authorized  bool
	Concurrency int
	Rate        int
	DialTimeout time.Duration
	Emit        func(Observation) error
}

type TCPResult struct {
	Rows        []Observation `json:"rows"`
	Planned     int           `json:"planned"`
	Attempted   int           `json:"attempted"`
	Denied      int           `json:"denied"`
	Unattempted int           `json:"unattempted"`
	Partial     bool          `json:"partial"`
}

type tcpJob struct {
	ip   string
	port int
}

type tcpOutcome struct {
	row     Observation
	attempt bool
	denied  bool
	ack     chan struct{}
}

type tcpDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type tcpRateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func (l *tcpRateLimiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	start := now
	if l.next.After(start) {
		start = l.next
	}
	l.next = start.Add(l.interval)
	l.mu.Unlock()
	if delay := time.Until(start); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

// ScanTCP performs bounded, context-aware TCP connects using literal IP
// addresses. Emit is called serially by the collector for durable persistence.
func ScanTCP(ctx context.Context, plan TCPPlan, ports []int, cfg TCPConfig) (TCPResult, error) {
	return scanTCP(ctx, plan, ports, cfg, &net.Dialer{Timeout: cfg.DialTimeout})
}

func scanTCP(ctx context.Context, plan TCPPlan, ports []int, cfg TCPConfig, dialer tcpDialer) (TCPResult, error) {
	result := TCPResult{Rows: []Observation{}}
	if ctx == nil || plan.index == nil || len(plan.ips) == 0 {
		return result, errors.New("a non-empty DNS-authorized TCP plan and context are required")
	}
	if cfg.Profile != "full" || !cfg.Authorized {
		return result, errors.New("TCP scanning requires full profile and explicit authorization")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 32 || cfg.Rate < 1 || cfg.Rate > 500 || cfg.DialTimeout <= 0 || cfg.DialTimeout > 2*time.Minute || dialer == nil {
		return result, errors.New("invalid TCP concurrency, rate, timeout, or dialer")
	}
	if len(ports) == 0 {
		return result, errors.New("at least one TCP port is required")
	}
	ports = append([]int(nil), ports...)
	sort.Ints(ports)
	for i, port := range ports {
		if port < 1 || port > 65535 || i > 0 && ports[i-1] == port {
			return result, fmt.Errorf("invalid or duplicate TCP port %d", port)
		}
	}
	targetCount := len(plan.ips) + plan.deferred
	if plan.index == nil || targetCount > int(^uint(0)>>1)/len(ports) {
		return result, errors.New("TCP plan is too large")
	}
	result.Planned = targetCount * len(ports)
	if ctx.Err() != nil {
		result.Unattempted = result.Planned
		result.Partial = true
		return result, ctx.Err()
	}
	if err := recheckPlan(plan); err != nil {
		result.Unattempted = result.Planned
		result.Partial = result.Planned > 0
		return result, err
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan tcpJob)
	outcomes := make(chan tcpOutcome, cfg.Concurrency)
	limiter := tcpRateLimiter{interval: time.Second / time.Duration(cfg.Rate)}
	var workers sync.WaitGroup
	workers.Add(cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		go func() {
			defer workers.Done()
			for job := range jobs {
				// A send can win the feeder's select concurrently with cancellation.
				// Do not begin another job after the previous durable emit failed.
				if workCtx.Err() != nil {
					return
				}
				outcome := scanTCPJob(workCtx, plan, job, cfg, dialer, &limiter)
				outcome.ack = make(chan struct{})
				outcomes <- outcome
				<-outcome.ack
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range plan.ips {
			for _, port := range ports {
				select {
				case <-workCtx.Done():
					return
				case jobs <- tcpJob{ip: ip, port: port}:
				}
			}
		}
	}()
	go func() {
		workers.Wait()
		close(outcomes)
	}()

	var emitErr error
	for outcome := range outcomes {
		result.Rows = append(result.Rows, outcome.row)
		if outcome.attempt {
			result.Attempted++
		}
		if outcome.denied {
			result.Denied++
		}
		if outcome.row.State == "unknown" || outcome.row.Reason == "connection_close_error" {
			result.Partial = true
		}
		if cfg.Emit != nil && emitErr == nil {
			if err := cfg.Emit(outcome.row); err != nil {
				emitErr = fmt.Errorf("persist TCP observation: %w", err)
				cancel()
			}
		}
		close(outcome.ack)
	}
	result.Unattempted = result.Planned - result.Attempted - result.Denied
	if result.Unattempted > 0 || result.Denied > 0 {
		result.Partial = true
	}
	if emitErr != nil {
		return result, emitErr
	}
	if err := ctx.Err(); err != nil {
		result.Partial = true
		return result, err
	}
	return result, nil
}

func recheckPlan(plan TCPPlan) error {
	if err := plan.policy.Validate(); err != nil {
		return err
	}
	if _, err := (core.ScopeChecker{Policy: plan.policy}).RequireActiveAllowed("verify", true, plan.root, "domain"); err != nil {
		return fmt.Errorf("TCP plan scope no longer valid: %w", err)
	}
	return nil
}

func scanTCPJob(ctx context.Context, plan TCPPlan, job tcpJob, cfg TCPConfig, dialer tcpDialer, limiter *tcpRateLimiter) tcpOutcome {
	row := Observation{IP: job.ip, Port: job.port, Protocol: "tcp"}
	if err := ctx.Err(); err != nil {
		row.State, row.Reason, row.Error = "unknown", "cancelled_before_connect", err.Error()
		return tcpOutcome{row: row}
	}
	if len(latestAuthorizedDomains(plan, job.ip)) == 0 {
		row.State, row.Reason = "unknown", "latest_dns_or_scope_admission_denied"
		return tcpOutcome{row: row, denied: true}
	}
	if err := limiter.wait(ctx); err != nil {
		row.State, row.Reason, row.Error = "unknown", "cancelled_before_connect", err.Error()
		return tcpOutcome{row: row}
	}
	// Recheck after rate limiting and immediately before the literal-IP dial.
	row.Domains = latestAuthorizedDomains(plan, job.ip)
	if len(row.Domains) == 0 {
		row.State, row.Reason = "unknown", "latest_dns_or_scope_admission_denied"
		return tcpOutcome{row: row, denied: true}
	}
	if err := ctx.Err(); err != nil {
		row.State, row.Reason, row.Error = "unknown", "cancelled_before_connect", err.Error()
		return tcpOutcome{row: row}
	}
	started := time.Now()
	row.Attempted = true
	row.StartedAt = started.UTC()
	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(job.ip, strconv.Itoa(job.port)))
	dialContextErr := dialCtx.Err()
	cancel()
	row.Duration = time.Since(started)
	if err == nil {
		if conn == nil {
			row.State, row.Reason, row.Error = "unknown", "invalid_dial_result", "dialer returned a nil connection without an error"
			return tcpOutcome{row: row, attempt: true}
		}
		row.State = "open"
		if closeErr := conn.Close(); closeErr != nil {
			row.Error, row.Reason = closeErr.Error(), "connection_close_error"
		}
		return tcpOutcome{row: row, attempt: true}
	}
	if conn != nil {
		_ = conn.Close()
	}
	row.Error = err.Error()
	if isTCPRefused(err) {
		row.State = "closed"
		row.Reason = "connection_refused"
	} else {
		row.State = "unknown"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(dialContextErr, context.DeadlineExceeded) {
			row.Reason = "dial_timeout"
		} else if errors.Is(err, context.Canceled) || errors.Is(dialContextErr, context.Canceled) {
			row.Reason = "cancelled_during_dial"
		} else {
			row.Reason = "ambiguous_dial_error"
		}
	}
	return tcpOutcome{row: row, attempt: true}
}

func latestAuthorizedDomains(plan TCPPlan, ip string) []string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !tcpAddressPermitted(addr, plan.policy) {
		return nil
	}
	checker := core.ScopeChecker{Policy: plan.policy}
	confirmed := plan.index.ConfirmedTargets(plan.root, false)
	var domains []string
	for _, domain := range plan.domainsByIP[ip] {
		decision := checker.CheckDomain(domain)
		if decision.Status != core.InScope || sharedDomain(plan.index, domain) || !exactActiveEligibility(plan.index.ExistingValidation(domain)) {
			continue
		}
		if _, exists := confirmed[decision.NormalizedValue]; !exists {
			continue
		}
		for _, candidate := range terminalIPs(plan.index.ExistingValidation(domain)) {
			if candidate == ip {
				domains = append(domains, decision.NormalizedValue)
				break
			}
		}
	}
	return domains
}

func isTCPRefused(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	if runtime.GOOS == "windows" {
		return errno == syscall.Errno(10061)
	}
	if runtime.GOOS == "linux" {
		return errno == syscall.Errno(111)
	}
	return false
}
