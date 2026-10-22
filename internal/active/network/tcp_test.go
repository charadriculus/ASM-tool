package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

func tcpIndex(policy core.ScopePolicy, entries ...map[string]any) *evidence.DNSRunIndex {
	idx := evidence.NewDNSRunIndex(policy)
	for _, entry := range entries {
		idx.Ingest(map[string]any{
			"event_type": "dns_validation", "normalized_value": entry["domain"], "observed_at": entry["observed"],
			"metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": entry["eligibility"], "terminal_ips": entry["ips"]},
		})
	}
	return idx
}

func tcpEntry(domain, observed, eligibility string, ips ...string) map[string]any {
	values := make([]any, len(ips))
	for i, ip := range ips {
		values[i] = ip
	}
	return map[string]any{"domain": domain, "observed": observed, "eligibility": eligibility, "ips": values}
}

func TestBuildTCPPlanFiltersAndBoundsDNSAddresses(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, ExcludedCIDRs: []string{"8.8.4.0/24"}}
	idx := tcpIndex(policy,
		tcpEntry("a.example.test", "2026-01-01T00:00:00Z", "eligible", "9.9.9.9", "127.0.0.1", "8.8.4.4"),
		tcpEntry("b.example.test", "2026-01-01T00:00:01Z", "eligible_override", "8.8.8.8"),
		tcpEntry("c.example.test", "2026-01-01T00:00:02Z", "eligible_but_not_exact", "1.1.1.1"),
	)
	plan, err := BuildTCPPlan(idx, "example.test", policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.IPs(), []string{"8.8.8.8"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("planned IPs=%v, want %v", got, want)
	}
	if got := plan.Domains("8.8.8.8"); !reflect.DeepEqual(got, []string{"b.example.test"}) {
		t.Fatalf("domains=%v", got)
	}
	if got := plan.BlockedSpecialIPs(); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Fatalf("blocked special IPs=%v", got)
	}
	if got := plan.DeferredIPs(); got != 1 {
		t.Fatalf("deferred targets=%d, want 1", got)
	}
	if !plan.Admitted("8.8.8.8") || plan.Admitted("9.9.9.9") {
		t.Fatal("plan latest-admission query did not reflect the selected target set")
	}
	got := plan.IPs()
	got[0] = "1.2.3.4"
	if plan.IPs()[0] != "8.8.8.8" {
		t.Fatal("IPs exposed mutable plan storage")
	}
}

func TestBuildTCPPlanRequiresExplicitCIDRForSpecialAddresses(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := tcpIndex(policy, tcpEntry("local.example.test", "1", "eligible", "127.0.0.1"))
	plan, err := BuildTCPPlan(idx, "example.test", policy, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.IPs()) != 0 {
		t.Fatalf("loopback admitted without explicit CIDR: %v", plan.IPs())
	}

	policy.AllowedCIDRs = []string{"127.0.0.1/32"}
	idx = tcpIndex(policy, tcpEntry("local.example.test", "1", "eligible", "127.0.0.1"))
	plan, err = BuildTCPPlan(idx, "example.test", policy, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.IPs(); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Fatalf("explicitly authorized loopback not admitted: %v", got)
	}
}

func TestBuildTCPPlanDropsDomainWithAnySharedASNAddress(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := tcpIndex(policy, tcpEntry("mixed.example.test", "1", "eligible", "8.8.8.8", "9.9.9.9"))
	idx.Ingest(map[string]any{"event_type": "asn_found", "metadata": map[string]any{"ip": "9.9.9.9", "as_name": "Example Hosting"}})
	plan, err := BuildTCPPlan(idx, "example.test", policy, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.IPs(); len(got) != 0 {
		t.Fatalf("mixed shared-infrastructure domain contributed IPs: %v", got)
	}
}

func TestScanTCPClassifiesOnlyRefusalAsClosedAndUsesLiteralIPv6(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := tcpIndex(policy,
		tcpEntry("v4.example.test", "1", "eligible", "8.8.8.8"),
		tcpEntry("v6.example.test", "2", "eligible", "2001:4860:4860::8888"),
	)
	plan, err := BuildTCPPlan(idx, "example.test", policy, 10)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &fakeTCPDialer{dial: func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Errorf("network=%q", network)
		}
		switch address {
		case "8.8.8.8:80":
			if runtime.GOOS == "windows" {
				return nil, syscall.Errno(10061)
			}
			return nil, syscall.Errno(111)
		case "[2001:4860:4860::8888]:80":
			return nil, context.DeadlineExceeded
		default:
			return nil, fmt.Errorf("unexpected address: %s", address)
		}
	}}
	result, err := scanTCP(context.Background(), plan, []int{80}, tcpTestConfig(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Attempted != 2 || result.Planned != 2 || !result.Partial {
		t.Fatalf("unexpected result summary: %+v", result)
	}
	states := map[string]string{}
	for _, row := range result.Rows {
		states[row.IP] = row.State
	}
	if states["8.8.8.8"] != "closed" || states["2001:4860:4860::8888"] != "unknown" {
		t.Fatalf("states=%v", states)
	}
}

func TestScanTCPRequiresAuthorizationAndRechecksLatestDNS(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	entry := tcpEntry("a.example.test", "2026-01-01T00:00:00Z", "eligible", "8.8.8.8")
	idx := tcpIndex(policy, entry)
	plan, err := BuildTCPPlan(idx, "example.test", policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &fakeTCPDialer{dial: func(context.Context, string, string) (net.Conn, error) { return testConn{}, nil }}
	cfg := tcpTestConfig()
	cfg.Authorized = false
	if _, err := scanTCP(context.Background(), plan, []int{443}, cfg, dialer); err == nil {
		t.Fatal("unauthorized scan accepted")
	}
	if dialer.calls.Load() != 0 {
		t.Fatal("unauthorized scan dialed")
	}
	cfg.Authorized, cfg.Profile = true, "verify"
	if _, err := scanTCP(context.Background(), plan, []int{443}, cfg, dialer); err == nil {
		t.Fatal("verify profile accepted a TCP port scan")
	}
	if dialer.calls.Load() != 0 {
		t.Fatal("verify profile scan dialed")
	}

	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "a.example.test", "observed_at": "2026-01-02T00:00:00Z", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "ineligible", "terminal_ips": []any{"8.8.8.8"}}})
	cfg.Authorized, cfg.Profile = true, "full"
	result, err := scanTCP(context.Background(), plan, []int{443}, cfg, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if dialer.calls.Load() != 0 || result.Denied != 1 || result.Attempted != 0 || !result.Partial {
		t.Fatalf("latest DNS recheck failed: calls=%d result=%+v", dialer.calls.Load(), result)
	}
}

func TestScanTCPCancellationPreservesCompletedOutcomes(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := tcpIndex(policy, tcpEntry("a.example.test", "1", "eligible", "8.8.8.8"))
	plan, err := BuildTCPPlan(idx, "example.test", policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &fakeTCPDialer{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := tcpTestConfig()
	var emitted atomic.Int32
	cfg.Emit = func(row Observation) error {
		if !row.Attempted {
			t.Error("completed dial observation was emitted as unattempted")
		}
		emitted.Add(1)
		return nil
	}
	result, err := scanTCP(ctx, plan, []int{80, 81}, cfg, dialer)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error=%v, want cancellation", err)
	}
	if dialer.calls.Load() != 1 || result.Attempted != 1 || len(result.Rows) < 1 || emitted.Load() != 1 || !result.Partial {
		t.Fatalf("cancellation lost/continued work: calls=%d result=%+v", dialer.calls.Load(), result)
	}
}

func TestScanTCPEmitFailurePreservesAttemptedRowsAndStopsFurtherDials(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := tcpIndex(policy, tcpEntry("a.example.test", "1", "eligible", "8.8.8.8"))
	plan, err := BuildTCPPlan(idx, "example.test", policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &fakeTCPDialer{dial: func(context.Context, string, string) (net.Conn, error) { return testConn{}, nil }}
	cfg := tcpTestConfig()
	cfg.Emit = func(Observation) error { return errors.New("storage unavailable") }
	result, err := scanTCP(context.Background(), plan, []int{80, 81}, cfg, dialer)
	if err == nil || !strings.Contains(err.Error(), "storage unavailable") {
		t.Fatalf("emit failure=%v", err)
	}
	if result.Attempted != 1 || len(result.Rows) != 1 || !result.Rows[0].Attempted || !result.Partial || dialer.calls.Load() != 1 {
		t.Fatalf("emit failure lost evidence or continued work: calls=%d result=%+v", dialer.calls.Load(), result)
	}
}

func TestScanTCPBoundsWorkersAndSerializesEmission(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := tcpIndex(policy,
		tcpEntry("a.example.test", "1", "eligible", "8.8.8.8"),
		tcpEntry("b.example.test", "2", "eligible", "9.9.9.9"),
		tcpEntry("c.example.test", "3", "eligible", "1.1.1.1"),
	)
	plan, err := BuildTCPPlan(idx, "example.test", policy, 3)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &fakeTCPDialer{dial: func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(5 * time.Millisecond)
		return testConn{}, nil
	}}
	cfg := tcpTestConfig()
	cfg.Concurrency = 2
	var emitting atomic.Int32
	cfg.Emit = func(Observation) error {
		if emitting.Add(1) != 1 {
			return errors.New("concurrent emission")
		}
		time.Sleep(time.Millisecond)
		emitting.Add(-1)
		return nil
	}
	result, err := scanTCP(context.Background(), plan, []int{80, 443}, cfg, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if dialer.maxActive.Load() > 2 || result.Attempted != 6 || result.Planned != 6 || result.Partial {
		t.Fatalf("worker bound/result mismatch: max_active=%d result=%+v", dialer.maxActive.Load(), result)
	}
}

func tcpTestConfig() TCPConfig {
	return TCPConfig{Profile: "full", Authorized: true, Concurrency: 1, Rate: 500, DialTimeout: time.Second}
}

type fakeTCPDialer struct {
	dial      func(context.Context, string, string) (net.Conn, error)
	calls     atomic.Int32
	active    atomic.Int32
	maxActive atomic.Int32
}

func (d *fakeTCPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	active := d.active.Add(1)
	for max := d.maxActive.Load(); active > max; max = d.maxActive.Load() {
		if d.maxActive.CompareAndSwap(max, active) {
			break
		}
	}
	defer d.active.Add(-1)
	return d.dial(ctx, network, address)
}

type testConn struct{}

func (testConn) Read([]byte) (int, error)         { return 0, errors.New("unused") }
func (testConn) Write([]byte) (int, error)        { return 0, errors.New("unused") }
func (testConn) Close() error                     { return nil }
func (testConn) LocalAddr() net.Addr              { return testAddr("local") }
func (testConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (testConn) SetDeadline(time.Time) error      { return nil }
func (testConn) SetReadDeadline(time.Time) error  { return nil }
func (testConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestTCPRejectsCanonicalHostAndDottedMaskExclusionsBeforeDial(t *testing.T) {
	for _, cidr := range []string{"8.8.8.8", "8.8.8.0/255.255.255.0", "8.8.8.0/24"} {
		t.Run(cidr, func(t *testing.T) {
			policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, ExcludedCIDRs: []string{cidr}}
			idx := tcpIndex(policy, tcpEntry("a.example.test", "2026-01-01T00:00:00Z", "eligible", "8.8.8.8"))
			plan, err := BuildTCPPlan(idx, "example.test", policy, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.IPs()) != 0 || plan.Admitted("8.8.8.8") {
				t.Fatalf("excluded IP admitted for %s: %v", cidr, plan.IPs())
			}
			dialer := &fakeTCPDialer{dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("excluded IP dialed")
				return testConn{}, nil
			}}
			if _, err := scanTCP(context.Background(), plan, []int{80}, tcpTestConfig(), dialer); err == nil || dialer.calls.Load() != 0 {
				t.Fatalf("excluded plan was executed: %v", err)
			}
		})
	}
}
func TestTCPNeverDialsUnspecifiedOrMulticastEvenWithBroadCIDR(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"0.0.0.0/0", "::/0"}}
	idx := tcpIndex(policy, tcpEntry("a.example.test", "2026-01-01T00:00:00Z", "eligible", "0.0.0.0", "224.0.0.1", "::", "ff02::1"))
	plan, err := BuildTCPPlan(idx, "example.test", policy, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.IPs()) != 0 || len(plan.BlockedSpecialIPs()) != 4 {
		t.Fatalf("invalid addresses admitted: %+v", plan)
	}
	for _, ip := range []string{"0.0.0.0", "224.0.0.1", "::", "ff02::1"} {
		if plan.Admitted(ip) {
			t.Fatalf("pre-dial admitted %s", ip)
		}
	}
}
