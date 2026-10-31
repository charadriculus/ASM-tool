package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/evidence"
	"golang.org/x/net/dns/dnsmessage"
)

func TestPipelineStreamsEligibleWebBeforeOtherDNSWorkersFinish(t *testing.T) {
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	var slowActive atomic.Bool
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := dnsConn.ReadFrom(buf)
			if e != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			go func() {
				var p dnsmessage.Parser
				h, e := p.Start(packet)
				if e != nil {
					return
				}
				q, e := p.Question()
				if e != nil {
					return
				}
				if strings.HasPrefix(q.Name.String(), "slow.example.test") {
					slowActive.Store(true)
					time.Sleep(350 * time.Millisecond)
					defer slowActive.Store(false)
				}
				reply := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
				if q.Type == dnsmessage.TypeA {
					reply.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
				}
				out, e := reply.Pack()
				if e == nil {
					_, _ = dnsConn.WriteTo(out, addr)
				}
			}()
		}
	}()
	dnsClient, err := dns.NewClientWithRate([]string{dnsConn.LocalAddr().String()}, time.Second, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var contactedDuringDNS atomic.Bool
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slowActive.Load() {
			contactedDuringDNS.Store(true)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>root</title>`))
	}))
	defer httpServer.Close()
	u, _ := url.Parse(httpServer.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test", "slow.example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 4, GlobalConcurrency: 2, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var sinkCalls atomic.Int64
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(core.Event) error { sinkCalls.Add(1); return nil }, KnownWebURLs: []string{"http://example.test:" + port + "/"}, PerHostRequests: 2, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 2, Workers: 2, WildcardEnabled: false, WildcardParentBudget: 1, MaxEnrichmentIPs: 1, Inventory: map[string]evidence.ProviderInventoryEntry{"slow.example.test": {Hostname: "slow.example.test", Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}}}}
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !contactedDuringDNS.Load() {
		t.Fatal("web request did not overlap the outstanding admitted DNS validation")
	}
	if len(out.Probes) != 1 || out.Probes[0].HTTP.StatusCode != http.StatusOK {
		t.Fatalf("web probe not retained: %+v", out.Probes)
	}
	if out.DNS.Validations["example.test"].Resolved == false {
		t.Fatal("root DNS validation missing")
	}
	if sinkCalls.Load() == 0 {
		t.Fatal("pipeline did not persist evidence")
	}
	if got := idx.ExistingValidation("example.test"); got == nil || len(terminalIPs(got["terminal_ips"])) != 1 {
		t.Fatal("HTTP admission did not observe indexed terminal IP")
	}
}

func TestPipelineRunsIndependentWebTargetsConcurrently(t *testing.T) {
	var slowStarted, fastDuringSlow atomic.Bool
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/slow") {
			slowStarted.Store(true)
			defer slowStarted.Store(false)
			time.Sleep(300 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			return
		}
		deadline := time.Now().Add(500 * time.Millisecond)
		for !slowStarted.Load() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if slowStarted.Load() {
			fastDuringSlow.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()
	u, _ := url.Parse(httpServer.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	for i, name := range []string{"example.test", "fast.example.test"} {
		idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": name, "observed_at": string(rune('1' + i)), "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	}
	dnsClient, err := dns.NewClientWithRate([]string{"127.0.0.1:53"}, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 4, GlobalConcurrency: 2, PerOriginConcurrency: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(core.Event) error { return nil }, KnownWebURLs: []string{"http://example.test:" + port + "/slow", "http://example.test:" + port + "/slow2", "http://fast.example.test:" + port + "/fast"}, PerHostRequests: 3, WebConcurrency: 2, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 2, Workers: 2, SkipPrevalidated: true, WildcardEnabled: false, WildcardParentBudget: 1, MaxEnrichmentIPs: 1, Inventory: map[string]evidence.ProviderInventoryEntry{"fast.example.test": {Hostname: "fast.example.test", Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}}}}
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !fastDuringSlow.Load() || len(out.Probes) != 3 {
		t.Fatalf("web targets were serialized: fast_during_slow=%v probes=%d", fastDuringSlow.Load(), len(out.Probes))
	}
}

func TestPipelineContinuesAfterPersistedTransportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	for i, entry := range []struct{ name, ip string }{{"example.test", "127.0.0.1"}, {"a-down.example.test", "127.0.0.2"}, {"b-fast.example.test", "127.0.0.1"}} {
		idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": entry.name, "observed_at": string(rune('1' + i)), "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{entry.ip}}})
	}
	dnsClient, err := dns.NewClientWithRate([]string{"127.0.0.1:53"}, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 3, GlobalConcurrency: 2, PerOriginConcurrency: 2, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(core.Event) error { return nil }, KnownWebURLs: []string{"http://example.test:" + port + "/root", "http://a-down.example.test:" + port + "/down", "http://b-fast.example.test:" + port + "/fast"}, PerHostRequests: 1, WebConcurrency: 2, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 3, Workers: 2, SkipPrevalidated: true, WildcardParentBudget: 1, MaxEnrichmentIPs: 1, Inventory: map[string]evidence.ProviderInventoryEntry{"a-down.example.test": {Hostname: "a-down.example.test", Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}, "b-fast.example.test": {Hostname: "b-fast.example.test", Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}}}}
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Partial || len(out.Probes) != 3 {
		t.Fatalf("transport failure did not preserve partial and peer results: partial=%v probes=%+v", out.Partial, out.Probes)
	}
	var fastOK, downFailed bool
	for _, result := range out.Probes {
		if result.Target.Domain == "b-fast.example.test" && result.HTTP.StatusCode == http.StatusOK {
			fastOK = true
		}
		if result.Target.Domain == "a-down.example.test" && result.HTTP.Error != "" {
			downFailed = true
		}
	}
	if !fastOK || !downFailed {
		t.Fatalf("success/failure evidence incomplete: %+v", out.Probes)
	}
}

func TestPipelineTreatsDurableSinkFailureAsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	dnsClient, err := dns.NewClientWithRate([]string{"127.0.0.1:53"}, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 2, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sinkErr := errors.New("disk full")
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(e core.Event) error {
		if e.EventType == core.WebTargetStatus {
			return sinkErr
		}
		return nil
	}, KnownWebURLs: []string{"http://example.test:" + port + "/"}, PerHostRequests: 1, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 1, Workers: 1, SkipPrevalidated: true, WildcardParentBudget: 1, MaxEnrichmentIPs: 1}}
	out, err := Run(context.Background(), cfg)
	if err == nil || !errors.Is(err, activehttp.ErrEventSink) {
		t.Fatalf("durable sink failure was not fatal: %v", err)
	}
	if len(out.Probes) != 1 || out.DNS.Reused["example.test"] == nil {
		t.Fatalf("fatal shutdown lost committed probe or DNS results: %+v", out)
	}
}

func TestPipelineReportsUnadmittedDynamicCandidates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="https://new.example.test/path">new</a>`))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	dnsClient, err := dns.NewClientWithRate([]string{"127.0.0.1:53"}, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 2, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var events []core.Event
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(e core.Event) error { events = append(events, e); return nil }, KnownWebURLs: []string{"http://example.test:" + port + "/"}, PerHostRequests: 1, DynamicEnabled: true, DynamicMaxRounds: 1, DynamicMaxNewDomains: 0, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 1, Workers: 1, SkipPrevalidated: true, WildcardParentBudget: 1, MaxEnrichmentIPs: 1}}
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Partial {
		t.Fatal("unadmitted dynamic candidate was silently treated as complete")
	}
	for _, event := range events {
		if event.EventType == core.Limitation && event.Metadata["remaining_domains"] == 1 && event.Confidence == 0 {
			return
		}
	}
	t.Fatalf("missing dynamic-budget limitation event: %+v", events)
}

func TestPipelineDynamicDiscoveryRunsToMultiGenerationFixedPoint(t *testing.T) {
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := dnsConn.ReadFrom(buf)
			if e != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			go func() {
				var p dnsmessage.Parser
				h, e := p.Start(packet)
				if e != nil {
					return
				}
				q, e := p.Question()
				if e != nil {
					return
				}
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
				if q.Type == dnsmessage.TypeA && !strings.HasPrefix(q.Name.String(), "asmw-") {
					m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
				}
				out, e := m.Pack()
				if e == nil {
					_, _ = dnsConn.WriteTo(out, addr)
				}
			}()
		}
	}()
	dnsClient, err := dns.NewClientWithRate([]string{dnsConn.LocalAddr().String()}, time.Second, 1000)
	if err != nil {
		t.Fatal(err)
	}
	port := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<a href="http://a.example.test:` + port + `/a">a</a>`))
		case "/a":
			_, _ = w.Write([]byte(`<a href="http://b.a.example.test:` + port + `/b">b</a>`))
		default:
			_, _ = w.Write([]byte(`<title>done</title>`))
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ = net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 4, GlobalConcurrency: 3, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	urls := []string{"http://example.test:" + port + "/", "http://a.example.test:" + port + "/a", "http://b.a.example.test:" + port + "/b"}
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(core.Event) error { return nil }, KnownWebURLs: urls, PerHostRequests: 2, DynamicEnabled: true, DynamicMaxRounds: 3, DynamicMaxNewDomains: 4, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 1, Workers: 1, WildcardEnabled: true, WildcardProbes: 3, WildcardParentBudget: 3, MaxEnrichmentIPs: 1}}
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.DynamicDomains) != 2 || out.DynamicDomains[0] != "a.example.test" || out.DynamicDomains[1] != "b.a.example.test" || len(out.Probes) != 3 || out.Partial {
		t.Fatalf("dynamic fixed point incomplete: domains=%v probes=%d partial=%v", out.DynamicDomains, len(out.Probes), out.Partial)
	}
}

func TestPipelineCancellationJoinsSaturatedWebWorkers(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case <-started:
		default:
			close(started)
		}
		<-r.Context().Done()
		select {
		case <-canceled:
		default:
			close(canceled)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := dnsConn.ReadFrom(buf)
			if e != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			go func() {
				var p dnsmessage.Parser
				h, e := p.Start(packet)
				if e != nil {
					return
				}
				q, e := p.Question()
				if e != nil {
					return
				}
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
				out, e := m.Pack()
				if e == nil {
					_, _ = dnsConn.WriteTo(out, addr)
				}
			}()
		}
	}()
	dnsClient, err := dns.NewClientWithRate([]string{dnsConn.LocalAddr().String()}, time.Second, 1000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	names := []string{"example.test", "a.example.test", "b.example.test", "c.example.test", "d.example.test"}
	inventory := map[string]evidence.ProviderInventoryEntry{}
	for i, name := range names {
		meta := map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}
		if i == 0 {
			meta["input_target"] = true
		}
		idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": name, "observed_at": string(rune('1' + i)), "metadata": meta})
		inventory[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}
	}
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(core.Event) error { return nil }, PerHostRequests: 2, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	urls := make([]string, 0, len(names))
	for _, name := range names {
		urls = append(urls, "http://"+name+":"+port+"/block")
	}
	cfg := Config{Root: "example.test", Policy: policy, Index: idx, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(core.Event) error { return nil }, KnownWebURLs: urls, PerHostRequests: 1, WebConcurrency: 1, DNS: dns.ExpansionConfig{Client: dnsClient, Inventory: inventory, Budget: 5, Workers: 2, WildcardEnabled: false, WildcardParentBudget: 1, MaxEnrichmentIPs: 1, SkipPrevalidated: true}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var out Result
	go func() { out, err = Run(ctx, cfg); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("web worker did not start")
	}
	cancel()
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline did not return after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pipeline cancellation error=%v", err)
	}
	if !out.Partial || len(out.DNS.Reused) == 0 || len(out.Probes) != 1 || len(out.Targets) != len(names) {
		t.Fatalf("cancelled pipeline lost partial committed results: %+v", out)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("HTTP child request did not observe cancellation")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("saturated scheduler started %d requests after cancellation; want only the in-flight request", got)
	}
}

func TestPipelineCancellationDuringDNSPreservesCommittedPartialResults(t *testing.T) {
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	slowSeen, webStarted, releaseSlow := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var slowOnce, webOnce sync.Once
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := dnsConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			go func() {
				var parser dnsmessage.Parser
				header, parseErr := parser.Start(packet)
				if parseErr != nil {
					return
				}
				question, parseErr := parser.Question()
				if parseErr != nil {
					return
				}
				if question.Name.String() == "slow.example.test." {
					slowOnce.Do(func() { close(slowSeen) })
					<-releaseSlow
				}
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{question}}
				if question.Name.String() == "example.test." && question.Type == dnsmessage.TypeA {
					response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
				}
				body, packErr := response.Pack()
				if packErr == nil {
					_, _ = dnsConn.WriteTo(body, addr)
				}
			}()
		}
	}()
	dnsClient, err := dns.NewClientWithRate([]string{dnsConn.LocalAddr().String()}, time.Second, 1000)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webOnce.Do(func() { close(webStarted) })
		<-r.Context().Done()
	}))
	defer httpServer.Close()
	serverURL, _ := url.Parse(httpServer.URL)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	index := evidence.NewDNSRunIndex(policy)
	var durableEvents atomic.Int32
	sink := func(core.Event) error { durableEvents.Add(1); return nil }
	httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: sink, PerHostRequests: 2, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]evidence.ProviderInventoryEntry{}
	for _, name := range []string{"example.test", "slow.example.test"} {
		entries[name] = evidence.ProviderInventoryEntry{Hostname: name, Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}
	}
	cfg := Config{Root: "example.test", Policy: policy, Index: index, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: sink, KnownWebURLs: []string{"http://example.test:" + serverURL.Port() + "/"}, PerHostRequests: 1, WebConcurrency: 1, DNS: dns.ExpansionConfig{Client: dnsClient, Inventory: entries, Budget: 2, Workers: 2, WildcardEnabled: false, WildcardParentBudget: 1, MaxEnrichmentIPs: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, runErr := Run(ctx, cfg); done <- outcome{result, runErr} }()
	select {
	case <-webStarted:
	case <-time.After(3 * time.Second):
		cancel()
		close(releaseSlow)
		t.Fatal("eligible root web request did not start")
	}
	select {
	case <-slowSeen:
	case <-time.After(time.Second):
		cancel()
		close(releaseSlow)
		t.Fatal("slow DNS worker was not in flight with web request")
	}
	cancel()
	close(releaseSlow)
	select {
	case outcome := <-done:
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("cancellation error=%v", outcome.err)
		}
		if !outcome.result.Partial || len(outcome.result.DNS.Validations["example.test"].IPs) == 0 || len(outcome.result.Targets) != 1 || len(outcome.result.Probes) != 1 || durableEvents.Load() == 0 {
			t.Fatalf("cancellation lost committed DNS/web state: partial=%v DNS=%+v targets=%+v probes=%+v events=%d", outcome.result.Partial, outcome.result.DNS, outcome.result.Targets, outcome.result.Probes, durableEvents.Load())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline did not join canceled DNS and web work")
	}
}

func TestDynamicEligibilityOracleAllFourInputsAndTypedRejections(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups struct {
			Dynamic struct {
				Input struct {
					Results []map[string]any `json:"results"`
				} `json:"input"`
				Expected map[string]bool `json:"expected"`
			} `json:"dynamic_eligibility"`
		} `json:"groups"`
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	rows := f.Groups.Dynamic.Input.Results
	if len(rows) != 4 {
		t.Fatalf("source oracle inputs=%d want=4", len(rows))
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	for i, row := range rows {
		index := evidence.NewDNSRunIndex(policy)
		meta := map[string]any{"dns_state": "resolved_clean_parent", "terminal_ips": []any{"192.0.2.10"}}
		switch value := row["eligible"].(type) {
		case bool:
			if value {
				meta["active_eligibility"] = "eligible"
			} else {
				meta["active_eligibility"] = "ineligible"
			}
		case string:
			meta["active_eligibility"] = value
		}
		index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "candidate.example.test", "observed_at": strconv.Itoa(i + 1), "metadata": meta})
		got, err := dns.ValidateQuick(context.Background(), dns.ExpansionConfig{Root: "example.test", Policy: policy, Index: index}, nil, "candidate.example.test")
		if err != nil {
			t.Fatalf("runtime quick validation case %d: %v", i, err)
		}
		want := f.Groups.Dynamic.Expected[strconv.Itoa(i)]
		if i == 3 { // The historical Python truthiness case is rejected by typed Go admission.
			want = false
		}
		if got.Eligible != want {
			t.Errorf("runtime dynamic eligibility case %d=%v want=%v (%+v)", i, got.Eligible, want, got)
		}
	}
}

func TestPipelineDrainsFinalIndexedNoticeWhenDNSCompletionRaces(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := listener.ReadFrom(buf)
			if e != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			var parser dnsmessage.Parser
			header, e := parser.Start(packet)
			if e != nil {
				continue
			}
			question, e := parser.Question()
			if e != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{question}}
			if question.Type == dnsmessage.TypeA {
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			}
			out, e := response.Pack()
			if e == nil {
				_, _ = listener.WriteTo(out, addr)
			}
		}
	}()
	dnsClient, err := dns.NewClientWithRate([]string{listener.LocalAddr().String()}, time.Second, 1000)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ready</title>"))
	}))
	defer httpServer.Close()
	httpURL, _ := url.Parse(httpServer.URL)
	port := httpURL.Port()
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	for attempt := 0; attempt < 1; attempt++ {
		index := evidence.NewDNSRunIndex(policy)
		httpClient, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: func(core.Event) error { return nil }, PerHostRequests: 20, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		cfg := Config{Root: "example.test", Policy: policy, Index: index, PassiveBarrier: func(context.Context) error { return nil }, HTTP: httpClient, Emit: func(core.Event) error { return nil }, KnownWebURLs: []string{"http://example.test:" + port + "/"}, PerHostRequests: 1, DNS: dns.ExpansionConfig{Client: dnsClient, Budget: 1, Workers: 1, WildcardEnabled: false, WildcardParentBudget: 1, MaxEnrichmentIPs: 1, Inventory: map[string]evidence.ProviderInventoryEntry{"example.test": {Hostname: "example.test", Providers: []string{"fixture"}, EvidenceFamilies: []string{"passive"}, FirstSeenByProvider: map[string]string{}, Observations: 1}}}}
		out, err := Run(context.Background(), cfg)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if len(out.Probes) != 1 || out.Probes[0].Status != "loaded" {
			t.Fatalf("attempt %d lost the final eligible notice: probes=%+v DNS=%+v", attempt, out.Probes, out.DNS)
		}
	}
}

func TestBulkCoordinatorDispatchesConsumedFinalNoticeBeforeFixedPoint(t *testing.T) {
	var contacts, durableEvents atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacts.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ready</title>"))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	index := evidence.NewDNSRunIndex(policy)
	index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	sink := func(core.Event) error { durableEvents.Add(1); return nil }
	client, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: sink, PerHostRequests: 1, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	jobs := make(chan probeJob, 1)
	completed := make(chan probeCompletion, 1)
	go func() {
		job := <-jobs
		result, probeErr := web.Probe(context.Background(), client, web.ProbeConfig{Policy: policy, Emit: sink, TLS: activehttp.VerifiedTLS}, job.target, job.urls[0])
		completed <- probeCompletion{results: []web.Result{result}, err: probeErr}
	}()
	coordinator := bulkCoordinator{order: []string{"example.test"}, finished: map[string]bool{"example.test": true}, eligible: map[string]bool{"example.test": true}, handled: map[string]bool{}, workerCount: 1, jobs: jobs, indexed: make(chan core.Event), completedWeb: completed}
	queueDomain := func(name string) error {
		targets, targetErr := web.EligibleTargets(index, "example.test", policy, false)
		if targetErr != nil {
			return targetErr
		}
		if len(targets) != 1 || targets[0].Domain != name {
			return fmt.Errorf("eligible target lookup for %q returned %+v", name, targets)
		}
		urls := web.PlanURLs(targets, []string{"http://example.test:" + serverURL.Port() + "/"}, policy, 1)
		coordinator.pending = append(coordinator.pending, probeJob{target: targets[0], urls: urls})
		return nil
	}
	coordinator.queueDomain = queueDomain
	var result probeCompletion
	coordinator.acceptCompletion = func(done probeCompletion) error {
		coordinator.active--
		result = done
		return done.err
	}
	if err := coordinator.run(context.Background()); err != nil {
		t.Fatalf("coordinator failed to dispatch the consumed final notice: %v", err)
	}
	if coordinator.active != 0 || len(coordinator.pending) != 0 || result.err != nil || len(result.results) != 1 || result.results[0].Status != "loaded" {
		t.Fatalf("final work did not reach fixed point: active=%d pending=%+v completion=%+v", coordinator.active, coordinator.pending, result)
	}
	if contacts.Load() != 1 || durableEvents.Load() == 0 {
		t.Fatalf("final notice contacts=%d durable_events=%d want 1 and >0", contacts.Load(), durableEvents.Load())
	}
}

func terminalIPs(v any) []netip.Addr {
	var out []netip.Addr
	if a, ok := v.([]string); ok {
		for _, s := range a {
			if ip, e := netip.ParseAddr(s); e == nil {
				out = append(out, ip)
			}
		}
	}
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if s, ok := x.(string); ok {
				if ip, e := netip.ParseAddr(s); e == nil {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}
