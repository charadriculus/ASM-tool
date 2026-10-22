package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"golang.org/x/net/dns/dnsmessage"
)

func TestResolveHostNXDOMAINStopsAfterA(t *testing.T) {
	var mu sync.Mutex
	var types []dnsmessage.Type
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		types = append(types, q.Questions[0].Type)
		mu.Unlock()
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: q.Questions}
	})
	c, err := NewClient([]string{resolver}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ResolveHost(context.Background(), c, "nxdomain.example.test", 8)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if r.Resolved || len(r.Queries) != 1 || r.Queries[0].Status != "nxdomain" || len(types) != 1 || types[0] != dnsmessage.TypeA {
		t.Fatalf("NXDOMAIN did not stop RR sequence: resolution=%+v types=%v", r, types)
	}
}

func TestEventSinkFailureDoesNotIngestDNSIndex(t *testing.T) {
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	want := errors.New("sink failure")
	cfg := ExpansionConfig{Index: idx, Emit: func(core.Event) error { return want }}
	ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_validation", "a.example.test", "a.example.test", core.InScope)
	if err != nil {
		t.Fatal(err)
	}
	ev.Metadata = map[string]any{"dns_state": "resolved_clean_parent"}
	ev.EventID = ""
	ev.Confidence = 0.77
	ev.Metadata["dns_state"] = "resolved_clean_parent"
	if err = cfg.emit(context.Background(), ev); !errors.Is(err, want) {
		t.Fatalf("got %v, want sink error", err)
	}
	if idx.ExistingValidation("a.example.test") != nil {
		t.Fatal("failed event was ingested into DNS index")
	}
}

func TestDNSEmitCancellationWhileWaitingForSerializationDoesNotCallSink(t *testing.T) {
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	mu := &sync.Mutex{}
	mu.Lock()
	sinkCalls := 0
	cfg := ExpansionConfig{Index: idx, emitMu: mu, Emit: func(core.Event) error { sinkCalls++; return nil }}
	ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_validation", "a.example.test", "a.example.test", core.InScope)
	if err != nil {
		t.Fatal(err)
	}
	ev.Metadata = map[string]any{"dns_state": "resolved_clean_parent"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cfg.emit(ctx, ev) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if sinkCalls != 0 {
		t.Fatalf("cancelled emit called the sink %d times", sinkCalls)
	}
	if idx.ExistingValidation("a.example.test") != nil {
		t.Fatal("cancelled event was ingested into DNS index")
	}
}

func TestWildcardEligibilityKeepsUncertainExcluded(t *testing.T) {
	r := HostResolution{Resolved: true, IPs: []string{"192.0.2.1"}}
	if got := ActiveEligibility("resolved_parent_inconclusive", r, false, true); got != "uncertain_excluded" {
		t.Fatalf("override promoted uncertain parent: %s", got)
	}
	if got := ActiveEligibility("resolved_wildcard_overlap", r, false, true); got != "eligible_override" {
		t.Fatalf("override not applied to overlap: %s", got)
	}
}

func TestWildcardRulesSourceFixture(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/phase4/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Inputs struct {
			Provider struct {
				Events []map[string]any `json:"events"`
				Root   string           `json:"root"`
				Budget int              `json:"budget"`
			} `json:"provider.inventory"`
			DNS struct {
				Domains    []string `json:"domains"`
				Root       string   `json:"root"`
				MaxParents int      `json:"max_parents"`
			} `json:"dns.wildcard_rules"`
		} `json:"inputs"`
		Outputs struct {
			DNS struct {
				Parents     []string          `json:"parents"`
				Eligibility map[string]string `json:"eligibility"`
			} `json:"dns.wildcard_rules"`
			Inventory struct{ Ranked, Deferred []string } `json:"provider.inventory"`
		} `json:"outputs"`
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	inventory, err := evidence.ProviderInventory(f.Inputs.Provider.Events, f.Inputs.Provider.Root)
	if err != nil {
		t.Fatal(err)
	}
	_, selected, deferred, err := selectInventory(inventory, f.Inputs.Provider.Root, f.Inputs.Provider.Budget, core.ScopePolicy{AllowedDomains: []string{f.Inputs.Provider.Root}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selected, f.Outputs.Inventory.Ranked) || !reflect.DeepEqual(deferred, f.Outputs.Inventory.Deferred) {
		t.Fatalf("selection=%v deferred=%v fixture=%v/%v", selected, deferred, f.Outputs.Inventory.Ranked, f.Outputs.Inventory.Deferred)
	}
	parents := PrioritizedParents(f.Inputs.DNS.Domains, f.Inputs.DNS.Root, f.Inputs.DNS.MaxParents)
	if !reflect.DeepEqual(parents, f.Outputs.DNS.Parents) {
		t.Fatalf("parents=%v fixture=%v", parents, f.Outputs.DNS.Parents)
	}
	if got, want := PrioritizedParents([]string{"example.test", "a.example.test", "x.deep.example.test"}, "example.test", 2), []string{"example.test", "deep.example.test"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("direct-child candidates duplicated root and displaced a deep parent: got=%v want=%v", got, want)
	}
	r := HostResolution{Resolved: true, IPs: []string{"192.0.2.1"}}
	for _, state := range []string{"resolved_clean_parent", "resolved_parent_inconclusive", "resolved_parent_untested", "resolved_wildcard_match", "resolved_wildcard_overlap"} {
		got := ActiveEligibility(state, r, false, true)
		if want := f.Outputs.DNS.Eligibility[state]; got != want {
			t.Errorf("%s eligibility=%q fixture=%q", state, got, want)
		}
	}
}

func localDNSServerDropA(t *testing.T, onQuery func(string, dnsmessage.Type)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			if len(q.Questions) != 1 {
				continue
			}
			onQuery(strings.TrimSuffix(q.Questions[0].Name.String(), "."), q.Questions[0].Type)
			if q.Questions[0].Type == dnsmessage.TypeA {
				continue
			}
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
			raw, e := m.Pack()
			if e == nil {
				_, _ = pc.WriteTo(raw, addr)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func TestResolveHostSourceCasesAgainstLocalDNS(t *testing.T) {
	type expectedQuery struct {
		Name     string   `json:"name"`
		RType    string   `json:"rtype"`
		Status   string   `json:"status"`
		Values   []string `json:"values"`
		TTL      *uint32  `json:"ttl"`
		Resolver string   `json:"resolver"`
		RCode    string   `json:"rcode"`
	}
	type expectedResolution struct {
		Hostname     string          `json:"hostname"`
		Queries      []expectedQuery `json:"queries"`
		IPs          []string        `json:"ips"`
		CNAMEChain   []string        `json:"cname_chain"`
		TerminalName string          `json:"terminal_name"`
		Resolved     bool            `json:"resolved"`
		DNSError     bool            `json:"dns_error"`
	}
	type fixtureCase struct {
		QueryOrder [][]string         `json:"query_order"`
		Resolution expectedResolution `json:"resolution"`
	}
	var fixture struct {
		Outputs struct {
			DNS map[string]fixtureCase `json:"dns.resolve_host"`
		} `json:"outputs"`
	}
	raw, err := os.ReadFile("../../../testdata/phase4/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	modes := map[string]struct{ hostname, mode string }{"alias": {"a", "alias"}, "cycle": {"a", "cycle"}, "nxdomain": {"x", "nxdomain"}, "terminal": {"x", "terminal"}, "transport_error": {"x", "timeout"}}
	if len(fixture.Outputs.DNS) != len(modes) {
		t.Fatalf("source oracle cases=%d want=%d", len(fixture.Outputs.DNS), len(modes))
	}
	for caseName, tc := range modes {
		t.Run(caseName, func(t *testing.T) {
			var mu sync.Mutex
			var order [][]string
			handler := func(q dnsmessage.Message) dnsmessage.Message {
				name := strings.TrimSuffix(q.Questions[0].Name.String(), ".")
				typ := q.Questions[0].Type
				mu.Lock()
				order = append(order, []string{name, dnsTypeName(typ)})
				mu.Unlock()
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
				if tc.mode == "nxdomain" && typ == dnsmessage.TypeA {
					m.Header.RCode = dnsmessage.RCodeNameError
					return m
				}
				addA := func(ip [4]byte) {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: ip}})
				}
				addAAAA := func(ip [16]byte) {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AAAAResource{AAAA: ip}})
				}
				addCNAME := func(to string) {
					n, _ := dnsmessage.NewName(to + ".")
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.CNAMEResource{CNAME: n}})
				}
				if tc.mode == "alias" || tc.mode == "cycle" {
					if typ == dnsmessage.TypeCNAME {
						if name == "a.example.test" {
							addCNAME("b.example.test")
						} else if tc.mode == "cycle" {
							addCNAME("a.example.test")
						}
					}
					if tc.mode == "alias" && name == "b.example.test" && typ == dnsmessage.TypeA {
						addA([4]byte{192, 0, 2, 3})
					}
				}
				if tc.mode == "terminal" && name == "x.example.test" {
					if typ == dnsmessage.TypeA {
						addA([4]byte{192, 0, 2, 2})
					}
					if typ == dnsmessage.TypeAAAA {
						addAAAA([16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
					}
				}
				return m
			}
			resolver := localDNSServer(t, handler)
			timeout := time.Second
			if tc.mode == "timeout" {
				resolver = localDNSServerDropA(t, func(name string, typ dnsmessage.Type) {
					mu.Lock()
					order = append(order, []string{name, dnsTypeName(typ)})
					mu.Unlock()
				})
				timeout = 100 * time.Millisecond
			}
			c, err := NewClientWithRate([]string{resolver}, timeout, 10000)
			if err != nil {
				t.Fatal(err)
			}
			name := tc.hostname + ".example.test"
			got, err := ResolveHost(context.Background(), c, name, 8)
			if err != nil {
				t.Fatal(err)
			}
			want := fixture.Outputs.DNS[caseName]
			if !sameStrings(got.IPs, want.Resolution.IPs) || !sameStrings(got.CNAMEChain, want.Resolution.CNAMEChain) || got.TerminalName != want.Resolution.TerminalName || got.Resolved != want.Resolution.Resolved || got.DNSError != want.Resolution.DNSError {
				t.Fatalf("got %+v; source oracle %+v", got, want.Resolution)
			}
			mu.Lock()
			actualOrder := append([][]string(nil), order...)
			mu.Unlock()
			if !reflect.DeepEqual(actualOrder, want.QueryOrder) {
				t.Fatalf("actual query order %v; oracle %v", actualOrder, want.QueryOrder)
			}
			if tc.mode == "timeout" && !got.DNSError {
				t.Fatal("transport timeout was not retained as a DNS error")
			}
			if len(got.Queries) != len(want.Resolution.Queries) {
				t.Fatalf("query count %d; oracle %d", len(got.Queries), len(want.Resolution.Queries))
			}
			for i, q := range got.Queries {
				e := want.Resolution.Queries[i]
				if q.Name != e.Name || q.RType != e.RType || q.Status != e.Status {
					t.Errorf("query[%d]=%s/%s/%s; oracle=%s/%s/%s", i, q.Name, q.RType, q.Status, e.Name, e.RType, e.Status)
				}
				normalize := func(values []string) []string {
					out := make([]string, len(values))
					for i, v := range values {
						out[i] = strings.TrimSuffix(strings.ToLower(v), ".")
					}
					sort.Strings(out)
					return out
				}
				if !reflect.DeepEqual(normalize(q.Values), normalize(e.Values)) {
					t.Errorf("query[%d] values=%v; oracle=%v", i, q.Values, e.Values)
				}
				if e.TTL != nil && q.TTL != nil && *e.TTL != *q.TTL {
					t.Errorf("query[%d] TTL=%d oracle=%d", i, *q.TTL, *e.TTL)
				}
			}
		})
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func dnsTypeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	}
	return "?"
}

func TestExpandEmitsDeferredUserScopeBeforeStartingDNS(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		t.Error("DNS started before deferred sink returned")
		return dnsmessage.Message{}
	})
	c, err := NewClient([]string{resolver}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	var emitted []core.Event
	want := errors.New("stop after deferred observation")
	result, err := Expand(context.Background(), ExpansionConfig{Root: "example.test", Policy: core.ScopePolicy{AllowedDomains: []string{"example.test", "authorized.example.test"}}, Client: c, Index: idx, Budget: 1, Workers: 1, Emit: func(e core.Event) error { emitted = append(emitted, e); return want }})
	if !errors.Is(err, want) {
		t.Fatalf("Expand error=%v", err)
	}
	if len(result.Deferred) != 1 || result.Deferred[0] != "authorized.example.test" {
		t.Fatalf("user scope candidate missing from full inventory/deferred: %+v", result)
	}
	if len(emitted) != 1 || emitted[0].EventType != core.DNSValidation || emitted[0].Metadata["dns_state"] != "deferred_by_dns_budget" {
		t.Fatalf("deferred event not preserved: %+v", emitted)
	}
	if idx.ExistingValidation("authorized.example.test") != nil {
		t.Fatal("failed sink event indexed")
	}
}

func TestExpandReusesLatestValidationWithoutRevalidatingHost(t *testing.T) {
	var mu sync.Mutex
	var types []dnsmessage.Type
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		types = append(types, q.Questions[0].Type)
		mu.Unlock()
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
	})
	c, err := NewClient([]string{resolver}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	ev, err := core.NewEvent(core.DNSValidation, "domain_expansion", "dns_validation", "example.test", "example.test", core.InScope)
	if err != nil {
		t.Fatal(err)
	}
	ev.Metadata = map[string]any{"dns_state": "resolved_input_root", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.8"}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	idx.Ingest(m)
	result, err := Expand(context.Background(), ExpansionConfig{Root: "example.test", Policy: core.ScopePolicy{AllowedDomains: []string{"example.test"}}, Client: c, Index: idx, Inventory: map[string]evidence.ProviderInventoryEntry{}, Budget: 1, SkipPrevalidated: true, Emit: func(core.Event) error { return nil }})
	if err != nil {
		t.Fatalf("Expand error=%v", err)
	}
	if got := result.Reused["example.test"]; got == nil || got["dns_state"] != "resolved_input_root" {
		t.Fatalf("latest validation not reused: %#v", result.Reused)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, typ := range types {
		if typ == dnsmessage.TypeA || typ == dnsmessage.TypeAAAA || typ == dnsmessage.TypeCNAME {
			t.Fatalf("reused root was revalidated with %s: %v", dnsTypeName(typ), types)
		}
	}
}

func TestRootFallbackUsesOnlyExplicitResolverAndSharedLimiter(t *testing.T) {
	var mu sync.Mutex
	contacts := 0
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		contacts++
		mu.Unlock()
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: q.Questions}
	})
	c, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	scope := core.ScopeChecker{Policy: core.ScopePolicy{AllowedDomains: []string{"example.test"}}}
	a, err := NewWildcardAnalyzer("example.test", c, 3, 1, true, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := ExpansionConfig{Root: "example.test", Client: c, Index: idx, emitMu: &sync.Mutex{}, Emit: func(core.Event) error { return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := validateOne(ctx, cfg, scope, a, "example.test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := contacts
	mu.Unlock()
	if n < 2 {
		t.Fatalf("pure-Go root fallback did not issue resolver contacts: %d", n)
	}
	if r.Resolved {
		t.Fatalf("negative local fixture unexpectedly resolved root: %+v", r)
	}
}

func TestWildcardConcurrentReservationBudgetAndCancellation(t *testing.T) {
	var mu sync.Mutex
	contacts := 0
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		contacts++
		mu.Unlock()
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: q.Questions}
	})
	c, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewWildcardAnalyzer("example.test", c, 3, 1, true, []string{"example.test", "other.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan WildcardParentResult, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := a.AnalyzeParent(context.Background(), "example.test")
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	for r := range results {
		if r.State != "clean" || len(r.Probes) != 3 {
			t.Fatalf("unexpected cached wildcard result: %+v", r)
		}
	}
	untested, err := a.AnalyzeParent(context.Background(), "other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if untested.State != "untested" {
		t.Fatalf("budget not reserved: %+v", untested)
	}
	mu.Lock()
	got := contacts
	mu.Unlock()
	if got != 3 {
		t.Fatalf("same-parent concurrent requests made %d wire contacts, want 3", got)
	}

	b, err := NewWildcardAnalyzer("example.test", c, 3, 1, true, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = b.AnalyzeParent(ctx, "example.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe error=%v", err)
	}
	// A canceled owner must release its reservation and must not cache an inconclusive result.
	fresh, err := b.AnalyzeParent(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.State != "clean" {
		t.Fatalf("canceled probe poisoned cache: %+v", fresh)
	}
}

func TestWildcardCachedAndDisabledFastPathsHonorCancellation(t *testing.T) {
	client, err := NewClientWithRate([]string{"127.0.0.1:53"}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewWildcardAnalyzer("example.test", client, 3, 1, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AnalyzeParent(context.Background(), "example.test"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.AnalyzeParent(ctx, "example.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached analyzer fast path returned %v, want context cancellation", err)
	}
	if _, _, err := a.Classify(ctx, "host.example.test", HostResolution{Resolved: true, IPs: []string{"192.0.2.3"}}, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("classify fast path returned %v, want context cancellation", err)
	}
}

func TestValidateOneEmitsSourceCompatibleRelationsAndResolution(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		name := strings.TrimSuffix(q.Questions[0].Name.String(), ".")
		typ := q.Questions[0].Type
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if name == "asmw" {
			return m
		}
		if strings.HasPrefix(name, "asmw-") {
			m.Header.RCode = dnsmessage.RCodeNameError
			return m
		}
		if name == "a.example.test" && typ == dnsmessage.TypeCNAME {
			n, _ := dnsmessage.NewName("b.example.test.")
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: n}}}
			return m
		}
		if name == "b.example.test" && typ == dnsmessage.TypeA {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 55}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 3}}}}
			return m
		}
		return m
	})
	c, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	a, err := NewWildcardAnalyzer("example.test", c, 3, 1, true, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Client: c, Index: idx, emitMu: &sync.Mutex{}, Emit: func(e core.Event) error { mu.Lock(); events = append(events, e); mu.Unlock(); return nil }}
	r, err := validateOne(context.Background(), cfg, core.ScopeChecker{Policy: policy}, a, "example.test", "a.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Resolved || !reflect.DeepEqual(r.IPs, []string{"192.0.2.3"}) || !reflect.DeepEqual(r.CNAMEChain, []string{"b.example.test"}) {
		t.Fatalf("resolution=%+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	found := map[core.EventType]core.Event{}
	for _, ev := range events {
		found[ev.EventType] = ev
	}
	for _, typ := range []core.EventType{core.DomainFound, core.IPFound, core.DNSRecordFound, core.DNSValidation} {
		if _, ok := found[typ]; !ok {
			t.Errorf("missing event %s", typ)
		}
	}
	if rel := found[core.DomainFound].Relations; len(rel) == 0 || rel[0]["relation_type"] != "cname_to" {
		t.Errorf("CNAME relation missing: %+v", rel)
	}
	if rel := found[core.IPFound].Relations; len(rel) == 0 || rel[0]["relation_type"] != "resolves_to" {
		t.Errorf("IP relation missing: %+v", rel)
	}
	meta := found[core.DNSValidation].Metadata
	if meta["wildcard_parent_state"] != "clean" || len(meta["validation_records"].([]map[string]any)) == 0 {
		t.Errorf("validation record metadata missing: %#v", meta)
	}
	structured := meta["structured_resolution"].(map[string]any)
	signature := structured["signature"].(map[string][]string)
	if !reflect.DeepEqual(signature["A"], []string{"192.0.2.3"}) || !reflect.DeepEqual(signature["CNAME"], []string{"b.example.test"}) {
		t.Errorf("signature missing: %#v", signature)
	}
	if rel := found[core.DNSValidation].Relations; len(rel) == 0 || rel[0]["relation_type"] != "subdomain_of" {
		t.Errorf("validation subdomain relation missing: %+v", rel)
	}
}

func TestDNSValidationEventsMatchSourceOracle(t *testing.T) {
	var fixture struct {
		Outputs struct {
			Events map[string]struct {
				Events []map[string]any `json:"events"`
			} `json:"dns.events"`
		} `json:"outputs"`
	}
	raw, err := os.ReadFile("../../../testdata/phase4/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key, name, mode, state string
	}{
		{"root_terminal", "example.test", "root", ""},
		{"alias_terminal", "www.example.test", "alias", "clean"},
		{"uncertain_parent", "maybe.example.test", "uncertain", "inconclusive"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
				name, typ := strings.TrimSuffix(q.Questions[0].Name.String(), "."), q.Questions[0].Type
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
				addA := func(ip [4]byte) {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: ip}})
				}
				switch name {
				case "example.test":
					if typ == dnsmessage.TypeA {
						addA([4]byte{192, 0, 2, 10})
					}
				case "www.example.test":
					if typ == dnsmessage.TypeCNAME {
						n, _ := dnsmessage.NewName("edge.example.test.")
						m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.CNAMEResource{CNAME: n}})
					}
				case "edge.example.test":
					if typ == dnsmessage.TypeA {
						addA([4]byte{192, 0, 2, 11})
					}
				case "maybe.example.test":
					if typ == dnsmessage.TypeA {
						addA([4]byte{192, 0, 2, 12})
					}
				}
				return m
			})
			client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
			if err != nil {
				t.Fatal(err)
			}
			policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
			scope := core.ScopeChecker{Policy: policy}
			analyzer, err := NewWildcardAnalyzer("example.test", client, 3, 1, false, []string{"example.test"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.state != "" {
				analyzer.cache["example.test"] = WildcardParentResult{Parent: "example.test", State: tc.state, Probes: []HostResolution{}, WildcardValues: map[string][]string{}, Reason: map[string]string{"clean": "fixture-clean", "inconclusive": "mixed/uncertain probes"}[tc.state]}
			}
			var events []core.Event
			cfg := ExpansionConfig{Root: "example.test", Client: client, Index: evidence.NewDNSRunIndex(policy), Emit: func(e core.Event) error { events = append(events, e); return nil }}
			if _, err := validateOne(context.Background(), cfg, scope, analyzer, "example.test", tc.name); err != nil {
				t.Fatal(err)
			}
			want := fixture.Outputs.Events[tc.key].Events
			if len(events) != len(want) {
				t.Fatalf("events=%d source oracle=%d", len(events), len(want))
			}
			for i, ev := range events {
				got := eventOracleShape(t, ev)
				wantShape := oracleEventShape(want[i])
				if !reflect.DeepEqual(got, wantShape) {
					t.Errorf("event[%d] differs from source oracle\n got: %#v\nwant: %#v", i, got, wantShape)
				}
				if metadata, ok := want[i]["metadata"].(map[string]any); ok {
					if expected, ok := metadata["structured_resolution"].(map[string]any); ok {
						actual, ok := ev.Metadata["structured_resolution"].(map[string]any)
						if !ok || !sameStructuredSemantics(actual, expected) {
							t.Errorf("event[%d] structured resolution semantics differ from source oracle: got=%#v want=%#v", i, actual, expected)
						}
					}
				}
			}
		})
	}
}

func sameStructuredSemantics(got, want map[string]any) bool {
	for _, key := range []string{"hostname", "ips", "cname_chain", "terminal_name", "resolved", "dns_error", "signature"} {
		if !sameJSONValue(got[key], want[key]) {
			return false
		}
	}
	return true
}

func TestValidateQuickFreshAndResumeAvoidsRepeatedDNS(t *testing.T) {
	var mu sync.Mutex
	queries := 0
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		queries++
		mu.Unlock()
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if q.Questions[0].Type == dnsmessage.TypeA {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}})
		}
		return m
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: idx, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	fresh, err := ValidateQuick(context.Background(), cfg, nil, "EXAMPLE.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Validated || !fresh.Eligible || fresh.DNSState != "resolved_input_root" || len(fresh.IPs) != 1 || len(fresh.Records) != 1 {
		t.Fatalf("unexpected fresh validation: %+v", fresh)
	}
	mu.Lock()
	firstQueries := queries
	mu.Unlock()
	firstEvents := len(events)
	if firstEvents != 3 {
		t.Fatalf("fresh validation emitted %d events, want IP, record and validation", firstEvents)
	}
	resumed, err := ValidateQuick(context.Background(), cfg, nil, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Reused || resumed.DNSState != fresh.DNSState || !resumed.Eligible || !reflect.DeepEqual(resumed.IPs, fresh.IPs) || !sameJSONValue(resumed.Records, fresh.Records) {
		t.Fatalf("resume did not reuse prior result: fresh=%+v resumed=%+v", fresh, resumed)
	}
	mu.Lock()
	finalQueries := queries
	mu.Unlock()
	if finalQueries != firstQueries || len(events) != firstEvents {
		t.Fatalf("resume repeated work: queries %d→%d, events %d→%d", firstQueries, finalQueries, firstEvents, len(events))
	}
	if got := resumed.Map(); got["reused"] != true || got["eligible"] != true {
		t.Fatalf("legacy quick result map missing caller fields: %#v", got)
	}
}

func TestValidateQuickRootFallbackRecordsSurviveResume(t *testing.T) {
	var mu sync.Mutex
	queries := 0
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		queries++
		count := queries
		mu.Unlock()
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if count > 3 && q.Questions[0].Type == dnsmessage.TypeA {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}}})
		}
		return m
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: idx, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	fresh, err := ValidateQuick(context.Background(), cfg, nil, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Validated || !fresh.Eligible || len(fresh.IPs) != 1 || fresh.IPs[0] != "192.0.2.42" {
		t.Fatalf("root fallback did not validate: %+v", fresh)
	}
	if len(fresh.Records) != 1 || fresh.Records[0]["type"] != "SYSTEM" || fresh.Records[0]["value"] != "192.0.2.42" {
		t.Fatalf("fallback record absent from quick result: %#v", fresh.Records)
	}
	if fresh.Records[0]["resolver"] != resolver || fresh.Records[0]["resolver_backend"] != ResolverBackend {
		t.Fatalf("fallback record has inaccurate resolver provenance: %#v", fresh.Records[0])
	}
	var fallbackEvent *core.Event
	for i := range events {
		if events[i].SourceTool == "system_resolver" {
			fallbackEvent = &events[i]
			break
		}
	}
	if fallbackEvent == nil || fallbackEvent.Confidence != .8 || len(fallbackEvent.Relations) != 1 || fallbackEvent.Relations[0]["relation_type"] != "resolves_to" || fallbackEvent.Relations[0]["evidence"].(map[string]any)["record_type"] != "system_resolver" || fallbackEvent.Metadata["collection"] != "public_dns_or_hosts" || fallbackEvent.Metadata["target_service_contacted"] != false {
		t.Fatalf("root fallback event differs from source shape: %+v", fallbackEvent)
	}
	indexed := idx.ExistingValidation("example.test")
	indexedRecords := quickMapList(indexed["validation_records"])
	if len(indexedRecords) != 1 || indexedRecords[0]["type"] != "SYSTEM" {
		t.Fatalf("fallback record absent from reusable validation event: %#v", indexedRecords)
	}
	var firstQueries int
	mu.Lock()
	firstQueries = queries
	mu.Unlock()
	firstEvents := len(events)
	resumed, err := ValidateQuick(context.Background(), cfg, nil, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Reused || !reflect.DeepEqual(resumed.IPs, fresh.IPs) || !sameJSONValue(resumed.Records, fresh.Records) {
		t.Fatalf("fallback resume mismatch: fresh=%+v resumed=%+v", fresh, resumed)
	}
	mu.Lock()
	finalQueries := queries
	mu.Unlock()
	if firstQueries != finalQueries || firstEvents != len(events) {
		t.Fatalf("fallback resume repeated work: queries %d→%d, events %d→%d", firstQueries, finalQueries, firstEvents, len(events))
	}
}

func TestValidateQuickUnresolvedMapUsesEmptySlices(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: evidence.NewDNSRunIndex(policy), Emit: func(core.Event) error { return nil }}
	result, err := ValidateQuick(context.Background(), cfg, nil, "none.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Validated || result.Eligible {
		t.Fatalf("empty target marked valid or eligible: %+v", result)
	}
	mapped := result.Map()
	if ips, ok := mapped["ips"].([]string); !ok || ips == nil || len(ips) != 0 {
		t.Fatalf("legacy quick ips projection is not an empty list: %#v", mapped["ips"])
	}
	if records, ok := mapped["records"].([]map[string]any); !ok || records == nil || len(records) != 0 {
		t.Fatalf("legacy quick records projection is not an empty list: %#v", mapped["records"])
	}
}

func TestDeferredValidationEventRetainsSourceCollection(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if q.Questions[0].Type == dnsmessage.TypeA {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}})
		}
		return m
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: evidence.NewDNSRunIndex(policy), Inventory: map[string]evidence.ProviderInventoryEntry{"deferred.example.test": {Hostname: "deferred.example.test", Providers: []string{"test"}, FirstSeenByProvider: map[string]string{}, Observations: 1}}, Budget: 1, Workers: 1, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	if _, err := Expand(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	budgetSummary := false
	for _, ev := range events {
		if ev.EventType == core.DNSValidation && ev.Metadata["dns_state"] == "deferred_by_dns_budget" {
			found = true
			if ev.Metadata["collection"] != "public_dns" {
				t.Errorf("deferred source metadata missing collection: %#v", ev.Metadata)
			}
		}
		if ev.EventType == core.Limitation && ev.SourceTool == "dns_budget" {
			budgetSummary = true
			if ev.Confidence != 1 || ev.Metadata["severity"] != "info" || ev.Metadata["deferred_by_dns_budget"] != 1 {
				t.Errorf("budget summary source shape mismatch: %+v", ev)
			}
		}
	}
	if !found {
		t.Fatalf("no deferred validation emitted: %+v", events)
	}
	if !budgetSummary {
		t.Fatalf("no source-shaped deferred budget summary: %+v", events)
	}
}

func TestExpandPreCancelledContextDoesNotEmitDeferredCandidates(t *testing.T) {
	client, err := NewClientWithRate([]string{"127.0.0.1:53"}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	var events []core.Event
	cfg := ExpansionConfig{
		Root: "example.test", Policy: policy, Client: client,
		Index: evidence.NewDNSRunIndex(policy),
		Inventory: map[string]evidence.ProviderInventoryEntry{
			"deferred.example.test": {Hostname: "deferred.example.test", Providers: []string{"test"}, FirstSeenByProvider: map[string]string{}, Observations: 1},
		},
		Budget: 1, Workers: 1,
		Emit: func(ev core.Event) error { events = append(events, ev); return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Expand(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if len(events) != 0 {
		t.Fatalf("pre-cancelled expansion emitted %d events: %+v", len(events), events)
	}
}

func TestExpandCancellationDuringLastBudgetLimitationReturnsContextError(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	var events []core.Event
	ctx, cancel := context.WithCancel(context.Background())
	cfg := ExpansionConfig{
		Root: "example.test", Policy: policy, Client: client,
		Index: evidence.NewDNSRunIndex(policy),
		Inventory: map[string]evidence.ProviderInventoryEntry{
			"deferred.example.test": {Hostname: "deferred.example.test", Providers: []string{"test"}, FirstSeenByProvider: map[string]string{}, Observations: 1},
		},
		Budget: 1, Workers: 1,
		Emit: func(ev core.Event) error {
			events = append(events, ev)
			if ev.EventType == core.Limitation && ev.SourceTool == "dns_budget" {
				cancel()
			}
			return nil
		},
	}
	if _, err := Expand(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if len(events) == 0 || events[len(events)-1].EventType != core.Limitation || events[len(events)-1].SourceTool != "dns_budget" {
		t.Fatalf("budget limitation was not durably emitted before cancellation: %+v", events)
	}
}

func TestValidateQuickPreCancelledContextDoesNotReuseValidation(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{
		"event_type": "dns_validation", "normalized_value": "host.example.test",
		"observed_at": "2025-01-01T00:00:00Z",
		"metadata":    map[string]any{"dns_state": "resolved_clean_parent", "terminal_ips": []any{"192.0.2.3"}, "active_eligibility": "eligible"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ValidateQuick(ctx, ExpansionConfig{Root: "example.test", Policy: policy, Index: idx}, nil, "host.example.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
}

func TestRootNoRecordLimitationKeepsSourceConfidence(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: evidence.NewDNSRunIndex(policy), Workers: 1, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	if _, err := Expand(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.EventType == core.Limitation && ev.SourceTool == "dns" && ev.RawValue == "No public DNS records were found for the root domain" {
			if ev.Confidence != 1 || ev.Metadata["severity"] != "error" || ev.Metadata["action"] != "check_target_spelling" || ev.Metadata["target_service_contacted"] != false {
				t.Fatalf("root limitation source shape mismatch: %+v", ev)
			}
			return
		}
	}
	t.Fatalf("root without DNS data did not emit source limitation: %+v", events)
}

func TestEnrichmentCancellationAtASNDescriptionStopsEvents(t *testing.T) {
	descStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		name, typ := strings.TrimSuffix(q.Questions[0].Name.String(), "."), q.Questions[0].Type
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		addTXT := func(value string) {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{value}}})
		}
		switch {
		case typ == dnsmessage.TypePTR && name == "11.2.0.192.in-addr.arpa":
			n, _ := dnsmessage.NewName("host.example.test.")
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.PTRResource{PTR: n}})
		case typ == dnsmessage.TypeTXT && name == "11.2.0.192.origin.asn.cymru.com":
			addTXT("64500 64501 | 192.0.2.0/24 | ZZ | arin | 2020-01-01")
		case typ == dnsmessage.TypeTXT && name == "as64500.asn.cymru.com":
			select {
			case descStarted <- struct{}{}:
			default:
			}
			<-release
			addTXT("64500 | ZZ | Example Provider | 2020-01-01 | Example AS")
		}
		return m
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{"event_type": "ip_found", "normalized_value": "192.0.2.11", "metadata": map[string]any{"domain": "host.example.test"}})
	var events []core.Event
	cfg := ExpansionConfig{Client: client, Index: idx, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := collectRootAndEnrichment(ctx, cfg, core.ScopeChecker{Policy: policy}, "example.test")
		result <- err
	}()
	select {
	case <-descStarted:
		cancel()
		close(release)
	case err := <-result:
		close(release)
		t.Fatalf("enrichment returned before the blocked description query: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		close(release)
		t.Fatal("ASN description query did not begin")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enrichment did not stop on parent cancellation")
	}
	for _, ev := range events {
		if ev.EventType == core.ASNFound || ev.EventType == core.CIDRFound {
			t.Fatalf("post-cancel ASN/CIDR event emitted: %+v", ev)
		}
	}
}

func TestCNAMEUnicodeRDATAIsNeverCanonicalizedIntoContactOrEligibility(t *testing.T) {
	var mu sync.Mutex
	var queried []string
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		name := strings.TrimSuffix(q.Questions[0].Name.String(), ".")
		mu.Lock()
		queried = append(queried, name)
		mu.Unlock()
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if name == "www.example.test" && q.Questions[0].Type == dnsmessage.TypeCNAME {
			alias, err := dnsmessage.NewName("K.example.test.")
			if err != nil {
				t.Errorf("fixture CNAME name: %v", err)
				return m
			}
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.CNAMEResource{CNAME: alias}})
		}
		if (name == "k.example.test" || name == "K.example.test") && q.Questions[0].Type == dnsmessage.TypeA {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 99}}})
		}
		return m
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	analyzer, err := NewWildcardAnalyzer("example.test", client, 3, 1, false, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: idx, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	r, err := validateOne(context.Background(), cfg, core.ScopeChecker{Policy: policy}, analyzer, "example.test", "www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.IPs) != 0 || r.Resolved {
		t.Fatalf("non-ASCII wire alias became an active resolution: %+v", r)
	}
	for _, q := range r.Queries {
		if q.Name == "k.example.test" || q.Name == "K.example.test" {
			t.Fatalf("canonicalized alias was queried: %+v", r.Queries)
		}
	}
	mu.Lock()
	for _, name := range queried {
		if name == "k.example.test" || name == "K.example.test" {
			mu.Unlock()
			t.Fatalf("fixture received query for wire alias %q", name)
		}
	}
	mu.Unlock()
	for _, ev := range events {
		if ev.EventType == core.IPFound {
			t.Fatalf("non-ASCII wire alias admitted an IP event: %+v", ev)
		}
		if ev.EventType == core.DNSValidation && strings.HasPrefix(fmt.Sprint(ev.Metadata["active_eligibility"]), "eligible") {
			t.Fatalf("non-ASCII wire alias became eligible: %+v", ev)
		}
	}
}

func sameJSONValue(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && reflect.DeepEqual(x, y)
}

func TestRootFallbackCancellationDoesNotEmitValidation(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	requests := 0
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		mu.Lock()
		requests++
		n := requests
		mu.Unlock()
		if n > 3 {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
		}
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	analyzer, err := NewWildcardAnalyzer("example.test", client, 3, 1, false, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var events []core.Event
	cfg := ExpansionConfig{Root: "example.test", Client: client, Index: evidence.NewDNSRunIndex(policy), Emit: func(e core.Event) error { events = append(events, e); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := validateOne(ctx, cfg, core.ScopeChecker{Policy: policy}, analyzer, "example.test", "example.test")
		result <- err
	}()
	select {
	case <-started:
		cancel()
		close(release)
	case err := <-result:
		close(release)
		t.Fatalf("root fallback did not begin before return: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		close(release)
		t.Fatal("root fallback did not issue its local resolver query")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("validation did not stop after parent cancellation")
	}
	for _, ev := range events {
		if ev.EventType == core.DNSValidation {
			t.Fatal("cancelled root was emitted as validated")
		}
	}
}

func TestRootEnrichmentPTRAndASNUseLocalDNSFixture(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		name, typ := strings.TrimSuffix(q.Questions[0].Name.String(), "."), q.Questions[0].Type
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if typ == dnsmessage.TypePTR && name == "11.2.0.192.in-addr.arpa" {
			n, _ := dnsmessage.NewName("host.example.test.")
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.PTRResource{PTR: n}})
		}
		if typ == dnsmessage.TypeTXT && name == "11.2.0.192.origin.asn.cymru.com" {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"64500 64501 | 192.0.2.0/24 | ZZ | arin | 2020-01-01"}}})
		}
		if typ == dnsmessage.TypeTXT && name == "as64500.asn.cymru.com" {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"64500 | ZZ | Example Provider | 2020-01-01 | Example AS"}}})
		}
		return m
	})
	client, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{"event_type": "ip_found", "normalized_value": "192.0.2.11", "metadata": map[string]any{"domain": "host.example.test"}})
	var events []core.Event
	cfg := ExpansionConfig{Client: client, Index: idx, Emit: func(e core.Event) error { events = append(events, e); return nil }}
	if _, err := collectRootAndEnrichment(context.Background(), cfg, core.ScopeChecker{Policy: policy}, "example.test"); err != nil {
		t.Fatal(err)
	}
	has := map[core.EventType]bool{}
	for _, ev := range events {
		has[ev.EventType] = true
	}
	for _, typ := range []core.EventType{core.DNSRecordFound, core.DomainFound, core.ASNFound, core.CIDRFound} {
		if !has[typ] {
			t.Errorf("fixture did not produce %s; events=%+v", typ, events)
		}
	}
	for _, ev := range events {
		if ev.EventType == core.ASNFound && (ev.NormalizedValue != "AS64500" || ev.ScopeStatus != core.NeedsManualReview || ev.Metadata["routing_context_not_ownership"] != true) {
			t.Errorf("unsafe ASN attribution semantics: %+v", ev)
		}
		if ev.EventType == core.ASNFound {
			wantRaw := map[string]any{"country": "ZZ", "registry": "arin", "allocated": "2020-01-01", "raw": "64500 64501 | 192.0.2.0/24 | ZZ | arin | 2020-01-01", "resolver": resolver, "routing_context_not_ownership": true, "as_name": "Example AS"}
			if !sameJSONValue(ev.RawValue, wantRaw) {
				t.Errorf("ASN raw metadata mismatch: %#v", ev.RawValue)
			}
			if ev.Confidence != .7 || ev.Relations[0]["relation_type"] != "announced_by" || ev.Metadata["collection"] != "passive_osint" || ev.Metadata["target_contacted"] != false || ev.Metadata["ip"] != "192.0.2.11" || ev.Metadata["as_name"] != "Example AS" {
				t.Errorf("ASN event source shape mismatch: %+v", ev)
			}
		}
		if ev.EventType == core.CIDRFound {
			if ev.NormalizedValue != "192.0.2.0/24" || ev.Confidence != .65 || ev.Relations[0]["relation_type"] != "contained_in" || ev.Metadata["collection"] != "passive_osint" || ev.Metadata["target_contacted"] != false || ev.Metadata["asn"] != "AS64500" {
				t.Errorf("CIDR event source shape mismatch: %+v", ev)
			}
		}
		if ev.EventType == core.DNSRecordFound {
			if record, ok := ev.NormalizedValue.(map[string]any); ok && record["type"] == "PTR" && (record["value"] != "host.example.test" || record["name"] != "192.0.2.11") {
				t.Errorf("PTR observation mismatch: %#v", record)
			}
			if record, ok := ev.NormalizedValue.(map[string]any); ok && record["type"] == "PTR" {
				if ev.Confidence != .55 || ev.Relations[0]["relation_type"] != "reverse_dns" || ev.ScopeStatus != core.InScope || ev.Metadata["collection"] != "public_dns" || ev.Metadata["target_service_contacted"] != false {
					t.Errorf("PTR event source shape mismatch: %+v", ev)
				}
			}
		}
	}
}

func oracleEventShape(source map[string]any) map[string]any {
	copy := make(map[string]any, len(source))
	for k, v := range source {
		copy[k] = v
	}
	if metadata, ok := copy["metadata"].(map[string]any); ok {
		metadataCopy := make(map[string]any, len(metadata))
		for k, v := range metadata {
			metadataCopy[k] = v
		}
		delete(metadataCopy, "structured_resolution") // separately covered by dns.resolve_host source replay
		copy["metadata"] = metadataCopy
	}
	return copy
}

func eventOracleShape(t *testing.T, ev core.Event) map[string]any {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	delete(out, "event_id")
	delete(out, "observed_at")
	delete(out, "observed_at_local")
	normalizeOracleResolvers(out)
	omitBackendProvenance(out)
	if metadata, ok := out["metadata"].(map[string]any); ok {
		delete(metadata, "structured_resolution") // validated separately against dns.resolve_host oracle
	}
	return out
}

func omitBackendProvenance(v any) {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "resolver_backend")
		for _, child := range x {
			omitBackendProvenance(child)
		}
	case []any:
		for _, child := range x {
			omitBackendProvenance(child)
		}
	}
}

func normalizeOracleResolvers(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if k == "resolver" {
				if _, ok := child.(string); ok {
					x[k] = "fixture"
					continue
				}
			}
			normalizeOracleResolvers(child)
		}
	case []any:
		for _, child := range x {
			normalizeOracleResolvers(child)
		}
	}
}

func TestResolveHostStopsAtEightCNAMEEdges(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		name := strings.TrimSuffix(q.Questions[0].Name.String(), ".")
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		if q.Questions[0].Type == dnsmessage.TypeCNAME {
			next := ""
			if name == "depth.example.test" {
				next = "d1.example.test"
			} else if strings.HasPrefix(name, "d") {
				var n int
				_, _ = fmt.Sscanf(name, "d%d.example.test", &n)
				if n < 9 {
					next = fmt.Sprintf("d%d.example.test", n+1)
				}
			}
			if next != "" {
				cn, _ := dnsmessage.NewName(next + ".")
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.CNAMEResource{CNAME: cn}}}
			}
		}
		return m
	})
	c, err := NewClientWithRate([]string{resolver}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ResolveHost(context.Background(), c, "depth.example.test", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.CNAMEChain) != 8 || r.TerminalName != "d8.example.test" || !r.DNSError {
		t.Fatalf("CNAME depth not bounded at eight: %+v", r)
	}
	if len(r.Queries) != 27 {
		t.Fatalf("queried past CNAME depth limit: got %d RR queries", len(r.Queries))
	}
}
