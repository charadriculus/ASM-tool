package dns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"golang.org/x/net/dns/dnsmessage"
)

func TestValidateQuickRejectsNearMatchEligibilityFromIndex(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "x.example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible_but_not_eligible", "terminal_ips": []any{"192.0.2.1"}}})
	got, err := ValidateQuick(context.Background(), ExpansionConfig{Root: "example.test", Policy: policy, Index: idx}, nil, "x.example.test")
	if err != nil || got.Eligible || got.ActiveEligibility != "eligible_but_not_eligible" {
		t.Fatalf("near-match eligibility accepted: result=%+v err=%v", got, err)
	}
}

func TestValidateQuickSharesWildcardParentBudgetAcrossDynamicCandidates(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var siblingQueries atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := conn.ReadFrom(buf)
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
				if q.Type == dnsmessage.TypeA && strings.HasPrefix(q.Name.String(), "asmw-") {
					siblingQueries.Add(1)
				}
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
				if q.Type == dnsmessage.TypeA && !strings.HasPrefix(q.Name.String(), "asmw-") {
					m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}}}
				}
				out, e := m.Pack()
				if e == nil {
					_, _ = conn.WriteTo(out, addr)
				}
			}()
		}
	}()
	client, err := NewClientWithRate([]string{conn.LocalAddr().String()}, time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	analyzer, err := NewWildcardAnalyzer("example.test", client, 3, 1, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ExpansionConfig{Root: "example.test", Policy: policy, Client: client, Index: idx, Emit: func(core.Event) error { return nil }, WildcardEnabled: true, WildcardProbes: 3, WildcardParentBudget: 1}
	first, err := ValidateQuick(context.Background(), cfg, analyzer, "a.example.test")
	if err != nil || !first.Validated {
		t.Fatalf("first quick validation=%+v err=%v", first, err)
	}
	second, err := ValidateQuick(context.Background(), cfg, analyzer, "b.other.example.test")
	if err != nil || second.Eligible || second.WildcardParentState == nil || *second.WildcardParentState != "untested" {
		t.Fatalf("second parent bypassed shared budget: result=%+v err=%v", second, err)
	}
	if got := siblingQueries.Load(); got != 3 {
		t.Fatalf("wildcard sibling DNS queries=%d want exactly 3 under shared parent budget", got)
	}
}
