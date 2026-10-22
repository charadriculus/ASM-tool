package app

import (
	"context"
	"testing"

	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/evidence"
)

func TestDynamicAdmissionFiltersAndDeduplicatesHTMLDomains(t *testing.T) {
	root := "example.test"
	policy := core.ScopePolicy{AllowedDomains: []string{root}}
	index := evidence.NewDNSRunIndex(policy)
	client, err := dns.NewClient([]string{"127.0.0.1:53"}, 1000000000)
	if err != nil {
		t.Fatal(err)
	}
	var events []core.Event
	var got []string
	admission, err := newDynamicDomainAdmission(root, dynamicTestPolicy(), policy, 1,
		dns.ExpansionConfig{Index: index, Client: client, Emit: func(ev core.Event) error { events = append(events, ev); return nil }},
		func(_ context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
			for name := range cfg.Inventory {
				got = append(got, name)
				index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": name, "metadata": map[string]any{"dns_state": "resolved_input_root", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.8"}}})
				index.Ingest(map[string]any{"event_type": "ip_found", "normalized_value": "192.0.2.8", "metadata": map[string]any{"domain": name}})
			}
			return dns.ExpansionResult{Selected: append([]string{root}, got...)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	result, err := admission.Admit(context.Background(), []string{"WWW.Example.Test.", "www.example.test", "example.test", "example.test.evil", "outside.test", "not a domain"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || len(result.Targets) != 1 || result.Targets[0].Domain != "www.example.test" {
		t.Fatalf("unexpected admitted result: %+v", result)
	}
	if len(got) != 1 || got[0] != "www.example.test" {
		t.Fatalf("DNS admission received unfiltered candidates: %v", got)
	}
	if len(events) != 0 {
		t.Fatalf("unexpected limitation for fully admitted candidates: %v", events)
	}
}

func TestDynamicAdmissionPreservesRunDNSAndNewDomainBudgets(t *testing.T) {
	root := "example.test"
	policy := core.ScopePolicy{AllowedDomains: []string{root}}
	index := evidence.NewDNSRunIndex(policy)
	client, err := dns.NewClient([]string{"127.0.0.1:53"}, 1000000000)
	if err != nil {
		t.Fatal(err)
	}
	collection := dynamicTestPolicy()
	collection.DNSCandidateBudget = 3 // initial root already consumed one candidate
	collection.DynamicDiscoveryMaxNewDomains = 10
	var admitted []string
	var events []core.Event
	admission, err := newDynamicDomainAdmission(root, collection, policy, 1,
		dns.ExpansionConfig{Index: index, Client: client, Emit: func(ev core.Event) error { events = append(events, ev); return nil }},
		func(_ context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
			names := make([]string, 0, len(cfg.Inventory))
			for name := range cfg.Inventory {
				names = append(names, name)
				admitted = append(admitted, name)
				index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": name, "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.9"}}})
				index.Ingest(map[string]any{"event_type": "ip_found", "normalized_value": "192.0.2.9", "metadata": map[string]any{"domain": name}})
			}
			return dns.ExpansionResult{Selected: append([]string{root}, names...)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	result, err := admission.Admit(context.Background(), []string{"a.example.test", "b.example.test", "c.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Deferred != 1 || !result.BudgetExhausted {
		t.Fatalf("DNS budget was not reflected: %+v", result)
	}
	if len(admitted) != 2 || len(result.Targets) != 2 {
		t.Fatalf("DNS budget admitted unexpected targets: got %v result=%+v", admitted, result)
	}
	if len(events) != 1 || events[0].EventType != core.Limitation || events[0].Metadata["severity"] != "warning" {
		t.Fatalf("deferred candidates need durable incomplete evidence: %+v", events)
	}
}

func TestDynamicAdmissionEnforcesRoundLimitAndCancellation(t *testing.T) {
	root := "example.test"
	policy := core.ScopePolicy{AllowedDomains: []string{root}}
	index := evidence.NewDNSRunIndex(policy)
	client, err := dns.NewClient([]string{"127.0.0.1:53"}, 1000000000)
	if err != nil {
		t.Fatal(err)
	}
	collection := dynamicTestPolicy()
	collection.DynamicDiscoveryMaxRounds = 1
	expand := func(_ context.Context, cfg dns.ExpansionConfig) (dns.ExpansionResult, error) {
		names := make([]string, 0, len(cfg.Inventory))
		for name := range cfg.Inventory {
			names = append(names, name)
			index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": name, "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"192.0.2.10"}}})
			index.Ingest(map[string]any{"event_type": "ip_found", "normalized_value": "192.0.2.10", "metadata": map[string]any{"domain": name}})
		}
		return dns.ExpansionResult{Selected: append([]string{root}, names...)}, nil
	}
	var events []core.Event
	admission, err := newDynamicDomainAdmission(root, collection, policy, 1,
		dns.ExpansionConfig{Index: index, Client: client, Emit: func(ev core.Event) error { events = append(events, ev); return nil }}, expand)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Admit(context.Background(), []string{"one.example.test"}); err != nil {
		t.Fatal(err)
	}
	second, err := admission.Admit(context.Background(), []string{"two.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !second.RoundLimit || len(second.Targets) != 0 || len(events) != 1 || events[0].Metadata["status"] != "dynamic_discovery_round_limit" {
		t.Fatalf("round limit was not enforced visibly: result=%+v events=%+v", second, events)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admission.Admit(cancelled, []string{"three.example.test"}); err == nil {
		t.Fatal("cancelled admission unexpectedly continued")
	}
}

func dynamicTestPolicy() config.CollectionPolicy {
	return config.CollectionPolicy{DNSCandidateBudget: 10, DynamicDiscoveryMaxRounds: 3, DynamicDiscoveryMaxNewDomains: 5, DynamicDiscoveryFromHTML: true, WildcardEnabled: false}
}
