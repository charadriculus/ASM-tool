package dns

import (
	"context"
	"errors"
	"sync"
	"testing"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

func validationEvent(t *testing.T) core.Event {
	t.Helper()
	e, err := core.NewEvent(core.DNSValidation, "domain_expansion", "dns", "a.example.test", "a.example.test", core.InScope)
	if err != nil {
		t.Fatal(err)
	}
	e.Metadata = map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"203.0.113.10"}}
	return e
}

func TestValidationObserverRunsAfterDurableIndexAndOutsideEmitLock(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	idx := evidence.NewDNSRunIndex(policy)
	mu := &sync.Mutex{}
	called := false
	cfg := ExpansionConfig{Index: idx, emitMu: mu, Emit: func(core.Event) error { return nil }, OnValidationIndexed: func(_ context.Context, _ core.Event) error {
		if !mu.TryLock() {
			t.Fatal("observer called while DNS emit mutex held")
		}
		mu.Unlock()
		meta := idx.ExistingValidation("a.example.test")
		if meta == nil || meta["active_eligibility"] != "eligible" {
			t.Fatal("observer ran before index ingestion")
		}
		called = true
		return nil
	}}
	if err := cfg.emit(context.Background(), validationEvent(t)); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("validation observer not called")
	}
	if idx.EventsIndexed != 1 {
		t.Fatalf("event ingested %d times", idx.EventsIndexed)
	}
}

func TestValidationObserverFailureFollowsCommit(t *testing.T) {
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	want := errors.New("observer failed")
	cfg := ExpansionConfig{Index: idx, Emit: func(core.Event) error { return nil }, OnValidationIndexed: func(context.Context, core.Event) error { return want }}
	if err := cfg.emit(context.Background(), validationEvent(t)); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	if idx.ExistingValidation("a.example.test") == nil || idx.EventsIndexed != 1 {
		t.Fatal("committed DNS validation was rolled back")
	}
}

func TestValidationObserverNotCalledWhenDurableSinkFails(t *testing.T) {
	idx := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	want := errors.New("sink failure")
	called := false
	cfg := ExpansionConfig{Index: idx, Emit: func(core.Event) error { return want }, OnValidationIndexed: func(context.Context, core.Event) error { called = true; return nil }}
	if err := cfg.emit(context.Background(), validationEvent(t)); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	if called || idx.ExistingValidation("a.example.test") != nil || idx.EventsIndexed != 0 {
		t.Fatal("failed sink event was observed or indexed")
	}
}
