package evidence

import (
	"asmtool/internal/core"
	"errors"
	"sort"
	"sync"
)

type ProviderInventoryEntry struct {
	Hostname            string            `json:"hostname"`
	Providers           []string          `json:"providers"`
	Collectors          []string          `json:"collectors"`
	EvidenceFamilies    []string          `json:"evidence_families"`
	FirstSeenByProvider map[string]string `json:"first_seen_by_provider"`
	Observations        int               `json:"observations"`
	InputTarget         bool              `json:"input_target"`
}

// ProviderInventoryAccumulator owns the live and post-hoc provider attribution policy.
// Callers should add observations only after their durable event sink accepts them.
type ProviderInventoryAccumulator struct {
	mu  sync.RWMutex
	acc *providerInventoryAccumulator
}

func NewProviderInventoryAccumulator(root string) (*ProviderInventoryAccumulator, error) {
	normalized, err := core.NormalizeDomain(root)
	if err != nil {
		return nil, err
	}
	acc := newProviderInventoryAccumulator(normalized)
	acc.ensureRoot()
	return &ProviderInventoryAccumulator{acc: acc}, nil
}

func (a *ProviderInventoryAccumulator) Contains(host string) bool {
	if a == nil || a.acc == nil {
		return false
	}
	normalized, err := core.NormalizeDomain(host)
	if err != nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.acc.items[normalized]
	return ok
}

func (a *ProviderInventoryAccumulator) Len() int {
	if a == nil || a.acc == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.acc.items)
}

// AddObservation applies the same root/scope/type filtering and attribution as JSONL replay.
func (a *ProviderInventoryAccumulator) AddObservation(host string, eventType core.EventType, status core.ScopeStatus, metadata map[string]any) error {
	if a == nil || a.acc == nil {
		return errors.New("nil provider inventory accumulator")
	}
	event := map[string]any{"event_type": string(eventType), "scope_status": string(status), "normalized_value": host, "metadata": metadata}
	a.mu.Lock()
	a.acc.add(event)
	a.mu.Unlock()
	return nil
}

// AddEvent applies an already accepted durable event using the same rules as replay.
func (a *ProviderInventoryAccumulator) AddEvent(event core.Event) error {
	if a == nil || a.acc == nil {
		return errors.New("nil provider inventory accumulator")
	}
	a.mu.Lock()
	a.acc.add(map[string]any{
		"event_type": string(event.EventType), "scope_status": string(event.ScopeStatus),
		"normalized_value": event.NormalizedValue, "metadata": event.Metadata,
	})
	a.mu.Unlock()
	return nil
}

func (a *ProviderInventoryAccumulator) Snapshot() map[string]ProviderInventoryEntry {
	if a == nil || a.acc == nil {
		return map[string]ProviderInventoryEntry{}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.acc.typed()
}

// ProviderInventory and Inventory share one policy accumulator; the path API streams records.
func ProviderInventory(events []map[string]any, root string) (map[string]ProviderInventoryEntry, error) {
	normalizedRoot, err := core.NormalizeDomain(root)
	if err != nil {
		return nil, err
	}
	acc := newProviderInventoryAccumulator(normalizedRoot)
	for _, event := range events {
		acc.add(event)
	}
	return acc.typed(), nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for value := range m {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
