package status

import (
	"asmtool/internal/backends"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ptr(n int) *int { return &n }
func TestWorkerSourceSemanticsAndTerminalStop(t *testing.T) {
	s, e := New(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.UpdateWorker("old", "dns", "first", "old.example", "", "running", "", ptr(5), ptr(9), true); e != nil {
		t.Fatal(e)
	}
	if e = s.UpdateWorker("new", "dns", "second", "new.example", "", "running", "", ptr(2), ptr(3), true); e != nil {
		t.Fatal(e)
	}
	if e = s.Update(map[string]any{"message": "kept"}, false); e != nil {
		t.Fatal(e)
	}
	if e = s.ClearWorker("new", ""); e != nil {
		t.Fatal(e)
	}
	if got := s.Snapshot()["message"]; got != "kept" {
		t.Fatalf("empty ClearWorker message changed stored message: %#v", got)
	}
	if got := s.Snapshot()["current_operation"]; got != "first" {
		t.Fatalf("clear did not select most recent active worker: %v", got)
	}
	if e = s.UpdateWorker("old", "dns", "first", "old.example", "", "running", "", ptr(3), nil, true); e != nil {
		t.Fatal(e)
	}
	w := s.Snapshot()["workers"].(map[string]any)["old"].(map[string]any)
	if w["completed"] != 3 || w["planned"] != nil {
		t.Fatalf("worker counters do not match source replacement semantics: %#v", w)
	}
	if e = s.UpdateWorker("old", "dns", "next", "new.example", "", "running", "", nil, nil, true); e != nil {
		t.Fatal(e)
	}
	w = s.Snapshot()["workers"].(map[string]any)["old"].(map[string]any)
	if w["completed"] != nil || w["planned"] != nil {
		t.Fatalf("operation change failed to clear nil counters: %#v", w)
	}
	if e = s.Update(map[string]any{"state": "complete"}, false); e != nil {
		t.Fatal(e)
	}
	select {
	case <-s.done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("terminal update left heartbeat running")
	}
	if e = s.ClearWorker("old", ""); e == nil {
		t.Fatal("terminal status accepted worker cleanup")
	}
	if e = s.Update(map[string]any{"message": "late"}, false); e == nil {
		t.Fatal("terminal status accepted update")
	}
	if e = s.Finish("complete", ""); e == nil {
		t.Fatal("Finish overwrote terminal update")
	}
}

func TestAtomicStatusAndSnapshotAreDetached(t *testing.T) {
	dir := t.TempDir()
	s, e := New(dir, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	nested := map[string]any{"worker": "before"}
	if e = s.Update(map[string]any{"custom": nested, "ignored": nil}, true); e != nil {
		t.Fatal(e)
	}
	nested["worker"] = "after"
	snap := s.Snapshot()
	if snap["custom"].(map[string]any)["worker"] != "before" {
		t.Fatal("status retained caller-owned mutable map")
	}
	path := filepath.Join(dir, "run_status.json")
	if _, e = os.Stat(path); e != nil {
		t.Fatal(e)
	}
	if e = s.Finish("interrupted", "test complete"); e != nil {
		t.Fatal(e)
	}
}

func TestTypedMapsDetachAndInvalidUpdateDoesNotMutate(t *testing.T) {
	s, err := New(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Finish("interrupted", "test complete")
	typed := map[string]string{"key": "before"}
	if err = s.Update(map[string]any{"typed": typed}, false); err != nil {
		t.Fatal(err)
	}
	typed["key"] = "after"
	if got := s.Snapshot()["typed"].(map[string]any)["key"]; got != "before" {
		t.Fatalf("typed map remained caller-owned: %v", got)
	}
	s.mu.Lock()
	before, err := backends.EncodeJSON(s.data, false, true, false)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Update(map[string]any{"broken": func() {}}, true); err == nil {
		t.Fatal("unsupported value update succeeded")
	}
	s.mu.Lock()
	after, err := backends.EncodeJSON(s.data, false, true, false)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("invalid update mutated status\nbefore %s\nafter %s", before, after)
	}
}

func TestNilUpdateIsSafeAndRetainsProgressBehavior(t *testing.T) {
	s, err := New(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Finish("interrupted", "test complete")
	if err = s.Update(nil, false); err != nil {
		t.Fatalf("nil no-op update: %v", err)
	}
	before := s.Snapshot()["last_progress_at_utc"]
	if err = s.Update(nil, true); err != nil {
		t.Fatalf("nil progress update: %v", err)
	}
	if after := s.Snapshot()["last_progress_at_utc"]; after == before {
		t.Fatalf("nil progress update failed to mark progress: %v", after)
	}
}

func TestTerminalUpdateReturnsSavedHeartbeatError(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "run_status.json")
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	for {
		s.mu.Lock()
		failed := s.writeErr != nil
		s.mu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat did not save its write error")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = s.Update(map[string]any{"state": "complete"}, false); err == nil {
		t.Fatal("terminal update hid prior heartbeat write error")
	}
	select {
	case <-s.done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("terminal update did not stop heartbeat")
	}
}
