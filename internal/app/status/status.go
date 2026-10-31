package status

import (
	"asmtool/internal/backends"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

var terminal = map[string]bool{"complete": true, "error": true, "interrupted": true}

type worker struct {
	ID           string `json:"worker_id"`
	Role         string `json:"role"`
	State        string `json:"state"`
	Operation    string `json:"operation"`
	Target       string `json:"target"`
	URL          string `json:"url"`
	Completed    *int   `json:"completed"`
	Planned      *int   `json:"planned"`
	Message      string `json:"message"`
	StartedLocal string `json:"operation_started_at_local"`
	StartedUTC   string `json:"operation_started_at_utc"`
	elapsed      time.Time
}
type Status struct {
	mu                         sync.Mutex
	path                       string
	interval                   time.Duration
	data                       map[string]any
	workers                    map[string]worker
	workerOrder                []string
	lastProgress               time.Time
	progressLocal, progressUTC string
	stop                       chan struct{}
	stopOnce                   sync.Once
	done                       chan struct{}
	writeErr                   error
}

func New(dir string, interval time.Duration) (*Status, error) {
	if interval < time.Second {
		interval = 5 * time.Second
	}
	now := time.Now()
	s := &Status{path: filepath.Join(dir, "run_status.json"), interval: interval, workers: map[string]worker{}, lastProgress: now, stop: make(chan struct{}), done: make(chan struct{}), data: map[string]any{"state": "initializing", "stage": nil, "current_target": nil, "current_url": nil, "current_operation": nil, "completed": 0, "planned": nil, "message": nil}}
	s.progressLocal = now.Local().Format(time.RFC3339Nano)
	s.progressUTC = now.UTC().Format(time.RFC3339Nano)
	if e := s.writeLocked(); e != nil {
		return nil, e
	}
	go s.heartbeat()
	return s, nil
}
func (s *Status) heartbeat() {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			if !terminal[text(s.data["state"])] {
				if e := s.writeLocked(); e != nil {
					s.writeErr = e
				}
			}
			s.mu.Unlock()
		}
	}
}
func text(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func (s *Status) markProgress() {
	now := time.Now()
	s.lastProgress = now
	s.progressLocal = now.Local().Format(time.RFC3339Nano)
	s.progressUTC = now.UTC().Format(time.RFC3339Nano)
}
func (s *Status) payload() map[string]any {
	p := map[string]any{}
	for k, v := range s.data {
		p[k] = clone(v)
	}
	p["heartbeat_at_local"] = time.Now().Local().Format(time.RFC3339Nano)
	p["heartbeat_at_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	p["last_progress_at_local"] = s.progressLocal
	p["last_progress_at_utc"] = s.progressUTC
	p["seconds_since_last_progress"] = max(0, time.Since(s.lastProgress).Seconds())
	workers := map[string]any{}
	for _, id := range s.workerOrder {
		w, exists := s.workers[id]
		if !exists {
			continue
		}
		var completed, planned any
		if w.Completed != nil {
			completed = *w.Completed
		}
		if w.Planned != nil {
			planned = *w.Planned
		}
		row := map[string]any{"worker_id": w.ID, "role": w.Role, "state": w.State, "operation": w.Operation, "target": w.Target, "url": w.URL, "completed": completed, "planned": planned, "message": w.Message, "operation_started_at_local": w.StartedLocal, "operation_started_at_utc": w.StartedUTC, "operation_elapsed_seconds": max(0, time.Since(w.elapsed).Seconds())}
		workers[id] = row
	}
	p["workers"] = workers
	return p
}
func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		y := map[string]any{}
		for k, v := range x {
			y[k] = clone(v)
		}
		return y
	case []any:
		y := make([]any, len(x))
		for i, v := range x {
			y[i] = clone(v)
		}
		return y
	default:
		return v
	}
}
func cloneInt(v *int) *int {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}
func (s *Status) writeLocked() error {
	return backends.WriteJSONAtomic(s.path, s.payload(), true, true, false, false)
}
func (s *Status) Update(values map[string]any, progress bool) error {
	if values == nil {
		values = map[string]any{}
	}
	encoded, err := backends.EncodeJSON(values, false, true, false)
	if err != nil {
		return fmt.Errorf("invalid status update: %w", err)
	}
	detached, err := backends.DecodeJSON(encoded)
	if err != nil {
		return fmt.Errorf("invalid status update: %w", err)
	}
	updates := detached.(map[string]any)
	s.mu.Lock()
	if terminal[text(s.data["state"])] {
		s.mu.Unlock()
		return errors.New("run status is terminal")
	}
	for k, v := range updates {
		if v == nil {
			continue
		}
		s.data[k] = clone(v)
	}
	if progress {
		s.markProgress()
	}
	e := s.writeLocked()
	stop := terminal[text(s.data["state"])]
	s.mu.Unlock()
	if stop {
		s.stopHeartbeat()
		if e == nil {
			return s.writeErr
		}
	}
	return e
}
func (s *Status) UpdateWorker(id, role, operation, target, url, state, message string, completed, planned *int, progress bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if terminal[text(s.data["state"])] {
		return errors.New("run status is terminal")
	}
	old, exists := s.workers[id]
	now := time.Now()
	changed := !exists || old.Operation != operation || old.Target != target || old.URL != url
	if changed {
		old.elapsed = now
		old.StartedLocal = now.Local().Format(time.RFC3339Nano)
		old.StartedUTC = now.UTC().Format(time.RFC3339Nano)
	}
	if !exists {
		s.workerOrder = append(s.workerOrder, id)
	}
	old.ID = id
	old.Role = role
	old.Operation = operation
	old.Target = target
	old.URL = url
	old.State = state
	old.Message = message
	old.Completed = cloneInt(completed)
	old.Planned = cloneInt(planned)
	s.workers[id] = old
	s.data["current_operation"] = operation
	if target != "" {
		s.data["current_target"] = target
	}
	if url != "" {
		s.data["current_url"] = url
	}
	if completed != nil {
		s.data["completed"] = *completed
	}
	if planned != nil {
		s.data["planned"] = *planned
	}
	if message != "" {
		s.data["message"] = message
	}
	if progress {
		s.markProgress()
	}
	return s.writeLocked()
}
func (s *Status) ClearWorker(id, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if terminal[text(s.data["state"])] {
		return errors.New("run status is terminal")
	}
	delete(s.workers, id)
	for i, key := range s.workerOrder {
		if key == id {
			s.workerOrder = append(s.workerOrder[:i], s.workerOrder[i+1:]...)
			break
		}
	}
	if message != "" {
		s.data["message"] = message
	}
	current := worker{}
	found := false
	for i := len(s.workerOrder) - 1; i >= 0; i-- {
		w, ok := s.workers[s.workerOrder[i]]
		if !ok {
			continue
		}
		if w.State != "idle" && w.State != "complete" && w.State != "stopped" {
			current = w
			found = true
			break
		}
	}
	if found {
		s.data["current_target"] = current.Target
		s.data["current_url"] = current.URL
		s.data["current_operation"] = current.Operation
	} else {
		s.data["current_target"] = nil
		s.data["current_url"] = nil
		s.data["current_operation"] = nil
	}
	s.markProgress()
	return s.writeLocked()
}
func (s *Status) Snapshot() map[string]any { s.mu.Lock(); defer s.mu.Unlock(); return s.payload() }
func (s *Status) stopHeartbeat()           { s.stopOnce.Do(func() { close(s.stop) }); <-s.done }
func (s *Status) Finish(state, message string) error {
	if !terminal[state] {
		return fmt.Errorf("invalid terminal state %q", state)
	}
	s.mu.Lock()
	if terminal[text(s.data["state"])] {
		s.mu.Unlock()
		return errors.New("run status already terminal")
	}
	s.data["state"] = state
	if message == "" {
		message = state
	}
	s.data["message"] = message
	s.markProgress()
	e := s.writeLocked()
	s.mu.Unlock()
	s.stopHeartbeat()
	if e != nil {
		return e
	}
	return s.writeErr
}
