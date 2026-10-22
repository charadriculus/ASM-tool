package evidence

import (
	"asmtool/internal/backends"
	"asmtool/internal/core"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func event(id, typ, value, scope string, meta map[string]any) map[string]any {
	return map[string]any{"event_id": id, "event_type": typ, "module": "dns", "source_tool": "fixture", "observed_at": "2026-01-01T00:00:00Z", "raw_value": value, "normalized_value": value, "scope_status": scope, "confidence": 0.8, "evidence": map[string]any{}, "relations": []any{}, "metadata": meta}
}
func TestWriterVisibilityBarrierAndJSONLRejections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	w := NewWriter(2, 8, time.Hour)
	ev := event("one", "domain_found", "example.com", "in_scope", map[string]any{})
	if e := w.Append(path, ev); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) == 0 {
		t.Fatalf("sync append not visible on return: %v", e)
	}
	ev2 := event("two", "domain_found", "two.example.com", "in_scope", map[string]any{})
	if e = w.AppendBuffered(path, ev2); e != nil {
		t.Fatal(e)
	}
	if e = w.Flush(path); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.WriteString("{broken}\n[]\n")
	_ = f.Close()
	records := []JSONLRecord{}
	if e = IterJSONL(path, func(r JSONLRecord) error { records = append(records, r); return nil }); e != nil {
		t.Fatal(e)
	}
	if len(records) != 4 || records[0].Err != nil || records[1].Err != nil || records[2].Err == nil || records[3].Err == nil || records[2].Path != path || records[2].Line != 3 {
		t.Fatalf("unexpected JSONL outcomes: %#v", records)
	}
}

func TestWriterFailurePropagatesToFlushAndClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events")
	w := NewWriter(2, 128, time.Hour)
	if e := w.AppendBuffered(path, event("ok", "domain_found", "a.example", "in_scope", map[string]any{})); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(dir, "isdir"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := w.Append(filepath.Join(dir, "isdir"), event("bad", "domain_found", "b.example", "in_scope", map[string]any{})); e == nil {
		t.Fatal("write-to-directory error not returned")
	}
	closeErr := w.Close()
	if closeErr == nil {
		t.Fatal("close failed to report prior writer error")
	}
	if repeated := w.Close(); repeated == nil || repeated.Error() != closeErr.Error() {
		t.Fatalf("repeated Close lost prior fatal: first=%v repeated=%v", closeErr, repeated)
	}
	if e := w.AppendBuffered(path, event("late", "domain_found", "late.example", "in_scope", map[string]any{})); e == nil {
		t.Fatal("append after Close succeeded")
	}
	if e := os.Remove(path); e != nil {
		t.Fatalf("writer handle remained open: %v", e)
	}
}

func TestWriterClosesAllFilesAndPreservesHealthyBufferedPath(t *testing.T) {
	full := "/dev/full"
	if _, err := os.Stat(full); err != nil {
		t.Skip("requires the local /dev/full failure sink")
	}
	dir := t.TempDir()
	healthy := filepath.Join(dir, "healthy.jsonl")
	w := NewWriter(8, 128, time.Hour)
	if err := w.AppendBuffered(healthy, event("healthy", "domain_found", "healthy.example", "in_scope", map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(full, event("full", "domain_found", "full.example", "in_scope", map[string]any{})); err == nil {
		t.Fatal("/dev/full write unexpectedly succeeded")
	}
	if err := w.Close(); err == nil {
		t.Fatal("Close hid the stored writer failure")
	}
	b, err := os.ReadFile(healthy)
	if err != nil {
		t.Fatalf("healthy file was not closed/flushed: %v", err)
	}
	if !bytes.Contains(b, []byte(`"event_id":"healthy"`)) {
		t.Fatalf("healthy buffered event lost during peer failure: %s", b)
	}
}

func TestWriterNewWriterDefaultsAndConcurrentClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "default.jsonl")
	w := NewWriter(0, 0, 0)
	var accepted atomic.Int64
	start := make(chan struct{})
	var callers sync.WaitGroup
	for i := 0; i < 32; i++ {
		callers.Add(1)
		go func(i int) {
			defer callers.Done()
			<-start
			if err := w.AppendBuffered(path, event(fmt.Sprintf("id-%d", i), "domain_found", "example.test", "in_scope", map[string]any{})); err == nil {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	callers.Wait()
	var records int
	if err := IterJSONL(path, func(r JSONLRecord) error {
		if r.Err != nil {
			return r.Err
		}
		records++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if records != int(accepted.Load()) {
		t.Fatalf("close persisted %d events, accepted %d", records, accepted.Load())
	}
}

func TestAppendBufferedDetachesCallerEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detached.jsonl")
	w := NewWriter(4, 100, time.Hour)
	ev := event("before", "domain_found", "example.test", "in_scope", map[string]any{"nested": map[string]any{"value": "before"}})
	if err := w.AppendBuffered(path, ev); err != nil {
		t.Fatal(err)
	}
	ev["event_id"] = "after"
	ev["metadata"].(map[string]any)["nested"].(map[string]any)["value"] = "after"
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var got JSONLRecord
	if err := IterJSONL(path, func(r JSONLRecord) error { got = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if got.Err != nil || got.Event["event_id"] != "before" || got.Event["metadata"].(map[string]any)["nested"].(map[string]any)["value"] != "before" {
		t.Fatalf("buffered append retained caller mutation: %#v", got)
	}
}

func TestWriterTimerFailureRemainsFatalAcrossClose(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("requires the local /dev/full failure sink")
	}
	w := NewWriter(4, 128, 20*time.Millisecond)
	if err := w.AppendBuffered("/dev/full", event("timer", "domain_found", "example.test", "in_scope", map[string]any{})); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		w.errMu.Lock()
		failed := w.fatal != nil
		w.errMu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			_ = w.Close()
			t.Fatal("idle timer did not persist its flush error")
		}
		time.Sleep(5 * time.Millisecond)
	}
	first := w.Close()
	second := w.Close()
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("repeated Close changed timer failure: first=%v second=%v", first, second)
	}
}

func resetDefaultWriterForTest() {
	defaultWriterMu.Lock()
	defaultEventsWriter = nil
	defaultOnce = sync.Once{}
	defaultWriterMu.Unlock()
}

func TestSingletonCloseBeforeFirstUse(t *testing.T) {
	resetDefaultWriterForTest()
	defer resetDefaultWriterForTest()
	if err := CloseEventWriters(); err != nil {
		t.Fatalf("close-before-first-use: %v", err)
	}
	if err := AppendEventBuffered(filepath.Join(t.TempDir(), "closed.jsonl"), event("closed", "domain_found", "example.test", "in_scope", map[string]any{})); err == nil {
		t.Fatal("default helper reopened a closed source singleton")
	}
	if err := CloseEventWriters(); err != nil {
		t.Fatalf("repeated singleton close lost stored result: %v", err)
	}
}

func TestSingletonEventHelpersConcurrentAppendAndClose(t *testing.T) {
	resetDefaultWriterForTest()
	t.Cleanup(func() {
		_ = CloseEventWriters()
		resetDefaultWriterForTest()
	})
	path := filepath.Join(t.TempDir(), "singleton.jsonl")
	var accepted atomic.Int64
	start := make(chan struct{})
	var writers sync.WaitGroup
	for i := 0; i < 24; i++ {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			<-start
			if err := AppendEventBuffered(path, event(fmt.Sprintf("singleton-%d", i), "domain_found", "example.test", "in_scope", map[string]any{})); err == nil {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	var closers sync.WaitGroup
	for i := 0; i < 2; i++ {
		closers.Add(1)
		go func() {
			defer closers.Done()
			if err := CloseEventWriters(); err != nil {
				t.Errorf("close singleton: %v", err)
			}
		}()
	}
	writers.Wait()
	closers.Wait()
	count := 0
	if err := IterJSONL(path, func(r JSONLRecord) error {
		if r.Err != nil {
			return r.Err
		}
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != int(accepted.Load()) {
		t.Fatalf("singleton close persisted %d events, accepted %d", count, accepted.Load())
	}
	if err := AppendEventBuffered(path, event("late", "domain_found", "example.test", "in_scope", map[string]any{})); err == nil {
		t.Fatal("default helper accepted append after close")
	}
	if err := CloseEventWriters(); err != nil {
		t.Fatalf("repeated singleton close lost successful result: %v", err)
	}
}

func TestProviderInventoryAndDNSBudgetSourceFixture(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase2/legacy_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	f := decoded.(map[string]any)["provider"].(map[string]any)
	path := filepath.Join(t.TempDir(), "provider.jsonl")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range f["input_events"].([]any) {
		line, x := backends.EncodeJSON(raw, false, true, true)
		if x != nil {
			t.Fatal(x)
		}
		if _, x = out.Write(line); x != nil {
			t.Fatal(x)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	inventory, err := Inventory([]string{path}, f["root"].(string))
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]map[string]any, 0, len(inventory))
	for _, item := range inventory {
		row := map[string]any{}
		for k, v := range item {
			switch x := v.(type) {
			case map[string]bool:
				values := make([]string, 0, len(x))
				for s := range x {
					values = append(values, s)
				}
				sort.Strings(values)
				arr := make([]any, len(values))
				for i := range values {
					arr[i] = values[i]
				}
				row[k] = arr
			default:
				row[k] = v
			}
		}
		actual = append(actual, row)
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i]["hostname"].(string) < actual[j]["hostname"].(string) })
	assertFixtureJSONEqual(t, "provider inventory", actual, f["inventory"])
	budget, err := strconv.Atoi(string(f["budget"].(json.Number)))
	if err != nil {
		t.Fatal(err)
	}
	selected, deferred := RankForDNS(inventory, f["root"].(string), budget)
	events := make([]map[string]any, 0, len(f["input_events"].([]any)))
	for _, raw := range f["input_events"].([]any) {
		events = append(events, raw.(map[string]any))
	}
	typedInventory, err := ProviderInventory(events, f["root"].(string))
	if err != nil {
		t.Fatal(err)
	}
	typedSelected, typedDeferred := RankProviderInventory(typedInventory, f["root"].(string), budget)
	names := func(items []map[string]any) []any {
		out := make([]any, len(items))
		for i, x := range items {
			out[i] = x["hostname"]
		}
		return out
	}
	assertFixtureJSONEqual(t, "DNS selected", names(selected), f["dns_selected"])
	assertFixtureJSONEqual(t, "DNS deferred", names(deferred), f["dns_deferred"])
	typedNames := func(items []ProviderInventoryEntry) []any {
		out := make([]any, len(items))
		for i, item := range items {
			out[i] = item.Hostname
		}
		return out
	}
	assertFixtureJSONEqual(t, "typed DNS selected", typedNames(typedSelected), f["dns_selected"])
	assertFixtureJSONEqual(t, "typed DNS deferred", typedNames(typedDeferred), f["dns_deferred"])
}

func assertFixtureJSONEqual(t *testing.T, what string, got, want any) {
	t.Helper()
	gb, err := backends.EncodeJSON(got, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := backends.EncodeJSON(want, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(gb) != string(wb) {
		t.Fatalf("%s mismatch: got %s want %s", what, gb, wb)
	}
}

func TestJSONLReaderFlushesCustomWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.jsonl")
	w := NewWriter(1, 99, time.Hour)
	if err := w.AppendBuffered(path, event("custom", "domain_found", "custom.example", "in_scope", map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var records []JSONLRecord
	if err := IterJSONL(path, func(r JSONLRecord) error { records = append(records, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Err != nil || records[0].Event["event_id"] != "custom" {
		t.Fatalf("custom writer event not visible to reader: %#v", records)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCompletenessAndProviderRanking(t *testing.T) {
	zero := 0
	if got := ClassifyCompleteness("ok", &zero, false, false, 0, false, false, 0, false); got != CompletenessUnknown {
		t.Fatal(got)
	}
	if got := ClassifyCompleteness("timeout", nil, true, false, 0, false, false, 4, false); got != PartialTimeout {
		t.Fatal(got)
	}
	if got := ClassifyCompleteness("ok", &zero, false, false, 0, true, false, 0, false); got != CompleteEmpty {
		t.Fatal(got)
	}
	root := map[string]any{"hostname": "example.com", "providers": map[string]bool{}, "evidence_families": map[string]bool{}, "first_seen_by_provider": map[string]string{}}
	a := map[string]any{"hostname": "a.example.com", "providers": map[string]bool{"p1": true}, "evidence_families": map[string]bool{"public_index": true}, "first_seen_by_provider": map[string]string{}}
	b := map[string]any{"hostname": "b.example.com", "providers": map[string]bool{"crt.sh": true, "p2": true}, "evidence_families": map[string]bool{"certificate_transparency": true}, "first_seen_by_provider": map[string]string{"crt.sh": "2026"}}
	selected, deferred := RankForDNS(map[string]map[string]any{"example.com": root, "a.example.com": a, "b.example.com": b}, "example.com", 2)
	if len(selected) != 2 || selected[1]["hostname"] != "b.example.com" || len(deferred) != 1 {
		t.Fatalf("selection=%v deferred=%v", selected, deferred)
	}
}

func TestDNSRunIndexScopeAndLatestValidation(t *testing.T) {
	x := NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.com"}})
	x.Ingest(event("v1", "dns_validation", "www.example.com", "in_scope", map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible"}))
	x.Ingest(event("ip", "ip_found", "192.0.2.1", "in_scope", map[string]any{"domain": "www.example.com"}))
	if got := x.IPsForDomain("www.example.com"); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatal(got)
	}
	if len(x.CleanSubdomains("example.com")) != 1 {
		t.Fatal("clean validation missing")
	}
	if len(x.ConfirmedTargets("example.com", false)) != 1 {
		t.Fatal("eligible target missing")
	}
	x.Ingest(event("out", "ip_found", "192.0.2.2", "in_scope", map[string]any{"domain": "outside.test"}))
	if len(x.IPsForDomain("outside.test")) != 0 {
		t.Fatal("out-of-scope association retained")
	}
}

func TestDNSRunIndexSourceFixtureMaps(t *testing.T) {
	data, err := os.ReadFile("../../testdata/phase2/legacy_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := backends.DecodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	gold := fixture.(map[string]any)["dns_index"].(map[string]any)
	x := NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	for _, raw := range gold["input_events"].([]any) {
		x.Ingest(raw.(map[string]any))
	}
	assert := func(key string, got []string) {
		t.Helper()
		want := gold[key].([]any)
		if len(got) != len(want) {
			t.Fatalf("%s got %v want %v", key, got, want)
		}
		for i, v := range want {
			if got[i] != v {
				t.Fatalf("%s got %v want %v", key, got, want)
			}
		}
	}
	assert("ips", x.IPs())
	assert("domains_for_in_scope_ip", x.DomainsForIP("192.0.2.20"))
	assert("ptr", x.PTRNamesForIP("192.0.2.20"))
	assert("cname", x.CNAMETargets("alias.example.test"))
	assert("asn_names", x.ASNNamesForIP("192.0.2.20"))
	assert("out_of_scope_ip_domains", x.DomainsForIP("192.0.2.21"))
	if got := x.ExistingValidation("app.example.test")["dns_state"]; got != gold["latest_validation"].(map[string]any)["dns_state"] {
		t.Fatalf("latest validation=%v", got)
	}
}

func TestCompletenessSourceFixture(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase2/legacy_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	rows := decoded.(map[string]any)["completeness"].([]any)
	for i, row := range rows {
		m := row.(map[string]any)
		in := m["input"].(map[string]any)
		var code *int
		if n, ok := in["returncode"].(json.Number); ok {
			x, e := n.Int64()
			if e != nil {
				t.Fatal(e)
			}
			v := int(x)
			code = &v
		}
		num := func(k string) int { n, _ := in[k].(json.Number); x, _ := n.Int64(); return int(x) }
		got := ClassifyCompleteness(text(in["collector_status"]), code, in["timed_out"] == true, in["rate_limited"] == true, num("transport_errors"), in["pagination_confirmed_complete"] == true, in["pagination_incomplete"] == true, num("returned_total"), in["truncated"] == true)
		if got != m["state"] {
			t.Fatalf("fixture case %d: %s != %v", i, got, m["state"])
		}
	}
}

func TestProviderAnomalySourceFixture(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase2/legacy_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	rows := decoded.(map[string]any)["provider_anomaly_warning_cases"].([]any)
	for i, row := range rows {
		m := row.(map[string]any)
		in := m["input"].(map[string]any)
		runs := in["historical_runs"].([]any)
		history := make([]HistoricalRun, 0, len(runs))
		for _, raw := range runs {
			r := raw.(map[string]any)
			count, _ := r["returned"].(json.Number).Int64()
			elapsed, _ := r["elapsed"].(json.Number).Float64()
			history = append(history, HistoricalRun{Returned: int(count), Elapsed: &elapsed})
		}
		current, _ := in["current_returned"].(json.Number).Int64()
		seconds, _ := in["current_elapsed_seconds"].(json.Number).Float64()
		got := AssessOutput(int(current), history, seconds)
		want := m["result"].(map[string]any)
		wantReasons := want["reasons"].([]any)
		reasonsMatch := len(got.Reasons) == len(wantReasons)
		for j := range got.Reasons {
			if !reasonsMatch || got.Reasons[j] != wantReasons[j] {
				reasonsMatch = false
				break
			}
		}
		if got.Status != want["status"] || got.Anomalous != (want["anomalous"] == true) || !reasonsMatch {
			t.Fatalf("anomaly fixture %d: got %+v want %#v", i, got, want)
		}
		sameNum := func(key string, actual *float64) {
			w := want[key]
			if w == nil {
				if actual != nil {
					t.Fatalf("fixture %d %s=%v, want null", i, key, *actual)
				}
				return
			}
			f, _ := w.(json.Number).Float64()
			if actual == nil || math.Abs(*actual-f) > 1e-12 {
				t.Fatalf("fixture %d %s=%v want %v", i, key, actual, f)
			}
		}
		sameNum("historical_median_returned", got.HistoricalMedian)
		sameNum("relative_to_historical_median", got.Ratio)
		sameNum("historical_median_elapsed_seconds", got.HistoricalMedianElapsed)
		sameNum("elapsed_ratio", got.ElapsedRatio)
	}
}
