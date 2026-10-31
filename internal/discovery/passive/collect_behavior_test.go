package passive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/platform"
)

func TestCollectContextAwareSummaryAndCallerCancellation(t *testing.T) {
	cfg := collectFixtureConfig(t)
	cfg.CollectionPolicy.CRTNameEnabled = true
	cfg.CollectionPolicy.SubMDFallbackEnabled = true
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusOK, `["one.example.test"]`)
	}))
	if _, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(ctx context.Context, e core.Event) error {
		if e.Metadata["collection"] == "passive_inventory_summary" && ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}}); err != nil {
		t.Fatalf("successful summary rejected: %v", err)
	}

	cfg.CollectionPolicy.CRTNameEnabled = false
	cfg.CollectionPolicy.SubMDFallbackEnabled = false
	cfg.CollectionPolicy.CRTShEnabled = true
	started, joined := make(chan struct{}), make(chan struct{})
	cancelCtx, cancel := context.WithCancel(context.Background())
	client = collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		close(joined)
		return nil, r.Context().Err()
	}))
	done := make(chan error, 1)
	go func() {
		_, err := Collect(cancelCtx, CollectRequest{Config: cfg, HTTP: client, Sink: func(context.Context, core.Event) error { return nil }})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Collect error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Collect did not join canceled provider")
	}
	select {
	case <-joined:
	default:
		t.Fatal("provider was not joined before return")
	}
}

func TestCollectSubfasterFallbackExecutesAndRecordsRisk(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.name", "crt.sh")
	cfg.CollectionPolicy.SubMDFallbackEnabled = true
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "crt.name" {
			return jsonResponse(r, http.StatusServiceUnavailable, "unavailable")
		}
		return jsonResponse(r, http.StatusOK, `[]`)
	}))
	tool := behaviorSubfaster(t, `package main
import "fmt"
func main(){fmt.Println("{\"host\":\"fallback.example.test\",\"sources\":[\"submd\"]}")}`)
	var health *core.Event
	var limitation *core.Event
	var submdObservations int
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Subfaster: &tool, Sink: func(_ context.Context, e core.Event) error {
		if e.EventType == core.SourceHealth && e.SourceTool == "submd" {
			health = &e
		}
		if e.EventType == core.Limitation && e.SourceTool == "submd" {
			limitation = &e
		}
		if e.EventType == core.SubdomainFound && e.SourceTool == "submd" {
			submdObservations++
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if health == nil || health.Metadata["status"] != "ok" || health.Metadata["tool_version"] != nil || health.Metadata["version_evidence_status"] != "manifest_identity_verified" || health.Metadata["known_startup_network_risk"] != true || len(fmt.Sprint(health.Metadata["component_sha256"])) != 64 {
		t.Fatalf("Subfaster execution provenance/risk missing: %+v", health)
	}
	if limitation != nil {
		t.Fatalf("successful Subfaster run emitted failure limitation: %+v", limitation)
	}
	if !strings.Contains(fmt.Sprint(health.Metadata["message"]), "triggered_by=crt.name") || submdObservations != 1 {
		t.Fatalf("fallback trigger or no-observation contract lost: health=%+v observations=%d", health.Metadata, submdObservations)
	}
}
func TestCollectDeepExecutesSelectedSubfasterProviders(t *testing.T) {
	cfg := collectFixtureConfig(t)
	cfg.CollectionPolicy.PassiveProviderProfile = "deep"
	cfg.CollectionPolicy.THCEnabled = true
	marker := filepath.Join(t.TempDir(), "subfaster-launched")
	source := fmt.Sprintf(`package main
import("os";"fmt";"encoding/json")
func main(){_ = os.WriteFile(%s, []byte("started"), 0600); source:=""; for i:=1;i+1<len(os.Args);i++ { if os.Args[i]=="-s" { source=os.Args[i+1] } }; row,_:=json.Marshal(map[string]any{"host":"deep.example.test","sources":[]string{source}}); fmt.Println(string(row)) }`, strconv.Quote(marker))
	tool := behaviorSubfaster(t, source)
	statuses := map[string]string{}
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, Subfaster: &tool, Sink: func(_ context.Context, e core.Event) error {
		if e.EventType == core.SourceHealth && e.Metadata["collector"] == "subfaster" {
			statuses[e.SourceTool] = fmt.Sprint(e.Metadata["status"])
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"thc", "submd", "shodanct", "rapiddns", "hackertarget", "sitedossier"} {
		if statuses[provider] != "ok" {
			t.Errorf("%s status=%q, want successful execution", provider, statuses[provider])
		}
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("Subfaster process was not created: stat err=%v", err)
	}
	cfg.CollectionPolicy.PassiveProviderProfile = "research"
	var ioCalls atomic.Int32
	client := collectFixtureClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { ioCalls.Add(1); return nil, errors.New("I/O reached") }))
	if _, err = Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Subfaster: &tool, Sink: func(context.Context, core.Event) error { return nil }}); err == nil || ioCalls.Load() != 0 {
		t.Fatalf("research profile must reject before I/O: err=%v calls=%d", err, ioCalls.Load())
	}
}
func TestCollectSubfasterFailureKeepsRawFailureAndComponentIdentity(t *testing.T) {
	cfg := collectFixtureConfig(t)
	cfg.CollectionPolicy.PassiveProviderProfile = "deep"
	tool := behaviorSubfaster(t, `package main
import("fmt";"os")
func main(){fmt.Fprintln(os.Stderr,"fixture failure");os.Exit(7)}`)
	var events []core.Event
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, Subfaster: &tool, Sink: func(_ context.Context, e core.Event) error { events = append(events, e); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.EventType == core.SubdomainFound && event.SourceTool != "passive_orchestrator" {
			t.Fatalf("failed Subfaster created an observation: %+v", event)
		}
		if event.EventType == core.SourceHealth && event.Metadata["collector"] == "subfaster" && (event.Metadata["status"] != "failed" || event.Metadata["transport_errors"] == 0 || event.Metadata["completeness_state"] != evidence.CollectorFailed || event.Metadata["component_sha256"] == nil || event.Metadata["known_startup_network_risk"] != true) {
			t.Errorf("failed health record lost status/provenance/risk: %+v", event.Metadata)
		}
	}
}
func TestCollectSerializesConcurrentDurableSinkCalls(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.sh", "certspotter")
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "crt.sh" {
			return jsonResponse(r, http.StatusOK, `[{"name_value":"one.example.test"}]`)
		}
		if r.URL.Query().Get("after") == "" {
			return jsonResponse(r, http.StatusOK, `[{"id":"p1","dns_names":["two.example.test"]}]`)
		}
		return jsonResponse(r, http.StatusOK, `[]`)
	}))
	var active, maximum atomic.Int32
	var eventsMu sync.Mutex
	var events []core.Event
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, e core.Event) error {
		n := active.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		time.Sleep(time.Millisecond)
		eventsMu.Lock()
		events = append(events, e)
		eventsMu.Unlock()
		active.Add(-1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 1 {
		t.Fatalf("durable sink had %d concurrent calls", maximum.Load())
	}
}

func TestStreamingCallbackAndHealthEmissionShareDurableOwner(t *testing.T) {
	cfg := collectFixtureConfig(t)
	inv, err := evidence.NewProviderInventoryAccumulator("example.test")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var active, maximum atomic.Int32
	var eventsMu sync.Mutex
	var events []core.Event
	state := &collectState{ctx: context.Background(), target: "example.test", cap: 8, inventory: inv, seen: map[string]map[string]bool{}, providerOutcomes: map[string]providerOutcome{}, req: CollectRequest{Config: cfg}}
	state.req.Sink = func(_ context.Context, e core.Event) error {
		n := active.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		if e.EventType == core.SubdomainFound {
			close(entered)
			<-release
		}
		eventsMu.Lock()
		events = append(events, e)
		eventsMu.Unlock()
		active.Add(-1)
		return nil
	}
	state.beginProvider(collectJob{name: "thc", role: "primary"})
	observationDone := make(chan error, 1)
	go func() {
		observationDone <- state.ingestObservation(context.Background(), evidence.ProviderObservation{Hostname: "stream.example.test", Provider: "thc", Collector: "subfaster", Family: "passive_dns_or_asset_index", Metadata: map[string]any{"reported_sources": []string{"thc"}, "explicit_source_selection": "thc"}}, "streaming", HTTPMeta{})
	}()
	<-entered
	healthDone := make(chan error, 1)
	healthStarted := make(chan struct{})
	go func() {
		close(healthStarted)
		healthDone <- state.emitHealth(context.Background(), "thc", providerOutcome{result: evidence.ProviderResult{Provider: "thc", Collector: "subfaster", Role: "primary", Status: "ok", CompletenessState: evidence.Complete}})
	}()
	<-healthStarted
	select {
	case err := <-healthDone:
		t.Fatalf("health event bypassed blocked streaming sink, err=%v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if maximum.Load() != 1 {
		t.Fatalf("stream observation and health sink overlapped: max active=%d", maximum.Load())
	}
	close(release)
	if err := <-observationDone; err != nil {
		t.Fatal(err)
	}
	if err := <-healthDone; err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 1 {
		t.Fatalf("serialized sink max active=%d, want 1", maximum.Load())
	}
	replay := make([]map[string]any, 0, len(events))
	for _, event := range events {
		b, _ := json.Marshal(event)
		var row map[string]any
		_ = json.Unmarshal(b, &row)
		replay = append(replay, row)
	}
	want, err := evidence.ProviderInventory(replay, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inv.Snapshot(), want) {
		t.Fatalf("durable/live commit mismatch: live=%s durable=%s", mustJSON(inv.Snapshot()), mustJSON(want))
	}
}

func TestCollectCommitsSinkSuccessBeforeCallerCancellation(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.sh")
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusOK, `[{"name_value":"one.example.test"}]`)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []core.Event
	got, err := Collect(ctx, CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, e core.Event) error {
		events = append(events, e)
		if e.Metadata["collection"] == "passive_osint" {
			cancel()
		} // The accepted durable write cancels its parent before returning.
		return nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Collect error=%v, want caller cancellation", err)
	}
	replay := make([]map[string]any, 0, len(events))
	for _, event := range events {
		b, _ := json.Marshal(event)
		var row map[string]any
		_ = json.Unmarshal(b, &row)
		replay = append(replay, row)
	}
	want, replayErr := evidence.ProviderInventory(replay, "example.test")
	if replayErr != nil {
		t.Fatal(replayErr)
	}
	if !reflect.DeepEqual(got.Inventory, want) {
		t.Fatalf("live inventory lost/added observations around cancellation\nlive=%s\ndurable=%s", mustJSON(got.Inventory), mustJSON(want))
	}
	if _, ok := got.Inventory["one.example.test"]; !ok {
		t.Fatalf("successful durable sink write was not committed: events=%d", len(events))
	}
}

func TestSubfasterSuccessfulExecutionRecordsKnownStartupRisk(t *testing.T) {
	cfg := collectFixtureConfig(t, "thc")
	tool := behaviorSubfaster(t, `package main
import "fmt"
func main(){fmt.Println("{\"host\":\"one.example.test\",\"source\":\"thc\"}")}`)
	var health map[string]any
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, Subfaster: &tool, Sink: func(_ context.Context, e core.Event) error {
		if e.EventType == core.SourceHealth && e.SourceTool == "thc" {
			health = e.Metadata
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if health == nil || health["status"] != "ok" || health["returned_total"] != 1 || health["transport_errors"] != 0 || health["known_startup_network_risk"] != true || health["version_evidence_status"] != "manifest_identity_verified" {
		t.Fatalf("successful provider status/risk missing: %#v", health)
	}
}
func behaviorSubfaster(t *testing.T, source string) (tool platform.Tool) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "tools")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(src, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "subfaster")
	cmd := exec.Command("go", "build", "-o", path, src)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build local helper: %s %v", out, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	manifest := fmt.Sprintf(`{"schema_version":1,"platform":%q,"files":[{"path":"tools/subfaster","sha256":%q}],"tools":[{"name":"subfaster","executable":"tools/subfaster","version":"2.18.0"}]}`, runtime.GOOS+"/"+runtime.GOARCH, hex.EncodeToString(sum[:]))
	mp := []byte(manifest)
	if err = os.WriteFile(filepath.Join(root, "bundle.json"), mp, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(mp)
	b, err := platform.NewBundle(root, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err = b.Tool("subfaster")
	if err != nil {
		t.Fatal(err)
	}
	return tool
}
