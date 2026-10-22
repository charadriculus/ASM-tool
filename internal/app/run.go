package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"asmtool/internal/app/status"
	"asmtool/internal/backends"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
	"asmtool/internal/platform"
	"asmtool/internal/portable"
	"asmtool/internal/report"
	"asmtool/internal/storage"
)

type Result struct {
	RunDir     string
	Outputs    report.Outputs
	Incomplete bool
}

// Execute validates authorization and the required portable payload before
// output writes or collection.
func Execute(ctx context.Context, p Plan, progress io.Writer) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if p.target == "" || p.timeout <= 0 {
		return Result{}, errors.New("validated plan is required")
	}
	if p.cfg.DirectTargetInteraction() && !p.cfg.AuthorizationConfirmed {
		return Result{}, ErrAuthorizationRequired
	}
	if p.cfg.DirectTargetInteraction() && (p.cfg.Modules.WebProbe || p.cfg.Modules.Crawler) && p.cfg.Backends.HTTPProbeBackend == "projectdiscovery_httpx" && !p.allowHTTPFallback {
		return Result{}, fmt.Errorf("%w: use --allow-http-fallback for explicit Go opt-in", platform.ErrNativeHTTPXBlocked)
	}
	if err := p.cfg.Validate(); err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	needSubfaster := p.cfg.Modules.Subdomains && (p.cfg.CollectionPolicy.THCEnabled || p.cfg.CollectionPolicy.SubMDFallbackEnabled || p.cfg.CollectionPolicy.PassiveProviderProfile == "deep")
	payload, err := portable.Verify(p.bundleDir, BundleManifestSHA256, needSubfaster, p.browserMode != "disabled")
	if err != nil {
		return Result{}, err
	}
	return executePassive(ctx, p, payload, progress, defaultStages())
}

// Small stage boundary enables offline lifecycle fixtures without replacing
// authorization or portable verification in the public entry point.
type stages struct {
	ops       activeOps
	collect   func(context.Context, passive.CollectRequest) (passive.CollectResult, error)
	expand    func(context.Context, dns.ExpansionConfig) (dns.ExpansionResult, error)
	quick     func(context.Context, dns.ExpansionConfig, *dns.WildcardAnalyzer, string) (dns.QuickValidationResult, error)
	generate  func(context.Context, report.Input, portable.Payload) (report.Outputs, error)
	dnsClient func(time.Duration, float64) (*dns.Client, error)
}

func defaultStages() stages {
	return stages{ops: defaultActiveOps(), collect: passive.Collect, expand: dns.Expand, quick: dns.ValidateQuick, dnsClient: dns.NewSystemClientWithRate, generate: func(ctx context.Context, in report.Input, p portable.Payload) (report.Outputs, error) {
		return report.Generate(ctx, in, p.Typst)
	}}
}

type durableSink struct {
	mu         sync.Mutex
	writer     *evidence.Writer
	db         *sql.DB
	path       string
	index      *evidence.DNSRunIndex
	incomplete bool
}

func (s *durableSink) emit(ctx context.Context, ev core.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	obj, err := object(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Evidence survives an ingest failure; SQLite idempotence is by event_id.
	if err := s.writer.Append(s.path, obj); err != nil {
		return fmt.Errorf("persist event: %w", err)
	}
	// Once JSONL accepts an event, finish its SQLite/index commit even when a
	// sibling stage cancels the run. The bounded persistence context prevents
	// cancellation from splitting the two durable projections mid-event.
	persistCtx, cancelPersist := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelPersist()
	if _, err := storage.IngestEvent(persistCtx, s.db, obj); err != nil {
		return fmt.Errorf("ingest event: %w", err)
	}
	s.index.Ingest(obj)
	if ev.EventType == core.Limitation {
		severity, _ := ev.Metadata["severity"].(string)
		if severity == "warning" || severity == "error" {
			s.incomplete = true
		}
	}
	return nil
}

// Run output is never reused, even after a failed run. Its forensic evidence
// remains available; report generations retain phase-7 atomic publication.
func executePassive(ctx context.Context, p Plan, payload portable.Payload, progress io.Writer, stage stages) (result Result, retErr error) {
	if p.cfg.DirectTargetInteraction() && !p.cfg.AuthorizationConfirmed {
		return Result{}, ErrAuthorizationRequired
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	dir := p.cfg.OutputDir
	if err := safeOutputParents(dir); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return Result{}, err
	}
	if err := safeOutputParents(dir); err != nil {
		return Result{}, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return Result{}, fmt.Errorf("run directory must be fresh: %w", err)
	}
	result.RunDir = dir
	runStatus, err := status.New(dir, time.Second)
	if err != nil {
		return result, err
	}
	// Only bounded, application-authored messages go to the operational log.
	logFile, err := os.OpenFile(filepath.Join(dir, "run.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, errors.Join(err, runStatus.Finish("error", "Cannot create operational log"))
	}
	started := time.Now().UTC()
	defer func() {
		state, message := "complete", "Collection and reports completed"
		if result.Incomplete {
			message = "Collection completed with incomplete evidence"
		}
		if retErr != nil {
			state, message = "error", "Run failed; persisted evidence retained"
		}
		if errors.Is(retErr, context.Canceled) || errors.Is(retErr, context.DeadlineExceeded) {
			state, message = "interrupted", "Run interrupted; persisted evidence retained"
		}
		retErr = errors.Join(retErr, runStatus.Update(map[string]any{"incomplete": result.Incomplete || retErr != nil, "completion": completion(result.Incomplete || retErr != nil)}, true), runStatus.Finish(state, message), logFile.Close())
	}()
	var announceMu sync.Mutex
	announce := func(name string) error {
		announceMu.Lock()
		defer announceMu.Unlock()
		// Provider messages and credentials are never copied into this log.
		if _, err := fmt.Fprintf(logFile, "%s stage=%s\n", time.Now().UTC().Format(time.RFC3339Nano), name); err != nil {
			return err
		}
		if err := logFile.Sync(); err != nil {
			return err
		}
		if progress != nil {
			if _, err := fmt.Fprintf(progress, "stage=%s\n", name); err != nil {
				return err
			}
		}
		return runStatus.Update(map[string]any{"state": "running", "profile": p.cfg.Profile, "stage": name, "target_domain": p.target}, true)
	}
	db, err := storage.Connect(ctx, p.cfg.DatabasePath)
	if err != nil {
		return result, err
	}
	writer := evidence.NewWriter(128, 32, 200*time.Millisecond)
	closed := false
	closeStore := func() error {
		if closed {
			return nil
		}
		closed = true
		return errors.Join(writer.Close(), db.Close())
	}
	defer func() { retErr = errors.Join(retErr, closeStore()) }()
	eventPath := filepath.Join(p.cfg.EventsDir(), "run.jsonl")
	index := evidence.NewDNSRunIndex(p.cfg.ScopePolicy)
	sink := &durableSink{writer: writer, db: db, path: eventPath, index: index}
	deferred := 0
	active := activeOutcome{}
	streaming := p.cfg.DirectTargetInteraction() && p.cfg.Modules.DomainExpansion && p.cfg.CollectionPolicy.StreamingPipelineEnabled
	schedule, streamingStatus, selectionPolicy := "bounded_sequential", "disabled_by_config", "ranked_inventory"
	if streaming {
		schedule, streamingStatus, selectionPolicy = "bounded_streaming", "implemented", "arrival_order"
	} else if p.cfg.CollectionPolicy.StreamingPipelineEnabled {
		streamingStatus = "not_applicable"
	}
	if !p.cfg.Modules.DomainExpansion {
		selectionPolicy = "not_requested"
	}
	if err := runStatus.Update(map[string]any{"pipeline_schedule": schedule, "streaming_requested": p.cfg.CollectionPolicy.StreamingPipelineEnabled, "streaming_schedule_status": streamingStatus, "dns_selection_policy": selectionPolicy}, true); err != nil {
		return result, err
	}
	if streaming {
		active, deferred, result.Incomplete, err = executeStreaming(ctx, p, payload, sink, stage, announce, func(provider, state, _ string) error {
			return runStatus.UpdateWorker(provider, "passive", "provider_collection", p.target, "", state, "Passive provider progress", nil, nil, true)
		})
		if err != nil {
			return result, err
		}
	} else {
		inventory := map[string]evidence.ProviderInventoryEntry{}
		if err := announce("passive_sources"); err != nil {
			return result, err
		}
		if p.cfg.Modules.Subdomains {
			collectionCtx, stopCollection := context.WithCancel(ctx)
			var progressMu sync.Mutex
			var progressErr error
			collected, err := stage.collect(collectionCtx, passive.CollectRequest{Config: p.cfg, Subfaster: payload.Subfaster, Sink: sink.emit,
				OnProgress: func(provider, state, _ string) {
					if e := runStatus.UpdateWorker(provider, "passive", "provider_collection", p.target, "", state, "Passive provider progress", nil, nil, true); e != nil {
						progressMu.Lock()
						progressErr = errors.Join(progressErr, e)
						progressMu.Unlock()
						stopCollection()
					}
				}})
			stopCollection()
			progressMu.Lock()
			err = errors.Join(err, progressErr)
			progressMu.Unlock()
			if err != nil {
				return result, err
			}
			inventory = collected.Inventory
			result.Incomplete = collectionIncomplete(collected)
		} else {
			ev, err := core.NewEvent(core.DomainFound, "input", "user_input", p.target, p.target, core.InScope)
			if err != nil {
				return result, err
			}
			ev.Confidence = 1
			ev.Metadata = map[string]any{"input_target": true, "collection": "user_input", "target_service_contacted": false}
			if err := sink.emit(ctx, ev); err != nil {
				return result, err
			}
		}
		var admission *dynamicDomainAdmission
		if p.cfg.Modules.DomainExpansion {
			if err := announce("public_dns"); err != nil {
				return result, err
			}
			client, err := stage.dnsClient(5*time.Second, p.cfg.RateLimits.DNSQueriesPerSecond)
			if err != nil {
				return result, err
			}
			expansionConfig := dns.ExpansionConfig{Root: p.target, Policy: p.cfg.ScopePolicy, Client: client, Index: index, Inventory: inventory,
				Budget: p.cfg.CollectionPolicy.DNSCandidateBudget, Workers: p.cfg.RateLimits.DNSWorkerCount,
				WildcardProbes: p.cfg.CollectionPolicy.WildcardProbesPerParent, WildcardParentBudget: p.cfg.CollectionPolicy.WildcardMaxParentZones,
				MaxEnrichmentIPs: p.cfg.CollectionPolicy.PassiveMaxIPs, WildcardEnabled: p.cfg.CollectionPolicy.WildcardEnabled,
				IncludeWildcardAmbiguous: p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive,
				Emit:                     func(ev core.Event) error { return sink.emit(ctx, ev) }}
			parents := wildcardParents(p.target, p.cfg.ScopePolicy, inventory, expansionConfig.Budget, expansionConfig.WildcardParentBudget)
			analyzer, err := dns.NewWildcardAnalyzer(p.target, client, expansionConfig.WildcardProbes, expansionConfig.WildcardParentBudget, expansionConfig.WildcardEnabled, parents)
			if err != nil {
				return result, err
			}
			expansionConfig.Analyzer = analyzer
			expanded, err := stage.expand(ctx, expansionConfig)
			if err != nil {
				return result, err
			}
			if p.cfg.DirectTargetInteraction() && p.cfg.CollectionPolicy.DynamicDiscoveryFromHTML {
				admission, err = newDynamicDomainAdmission(p.target, p.cfg.CollectionPolicy, p.cfg.ScopePolicy, len(expanded.Selected), expansionConfig, stage.expand)
				if err != nil {
					return result, err
				}
			}
			deferred = len(expanded.Deferred)
			if deferred > 0 {
				result.Incomplete = true
			}
		}
		if p.cfg.Modules.PortScan && p.cfg.CollectionPolicy.InternetdbEnabled {
			if err := announce("passive_port_inventory"); err != nil {
				return result, err
			}
			client, err := newInventoryClient(p.cfg)
			if err != nil {
				return result, err
			}
			incomplete, err := collectPortInventory(ctx, p.cfg, index, client, sink.emit)
			if err != nil {
				return result, err
			}
			result.Incomplete = result.Incomplete || incomplete
		}
		if p.cfg.DirectTargetInteraction() {
			if admission != nil {
				stage.ops.admitDomains = admission.Admit
			}
			active, err = executeActive(ctx, p, payload, sink, announce, stage.ops)
			result.Incomplete = result.Incomplete || active.Incomplete
			if err != nil {
				return result, err
			}
		}
	}
	sink.mu.Lock()
	result.Incomplete = result.Incomplete || sink.incomplete
	sink.mu.Unlock()
	if err := announce("persist_barrier"); err != nil {
		return result, err
	}
	if err := closeStore(); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	input, err := reportInput(p, started, eventPath, payload.FontDir, result.Incomplete, deferred)
	if err != nil {
		return result, err
	}
	if p.cfg.DirectTargetInteraction() {
		input.ConfirmedWebTargets = active.Targets
		input.Coverage = active.Coverage
		input.Coverage["incomplete"] = result.Incomplete
		input.Coverage["deferred_by_dns_budget"] = deferred

		input.BackendProvenance["active"] = active.BackendProvenance
	}
	input.Coverage["pipeline_schedule"] = schedule
	input.Coverage["streaming_requested"] = p.cfg.CollectionPolicy.StreamingPipelineEnabled
	input.Coverage["streaming_schedule_status"] = streamingStatus
	input.Coverage["dns_selection_policy"] = selectionPolicy
	if err := backends.WriteJSONAtomic(filepath.Join(dir, "backend_provenance.json"), input.BackendProvenance, true, true, true, false); err != nil {
		return result, err
	}
	if err := backends.WriteJSONAtomic(filepath.Join(dir, "run_summary.json"), map[string]any{"schema_version": 1, "asm_version": Version, "profile": p.cfg.Profile, "target_domain": p.target, "incomplete": result.Incomplete, "deferred_by_dns_budget": deferred, "active_target_contact": activeContact(p.cfg.DirectTargetInteraction(), active.Coverage), "coverage": input.Coverage}, true, true, true, false); err != nil {
		return result, err
	}
	if err := announce("report"); err != nil {
		return result, err
	}
	result.Outputs, err = stage.generate(ctx, input, payload)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := runStatus.Update(map[string]any{"incomplete": result.Incomplete, "completion": completion(result.Incomplete)}, true); err != nil {
		return result, err
	}
	return result, nil
}

func newInventoryClient(cfg config.ToolConfig) (*passive.Client, error) {
	return passive.NewClient(passive.HTTPPolicy{RequestsPerSecond: cfg.RateLimits.PassiveSourceRequestsPerSecond,
		ConnectTimeout: time.Duration(cfg.CollectionPolicy.PassiveConnectTimeoutSeconds * float64(time.Second)),
		ReadTimeout:    time.Duration(cfg.CollectionPolicy.PassiveReadTimeoutSeconds * float64(time.Second)),
		Retries:        cfg.CollectionPolicy.PassiveSourceRetries, CacheDir: filepath.Join(cfg.OutputDir, "cache", "passive"),
		CacheTTL:         time.Duration(cfg.CollectionPolicy.PassiveCacheTTLHours) * time.Hour,
		MaxResponseBytes: 2 << 20, MaxCacheBytes: 4 << 20, UserAgent: cfg.UserAgent}, nil)
}

func completion(incomplete bool) string {
	if incomplete {
		return "degraded"
	}
	return "complete"
}
func reportInput(p Plan, started time.Time, eventPath, fontDir string, incomplete bool, deferred int) (report.Input, error) {
	scope, err := object(p.cfg.ScopePolicy)
	if err != nil {
		return report.Input{}, err
	}
	modules, err := object(p.cfg.Modules)
	if err != nil {
		return report.Input{}, err
	}
	policy, err := object(p.cfg.CollectionPolicy)
	if err != nil {
		return report.Input{}, err
	}
	provenance := map[string]any{"schema_version": 1, "runtime": "go", "backends": []evidence.BackendResolution{
		evidence.ResolveBackend("serialization", p.cfg.Backends.SerializationBackend, "events/reports"),
		evidence.ResolveBackend("schema", p.cfg.Backends.SchemaBackend, "events/reports"),
		evidence.ResolveBackend("storage", "sqlite", "run"),
	}}
	limits := p.cfg.Reporting
	return report.Input{DatabasePath: p.cfg.DatabasePath, OutputDir: p.cfg.OutputDir, Version: Version, Profile: p.cfg.Profile,
		GeneratedAt: started, TargetDomain: p.target, Language: limits.Language, FullReport: limits.FullReport,
		RowLimits: report.RowLimits{Domain: limits.DomainRows, IP: limits.IPRows, Routing: limits.RoutingRows, RelatedDomain: limits.RelatedDomainRows, Port: limits.PortRows, WebCoverage: limits.WebCoverageRows, Web: limits.WebRows, Document: limits.DocumentRows, Screenshot: limits.ScreenshotRows},
		Scope:     scope, Modules: modules, CollectionPolicy: policy,
		Coverage:          map[string]any{"incomplete": incomplete, "deferred_by_dns_budget": deferred, "target_contacted": false, "http": "not_run_passive", "crawler": "not_run_passive", "tcp": "not_run_passive", "browser": "not_run_passive"},
		BackendProvenance: provenance, EventFiles: []string{eventPath}, FontDir: fontDir}, nil
}

// A failed active attempt is not evidence that no connection occurred.
func activeContact(active bool, coverage map[string]any) any {
	if !active {
		return false
	}
	return coverage["target_contacted"]
}
