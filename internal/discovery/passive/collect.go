package passive

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/platform"
)

const collectWorkers = 4
const subfasterTimeout = 360 * time.Second

type EventSink func(context.Context, core.Event) error
type ProgressSink func(provider, state, message string)

type CollectRequest struct {
	Config     config.ToolConfig
	HTTP       *Client
	Subfaster  *platform.Tool
	Sink       EventSink
	OnProgress ProgressSink
}

type CollectResult struct {
	Inventory map[string]evidence.ProviderInventoryEntry
	Providers []evidence.ProviderResult
	Truncated bool
}

type collectJob struct {
	name string
	role string
	run  func(context.Context, func(string, []string) (bool, error)) providerOutcome
}

type providerOutcome struct {
	result                  evidence.ProviderResult
	err                     error
	meta                    HTTPMeta
	start                   string
	finish                  string
	rows                    int
	stdoutLines             int
	malformed               int
	duplicates              int
	duplicateRows           int
	returnCode              int
	version                 string
	versionEvidenceStatus   string
	knownStartupNetworkRisk bool
	componentSHA256         string
	versionWarning          string
	binaryPath              string
	environmentMode         string
	expectedVersion         string
	truncated               bool
	truncationReason        string
	accepted                int
	deferred                int
	newToInventory          int
	pagesAttempted          int
	pagesCompleted          int
	httpAttempts            int
	httpLogical             int
	stderrLines             int
	duplicateRowsPresent    bool
	httpTelemetryPresent    bool
	httpTimeoutsPresent     bool
	rateLimited             bool
	connectTimeout          float64
	readTimeout             float64
	started                 time.Time
	finished                time.Time
}

type collectState struct {
	mu               sync.Mutex
	emitMu           sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	req              CollectRequest
	target           string
	cap              int
	seen             map[string]map[string]bool
	inventory        *evidence.ProviderInventoryAccumulator
	providerOutcomes map[string]providerOutcome
	jobs             []collectJob
	fallbackReason   string
	clientMu         sync.Mutex
	clients          map[string]*Client
	fatal            error
	capExceeded      bool
}

func Collect(ctx context.Context, req CollectRequest) (CollectResult, error) {
	if ctx == nil || req.Sink == nil {
		return CollectResult{}, errors.New("collect requires a context and durable event sink")
	}
	cfg := req.Config
	if cfg.CollectionPolicy.PassiveProviderProfile != "standard" && cfg.CollectionPolicy.PassiveProviderProfile != "deep" {
		return CollectResult{}, fmt.Errorf("unsupported passive provider profile %q", cfg.CollectionPolicy.PassiveProviderProfile)
	}
	if err := cfg.ScopePolicy.Validate(); err != nil {
		return CollectResult{}, err
	}
	targetRaw := ""
	if cfg.TargetDomain != nil {
		targetRaw = *cfg.TargetDomain
	} else if len(cfg.AllowedDomains) > 0 {
		targetRaw = cfg.AllowedDomains[0]
	}
	target, err := core.NormalizeDomain(targetRaw)
	if err != nil {
		return CollectResult{}, fmt.Errorf("invalid passive target: %w", err)
	}
	if decision := (core.ScopeChecker{Policy: cfg.ScopePolicy}).CheckDomain(target); decision.Status != core.InScope {
		return CollectResult{}, fmt.Errorf("passive target is not in scope: %s", decision.Reason)
	}
	cap := cfg.CollectionPolicy.PassiveInventorySafetyCap
	if cap < 1 {
		return CollectResult{}, errors.New("passive inventory safety cap must be positive")
	}
	inventory, err := evidence.NewProviderInventoryAccumulator(target)
	if err != nil {
		return CollectResult{}, err
	}
	workCtx, cancel := context.WithCancel(ctx)
	s := &collectState{ctx: workCtx, cancel: cancel, req: req, target: target, cap: cap, seen: map[string]map[string]bool{}, inventory: inventory, providerOutcomes: map[string]providerOutcome{}, clients: map[string]*Client{}}
	defer cancel()
	if err := s.emitInput(); err != nil {
		return CollectResult{}, err
	}
	jobs, err := s.plan()
	if err != nil {
		return CollectResult{}, err
	}
	if err = s.run(jobs); err != nil {
		return s.result(), err
	}
	if err = s.emitSummary(); err != nil {
		return s.result(), err
	}
	if err = ctx.Err(); err != nil {
		return s.result(), err
	}
	if err = s.writeCompleteness(); err != nil {
		return s.result(), err
	}
	return s.result(), nil
}

func newCollectHTTP(cfg config.ToolConfig, provider string) (*Client, error) {
	p := cfg.CollectionPolicy
	connect, err := secondsDuration(p.PassiveConnectTimeoutSeconds)
	if err != nil {
		return nil, err
	}
	read, err := secondsDuration(p.PassiveReadTimeoutSeconds)
	if err != nil {
		return nil, err
	}
	if provider == "crt.name" {
		connect, err = secondsDuration(p.CRTNameConnectTimeoutSeconds)
		if err != nil {
			return nil, err
		}
		read, err = secondsDuration(p.CRTNameReadTimeoutSeconds)
		if err != nil {
			return nil, err
		}
	}
	return NewClient(HTTPPolicy{
		RequestsPerSecond: cfg.RateLimits.PassiveSourceRequestsPerSecond,
		ConnectTimeout:    connect, ReadTimeout: read, Retries: p.PassiveSourceRetries,
		CacheDir:         filepath.Join(cfg.OutputDir, "cache", "passive"),
		CacheTTL:         time.Duration(p.PassiveCacheTTLHours) * time.Hour,
		MaxResponseBytes: 32 << 20, MaxCacheBytes: 64 << 20, UserAgent: cfg.UserAgent,
	}, nil)
}

func (s *collectState) httpClient(provider string) (*Client, error) {
	if s.req.HTTP != nil {
		return s.req.HTTP, nil
	}
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if c := s.clients[provider]; c != nil {
		return c, nil
	}
	c, err := newCollectHTTP(s.req.Config, provider)
	if err != nil {
		return nil, err
	}
	s.clients[provider] = c
	return c, nil
}

func secondsDuration(seconds float64) (time.Duration, error) {
	d := time.Duration(seconds * float64(time.Second))
	if seconds <= 0 || d <= 0 {
		return 0, errors.New("passive source timeout must be positive")
	}
	return d, nil
}

func (s *collectState) plan() ([]collectJob, error) {
	p := s.req.Config.CollectionPolicy
	if p.CRTNameEnabled {
		apex, _, err := core.RegisteredApex(s.target)
		if err != nil {
			return nil, err
		}
		client, err := s.httpClient("crt.name")
		if err != nil {
			return nil, err
		}
		s.addHTTPJob("crt.name", "primary", client, func(ctx context.Context) (FetchResult, error) {
			return CRTName(ctx, client, apex, s.target, s.cap)
		})
	}
	if p.THCEnabled {
		s.addSubfasterJob("thc", "primary")
	}
	if p.CRTShEnabled {
		client, err := s.httpClient("crt.sh")
		if err != nil {
			return nil, err
		}
		s.addHTTPJob("crt.sh", "primary", client, func(ctx context.Context) (FetchResult, error) {
			return CRTSh(ctx, client, s.target, s.cap)
		})
	}
	if p.CertspotterEnabled {
		client, err := s.httpClient("certspotter")
		if err != nil {
			return nil, err
		}
		s.addHTTPJob("certspotter", "primary", client, func(ctx context.Context) (FetchResult, error) {
			return CertSpotter(ctx, client, s.target, s.cap)
		})
	}
	if p.PassiveProviderProfile == "deep" {
		for _, name := range []string{"submd", "shodanct", "rapiddns", "hackertarget", "sitedossier"} {
			s.addSubfasterJob(name, "deep")
		}
	}
	jobs := s.jobs
	if p.PassiveProviderProfile == "standard" && p.SubMDFallbackEnabled && !p.CRTNameEnabled {
		s.fallbackReason = "; triggered_by=crt.name:disabled"
		jobs = append(jobs, s.subfasterJob("submd", "fallback"))
	}
	return jobs, nil
}

func (s *collectState) addHTTPJob(name, role string, client *Client, fetch func(context.Context) (FetchResult, error)) {
	s.jobs = append(s.jobs, collectJob{name: name, role: role, run: func(ctx context.Context, _ func(string, []string) (bool, error)) providerOutcome {
		started := time.Now()
		fetched, err := fetch(ctx)
		finished := time.Now()
		transportErrors := 0
		if err != nil || fetched.Status == "partial" && fetched.Error != "" {
			transportErrors = 1
		}
		policy := s.req.Config.CollectionPolicy
		connect, _ := secondsDuration(policy.PassiveConnectTimeoutSeconds)
		read, _ := secondsDuration(policy.PassiveReadTimeoutSeconds)
		if name == "crt.name" {
			connect, _ = secondsDuration(policy.CRTNameConnectTimeoutSeconds)
			read, _ = secondsDuration(policy.CRTNameReadTimeoutSeconds)
		}
		termination := fetched.TruncationReason
		if fetched.Meta.ErrorType != "" {
			termination = fetched.Meta.ErrorType
		}
		return providerOutcome{result: evidence.ProviderResult{Provider: name, Collector: "asm_http", Family: Family(name), Role: role, Status: fetched.Status, Warning: fetched.Error, CompletenessState: fetched.Completeness, TerminationReason: termination, ReturnedTotal: len(fetched.Observations), Truncated: fetched.Truncated, TransportErrors: transportErrors, Observations: toEvidenceObservations(fetched.Observations)}, err: err, meta: fetched.Meta, start: started.UTC().Format(time.RFC3339Nano), finish: finished.UTC().Format(time.RFC3339Nano), truncated: fetched.Truncated, truncationReason: fetched.TruncationReason, rateLimited: fetched.Meta.ErrorType == "rate_limited", started: started, finished: finished, pagesAttempted: fetched.PagesAttempted, pagesCompleted: fetched.PagesCompleted, httpAttempts: fetched.Meta.Attempts, httpLogical: fetched.Meta.LogicalRequests, httpTelemetryPresent: fetched.Meta.LogicalRequests > 0 || fetched.Meta.Attempts > 0 || fetched.Meta.CacheHit, httpTimeoutsPresent: true, connectTimeout: connect.Seconds(), readTimeout: read.Seconds()}
	}})
}

func toEvidenceObservations(in []Observation) []evidence.ProviderObservation {
	out := make([]evidence.ProviderObservation, 0, len(in))
	for _, o := range in {
		out = append(out, evidence.ProviderObservation{Hostname: o.Hostname, Provider: o.Provider, Collector: "asm_http", Family: o.Family, FirstSeen: o.FirstSeen, Raw: o.Raw, Metadata: o.Metadata})
	}
	return out
}

func (s *collectState) addSubfasterJob(name, role string) {
	s.jobs = append(s.jobs, s.subfasterJob(name, role))
}

func (s *collectState) subfasterJob(name, role string) collectJob {
	return collectJob{name: name, role: role, run: func(ctx context.Context, onRow func(string, []string) (bool, error)) providerOutcome {
		started := time.Now()
		out := providerOutcome{result: evidence.ProviderResult{Provider: name, Collector: "subfaster", Family: Family(name), Role: role}}
		if s.req.Subfaster == nil {
			out.err = errors.New("verified Subfaster bundle is unavailable")
		} else if err := s.req.Subfaster.Verify(); err != nil {
			out.err = fmt.Errorf("verify Subfaster: %w", err)
		} else {
			run, err := StreamSubfaster(ctx, *s.req.Subfaster, s.target, name, subfasterTimeout, func(_ context.Context, host string, sources []string) error {
				unique, rowErr := onRow(host, sources)
				if unique {
					out.rows++
				}
				return rowErr
			})
			out.err, out.returnCode, out.version = err, run.ReturnCode, run.Version
			out.componentSHA256 = run.ComponentSHA256
			out.versionEvidenceStatus = run.VersionEvidenceStatus
			out.knownStartupNetworkRisk = run.KnownStartupNetworkRisk
			if errors.Is(err, ErrSubfasterNetworkSafetyBlocked) {
				out.result.Status = "security_blocked"
				out.result.CompletenessState = evidence.CollectorFailed
				out.result.TerminationReason = "blocked_before_process_creation"
				out.version = run.PinnedVersion
			}
			s.mu.Lock()
			streamed := s.providerOutcomes[name]
			out.rows = streamed.result.ReturnedTotal
			out.duplicateRows = streamed.duplicateRows
			out.truncated = streamed.truncated
			out.truncationReason = streamed.truncationReason
			s.mu.Unlock()
			out.binaryPath = s.req.Subfaster.Path()
			out.environmentMode = "verified_subprocess"
			out.expectedVersion = ExpectedSubfasterVersion
			out.stdoutLines = run.StdoutLines
			out.stderrLines = len(nonEmptyLines(run.Stderr))
			out.duplicateRowsPresent = true
			diagnostics := subfasterStderrDiagnostics(run.Stderr)
			out.rateLimited = diagnostics.rateLimited
			out.result.TransportErrors = diagnostics.errors
			if out.returnCode != 0 && out.result.TransportErrors == 0 {
				out.result.TransportErrors = 1
			}
			if out.version != "" && out.version != ExpectedSubfasterVersion {
				out.versionWarning = "tested version " + ExpectedSubfasterVersion + "; actual version " + out.version
			} else if out.version == "" {
				out.versionWarning = "runtime version was not executed; bundle manifest declares Subfaster " + ExpectedSubfasterVersion
			}
			out.malformed = run.MalformedLines
		}
		finished := time.Now()
		out.started, out.finished = started, finished
		out.start, out.finish = started.UTC().Format(time.RFC3339Nano), finished.UTC().Format(time.RFC3339Nano)
		out.result.ReturnedTotal = out.rows
		out.result.Truncated = out.truncated
		out.result.TerminationReason = out.truncationReason
		out.result.Warning = subfasterMessage(out.err, out.rows, out.duplicateRows)
		if out.err == nil && out.rateLimited {
			out.result.Warning += "; stderr indicates provider rate limiting"
		} else if out.err == nil && out.result.TransportErrors > 0 {
			out.result.Warning += "; stderr reports provider errors"
		}
		if errors.Is(out.err, ErrSubfasterNetworkSafetyBlocked) {
			out.result.Status = "security_blocked"
			out.result.TerminationReason = "blocked_before_process_creation"
			out.result.CompletenessState = evidence.CollectorFailed
		} else {
			out.result.TerminationReason = subfasterTermination(out.err, out.returnCode, out.rateLimited, out.result.TransportErrors)
			if out.err != nil {
				out.result.Status = subfasterStatus(out.err, out.rows)
			} else if out.truncated || out.rateLimited || out.result.TransportErrors > 0 {
				out.result.Status = "partial"
			} else if out.rows == 0 {
				out.result.Status = "no_data"
			} else {
				out.result.Status = "ok"
			}
			out.result.CompletenessState = evidence.ClassifyCompleteness(out.result.Status, intPointer(out.returnCode), errors.Is(out.err, context.DeadlineExceeded), out.rateLimited, out.result.TransportErrors, false, false, out.result.ReturnedTotal, out.truncated)
		}
		return out
	}}
}

// jobs is initialized separately so the plan remains a straightforward list of immutable source tasks.
//
//nolint:structcheck
func (s *collectState) run(jobs []collectJob) error {
	if len(jobs) == 0 {
		return s.ctx.Err()
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	tasks := make(chan collectJob, len(jobs)+1)
	results := make(chan providerOutcomeEnvelope, collectWorkers)
	for _, job := range jobs {
		tasks <- job
	}
	workers := min(collectWorkers, len(jobs)+1)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range tasks {
				if ctx.Err() != nil {
					results <- providerOutcomeEnvelope{name: job.name, role: job.role, outcome: failedOutcome(job.name, job.role, ctx.Err())}
					continue
				}
				s.beginProvider(job)
				out := job.run(ctx, func(host string, sources []string) (bool, error) {
					return s.ingestSubfaster(ctx, job.name, host, sources)
				})
				results <- providerOutcomeEnvelope{name: job.name, role: job.role, outcome: out}
			}
		}()
	}
	remaining := len(jobs)
	fallbackAdded := false
	for remaining > 0 {
		envelope := <-results
		remaining--
		out := envelope.outcome
		if envelope.name == "crt.name" && !fallbackAdded && s.req.Config.CollectionPolicy.PassiveProviderProfile == "standard" && s.req.Config.CollectionPolicy.SubMDFallbackEnabled && (out.err != nil || out.result.Status != "ok" || out.meta.CacheStale) && ctx.Err() == nil {
			fallbackAdded = true
			job := s.subfasterJob("submd", "fallback")
			s.mu.Lock()
			s.fallbackReason = fallbackTrigger(out)
			s.mu.Unlock()
			tasks <- job
			remaining++
		}
		if envelope.name == "submd" && envelope.role == "fallback" {
			s.mu.Lock()
			out.result.Warning += s.fallbackReason
			s.mu.Unlock()
		}
		if err := s.consume(ctx, envelope.name, out); err != nil {
			cancel()
		}
		if s.hasFatal() {
			cancel()
		}
	}
	close(tasks)
	wg.Wait()
	s.mu.Lock()
	fatal := s.fatal
	s.mu.Unlock()
	if fatal != nil {
		return fatal
	}
	return s.ctx.Err()
}

type providerOutcomeEnvelope struct {
	name, role string
	outcome    providerOutcome
}

func failedOutcome(provider, role string, err error) providerOutcome {
	status := "failed"
	if errors.Is(err, context.DeadlineExceeded) {
		status = "timeout"
	}
	if errors.Is(err, context.Canceled) {
		status = "cancelled"
	}
	return providerOutcome{result: evidence.ProviderResult{Provider: provider, Collector: "unknown", Family: Family(provider), Role: role, Status: status, CompletenessState: evidence.ClassifyCompleteness(status, nil, status == "timeout", false, 1, false, false, 0, false), TransportErrors: 1}, err: err, start: time.Now().UTC().Format(time.RFC3339Nano), finish: time.Now().UTC().Format(time.RFC3339Nano)}
}

func (s *collectState) consume(ctx context.Context, provider string, out providerOutcome) error {
	status := out.result.Status
	if errors.Is(out.err, ErrSubfasterNetworkSafetyBlocked) {
		status = "security_blocked"
		out.result.Status = status
		if out.result.Warning == "" {
			out.result.Warning = out.err.Error()
		} else if !strings.Contains(out.result.Warning, out.err.Error()) {
			out.result.Warning += "; " + out.err.Error()
		}
		out.result.CompletenessState = evidence.CollectorFailed
		out.result.TerminationReason = "blocked_before_process_creation"
		out.result.TransportErrors = 0
	} else if out.err != nil {
		if status != "partial" {
			status = collectErrorStatus(out.err)
		}
		out.result.Status = status
		out.result.Warning = out.err.Error()
		out.result.TransportErrors = 1
	}
	if status == "" {
		status = "failed"
		out.result.Status = status
	}
	observations := out.result.Observations
	out.result.Observations = nil // Release fetched row/event buffers after ingestion.
	s.mu.Lock()
	current := s.providerOutcomes[provider]
	current.result = out.result
	current.err, current.meta = out.err, out.meta
	current.start, current.finish = out.start, out.finish
	current.started, current.finished = out.started, out.finished
	current.rows, current.stdoutLines, current.malformed, current.returnCode = out.rows, out.stdoutLines, out.malformed, out.returnCode
	current.version, current.versionWarning = out.version, out.versionWarning
	current.versionEvidenceStatus, current.knownStartupNetworkRisk = out.versionEvidenceStatus, out.knownStartupNetworkRisk
	current.componentSHA256 = out.componentSHA256
	current.binaryPath = out.binaryPath
	current.environmentMode = out.environmentMode
	current.expectedVersion = out.expectedVersion
	current.pagesAttempted, current.pagesCompleted = out.pagesAttempted, out.pagesCompleted
	current.httpAttempts, current.httpLogical, current.stderrLines = out.httpAttempts, out.httpLogical, out.stderrLines
	current.duplicateRowsPresent = out.duplicateRowsPresent
	current.httpTelemetryPresent = out.httpTelemetryPresent
	current.httpTimeoutsPresent = out.httpTimeoutsPresent
	current.connectTimeout, current.readTimeout = out.connectTimeout, out.readTimeout
	current.rateLimited = current.rateLimited || out.rateLimited
	current.truncated = current.truncated || out.truncated
	if out.truncationReason != "" {
		current.truncationReason = out.truncationReason
	}
	s.providerOutcomes[provider] = current
	s.mu.Unlock()
	for _, observation := range observations {
		if err := s.ingestObservation(ctx, observation, status, out.meta); err != nil {
			return err
		}
	}
	s.mu.Lock()
	current = s.providerOutcomes[provider]
	current.result.ReturnedTotal = max(current.result.ReturnedTotal, out.result.ReturnedTotal)
	current.result.Truncated = current.truncated
	current.result.TransportErrors = out.result.TransportErrors
	current.result.CompletenessState = out.result.CompletenessState
	if current.truncated {
		current.result.CompletenessState = evidence.PaginationIncomplete
	}
	if current.result.CompletenessState == "" {
		completePagination := provider == "certspotter" && status == "ok"
		current.result.CompletenessState = evidence.ClassifyCompleteness(status, intPointer(out.returnCode), errors.Is(out.err, context.DeadlineExceeded), false, current.result.TransportErrors, completePagination, false, current.result.ReturnedTotal, current.truncated)
	}
	out = current
	s.providerOutcomes[provider] = current
	s.mu.Unlock()
	if err := s.emitHealth(ctx, provider, out); err != nil {
		return err
	}
	if s.req.OnProgress != nil {
		s.req.OnProgress(provider, "complete", status)
	}
	return nil
}

func (s *collectState) beginProvider(job collectJob) {
	s.mu.Lock()
	if _, ok := s.providerOutcomes[job.name]; !ok {
		collector := "asm_http"
		if job.name == "thc" || job.name == "submd" || job.name == "shodanct" || job.name == "rapiddns" || job.name == "hackertarget" || job.name == "sitedossier" {
			collector = "subfaster"
		}
		s.providerOutcomes[job.name] = providerOutcome{result: evidence.ProviderResult{Provider: job.name, Collector: collector, Family: Family(job.name), Role: job.role}}
	}
	s.mu.Unlock()
}

func (s *collectState) hasFatal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal != nil
}

func (s *collectState) emitInput() error {
	ev, err := core.NewEvent(core.DomainFound, "subdomains", "input", s.target, s.target, core.InScope)
	if err != nil {
		return err
	}
	ev.Confidence = 1
	ev.Metadata = map[string]any{"collection": "user_input", "input_target": true, "provider": "user_input", "collector_tool": "input", "evidence_family": "user_input", "target_contacted_by_asm": false}
	if err := s.emitSerialized(s.ctx, ev); err != nil {
		return err
	}
	return nil // The shared accumulator already includes its canonical input-root entry.
}

func (s *collectState) emitSerialized(ctx context.Context, event core.Event) error {
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	return s.emitWithLock(ctx, event)
}

func (s *collectState) emitAndCommit(ctx context.Context, event core.Event, commit func() error) error {
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	if err := s.emitWithLock(ctx, event); err != nil {
		return err
	}
	return commit()
}

// emitWithLock is called with emitMu held so callbacks and live commits have
// one durable order without holding collectState.mu across caller code.
func (s *collectState) emitWithLock(ctx context.Context, event core.Event) error {
	if err := ctx.Err(); err != nil {
		return s.stop(err)
	}
	if err := s.req.Sink(ctx, event); err != nil {
		return s.stop(err)
	}
	return nil
}

func (s *collectState) ingestSubfaster(ctx context.Context, provider, raw string, sources []string) (bool, error) {
	if len(sources) == 0 {
		return false, nil
	}
	name, err := core.NormalizeDomain(raw)
	if err != nil {
		return false, nil
	}
	key := provider + "\x00subfaster"
	s.mu.Lock()
	if s.fatal != nil {
		fatal := s.fatal
		s.mu.Unlock()
		return false, fatal
	}
	seen := s.seen[key]
	if seen == nil {
		seen = map[string]bool{}
		s.seen[key] = seen
	}
	if seen[name] {
		out := s.providerOutcomes[provider]
		out.duplicateRows++
		s.providerOutcomes[provider] = out
		s.mu.Unlock()
		return false, nil
	}
	if len(seen) >= s.cap {
		out := s.providerOutcomes[provider]
		out.truncated = true
		out.truncationReason = "provider output reached passive inventory safety cap"
		out.result.Truncated = true
		s.providerOutcomes[provider] = out
		s.mu.Unlock()
		return false, nil
	}
	seen[name] = true
	out := s.providerOutcomes[provider]
	out.result.ReturnedTotal++
	s.providerOutcomes[provider] = out
	s.mu.Unlock()
	observation := evidence.ProviderObservation{Hostname: name, Provider: provider, Collector: "subfaster", Family: SubfasterFamily(provider), Raw: raw, Metadata: map[string]any{"reported_sources": append([]string(nil), sources...), "explicit_source_selection": provider}}
	return true, s.ingestObservation(ctx, observation, "streaming", HTTPMeta{}, true)
}

func (s *collectState) ingestObservation(ctx context.Context, o evidence.ProviderObservation, status string, meta HTTPMeta, sourceDeduped ...bool) error {
	name, err := core.NormalizeDomain(o.Hostname)
	if err != nil {
		return nil
	}
	decision := (core.ScopeChecker{Policy: s.req.Config.ScopePolicy}).CheckDomain(name)
	if decision.Status != core.InScope {
		return nil
	}
	provider, collector, family := o.Provider, o.Collector, o.Family
	if provider == "" || collector == "" {
		return nil
	}
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	if err := ctx.Err(); err != nil {
		return s.stop(err)
	}
	key := provider + "\x00" + collector
	s.mu.Lock()
	if s.fatal != nil {
		err := s.fatal
		s.mu.Unlock()
		return err
	}
	seen := s.seen[key]
	if seen == nil {
		seen = map[string]bool{}
	}
	deduped := len(sourceDeduped) > 0 && sourceDeduped[0]
	if !deduped {
		if seen[name] {
			s.mu.Unlock()
			return nil
		}
		if len(seen) >= s.cap {
			seen[name] = true
			s.seen[key] = seen
			s.providerOutcomes[provider] = addTruncated(s.providerOutcomes[provider])
			s.capExceeded = true
			s.mu.Unlock()
			return nil
		}
	}
	existed := s.inventory.Contains(name)
	if !existed && s.inventory.Len() >= s.cap {
		if !deduped {
			seen[name] = true
			s.seen[key] = seen
		}
		s.capExceeded = true
		s.providerOutcomes[provider] = addTruncated(s.providerOutcomes[provider])
		s.mu.Unlock()
		return nil
	}
	newInventoryName := !existed
	kind := core.SubdomainFound
	if name == s.target {
		kind = core.DomainFound
	}
	relations := []map[string]any{}
	if name != s.target {
		relations = append(relations, map[string]any{"source_id": "domain:" + name, "target_id": "domain:" + s.target, "relation_type": "subdomain_of", "evidence": map[string]any{"provider": provider, "collector": collector, "evidence_family": family}})
	}
	metadata := map[string]any{"collection": "passive_osint", "target_contacted_by_asm": false, "target_contacted": false, "provider": provider, "collector_tool": collector, "evidence_family": family, "provider_unknown_aggregate": provider == UnknownAggregate, "independent_provider_evidence": provider != UnknownAggregate, "provider_metadata": o.Metadata, "first_seen_by_provider": o.FirstSeen, "cache_hit": meta.CacheHit, "cache_stale": meta.CacheStale, "input_target": name == s.target, "dns_validated": false}
	ev, err := core.NewEvent(kind, "subdomains", provider, o.Raw, name, decision.Status)
	if err != nil {
		s.mu.Unlock()
		return s.stop(err)
	}
	ev.Confidence = .62
	if name == s.target {
		ev.Confidence = 1
	}
	ev.Relations, ev.Metadata = relations, metadata
	s.mu.Unlock()
	if err = s.emitWithLock(ctx, ev); err != nil {
		return err
	}
	s.mu.Lock()
	if err = s.inventory.AddObservation(name, kind, decision.Status, metadata); err != nil {
		s.mu.Unlock()
		return s.stop(err)
	}
	s.providerOutcomes[provider] = addAccepted(s.providerOutcomes[provider])
	if newInventoryName {
		s.providerOutcomes[provider] = addNewInventory(s.providerOutcomes[provider])
	} else {
		s.providerOutcomes[provider] = addDuplicate(s.providerOutcomes[provider])
	}
	if !deduped {
		s.seen[key] = seen
		seen[name] = true
	}
	accepted := s.providerOutcomes[provider].accepted
	s.mu.Unlock()
	if family == "certificate_transparency" {
		tls, eventErr := core.NewEvent(core.TLSNameFound, "subdomains", provider, o.Raw, name, decision.Status)
		if eventErr != nil {
			return s.stop(eventErr)
		}
		tlsMetadata := make(map[string]any, len(metadata)+1)
		for key, value := range metadata {
			tlsMetadata[key] = value
		}
		tlsMetadata["collection"] = "certificate_transparency"
		tlsMetadata["meaning"] = "name observed in public certificate-transparency data"
		tls.Confidence, tls.Relations, tls.Metadata = .68, relations, tlsMetadata
		if err = s.emitWithLock(ctx, tls); err != nil {
			return err
		}
	}
	if s.req.OnProgress != nil {
		s.req.OnProgress(provider, "collecting", fmt.Sprintf("accepted %d in-scope names", accepted))
	}
	return nil
}

func (s *collectState) emitHealth(ctx context.Context, provider string, out providerOutcome) error {
	r := out.result
	metadata := s.healthMetadata(provider, out)
	message := r.Warning
	rawValue := any(r.Status)
	if message != "" {
		rawValue = message
	}
	ev, err := core.NewEvent(core.SourceHealth, "subdomains", provider, rawValue, provider, core.InScope)
	if err != nil {
		return err
	}
	ev.Confidence = .5
	if r.Status == "ok" || r.Status == "no_data" || r.Status == "fallback_not_needed" || r.Status == "skipped" {
		ev.Confidence = 1
	}
	ev.Metadata = metadata
	if err = s.emitSerialized(ctx, ev); err != nil {
		return err
	}
	if r.Status == "partial" || r.Status == "failed" || r.Status == "unavailable" || r.Status == "timeout" || r.Status == "rate_limited" || r.Status == "security_blocked" {
		if message == "" {
			message = fmt.Sprintf("Passive provider %s ended with status %s.", provider, r.Status)
		}
		lim, e := core.NewEvent(core.Limitation, "subdomains", provider, message, s.target, core.InScope)
		if e != nil {
			return e
		}
		lim.Confidence = 0
		lim.Metadata = map[string]any{"severity": "warning", "provider": provider, "collector": r.Collector, "provider_status": r.Status, "error_type": nullableString(out.meta.ErrorType), "target_contacted_by_asm": false}
		if r.Status == "security_blocked" {
			lim.Metadata["security_status"] = r.Status
			lim.Metadata["completeness_state"] = r.CompletenessState
			lim.Metadata["termination_reason"] = r.TerminationReason
			if out.version != "" {
				lim.Metadata["component_version"] = out.version
			}
			if out.componentSHA256 != "" {
				lim.Metadata["component_sha256"] = out.componentSHA256
			}
		}
		if err = s.emitSerialized(ctx, lim); err != nil {
			return err
		}
	}
	if provider == "thc" && r.CompletenessState != "" && r.CompletenessState != evidence.Complete && r.CompletenessState != evidence.CompleteEmpty {
		lim, e := core.NewEvent(core.Limitation, "subdomains", provider, "THC collector technical completion does not prove complete provider pagination in this run.", s.target, core.InScope)
		if e != nil {
			return e
		}
		lim.Confidence = 0
		lim.Metadata = map[string]any{"severity": "warning", "provider": provider, "collector": r.Collector, "provider_status": r.Status, "completeness_state": r.CompletenessState, "termination_reason": r.TerminationReason, "target_contacted_by_asm": false}
		if err = s.emitSerialized(ctx, lim); err != nil {
			return err
		}
	}
	return nil
}

func (s *collectState) healthMetadata(provider string, out providerOutcome) map[string]any {
	r := out.result
	elapsed := 0.0
	if !out.started.IsZero() && !out.finished.IsZero() {
		elapsed = math.Round(out.finished.Sub(out.started).Seconds()*1e6) / 1e6
	}
	errorType := out.meta.ErrorType
	if errorType == "" && out.err != nil {
		errorType = collectErrorStatus(out.err)
	}
	message := r.Warning
	var expected any
	if out.expectedVersion != "" {
		expected = out.expectedVersion
	}
	var pagesAttempted, pagesCompleted any
	if out.pagesAttempted > 0 {
		pagesAttempted, pagesCompleted = out.pagesAttempted, out.pagesCompleted
	}
	var httpAttempts, httpLogical, connect, read any
	if r.Collector == "asm_http" && out.httpTelemetryPresent {
		httpAttempts, httpLogical = out.httpAttempts, out.httpLogical
	}
	if r.Collector == "asm_http" && out.httpTimeoutsPresent {
		connect, read = out.connectTimeout, out.readTimeout
	}
	var stdout, stderr, malformed, returnCode any
	if r.Collector == "subfaster" {
		stdout, stderr, malformed, returnCode = out.stdoutLines, out.stderrLines, out.malformed, out.returnCode
	}
	var binary any
	if out.binaryPath != "" {
		binary = out.binaryPath
	}
	var env any
	if out.environmentMode != "" {
		env = out.environmentMode
	}
	metadata := map[string]any{
		"collection": "passive_osint_source_health", "target_contacted_by_asm": false,
		"provider": provider, "collector": r.Collector, "role": r.Role, "status": r.Status,
		"started_at": nullableString(out.start), "finished_at": nullableString(out.finish), "elapsed_seconds": elapsed,
		"returned_total": r.ReturnedTotal, "accepted_in_scope": out.accepted, "duplicate_existing": out.duplicates,
		"new_to_inventory_at_ingest": out.newToInventory, "deferred_by_inventory_safety_cap": out.deferred,
		"dns_attempted": 0, "dns_resolved": 0, "dns_clean_or_distinct": 0, "dns_wildcard_ambiguous": 0, "dns_not_resolved": 0,
		"error_type": nullableString(errorType), "message": nullableString(message), "technical_error": nullableString(technicalError(out.err)),
		"cache_hit": out.meta.CacheHit, "cache_stale": out.meta.CacheStale, "cache_age_seconds": nullableFloat(out.meta.CacheAgeSeconds, out.meta.CacheHit),
		"fallback_after_error": nullableString(out.meta.FallbackAfterError), "last_http_status": nullableInt(out.meta.StatusCode),
		"truncated": out.truncated, "truncation_reason": nullableString(out.truncationReason), "tool_version": nullableString(out.version),
		"binary_path": binary, "expected_version": expected, "version_warning": nullableString(out.versionWarning),
		"http_attempts": httpAttempts, "http_logical_requests": httpLogical, "connect_timeout_seconds": connect, "read_timeout_seconds": read,
		"timeout_phase": nullableString(out.meta.TimeoutPhase), "collector_returncode": returnCode,
		"environment_mode": env, "stdout_lines": stdout, "stderr_lines": stderr,
		"duplicate_rows": nullableIntIf(out.duplicateRows, out.duplicateRowsPresent), "malformed_output_lines": malformed,
		"requests_attempted": nil, "pages_attempted": pagesAttempted, "pages_completed": pagesCompleted,
		"pagination_telemetry_status": nullableString(paginationTelemetry(out)), "transport_errors": r.TransportErrors,
		"termination_reason": nullableString(r.TerminationReason), "completeness_state": nullableString(r.CompletenessState),
	}
	if out.componentSHA256 != "" {
		metadata["component_sha256"] = out.componentSHA256
	}
	if r.Collector == "subfaster" {
		if out.versionEvidenceStatus != "" {
			metadata["version_evidence_status"] = out.versionEvidenceStatus
		}
		if out.knownStartupNetworkRisk {
			metadata["known_startup_network_risk"] = true
			metadata["known_startup_network_risk_detail"] = SubfasterStartupNetworkRisk
		}
	}
	return metadata
}

func (s *collectState) emitSummary() error {
	inventory := s.inventory.Snapshot()
	names := make([]string, 0, len(inventory))
	for name := range inventory {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		item := passiveAttribution(inventory[name])
		providers, families, collectors := item.Providers, item.EvidenceFamilies, item.Collectors
		if name == s.target && len(providers)+len(families)+len(collectors) == 0 {
			continue // The input-root event is not an aggregate provider observation.
		}
		confidence := passiveConfidence(len(providers), len(families), hasCTProvider(providers))
		if name == s.target {
			confidence = 1
		}
		kind := core.SubdomainFound
		if name == s.target {
			kind = core.DomainFound
		}
		ev, err := core.NewEvent(kind, "subdomains", "passive_orchestrator", name, name, core.InScope)
		if err != nil {
			return err
		}
		ev.Confidence = confidence
		relations := []map[string]any{}
		if name != s.target {
			relations = append(relations, map[string]any{"source_id": "domain:" + name, "target_id": "domain:" + s.target, "relation_type": "subdomain_of", "evidence": map[string]any{"providers": providers}})
		}
		ev.Relations = relations
		ev.Metadata = map[string]any{"collection": "passive_inventory_summary", "target_contacted_by_asm": false, "providers": providers, "collectors": collectors, "evidence_families": families, "unique_provider_count": len(providers), "collector_count": len(collectors), "unique_evidence_family_count": len(families), "found_by": providers, "dns_validated": false}
		if err = s.emitAndCommit(s.ctx, ev, func() error { return s.inventory.AddEvent(ev) }); err != nil {
			return s.stop(err)
		}
	}
	if s.req.Config.CollectionPolicy.PassiveProviderProfile == "standard" && s.req.Config.CollectionPolicy.SubMDFallbackEnabled && s.req.Config.CollectionPolicy.CRTNameEnabled {
		if outcome, ok := s.providerOutcomes["crt.name"]; ok && outcome.result.Status == "ok" && !outcome.meta.CacheStale {
			if _, exists := s.providerOutcomes["submd"]; !exists {
				if err := s.emitFallbackNotNeeded(); err != nil {
					return err
				}
			}
		}
	}
	if s.capExceeded {
		ev, err := core.NewEvent(core.Limitation, "subdomains", "passive_inventory", "Passive inventory safety ceiling was reached; additional new hostnames were not retained.", s.target, core.InScope)
		if err != nil {
			return err
		}
		ev.Metadata = map[string]any{"severity": "warning", "limitation_type": "passive_inventory_safety_cap", "configured_cap": s.cap, "inventory_retained": s.inventory.Len()}
		if err = s.emitSerialized(s.ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *collectState) emitFallbackNotNeeded() error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ev, err := core.NewEvent(core.SourceHealth, "subdomains", "submd", "crt.name completed with fresh data; fallback not needed", "submd", core.InScope)
	if err != nil {
		return err
	}
	ev.Confidence = 1
	ev.Metadata = map[string]any{"collection": "passive_osint_source_health", "target_contacted_by_asm": false, "provider": "submd", "collector": "subfaster", "role": "fallback", "status": "fallback_not_needed", "started_at": now, "finished_at": now, "elapsed_seconds": 0.0, "returned_total": 0, "accepted_in_scope": 0, "duplicate_existing": 0, "new_to_inventory_at_ingest": 0, "deferred_by_inventory_safety_cap": 0, "dns_attempted": 0, "dns_resolved": 0, "dns_clean_or_distinct": 0, "dns_wildcard_ambiguous": 0, "dns_not_resolved": 0, "error_type": nil, "message": "crt.name completed with fresh data; fallback not needed", "technical_error": nil, "cache_hit": false, "cache_stale": false, "cache_age_seconds": nil, "fallback_after_error": nil, "last_http_status": nil, "truncated": false, "truncation_reason": nil, "tool_version": nil, "binary_path": nil, "expected_version": ExpectedSubfasterVersion, "version_warning": nil, "http_attempts": nil, "http_logical_requests": nil, "connect_timeout_seconds": nil, "read_timeout_seconds": nil, "timeout_phase": nil, "collector_returncode": nil, "environment_mode": nil, "stdout_lines": nil, "stderr_lines": nil, "duplicate_rows": nil, "malformed_output_lines": nil, "requests_attempted": nil, "pages_attempted": nil, "pages_completed": nil, "pagination_telemetry_status": nil, "transport_errors": 0, "termination_reason": nil, "completeness_state": nil}
	if err := s.emitSerialized(s.ctx, ev); err != nil {
		return err
	}
	return nil
}

func (s *collectState) result() CollectResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := CollectResult{Inventory: s.inventory.Snapshot(), Truncated: s.capExceeded}
	for _, o := range s.providerOutcomes {
		r := o.result
		r.Observations = nil
		out.Providers = append(out.Providers, r)
		out.Truncated = out.Truncated || r.Truncated
	}
	sort.Slice(out.Providers, func(i, j int) bool { return out.Providers[i].Provider < out.Providers[j].Provider })
	return out
}

func (s *collectState) stop(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked(err)
}
func (s *collectState) stopLocked(err error) error {
	if s.fatal == nil {
		s.fatal = err
		s.cancel()
	}
	return err
}

func collectErrorStatus(err error) string {
	if errors.Is(err, ErrSubfasterNetworkSafetyBlocked) {
		return "security_blocked"
	}
	var source *SourceError
	if errors.As(err, &source) {
		if source.Kind != "" {
			return source.Kind
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "failed"
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableIntIf(value int, present bool) any {
	if !present {
		return nil
	}
	return value
}

func nullableFloat(value float64, present bool) any {
	if !present {
		return nil
	}
	return value
}

func technicalError(err error) string {
	if err == nil {
		return ""
	}
	var source *SourceError
	if errors.As(err, &source) && source.StatusCode != 0 {
		return fmt.Sprintf("HTTP %d", source.StatusCode)
	}
	return err.Error()
}

func paginationTelemetry(out providerOutcome) string {
	if out.pagesAttempted == 0 {
		return ""
	}
	if out.pagesAttempted == out.pagesCompleted && (out.result.CompletenessState == evidence.Complete || out.result.CompletenessState == evidence.CompleteEmpty) {
		return "complete"
	}
	return "partial"
}

func nonEmptyLines(value string) []string {
	lines := strings.Split(value, "\n")
	out := lines[:0]
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

type subfasterDiagnostics struct {
	errors      int
	rateLimited bool
}

func subfasterStderrDiagnostics(stderr string) subfasterDiagnostics {
	d := subfasterDiagnostics{}
	for _, line := range nonEmptyLines(stderr) {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(line, "429") || strings.Contains(line, "rate limit") || strings.Contains(line, "ratelimit") {
			d.rateLimited = true
		}
		if strings.Contains(line, "error") || strings.Contains(line, "failed") || strings.Contains(line, "failure") || strings.Contains(line, "429") || strings.Contains(line, "rate limit") || strings.Contains(line, "timeout") || strings.Contains(line, "timed out") {
			d.errors++
		}
	}
	return d
}

func subfasterTermination(err error, returnCode int, rateLimited bool, transportErrors int) string {
	if returnCode != 0 {
		return "collector_nonzero_exit"
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "timeout"
		}
		if errors.Is(err, context.Canceled) {
			return "cancelled"
		}
		return "collector_exception"
	}
	if rateLimited {
		return "collector_exit_0_with_rate_limit_evidence"
	}
	if transportErrors > 0 {
		return "collector_exit_0_with_transport_error_evidence"
	}
	return "collector_exit_0"
}

func subfasterMessage(err error, returned, duplicateRows int) string {
	if err != nil {
		return err.Error()
	}
	message := "provider returned no in-scope names"
	if returned > 0 {
		message = fmt.Sprintf("provider returned %d normalized unique observations", returned)
	}
	if duplicateRows > 0 {
		message += fmt.Sprintf("; normalized_rows=%d", returned+duplicateRows)
	}
	return message
}

func hasCTProvider(providers []string) bool {
	for _, provider := range providers {
		if provider == "crt.sh" || provider == "certspotter" {
			return true
		}
	}
	return false
}

func passiveConfidence(providerCount, familyCount int, directCT bool) float64 {
	value := 0.58 + min(0.18, 0.06*float64(max(0, providerCount-1))) + min(0.14, 0.07*float64(max(0, familyCount-1)))
	if directCT {
		value += 0.05
	}
	return min(0.95, value)
}
func terminationReason(err error, code int) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if err != nil {
		return "collector_exception"
	}
	if code != 0 {
		return "collector_nonzero_exit"
	}
	return "collector_exit_0"
}
func fallbackTrigger(out providerOutcome) string {
	if out.meta.CacheStale && out.err == nil && out.result.Status == "ok" {
		return "; triggered_by=crt.name:stale_cache"
	}
	if out.err != nil {
		return "; triggered_by=crt.name:" + collectErrorStatus(out.err)
	}
	return "; triggered_by=crt.name:" + out.result.Status
}
func intPointer(v int) *int { return &v }
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func sortedBoolKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func subfasterStatus(err error, returned int) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if returned > 0 {
		return "partial"
	}
	return collectErrorStatus(err)
}

func addAccepted(o providerOutcome) providerOutcome     { o.accepted++; return o }
func addNewInventory(o providerOutcome) providerOutcome { o.newToInventory++; return o }
func addDuplicate(o providerOutcome) providerOutcome    { o.duplicates++; return o }
func addTruncated(o providerOutcome) providerOutcome {
	o.truncated = true
	o.deferred++
	o.result.Truncated = true
	o.result.CompletenessState = evidence.PaginationIncomplete
	return o
}
