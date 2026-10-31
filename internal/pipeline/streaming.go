package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/active/web"
	"asmtool/internal/core"
	"asmtool/internal/discovery/dns"
	"asmtool/internal/evidence"
)

type Config struct {
	Root                                   string
	Policy                                 core.ScopePolicy
	Index                                  *evidence.DNSRunIndex
	PassiveBarrier                         func(context.Context) error
	DNS                                    dns.ExpansionConfig
	HTTP                                   *activehttp.Client
	Emit                                   func(core.Event) error
	KnownWebURLs                           []string
	PerHostRequests                        int
	PrimaryOnly                            bool
	DynamicEnabled                         bool
	DynamicMaxRounds, DynamicMaxNewDomains int
	WebConcurrency                         int
	Crawler                                func(context.Context, []string) error
}
type probeJob struct {
	target web.Target
	urls   []string
}
type probeCompletion struct {
	results []web.Result
	err     error
}
type dnsCompletion struct {
	value dns.ExpansionResult
	err   error
}
type bulkCoordinator struct {
	order               []string
	finished, eligible  map[string]bool
	handled             map[string]bool
	pending             []probeJob
	active, workerCount int
	jobs                chan probeJob
	indexed             chan core.Event
	completedWeb        chan probeCompletion
	dnsDone             <-chan dnsCompletion
	dnsJoined           bool
	expansion           dnsCompletion
	queueDomain         func(string) error
	acceptCompletion    func(probeCompletion) error
	includeWildcard     bool
}

func (b *bulkCoordinator) prepare(queueDomain func(string) error, jobs chan<- probeJob, dnsPending bool, indexedPending int) (bool, error) {
	for _, name := range b.order {
		if !b.finished[name] || b.handled[name] {
			continue
		}
		b.handled[name] = true
		if b.eligible[name] {
			if err := queueDomain(name); err != nil {
				return false, err
			}
		}
	}
	b.dispatch(jobs)
	return !dnsPending && b.active == 0 && len(b.pending) == 0 && indexedPending == 0, nil
}

func (b *bulkCoordinator) dispatch(jobs chan<- probeJob) {
	for b.active < b.workerCount && len(b.pending) > 0 {
		select {
		case jobs <- b.pending[0]:
			b.pending = b.pending[1:]
			b.active++
		default:
			return
		}
	}
}

func (b *bulkCoordinator) run(ctx context.Context) error {
	for {
		fixedPoint, err := b.prepare(b.queueDomain, b.jobs, b.dnsDone != nil, len(b.indexed))
		if err != nil {
			return err
		}
		if fixedPoint {
			return nil
		}
		select {
		case event := <-b.indexed:
			name, ok := event.NormalizedValue.(string)
			if !ok || !contains(b.order, name) {
				continue
			}
			b.finished[name] = true
			b.eligible[name] = isEligible(event.Metadata["active_eligibility"], b.includeWildcard)
		case expansion := <-b.dnsDone:
			b.dnsDone = nil
			b.dnsJoined = true
			b.expansion = expansion
			if expansion.err != nil {
				return expansion.err
			}
		case completion := <-b.completedWeb:
			if err := b.acceptCompletion(completion); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type Result struct {
	DNS            dns.ExpansionResult
	Targets        []web.Target
	Probes         []web.Result
	DynamicDomains []string
	Crawled        bool
	Partial        bool
}

// Run overlaps DNS validation and bounded web work after the passive barrier.
// DNS candidates are admitted in deterministic rank order; callback delivery is
// bounded and coordinator-owned, so producers cannot deadlock against web work.
func Run(ctx context.Context, c Config) (out Result, runErr error) {
	if ctx == nil {
		return out, fmt.Errorf("context required")
	}
	if c.PassiveBarrier == nil || c.Index == nil || c.HTTP == nil || c.Emit == nil {
		return out, fmt.Errorf("passive barrier, DNS index, HTTP client, and durable sink are required")
	}
	root, err := core.NormalizeDomain(c.Root)
	if err != nil {
		return out, err
	}
	if d := (core.ScopeChecker{Policy: c.Policy}).CheckDomain(root); d.Status != core.InScope {
		return out, fmt.Errorf("pipeline root is not authorized: %s", d.Status)
	}
	if c.DynamicEnabled && (c.DynamicMaxRounds < 0 || c.DynamicMaxNewDomains < 0) {
		return out, fmt.Errorf("invalid dynamic discovery budgets")
	}
	if c.PerHostRequests < 1 || c.WebConcurrency < 0 {
		return out, fmt.Errorf("invalid web request or concurrency budget")
	}
	if err = c.PassiveBarrier(ctx); err != nil {
		return out, fmt.Errorf("passive barrier: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	dnsConfig := c.DNS
	dnsConfig.Root = root
	dnsConfig.Policy = c.Policy
	dnsConfig.Index = c.Index
	var sinkMu sync.Mutex
	durableEmit := func(event core.Event) error {
		sinkMu.Lock()
		defer sinkMu.Unlock()
		return c.Emit(event)
	}
	// DNS, web and HTTP events share one durable sink before index/completion.
	dnsConfig.Emit = durableEmit
	if err = c.HTTP.SetEventSink(durableEmit); err != nil {
		return out, err
	}
	order, err := dns.RankedInventoryNames(dnsConfig.Inventory, root, dnsConfig.Budget, c.Policy)
	if err != nil {
		return out, err
	}
	analyzer := dnsConfig.Analyzer
	if analyzer == nil {
		analyzer, err = dns.NewWildcardAnalyzer(root, dnsConfig.Client, dnsConfig.WildcardProbes, dnsConfig.WildcardParentBudget, dnsConfig.WildcardEnabled, dns.PrioritizedParents(order, root, dnsConfig.WildcardParentBudget))
		if err != nil {
			return out, err
		}
	}
	dnsConfig.Analyzer = analyzer
	indexed := make(chan core.Event, max(1, dnsConfig.Workers*2))
	previousObserver := dnsConfig.OnValidationIndexed
	dnsConfig.OnValidationIndexed = func(ctx context.Context, event core.Event) error {
		if previousObserver != nil {
			if err := previousObserver(ctx, event); err != nil {
				return err
			}
		}
		select {
		case indexed <- event:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	child, cancel := context.WithCancel(ctx)
	workerCount := c.WebConcurrency
	if workerCount < 1 {
		workerCount = max(1, min(4, dnsConfig.Workers))
	}
	jobs := make(chan probeJob, workerCount)
	completedWeb := make(chan probeCompletion, workerCount)
	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-child.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					completion := probeCompletion{results: make([]web.Result, 0, len(job.urls))}
					for _, raw := range job.urls {
						result, e := web.Probe(child, c.HTTP, web.ProbeConfig{Policy: c.Policy, Emit: durableEmit, TLS: activehttp.SourceProbeUnverifiedTLS, MaxRedirects: 3}, job.target, raw)
						completion.results = append(completion.results, result)
						if e != nil {
							if errors.Is(e, activehttp.ErrCollection) {
								completion.err = e
								continue
							}
							completion.err = e
							break
						}
						if result.HTTP.StopStatus {
							break
						}
					}
					// Active counts include queued, running, and buffered completions,
					// so shutdown can drain at most workerCount committed completions.
					completedWeb <- completion
				}
			}
		}()
	}
	done := make(chan dnsCompletion, 1)
	dnsJoined := false
	completed := false
	defer func() {
		cancel()
		close(jobs)
		workers.Wait()
		if !dnsJoined {
			result := <-done
			out.DNS = result.value
			if runErr == nil && result.err != nil {
				runErr = result.err
			}
		}
	drain:
		for {
			select {
			case completion := <-completedWeb:
				out.Probes = append(out.Probes, completion.results...)
				for _, result := range completion.results {
					if result.Partial {
						out.Partial = true
					}
				}
				if completion.err != nil {
					out.Partial = true
					if runErr == nil {
						runErr = completion.err
					}
				}
			default:
				break drain
			}
		}
		if runErr != nil && !completed {
			out.Partial = true
		}
	}()
	go func() { value, err := dns.Expand(child, dnsConfig); done <- dnsCompletion{value, err} }()
	if c.DNS.SkipPrevalidated {
		out.Targets, err = web.EligibleTargets(c.Index, root, c.Policy, c.PrimaryOnly, dnsConfig.IncludeWildcardAmbiguous)
		if err != nil {
			return out, err
		}
	}
	probed := map[string]bool{}
	targetSeen := map[string]bool{}
	for _, target := range out.Targets {
		targetSeen[target.Domain] = true
	}
	addTarget := func(target web.Target) {
		if !targetSeen[target.Domain] {
			targetSeen[target.Domain] = true
			out.Targets = append(out.Targets, target)
		}
	}
	dynamicSeen := map[string]bool{}
	var crawlRoots []string
	bulk := bulkCoordinator{order: order, finished: map[string]bool{}, eligible: map[string]bool{}, handled: map[string]bool{}, workerCount: workerCount, jobs: jobs, indexed: indexed, completedWeb: completedWeb, dnsDone: done, includeWildcard: dnsConfig.IncludeWildcardAmbiguous}
	queueDomain := func(name string) error {
		targets, err := web.EligibleTargets(c.Index, root, c.Policy, c.PrimaryOnly, dnsConfig.IncludeWildcardAmbiguous)
		if err != nil {
			return err
		}
		for _, target := range targets {
			if target.Domain != name {
				continue
			}
			addTarget(target)
			urls := web.PlanURLs([]web.Target{target}, c.KnownWebURLs, c.Policy, c.PerHostRequests)
			var planned []string
			for _, raw := range urls {
				if probed[raw] {
					continue
				}
				probed[raw] = true
				planned = append(planned, raw)
			}
			if len(planned) > 0 {
				bulk.pending = append(bulk.pending, probeJob{target: target, urls: planned})
			}
		}
		return nil
	}
	bulk.queueDomain = queueDomain
	acceptCompletion := func(done probeCompletion) error {
		bulk.active--
		for _, result := range done.results {
			out.Probes = append(out.Probes, result)
			if result.Partial {
				out.Partial = true
			}
			if result.Status == "loaded" && result.HTTP.FinalURL != "" {
				crawlRoots = append(crawlRoots, result.HTTP.FinalURL)
			}
			for _, host := range result.DiscoveredDomains {
				dynamicSeen[host] = true
			}
		}
		if done.err != nil {
			if child.Err() != nil {
				return child.Err()
			}
			if errors.Is(done.err, activehttp.ErrEventSink) {
				return done.err
			}
			if !errors.Is(done.err, activehttp.ErrCollection) {
				return done.err
			}
			out.Partial = true
		}
		return nil
	}
	bulk.acceptCompletion = acceptCompletion
	if dnsConfig.SkipPrevalidated {
		for _, name := range order {
			if meta := c.Index.ExistingValidation(name); meta != nil {
				bulk.finished[name] = true
				bulk.eligible[name] = isEligible(meta["active_eligibility"], dnsConfig.IncludeWildcardAmbiguous)
			}
		}
	}
	err = bulk.run(ctx)
	dnsJoined = bulk.dnsJoined
	expansion := bulk.expansion
	out.DNS = expansion.value
	if err != nil {
		return out, err
	}
	targets, err := web.EligibleTargets(c.Index, root, c.Policy, c.PrimaryOnly, dnsConfig.IncludeWildcardAmbiguous)
	if err != nil {
		return out, err
	}
	for _, target := range targets {
		addTarget(target)
	}
	if expansion.err != nil {
		return out, expansion.err
	}
	if c.DynamicEnabled {
		admitted := 0
		for round := 0; round < c.DynamicMaxRounds && admitted < c.DynamicMaxNewDomains; round++ {
			candidates := sortedNew(dynamicSeen)
			if len(candidates) == 0 {
				break
			}
			queuedBefore := len(bulk.pending) + bulk.active
			for _, name := range candidates {
				if admitted >= c.DynamicMaxNewDomains {
					break
				}
				if c.Index.ExistingValidation(name) != nil {
					delete(dynamicSeen, name)
					continue
				}
				delete(dynamicSeen, name)
				admitted++
				dynamicDNS := dnsConfig
				dynamicDNS.OnValidationIndexed = nil
				validation, e := dns.ValidateQuick(child, dynamicDNS, analyzer, name)
				if e != nil {
					return out, e
				}
				if validation.Eligible {
					out.DynamicDomains = append(out.DynamicDomains, name)
					if e = queueDomain(name); e != nil {
						return out, e
					}
				}
			}
			for bulk.active > 0 || len(bulk.pending) > 0 {
				bulk.dispatch(jobs)
				select {
				case webResult := <-completedWeb:
					if err = acceptCompletion(webResult); err != nil {
						return out, err
					}
				case <-ctx.Done():
					return out, ctx.Err()
				}
			}
			if len(bulk.pending)+bulk.active == queuedBefore && len(dynamicSeen) == 0 {
				break
			}
		}
		if len(dynamicSeen) > 0 {
			out.Partial = true
			e, eErr := core.NewEvent(core.Limitation, "pipeline", "dynamic_discovery_budget", "dynamic discovery stopped with unprocessed domains", "dynamic_discovery_budget", core.InScope)
			if eErr != nil {
				return out, eErr
			}
			e.Metadata = map[string]any{"remaining_domains": len(dynamicSeen), "max_rounds": c.DynamicMaxRounds, "max_new_domains": c.DynamicMaxNewDomains}
			e.Confidence = 0
			if eErr = durableEmit(e); eErr != nil {
				return out, fmt.Errorf("%w: persist dynamic discovery limitation: %v", activehttp.ErrEventSink, eErr)
			}
		}
	}
	if c.Crawler != nil && len(crawlRoots) > 0 {
		sort.Strings(crawlRoots)
		if err = c.Crawler(child, crawlRoots); err != nil {
			out.Partial = true
			return out, err
		}
		out.Crawled = true
	}
	completed = true
	return out, nil
}
func sortedNew(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
func isEligible(v any, allowWildcard bool) bool {
	s, ok := v.(string)
	return ok && (s == "eligible" || allowWildcard && s == "eligible_override")
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
