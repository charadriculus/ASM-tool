package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asmtool/internal/active/web"
	"asmtool/internal/browser"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/execution"
	"asmtool/internal/platform"
)

type browserController interface {
	Capture(context.Context, browser.CaptureRequest) (browser.CaptureResult, error)
	Close(context.Context) error
}

func runBrowserStage(ctx context.Context, p Plan, bundle *platform.Bundle, index *evidence.DNSRunIndex, sink *durableSink, announce func(string) error, ops activeOps, out *activeOutcome) error {
	if p.browserMode == "disabled" {
		out.Coverage["browser"] = "not_requested"
		out.Coverage["browser_availability"] = "disabled_by_policy"
		out.Coverage["browser_pages_attempted"] = 0
		return nil
	}
	if !p.cfg.DirectTargetInteraction() || !p.cfg.AuthorizationConfirmed {
		return ErrAuthorizationRequired
	}
	targets, err := web.EligibleTargets(index, p.target, p.cfg.ScopePolicy, p.cfg.CollectionPolicy.WebPrimaryDomainOnly, p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive)
	if err != nil {
		return err
	}
	urls := web.PlanURLs(targets, configuredWebURLs(p), p.cfg.ScopePolicy, p.cfg.RateLimits.HTTPMaxRequestsPerHost)
	pageLimit := p.cfg.RateLimits.CrawlerMaxTotalPages
	if pageLimit < 1 || pageLimit > 150 {
		pageLimit = 150
	}
	plannedCount := len(urls)
	if len(urls) > pageLimit {
		urls = urls[:pageLimit]
		out.Incomplete = true
	}
	out.Coverage["browser_pages_planned"] = len(urls)
	out.Coverage["browser_pages_eligible"] = plannedCount
	out.Coverage["browser_pages_attempted"] = 0
	out.Coverage["browser_pages_loaded"] = 0
	out.Coverage["browser_pages_failed"] = 0
	if len(urls) == 0 {
		out.Coverage["browser"] = "no_eligible_targets"
		out.Coverage["browser_availability"] = "not_started"
		out.Coverage["screenshots_status"] = screenshotState(p, "no_eligible_targets")
		return nil
	}
	if err := emitLimitation(ctx, sink, "browser", "not_qualified", "info", "candidate31_preconnect_security_failure", 0, domainsOf(targets)); err != nil {
		return err
	}
	if plannedCount > len(urls) {
		if err := emitLimitation(ctx, sink, "browser", "partial", "warning", "browser_page_limit", plannedCount-len(urls), nil); err != nil {
			return err
		}
	}
	if ops.newBrowser == nil {
		out.Incomplete = true
		out.Coverage["browser"] = "unavailable"
		out.Coverage["browser_availability"] = "unavailable"
		out.Coverage["browser_pages_failed"] = len(urls)
		out.BackendProvenance = append(out.BackendProvenance, map[string]any{"category": "browser", "requested": p.browserMode, "actual": "none", "status": "unavailable", "available": false})
		if err := emitLimitation(ctx, sink, "browser", "partial", "warning", "browser_operation_unavailable", len(urls), domainsOf(targets)); err != nil {
			return err
		}
		return nil
	}
	if err := announce("browser_capture"); err != nil {
		return err
	}
	artifactRoot := filepath.Join(p.cfg.OutputDir, "artifacts")
	if err := ensureBrowserArtifactRoot(p.cfg.OutputDir, artifactRoot); err != nil {
		return err
	}
	commandTimeout := time.Duration(p.cfg.RateLimits.BrowserScreenshotTimeoutSeconds * float64(time.Second))
	if commandTimeout > 20*time.Second {
		commandTimeout = 20 * time.Second
	}
	opts := browser.Options{
		Scope: core.ScopeChecker{Policy: p.cfg.ScopePolicy}, Profile: p.cfg.Profile, Authorized: p.cfg.AuthorizationConfirmed,
		UserAgent:         p.cfg.UserAgent,
		CommandTimeout:    commandTimeout,
		NavigationTimeout: time.Duration(p.cfg.RateLimits.BrowserNavigationTimeoutSeconds * float64(time.Second)),
		PollInterval:      100 * time.Millisecond,
		SettleDelay:       time.Duration(p.cfg.RateLimits.BrowserDomSettleMilliseconds) * time.Millisecond,
		MaxResultBytes:    32 << 20, MaxHTMLBytes: 16 << 20, MaxScreenshotBytes: 16 << 20,
		MaxLinks: 1000, MaxPages: pageLimit, MaxEvaluations: 1000, ViewportWidth: 1440, ViewportHeight: 900,
	}
	controller, err := ops.newBrowser(ctx, bundle, opts)
	if err != nil {
		out.Incomplete = true
		out.Coverage["browser"] = "unavailable"
		out.Coverage["browser_availability"] = "unavailable"
		out.Coverage["browser_pages_failed"] = len(urls)
		out.BackendProvenance = append(out.BackendProvenance, map[string]any{"category": "browser", "requested": p.browserMode, "actual": "obscura_cdp", "status": "unavailable", "available": false})
		out.Coverage["screenshots_status"] = screenshotState(p, "unavailable")
		for _, raw := range urls {
			if e := emitTargetStage(ctx, sink, web.Target{Domain: hostFromURL(raw)}, "browser", "failed", screenshotState(p, "unavailable"), "browser_start_failed", true); e != nil {
				return e
			}
		}
		return emitLimitation(ctx, sink, "browser", "partial", "warning", "browser_start_failed", len(urls), domainsOf(targets))
	}
	if controller == nil {
		out.Incomplete = true
		out.Coverage["browser"] = "unavailable"
		out.Coverage["browser_availability"] = "unavailable"
		out.Coverage["browser_pages_failed"] = len(urls)
		out.BackendProvenance = append(out.BackendProvenance, map[string]any{"category": "browser", "requested": p.browserMode, "actual": "obscura_cdp", "status": "unavailable", "available": false})
		return emitLimitation(ctx, sink, "browser", "partial", "warning", "browser_constructor_returned_nil", len(urls), domainsOf(targets))
	}
	out.Coverage["browser_availability"] = "available"
	out.BackendProvenance = append(out.BackendProvenance, map[string]any{"category": "browser", "requested": p.browserMode, "actual": "obscura_cdp", "status": "available", "available": true, "security_status": "NOT_QUALIFIED", "known_network_risk": "candidate31_preconnect_security_failure"})
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := controller.Close(closeCtx); closeErr != nil {
			out.Incomplete = true
			out.Coverage["browser_cleanup"] = "failed"
			out.Coverage["browser"] = "partial"
			_ = emitLimitation(context.Background(), sink, "browser", "partial", "warning", "browser_cleanup_failed", 1, nil)
		} else {
			out.Coverage["browser_cleanup"] = "complete"
		}
	}()
	out.Coverage["browser"] = "complete"
	loaded, failed, screenshots := 0, 0, 0
	seen := map[string]bool{}
	var previous time.Time
	for _, raw := range urls {
		if err := ctx.Err(); err != nil {
			return err
		}
		host := hostFromURL(raw)
		if host == "" || seen[raw] {
			continue
		}
		// Re-evaluate current-run DNS eligibility immediately before each browser navigation.
		current, err := web.EligibleTargets(index, p.target, p.cfg.ScopePolicy, p.cfg.CollectionPolicy.WebPrimaryDomainOnly, p.cfg.CollectionPolicy.IncludeWildcardAmbiguousActive)
		if err != nil {
			return err
		}
		var selected *web.Target
		for i := range current {
			if strings.EqualFold(current[i].Domain, host) {
				selected = &current[i]
				break
			}
		}
		if selected == nil {
			failed++
			out.Incomplete = true
			if err := emitTargetStage(ctx, sink, web.Target{Domain: host}, "browser", "denied", "not_requested", "current_dns_eligibility_lost", true); err != nil {
				return err
			}
			continue
		}
		if interval := time.Duration(p.cfg.RateLimits.HTTPStartIntervalSeconds * float64(time.Second)); previous.IsZero() == false && interval > 0 {
			wait := interval - time.Since(previous)
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		seen[raw] = true
		attempted := intValue(out.Coverage["browser_pages_attempted"]) + 1
		out.Coverage["browser_pages_attempted"] = attempted
		markActiveAttempt(out)
		pageCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.RateLimits.BrowserTargetTotalTimeoutSeconds*float64(time.Second)))
		request := browser.CaptureRequest{URL: raw, Module: "browser_capture", Phase: p.cfg.Profile, Depth: 0, TargetDomains: []string{selected.Domain}, Sink: func(ev core.Event) error { return sink.emit(pageCtx, ev) }}
		name := browserArtifactName(raw)
		if p.cfg.Modules.Screenshots {
			request.ScreenshotRoot = artifactRoot
			request.ScreenshotRelativePath = filepath.Join("screenshots", name+".png")
		}
		capture, captureErr := controller.Capture(pageCtx, request)
		cancel()
		previous = time.Now()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if capture.NetworkContacted {
			out.Coverage["target_contacted"] = true
		}
		if captureErr != nil && len(capture.Events) > capture.PersistedEvents {
			return captureErr // Event persistence failed; retaining a success-shaped result is unsafe.
		}
		if captureErr == nil && !capture.DownloadDetected && capture.DOM == "" {
			captureErr = errors.New("browser returned no rendered DOM")
		}
		status, reason := "loaded", ""
		if captureErr != nil && capture.DownloadDetected {
			status, reason = "download_detected", "download_detected"
		} else if captureErr != nil {
			status, reason = "failed", "browser_capture_failed"
			failed++
			out.Incomplete = true
		}
		if captureErr == nil && capture.DownloadDetected {
			status, reason = "download_detected", "download_detected"
		}
		if status == "loaded" {
			loaded++
			out.Coverage["browser_dom"] = true
			if capture.DOM != "" {
				if _, err := writeBrowserDOM(ctx, artifactRoot, filepath.Join("dom", name+".html"), capture.DOM); err != nil {
					return err
				}
				if err := emitBrowserLinks(ctx, sink, capture, selected.Domain, core.ScopeChecker{Policy: p.cfg.ScopePolicy}); err != nil {
					return err
				}
			}
		}
		if p.cfg.Modules.Screenshots {
			if capture.Screenshot != nil {
				screenshots++
			} else {
				out.Incomplete = true
				if reason == "" {
					reason = "screenshot_unavailable"
				}
			}
		}
		shotStatus := "not_requested"
		if p.cfg.Modules.Screenshots {
			if capture.Screenshot != nil {
				shotStatus = "saved"
			} else {
				shotStatus = "failed"
			}
		}
		if err := emitTargetStageContact(ctx, sink, *selected, "browser", status, shotStatus, reason, true, capture.NetworkContacted); err != nil {
			return err
		}
		if status == "failed" || (p.cfg.Modules.Screenshots && capture.Screenshot == nil) {
			if err := emitLimitation(ctx, sink, "browser", "partial", "warning", reason, 1, []string{selected.Domain}); err != nil {
				return err
			}
		}
	}
	out.Coverage["browser_pages_loaded"] = loaded
	out.Coverage["browser_pages_failed"] = failed
	if failed > 0 || out.Incomplete {
		out.Coverage["browser"] = "partial"
	}
	if p.cfg.Modules.Screenshots {
		out.Coverage["screenshots_status"] = "complete"
		if screenshots < intValue(out.Coverage["browser_pages_attempted"]) || failed > 0 {
			out.Coverage["screenshots_status"] = "partial"
		}
	} else {
		out.Coverage["screenshots_status"] = "not_requested"
	}
	return nil
}

func ensureBrowserArtifactRoot(outputDir, artifactRoot string) error {
	if _, err := execution.SafeArtifactPath(outputDir, filepath.Join("artifacts", "root-check")); err != nil {
		return err
	}
	if err := os.Mkdir(artifactRoot, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(artifactRoot)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("browser artifacts root is not a regular directory")
	}
	if _, err := execution.SafeArtifactPath(outputDir, filepath.Join("artifacts", "root-check")); err != nil {
		return err
	}
	return nil
}

func screenshotState(p Plan, status string) string {
	if !p.cfg.Modules.Screenshots {
		return "not_requested"
	}
	if status == "loaded" {
		return "requested"
	}
	return status
}

// browserArtifactPath uses a stable URL-derived name and an exclusive create so
// reruns cannot silently replace earlier evidence.
func writeBrowserDOM(ctx context.Context, root, rel string, dom string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, err := execution.SafeArtifactPath(root, rel)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	path, err = execution.SafeArtifactPath(root, rel)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".browser-dom-")
	if err != nil {
		return "", err
	}
	staged := f.Name()
	defer os.Remove(staged)
	_, writeErr := f.WriteString(dom)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.Link(staged, path); err != nil {
		return "", err
	}
	return path, nil
}

func browserArtifactName(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func emitBrowserLinks(ctx context.Context, sink *durableSink, capture browser.CaptureResult, target string, scope core.ScopeChecker) error {
	for _, raw := range capture.Links {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := core.ParseHTTPURL(raw)
		if err != nil || !core.DomainMatches(strings.ToLower(u.Hostname()), target) || scope.CheckURL(raw).Status != core.InScope {
			continue
		}
		ev, err := core.NewEvent(core.URLFound, "browser_capture", "direct_cdp", raw, u.String(), core.InScope)
		if err != nil {
			return err
		}
		ev.Metadata = map[string]any{"source_url": capture.FinalURL, "target_domain": target, "rendered_dom": true}
		if err := sink.emit(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}
