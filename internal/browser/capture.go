package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"asmtool/internal/backends"
	"asmtool/internal/core"
)

// EventSink persists one event. Capture reports sink failures and counts only
// calls that returned nil as persisted.
type EventSink func(core.Event) error

// CaptureRequest describes one authorized visit. Empty screenshot fields
// disable screenshot creation; both must be present to enable it.
type CaptureRequest struct {
	URL                    string
	Module                 string
	Phase                  string
	Depth                  int
	TargetDomains          []string
	ScreenshotRoot         string
	ScreenshotRelativePath string
	Sink                   EventSink
}

// CaptureResult retains the response and data observed on one owned page.
// Events includes an event whose sink call failed; PersistedEvents excludes it.
// A published screenshot remains in Screenshot if its event sink later fails.
type CaptureResult struct {
	RequestedURL     string
	FinalURL         string
	DOM              string
	Title            string
	Links            []string
	Response         DocumentResponse
	Screenshot       *ScreenshotArtifact
	Events           []core.Event
	PersistedEvents  int
	DownloadDetected bool
	NetworkContacted bool
}

// Capture owns its page for the full operation. This keeps other callers from
// interleaving navigation, DOM reads or screenshots into the capture sequence.
func (b *Browser) Capture(ctx context.Context, req CaptureRequest) (result CaptureResult, retErr error) {
	result.RequestedURL = req.URL
	if b == nil {
		return result, errors.New("browser: nil receiver")
	}
	if ctx == nil {
		return result, errors.New("browser: nil capture context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := b.opts.validate(); err != nil {
		return result, fmt.Errorf("browser: invalid capture options: %w", err)
	}
	if req.Sink == nil || strings.TrimSpace(req.Module) == "" || strings.TrimSpace(req.Phase) == "" || req.Depth < 0 || len(req.TargetDomains) == 0 {
		return result, errors.New("browser: incomplete capture request or event sink")
	}
	if (req.ScreenshotRoot == "") != (req.ScreenshotRelativePath == "") {
		return result, errors.New("browser: screenshot root and relative path must be supplied together")
	}
	u, err := core.ParseHTTPURL(req.URL)
	if err != nil {
		return result, fmt.Errorf("browser: invalid capture URL: %w", err)
	}
	if u.User != nil {
		return result, errors.New("browser: URL credentials are not permitted")
	}
	if _, err := b.opts.Scope.RequireActiveAllowed(b.opts.Profile, b.opts.Authorized, req.URL, "url"); err != nil {
		return result, fmt.Errorf("browser: refusing capture: %w", err)
	}
	requested := u.String()
	result.RequestedURL = requested
	domains, err := checkedTargetDomains(req.TargetDomains, b.opts.Scope, u.Hostname())
	if err != nil {
		return result, err
	}
	emit := func(event core.Event) error {
		result.Events = append(result.Events, event)
		if err := req.Sink(event); err != nil {
			return fmt.Errorf("browser: persist %s event: %w", event.EventType, err)
		}
		result.PersistedEvents++
		return nil
	}
	emitDownload := func(rawURL, source, reason string, contacted bool, response *DocumentResponse) error {
		var status *int
		contentType, disposition := "", ""
		if response != nil {
			status = &response.Status
			contentType, disposition = response.ContentType, response.ContentDisposition
		}
		event, eventErr := NewDownloadEvent(DownloadEventInput{
			Module: req.Module, SourceTool: source, URL: rawURL, TargetDomains: domains,
			Phase: req.Phase, Depth: req.Depth, StatusCode: status,
			ContentType: contentType, ContentDisposition: disposition,
			NetworkContacted: contacted, DetectionReason: reason,
		})
		if eventErr != nil {
			return eventErr
		}
		result.DownloadDetected, result.NetworkContacted = true, contacted
		return emit(event)
	}

	// URL extension classification is performed after scope/authorization
	// validation and before page creation or navigation.
	if _, downloadable := DownloadableResourceInfo(requested, "", ""); downloadable {
		if err := emitDownload(requested, "direct_cdp", "url_extension", false, nil); err != nil {
			return result, err
		}
		return result, nil
	}

	page, err := b.NewPage(ctx)
	if err != nil {
		return result, err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), b.opts.CommandTimeout)
		defer cancel()
		retErr = errors.Join(retErr, page.Close(closeCtx))
	}()

	if err = page.Navigate(ctx, requested); err != nil {
		if !errors.Is(err, ErrDownloadableResource) {
			return result, err
		}
		result.NetworkContacted = true
		response, snapshotErr := pageResponseSnapshot(page)
		if snapshotErr == nil {
			result.Response, result.FinalURL = response, response.URL
			if _, scopeErr := validateCaptureURL(b.opts, requested, response.URL); scopeErr != nil {
				return result, errors.Join(err, fmt.Errorf("browser: response URL is not authorized: %w", scopeErr))
			}
			if _, downloadable := DownloadableResourceInfo(response.URL, response.ContentType, response.ContentDisposition); downloadable {
				if emitErr := emitDownload(response.URL, "response_headers", "response_headers", true, &response); emitErr != nil {
					return result, errors.Join(err, emitErr)
				}
			}
		}
		if !result.DownloadDetected {
			if emitErr := emitDownload(requested, "direct_cdp", "cdp_download_signal", true, nil); emitErr != nil {
				return result, errors.Join(err, emitErr)
			}
		}
		// A navigation error can contain a target cleanup failure. Keep it
		// visible even when the download event was successfully persisted.
		return result, err
	}
	result.NetworkContacted = true
	response, err := pageResponseSnapshot(page)
	if err != nil {
		return result, fmt.Errorf("browser: capture response metadata: %w", err)
	}
	result.Response = response
	if !response.Complete {
		return result, errors.New("browser: main document response is incomplete")
	}
	if _, err := validateCaptureURL(b.opts, requested, response.URL); err != nil {
		return result, fmt.Errorf("browser: response URL is not authorized: %w", err)
	}
	if _, downloadable := DownloadableResourceInfo(response.URL, response.ContentType, response.ContentDisposition); downloadable {
		result.FinalURL = response.URL
		if err := emitDownload(response.URL, "response_headers", "response_headers", true, &response); err != nil {
			return result, err
		}
		return result, nil
	}

	snapshot, err := page.Snapshot(ctx)
	if err != nil {
		return result, fmt.Errorf("browser: capture DOM: %w", err)
	}
	result.DOM = snapshot.HTML
	if _, err := validateCaptureURL(b.opts, requested, snapshot.URL); err != nil {
		return result, fmt.Errorf("browser: captured DOM URL is not authorized: %w", err)
	}
	result.FinalURL = snapshot.URL
	features, err := backends.ParseHTML(result.DOM)
	if err != nil {
		return result, fmt.Errorf("browser: parse captured DOM: %w", err)
	}
	result.Title, err = page.Title(ctx)
	if err != nil {
		return result, fmt.Errorf("browser: capture title: %w", err)
	}
	result.Links, err = page.Links(ctx)
	if err != nil {
		return result, fmt.Errorf("browser: capture links: %w", err)
	}
	result.FinalURL, err = validateLivePage(ctx, page, b.opts, requested, snapshot.URL)
	if err != nil {
		return result, err
	}

	screenshotExpected := req.ScreenshotRoot != ""
	if screenshotExpected {
		pngData, shotErr := page.Screenshot(ctx)
		if shotErr == nil {
			if _, err = validateLivePage(ctx, page, b.opts, requested, snapshot.URL); err != nil {
				return result, err
			}
			var artifact ScreenshotArtifact
			artifact, shotErr = SaveScreenshot(ctx, req.ScreenshotRoot, req.ScreenshotRelativePath, pngData, b.opts.MaxScreenshotBytes)
			if shotErr == nil {
				result.Screenshot = &artifact
				if _, err = validateLivePage(ctx, page, b.opts, requested, snapshot.URL); err != nil {
					return result, err
				}
				shotEvent, eventErr := screenshotEvent(req, domains, result.FinalURL, result.Title, response, artifact)
				if eventErr != nil {
					return result, eventErr
				}
				if err := emit(shotEvent); err != nil {
					return result, err
				}
			}
		}
		if shotErr != nil {
			if ctx.Err() != nil || errors.Is(shotErr, context.Canceled) || errors.Is(shotErr, context.DeadlineExceeded) {
				return result, shotErr
			}
			// Optional image failure is reportable only while the owned page is
			// still ready and authorized; a closed or changed page is fatal.
			result.FinalURL, err = validateLivePage(ctx, page, b.opts, requested, snapshot.URL)
			if err != nil {
				return result, errors.Join(shotErr, err)
			}
			limitation, eventErr := captureLimitation(req, domains, result.FinalURL, shotErr)
			if eventErr != nil {
				return result, eventErr
			}
			if err := emit(limitation); err != nil {
				return result, err
			}
		}
	}

	result.FinalURL, err = validateLivePage(ctx, page, b.opts, requested, snapshot.URL)
	if err != nil {
		return result, err
	}
	htmlEvent, err := htmlAnalyzedEvent(req, domains, requested, result.FinalURL, result.Title, features, response, len(result.Links), result.Screenshot != nil, screenshotExpected)
	if err != nil {
		return result, err
	}
	if err := emit(htmlEvent); err != nil {
		return result, err
	}
	return result, nil
}

func pageResponseSnapshot(p *Page) (DocumentResponse, error) {
	return p.Response()
}

func validateCaptureURL(opts Options, requested, candidate string) (*url.URL, error) {
	parsed, err := core.ParseHTTPURL(candidate)
	if err != nil {
		return nil, err
	}
	if parsed.User != nil {
		return nil, errors.New("URL credentials are not permitted")
	}
	if _, err := opts.Scope.RequireActiveAllowed(opts.Profile, opts.Authorized, candidate, "url"); err != nil {
		return nil, err
	}
	base, err := url.Parse(requested)
	if err != nil || !sameOrigin(base, parsed) {
		return nil, errors.New("capture URL changed origin; browser request may already have reached the network")
	}
	return parsed, nil
}

func validateLivePage(ctx context.Context, page *Page, opts Options, requested, expectedURL string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	current, err := page.URL(ctx)
	if err != nil {
		return "", fmt.Errorf("browser: verify current page URL: %w", err)
	}
	if _, err := validateCaptureURL(opts, requested, current); err != nil {
		return "", fmt.Errorf("browser: current page is no longer authorized: %w", err)
	}
	if expectedURL != "" && current != expectedURL {
		return "", errors.New("browser: page URL changed during capture; captured DOM may be stale")
	}
	return current, nil
}

func htmlAnalyzedEvent(req CaptureRequest, domains []string, requested, finalURL, title string, features backends.HTMLFeatures, response DocumentResponse, linkCount int, screenshotSaved, screenshotExpected bool) (core.Event, error) {
	event, err := core.NewEvent(core.HTMLAnalyzed, req.Module, "direct_cdp", requested, finalURL, core.InScope)
	if err != nil {
		return core.Event{}, err
	}
	event.Confidence = 0.9
	event.Metadata = map[string]any{
		"title": title, "anchor_count": len(features.AnchorHrefs), "links_count": linkCount,
		"status_code": response.Status, "content_type": response.ContentType, "depth": req.Depth,
		"origin": origin(finalURL), "target_domain": firstDomain(domains), "target_domains": domains,
		"requested_url": requested, "final_url": finalURL, "phase": req.Phase,
		"screenshot_saved": screenshotSaved, "screenshot_expected": screenshotExpected,
		"page_loaded": true, "network_contacted": true,
		"observation_type": "active_low_noise_validation", "browser_dom": true,
		"partial": !response.Complete, "browser_backend": "obscura", "browser_backend_version": "0.2.2",
		"control_client": "go-rod", "control_client_version": "0.116.2", "transport": "cdp", "stealth": false,
		// Candidate31 observed connection establishment before Fetch.requestPaused.
		"out_of_scope_subresources_blocked": false,
		"scope_limitation":                  "candidate31: CDP Fetch does not guarantee authorization before a subresource network connection",
	}
	return event, nil
}

func screenshotEvent(req CaptureRequest, domains []string, finalURL, title string, response DocumentResponse, artifact ScreenshotArtifact) (core.Event, error) {
	abs, err := filepath.Abs(artifact.Path)
	if err != nil {
		return core.Event{}, err
	}
	event, err := core.NewEvent(core.ScreenshotSaved, "browser_capture", "direct_cdp", finalURL, finalURL, core.InScope)
	if err != nil {
		return core.Event{}, err
	}
	event.Confidence = 0.9
	event.Metadata = map[string]any{
		"url": finalURL, "path": artifact.Path, "absolute_path": abs, "sha256": artifact.SHA256,
		"status_code": response.Status, "title": title, "target_domain": firstDomain(domains),
		"target_domains": domains, "origin": origin(finalURL), "phase": req.Phase, "depth": req.Depth,
		"captured_from_current_page": true, "additional_navigation": false,
		"observation_type": "active_low_noise_validation", "browser_backend": "obscura",
		"browser_backend_version": "0.2.2", "control_client": "go-rod", "control_client_version": "0.116.2",
		"transport": "cdp", "stealth": false,
	}
	return event, nil
}

func captureLimitation(req CaptureRequest, domains []string, pageURL string, cause error) (core.Event, error) {
	event, err := core.NewEvent(core.Limitation, req.Module, "direct_cdp", cause.Error(), pageURL, core.InScope)
	if err != nil {
		return core.Event{}, err
	}
	event.Confidence = 0
	event.Metadata = map[string]any{
		"origin": origin(pageURL), "target_domain": firstDomain(domains), "target_domains": domains,
		"page_loaded": true, "screenshot_expected": true, "severity": "warning",
	}
	return event, nil
}

func checkedTargetDomains(values []string, scope core.ScopeChecker, host string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("browser: at least one target domain is required")
	}
	matchedHost := false
	for _, value := range values {
		if strings.TrimSpace(value) == "" || scope.CheckTarget(value).Status != core.InScope {
			return nil, fmt.Errorf("browser: target domain metadata is outside authorized scope: %q", value)
		}
		if core.DomainMatches(host, value) || strings.EqualFold(host, value) {
			matchedHost = true
		}
	}
	if !matchedHost {
		return nil, errors.New("browser: target domains do not identify the requested host")
	}
	return sortedUnique(values), nil
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) < 2 {
		return result
	}
	out := result[:1]
	for _, value := range result[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func firstDomain(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}
