package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"math"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/core"
)

// commandClient is intentionally the only transport surface used by this
// controller. The runtime owns its CDP connection and process lifecycle.
type commandClient interface {
	Call(context.Context, string, string, any) ([]byte, error)
}

// Browser controls Obscura through direct CDP commands. It does not claim that
// CDP Fetch prevents a request from reaching the network; candidate31 showed
// that it does not. Callers must retain the existing authorization gate and
// must not use this adapter for arbitrary targets.
type Browser struct {
	client commandClient
	opts   Options

	mu         sync.Mutex
	closed     bool
	closeErr   error
	cleanupErr error
	closeDone  chan struct{}
	pageUsed   int
	evalUsed   int
	pages      map[string]*Page
	creating   sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	process    *ownedProcess
}

// Page is one flattened CDP target. Its methods serialize operations so page
// state and the configured evaluation budget cannot race.
type Page struct {
	browser   *Browser
	target    string
	session   string
	mu        sync.Mutex
	closed    bool
	closeErr  error
	current   string
	requested string
	document  *documentResponseCollector
}

func newBrowser(client commandClient, opts Options) *Browser {
	opts.Scope.Policy.AllowedDomains = append([]string(nil), opts.Scope.Policy.AllowedDomains...)
	opts.Scope.Policy.AllowedCIDRs = append([]string(nil), opts.Scope.Policy.AllowedCIDRs...)
	opts.Scope.Policy.ExcludedDomains = append([]string(nil), opts.Scope.Policy.ExcludedDomains...)
	opts.Scope.Policy.ExcludedCIDRs = append([]string(nil), opts.Scope.Policy.ExcludedCIDRs...)
	ctx, cancel := context.WithCancel(context.Background())
	return &Browser{client: client, opts: opts, pages: make(map[string]*Page), ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}
}

func (b *Browser) NewPage(ctx context.Context) (*Page, error) {
	if b == nil {
		return nil, errors.New("browser: nil receiver")
	}
	if ctx == nil {
		return nil, errors.New("browser: nil context")
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("browser: closed")
	}
	if b.cleanupErr != nil {
		err := b.cleanupErr
		b.mu.Unlock()
		return nil, fmt.Errorf("browser: refusing new targets after uncertain cleanup: %w", err)
	}
	if b.pages == nil {
		b.pages = make(map[string]*Page)
	}
	if b.client == nil {
		b.mu.Unlock()
		return nil, errors.New("browser: CDP client unavailable")
	}
	if err := b.opts.validate(); err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("browser: invalid controller options: %w", err)
	}
	if b.pageUsed >= b.opts.MaxPages {
		b.mu.Unlock()
		return nil, errors.New("browser: page limit reached")
	}
	b.pageUsed++
	b.creating.Add(1)
	b.mu.Unlock()
	defer b.creating.Done()
	ctx, stop := b.operationContext(ctx)
	defer stop()

	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := b.call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &created); err != nil {
		failure := fmt.Errorf("browser: create target outcome is unknown: %w", err)
		b.recordCleanupError(failure)
		return nil, failure
	}
	if created.TargetID == "" {
		failure := errors.New("browser: CDP returned an empty target id; creation outcome unknown")
		b.recordCleanupError(failure)
		return nil, failure
	}
	closeTarget := func() error {
		closeCtx, cancel := context.WithTimeout(context.Background(), b.opts.CommandTimeout)
		defer cancel()
		var response struct {
			Success bool `json:"success"`
		}
		if err := b.call(closeCtx, "", "Target.closeTarget", map[string]any{"targetId": created.TargetID}, &response); err != nil {
			failure := fmt.Errorf("browser: cleanup target: %w", err)
			b.recordCleanupError(failure)
			return failure
		}
		if !response.Success {
			failure := errors.New("browser: cleanup target was not confirmed")
			b.recordCleanupError(failure)
			return failure
		}
		return nil
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := b.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil {
		return nil, errors.Join(fmt.Errorf("browser: attach target: %w", err), closeTarget())
	}
	if attached.SessionID == "" {
		return nil, errors.Join(errors.New("browser: CDP returned an empty session id"), closeTarget())
	}
	p := &Page{browser: b, target: created.TargetID, session: attached.SessionID}
	for _, command := range []struct {
		method string
		params any
	}{
		{"Page.enable", map[string]any{}},
		{"Runtime.enable", map[string]any{}},
		{"Network.enable", map[string]any{}},
		{"Emulation.setDeviceMetricsOverride", map[string]any{
			"width": b.opts.ViewportWidth, "height": b.opts.ViewportHeight,
			"deviceScaleFactor": 1, "mobile": false,
		}},
	} {
		if err := b.call(ctx, p.session, command.method, command.params, nil); err != nil {
			return nil, errors.Join(fmt.Errorf("browser: %s: %w", command.method, err), closeTarget())
		}
	}
	if b.opts.UserAgent != "" {
		if err := b.call(ctx, p.session, "Network.setUserAgentOverride", map[string]any{"userAgent": b.opts.UserAgent}, nil); err != nil {
			return nil, errors.Join(fmt.Errorf("browser: set user agent: %w", err), closeTarget())
		}
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.Join(errors.New("browser: closed during page creation"), closeTarget())
	}
	b.pages[p.target] = p
	b.mu.Unlock()
	return p, nil
}

// Close closes each owned target. Obscura's Browser.close behavior is not
// relied upon; the process supervisor remains responsible for the browser.
func (b *Browser) Close(ctx context.Context) error {
	if b == nil {
		return errors.New("browser: nil receiver")
	}
	if ctx == nil {
		return errors.New("browser: nil context")
	}
	b.mu.Lock()
	if b.closed {
		done := b.closeDone
		closeErr := b.closeErr
		b.mu.Unlock()
		if done == nil {
			return closeErr
		}
		select {
		case <-done:
			b.mu.Lock()
			closeErr = b.closeErr
			b.mu.Unlock()
			return closeErr
		case <-ctx.Done():
			select {
			case <-done:
				b.mu.Lock()
				closeErr = b.closeErr
				b.mu.Unlock()
				return closeErr
			default:
			}
			return errors.Join(ctx.Err(), closeErr)
		}
	}
	if b.closeDone == nil {
		b.closeDone = make(chan struct{})
	}
	b.closed = true
	if b.cancel != nil {
		b.cancel()
	}
	b.mu.Unlock()
	creatingDone := make(chan struct{})
	go func() {
		b.creating.Wait()
		close(creatingDone)
	}()
	select {
	case <-creatingDone:
	case <-ctx.Done():
		var closeErr error
		if closer, ok := b.client.(interface{ Close() error }); ok {
			closeErr = closer.Close()
		}
		if b.process != nil {
			closeErr = errors.Join(closeErr, b.process.Close(ctx))
		}
		result := errors.Join(ctx.Err(), closeErr)
		b.mu.Lock()
		result = errors.Join(result, b.cleanupErr)
		b.mu.Unlock()
		b.finishClose(result)
		return result
	}
	closeCtx, cancelClose := withTimeout(ctx, b.opts.CommandTimeout)
	defer cancelClose()
	b.mu.Lock()
	pages := make([]*Page, 0, len(b.pages))
	for _, p := range b.pages {
		pages = append(pages, p)
	}
	b.mu.Unlock()
	sort.Slice(pages, func(i, j int) bool { return pages[i].target < pages[j].target })
	var result error
	for _, p := range pages {
		if err := closeCtx.Err(); err != nil {
			result = errors.Join(result, err)
			break
		}
		if err := p.Close(closeCtx); err != nil {
			result = errors.Join(result, err)
			if closeCtx.Err() != nil {
				break
			}
		}
	}
	b.mu.Lock()
	result = errors.Join(result, b.cleanupErr)
	b.mu.Unlock()
	if closer, ok := b.client.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("browser: close CDP transport: %w", err))
		}
	}
	if b.process != nil {
		if err := b.process.Close(closeCtx); err != nil {
			result = errors.Join(result, fmt.Errorf("browser: stop Obscura process: %w", err))
		}
	}
	b.finishClose(result)
	return result
}

func (b *Browser) finishClose(err error) {
	b.mu.Lock()
	b.closeErr = err
	if b.closeDone != nil {
		close(b.closeDone)
		b.closeDone = nil
	}
	b.mu.Unlock()
}

func (b *Browser) recordCleanupError(err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	b.cleanupErr = errors.Join(b.cleanupErr, err)
	b.mu.Unlock()
}

func (p *Page) Navigate(ctx context.Context, rawURL string) error {
	if p == nil || p.browser == nil {
		return errors.New("browser: nil page")
	}
	if ctx == nil {
		return errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return err
	}
	if !p.browser.opts.Authorized || (p.browser.opts.Profile != "verify" && p.browser.opts.Profile != "full") {
		return errors.New("browser: navigation requires explicit verify/full authorization")
	}
	if _, err := p.browser.opts.Scope.RequireActiveAllowed(p.browser.opts.Profile, p.browser.opts.Authorized, rawURL, "url"); err != nil {
		return fmt.Errorf("browser: refusing navigation: %w", err)
	}
	u, err := core.ParseHTTPURL(rawURL)
	if err != nil {
		return fmt.Errorf("browser: invalid navigation URL: %w", err)
	}
	if u.User != nil {
		return errors.New("browser: URL credentials are not permitted")
	}
	if _, downloadable := DownloadableResourceInfo(rawURL, "", ""); downloadable {
		return fmt.Errorf("browser: %w: %s", ErrDownloadableResource, rawURL)
	}
	p.current = ""
	p.requested = u.String()
	p.document = nil
	if source, ok := p.browser.client.(interface {
		observeDocument(string) (*documentResponseCollector, func(), error)
	}); ok {
		collector, release, err := source.observeDocument(p.session)
		if err != nil {
			return err
		}
		p.document = collector
		defer release()
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	ctx, cancel := withTimeout(ctx, p.browser.opts.NavigationTimeout)
	defer cancel()
	var nav struct {
		ErrorText  string `json:"errorText"`
		IsDownload bool   `json:"isDownload"`
		FrameID    string `json:"frameId"`
		LoaderID   string `json:"loaderId"`
	}
	if err := p.browser.call(ctx, p.session, "Page.navigate", map[string]any{"url": u.String()}, &nav); err != nil {
		return errors.Join(fmt.Errorf("browser: navigate: %w", err), p.closeTargetLocked())
	}
	if nav.IsDownload {
		return errors.Join(fmt.Errorf("browser: %w: %s", ErrDownloadableResource, u.String()), p.closeTargetLocked())
	}
	if nav.ErrorText != "" {
		return errors.Join(fmt.Errorf("browser: navigation failed: %s", boundedText(nav.ErrorText, 512)), p.closeTargetLocked())
	}
	if p.document != nil {
		if err := p.document.ConfigureNavigation(p.session, nav.FrameID, nav.LoaderID); err != nil {
			return errors.Join(err, p.closeTargetLocked())
		}
	}
	deadline, _ := ctx.Deadline()
	for {
		if p.document != nil {
			if response, err := p.document.Snapshot(); err == nil {
				observed, parseErr := core.ParseHTTPURL(response.URL)
				_, scopeErr := p.browser.opts.Scope.RequireActiveAllowed(p.browser.opts.Profile, true, response.URL, "url")
				if parseErr != nil || scopeErr != nil || observed.User != nil || !sameOrigin(u, observed) {
					return errors.Join(errors.New("browser: document response outside authorized origin (contact may already have occurred)"), p.closeTargetLocked())
				}
				if _, download := DownloadableResourceInfo(response.URL, response.ContentType, response.ContentDisposition); download {
					return errors.Join(ErrDownloadableResource, p.closeTargetLocked())
				}
			}
		}
		state, evalErr := p.evaluateLocked(ctx, `({state: document.readyState, url: location.href})`)
		if evalErr == nil {
			var ready struct {
				State string `json:"state"`
				URL   string `json:"url"`
			}
			responseReady := true
			if p.document != nil {
				_, err := p.document.Result()
				responseReady = err == nil
			}
			if json.Unmarshal(state, &ready) == nil && (ready.State == "interactive" || ready.State == "complete") && responseReady {
				if p.browser.opts.SettleDelay > 0 {
					timer := time.NewTimer(p.browser.opts.SettleDelay)
					select {
					case <-ctx.Done():
						timer.Stop()
						return errors.Join(ctx.Err(), p.closeTargetLocked())
					case <-timer.C:
					}
					settled, settleErr := p.evaluateLocked(ctx, `({state: document.readyState, url: location.href})`)
					if settleErr != nil {
						return errors.Join(fmt.Errorf("browser: verify settled page: %w", settleErr), p.closeTargetLocked())
					}
					if err := json.Unmarshal(settled, &ready); err != nil || (ready.State != "interactive" && ready.State != "complete") {
						return errors.Join(errors.New("browser: page left DOM-ready state during settle delay"), p.closeTargetLocked())
					}
				}
				if _, scopeErr := p.browser.opts.Scope.RequireActiveAllowed(p.browser.opts.Profile, true, ready.URL, "url"); scopeErr != nil {
					return errors.Join(fmt.Errorf("browser: final URL outside authorized scope (request may already have reached the network): %w", scopeErr), p.closeTargetLocked())
				}
				final, parseErr := url.Parse(ready.URL)
				if parseErr != nil || !sameOrigin(u, final) {
					return errors.Join(errors.New("browser: redirect changed origin; refusing to continue (request may already have reached the network)"), p.closeTargetLocked())
				}
				if p.document != nil {
					response, responseErr := p.document.Result()
					observed, observedErr := core.ParseHTTPURL(response.URL)
					if responseErr != nil || observedErr != nil || observed.User != nil || !sameOrigin(u, observed) {
						return errors.Join(errors.New("browser: settled document response incomplete or changed origin"), responseErr, p.closeTargetLocked())
					}
					if _, downloadable := DownloadableResourceInfo(response.URL, response.ContentType, response.ContentDisposition); downloadable {
						return errors.Join(ErrDownloadableResource, p.closeTargetLocked())
					}
				}
				p.current = ready.URL
				return nil
			}
			if ctx.Err() != nil {
				return errors.Join(ctx.Err(), p.closeTargetLocked())
			}
		}
		if time.Now().After(deadline) {
			if p.document != nil {
				if _, metadataErr := p.document.Result(); metadataErr != nil {
					return errors.Join(context.DeadlineExceeded, metadataErr, p.closeTargetLocked())
				}
			}
			if evalErr != nil {
				return errors.Join(fmt.Errorf("browser: wait for DOMContentLoaded: %w", evalErr), p.closeTargetLocked())
			}
			return errors.Join(context.DeadlineExceeded, p.closeTargetLocked())
		}
		timer := time.NewTimer(p.browser.opts.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), p.closeTargetLocked())
		case <-timer.C:
		}
	}
}

func (p *Page) Evaluate(ctx context.Context, expression string) (json.RawMessage, error) {
	if p == nil || p.browser == nil {
		return nil, errors.New("browser: nil page")
	}
	if ctx == nil {
		return nil, errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return nil, err
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	if strings.TrimSpace(expression) == "" || len(expression) > p.browser.opts.MaxResultBytes {
		return nil, errors.New("browser: empty or oversized JavaScript expression")
	}
	if _, err := p.currentURLLocked(ctx); err != nil {
		return nil, err
	}
	return p.evaluateLocked(ctx, expression)
}

func (p *Page) evaluateLocked(ctx context.Context, expression string) (json.RawMessage, error) {
	p.browser.mu.Lock()
	if p.browser.closed {
		p.browser.mu.Unlock()
		return nil, errors.New("browser: browser is closed")
	}
	if p.browser.evalUsed >= p.browser.opts.MaxEvaluations {
		p.browser.mu.Unlock()
		return nil, errors.New("browser: evaluation limit reached")
	}
	p.browser.evalUsed++
	p.browser.mu.Unlock()
	ctx, cancel := withTimeout(ctx, p.browser.opts.CommandTimeout)
	defer cancel()
	var result struct {
		Result struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
			Error string          `json:"description"`
		} `json:"result"`
		Exception *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := p.browser.call(ctx, p.session, "Runtime.evaluate", map[string]any{
		"expression": expression, "awaitPromise": true, "returnByValue": true,
		"userGesture": false, "includeCommandLineAPI": false,
	}, &result); err != nil {
		if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, errors.Join(ctx.Err(), err, p.closeTargetLocked())
		}
		return nil, fmt.Errorf("browser: evaluate: %w", err)
	}
	if result.Exception != nil {
		message := result.Exception.Text
		if result.Exception.Exception.Description != "" {
			message = result.Exception.Exception.Description
		}
		return nil, fmt.Errorf("browser: JavaScript exception: %s", boundedText(message, 512))
	}
	if result.Result.Value == nil || string(result.Result.Value) == "null" && result.Result.Type == "undefined" {
		return nil, errors.New("browser: JavaScript returned no value")
	}
	if len(result.Result.Value) > p.browser.opts.MaxResultBytes {
		return nil, errors.New("browser: JavaScript result exceeds configured limit")
	}
	return append(json.RawMessage(nil), result.Result.Value...), nil
}

func (p *Page) DOM(ctx context.Context) (string, error) {
	snapshot, err := p.Snapshot(ctx)
	return snapshot.HTML, err
}

// PageSnapshot binds the DOM and its location in one synchronous evaluation.
type PageSnapshot struct{ URL, HTML string }

func (p *Page) Snapshot(ctx context.Context) (PageSnapshot, error) {
	if p == nil || p.browser == nil {
		return PageSnapshot{}, errors.New("browser: nil page")
	}
	if p.browser.opts.MaxHTMLBytes <= 0 {
		return PageSnapshot{}, errors.New("browser: HTML limit is invalid")
	}
	if ctx == nil {
		return PageSnapshot{}, errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return PageSnapshot{}, err
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	location, html, err := p.snapshotLocked(ctx)
	return PageSnapshot{location, html}, err
}

func (p *Page) snapshotLocked(ctx context.Context) (string, string, error) {
	expression := fmt.Sprintf(`(()=>{const u=location.href;const e=document.documentElement;const h=e?e.outerHTML:"";const v={url:u,html:h};const enc=new TextEncoder();return enc.encode(h).length>%d||enc.encode(JSON.stringify(v)).length>%d?null:v})()`, p.browser.opts.MaxHTMLBytes, p.browser.opts.MaxResultBytes-4096)
	value, err := p.evaluateLocked(ctx, expression)
	if err != nil {
		return "", "", err
	}
	var snapshot struct {
		URL  string `json:"url"`
		HTML string `json:"html"`
	}
	if err := json.Unmarshal(value, &snapshot); err != nil || snapshot.HTML == "" {
		return "", "", errors.New("browser: page snapshot is missing or exceeds configured limits")
	}
	if len(snapshot.HTML) > p.browser.opts.MaxHTMLBytes {
		return "", "", errors.New("browser: DOM exceeds configured byte limit")
	}
	if err := p.acceptCurrentURLLocked(snapshot.URL); err != nil {
		return "", "", err
	}
	return snapshot.URL, snapshot.HTML, nil
}

func (p *Page) Links(ctx context.Context) ([]string, error) {
	if p == nil || p.browser == nil {
		return nil, errors.New("browser: nil page")
	}
	if ctx == nil {
		return nil, errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return nil, err
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	pageURL, dom, err := p.snapshotLocked(ctx)
	if err != nil {
		return nil, err
	}
	features, err := backends.ParseHTML(dom)
	if err != nil {
		return nil, fmt.Errorf("browser: parse DOM: %w", err)
	}
	base, err := url.Parse(pageURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("browser: current page URL is unavailable")
	}
	seen := make(map[string]struct{}, min(len(features.AnchorHrefs), p.browser.opts.MaxLinks))
	links := make([]string, 0, min(len(features.AnchorHrefs), p.browser.opts.MaxLinks))
	for _, href := range features.AnchorHrefs {
		ref, parseErr := url.Parse(strings.TrimSpace(href))
		if parseErr != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		resolved.Fragment = ""
		value := resolved.String()
		if _, parseErr = core.ParseHTTPURL(value); parseErr != nil || p.browser.opts.Scope.CheckURL(value).Status != core.InScope || !sameOrigin(base, resolved) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		if len(links) >= p.browser.opts.MaxLinks {
			return links, errors.New("browser: link limit reached; result is incomplete")
		}
		seen[value] = struct{}{}
		links = append(links, value)
	}
	return links, nil
}

func (p *Page) Title(ctx context.Context) (string, error) {
	if p == nil || p.browser == nil {
		return "", errors.New("browser: nil page")
	}
	if ctx == nil {
		return "", errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return "", err
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	value, err := p.evaluateLocked(ctx, `({url:location.href,title:document.title})`)
	if err != nil {
		return "", err
	}
	var snapshot struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	}
	if err := json.Unmarshal(value, &snapshot); err != nil {
		return "", errors.New("browser: title is missing or not text")
	}
	if err := p.acceptCurrentURLLocked(snapshot.URL); err != nil {
		return "", err
	}
	return snapshot.Title, nil
}

func (p *Page) URL(ctx context.Context) (string, error) {
	if p == nil || p.browser == nil {
		return "", errors.New("browser: nil page")
	}
	if ctx == nil {
		return "", errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return "", err
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	return p.currentURLLocked(ctx)
}

func (p *Page) currentURLLocked(ctx context.Context) (string, error) {
	value, err := p.evaluateLocked(ctx, `location.href`)
	if err != nil {
		return "", err
	}
	var current string
	if err := json.Unmarshal(value, &current); err != nil || current == "" {
		return "", errors.Join(errors.New("browser: current URL is missing"), p.closeTargetLocked())
	}
	if err := p.acceptCurrentURLLocked(current); err != nil {
		return "", err
	}
	return current, nil
}

func (p *Page) acceptCurrentURLLocked(current string) error {
	parsed, err := core.ParseHTTPURL(current)
	if err != nil {
		return errors.Join(fmt.Errorf("browser: current page URL is invalid: %w", err), p.closeTargetLocked())
	}
	if _, err := p.browser.opts.Scope.RequireActiveAllowed(p.browser.opts.Profile, p.browser.opts.Authorized, current, "url"); err != nil {
		return errors.Join(fmt.Errorf("browser: current page URL outside authorized scope (request may already have reached the network): %w", err), p.closeTargetLocked())
	}
	previous := p.current
	if previous == "" {
		return errors.Join(errors.New("browser: page has no successfully authorized navigation"), p.closeTargetLocked())
	}
	original, parseErr := url.Parse(previous)
	if parseErr != nil || !sameOrigin(original, parsed) {
		return errors.Join(errors.New("browser: page changed origin; refusing to continue (navigation may already have reached the network)"), p.closeTargetLocked())
	}
	p.current = current
	return nil
}

func (p *Page) Screenshot(ctx context.Context) ([]byte, error) {
	if p == nil || p.browser == nil {
		return nil, errors.New("browser: nil page")
	}
	if ctx == nil {
		return nil, errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ready(); err != nil {
		return nil, err
	}
	ctx, stop := p.browser.operationContext(ctx)
	defer stop()
	ctx, cancel := withTimeout(ctx, p.browser.opts.CommandTimeout)
	defer cancel()
	if _, err := p.currentURLLocked(ctx); err != nil {
		return nil, err
	}
	var metrics struct {
		ContentSize struct {
			Width  float64 `json:"width"`
			Height float64 `json:"height"`
		} `json:"contentSize"`
	}
	if err := p.browser.call(ctx, p.session, "Page.getLayoutMetrics", map[string]any{}, &metrics); err != nil {
		return nil, fmt.Errorf("browser: page metrics: %w", err)
	}
	width, height := metrics.ContentSize.Width, metrics.ContentSize.Height
	if math.IsNaN(width) || math.IsInf(width, 0) || math.IsNaN(height) || math.IsInf(height, 0) {
		return nil, errors.New("browser: screenshot dimensions are not finite")
	}
	if width < 1 || height < 1 || width > 10000 || height > 50000 {
		return nil, errors.New("browser: screenshot dimensions are invalid or exceed safety limits")
	}
	w, h := int(math.Ceil(width)), int(math.Ceil(height))
	if int64(w)*int64(h) > 64<<20 {
		return nil, errors.New("browser: screenshot pixel count exceeds safety limit")
	}
	var captured struct {
		Data string `json:"data"`
	}
	params := map[string]any{
		"format": "png", "fromSurface": true, "captureBeyondViewport": true,
		"clip": map[string]any{"x": 0, "y": 0, "width": w, "height": h, "scale": 1},
	}
	if err := p.browser.call(ctx, p.session, "Page.captureScreenshot", params, &captured); err != nil {
		return nil, fmt.Errorf("browser: full-page screenshot unsupported or failed: %w", err)
	}
	if captured.Data == "" || int64(len(captured.Data)) > int64(p.browser.opts.MaxScreenshotBytes)*4/3+8 {
		return nil, errors.New("browser: screenshot response missing or exceeds configured limit")
	}
	data, err := base64.StdEncoding.DecodeString(captured.Data)
	if err != nil {
		return nil, fmt.Errorf("browser: decode screenshot: %w", err)
	}
	if len(data) == 0 || len(data) > p.browser.opts.MaxScreenshotBytes {
		return nil, errors.New("browser: screenshot exceeds configured limit")
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width != w || config.Height != h {
		return nil, errors.New("browser: screenshot is not a valid full-page PNG")
	}
	if err := validateScreenshotPNG(ctx, data); err != nil {
		return nil, fmt.Errorf("browser: validate screenshot PNG: %w", err)
	}
	return data, nil
}

func (p *Page) Close(ctx context.Context) error {
	if p == nil || p.browser == nil {
		return errors.New("browser: nil page")
	}
	if ctx == nil {
		return errors.New("browser: nil context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	callerErr := ctx.Err()
	cleanupCtx, cancel := withTimeout(ctx, p.browser.opts.CommandTimeout)
	defer cancel()
	var response struct {
		Success bool `json:"success"`
	}
	err := p.browser.call(cleanupCtx, "", "Target.closeTarget", map[string]any{"targetId": p.target}, &response)
	p.browser.mu.Lock()
	delete(p.browser.pages, p.target)
	p.browser.mu.Unlock()
	if err != nil {
		p.closeErr = errors.Join(callerErr, fmt.Errorf("browser: close target: %w", err))
		p.browser.recordCleanupError(p.closeErr)
		return p.closeErr
	}
	if !response.Success {
		p.closeErr = errors.Join(callerErr, errors.New("browser: CDP did not confirm target closure"))
		p.browser.recordCleanupError(p.closeErr)
		return p.closeErr
	}
	p.closeErr = callerErr
	return p.closeErr
}

// closeTargetLocked is the cancellation path for an in-flight command. The
// unsupported Page.stopLoading command is deliberately not used.
func (p *Page) closeTargetLocked() error {
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), p.browser.opts.CommandTimeout)
	defer cancel()
	var response struct {
		Success bool `json:"success"`
	}
	err := p.browser.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": p.target}, &response)
	p.browser.mu.Lock()
	delete(p.browser.pages, p.target)
	p.browser.mu.Unlock()
	if err != nil {
		p.closeErr = fmt.Errorf("browser: cancel and close target: %w", err)
		p.browser.recordCleanupError(p.closeErr)
		return p.closeErr
	}
	if !response.Success {
		p.closeErr = errors.New("browser: cancellation target closure was not confirmed")
		p.browser.recordCleanupError(p.closeErr)
		return p.closeErr
	}
	return nil
}

func (p *Page) ready() error {
	if p == nil || p.browser == nil {
		return errors.New("browser: nil page")
	}
	if p.closed {
		return errors.New("browser: page is closed")
	}
	p.browser.mu.Lock()
	closed := p.browser.closed
	p.browser.mu.Unlock()
	if closed {
		return errors.New("browser: browser is closed")
	}
	return nil
}

func (b *Browser) call(ctx context.Context, session, method string, params, out any) error {
	if b == nil || b.client == nil {
		return errors.New("browser: CDP client unavailable")
	}
	if ctx == nil {
		return errors.New("browser: nil context")
	}
	ctx, cancel := withTimeout(ctx, b.opts.CommandTimeout)
	defer cancel()
	payload, err := b.client.Call(ctx, session, method, params)
	if err != nil {
		return err
	}
	maxBytes := b.opts.MaxResultBytes
	if method == "Page.captureScreenshot" && b.opts.MaxScreenshotBytes > 0 {
		maxBytes = b.opts.MaxScreenshotBytes*4/3 + 4096
	}
	if len(payload) > maxBytes {
		return errors.New("browser: CDP result exceeds configured limit")
	}
	if out == nil {
		return nil
	}
	if len(payload) == 0 {
		return io.ErrUnexpectedEOF
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("browser: decode %s result: %w", method, err)
	}
	return nil
}

func (b *Browser) operationContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	b.mu.Lock()
	lifetime := b.ctx
	closed := b.closed
	b.mu.Unlock()
	if closed || lifetime == nil {
		cancel()
		return ctx, func() {}
	}
	stop := context.AfterFunc(lifetime, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if value := u.Port(); value != "" {
			return value
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return port(a) == port(b)
}

func boundedText(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}
