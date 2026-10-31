package browser

import (
	"errors"
	"net/url"
)

// Response returns observed final main-document metadata. It never invents
// status or headers when a transport lacks the required CDP events.
func (p *Page) Response() (DocumentResponse, error) {
	if p == nil || p.browser == nil {
		return DocumentResponse{}, errors.New("browser: nil page")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.document == nil {
		return DocumentResponse{}, errors.New("browser: document response unavailable")
	}
	response, err := p.document.Snapshot()
	if err != nil {
		return DocumentResponse{}, err
	}
	if _, err := p.browser.opts.Scope.RequireActiveAllowed(p.browser.opts.Profile, p.browser.opts.Authorized, response.URL, "url"); err != nil {
		return DocumentResponse{}, err
	}
	observed, err := url.Parse(response.URL)
	if err != nil || observed.User != nil {
		return DocumentResponse{}, errors.New("browser: invalid document URL")
	}
	if p.current != "" {
		current, err := url.Parse(p.current)
		if err != nil || !sameOrigin(current, observed) {
			return DocumentResponse{}, errors.New("browser: document origin changed")
		}
	}
	if p.requested != "" {
		requested, err := url.Parse(p.requested)
		if err != nil || !sameOrigin(requested, observed) {
			return DocumentResponse{}, errors.New("browser: response differs from requested origin")
		}
	}
	return response, nil
}
