package browser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// EventLimits bounds the small subset of CDP events retained while a main
// document navigation is correlated. Zero limits are invalid; callers must
// choose explicit limits rather than accidentally opting into unbounded state.
type EventLimits struct {
	MaxEvents      int
	MaxEventBytes  int
	MaxTotalBytes  int
	MaxHeaderBytes int
}

// documentResponse is metadata from the final main-frame document response.
// Complete is true only after Network.loadingFinished for the correlated
// request; redirects and subresources are never treated as the final response.
type DocumentResponse struct {
	URL                string
	Status             int
	ContentType        string
	ContentDisposition string
	RequestID          string
	LoaderID           string
	FrameID            string
	Complete           bool
}

// documentResponse remains a private spelling for the collector's internal
// state while Page exposes the public metadata type.
type documentResponse = DocumentResponse

type retainedEvent struct {
	session string
	method  string
	params  json.RawMessage
}

type documentResponseCollector struct {
	mu sync.Mutex

	limits     EventLimits
	events     []retainedEvent
	bytes      int
	eventCount int
	err        error

	configured bool
	sessionSet bool
	session    string
	frameID    string
	loaderID   string
	requestID  string
	response   *documentResponse
	failed     bool
}

// newDocumentResponseCollector creates a bounded event collector. A practical
// caller limit is small (for example 512 events, 64 KiB/event and 2 MiB total).
func newDocumentResponseCollector(limits EventLimits) (*documentResponseCollector, error) {
	if limits.MaxEvents <= 0 || limits.MaxEvents > 4096 ||
		limits.MaxEventBytes <= 0 || limits.MaxEventBytes > 1<<20 ||
		limits.MaxTotalBytes <= 0 || limits.MaxTotalBytes > 8<<20 ||
		limits.MaxHeaderBytes <= 0 || limits.MaxHeaderBytes > 256<<10 ||
		limits.MaxHeaderBytes > limits.MaxEventBytes || limits.MaxEventBytes > limits.MaxTotalBytes {
		return nil, errors.New("invalid document event limits")
	}
	return &documentResponseCollector{limits: limits}, nil
}

// Ingest accepts only raw CDP event parameters. It performs no command calls
// and is safe to invoke from the transport's event reader. Relevant event
// packets are copied and retained only until the navigation identity is known.
func (c *documentResponseCollector) Ingest(sessionID, method string, params json.RawMessage) error {
	if c == nil {
		return errors.New("nil document response collector")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if !relevantDocumentMethod(method) {
		return nil
	}
	if c.sessionSet && sessionID != c.session {
		return nil
	}
	if len(params) == 0 || len(params) > c.limits.MaxEventBytes || !json.Valid(params) {
		return c.failLocked(errors.New("malformed or oversized document CDP event"))
	}
	if c.eventCount >= c.limits.MaxEvents || len(params) > c.limits.MaxTotalBytes-c.bytes {
		return c.failLocked(errors.New("document CDP event buffer limit exceeded"))
	}
	e := retainedEvent{session: sessionID, method: method, params: append(json.RawMessage(nil), params...)}
	c.eventCount++
	c.bytes += len(params)
	if c.configured {
		return c.processLocked(e)
	}
	c.events = append(c.events, e)
	return nil
}

// SetSession pins the collector to one flattened CDP target before navigation.
// Events from other sessions are ignored before validation or budget use.
func (c *documentResponseCollector) SetSession(sessionID string) error {
	if c == nil {
		return errors.New("nil document response collector")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if sessionID == "" || c.configured || c.sessionSet || len(c.events) != 0 {
		return c.failLocked(errors.New("missing or late document CDP session identity"))
	}
	c.session, c.sessionSet = sessionID, true
	return nil
}

// ConfigureNavigation binds buffered events to the exact flattened CDP
// session, main frame and loader returned by Page.navigate. Empty identities
// are rejected because they cannot safely distinguish same-document or stale
// responses. Events already received are replayed in wire order.
func (c *documentResponseCollector) ConfigureNavigation(sessionID, frameID, loaderID string) error {
	if c == nil {
		return errors.New("nil document response collector")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.configured || sessionID == "" || frameID == "" || loaderID == "" || (c.sessionSet && sessionID != c.session) {
		return c.failLocked(errors.New("missing or repeated document navigation identity"))
	}
	c.configured, c.session, c.frameID, c.loaderID = true, sessionID, frameID, loaderID
	for _, e := range c.events {
		if err := c.processLocked(e); err != nil {
			c.events = nil
			return err
		}
	}
	// Drop raw event payloads, which may include cookies or other headers. Only
	// the bounded response fields explicitly copied by processLocked survive.
	c.events = nil
	return nil
}

// Snapshot returns observed response metadata before load completion, with
// Complete=false. A failed load remains explicitly incomplete while retaining
// headers already observed, which permits accurate download classification.
func (c *documentResponseCollector) Snapshot() (DocumentResponse, error) {
	if c == nil {
		return DocumentResponse{}, errors.New("nil document response collector")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return DocumentResponse{}, c.err
	}
	if !c.configured {
		return DocumentResponse{}, errors.New("document response incomplete: navigation identity unavailable")
	}
	if c.response == nil {
		if c.failed {
			return DocumentResponse{}, errors.New("document response incomplete: main document load failed before headers")
		}
		return DocumentResponse{}, errors.New("document response incomplete: main document headers unavailable")
	}
	return *c.response, nil
}

// Result returns the response only when the final main-document response and
// its completion event were both observed. No status or headers are inferred.
func (c *documentResponseCollector) Result() (documentResponse, error) {
	if c == nil {
		return documentResponse{}, errors.New("nil document response collector")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return documentResponse{}, c.err
	}
	if !c.configured {
		return documentResponse{}, errors.New("document response incomplete: navigation identity unavailable")
	}
	if c.failed {
		return documentResponse{}, errors.New("document response incomplete: main document load failed")
	}
	if c.response == nil {
		return documentResponse{}, errors.New("document response incomplete: main document headers unavailable")
	}
	if !c.response.Complete {
		return documentResponse{}, errors.New("document response incomplete: load completion unavailable")
	}
	return *c.response, nil
}

func (c *documentResponseCollector) processLocked(e retainedEvent) error {
	if !c.configured || e.session != c.session {
		return nil
	}
	switch e.method {
	case "Network.requestWillBeSent":
		var p struct {
			RequestID string `json:"requestId"`
			LoaderID  string `json:"loaderId"`
			FrameID   string `json:"frameId"`
			Type      string `json:"type"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if err := decodeRequired(e.params, &p); err != nil {
			return c.failLocked(fmt.Errorf("malformed document request event: %w", err))
		}
		// Worker and other non-document requests may legitimately omit frame or
		// loader identity. They cannot be correlated to this main navigation.
		if p.LoaderID != c.loaderID || p.FrameID != c.frameID || p.Type != "Document" {
			return nil
		}
		if p.RequestID == "" || p.Request.URL == "" {
			return c.failLocked(errors.New("main document request event missing request identity or URL"))
		}
		if p.LoaderID == c.loaderID && p.FrameID == c.frameID && p.Type == "Document" {
			c.requestID = p.RequestID
			c.response = nil // a redirect starts the next response for this request
			c.failed = false
		}
	case "Network.responseReceived":
		var p struct {
			RequestID string `json:"requestId"`
			LoaderID  string `json:"loaderId"`
			FrameID   string `json:"frameId"`
			Type      string `json:"type"`
			Response  struct {
				URL         string          `json:"url"`
				Status      json.RawMessage `json:"status"`
				Headers     json.RawMessage `json:"headers"`
				HeadersText string          `json:"headersText"`
			} `json:"response"`
		}
		if err := decodeRequired(e.params, &p); err != nil {
			return c.failLocked(fmt.Errorf("malformed document response event: %w", err))
		}
		if p.LoaderID != c.loaderID || p.FrameID != c.frameID || p.Type != "Document" {
			return nil
		}
		if c.requestID == "" || p.RequestID == "" {
			return c.failLocked(errors.New("main document response has no established request identity"))
		}
		if p.RequestID != c.requestID {
			return nil
		}
		if p.Response.URL == "" || len(p.Response.Status) == 0 || len(p.Response.Headers) == 0 {
			return c.failLocked(errors.New("main document response missing URL, status or headers"))
		}
		status, err := parseHTTPStatus(p.Response.Status)
		if err != nil {
			return c.failLocked(err)
		}
		headers, err := parseResponseHeaders(p.Response.Headers, p.Response.HeadersText, c.limits.MaxHeaderBytes)
		if err != nil {
			return c.failLocked(err)
		}
		if _, err := url.ParseRequestURI(p.Response.URL); err != nil {
			return c.failLocked(errors.New("main document response has malformed URL"))
		}
		c.response = &documentResponse{
			URL: p.Response.URL, Status: status,
			ContentType: headers["content-type"], ContentDisposition: headers["content-disposition"],
			RequestID: p.RequestID, LoaderID: p.LoaderID, FrameID: p.FrameID,
		}
	case "Network.loadingFinished":
		var p struct {
			RequestID string `json:"requestId"`
		}
		if err := decodeRequired(e.params, &p); err != nil || p.RequestID == "" {
			return c.failLocked(errors.New("malformed document loadingFinished event"))
		}
		if p.RequestID == c.requestID && c.response != nil && !c.failed {
			c.response.Complete = true
		}
	case "Network.loadingFailed":
		var p struct {
			RequestID string `json:"requestId"`
		}
		if err := decodeRequired(e.params, &p); err != nil || p.RequestID == "" {
			return c.failLocked(errors.New("malformed document loadingFailed event"))
		}
		if p.RequestID == c.requestID {
			c.failed = true
			if c.response != nil {
				c.response.Complete = false
			}
		}
	}
	return nil
}

func relevantDocumentMethod(method string) bool {
	switch method {
	case "Network.requestWillBeSent", "Network.responseReceived", "Network.loadingFinished", "Network.loadingFailed":
		return true
	default:
		return false
	}
}

func (c *documentResponseCollector) failLocked(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}

func decodeRequired(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func parseHTTPStatus(raw json.RawMessage) (int, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return 0, errors.New("main document status is malformed")
	}
	n, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("main document status is not a JSON number")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return 0, errors.New("main document status has trailing data")
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 100 || f > 599 || math.Trunc(f) != f {
		return 0, errors.New("main document status is outside HTTP range")
	}
	return int(f), nil
}

func parseResponseHeaders(raw json.RawMessage, headersText string, max int) (map[string]string, error) {
	if len(raw) > max || len(headersText) > max {
		return nil, errors.New("main document response headers exceed byte limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("main document response headers are malformed")
	}
	values := make(map[string]string)
	for dec.More() {
		tok, err = dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok || name == "" {
			return nil, errors.New("main document response header name is malformed")
		}
		key := strings.ToLower(name)
		var value string
		if err = dec.Decode(&value); err != nil {
			return nil, errors.New("main document response header value is malformed")
		}
		if strings.ContainsAny(name, "\r\n\x00") {
			return nil, errors.New("main document response header contains control characters")
		}
		if key == "content-type" || key == "content-disposition" {
			if _, duplicate := values[key]; duplicate {
				return nil, errors.New("main document response contains duplicate retained header names")
			}
			if strings.ContainsAny(value, "\r\n\x00") {
				return nil, errors.New("main document retained response header contains control characters")
			}
			values[key] = value
		}
	}
	if _, err = dec.Token(); err != nil {
		return nil, errors.New("main document response headers are malformed")
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("main document response headers contain trailing data")
	}
	if headersText != "" && len(headersText) > max {
		return nil, errors.New("main document response header text exceeds byte limit")
	}
	return values, nil
}
