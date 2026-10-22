package passive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Provider URLs are fixed product endpoints; callers cannot turn passive collection into an arbitrary fetcher.
var providerURLs = map[string]string{
	"crt.name":    "https://crt.name/v1/search",
	"crt.sh":      "https://crt.sh/",
	"certspotter": "https://api.certspotter.com/v1/issuances",
	"internetdb":  "https://internetdb.shodan.io/",
}

type HTTPPolicy struct {
	RequestsPerSecond           float64
	ConnectTimeout, ReadTimeout time.Duration
	Retries                     int
	CacheDir                    string
	CacheTTL                    time.Duration
	MaxResponseBytes            int64
	MaxCacheBytes               int64
	UserAgent                   string
}

type HTTPMeta struct {
	StatusCode         int     `json:"status_code,omitempty"`
	Attempts           int     `json:"attempts"`
	LogicalRequests    int     `json:"logical_requests"`
	CacheHit           bool    `json:"cache_hit"`
	CacheStale         bool    `json:"cache_stale"`
	CacheAgeSeconds    float64 `json:"cache_age_seconds,omitempty"`
	URL                string  `json:"url,omitempty"`
	ErrorType          string  `json:"error_type,omitempty"`
	TimeoutPhase       string  `json:"timeout_phase,omitempty"`
	FallbackAfterError string  `json:"fallback_after_error,omitempty"`
}

type SourceError struct {
	StatusCode    int
	Kind, Message string
	Cause         error
}

func (e *SourceError) Error() string { return e.Message }
func (e *SourceError) Unwrap() error { return e.Cause }

type cacheEnvelope struct {
	Created time.Time       `json:"created_at"`
	URL     string          `json:"url"`
	Data    json.RawMessage `json:"data"`
}
type Client struct {
	policy         HTTPPolicy
	http           *http.Client
	redirectPolicy func(*http.Request, []*http.Request) error
	mu             sync.Mutex
	last           map[string]time.Time
}

func NewClient(policy HTTPPolicy, client *http.Client) (*Client, error) {
	if policy.RequestsPerSecond <= 0 || math.IsNaN(policy.RequestsPerSecond) || math.IsInf(policy.RequestsPerSecond, 0) || policy.ConnectTimeout <= 0 || policy.ReadTimeout <= 0 || policy.Retries < 1 || policy.MaxResponseBytes < 1 || policy.MaxCacheBytes < 1 || policy.CacheTTL < 0 || strings.TrimSpace(policy.UserAgent) == "" {
		return nil, errors.New("invalid passive HTTP policy")
	}
	if client == nil {
		client = &http.Client{}
	}
	// Copy caller-owned policy before applying provider-specific redirect controls.
	clientCopy := *client
	if clientCopy.Transport == nil {
		clientCopy.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: policy.ConnectTimeout}).DialContext, TLSHandshakeTimeout: policy.ConnectTimeout}
	}
	priorRedirect := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{policy: policy, http: &clientCopy, redirectPolicy: priorRedirect, last: map[string]time.Time{}}, nil
}

func rateInterval(qps float64) time.Duration {
	seconds := 1.01 / qps
	if seconds >= float64(math.MaxInt64)/float64(time.Second) {
		return time.Duration(math.MaxInt64)
	}
	interval := time.Duration(seconds * float64(time.Second))
	if interval < time.Nanosecond {
		return time.Nanosecond
	}
	return interval
}

func (c *Client) wait(ctx context.Context, provider string) error {
	interval := rateInterval(c.policy.RequestsPerSecond)
	for {
		c.mu.Lock()
		delay := time.Until(c.last[provider].Add(interval))
		if delay <= 0 {
			c.last[provider] = time.Now()
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (c *Client) doProviderRequest(ctx context.Context, provider string, req *http.Request) (*http.Response, error) {
	via := make([]*http.Request, 0, 10)
	for {
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if !isRedirectStatus(resp.StatusCode) || resp.Header.Get("Location") == "" {
			return resp, nil
		}
		if len(via) >= 10 {
			resp.Body.Close()
			return nil, errors.New("passive provider redirect limit exceeded")
		}
		nextURL, err := resp.Location()
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		if !strings.EqualFold(req.URL.Host, nextURL.Host) || !strings.EqualFold(req.URL.Scheme, nextURL.Scheme) {
			resp.Body.Close()
			return nil, errors.New("cross-origin or transport-downgrade redirect rejected")
		}
		next := req.Clone(ctx)
		next.URL = nextURL
		next.Host = ""
		if c.redirectPolicy != nil {
			chain := append(append([]*http.Request(nil), via...), req)
			if err := c.redirectPolicy(next, chain); err != nil {
				if errors.Is(err, http.ErrUseLastResponse) {
					return resp, nil
				}
				resp.Body.Close()
				return nil, err
			}
		}
		resp.Body.Close()
		if err := c.wait(ctx, provider); err != nil {
			return nil, err
		}
		via = append(via, req)
		req = next
	}
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func canonical(provider string, params url.Values) (string, error) {
	base, ok := providerURLs[provider]
	if !ok {
		return "", fmt.Errorf("unsupported passive provider %q", provider)
	}
	u, _ := url.Parse(base)
	if provider == "internetdb" {
		ip := params.Get("_ip")
		parsed, err := netip.ParseAddr(ip)
		if err != nil {
			return "", errors.New("InternetDB requires an IP address")
		}
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + parsed.String()
		params = url.Values{}
	}
	q := url.Values{}
	for k, vs := range params {
		q[k] = append([]string(nil), vs...)
	}
	q.Encode()
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *Client) cachePath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.policy.CacheDir, hex.EncodeToString(sum[:])+".json")
}
func (c *Client) readCache(path string, allowStale bool) (json.RawMessage, HTTPMeta, bool) {
	var meta HTTPMeta
	if c.policy.CacheDir == "" {
		return nil, meta, false
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, meta, false
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, c.policy.MaxCacheBytes+1))
	if e != nil || int64(len(data)) > c.policy.MaxCacheBytes {
		return nil, meta, false
	}
	var env cacheEnvelope
	if json.Unmarshal(data, &env) != nil || env.Created.IsZero() || len(env.Data) == 0 {
		return nil, meta, false
	}
	age := time.Since(env.Created)
	if age < 0 {
		age = 0
	}
	stale := c.policy.CacheTTL == 0 || age > c.policy.CacheTTL
	if stale && !allowStale {
		return nil, meta, false
	}
	meta = HTTPMeta{CacheHit: true, CacheStale: stale, CacheAgeSeconds: age.Seconds(), URL: env.URL}
	return env.Data, meta, true
}
func (c *Client) writeCache(path, rawURL string, body []byte) {
	if c.policy.CacheDir == "" {
		return
	}
	if os.MkdirAll(c.policy.CacheDir, 0700) != nil {
		return
	}
	data, e := json.Marshal(cacheEnvelope{Created: time.Now().UTC(), URL: rawURL, Data: body})
	if e != nil || int64(len(data)) > c.policy.MaxCacheBytes {
		return
	}
	f, e := os.CreateTemp(c.policy.CacheDir, ".passive-*.tmp")
	if e != nil {
		return
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return
	}
	if e = f.Close(); e != nil {
		return
	}
	_ = os.Rename(name, path)
}

// GetJSON accepts only fixed provider IDs, limits attempts/body/cache, and returns stale data with explicit metadata after failure.
func (c *Client) GetJSON(ctx context.Context, provider string, params url.Values, cacheKey string, extraRetry map[int]bool) (json.RawMessage, HTTPMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, HTTPMeta{}, err
	}
	rawURL, e := canonical(provider, params)
	if e != nil {
		return nil, HTTPMeta{}, e
	}
	key := rawURL
	if cacheKey != "" {
		key = provider + ":" + cacheKey
	}
	path := c.cachePath(key)
	if b, m, ok := c.readCache(path, false); ok {
		return b, m, nil
	}
	var lastErr error
	meta := HTTPMeta{LogicalRequests: 1}
	for attempt := 0; attempt < c.policy.Retries; attempt++ {
		attemptNo := attempt + 1
		if e = c.wait(ctx, provider); e != nil {
			return nil, meta, e
		}
		meta.Attempts = attemptNo
		ctxReq, cancel := context.WithTimeout(ctx, c.policy.ReadTimeout)
		retryDelay := time.Duration(0)
		req, err := http.NewRequestWithContext(ctxReq, http.MethodGet, rawURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", c.policy.UserAgent)
			req.Header.Set("Accept", "application/json,text/plain,*/*")
			resp, doErr := c.doProviderRequest(ctxReq, provider, req)
			err = doErr
			if doErr == nil {
				limited, readErr := io.ReadAll(io.LimitReader(resp.Body, c.policy.MaxResponseBytes+1))
				resp.Body.Close()
				if int64(len(limited)) > c.policy.MaxResponseBytes {
					readErr = errors.New("passive provider response exceeds byte limit")
				}
				meta = HTTPMeta{StatusCode: resp.StatusCode, Attempts: attemptNo, URL: resp.Request.URL.String(), LogicalRequests: 1}
				if readErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
					var value any
					if json.Unmarshal(limited, &value) == nil {
						c.writeCache(path, rawURL, limited)
						cancel()
						return limited, meta, nil
					}
					readErr = errors.New("invalid JSON from passive provider")
				}
				if readErr != nil {
					err = readErr
				} else {
					err = &SourceError{StatusCode: resp.StatusCode, Kind: "http", Message: fmt.Sprintf("passive provider %s returned HTTP %d", provider, resp.StatusCode)}
				}
				if (resp.StatusCode == 408 || resp.StatusCode == 425 || resp.StatusCode == 429 || resp.StatusCode >= 500 || extraRetry[resp.StatusCode]) && attemptNo < c.policy.Retries {
					if value, valid := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); valid {
						retryDelay = value
						if retryDelay < time.Second {
							retryDelay = time.Second
						}
						if retryDelay > 20*time.Second {
							retryDelay = 20 * time.Second
						}
					}
					err = nil
				}
			}
		}
		cancel()
		if err == nil {
			if retryDelay == 0 {
				retryDelay = retryBackoff(attemptNo)
			}
			t := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, meta, ctx.Err()
			case <-t.C:
			}
			continue
		}
		lastErr = err
		if attemptNo < c.policy.Retries {
			var se *SourceError
			if errors.As(err, &se) && se.StatusCode != 0 && se.StatusCode != 408 && se.StatusCode != 425 && se.StatusCode != 429 && se.StatusCode < 500 && !extraRetry[se.StatusCode] {
				break
			}
			delay := retryBackoff(attemptNo)
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, meta, ctx.Err()
			case <-t.C:
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, meta, err
	}
	kind := "failed"
	var netErr net.Error
	if errors.Is(lastErr, context.DeadlineExceeded) || errors.Is(lastErr, context.Canceled) || errors.As(lastErr, &netErr) && netErr.Timeout() {
		kind = "timeout"
		meta.TimeoutPhase = "read"
		var opErr *net.OpError
		if errors.As(lastErr, &opErr) && opErr.Op == "dial" {
			meta.TimeoutPhase = "connect"
		}
	} else {
		var opErr *net.OpError
		if errors.As(lastErr, &opErr) {
			kind = "unavailable"
		}
	}
	var se *SourceError
	if errors.As(lastErr, &se) && se.StatusCode == 429 {
		kind = "rate_limited"
	}
	meta.ErrorType = kind
	if b, stale, ok := c.readCache(path, true); ok {
		stale.Attempts = meta.Attempts
		stale.LogicalRequests = meta.LogicalRequests
		stale.StatusCode = meta.StatusCode
		stale.ErrorType = kind
		stale.TimeoutPhase = meta.TimeoutPhase
		stale.FallbackAfterError = lastErr.Error()
		return b, stale, nil
	}
	return nil, meta, &SourceError{StatusCode: meta.StatusCode, Kind: kind, Cause: lastErr, Message: fmt.Sprintf("passive provider %s failed: %v", provider, lastErr)}
}

func retryBackoff(attempt int) time.Duration {
	exponent := min(max(attempt-1, 0), 3)
	return time.Duration(1<<exponent) * time.Second
}

func values(pairs ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Add(pairs[i], pairs[i+1])
	}
	for _, k := range sortedKeys(v) {
		sort.Strings(v[k])
	}
	return v
}
func sortedKeys(v url.Values) []string {
	k := make([]string, 0, len(v))
	for x := range v {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
func parseRetryAfter(s string, now time.Time) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s != "" {
		digits := true
		for _, r := range s {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		if digits {
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil || n > 20 {
				return 20 * time.Second, true
			}
			return time.Duration(n) * time.Second, true
		}
	}
	if t, e := http.ParseTime(s); e == nil && t.After(now) {
		return t.Sub(now), true
	}
	return 0, false
}
