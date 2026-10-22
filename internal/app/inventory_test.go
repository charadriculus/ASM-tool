package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
)

type inventoryRewriteTransport struct {
	base http.RoundTripper
	to   string
}

func (t inventoryRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	baseURL, err := url.Parse(t.to)
	if err != nil {
		return nil, err
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/") + req.URL.Path
	copy.URL = baseURL
	copy.Host = baseURL.Host
	return t.base.RoundTrip(copy)
}

func newInventoryTestClient(t *testing.T, handler http.Handler) (*passive.Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	base := http.DefaultTransport
	client, err := passive.NewClient(passive.HTTPPolicy{
		RequestsPerSecond: 1000, ConnectTimeout: time.Second, ReadTimeout: time.Second,
		Retries: 1, CacheTTL: 0, MaxResponseBytes: 1 << 16, MaxCacheBytes: 1 << 16,
		UserAgent: config.UserAgent,
	}, &http.Client{Transport: inventoryRewriteTransport{base: base, to: server.URL}})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server.Close
}

func inventoryTestConfig(t *testing.T) config.ToolConfig {
	t.Helper()
	cfg := config.ToolConfig{ScopePolicy: core.ScopePolicy{AllowedDomains: []string{"example.test"}}, CollectionPolicy: config.CollectionPolicy{InternetdbEnabled: true, PassiveMaxIPs: 10}}
	cfg.OutputDir = t.TempDir()
	return cfg
}

func inventoryTestIndex() *evidence.DNSRunIndex {
	index := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	index.Ingest(map[string]any{"event_type": string(core.IPFound), "normalized_value": "192.0.2.10", "metadata": map[string]any{"domain": "www.example.test"}})
	return index
}

func TestCollectPortInventoryUsesOnlyIndexedIPsAndKeepsSharedHostContext(t *testing.T) {
	var requested string
	client, closeServer := newInventoryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		_, _ = fmt.Fprint(w, `{"ports":[443,"8080",0,70000,-1,"ssh",443],"hostnames":["www.example.test","unrelated.test"],"tags":["cloud"],"cpes":["cpe:/a:test"],"vulns":["CVE-2026-9999"]}`)
	}))
	defer closeServer()
	var events []core.Event
	cfg := inventoryTestConfig(t)
	incomplete, err := collectPortInventory(context.Background(), cfg, inventoryTestIndex(), client, func(_ context.Context, event core.Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if incomplete {
		t.Fatal("valid bounded observation marked incomplete")
	}
	if requested != "/192.0.2.10" {
		t.Fatalf("InternetDB request path = %q", requested)
	}
	var domains, ports, web int
	webURLs := make(map[string]bool)
	var evidencePath, evidenceHash string
	for _, event := range events {
		switch event.EventType {
		case core.DomainFound:
			domains++
			if event.ScopeStatus == core.InScope || event.Metadata["context_only"] != true || event.Metadata["not_added_to_active_scope"] != true {
				t.Fatalf("related hostname must remain context-only and out of scope: %#v", event)
			}
		case core.PortFound:
			ports++
			if event.ScopeStatus != core.NeedsManualReview || event.Metadata["observation_type"] != "passive_osint" {
				t.Fatalf("shared IP observation lacks attribution warning: %#v", event)
			}
			if raw, ok := event.RawValue.(map[string]any); !ok || raw["vulns"] != nil {
				t.Fatalf("port event should contain only compact known fields: %#v", event.RawValue)
			}
			evidencePath, _ = event.Metadata["provider_evidence_path"].(string)
			evidenceHash, _ = event.Metadata["provider_evidence_sha256"].(string)
		case core.WebServiceFound:
			web++
			url, ok := event.NormalizedValue.(string)
			if !ok || event.Metadata["live_confirmed"] != false {
				t.Fatalf("web service was not inferred from mapped DNS evidence: %#v", event)
			}
			webURLs[url] = true
		}
	}
	if domains != 1 || ports != 2 || web != 2 {
		t.Fatalf("domain/port/web events = %d/%d/%d", domains, ports, web)
	}
	if !webURLs["https://www.example.test/"] || !webURLs["http://www.example.test:8080/"] {
		t.Fatalf("inferred URLs = %#v", webURLs)
	}
	if !strings.HasPrefix(evidencePath, "artifacts/internetdb/internetdb-") || evidenceHash == "" {
		t.Fatalf("missing local provider evidence reference: path=%q hash=%q", evidencePath, evidenceHash)
	}
	artifactPath := filepath.Join(cfg.OutputDir, filepath.FromSlash(evidencePath))
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read provider evidence artifact: %v", err)
	}
	gotHash, err := backends.SHA256File(artifactPath)
	if err != nil || gotHash != evidenceHash || !strings.Contains(string(artifact), `"ports"`) || !strings.Contains(string(artifact), `"cpes"`) || !strings.Contains(string(artifact), `"CVE-2026-9999"`) {
		t.Fatalf("provider artifact/hash mismatch: hash=%q want=%q err=%v", gotHash, evidenceHash, err)
	}
}

func TestCollectPortInventoryDoesNotAttributeUnmappedIPToScope(t *testing.T) {
	client, closeServer := newInventoryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ports":[443]}`)
	}))
	defer closeServer()
	index := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	index.Ingest(map[string]any{"event_type": string(core.IPFound), "normalized_value": "192.0.2.11", "metadata": map[string]any{}})
	var ports, web int
	_, err := collectPortInventory(context.Background(), inventoryTestConfig(t), index, client, func(_ context.Context, event core.Event) error {
		switch event.EventType {
		case core.PortFound:
			ports++
			if event.ScopeStatus != core.NeedsManualReview || event.Metadata["context_only"] != true || event.Metadata["not_added_to_active_scope"] != true {
				t.Fatalf("unmapped IP marked in scope: %#v", event)
			}
		case core.WebServiceFound:
			web++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ports != 1 || web != 0 {
		t.Fatalf("unmapped IP emitted port/web events %d/%d", ports, web)
	}
}

func TestCollectPortInventoryBoundsMappedDomainContext(t *testing.T) {
	client, closeServer := newInventoryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ports":[443]}`)
	}))
	defer closeServer()
	index := evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}})
	for i := 0; i <= maxInternetDBNames; i++ {
		domain := fmt.Sprintf("host-%02d.example.test", i)
		index.Ingest(map[string]any{"event_type": string(core.IPFound), "normalized_value": "192.0.2.12", "metadata": map[string]any{"domain": domain}})
	}
	var portEvent core.Event
	var webCount, truncationWarnings int
	incomplete, err := collectPortInventory(context.Background(), inventoryTestConfig(t), index, client, func(_ context.Context, event core.Event) error {
		switch event.EventType {
		case core.PortFound:
			portEvent = event
		case core.WebServiceFound:
			webCount++
		case core.Limitation:
			if event.Metadata["source_status"] == "truncated" {
				truncationWarnings++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !incomplete || len(portEvent.Metadata["mapped_in_scope_domains"].([]string)) != maxInternetDBNames || portEvent.Metadata["mapped_in_scope_domains_total"] != maxInternetDBNames+1 || portEvent.Metadata["mapped_in_scope_domains_truncated"] != true || webCount != maxInternetDBNames || truncationWarnings != 1 {
		t.Fatalf("mapped-domain attribution bounds: incomplete=%v metadata=%#v web=%d warnings=%d", incomplete, portEvent.Metadata, webCount, truncationWarnings)
	}
}

func TestParseInternetDBBoundsStringsAndPortArrays(t *testing.T) {
	longValue := strings.Repeat("é", maxInternetDBText)
	var raw strings.Builder
	raw.WriteString(`{"ports":[`)
	for i := 1; i <= maxInternetDBPorts+1; i++ {
		if i > 1 {
			raw.WriteByte(',')
		}
		fmt.Fprint(&raw, i)
	}
	raw.WriteString(`],"hostnames":[`)
	for i := 0; i < maxInternetDBNames+1; i++ {
		if i > 0 {
			raw.WriteByte(',')
		}
		fmt.Fprintf(&raw, `"%s"`, longValue)
	}
	raw.WriteString(`],"tags":[`)
	fmt.Fprintf(&raw, `"%s"`, longValue)
	raw.WriteString(`],"cpes":[`)
	fmt.Fprintf(&raw, `"%s"`, longValue)
	raw.WriteString(`]}`)
	observation, err := parseInternetDB([]byte(raw.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.truncated || len(observation.ports) != maxInternetDBPorts || len(observation.hostnames) != maxInternetDBNames {
		t.Fatalf("bounded parse truncated=%v ports=%d hostnames=%d", observation.truncated, len(observation.ports), len(observation.hostnames))
	}
	for name, values := range map[string][]string{"hostnames": observation.hostnames, "tags": observation.tags, "cpes": observation.cpes} {
		limit := maxInternetDBText
		if name == "hostnames" {
			limit = 253
		}
		for _, value := range values {
			if len(value) > limit {
				t.Fatalf("%s item exceeded byte limit %d: %d", name, limit, len(value))
			}
		}
	}
}

func TestCollectPortInventoryDistinguishesNoResultsFromUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantResult string
		wantBad    bool
	}{
		{name: "not found", status: http.StatusNotFound, wantResult: "no_results"},
		{name: "provider failed", status: http.StatusServiceUnavailable, wantResult: "unavailable", wantBad: true},
		{name: "malformed provider payload", status: http.StatusOK, body: `[]`, wantResult: "invalid_response", wantBad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, closeServer := newInventoryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer closeServer()
			var got []core.Event
			incomplete, err := collectPortInventory(context.Background(), inventoryTestConfig(t), inventoryTestIndex(), client, func(_ context.Context, event core.Event) error {
				got = append(got, event)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if incomplete != tc.wantBad {
				t.Fatalf("incomplete = %v, want %v", incomplete, tc.wantBad)
			}
			if len(got) != 1 || got[0].Metadata["source_status"] != tc.wantResult {
				t.Fatalf("limitation evidence = %#v", got)
			}
		})
	}
}

func TestCollectPortInventorySkipsEmptyIndexAndPropagatesSinkFailure(t *testing.T) {
	requested := false
	client, closeServer := newInventoryTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requested = true }))
	defer closeServer()
	var got core.Event
	incomplete, err := collectPortInventory(context.Background(), inventoryTestConfig(t), evidence.NewDNSRunIndex(core.ScopePolicy{AllowedDomains: []string{"example.test"}}), client, func(_ context.Context, event core.Event) error { got = event; return nil })
	if err != nil || !incomplete || requested || got.Metadata["action"] != "check_target_dns" {
		t.Fatalf("empty DNS index result incomplete=%v requested=%v event=%#v err=%v", incomplete, requested, got, err)
	}

	want := errors.New("sink failed")
	_, err = collectPortInventory(context.Background(), inventoryTestConfig(t), inventoryTestIndex(), client, func(context.Context, core.Event) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("sink error was swallowed: %v", err)
	}
}

func TestCollectPortInventoryCancellationPreventsProviderContact(t *testing.T) {
	requested := false
	client, closeServer := newInventoryTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requested = true }))
	defer closeServer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := collectPortInventory(ctx, inventoryTestConfig(t), inventoryTestIndex(), client, func(context.Context, core.Event) error { return nil })
	if !errors.Is(err, context.Canceled) || requested {
		t.Fatalf("cancellation result err=%v requested=%v", err, requested)
	}
}
