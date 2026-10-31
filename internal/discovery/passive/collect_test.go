package passive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"asmtool/internal/config"
	"asmtool/internal/core"
)

func collectFixtureConfig(t *testing.T, providers ...string) config.ToolConfig {
	t.Helper()
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	target := "example.test"
	cfg.TargetDomain = &target
	cfg.AllowedDomains = []string{target}
	cfg.OutputDir = t.TempDir()
	cfg.UserAgent = "test-agent"
	cfg.RateLimits.PassiveSourceRequestsPerSecond = 1000
	cfg.CollectionPolicy.PassiveProviderProfile = "standard"
	cfg.CollectionPolicy.PassiveInventorySafetyCap = 8
	cfg.CollectionPolicy.PassiveSourceRetries = 1
	cfg.CollectionPolicy.PassiveConnectTimeoutSeconds = 1
	cfg.CollectionPolicy.PassiveReadTimeoutSeconds = 1
	cfg.CollectionPolicy.CRTNameConnectTimeoutSeconds = 1
	cfg.CollectionPolicy.CRTNameReadTimeoutSeconds = 1
	cfg.CollectionPolicy.CRTNameEnabled = false
	cfg.CollectionPolicy.THCEnabled = false
	cfg.CollectionPolicy.CRTShEnabled = false
	cfg.CollectionPolicy.CertspotterEnabled = false
	cfg.CollectionPolicy.SubMDFallbackEnabled = false
	for _, provider := range providers {
		switch provider {
		case "crt.name":
			cfg.CollectionPolicy.CRTNameEnabled = true
		case "thc":
			cfg.CollectionPolicy.THCEnabled = true
		case "crt.sh":
			cfg.CollectionPolicy.CRTShEnabled = true
		case "certspotter":
			cfg.CollectionPolicy.CertspotterEnabled = true
		}
	}
	return cfg
}

func collectFixtureClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	c, err := NewClient(HTTPPolicy{RequestsPerSecond: 1000, ConnectTimeout: time.Second, ReadTimeout: time.Second, Retries: 1, CacheTTL: time.Hour, MaxResponseBytes: 1 << 20, MaxCacheBytes: 1 << 20, UserAgent: "test-agent"}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsonResponse(req *http.Request, status int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func TestCollectUsesSharedTypedInventoryAndReportsSafetyCap(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.sh")
	cfg.CollectionPolicy.PassiveInventorySafetyCap = 3
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusOK, `[{"name_value":"a.example.test"},{"name_value":"b.example.test"},{"name_value":"c.example.test"}]`)
	}))
	var events []core.Event
	got, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, ev core.Event) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Inventory) != 3 || !got.Truncated {
		t.Fatalf("full retained inventory/cap mismatch: count=%d truncated=%t", len(got.Inventory), got.Truncated)
	}
	if root := got.Inventory["example.test"]; !root.InputTarget || len(root.Providers) != 1 || root.Providers[0] != "user_input" {
		t.Fatalf("input target attribution lost: %+v", root)
	}
	if item := got.Inventory["a.example.test"]; len(item.Providers) != 1 || item.Providers[0] != "crt.sh" || len(item.EvidenceFamilies) != 1 || item.EvidenceFamilies[0] != "certificate_transparency" {
		t.Fatalf("typed source provenance missing: %+v", item)
	}
	limitation := false
	for _, ev := range events {
		if ev.EventType == core.Limitation && ev.Metadata["limitation_type"] == "passive_inventory_safety_cap" {
			limitation = true
		}
	}
	if !limitation {
		t.Fatal("inventory safety cap was reached without a limitation event")
	}
}

func TestCollectCommitsEachObservationOnlyAfterItsPrimaryEvent(t *testing.T) {
	for _, failOn := range []core.EventType{core.SubdomainFound, core.TLSNameFound} {
		t.Run(string(failOn), func(t *testing.T) {
			cfg := collectFixtureConfig(t, "crt.sh")
			client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return jsonResponse(r, http.StatusOK, `[{"name_value":"a.example.test"}]`)
			}))
			wantErr := errors.New("sink failure")
			got, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, ev core.Event) error {
				if ev.EventType == failOn {
					return wantErr
				}
				return nil
			}})
			if !errors.Is(err, wantErr) {
				t.Fatalf("sink failure not propagated: %v", err)
			}
			_, retained := got.Inventory["a.example.test"]
			if retained != (failOn == core.TLSNameFound) {
				t.Fatalf("inventory disagrees with primary event persistence: retained=%t failed_event=%s", retained, failOn)
			}
		})
	}
}

func TestCollectCancelsAndJoinsOtherProvidersAfterSinkFailure(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.sh", "certspotter")
	started := make(chan struct{})
	canceled := make(chan struct{})
	var once sync.Once
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.certspotter.com" {
			once.Do(func() { close(started) })
			<-r.Context().Done()
			close(canceled)
			return nil, r.Context().Err()
		}
		select {
		case <-started:
		case <-time.After(time.Second):
		}
		return jsonResponse(r, http.StatusOK, `[{"name_value":"a.example.test"}]`)
	}))
	wantErr := errors.New("sink failure")
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, ev core.Event) error {
		if ev.EventType == core.SubdomainFound {
			return wantErr
		}
		return nil
	}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("sink failure not returned: %v", err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("in-flight provider was not canceled before Collect returned")
	}
}

func TestCollectEmitsTLSProvenanceAggregateConfidenceAndFallbackStatus(t *testing.T) {
	cfg := collectFixtureConfig(t, "crt.sh")
	cfg.CollectionPolicy.CRTNameEnabled = true
	cfg.CollectionPolicy.SubMDFallbackEnabled = true
	client := collectFixtureClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "crt.name" {
			return jsonResponse(r, http.StatusOK, `["a.example.test"]`)
		}
		return jsonResponse(r, http.StatusOK, `[{"name_value":"a.example.test"}]`)
	}))
	var events []core.Event
	_, err := Collect(context.Background(), CollectRequest{Config: cfg, HTTP: client, Sink: func(_ context.Context, event core.Event) error {
		events = append(events, event)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	var tls, aggregate, fallback *core.Event
	for i := range events {
		event := &events[i]
		switch {
		case event.EventType == core.TLSNameFound:
			tls = event
		case event.Metadata["collection"] == "passive_inventory_summary" && event.NormalizedValue == "a.example.test":
			aggregate = event
		case event.EventType == core.SourceHealth && event.SourceTool == "submd" && event.Metadata["status"] == "fallback_not_needed":
			fallback = event
		}
	}
	if tls == nil || tls.Metadata["provider_metadata"] == nil || tls.Metadata["independent_provider_evidence"] != true || tls.Metadata["dns_validated"] != false {
		t.Fatalf("TLS event lost observation provenance: %+v", tls)
	}
	if aggregate == nil || aggregate.Confidence != .76 || aggregate.Metadata["unique_provider_count"] != 2 {
		t.Fatalf("aggregate confidence/provenance mismatch: %+v", aggregate)
	}
	if fallback == nil || fallback.Confidence != 1 || fallback.Metadata["expected_version"] != ExpectedSubfasterVersion {
		t.Fatalf("fresh crt.name run did not report fallback_not_needed: %+v", fallback)
	}
}
