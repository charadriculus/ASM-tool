package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/report"
	"asmtool/internal/storage"
)

type identityFixtureTransport struct{}

func (identityFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: r,
		Body: io.NopCloser(strings.NewReader(`[{"name_value":"a.example.test"}]`))}, nil
}

// Exercise the real producer and report reader together; no sockets or binaries.
func TestFreshPassiveCompletenessReportIdentity(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	target := "example.test"
	cfg.TargetDomain = &target
	cfg.AllowedDomains = []string{target}
	// Keep history discovery inside this test's isolated parent directory.
	cfg.OutputDir = filepath.Join(t.TempDir(), "run")
	cfg.CollectionPolicy.PassiveProviderProfile = "standard"
	cfg.CollectionPolicy.CRTNameEnabled = false
	cfg.CollectionPolicy.THCEnabled = false
	cfg.CollectionPolicy.CRTShEnabled = true
	cfg.CollectionPolicy.CertspotterEnabled = false
	cfg.CollectionPolicy.SubMDFallbackEnabled = false
	client, err := passive.NewClient(passive.HTTPPolicy{
		RequestsPerSecond: 1000, ConnectTimeout: time.Second, ReadTimeout: time.Second,
		Retries: 1, CacheTTL: time.Hour, MaxResponseBytes: 1 << 20, MaxCacheBytes: 1 << 20,
		UserAgent: cfg.UserAgent,
	}, &http.Client{Transport: identityFixtureTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.OutputDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(cfg.OutputDir, "asm.sqlite3")
	db, err := storage.Connect(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = passive.Collect(ctx, passive.CollectRequest{Config: cfg, HTTP: client,
		Sink: func(_ context.Context, _ core.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	input := report.Input{
		DatabasePath: dbPath, OutputDir: cfg.OutputDir, Version: Version,
		TargetDomain: target, Profile: "passive", Language: "en", GeneratedAt: time.Now().UTC(),
		Scope: map[string]any{"target_domain": target}, Modules: map[string]any{},
		CollectionPolicy: map[string]any{}, Coverage: map[string]any{},
	}
	model, _, err := report.Load(ctx, input)
	if err != nil {
		t.Fatalf("report rejected fresh passive completeness: %v", err)
	}
	health, ok := model["passive_provider_health"].([]any)
	if !ok || len(health) != 1 {
		t.Fatalf("provider evidence missing: %#v", model["passive_provider_health"])
	}

	// Strict identity validation must still reject incompatible artifacts.
	artifact := filepath.Join(cfg.ArtifactsDir(), "passive_provider_completeness.json")
	original, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"asm_version", "0.12.0-go"}, {"domain", "other.test"}, {"schema_version", 2},
	} {
		t.Run(tc.key, func(t *testing.T) {
			var bad map[string]any
			if err := json.Unmarshal(original, &bad); err != nil {
				t.Fatal(err)
			}
			bad[tc.key] = tc.value
			data, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(artifact, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, _, err = report.Load(ctx, input)
			if err == nil || !strings.Contains(err.Error(), "passive completeness artifact identity mismatch") {
				t.Fatalf("tampered %s was not rejected: %v", tc.key, err)
			}
		})
	}
}
