//go:build !windows

package backends

import (
	"asmtool/internal/platform"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func registryFixture(t *testing.T, failingVersion bool) *platform.Bundle {
	t.Helper()
	root := t.TempDir()
	files := []any{}
	tools := []any{}
	for _, spec := range []struct{ name, rel, pin, body string }{
		{"typst", "bin/typst", "0.15.1", "#!/bin/sh\nprintf 'typst 0.15.2\\n'\n"},
		{"subfaster", "bin/subfaster", "2.18.0", "#!/bin/sh\nprintf 'must not start\\n'\n"},
	} {
		body := spec.body
		if spec.name == "typst" && failingVersion {
			body = "#!/bin/sh\nprintf 'typst 0.15.1\\n'\nexit 7\n"
		}
		p := filepath.Join(root, filepath.FromSlash(spec.rel))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(body))
		files = append(files, map[string]any{"path": spec.rel, "sha256": hex.EncodeToString(h[:])})
		tools = append(tools, map[string]any{"name": spec.name, "executable": spec.rel, "version": spec.pin})
	}
	m, err := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": files, "tools": tools})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), m, 0600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(m)
	b, err := platform.NewBundle(root, hex.EncodeToString(d[:]))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProcessRegistryUsesObservedVersionAndNoFallback(t *testing.T) {
	r := NewProcessRegistry(registryFixture(t, false))
	typst := r.Probe(context.Background(), "typst")
	if typst.Status != "version_mismatch" || typst.Available || typst.ActualVersion != "0.15.2" || typst.PinnedVersion != "0.15.1" {
		t.Fatalf("Typst provenance: %#v", typst)
	}
	s := r.Probe(context.Background(), "subfaster")
	if s.Status != "available" || !s.Available || s.ActualVersion != "" || s.PinnedVersion != "2.18.0" || s.VersionEvidenceStatus != "manifest_identity_verified" || !s.KnownStartupNetworkRisk || s.KnownStartupNetworkRiskDetail == "" || len(s.ComponentSHA256) != 64 || s.ExecutionMode != "verified_subprocess" {
		t.Fatalf("Subfaster must be identity-verified without a startup version probe: %#v", s)
	}
	u := r.Resolve(context.Background(), "not-registered")
	if u.Status != "not_implemented" || u.FallbackUsed {
		t.Fatalf("unexpected fallback: %#v", u)
	}
	h := r.Probe(context.Background(), "projectdiscovery_httpx")
	if h.Status != "blocked" || h.Actual != "" || h.PinnedVersion != "1.8.1" || h.Available || h.FallbackUsed {
		t.Fatalf("HTTPX was not explicitly blocked: %#v", h)
	}
}

func TestSubfasterRegistryProbeVerifiesManifestWithoutCreatingProcess(t *testing.T) {
	root := t.TempDir()
	toolPath := filepath.Join(root, "tools", "subfaster")
	if err := os.MkdirAll(filepath.Dir(toolPath), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\nprintf started > \"$(dirname \"$0\")/started\"\nprintf 'v2.18.0\n'\n")
	if err := os.WriteFile(toolPath, body, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	manifest, _ := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": "tools/subfaster", "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "subfaster", "executable": "tools/subfaster", "version": "2.18.0"}}})
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(manifest)
	bundle, err := platform.NewBundle(root, hex.EncodeToString(manifestHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	result := NewProcessRegistry(bundle).Probe(context.Background(), "subfaster")
	if result.Status != "available" || !result.Available || result.ActualVersion != "" || result.VersionEvidenceStatus != "manifest_identity_verified" || !result.KnownStartupNetworkRisk || result.KnownStartupNetworkRiskDetail == "" || result.ComponentSHA256 != hex.EncodeToString(h[:]) {
		t.Fatalf("Subfaster probe result=%+v", result)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(toolPath), "started")); !os.IsNotExist(err) {
		t.Fatalf("version probe created Subfaster process: stat err=%v", err)
	}
}

func TestProcessRegistryRejectsMatchingVersionFromFailedProbe(t *testing.T) {
	r := NewProcessRegistry(registryFixture(t, true))
	typst := r.Probe(context.Background(), "typst")
	if typst.Available || typst.Status != "unavailable" || typst.ActualVersion != typst.PinnedVersion || typst.Error == "" {
		t.Fatalf("failed matching-version probe reported available: %#v", typst)
	}
}

func TestNativeHTTPXIsBlockedBeforeVersionProbeSpawns(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "spawned")
	quotedMarker := "'" + strings.ReplaceAll(marker, "'", "'\\''") + "'"
	executable := filepath.Join(root, "tools", "httpx")
	if err := os.MkdirAll(filepath.Dir(executable), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\nprintf reached > " + quotedMarker + "\nprintf 'httpx version 1.8.1\\n'\n")
	if err := os.WriteFile(executable, body, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	manifest, _ := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": "tools/httpx", "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "projectdiscovery_httpx", "executable": "tools/httpx", "version": "1.8.1"}}})
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(manifest)
	bundle, err := platform.NewBundle(root, hex.EncodeToString(d[:]))
	if err != nil {
		t.Fatal(err)
	}
	result := NewProcessRegistry(bundle).Probe(context.Background(), "projectdiscovery_httpx")
	if result.Status != "blocked" || result.PinnedVersion != "1.8.1" {
		t.Fatalf("HTTPX probe result=%+v", result)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("blocked HTTPX version probe spawned fixture: stat err=%v", err)
	}
}
