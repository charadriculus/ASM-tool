//go:build linux

package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/platform"
	"asmtool/internal/storage"
)

// This deliberately uses a verified synthetic tool to stop inside the compile
// step. It is cancellation evidence only and never counts as Typst/PDF PASS.
func TestGenerateCancellationDuringSyntheticCompilePreservesPublishedFiles(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "started")
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep utility is required for the synthetic cancellation test")
	}
	executable := []byte("#!/bin/sh\nprintf started > '" + strings.ReplaceAll(marker, "'", "'\\''") + "'\nexec '" + strings.ReplaceAll(sleepPath, "'", "'\\''") + "' 30\n")
	typst := makeSyntheticTypst(t, root, executable)

	database := filepath.Join(root, "asm.sqlite3")
	db, err := storage.Connect(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fontDir := filepath.Join(root, "fonts")
	if err := os.Mkdir(fontDir, 0700); err != nil {
		t.Fatal(err)
	}
	in := sampleInput(database, filepath.Join(root, "output"))
	in.FontDir = fontDir
	priorDir, priorFile := seedPriorGeneration(t, filepath.Join(in.OutputDir, "reports"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Generate(ctx, in, typst)
		done <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	started := false
	for !started {
		select {
		case err := <-done:
			t.Fatalf("synthetic tool exited before cancellation: %v", err)
		case <-deadline.C:
			t.Fatal("synthetic tool did not start")
		case <-ticker.C:
			_, err := os.Stat(marker)
			started = err == nil
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted Generate error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Generate did not stop after context cancellation")
	}
	reportsDir := filepath.Join(in.OutputDir, "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(priorDir) {
		t.Fatalf("interrupted generation changed published set: %v", entries)
	}
	prior, err := os.ReadFile(priorFile)
	if err != nil || string(prior) != "previous complete report" {
		t.Fatalf("previous report changed after interruption: %q, %v", prior, err)
	}
}

func TestGenerateSyntheticCompilerFailurePreservesPreviousGeneration(t *testing.T) {
	root := t.TempDir()
	typst := makeSyntheticTypst(t, root, []byte("#!/bin/sh\nprintf 'fixture compiler failure' >&2\nexit 17\n"))
	database := filepath.Join(root, "asm.sqlite3")
	db, err := storage.Connect(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fontDir := filepath.Join(root, "fonts")
	if err := os.Mkdir(fontDir, 0700); err != nil {
		t.Fatal(err)
	}
	in := sampleInput(database, filepath.Join(root, "output"))
	in.FontDir = fontDir
	priorDir, priorFile := seedPriorGeneration(t, filepath.Join(in.OutputDir, "reports"))
	_, err = Generate(context.Background(), in, typst)
	if err == nil || !strings.Contains(err.Error(), "child process exit=17") {
		t.Fatalf("Generate error = %v, want observed child process exit=17 diagnostic", err)
	}
	entries, err := os.ReadDir(filepath.Dir(priorDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(priorDir) {
		t.Fatalf("compiler failure changed report generation set: %v", entries)
	}
	prior, err := os.ReadFile(priorFile)
	if err != nil || string(prior) != "previous complete report" {
		t.Fatalf("previous report changed after compiler failure: %q, %v", prior, err)
	}
}

func seedPriorGeneration(t *testing.T, reportsDir string) (string, string) {
	t.Helper()
	if err := os.MkdirAll(reportsDir, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"final_report.json": []byte(`{"previous":true}`),
		"report.html":       []byte("previous complete report"),
		"report.typ":        []byte("# previous"),
		"report.pdf":        []byte("%PDF-1.4\nprevious test pdf bytes padded to pass the output validator length requirement................................"),
		"subdomains.csv":    []byte("hostname\n"),
	}
	hashes := make(map[string]string, len(files))
	for name, data := range files {
		hashes[name] = backends.SHA256(data)
	}
	manifest, err := backends.EncodeJSON(map[string]any{"status": "ok", "generated_at_utc": "2026-10-13T12:00:00Z", "report_language": "en", "report_mode": "bounded", "typst_version": "0.15.1", "sha256": hashes}, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	stage, digests := stagedGeneration(t, reportsDir, files, manifest)
	path, moved, err := publishGeneration(context.Background(), reportsDir, stage, manifest, digests)
	if err != nil || !moved {
		t.Fatalf("seed previous generation = %q, %v, %v", path, moved, err)
	}
	return path, filepath.Join(path, "report.html")
}

func makeSyntheticTypst(t *testing.T, root string, executable []byte) platform.Tool {
	t.Helper()
	bundleRoot := filepath.Join(root, "tool-bundle")
	if err := os.Mkdir(bundleRoot, 0700); err != nil {
		t.Fatal(err)
	}
	toolPath := filepath.Join(bundleRoot, "fake-typst")
	if err := os.WriteFile(toolPath, executable, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executable)
	manifest := struct {
		SchemaVersion int    `json:"schema_version"`
		Platform      string `json:"platform"`
		Files         []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		Tools []struct {
			Name       string `json:"name"`
			Executable string `json:"executable"`
			Version    string `json:"version"`
		} `json:"tools"`
	}{SchemaVersion: 1, Platform: runtime.GOOS + "/" + runtime.GOARCH}
	manifest.Files = append(manifest.Files, struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}{Path: "fake-typst", SHA256: hex.EncodeToString(digest[:])})
	manifest.Tools = append(manifest.Tools, struct {
		Name       string `json:"name"`
		Executable string `json:"executable"`
		Version    string `json:"version"`
	}{Name: "typst", Executable: "fake-typst", Version: "0.15.1"})
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(manifestBytes)
	bundle, err := platform.NewBundle(bundleRoot, hex.EncodeToString(manifestHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	typst, err := bundle.Tool("typst")
	if err != nil {
		t.Fatal(err)
	}
	return typst
}
