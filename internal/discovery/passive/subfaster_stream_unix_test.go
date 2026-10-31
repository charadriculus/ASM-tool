//go:build !windows

package passive

import (
	"asmtool/internal/platform"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func makeSubfaster(t *testing.T, body string) platform.Tool {
	t.Helper()
	root := t.TempDir()
	toolPath := filepath.Join(root, "tools", "subfaster")
	if err := os.MkdirAll(filepath.Dir(toolPath), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\nset -eu\n" + body + "\n")
	if err := os.WriteFile(toolPath, content, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(content)
	manifest, _ := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": "tools/subfaster", "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "subfaster", "executable": "tools/subfaster", "version": "2.18.0"}}})
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(manifest)
	bundle, err := platform.NewBundle(root, hex.EncodeToString(manifestHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Tool("subfaster")
	if err != nil {
		t.Fatal(err)
	}
	return tool
}

func TestStreamSubfasterPassesExplicitProviderAndStreamsJSONL(t *testing.T) {
	tool := makeSubfaster(t, `printf '%s\n' "$@" > "$(dirname "$0")/argv"; echo '{"host":"www.example.test","sources":["thc"]}'`)
	var rows []string
	run, err := StreamSubfaster(context.Background(), tool, "example.test", "thc", time.Second, func(_ context.Context, host string, sources []string) error {
		rows = append(rows, host+":"+strings.Join(sources, ","))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rows, "|") != "www.example.test:thc" || run.ParsedRows != 1 || run.StdoutLines != 1 {
		t.Fatalf("run=%+v rows=%v", run, rows)
	}
	if run.Version != "" || run.PinnedVersion != "2.18.0" || run.VersionEvidenceStatus != "manifest_identity_verified" || !run.KnownStartupNetworkRisk || len(run.ComponentSHA256) != 64 {
		t.Fatalf("version/risk evidence=%+v", run)
	}
	argv, err := os.ReadFile(filepath.Join(filepath.Dir(tool.Path()), "argv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(argv)) != "-d\nexample.test\n-s\nthc\n-oJ\n-cs" {
		t.Fatalf("argv=%q", argv)
	}
}

func TestStreamSubfasterRejectsUnsupportedProviderBeforeProcess(t *testing.T) {
	tool := makeSubfaster(t, `touch "$(dirname "$0")/started"`)
	if _, err := StreamSubfaster(context.Background(), tool, "example.test", "all", time.Second, func(context.Context, string, []string) error { return nil }); err == nil {
		t.Fatal("unsupported provider was accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(tool.Path()), "started")); !os.IsNotExist(err) {
		t.Fatalf("invalid request started Subfaster: %v", err)
	}
}

func TestStreamSubfasterReturnsRowsAndNonzeroProcessError(t *testing.T) {
	tool := makeSubfaster(t, `echo '{"host":"one.example.test","source":"thc"}'; echo 'provider fixture failure' >&2; exit 7`)
	var count int
	run, err := StreamSubfaster(context.Background(), tool, "example.test", "thc", time.Second, func(context.Context, string, []string) error { count++; return nil })
	if err == nil || run.ReturnCode != 7 || count != 1 || !strings.Contains(run.Stderr, "provider fixture failure") {
		t.Fatalf("run=%+v count=%d err=%v", run, count, err)
	}
}

func TestStreamSubfasterCancellationJoinsProcess(t *testing.T) {
	tool := makeSubfaster(t, `touch "$(dirname "$0")/started"; sleep 5`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := StreamSubfaster(ctx, tool, "example.test", "thc", 10*time.Second, func(context.Context, string, []string) error { return nil })
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(filepath.Dir(tool.Path()), "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Subfaster fixture did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v, want cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamSubfaster did not join canceled process")
	}
}
