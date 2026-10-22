//go:build !windows

package execution

import (
	"asmtool/internal/platform"
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
	"sync"
	"testing"
	"time"
)

var helperOnce sync.Once
var helperPath string
var helperErr error

func testHelperPath(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		dir, e := os.MkdirTemp("", "asm-phase3-go-helper-")
		if e != nil {
			helperErr = e
			return
		}
		helperPath = filepath.Join(dir, "process-helper")
		cmd := exec.Command("go", "build", "-o", helperPath, filepath.Join("..", "..", "testdata", "phase3", "process_helper", "main.go"))
		cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOWORK=off", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			helperErr = errors.New(string(out) + err.Error())
		}
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	return helperPath
}

func fixtureTool(t *testing.T) platform.Tool {
	t.Helper()
	root := t.TempDir()
	rel := "bin/helper"
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(testHelperPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	m, _ := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": rel, "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "helper", "executable": rel, "version": "test"}}})
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), m, 0600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(m)
	b, err := platform.NewBundle(root, hex.EncodeToString(d[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := b.Tool("helper")
	if err != nil {
		t.Fatal(err)
	}
	return tool
}

func childArgs(mode string) []string { return []string{"--mode=" + mode} }

func TestRunLiteralArgsSanitizedEnvironmentAndArtifact(t *testing.T) {
	tool := fixtureTool(t)
	t.Setenv("ASM_TEST_SECRET", "must-not-leak")
	artifact := filepath.Join(t.TempDir(), "out")
	r, err := Run(context.Background(), tool, append(childArgs("echo"), "space & ё", "$(touch nope)"), Options{Timeout: time.Second, MaxOutputBytes: 4096, TailBytes: 4096, ArtifactRoot: filepath.Dir(artifact), StdoutArtifact: filepath.Base(artifact)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Stdout != "space & ё|$(touch nope)|" {
		t.Fatalf("literal arguments or environment changed: %q", r.Stdout)
	}
	if string(mustRead(t, artifact)) != r.Stdout || !r.ArtifactWritten {
		t.Fatal("artifact did not contain complete stdout")
	}
}

func TestRunProvidesStdinFromPrivateScratchFile(t *testing.T) {
	tool := fixtureTool(t)
	want := []byte("input\x00with\nbytes")
	r, err := Run(context.Background(), tool, childArgs("stdin"), Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128, Stdin: want})
	if err != nil || r.Stdout != string(want) {
		t.Fatalf("stdin result=%+v err=%v", r, err)
	}
}

func TestRunPreCanceledDoesNotExecuteAndSeparatesTimeoutFromCancel(t *testing.T) {
	tool := fixtureTool(t)
	marker := filepath.Join(t.TempDir(), "started")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(canceled, tool, append(childArgs("marker"), marker), Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel error=%v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("pre-canceled child ran: %v", err)
	}
	r, err := Run(context.Background(), tool, childArgs("sleep"), Options{Timeout: 30 * time.Millisecond, MaxOutputBytes: 1024, TailBytes: 128})
	if err == nil || !r.TimedOut {
		t.Fatalf("timeout result=%+v err=%v", r, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, stop)
	r, err = Run(ctx, tool, childArgs("sleep"), Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128})
	if !errors.Is(err, context.Canceled) || r.TimedOut {
		t.Fatalf("cancel result=%+v err=%v", r, err)
	}
}

func TestRunRootExitKillsDescendantHoldingPipes(t *testing.T) {
	tool := fixtureTool(t)
	start := time.Now()
	r, err := Run(context.Background(), tool, childArgs("spawn-holding-child"), Options{Timeout: 2 * time.Second, MaxOutputBytes: 4096, TailBytes: 128})
	if err != nil || !strings.Contains(r.Stdout, "root-exit") {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("descendant kept process pipes open after root exit")
	}
}

func TestRunOverflowPreservesPartialOutputAndCallbackStopsAfterError(t *testing.T) {
	tool := fixtureTool(t)
	r, err := Run(context.Background(), tool, childArgs("overflow"), Options{Timeout: time.Second, MaxOutputBytes: 512, TailBytes: 128})
	if err == nil || !r.OutputLimitExceeded || len(r.Stdout) == 0 || r.StdoutBytes == 0 {
		t.Fatalf("overflow result=%+v err=%v", r, err)
	}
	want := errors.New("sink failed")
	var lines []string
	r, err = Run(context.Background(), tool, childArgs("rows"), Options{Timeout: time.Second, MaxOutputBytes: 4096, TailBytes: 128, OnStdoutLine: func(_ context.Context, line string) error {
		lines = append(lines, line)
		return want
	}})
	if !errors.Is(err, want) || len(lines) != 1 || lines[0] != "first" {
		t.Fatalf("callback error=%v lines=%v result=%+v", err, lines, r)
	}
}

func TestRunBoundsFragmentedAndCompletedLines(t *testing.T) {
	tool := fixtureTool(t)
	var lines []string
	_, err := Run(context.Background(), tool, childArgs("fragmented"), Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128, MaxLineBytes: 4, OnStdoutLine: func(_ context.Context, line string) error {
		lines = append(lines, line)
		return nil
	}})
	if err != nil || strings.Join(lines, ",") != "a,b,last" {
		t.Fatalf("fragmented lines=%v err=%v", lines, err)
	}
	for _, mode := range []string{"long-terminated", "long-unterm"} {
		_, err := Run(context.Background(), tool, childArgs(mode), Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128, MaxLineBytes: 4, OnStdoutLine: func(context.Context, string) error { return nil }})
		if err == nil || !strings.Contains(err.Error(), "line exceeds") {
			t.Fatalf("mode %s accepted overlong line: %v", mode, err)
		}
	}
}

func TestRunArtifactNoClobber(t *testing.T) {
	tool := fixtureTool(t)
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), tool, childArgs("echo"), Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128, ArtifactRoot: filepath.Dir(path), StdoutArtifact: filepath.Base(path)})
	if err == nil || r.ArtifactWritten {
		t.Fatalf("clobber attempt result=%+v err=%v", r, err)
	}
	if string(mustRead(t, path)) != "original" {
		t.Fatal("previous artifact was changed")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
