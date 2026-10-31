package app

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseOptionsDefaultsAndExplicitAliases(t *testing.T) {
	opts, err := ParseOptions([]string{"run", "--target", "example.test", "--report-language", "ru", "--confirm-authorization", "--ports", "443,80,443"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Profile != "passive" || opts.Domain != "example.test" || opts.Language != "ru" || opts.Ports != "80,443" || !opts.Authorized || opts.TimeoutSeconds != 3600 {
		t.Fatalf("unexpected options: %+v", opts)
	}
	for _, name := range []string{"target", "domain", "report-language", "language", "confirm-authorization", "yes", "ports"} {
		if !opts.Set[name] {
			t.Errorf("explicit option %q was not recorded", name)
		}
	}
	if opts.Set["profile"] {
		t.Error("default profile must not override a profile loaded from config")
	}
}

func TestParseOptionsWholeRunTimeout(t *testing.T) {
	for _, value := range []string{"1", "3600", "86400"} {
		opts, err := ParseOptions([]string{"--timeout-seconds", value})
		if err != nil {
			t.Errorf("timeout %s rejected: %v", value, err)
			continue
		}
		if !opts.Set["timeout-seconds"] {
			t.Errorf("explicit timeout %s not recorded", value)
		}
	}
	for _, value := range []string{"0", "86401", "-1", "nope"} {
		if _, err := ParseOptions([]string{"--timeout-seconds", value}); err == nil {
			t.Errorf("invalid timeout %q accepted", value)
		}
	}
	if opts, err := ParseOptions(nil); err != nil || opts.TimeoutSeconds != 3600 {
		t.Errorf("default timeout = %d, err=%v; want 3600", opts.TimeoutSeconds, err)
	}
}

func TestParseOptionsRejectsConflictingOrUnsupportedModes(t *testing.T) {
	cases := [][]string{
		{"--verify", "--full"},
		{"--profile", "verify", "--passive"},
		{"--profile", "research"},
		{"--passive-sources", "research"},
		{"--ai-review"},
		{"--ollama-model", "local"},
		{"research-metrics"},
		{"build-ai-report"},
		{"--profile", "verify", "trailing"},
		{"--ports", "80,0"},
		{"--ports", ""},
		{"--language", "de"},
		{"--dns-budget", "-1"},
		{"--passive", "--yes"},
	}
	for _, args := range cases {
		if _, err := ParseOptions(args); err == nil {
			t.Errorf("ParseOptions(%q) accepted", args)
		}
	}
}

func TestProfileSelectionAndAuthorizationParsing(t *testing.T) {
	opts, err := ParseOptions([]string{"--domain", "example.test", "--verify", "--yes", "--allow-http-fallback"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Profile != "verify" || !opts.Authorized || !opts.AllowHTTPFallback || !opts.Set["profile"] {
		t.Fatalf("expected explicit authorized verify options, got %+v", opts)
	}
	if _, err := ParseOptions([]string{"--domain", "example.test", "--full"}); err != nil {
		t.Fatalf("parsing active profile should defer authorization prompting to RunCLI: %v", err)
	}
}

func TestHelpAndVersionAreLocalAndRejectUnsupportedFlags(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := RunCLI(context.Background(), []string{"--help", "--config", "/missing/config.yml"}, strings.NewReader(""), &out, &stderr); code != 0 {
		t.Fatalf("help exit = %d, stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(out.String(), "ASM Tool "+Version+"\n") || !strings.Contains(out.String(), "Usage:") || stderr.Len() != 0 {
		t.Fatalf("unexpected help output: %q %q", out.String(), stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if code := RunCLI(context.Background(), []string{"--version"}, strings.NewReader(""), &out, &stderr); code != 0 {
		t.Fatalf("version exit = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(out.String(), Version) || !strings.Contains(out.String(), runtime.GOOS+"/"+runtime.GOARCH) {
		t.Fatalf("version lacks platform identity: %q", out.String())
	}
	out.Reset()
	stderr.Reset()
	if code := RunCLI(context.Background(), []string{"--help", "--ai-review"}, strings.NewReader(""), &out, &stderr); code != 2 || out.Len() != 0 {
		t.Fatalf("unsupported flag must take precedence over help: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}

func TestNonInteractiveAndPromptInputFailuresStopBeforePreparation(t *testing.T) {
	cases := []struct {
		args  []string
		input string
	}{
		{[]string{"--non-interactive"}, ""},
		{[]string{"--full", "--domain", "example.test", "--non-interactive"}, ""},
		{[]string{}, ""},
	}
	for _, tc := range cases {
		var out, stderr bytes.Buffer
		if code := RunCLI(context.Background(), tc.args, strings.NewReader(tc.input), &out, &stderr); code != 2 {
			t.Errorf("RunCLI(%q) exit=%d, want 2; stdout=%q stderr=%q", tc.args, code, out.String(), stderr.String())
		}
	}
}

func TestInteractiveInputsAreBoundedAndRequireExactAuthorization(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := RunCLI(context.Background(), []string{"--full"}, strings.NewReader("example.test\nno\n"), &out, &stderr); code != 2 {
		t.Fatalf("unconfirmed active profile exit=%d; stderr=%q", code, stderr.String())
	}
	tooLong := strings.Repeat("a", 4097) + "\n"
	out.Reset()
	stderr.Reset()
	if code := RunCLI(context.Background(), nil, strings.NewReader(tooLong), &out, &stderr); code != 2 || !strings.Contains(stderr.String(), "cannot read target") {
		t.Fatalf("oversized prompt line should fail locally: exit=%d stderr=%q", code, stderr.String())
	}
}

func TestPromptReaderPreservesBufferedLinesAndRejectsInvalidText(t *testing.T) {
	var out bytes.Buffer
	prompts := newPromptReader(strings.NewReader("example.test\nAUTHORIZE\n"), &out)
	first, err := prompts.line(context.Background(), "Target: ")
	if err != nil || first != "example.test" {
		t.Fatalf("first prompt = %q, %v", first, err)
	}
	second, err := prompts.line(context.Background(), "Confirm: ")
	if err != nil || second != "AUTHORIZE" {
		t.Fatalf("second prompt lost buffered input: %q, %v", second, err)
	}
	if got := out.String(); !strings.Contains(got, "Target: ") || !strings.Contains(got, "Confirm: ") {
		t.Fatalf("prompts were not written: %q", got)
	}

	for _, input := range [][]byte{[]byte("bad\x00value\n"), {0xff, '\n'}} {
		reader := newPromptReader(bytes.NewReader(input), &out)
		if _, err := reader.line(context.Background(), ""); err == nil {
			t.Errorf("invalid text %q should be rejected, got %v", input, err)
		}
	}
}

type notifyWriter struct {
	once  sync.Once
	wrote chan struct{}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.wrote) })
	return len(p), nil
}

func TestRunCLICancellationInterruptsClosablePromptInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	prompts := &notifyWriter{wrote: make(chan struct{})}
	result := make(chan int, 1)
	go func() {
		result <- RunCLI(ctx, nil, reader, prompts, io.Discard)
	}()

	select {
	case <-prompts.wrote:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not begin its domain prompt")
	}
	select {
	case code := <-result:
		if code != 130 {
			t.Fatalf("cancelled prompt exit = %d, want 130", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt the closable prompt input")
	}
}
