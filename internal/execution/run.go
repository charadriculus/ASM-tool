package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"asmtool/internal/platform"
)

type Options struct {
	Timeout        time.Duration
	MaxOutputBytes int64
	TailBytes      int
	MaxLineBytes   int
	Stdin          []byte
	ArtifactRoot   string
	StdoutArtifact string
	OnStdoutLine   func(context.Context, string) error
}
type Result struct {
	Args                          []string
	ExitCode                      int
	StartedAt, EndedAt            time.Time
	Stdout, Stderr                string
	StdoutBytes, StderrBytes      int64
	TimedOut, OutputLimitExceeded bool
	Artifact                      string
	ArtifactWritten               bool
}
type ProcessError struct {
	Err    error
	Result Result
}

func (e *ProcessError) Error() string { return e.Err.Error() }
func (e *ProcessError) Unwrap() error { return e.Err }

func Run(ctx context.Context, tool platform.Tool, args []string, opts Options) (Result, error) {
	if len(opts.Stdin) > 16<<20 {
		return Result{}, errors.New("process stdin exceeds 16 MiB")
	}
	if len(args) > 0 {
		if err := ValidateArgs(args); err != nil {
			return Result{}, err
		}
	}
	if ctx == nil {
		return Result{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if opts.MaxLineBytes <= 0 {
		opts.MaxLineBytes = 1 << 20
	}
	if opts.Timeout <= 0 || opts.MaxOutputBytes <= 0 || opts.TailBytes <= 0 || int64(opts.TailBytes) > opts.MaxOutputBytes {
		return Result{}, errors.New("invalid execution limits")
	}
	if opts.StdoutArtifact != "" {
		if opts.ArtifactRoot == "" {
			return Result{}, errors.New("stdout artifact requires a root directory")
		}
		path, e := SafeArtifactPath(opts.ArtifactRoot, opts.StdoutArtifact)
		if e != nil {
			return Result{}, e
		}
		opts.StdoutArtifact = path
	}
	if tool.Path() == "" {
		return Result{}, errors.New("invalid verified tool")
	}
	argv := tool.Command(args)
	if err := ValidateArgs(argv); err != nil {
		return Result{}, err
	}
	if err := tool.Verify(); err != nil {
		return Result{}, fmt.Errorf("verify tool bundle: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return runProcess(ctx, tool, argv, opts)
}

func writeArtifact(path string, b []byte) error {
	if path == "" {
		return nil
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, we := f.Write(b)
	ce := f.Close()
	if we != nil {
		_ = os.Remove(path)
		return we
	}
	if ce != nil {
		_ = os.Remove(path)
		return ce
	}
	return nil
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
func min64(a int64, b int) int {
	if a < int64(b) {
		return int(a)
	}
	return b
}

func windowsEnvBlock(m map[string]string) ([]uint16, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToUpper(keys[i]) < strings.ToUpper(keys[j]) })
	var b strings.Builder
	for _, k := range keys {
		if strings.ContainsAny(k, "=\x00") || strings.ContainsRune(m[k], 0) {
			return nil, fmt.Errorf("invalid environment entry")
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return utf16.Encode([]rune(b.String())), nil
}

func validateWindowsSearchPaths(dirs []string) error {
	for _, dir := range dirs {
		if strings.ContainsAny(dir, ";\x00") {
			return fmt.Errorf("unsafe Windows executable search path %q", dir)
		}
	}
	return nil
}
