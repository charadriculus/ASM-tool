package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"asmtool/internal/platform"
)

const cleanupBudget = 2 * time.Second

type childProcess interface {
	terminateTree() error
	pollRoot() (done bool, exitCode int, err error)
	closeHandles() error
}

type processIO struct {
	process childProcess
	stdout  *os.File
	stderr  *os.File
}

type pipeEvent struct {
	stream string
	data   []byte
	err    error
}

func runProcess(ctx context.Context, tool platform.Tool, argv []string, opts Options) (Result, error) {
	started := time.Now()
	result := Result{Args: RedactArgs(argv), ExitCode: -1, StartedAt: started, Artifact: opts.StdoutArtifact}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	tmp, err := os.MkdirTemp("", "asm-tool-child-")
	if err != nil {
		return result, err
	}
	input, err := os.CreateTemp(tmp, "stdin-")
	if err != nil {
		return result, errors.Join(err, os.RemoveAll(tmp))
	}
	if err = input.Chmod(0600); err == nil {
		_, err = input.Write(opts.Stdin)
	}
	if err == nil {
		_, err = input.Seek(0, io.SeekStart)
	}
	if err != nil {
		return result, errors.Join(err, input.Close(), os.RemoveAll(tmp))
	}
	child, launchErr := launchProcess(ctx, tool, argv, tmp, input)
	closeInputErr := input.Close()
	if launchErr != nil {
		return result, errors.Join(launchErr, closeInputErr, os.RemoveAll(tmp))
	}
	result, runErr := superviseProcess(ctx, argv, opts, child, started)
	removeErr := os.RemoveAll(tmp)
	if err := errors.Join(closeInputErr, removeErr); err != nil {
		runErr = errors.Join(runErr, err)
	}
	if runErr != nil {
		return result, &ProcessError{Err: runErr, Result: result}
	}
	return result, nil
}

func superviseProcess(ctx context.Context, argv []string, opts Options, child processIO, started time.Time) (Result, error) {
	result := Result{Args: RedactArgs(argv), ExitCode: -1, StartedAt: started, Artifact: opts.StdoutArtifact}
	events := make(chan pipeEvent, 16)
	stopReaders := make(chan struct{})
	var readerWG sync.WaitGroup
	read := func(stream string, f *os.File) {
		defer readerWG.Done()
		pipeRead := newPipeReader(f)
		buf := make([]byte, 16*1024)
		for {
			n, e := pipeRead(buf, stopReaders)
			if n > 0 {
				piece := append([]byte(nil), buf[:n]...)
				select {
				case events <- pipeEvent{stream: stream, data: piece}:
				case <-stopReaders:
					return
				}
			}
			if e != nil {
				select {
				case events <- pipeEvent{stream: stream, err: e}:
				case <-stopReaders:
				}
				return
			}
		}
	}
	readerWG.Add(2)
	go read("stdout", child.stdout)
	go read("stderr", child.stderr)

	out := make([]byte, 0, min64(opts.MaxOutputBytes, 32768))
	errout := make([]byte, 0, min64(opts.MaxOutputBytes, 32768))
	var total int64
	var lineBuf []byte
	var runErr error
	var cleanupErr error
	var code = -1
	var rootDone bool
	var closedStreams int
	var terminal bool
	var timedOut bool
	var outputExceeded bool
	var cleanupStarted bool
	var cleanupDeadline time.Time
	var ticker = time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var cleanupTimer *time.Timer
	var cleanupC <-chan time.Time
	ctxDone := ctx.Done()
	cleanupExpired := false

	triggerCleanup := func(cause error) {
		if cause != nil && !terminal {
			terminal = true
			runErr = errors.Join(runErr, cause)
		}
		if cleanupStarted {
			return
		}
		cleanupStarted = true
		cleanupDeadline = time.Now().Add(cleanupBudget)
		cleanupTimer = time.NewTimer(cleanupBudget)
		cleanupC = cleanupTimer.C
		if e := child.process.terminateTree(); e != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("terminate child tree: %w", e))
		}
	}
	for {
		if rootDone && closedStreams == 2 {
			break
		}
		select {
		case <-ctxDone:
			timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
			triggerCleanup(ctx.Err())
			ctxDone = nil
		case <-cleanupC:
			cleanupErr = errors.Join(cleanupErr, errors.New("child cleanup deadline exceeded"))
			cleanupC = nil
			cleanupExpired = true
		case ev := <-events:
			if ev.err != nil {
				closedStreams++
				if ev.err != io.EOF && !errors.Is(ev.err, os.ErrClosed) && !terminal {
					triggerCleanup(fmt.Errorf("read child %s: %w", ev.stream, ev.err))
				}
				continue
			}
			remaining := opts.MaxOutputBytes - total
			if remaining > 0 {
				keep := len(ev.data)
				if int64(keep) > remaining {
					keep = int(remaining)
				}
				if ev.stream == "stdout" {
					out = append(out, ev.data[:keep]...)
				} else {
					errout = append(errout, ev.data[:keep]...)
				}
			}
			total += int64(len(ev.data))
			if total > opts.MaxOutputBytes && !outputExceeded {
				outputExceeded = true
				triggerCleanup(errors.New("process output limit exceeded"))
			}
			if ev.stream == "stdout" && opts.OnStdoutLine != nil && !terminal {
				lineBuf = append(lineBuf, ev.data...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					lineBytes := lineBuf[:idx]
					if len(lineBytes) > opts.MaxLineBytes {
						triggerCleanup(errors.New("stdout line exceeds configured limit"))
						break
					}
					line := strings.TrimSuffix(string(lineBytes), "\r")
					lineBuf = append(lineBuf[:0], lineBuf[idx+1:]...)
					if err := opts.OnStdoutLine(ctx, line); err != nil {
						triggerCleanup(err)
						break
					}
				}
				if !terminal && len(lineBuf) > opts.MaxLineBytes {
					triggerCleanup(errors.New("stdout line exceeds configured limit"))
				}
			}
		case <-ticker.C:
			done, exit, e := child.process.pollRoot()
			if e != nil {
				triggerCleanup(fmt.Errorf("poll child process: %w", e))
			} else if done && !rootDone {
				rootDone = true
				code = exit
				triggerCleanup(nil) // Root exit still requires bounded descendant cleanup.
			}
		}
		if cleanupExpired {
			break
		}
		if cleanupStarted {
			if time.Now().After(cleanupDeadline) && cleanupC != nil {
				// Timer delivery and scheduler latency cannot extend the cleanup bound.
				cleanupErr = errors.Join(cleanupErr, errors.New("child cleanup deadline exceeded"))
				cleanupC = nil
				cleanupExpired = true
			}
		}
	}
	if cleanupTimer != nil {
		cleanupTimer.Stop()
	}
	if len(lineBuf) > 0 && opts.OnStdoutLine != nil && !terminal {
		if len(lineBuf) > opts.MaxLineBytes {
			triggerCleanup(errors.New("stdout line exceeds configured limit"))
		} else if err := opts.OnStdoutLine(ctx, string(lineBuf)); err != nil {
			triggerCleanup(err)
		}
	}
	close(stopReaders)
	readerWG.Wait()
	if err := child.stdout.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close child stdout: %w", err))
	}
	if err := child.stderr.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close child stderr: %w", err))
	}
	cleanupErr = errors.Join(cleanupErr, child.process.closeHandles())
	result.EndedAt = time.Now()
	result.ExitCode = code
	result.StdoutBytes = int64(len(out))
	result.StderrBytes = int64(len(errout))
	result.Stdout = tail(out, opts.TailBytes)
	result.Stderr = tail(errout, opts.TailBytes)
	result.TimedOut = timedOut
	result.OutputLimitExceeded = outputExceeded
	if err := writeArtifact(opts.StdoutArtifact, out); err != nil {
		runErr = errors.Join(runErr, err)
	} else if opts.StdoutArtifact != "" {
		result.ArtifactWritten = true
	}
	if cleanupErr != nil {
		runErr = errors.Join(runErr, cleanupErr)
	}
	if runErr != nil {
		return result, &ProcessError{Err: runErr, Result: result}
	}
	if code != 0 {
		return result, &ProcessError{Err: fmt.Errorf("child process exit=%d", code), Result: result}
	}
	return result, nil
}
