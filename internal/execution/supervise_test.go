//go:build !windows

package execution

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeChild struct {
	mu       sync.Mutex
	done     bool
	pollErr  error
	killErr  error
	closeErr error
	writers  []*os.File
}

func (p *fakeChild) terminateTree() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.killErr == nil {
		p.done = true
	}
	if p.killErr == nil {
		for _, w := range p.writers {
			_ = w.Close()
		}
		p.writers = nil
	}
	return p.killErr
}
func (p *fakeChild) pollRoot() (bool, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pollErr != nil {
		err := p.pollErr
		p.pollErr = nil
		return false, -1, err
	}
	if p.done {
		return true, 0, nil
	}
	return false, -1, nil
}
func (p *fakeChild) closeHandles() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, w := range p.writers {
		_ = w.Close()
	}
	p.writers = nil
	return p.closeErr
}

func fakeProcessIO(t *testing.T, child *fakeChild, stdout string) processIO {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(int(outR.Fd()), true); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(int(errR.Fd()), true); err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		if _, err := io.WriteString(outW, stdout); err != nil {
			t.Fatal(err)
		}
	}
	child.writers = append(child.writers, outW, errW)
	t.Cleanup(func() {
		_ = outR.Close()
		_ = errR.Close()
		_ = outW.Close()
		_ = errW.Close()
	})
	return processIO{process: child, stdout: outR, stderr: errR}
}

func testOptions() Options {
	return Options{Timeout: time.Second, MaxOutputBytes: 1024, TailBytes: 128, MaxLineBytes: 128}
}

func TestSupervisorJoinsFirstCallbackAndTerminationErrorsAndSuppressesLaterRows(t *testing.T) {
	callbackErr := errors.New("callback failed")
	killErr := errors.New("tree termination failed")
	child := &fakeChild{killErr: killErr}
	var callbacks int
	options := testOptions()
	options.OnStdoutLine = func(context.Context, string) error {
		callbacks++
		return callbackErr
	}
	_, err := superviseProcess(context.Background(), []string{"helper"}, options, fakeProcessIO(t, child, "first\nsecond\n"), time.Now())
	if !errors.Is(err, callbackErr) || !errors.Is(err, killErr) || callbacks != 1 {
		t.Fatalf("errors/callbacks = %v/%d", err, callbacks)
	}
}

func TestSupervisorJoinsPollAndCloseFailures(t *testing.T) {
	pollErr := errors.New("root poll failed")
	closeErr := errors.New("handle close failed")
	child := &fakeChild{pollErr: pollErr, closeErr: closeErr}
	_, err := superviseProcess(context.Background(), []string{"helper"}, testOptions(), fakeProcessIO(t, child, "partial"), time.Now())
	if !errors.Is(err, pollErr) || !errors.Is(err, closeErr) {
		t.Fatalf("cleanup errors were lost: %v", err)
	}
}

func TestSupervisorBoundsCleanupWhenRootNeverStops(t *testing.T) {
	child := &fakeChild{killErr: errors.New("forced termination failed")}
	start := time.Now()
	options := testOptions()
	options.OnStdoutLine = func(context.Context, string) error { return errors.New("force cleanup") }
	result, err := superviseProcess(context.Background(), []string{"helper"}, options, fakeProcessIO(t, child, "partial-output\n"), start)
	if err == nil || !errors.Is(err, child.killErr) || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("cleanup deadline evidence missing: %v", err)
	}
	if time.Since(start) > cleanupBudget+time.Second || result.Stdout != "partial-output\n" {
		t.Fatalf("cleanup was unbounded or partial output lost: duration=%v result=%+v", time.Since(start), result)
	}
}
