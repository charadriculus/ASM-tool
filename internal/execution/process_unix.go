//go:build !windows

package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"asmtool/internal/platform"
)

type unixProcess struct {
	cmd      *exec.Cmd
	stdout   *os.File
	stderr   *os.File
	wait     chan error
	waitErr  error
	rootDone bool
}

func launchProcess(ctx context.Context, tool platform.Tool, argv []string, tmp string, stdin *os.File) (processIO, error) {
	if err := ctx.Err(); err != nil {
		return processIO{}, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = filepath.Dir(tool.Path())
	cmd.Env = []string{"HOME=" + tmp, "TMPDIR=" + tmp, "TMP=" + tmp, "TEMP=" + tmp, "LC_ALL=C", "LANG=C"}
	stdout, stdoutChild, err := os.Pipe()
	if err != nil {
		return processIO{}, err
	}
	stderr, stderrChild, err := os.Pipe()
	if err != nil {
		for _, f := range []*os.File{stdout, stdoutChild} {
			_ = f.Close()
		}
		return processIO{}, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdoutChild, stderrChild
	if err := ctx.Err(); err != nil {
		for _, f := range []*os.File{stdout, stdoutChild, stderr, stderrChild} {
			_ = f.Close()
		}
		return processIO{}, err
	}
	for _, f := range []*os.File{stdout, stderr} {
		if err := syscall.SetNonblock(int(f.Fd()), true); err != nil {
			for _, owned := range []*os.File{stdout, stdoutChild, stderr, stderrChild} {
				_ = owned.Close()
			}
			return processIO{}, fmt.Errorf("set child output pipe nonblocking: %w", err)
		}
	}
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{stdout, stdoutChild, stderr, stderrChild} {
			_ = f.Close()
		}
		return processIO{}, err
	}
	_ = stdoutChild.Close()
	_ = stderrChild.Close()
	p := &unixProcess{cmd: cmd, stdout: stdout, stderr: stderr, wait: make(chan error, 1)}
	go func() { p.wait <- cmd.Wait() }()
	return processIO{process: p, stdout: stdout, stderr: stderr}, nil
}

func newPipeReader(f *os.File) func([]byte, <-chan struct{}) (int, error) {
	fd := int(f.Fd()) // Obtain once: Fd changes Go's nonblocking flag.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return func([]byte, <-chan struct{}) (int, error) { return 0, err }
	}
	return func(buf []byte, stop <-chan struct{}) (int, error) {
		for {
			select {
			case <-stop:
				return 0, os.ErrClosed
			default:
			}
			n, err := syscall.Read(fd, buf)
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				timer := time.NewTimer(10 * time.Millisecond)
				select {
				case <-stop:
					timer.Stop()
					return 0, os.ErrClosed
				case <-timer.C:
				}
				continue
			}
			if err != nil {
				return n, err
			}
			if n == 0 {
				return 0, io.EOF
			}
			runtime.KeepAlive(f)
			return n, nil
		}
	}
}

func (p *unixProcess) terminateTree() error {
	err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (p *unixProcess) pollRoot() (bool, int, error) {
	if p.rootDone {
		if p.cmd.ProcessState == nil {
			return true, -1, errors.New("missing process state after wait")
		}
		return true, p.cmd.ProcessState.ExitCode(), nil
	}
	select {
	case p.waitErr = <-p.wait:
		p.rootDone = true
		if p.cmd.ProcessState == nil {
			return true, -1, errors.Join(errors.New("missing process state after wait"), p.waitErr)
		}
		return true, p.cmd.ProcessState.ExitCode(), nil
	default:
		return false, -1, nil
	}
}

func (p *unixProcess) closeHandles() error {
	var errs error
	for _, f := range []*os.File{p.stdout, p.stderr} {
		if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = errors.Join(errs, err)
		}
	}
	if !p.rootDone {
		return errors.Join(errs, fmt.Errorf("root process did not stop within cleanup budget"))
	}
	return errs
}
