//go:build windows

package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"asmtool/internal/platform"
	"golang.org/x/sys/windows"
)

type winProcess struct {
	info     windows.ProcessInformation
	job      windows.Handle
	assigned bool
}

func (p *winProcess) terminateTree() error {
	if p.job == 0 || !p.assigned {
		return errors.New("process job unavailable or process not assigned")
	}
	return windows.TerminateJobObject(p.job, 1)
}
func (p *winProcess) pollRoot() (bool, int, error) {
	v, e := windows.WaitForSingleObject(p.info.Process, 0)
	if e != nil {
		return false, -1, e
	}
	if v == 0x00000102 {
		return false, -1, nil
	}
	if v != windows.WAIT_OBJECT_0 {
		return false, -1, fmt.Errorf("unexpected process wait result %d", v)
	}
	var code uint32
	if e = windows.GetExitCodeProcess(p.info.Process, &code); e != nil {
		return false, -1, e
	}
	return true, int(int32(code)), nil
}
func (p *winProcess) closeHandles() error {
	var errs error
	if p.job != 0 {
		if e := windows.CloseHandle(p.job); e != nil {
			errs = errors.Join(errs, e)
		}
		p.job = 0
	}
	if p.info.Thread != 0 {
		if e := windows.CloseHandle(p.info.Thread); e != nil {
			errs = errors.Join(errs, e)
		}
		p.info.Thread = 0
	}
	if p.info.Process != 0 {
		if e := windows.CloseHandle(p.info.Process); e != nil {
			errs = errors.Join(errs, e)
		}
		p.info.Process = 0
	}
	return errs
}

func createPipePair() (windows.Handle, windows.Handle, error) {
	var r, w windows.Handle
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if e := windows.CreatePipe(&r, &w, sa, 0); e != nil {
		return 0, 0, e
	}
	return r, w, nil
}

func launchProcess(ctx context.Context, tool platform.Tool, args []string, tmp string, stdin *os.File) (processIO, error) {
	if err := ctx.Err(); err != nil {
		return processIO{}, err
	}
	var pi windows.ProcessInformation
	var inR windows.Handle
	e := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(stdin.Fd()), windows.CurrentProcess(), &inR, 0, true, windows.DUPLICATE_SAME_ACCESS)
	if e != nil {
		return processIO{}, fmt.Errorf("duplicate child stdin handle: %w", e)
	}
	outR, outW, e := createPipePair()
	if e != nil {
		_ = windows.CloseHandle(inR)
		return processIO{}, e
	}
	errR, errW, e := createPipePair()
	if e != nil {
		for _, h := range []windows.Handle{inR, outR, outW} {
			windows.CloseHandle(h)
		}
		return processIO{}, e
	}
	cleanup := func() {
		for _, h := range []windows.Handle{inR, outR, outW, errR, errW} {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
		}
	}
	for _, h := range []windows.Handle{outR, errR} {
		if e = windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, 0); e != nil {
			cleanup()
			return processIO{}, e
		}
	}
	attrs, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		cleanup()
		return processIO{}, e
	}
	defer attrs.Delete()
	handles := []windows.Handle{inR, outW, errW}
	if e = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); e != nil {
		cleanup()
		return processIO{}, e
	}
	sysdir, e := windows.GetSystemDirectory()
	if e != nil {
		cleanup()
		return processIO{}, e
	}
	systemRoot := filepath.Dir(sysdir)
	searchDirs := append([]string{sysdir, filepath.Dir(tool.Path())}, tool.NativeDirectories()...)
	if e = validateWindowsSearchPaths(searchDirs); e != nil {
		cleanup()
		return processIO{}, e
	}
	env := map[string]string{"SystemRoot": systemRoot, "WINDIR": systemRoot, "PATH": strings.Join(searchDirs, ";"), "HOME": tmp, "TEMP": tmp, "TMP": tmp, "USERPROFILE": tmp, "LC_ALL": "C", "LANG": "C"}
	envBlock, e := windowsEnvBlock(env)
	if e != nil {
		cleanup()
		return processIO{}, e
	}
	argvLine := strings.Builder{}
	for i, arg := range args {
		if i > 0 {
			argvLine.WriteByte(' ')
		}
		argvLine.WriteString(windows.EscapeArg(arg))
	}
	line, e := windows.UTF16PtrFromString(argvLine.String())
	if e != nil {
		cleanup()
		return processIO{}, e
	}
	app, e := windows.UTF16PtrFromString(tool.Path())
	if e != nil {
		cleanup()
		return processIO{}, e
	}
	cwd, e := windows.UTF16PtrFromString(filepath.Dir(tool.Path()))
	if e != nil {
		cleanup()
		return processIO{}, e
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: inR, StdOutput: outW, StdErr: errW}, ProcThreadAttributeList: attrs.List()}
	if e = windows.CreateProcess(app, line, nil, nil, true, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT, &envBlock[0], cwd, &si.StartupInfo, &pi); e != nil {
		cleanup()
		return processIO{}, e
	}
	child := &winProcess{info: pi}
	dropChildEnds := func() {
		for _, pair := range []*windows.Handle{&inR, &outW, &errW} {
			if *pair != 0 {
				_ = windows.CloseHandle(*pair)
				*pair = 0
			}
		}
	}
	stopSuspended := func(cause error) error {
		var errs error = cause
		if child.assigned {
			if err := child.terminateTree(); err != nil {
				errs = errors.Join(errs, err)
			}
		} else if err := windows.TerminateProcess(pi.Process, 1); err != nil {
			errs = errors.Join(errs, err)
		}
		dropChildEnds()
		for _, h := range []windows.Handle{inR, outR, outW, errR, errW} {
			if h != 0 {
				if err := windows.CloseHandle(h); err != nil {
					errs = errors.Join(errs, err)
				}
			}
		}
		if pi.Thread != 0 {
			if err := windows.CloseHandle(pi.Thread); err != nil {
				errs = errors.Join(errs, err)
			}
		}
		if pi.Process != 0 {
			if err := windows.CloseHandle(pi.Process); err != nil {
				errs = errors.Join(errs, err)
			}
		}
		if child.job != 0 {
			if err := windows.CloseHandle(child.job); err != nil {
				errs = errors.Join(errs, err)
			}
		}
		return errs
	}
	if err := ctx.Err(); err != nil {
		return processIO{}, stopSuspended(err)
	}
	dropChildEnds()
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return processIO{}, stopSuspended(e)
	}
	child.job = job
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return processIO{}, stopSuspended(e)
	}
	if e = windows.AssignProcessToJobObject(job, pi.Process); e != nil {
		return processIO{}, stopSuspended(e)
	}
	child.assigned = true
	if err := ctx.Err(); err != nil {
		return processIO{}, stopSuspended(err)
	}
	if _, e = windows.ResumeThread(pi.Thread); e != nil {
		return processIO{}, stopSuspended(e)
	}
	stdout := os.NewFile(uintptr(outR), "child-stdout")
	stderr := os.NewFile(uintptr(errR), "child-stderr")
	return processIO{process: child, stdout: stdout, stderr: stderr}, nil
}
