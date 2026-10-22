//go:build windows

package execution

import (
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var peekNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")

func newPipeReader(f *os.File) func([]byte, <-chan struct{}) (int, error) {
	handle := windows.Handle(f.Fd())
	return func(buf []byte, stop <-chan struct{}) (int, error) {
		for {
			select {
			case <-stop:
				return 0, os.ErrClosed
			default:
			}
			var available uint32
			ok, _, callErr := peekNamedPipe.Call(uintptr(handle), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
			if ok == 0 {
				if callErr == windows.ERROR_BROKEN_PIPE {
					return 0, io.EOF
				}
				return 0, callErr
			}
			if available == 0 {
				timer := time.NewTimer(10 * time.Millisecond)
				select {
				case <-stop:
					timer.Stop()
					return 0, os.ErrClosed
				case <-timer.C:
				}
				continue
			}
			readBuf := buf
			if uint32(len(readBuf)) > available {
				readBuf = readBuf[:int(available)]
			}
			var n uint32
			if err := windows.ReadFile(handle, readBuf, &n, nil); err != nil {
				if err == windows.ERROR_BROKEN_PIPE {
					return 0, io.EOF
				}
				return int(n), err
			}
			if n == 0 {
				return 0, io.EOF
			}
			return int(n), nil
		}
	}
}
