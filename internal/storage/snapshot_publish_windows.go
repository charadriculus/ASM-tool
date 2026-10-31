//go:build windows

package storage

import (
	"syscall"
	"unsafe"
)

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func publishSnapshot(source, destination string) error {
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// Flags=0 disallows replacement and cross-volume copy.
	r, _, callErr := moveFileExW.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 0)
	if r == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return syscall.EINVAL
	}
	return nil
}
