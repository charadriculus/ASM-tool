//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
	"syscall"
)

func isReparsePoint(path string) bool {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return true
	}
	a, e := windows.GetFileAttributes(p)
	return e == nil && a&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
