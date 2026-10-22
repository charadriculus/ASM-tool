//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func isReparsePoint(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attrs, err := windows.GetFileAttributes(p)
	return err == nil && attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
