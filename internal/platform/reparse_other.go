//go:build !windows

package platform

func isReparsePoint(string) bool { return false }
