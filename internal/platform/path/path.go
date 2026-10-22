// Package path owns writable user paths; it does not resolve executables or probe the filesystem.
package path

import (
	"os"
	"path/filepath"
	"runtime"
)

func UserDataRoot() (string, error) { return userDataRoot(runtime.GOOS, os.Getenv, os.UserHomeDir) }
func userDataRoot(goos string, getenv func(string) string, home func() (string, error)) (string, error) {
	root := getenv("LOCALAPPDATA")
	if root == "" {
		h, e := home()
		if e != nil {
			return "", e
		}
		root = filepath.Join(h, "AppData", "Local")
	}
	return filepath.Join(root, "ASM Tool"), nil
}
func DefaultOutputRoot() (string, error) {
	return defaultOutputRoot(runtime.GOOS, os.Getenv, os.UserHomeDir)
}
func defaultOutputRoot(goos string, getenv func(string) string, home func() (string, error)) (string, error) {
	if goos != "windows" {
		return "runs", nil
	}
	root, e := userDataRoot(goos, getenv, home)
	if e != nil {
		return "", e
	}
	return filepath.Join(root, "runs"), nil
}
func SettingsPath() (string, error) { return settingsPath(runtime.GOOS, os.Getenv, os.UserHomeDir) }
func settingsPath(goos string, getenv func(string) string, home func() (string, error)) (string, error) {
	if goos == "windows" {
		r, e := userDataRoot(goos, getenv, home)
		if e != nil {
			return "", e
		}
		return filepath.Join(r, "config", "settings.yml"), nil
	}
	root := getenv("XDG_CONFIG_HOME")
	if root == "" {
		h, e := home()
		if e != nil {
			return "", e
		}
		root = filepath.Join(h, ".config")
	}
	return filepath.Join(root, "asm-tool", "settings.yml"), nil
}
