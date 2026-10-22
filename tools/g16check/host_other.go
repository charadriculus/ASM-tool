//go:build !windows

package main

func windowsHostFacts() (string, bool, error) { return "", false, nil }
func checkLocalWindowsPath(string) error      { return nil }
