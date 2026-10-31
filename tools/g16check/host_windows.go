//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func windowsHostFacts() (string, bool, error) {
	runtimeVersion := windows.RtlGetVersion()
	version := fmt.Sprintf("Windows %d.%d build %d", runtimeVersion.MajorVersion, runtimeVersion.MinorVersion, runtimeVersion.BuildNumber)
	token := windows.GetCurrentProcessToken()
	elevated := token.IsElevated()
	if runtimeVersion.MajorVersion != 10 || runtimeVersion.BuildNumber < 19041 || runtimeVersion.BuildNumber > 19045 {
		return version, elevated, fmt.Errorf("Windows 10 x64 build 19041..19045 required; detected %s (Windows 11 is a separate qualification)", version)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return version, elevated, fmt.Errorf("inspect Windows user token: %w", err)
	}
	admin, err := windows.Token(0).IsMember(adminSID)
	if err != nil {
		return version, elevated, fmt.Errorf("inspect Windows user membership: %w", err)
	}
	if elevated || admin {
		return version, elevated, errors.New("Windows check kit requires a non-elevated token without enabled administrator membership")
	}
	return version, false, nil
}

func checkLocalWindowsPath(path string) error {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return errors.New("UNC/network paths are not accepted")
	}
	volume := filepath.VolumeName(path)
	if volume == "" || len(volume) < 2 || volume[1] != ':' {
		return errors.New("local drive-letter path required")
	}
	root := volume + `\`
	ptr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	typeID := windows.GetDriveType(ptr)
	if typeID != windows.DRIVE_FIXED && typeID != windows.DRIVE_REMOVABLE {
		return fmt.Errorf("local fixed/removable drive required (drive type %d)", typeID)
	}
	return nil
}
