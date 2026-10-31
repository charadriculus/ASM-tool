//go:build !linux && !windows

package storage

import "errors"

func publishSnapshot(string, string) error {
	return errors.New("atomic no-clobber snapshot publication is unsupported on this platform")
}
