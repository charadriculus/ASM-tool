//go:build linux

package storage

import "os"

func publishSnapshot(source, destination string) error {
	// link(2) is atomic and fails with EEXIST; both paths are staged on the
	// destination filesystem.
	return os.Link(source, destination)
}
