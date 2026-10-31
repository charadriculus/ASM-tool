//go:build !windows

package execution

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeArtifactPathRejectsSymlinkEscapeAndTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(root, "link")); e != nil {
		t.Skip(e)
	}
	if _, e := SafeArtifactPath(root, "link/out.json"); e == nil {
		t.Fatal("accepted symlink escape")
	}
	if _, e := SafeArtifactPath(root, "a/../out.json"); e == nil {
		t.Fatal("accepted parent component")
	}
	if _, e := SafeArtifactPath(root, ".hidden/out.json"); e == nil {
		t.Fatal("accepted hidden path")
	}
	if p, e := SafeArtifactPath(root, "clean/out.json"); e != nil || p != filepath.Join(root, "clean", "out.json") {
		t.Fatalf("safe path=%s err=%v", p, e)
	}
}
