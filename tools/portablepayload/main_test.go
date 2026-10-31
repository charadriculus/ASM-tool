package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"asmtool/internal/platform"
)

func TestStageArchiveAndOfflineVerificationAreReproducible(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture sources use the approved Linux system DejaVu font paths")
	}
	base := t.TempDir()
	lock, appHash := createValidLock(t, base)
	staged := filepath.Join(base, "bundle source")
	result, err := stage(lock, staged)
	if err != nil {
		t.Fatal(err)
	}
	app := []byte("synthetic app executable; never executed")
	if err := os.WriteFile(filepath.Join(staged, "asm-tool"), app, 0755); err != nil {
		t.Fatal(err)
	}
	appHash = hashString(app)
	files, platform, err := verifyRoot(staged, appHash, result.BundleSHA256, result.ProvenanceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if platform != "linux/amd64" || len(files) != 9 {
		t.Fatalf("verified platform=%q files=%d", platform, len(files))
	}
	first, second := filepath.Join(base, "first.zip"), filepath.Join(base, "second.zip")
	if err := writeArchive(staged, first, files); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(staged, second, files); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(a, b) {
		t.Fatal("same reviewed tree produced different archive bytes")
	}
	if err := os.WriteFile(filepath.Join(staged, "unlisted.bin"), []byte("surprise"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyRoot(staged, appHash, result.BundleSHA256, result.ProvenanceSHA256); err == nil || !strings.Contains(err.Error(), "unlisted") {
		t.Fatalf("verify unlisted file: %v", err)
	}
}

func TestStageRejectsSourceHashMismatchAndPreservesExistingOutput(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "font.bin")
	if err := os.WriteFile(source, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	lock := payloadLock{SchemaVersion: 1, Platform: "linux/amd64", Sources: []sourceLock{{ID: "font", Path: source, SHA256: strings.Repeat("0", 64), Version: "fixture", License: "fixture"}}, Files: []fileLock{{Path: "payload/fonts/dejavu/DejaVuSans.ttf", Source: "font", SHA256: strings.Repeat("0", 64), Size: 7}}}
	lockPath := writeLock(t, base, lock)
	out := filepath.Join(base, "existing")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(out, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stage(lockPath, out); err == nil || !strings.Contains(err.Error(), "output already exists") {
		t.Fatalf("stage error=%v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
		t.Fatalf("previous output changed: %q, %v", data, err)
	}
}

func TestStageRejectsUnsafeAndDuplicateArchiveMembers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members []string
		want    string
	}{
		{"traversal", []string{"../escape"}, "unsafe archive member"},
		{"duplicate", []string{"bin/typst", "bin/typst"}, "duplicate or case-colliding"},
		{"case collision", []string{"bin/typst", "BIN/TYPST"}, "duplicate or case-colliding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			archive := filepath.Join(base, "source.zip")
			f, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			zw := zip.NewWriter(f)
			for _, name := range tc.members {
				w, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = w.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			hash, err := hashFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			lock := payloadLock{SchemaVersion: 1, Platform: "linux/amd64", Sources: []sourceLock{{ID: "src", Path: archive, SHA256: hash, Archive: true, Version: "fixture", License: "fixture"}}, Files: []fileLock{{Path: "payload/bin/typst", Source: "src", Member: "bin/typst", SHA256: hashString([]byte("x")), Size: 1, Executable: true}}}
			_, err = stage(writeLock(t, base, lock), filepath.Join(base, "out"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage error=%v; want %q", err, tc.want)
			}
		})
	}
}

func createValidLock(t *testing.T, base string) (string, string) {
	t.Helper()
	lock := payloadLock{SchemaVersion: 1, Platform: "linux/amd64"}
	add := func(id, sourcePath, target, member string, archive bool, content []byte, executable bool) {
		t.Helper()
		src := sourceLock{ID: id, Path: sourcePath, SHA256: hashString(content), Archive: archive, Version: "source version recorded in lock", License: "license recorded in lock"}
		lock.Sources = append(lock.Sources, src)
		lock.Files = append(lock.Files, fileLock{Path: target, Source: id, Member: member, SHA256: hashString(content), Size: int64(len(content)), Executable: executable})
	}
	fontNames := []string{"DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans-Oblique.ttf", "DejaVuSans-BoldOblique.ttf"}
	fontDir := os.Getenv("ASM_PORTABLE_TEST_FONT_DIR")
	if fontDir == "" {
		fontDir = "/usr/share/fonts/truetype/dejavu"
	}
	for _, name := range fontNames {
		p := filepath.Join(fontDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Skipf("pinned font fixture unavailable: %v", err)
		}
		add("font_"+strings.ReplaceAll(strings.TrimSuffix(name, ".ttf"), "-", "_"), p, "payload/fonts/dejavu/"+name, "", false, b, false)
	}
	typst := []byte("synthetic pinned Typst fixture; never executed")
	typstPath := filepath.Join(base, "typst.fixture")
	if err := os.WriteFile(typstPath, typst, 0600); err != nil {
		t.Fatal(err)
	}
	add("typst", typstPath, "payload/bin/typst", "", false, typst, true)
	lock.Tools = []toolLock{{Name: "typst", Executable: "payload/bin/typst", Version: "0.15.1", Usage: "qualification-only", Capabilities: []string{"report rendering; integrity only"}, License: "fixture license metadata"}}
	lockPath := writeLock(t, base, lock)
	return lockPath, hashString([]byte("synthetic app executable; never executed"))
}

func writeLock(t *testing.T, base string, lock payloadLock) string {
	t.Helper()
	b, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(base, "reviewed-lock.json")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func hashString(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMetadataAnchorsAndStableArchiveModes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local reviewed font fixtures")
	}
	base := t.TempDir()
	lock, appHash := createValidLock(t, base)
	root := filepath.Join(base, "Unicode-отчёт")
	result, err := stage(lock, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asm-tool"), []byte("synthetic app executable; never executed"), 0755); err != nil {
		t.Fatal(err)
	}
	files, _, err := verifyRoot(root, appHash, result.BundleSHA256, result.ProvenanceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(base, "a.zip")
	if err := writeArchive(root, first, files); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "payload/fonts/dejavu/DejaVuSans.ttf"), 0600); err != nil {
		t.Fatal(err)
	}
	files, _, err = verifyRoot(root, appHash, result.BundleSHA256, result.ProvenanceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(base, "b.zip")
	if err := writeArchive(root, second, files); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if !equalBytes(a, b) {
		t.Fatal("chmod changed archive bytes")
	}
	if err := writeArchive(root, first, files); err == nil {
		t.Fatal("existing archive overwritten")
	}
	after, _ := os.ReadFile(first)
	if !equalBytes(a, after) {
		t.Fatal("previous archive changed")
	}
	for _, name := range []string{"payload-provenance.json", "README.md"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(root, name)
			before, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			mutated := append([]byte(nil), before...)
			mutated[0] ^= 1
			if err := os.WriteFile(p, mutated, 0644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifyRoot(root, appHash, result.BundleSHA256, result.ProvenanceSHA256); err == nil {
				t.Fatal("changed metadata accepted")
			}
			if err := os.WriteFile(p, before, 0644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBoundedReadsAndSymlinkAncestors(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "data")
	if err := os.WriteFile(p, []byte("123456"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(p, 5); err == nil {
		t.Fatal("unbounded read accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := regularNoLink(filepath.Join(link, "data")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

func TestSourceHashMismatchLeavesNoOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local reviewed font fixtures")
	}
	base := t.TempDir()
	lockPath, _ := createValidLock(t, base)
	var lock payloadLock
	b, _ := os.ReadFile(lockPath)
	if err := json.Unmarshal(b, &lock); err != nil {
		t.Fatal(err)
	}
	lock.Sources[0].SHA256 = strings.Repeat("0", 64)
	writeLock(t, base, lock)
	out := filepath.Join(base, "not-created")
	if _, err := stage(lockPath, out); err == nil {
		t.Fatal("wrong source hash accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed stage published output")
	}
}

func TestIntegrityMutationAndArchiveCopyRecheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local reviewed font fixtures")
	}
	base := t.TempDir()
	lock, appHash := createValidLock(t, base)
	root := filepath.Join(base, "root")
	result, err := stage(lock, root)
	if err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(root, "asm-tool")
	if err := os.WriteFile(app, []byte("synthetic app executable; never executed"), 0755); err != nil {
		t.Fatal(err)
	}
	files, _, err := verifyRoot(root, appHash, result.BundleSHA256, result.ProvenanceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{app, filepath.Join(root, "payload/bin/typst"), filepath.Join(root, "payload/bundle.json")} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		mutated := append([]byte(nil), b...)
		mutated[0] ^= 1
		if err := os.WriteFile(p, mutated, 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifyRoot(root, appHash, result.BundleSHA256, result.ProvenanceSHA256); err == nil {
			t.Fatalf("mutation accepted: %s", p)
		}
		archive := filepath.Join(base, "mutation.zip")
		if err := writeArchive(root, archive, files); err == nil {
			t.Fatalf("copy did not recheck %s", p)
		}
		if _, err := os.Stat(archive); !os.IsNotExist(err) {
			t.Fatal("failed copy published archive")
		}
		if err := os.WriteFile(p, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUndeclaredExecutableRejected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local reviewed font fixtures")
	}
	base := t.TempDir()
	p, _ := createValidLock(t, base)
	b, _ := os.ReadFile(p)
	var lock payloadLock
	if err := json.Unmarshal(b, &lock); err != nil {
		t.Fatal(err)
	}
	lock.Files[0].Executable = true
	writeLock(t, base, lock)
	if _, err := stage(p, filepath.Join(base, "out")); err == nil || !strings.Contains(err.Error(), "not a declared tool") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestStageRejectsNmapLockEntries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*payloadLock)
		want   string
	}{
		{
			name:   "payload file",
			mutate: func(lock *payloadLock) { lock.Files[0].Path = "payload/bin/nmap/nmap.exe" },
			want:   "Nmap payload path",
		},
		{
			name: "tool",
			mutate: func(lock *payloadLock) {
				lock.Tools = append(lock.Tools, toolLock{Name: "nmap", Executable: "payload/bin/nmap/nmap.exe", Version: "fixture", Usage: "qualification-only", Capabilities: []string{"fixture"}, License: "fixture"})
			},
			want: "Nmap is not supported",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			lockPath, _ := createValidLock(t, base)
			encoded, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			var lock payloadLock
			if err := json.Unmarshal(encoded, &lock); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&lock)
			lockPath = writeLock(t, base, lock)
			if _, err := stage(lockPath, filepath.Join(base, "out")); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage error=%v; want %q", err, tc.want)
			}
		})
	}
}

func TestStageRequiresLinuxLoaderAsOnlyAdditionalExecutable(t *testing.T) {
	base := t.TempDir()
	lockPath, _ := createValidLock(t, base)
	encoded, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var lock payloadLock
	if err := json.Unmarshal(encoded, &lock); err != nil {
		t.Fatal(err)
	}
	add := func(id, rel string, body []byte, executable bool) {
		t.Helper()
		source := filepath.Join(base, id+".fixture")
		if err := os.WriteFile(source, body, 0600); err != nil {
			t.Fatal(err)
		}
		lock.Sources = append(lock.Sources, sourceLock{ID: id, Path: source, SHA256: hashString(body), Version: "fixture", License: "fixture"})
		lock.Files = append(lock.Files, fileLock{Path: rel, Source: id, SHA256: hashString(body), Size: int64(len(body)), Executable: executable})
	}
	add("loader", "payload/bin/linux-runtime/ld-linux-x86-64.so.2", []byte("loader fixture"), false)
	add("libc", "payload/bin/linux-runtime/libc.so.6", []byte("libc fixture"), false)
	add("subfaster", "payload/bin/subfaster", []byte("Subfaster fixture"), true)
	lock.Tools = append(lock.Tools, toolLock{Name: "subfaster", Executable: "payload/bin/subfaster", Version: "2.18.0", Usage: "qualification-only", Capabilities: []string{"passive"}, License: "fixture"})
	lock.LinuxRuntime = &platform.LinuxRuntimeSpec{Loader: "bin/linux-runtime/ld-linux-x86-64.so.2", LibraryDir: "bin/linux-runtime", Tools: []string{"subfaster"}}
	lockPath = writeLock(t, base, lock)
	if _, err := stage(lockPath, filepath.Join(base, "out")); err == nil || !strings.Contains(err.Error(), "loader must be declared executable") {
		t.Fatalf("stage error=%v", err)
	}
}
