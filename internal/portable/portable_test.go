package portable

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type bundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type bundleTool struct {
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Version    string `json:"version"`
}

type bundleManifest struct {
	SchemaVersion int          `json:"schema_version"`
	Platform      string       `json:"platform"`
	Files         []bundleFile `json:"files"`
	Tools         []bundleTool `json:"tools"`
}

type fixtureOptions struct {
	withSubfaster  bool
	withBrowser    bool
	browserVersion string
	nmapManifest   bool
	omitFont       string
	corruptFont    string
	extraFile      bool
	traversal      bool
	wrongPlatform  bool
	toolVersion    string
	wrongToolPath  bool
}

func makePayloadFixture(t *testing.T, options fixtureOptions) (root, manifestDigest string, fontPins map[string]string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "Отчёт with spaces", "payload")
	fontDir := filepath.Join(root, filepath.FromSlash(FontRelativePath))
	binDir := filepath.Join(root, BinRelativePath)
	if err := os.MkdirAll(fontDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}

	fontPins = make(map[string]string, len(requiredFonts))
	manifest := bundleManifest{SchemaVersion: 1, Platform: runtime.GOOS + "/" + runtime.GOARCH}
	if options.wrongPlatform {
		manifest.Platform = "other/arch"
	}
	addFile := func(rel string, content []byte) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		manifest.Files = append(manifest.Files, bundleFile{Path: rel, SHA256: hex.EncodeToString(digest[:])})
	}

	for name := range requiredFonts {
		body := []byte("portable fixture font: " + name)
		digest := sha256.Sum256(body)
		fontPins[name] = hex.EncodeToString(digest[:])
		if name == options.omitFont {
			continue
		}
		if name == options.corruptFont {
			body = []byte("changed fixture font: " + name)
		}
		addFile(filepath.ToSlash(filepath.Join(FontRelativePath, name)), body)
	}

	typstName := TypstName
	subfasterName := SubfasterName
	if runtime.GOOS == "windows" {
		typstName += ".exe"
		subfasterName += ".exe"
	}
	typstPath := filepath.ToSlash(filepath.Join(BinRelativePath, typstName))
	if options.wrongToolPath {
		typstPath = filepath.ToSlash(filepath.Join("elsewhere", typstName))
	}
	addFile(typstPath, []byte("synthetic Typst fixture; never executed"))
	manifest.Tools = append(manifest.Tools, bundleTool{Name: TypstName, Executable: typstPath, Version: TypstVersion})
	if options.withSubfaster {
		subPath := filepath.ToSlash(filepath.Join(BinRelativePath, subfasterName))
		addFile(subPath, []byte("synthetic Subfaster fixture; never executed"))
		version := "2.18.0"
		if options.toolVersion != "" {
			version = options.toolVersion
		}
		manifest.Tools = append(manifest.Tools, bundleTool{Name: SubfasterName, Executable: subPath, Version: version})
	}
	if options.withBrowser {
		version := options.browserVersion
		if version == "" {
			version = ObscuraVersion
		}
		for _, name := range []string{ObscuraName, ObscuraWorkerName} {
			rel := filepath.ToSlash(filepath.Join(BinRelativePath, name))
			if runtime.GOOS == "windows" {
				rel += ".exe"
			}
			addFile(rel, []byte("synthetic "+name+" fixture; never executed"))
			manifest.Tools = append(manifest.Tools, bundleTool{Name: name, Executable: rel, Version: version})
		}
	}
	if options.nmapManifest {
		name := "nmap"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		rel := "bin/" + name
		if runtime.GOOS == "windows" {
			rel = "bin/nmap/nmap.exe"
		}
		addFile(rel, []byte("synthetic Nmap fixture; never executed"))
		manifest.Tools = append(manifest.Tools, bundleTool{Name: "nmap", Executable: rel, Version: "fixture-only"})
	}
	if options.extraFile {
		if err := os.WriteFile(filepath.Join(root, "unexpected.txt"), []byte("unlisted"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if options.traversal {
		manifest.Files[0].Path = "../escape"
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifestBytes)
	return root, hex.EncodeToString(digest[:]), fontPins
}

func useFixtureFontPins(t *testing.T, pins map[string]string) {
	t.Helper()
	original := requiredFonts
	requiredFonts = pins
	t.Cleanup(func() { requiredFonts = original })
}

func TestVerifyPortablePayloadUnicodePathsAndOptionalSubfaster(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("portable fixtures target Linux/Windows amd64")
	}
	root, digest, pins := makePayloadFixture(t, fixtureOptions{withSubfaster: true})
	useFixtureFontPins(t, pins)

	payload, err := Verify(root, digest, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Bundle == nil || payload.Typst.Version() != TypstVersion || payload.Subfaster != nil {
		t.Fatalf("unexpected verified payload: %+v", payload)
	}
	if !strings.Contains(payload.FontDir, "Отчёт with spaces") || filepath.Base(payload.FontDir) != "dejavu" {
		t.Fatalf("Unicode payload path was not preserved: %q", payload.FontDir)
	}

	withSubfaster, err := Verify(root, digest, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if withSubfaster.Subfaster == nil || withSubfaster.Subfaster.Version() != "2.18.0" {
		t.Fatalf("expected verified Subfaster 2.18.0; got %#v", withSubfaster.Subfaster)
	}
}

func TestVerifyRejectsTrustAndPayloadFailures(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("portable fixtures target Linux/Windows amd64")
	}
	tests := []struct {
		name    string
		options fixtureOptions
		needSub bool
		badHash bool
		want    string
	}{
		{name: "wrong manifest digest", badHash: true, want: "manifest digest mismatch"},
		{name: "missing required font", options: fixtureOptions{omitFont: "DejaVuSans.ttf"}, want: "font DejaVuSans.ttf"},
		{name: "font digest differs from pinned font", options: fixtureOptions{corruptFont: "DejaVuSans.ttf"}, want: "font DejaVuSans.ttf SHA-256 mismatch"},
		{name: "unlisted entry", options: fixtureOptions{extraFile: true}, want: "unlisted"},
		{name: "traversal entry", options: fixtureOptions{traversal: true}, want: "invalid bundle component"},
		{name: "platform mismatch", options: fixtureOptions{wrongPlatform: true}, want: "unsupported or empty bundle manifest"},
		{name: "tool at unexpected path", options: fixtureOptions{wrongToolPath: true}, want: "portable typst must be stored"},
		{name: "Subfaster missing when requested", needSub: true, want: "portable Subfaster is unavailable"},
		{name: "wrong Subfaster version", options: fixtureOptions{withSubfaster: true, toolVersion: "2.17.0"}, needSub: true, want: "portable Subfaster version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, digest, pins := makePayloadFixture(t, tt.options)
			useFixtureFontPins(t, pins)
			if tt.badHash {
				digest = strings.Repeat("0", 64)
			}
			_, err := Verify(root, digest, tt.needSub, false)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Verify() error=%v; want text %q", err, tt.want)
			}
		})
	}
}

func TestVerifyRejectsBundleSymlink(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("portable fixtures target Linux/Windows amd64")
	}
	root, digest, pins := makePayloadFixture(t, fixtureOptions{})
	useFixtureFontPins(t, pins)
	target := filepath.Join(root, "fonts", "dejavu", "DejaVuSans.ttf")
	link := filepath.Join(root, "fonts", "dejavu", "linked.ttf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, err := Verify(root, digest, false, false); err == nil || !strings.Contains(err.Error(), "symlink forbidden") {
		t.Fatalf("Verify() error=%v; expected symlink rejection", err)
	}
}

func TestVerifyDoesNotRequireNmapAndRejectsNmapManifest(t *testing.T) {
	root, digest, pins := makePayloadFixture(t, fixtureOptions{})
	useFixtureFontPins(t, pins)
	if _, err := Verify(root, digest, false, false); err != nil {
		t.Fatalf("portable verification unexpectedly requires Nmap: %v", err)
	}
	root, digest, pins = makePayloadFixture(t, fixtureOptions{nmapManifest: true})
	useFixtureFontPins(t, pins)
	if _, err := Verify(root, digest, false, false); err == nil || !strings.Contains(err.Error(), "Nmap") {
		t.Fatalf("Nmap manifest accepted: %v", err)
	}
}

func TestVerifyRequestedObscuraRequiresBothPinnedExecutables(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("portable fixtures target Linux/Windows amd64")
	}
	root, digest, pins := makePayloadFixture(t, fixtureOptions{withBrowser: true})
	useFixtureFontPins(t, pins)
	payload, err := Verify(root, digest, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Obscura == nil || payload.ObscuraWorker == nil || payload.Obscura.Version() != ObscuraVersion || payload.ObscuraWorker.Version() != ObscuraVersion {
		t.Fatalf("browser payload not verified: %+v", payload)
	}
	if err := os.Remove(payload.ObscuraWorker.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, digest, false, true); err == nil {
		t.Fatal("browser accepted after worker removal")
	}
}

func TestVerifyRequestedObscuraRejectsMissingOrWrongVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts fixtureOptions
		want string
	}{
		{name: "missing pair", want: "portable Obscura is unavailable"},
		{name: "wrong pinned version", opts: fixtureOptions{withBrowser: true, browserVersion: "0.2.1"}, want: "portable Obscura version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, digest, pins := makePayloadFixture(t, tc.opts)
			useFixtureFontPins(t, pins)
			if _, err := Verify(root, digest, false, true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error=%v want %q", err, tc.want)
			}
		})
	}
}
