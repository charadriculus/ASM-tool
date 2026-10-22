package portable

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"asmtool/internal/platform"
)

func fixtureManifestSpec(target string) ManifestSpec {
	files := make([]TrustedFile, 0, len(requiredFonts)+2)
	for name, digest := range requiredFonts {
		files = append(files, TrustedFile{Path: FontRelativePath + "/" + name, SHA256: digest})
	}
	typstPath := toolPath(target, TypstName)
	typstDigest := sha256.Sum256([]byte("reviewed Typst identity"))
	files = append(files,
		TrustedFile{Path: typstPath, SHA256: hex.EncodeToString(typstDigest[:])},
		TrustedFile{Path: "licenses/Типографика.txt", SHA256: strings.Repeat("a", 64)},
	)
	return ManifestSpec{Platform: target, Files: files, Tools: []ToolSpec{{Name: TypstName, Executable: typstPath, Version: TypstVersion}}}
}

func manifestFileIndex(spec *ManifestSpec, name string) int {
	for i := range spec.Files {
		if spec.Files[i].Path == name {
			return i
		}
	}
	return -1
}

func TestEncodeManifestIsDeterministicAndUsesBundleSchema(t *testing.T) {
	spec := fixtureManifestSpec("linux/amd64")
	first, firstDigest, err := EncodeManifest(spec)
	if err != nil {
		t.Fatal(err)
	}
	for left, right := 0, len(spec.Files)-1; left < right; left, right = left+1, right-1 {
		spec.Files[left], spec.Files[right] = spec.Files[right], spec.Files[left]
	}
	second, secondDigest, err := EncodeManifest(spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || firstDigest != secondDigest {
		t.Fatal("manifest output depends on input order")
	}
	var decoded struct {
		SchemaVersion int    `json:"schema_version"`
		Platform      string `json:"platform"`
		Files         []struct {
			Path string `json:"path"`
			Hash string `json:"sha256"`
		} `json:"files"`
		Tools []struct {
			Name       string `json:"name"`
			Executable string `json:"executable"`
			Version    string `json:"version"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != 1 || decoded.Platform != "linux/amd64" || len(decoded.Tools) != 1 || decoded.Tools[0].Name != TypstName {
		t.Fatalf("unexpected manifest schema: %+v", decoded)
	}
}

func TestEncodeManifestWindowsLayoutAndTrustedAllowlist(t *testing.T) {
	layout, err := Layout("windows/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if layout.Executable != "asm-tool.exe" || layout.PayloadDir != "payload" {
		t.Fatalf("unexpected Windows archive layout: %+v", layout)
	}
	spec := fixtureManifestSpec("windows/amd64")
	spec.Tools = append(spec.Tools, ToolSpec{Name: SubfasterName, Executable: toolPath(spec.Platform, SubfasterName), Version: SubfasterVersion})
	digest := sha256.Sum256([]byte("reviewed Subfaster identity"))
	spec.Files = append(spec.Files, TrustedFile{Path: toolPath(spec.Platform, SubfasterName), SHA256: hex.EncodeToString(digest[:])})
	if _, _, err := EncodeManifest(spec); err != nil {
		t.Fatal(err)
	}
}

func TestEncodeManifestRejectsUnsafeOrUntrustedInputs(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ManifestSpec)
		want   string
	}{
		{name: "unsupported target", change: func(spec *ManifestSpec) { spec.Platform = "darwin/arm64" }, want: "unsupported portable target"},
		{name: "self manifest", change: func(spec *ManifestSpec) {
			spec.Files = append(spec.Files, TrustedFile{Path: "bundle.json", SHA256: strings.Repeat("a", 64)})
		}, want: "cannot include its own bundle manifest"},
		{name: "traversal", change: func(spec *ManifestSpec) {
			spec.Files[manifestFileIndex(spec, "fonts/dejavu/DejaVuSans.ttf")].Path = "../escape"
		}, want: "unsafe component"},
		{name: "noncanonical path", change: func(spec *ManifestSpec) {
			spec.Files[manifestFileIndex(spec, "fonts/dejavu/DejaVuSans.ttf")].Path = "fonts/dejavu/../dejavu/DejaVuSans.ttf"
		}, want: "clean relative"},
		{name: "invalid digest", change: func(spec *ManifestSpec) {
			spec.Files[manifestFileIndex(spec, "fonts/dejavu/DejaVuSans.ttf")].SHA256 = "xyz"
		}, want: "invalid SHA-256"},
		{name: "case collision", change: func(spec *ManifestSpec) {
			i := manifestFileIndex(spec, "fonts/dejavu/DejaVuSans.ttf")
			spec.Files = append(spec.Files, TrustedFile{Path: strings.ToUpper(spec.Files[i].Path), SHA256: spec.Files[i].SHA256})
		}, want: "duplicate or case-colliding"},
		{name: "linux path case mismatch", change: func(spec *ManifestSpec) { spec.Tools[0].Executable = "BIN/TYPST" }, want: "not allowlisted"},
		{name: "missing font", change: func(spec *ManifestSpec) {
			i := manifestFileIndex(spec, "fonts/dejavu/DejaVuSans.ttf")
			spec.Files = append(spec.Files[:i], spec.Files[i+1:]...)
		}, want: "missing pinned font"},
		{name: "changed pinned font", change: func(spec *ManifestSpec) {
			spec.Files[manifestFileIndex(spec, "fonts/dejavu/DejaVuSans.ttf")].SHA256 = strings.Repeat("0", 64)
		}, want: "does not match its pinned digest"},
		{name: "unlisted tool", change: func(spec *ManifestSpec) { spec.Tools[0].Executable = "bin/other" }, want: "not allowlisted"},
		{name: "wrong Typst version", change: func(spec *ManifestSpec) { spec.Tools[0].Version = "0.14.0" }, want: "requires Typst 0.15.1"},
		{name: "browser requires worker", change: func(spec *ManifestSpec) {
			path := toolPath(spec.Platform, ObscuraName)
			spec.Files = append(spec.Files, TrustedFile{Path: path, SHA256: strings.Repeat("a", 64)})
			spec.Tools = append(spec.Tools, ToolSpec{Name: ObscuraName, Executable: path, Version: ObscuraVersion})
		}, want: "requires both browser executables"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := fixtureManifestSpec("linux/amd64")
			tt.change(&spec)
			if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("EncodeManifest() error=%v; want text %q", err, tt.want)
			}
		})
	}
}

func TestEncodeManifestRejectsNmapToolAndPayload(t *testing.T) {
	for _, target := range []string{"linux/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			t.Run("Nmap paths", func(t *testing.T) {
				for _, filePath := range []string{"bin/nmap/nmap.exe", "bin/nmap-services", "bin/nselib/comm.lua", "bin/scripts/http-title.nse", "bin/nse_main.lua"} {
					spec := fixtureManifestSpec(target)
					spec.Files = append(spec.Files, TrustedFile{Path: filePath, SHA256: strings.Repeat("a", 64)})
					if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), "Nmap") {
						t.Fatalf("Nmap payload path %q accepted: %v", filePath, err)
					}
				}
			})
			t.Run("tool identity", func(t *testing.T) {
				spec := fixtureManifestSpec(target)
				spec.Files = append(spec.Files, TrustedFile{Path: "bin/helper.exe", SHA256: strings.Repeat("a", 64)})
				spec.Tools = append(spec.Tools, ToolSpec{Name: "nmap", Executable: "bin/helper.exe", Version: "fixture"})
				if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), "outside the supported portable payload") {
					t.Fatalf("Nmap tool identity accepted: %v", err)
				}
			})
		})
	}
}

func TestEncodeManifestLinuxRuntimeClosureContract(t *testing.T) {
	spec := fixtureManifestSpec("linux/amd64")
	loader := "bin/linux-runtime/ld-linux-x86-64.so.2"
	spec.Files = append(spec.Files,
		TrustedFile{Path: loader, SHA256: strings.Repeat("b", 64)},
		TrustedFile{Path: "bin/linux-runtime/libc.so.6", SHA256: strings.Repeat("c", 64)},
		TrustedFile{Path: "bin/subfaster", SHA256: strings.Repeat("d", 64)},
	)
	spec.Tools = append(spec.Tools, ToolSpec{Name: "subfaster", Executable: "bin/subfaster", Version: SubfasterVersion})
	spec.LinuxRuntime = &platform.LinuxRuntimeSpec{Loader: loader, LibraryDir: "bin/linux-runtime", Tools: []string{SubfasterName}}
	first, _, err := EncodeManifest(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.LinuxRuntime.Tools = []string{"subfaster", "subfaster"}
	if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), "unsupported or duplicate") {
		t.Fatalf("undeclared loader tool error=%v", err)
	}
	var decoded struct {
		LinuxRuntime platform.LinuxRuntimeSpec `json:"linux_runtime"`
	}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.LinuxRuntime.Loader != loader || decoded.LinuxRuntime.LibraryDir != "bin/linux-runtime" || len(decoded.LinuxRuntime.Tools) != 1 || decoded.LinuxRuntime.Tools[0] != SubfasterName {
		t.Fatalf("unexpected runtime manifest: %+v", decoded.LinuxRuntime)
	}
}

func TestEncodeManifestRejectsUnsafeLinuxRuntimeDeclarations(t *testing.T) {
	base := func() ManifestSpec {
		spec := fixtureManifestSpec("linux/amd64")
		loader := "bin/linux-runtime/ld-linux-x86-64.so.2"
		spec.Files = append(spec.Files,
			TrustedFile{Path: loader, SHA256: strings.Repeat("b", 64)},
			TrustedFile{Path: "bin/linux-runtime/libc.so.6", SHA256: strings.Repeat("c", 64)},
			TrustedFile{Path: "bin/subfaster", SHA256: strings.Repeat("d", 64)},
		)
		spec.Tools = append(spec.Tools, ToolSpec{Name: SubfasterName, Executable: "bin/subfaster", Version: SubfasterVersion})
		spec.LinuxRuntime = &platform.LinuxRuntimeSpec{Loader: loader, LibraryDir: "bin/linux-runtime", Tools: []string{SubfasterName}}
		return spec
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ManifestSpec)
		want   string
	}{
		{"platform", func(s *ManifestSpec) { s.Platform = "windows/amd64" }, "only on linux/amd64"},
		{"loader path", func(s *ManifestSpec) { s.LinuxRuntime.Loader = "bin/other-loader" }, "fixed bin/linux-runtime"},
		{"missing libc", func(s *ManifestSpec) {
			i := manifestFileIndex(s, "bin/linux-runtime/libc.so.6")
			s.Files = append(s.Files[:i], s.Files[i+1:]...)
		}, "lacks libc.so.6"},
		{"unsupported tool", func(s *ManifestSpec) { s.LinuxRuntime.Tools = []string{"typst"} }, "unsupported or duplicate"},
		{"duplicate tool", func(s *ManifestSpec) { s.LinuxRuntime.Tools = []string{SubfasterName, SubfasterName} }, "unsupported or duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := base()
			tc.mutate(&spec)
			if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("EncodeManifest error=%v; want %q", err, tc.want)
			}
		})
	}
}

func TestManifestPathsAcceptOrdinaryNamesAndRejectDevices(t *testing.T) {
	for _, valid := range []string{"bin/subfaster", "bin/lib/helper.lua", "bin/LPTx.dat"} {
		if err := validateManifestPath(valid); err != nil {
			t.Fatalf("valid bundled resource rejected %q: %v", valid, err)
		}
	}
	for _, bad := range []string{"bin/COM1.lua", "bin/COM9", "bin/LPT1.dat", "bin/LPT9", "bin/COM¹.lua", "bin/LPT²"} {
		if err := validateManifestPath(bad); err == nil {
			t.Fatalf("Windows device accepted: %q", bad)
		}
	}
}

func TestEncodeManifestRejectsObscuraLoaderWrapper(t *testing.T) {
	for _, name := range []string{ObscuraName, ObscuraWorkerName} {
		t.Run(name, func(t *testing.T) {
			spec := fixtureManifestSpec("linux/amd64")
			loader := "bin/linux-runtime/ld-linux-x86-64.so.2"
			exe := toolPath(spec.Platform, name)
			spec.Files = append(spec.Files,
				TrustedFile{Path: loader, SHA256: strings.Repeat("b", 64)},
				TrustedFile{Path: "bin/linux-runtime/libc.so.6", SHA256: strings.Repeat("c", 64)},
				TrustedFile{Path: exe, SHA256: strings.Repeat("d", 64)},
			)
			spec.Tools = append(spec.Tools, ToolSpec{Name: name, Executable: exe, Version: ObscuraVersion})
			if name == ObscuraName {
				workerPath := toolPath(spec.Platform, ObscuraWorkerName)
				spec.Files = append(spec.Files, TrustedFile{Path: workerPath, SHA256: strings.Repeat("e", 64)})
				spec.Tools = append(spec.Tools, ToolSpec{Name: ObscuraWorkerName, Executable: workerPath, Version: ObscuraVersion})
			} else {
				browserPath := toolPath(spec.Platform, ObscuraName)
				spec.Files = append(spec.Files, TrustedFile{Path: browserPath, SHA256: strings.Repeat("e", 64)})
				spec.Tools = append(spec.Tools, ToolSpec{Name: ObscuraName, Executable: browserPath, Version: ObscuraVersion})
			}
			spec.LinuxRuntime = &platform.LinuxRuntimeSpec{Loader: loader, LibraryDir: "bin/linux-runtime", Tools: []string{name}}
			if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), "unsupported or duplicate") {
				t.Fatalf("EncodeManifest error=%v; wanted Obscura not to use custom loader", err)
			}
		})
	}
}

func TestWindowsObscuraManifestRequiresBothCRTImports(t *testing.T) {
	for _, missing := range []string{"vcruntime140.dll", "vcruntime140_1.dll"} {
		t.Run(missing, func(t *testing.T) {
			spec := fixtureManifestSpec("windows/amd64")
			for _, name := range []string{ObscuraName, ObscuraWorkerName} {
				path := toolPath(spec.Platform, name)
				spec.Files = append(spec.Files, TrustedFile{Path: path, SHA256: strings.Repeat("a", 64)})
				spec.Tools = append(spec.Tools, ToolSpec{Name: name, Executable: path, Version: ObscuraVersion})
			}
			for _, name := range []string{"vcruntime140.dll", "vcruntime140_1.dll"} {
				if name != missing {
					spec.Files = append(spec.Files, TrustedFile{Path: "bin/" + name, SHA256: strings.Repeat("b", 64)})
				}
			}
			if _, _, err := EncodeManifest(spec); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("EncodeManifest error=%v; wanted %s requirement", err, missing)
			}
		})
	}
}
