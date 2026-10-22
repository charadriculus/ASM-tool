package portable

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"asmtool/internal/platform"
)

// TrustedFile is a reviewed payload path and digest. EncodeManifest does not
// read files or establish provenance; the caller must supply approved offline
// acquisition/build identities.
type TrustedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ToolSpec records the executable path and pinned version represented by the
// bundle. Runtime acquisition still goes through platform.Bundle.Tool.
type ToolSpec struct {
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Version    string `json:"version"`
}

// ManifestSpec is the deterministic, platform-specific allowlist input.
type ManifestSpec struct {
	Platform     string
	Files        []TrustedFile
	Tools        []ToolSpec
	LinuxRuntime *platform.LinuxRuntimeSpec
}

// ArchiveLayout describes the stable root entries for a user ZIP. The archive
// itself is not assembled by this API.
type ArchiveLayout struct {
	Executable string
	PayloadDir string
}

func Layout(target string) (ArchiveLayout, error) {
	if target != "linux/amd64" && target != "windows/amd64" {
		return ArchiveLayout{}, fmt.Errorf("unsupported portable target %q", target)
	}
	name := "asm-tool"
	if target == "windows/amd64" {
		name += ".exe"
	}
	return ArchiveLayout{Executable: name, PayloadDir: "payload"}, nil
}

type manifestDocument struct {
	SchemaVersion int                        `json:"schema_version"`
	Platform      string                     `json:"platform"`
	Files         []TrustedFile              `json:"files"`
	Tools         []ToolSpec                 `json:"tools"`
	LinuxRuntime  *platform.LinuxRuntimeSpec `json:"linux_runtime,omitempty"`
}

// EncodeManifest validates an explicit allowlist and returns its canonical
// JSON and SHA-256 trust anchor. It performs no filesystem operations and
// never derives trust from an adjacent manifest file.
func EncodeManifest(spec ManifestSpec) ([]byte, string, error) {
	if spec.Platform != "linux/amd64" && spec.Platform != "windows/amd64" {
		return nil, "", fmt.Errorf("unsupported portable target %q", spec.Platform)
	}
	if spec.LinuxRuntime != nil && spec.Platform != "linux/amd64" {
		return nil, "", errors.New("Linux runtime loader is supported only on linux/amd64")
	}
	if len(spec.Files) == 0 {
		return nil, "", errors.New("portable manifest requires an explicit file allowlist")
	}
	files := append([]TrustedFile(nil), spec.Files...)
	seenPaths := make(map[string]struct{}, len(files))
	for i := range files {
		if err := validateManifestPath(files[i].Path); err != nil {
			return nil, "", fmt.Errorf("payload file %q: %w", files[i].Path, err)
		}
		if isNmapPath(files[i].Path) {
			return nil, "", fmt.Errorf("Nmap payload path %q is unsupported", files[i].Path)
		}
		if strings.EqualFold(files[i].Path, "bundle.json") {
			return nil, "", errors.New("payload allowlist cannot include its own bundle manifest")
		}
		if _, err := hex.DecodeString(files[i].SHA256); err != nil || len(files[i].SHA256) != sha256.Size*2 {
			return nil, "", fmt.Errorf("invalid SHA-256 for payload file %q", files[i].Path)
		}
		files[i].SHA256 = strings.ToLower(files[i].SHA256)
		folded := strings.ToLower(files[i].Path)
		if _, exists := seenPaths[folded]; exists {
			return nil, "", fmt.Errorf("duplicate or case-colliding payload path %q", files[i].Path)
		}
		seenPaths[folded] = struct{}{}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for name, want := range requiredFonts {
		found := false
		for _, file := range files {
			if !manifestPathEqual(spec.Platform, file.Path, FontRelativePath+"/"+name) {
				continue
			}
			found = true
			if file.SHA256 != want {
				return nil, "", fmt.Errorf("portable manifest font %s does not match its pinned digest", name)
			}
		}
		if !found {
			return nil, "", fmt.Errorf("portable manifest is missing pinned font %s", name)
		}
	}

	tools := append([]ToolSpec(nil), spec.Tools...)
	seenTools := make(map[string]struct{}, len(tools))
	toolByName := make(map[string]ToolSpec, len(tools))
	for i := range tools {
		tools[i].Name = strings.TrimSpace(tools[i].Name)
		tools[i].Version = strings.TrimSpace(tools[i].Version)
		if tools[i].Name == "" || tools[i].Version == "" || !utf8.ValidString(tools[i].Name) || !utf8.ValidString(tools[i].Version) {
			return nil, "", errors.New("portable tool name and version are required")
		}
		if err := validateManifestPath(tools[i].Executable); err != nil {
			return nil, "", fmt.Errorf("portable tool %q executable: %w", tools[i].Name, err)
		}
		foldedName := strings.ToLower(tools[i].Name)
		if unsupportedPortableTool(foldedName) || strings.EqualFold(path.Base(tools[i].Executable), "nmap") || strings.EqualFold(path.Base(tools[i].Executable), "nmap.exe") {
			return nil, "", fmt.Errorf("tool %q is outside the supported portable payload", tools[i].Name)
		}
		if _, exists := seenTools[foldedName]; exists {
			return nil, "", fmt.Errorf("duplicate portable tool %q", tools[i].Name)
		}
		seenTools[foldedName] = struct{}{}
		allowlisted := false
		for _, file := range files {
			if manifestPathEqual(spec.Platform, file.Path, tools[i].Executable) {
				allowlisted = true
				break
			}
		}
		if !allowlisted {
			return nil, "", fmt.Errorf("portable tool %q executable is not allowlisted", tools[i].Name)
		}
		toolByName[foldedName] = tools[i]
	}
	typst, ok := toolByName[TypstName]
	if !ok || typst.Version != TypstVersion || !manifestPathEqual(spec.Platform, typst.Executable, toolPath(spec.Platform, TypstName)) {
		return nil, "", errors.New("portable manifest requires Typst 0.15.1 at the fixed bin path")
	}
	if subfaster, ok := toolByName[SubfasterName]; ok && (subfaster.Version != SubfasterVersion || !manifestPathEqual(spec.Platform, subfaster.Executable, toolPath(spec.Platform, SubfasterName))) {
		return nil, "", errors.New("portable manifest Subfaster must be 2.18.0 at the fixed bin path")
	}
	obscura, hasObscura := toolByName[ObscuraName]
	worker, hasWorker := toolByName[ObscuraWorkerName]
	if hasObscura != hasWorker {
		return nil, "", errors.New("portable Obscura manifest requires both browser executables")
	}
	if hasObscura && (obscura.Version != ObscuraVersion || !manifestPathEqual(spec.Platform, obscura.Executable, toolPath(spec.Platform, ObscuraName)) || worker.Version != ObscuraVersion || !manifestPathEqual(spec.Platform, worker.Executable, toolPath(spec.Platform, ObscuraWorkerName))) {
		return nil, "", errors.New("portable Obscura executables must be 0.2.2 at the fixed bin paths")
	}
	if hasObscura && spec.Platform == "windows/amd64" {
		for _, name := range []string{"vcruntime140.dll", "vcruntime140_1.dll"} {
			found := false
			for _, file := range files {
				if manifestPathEqual(spec.Platform, file.Path, BinRelativePath+"/"+name) {
					found = true
					break
				}
			}
			if !found {
				return nil, "", fmt.Errorf("Windows Obscura payload requires %s", name)
			}
		}
	}
	if err := validateLinuxRuntime(spec, files, toolByName); err != nil {
		return nil, "", err
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	var linuxRuntime *platform.LinuxRuntimeSpec
	if spec.LinuxRuntime != nil {
		copyRuntime := *spec.LinuxRuntime
		copyRuntime.Tools = append([]string(nil), spec.LinuxRuntime.Tools...)
		sort.Strings(copyRuntime.Tools)
		linuxRuntime = &copyRuntime
	}
	document := manifestDocument{SchemaVersion: 1, Platform: spec.Platform, Files: files, Tools: tools, LinuxRuntime: linuxRuntime}
	data, err := json.Marshal(document)
	if err != nil {
		return nil, "", fmt.Errorf("encode portable manifest: %w", err)
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func validateLinuxRuntime(spec ManifestSpec, files []TrustedFile, tools map[string]ToolSpec) error {
	r := spec.LinuxRuntime
	if r == nil {
		return nil
	}
	if spec.Platform != "linux/amd64" {
		return errors.New("Linux runtime loader is supported only on linux/amd64")
	}
	if r.Loader != "bin/linux-runtime/ld-linux-x86-64.so.2" || r.LibraryDir != "bin/linux-runtime" || len(r.Tools) == 0 {
		return errors.New("Linux runtime loader must use the fixed bin/linux-runtime layout and name at least one tool")
	}
	seen := map[string]bool{}
	for _, name := range r.Tools {
		if name != SubfasterName || seen[name] {
			return fmt.Errorf("unsupported or duplicate Linux runtime tool %q", name)
		}
		seen[name] = true
		tool, ok := tools[name]
		if !ok || !manifestPathEqual(spec.Platform, tool.Executable, toolPath(spec.Platform, name)) {
			return fmt.Errorf("Linux runtime tool %q must be declared at its fixed bin path", name)
		}
	}
	listed := map[string]bool{}
	for _, f := range files {
		listed[f.Path] = true
	}
	if !listed[r.Loader] {
		return errors.New("Linux runtime loader is not hash-allowlisted")
	}
	libc := false
	for _, f := range files {
		if strings.HasPrefix(f.Path, r.LibraryDir+"/") && path.Base(f.Path) == "libc.so.6" {
			libc = true
		}
	}
	if !libc {
		return errors.New("Linux runtime library directory lacks libc.so.6")
	}
	return nil
}

func manifestPathEqual(target, a, b string) bool {
	if target == "windows/amd64" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func unsupportedPortableTool(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	switch name {
	case "nmap", "cdp", "ollama", "ai", "ai_review", "research", "subfinder", "findomain", "amass", "assetfinder", "bbot", "httpx", "projectdiscovery_httpx":
		return true
	default:
		return false
	}
}

func toolPath(target, name string) string {
	filename := name
	if target == "windows/amd64" {
		filename += ".exe"
	}
	return BinRelativePath + "/" + filename
}

func isNmapPath(value string) bool {
	clean := strings.ToLower(strings.TrimPrefix(value, "payload/"))
	return strings.HasPrefix(clean, "bin/nmap") || strings.HasPrefix(clean, "bin/nselib/") || strings.HasPrefix(clean, "bin/scripts/") || clean == "bin/nse_main.lua"
}

func validateManifestPath(value string) error {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\\:\x00") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return errors.New("path must be a clean relative slash path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return errors.New("path contains an unsafe component")
		}
		device := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		if device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" || (len(device) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && device[3] >= '0' && device[3] <= '9') || device == "COM¹" || device == "COM²" || device == "COM³" || device == "LPT¹" || device == "LPT²" || device == "LPT³" {
			return errors.New("path contains a reserved Windows component")
		}
	}
	return nil
}
