package platform

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type LinuxRuntimeSpec struct {
	Loader     string   `json:"loader"`
	LibraryDir string   `json:"library_dir"`
	Tools      []string `json:"tools"`
}

type manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Platform      string `json:"platform"`
	Files         []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
	Tools []struct {
		Name       string `json:"name"`
		Executable string `json:"executable"`
		Version    string `json:"version"`
	} `json:"tools"`
	NativeCRT    []string          `json:"native_crt,omitempty"`
	LinuxRuntime *LinuxRuntimeSpec `json:"linux_runtime,omitempty"`
}

type fileDigest struct{ path, hash string }

type Bundle struct {
	root         string
	manifestHash string
	files        map[string]fileDigest
	tools        map[string]Tool
	crt          []string
	linuxRuntime *LinuxRuntimeSpec
}

var ErrNativeHTTPXBlocked = errors.New("native projectdiscovery_httpx 1.8.1 is blocked by policy")

// CheckNativeHTTPX is shared by bundle execution and the HTTP backend selector.
func CheckNativeHTTPX(name, version string) error {
	if (strings.EqualFold(name, "projectdiscovery_httpx") || strings.EqualFold(name, "httpx") || strings.EqualFold(name, "httpx.exe")) && version == "1.8.1" {
		return ErrNativeHTTPXBlocked
	}
	return nil
}

// Tool's private fields prevent callers from substituting an unverified executable.
type Tool struct {
	path, name, version string
	bundle              *Bundle
}

// Command returns the authenticated executable argv. Linux bundled tools use
// only the fixed in-payload ELF loader; callers cannot add loader options.
func (t Tool) Command(args []string) []string {
	if t.bundle == nil || t.bundle.linuxRuntime == nil || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return append([]string{t.path}, args...)
	}
	spec := t.bundle.linuxRuntime
	usesLoader := false
	for _, name := range spec.Tools {
		if name == t.name {
			usesLoader = true
			break
		}
	}
	if !usesLoader {
		return append([]string{t.path}, args...)
	}
	return append([]string{
		filepath.Join(t.bundle.root, filepath.FromSlash(spec.Loader)),
		"--inhibit-cache", "--library-path",
		filepath.Join(t.bundle.root, filepath.FromSlash(spec.LibraryDir)),
		t.path,
	}, args...)
}

func (t Tool) Name() string    { return t.name }
func (t Tool) Version() string { return t.version }
func (t Tool) Path() string    { return t.path }
func (t Tool) NativeDirectories() []string {
	if t.bundle == nil {
		return nil
	}
	out := make([]string, 0, len(t.bundle.crt))
	for _, p := range t.bundle.crt {
		out = append(out, filepath.Join(t.bundle.root, filepath.FromSlash(p)))
	}
	return out
}
func (t Tool) Verify() error {
	if t.bundle == nil {
		return errors.New("invalid tool handle")
	}
	return t.bundle.Verify(t)
}

func NewBundle(root, trustedManifestSHA256 string) (*Bundle, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := verifyPathAncestors(root); err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(root, "bundle.json")
	if err := verifyRegularNoLink(manifestPath); err != nil {
		return nil, err
	}
	manifestInfo, err := os.Stat(manifestPath)
	if err != nil {
		return nil, err
	}
	if manifestInfo.Size() > 1<<20 {
		return nil, errors.New("bundle manifest exceeds 1 MiB")
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), trustedManifestSHA256) {
		return nil, errors.New("bundle manifest digest mismatch")
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("bundle manifest: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("bundle manifest has trailing data")
	}
	if m.SchemaVersion != 1 || m.Platform != runtime.GOOS+"/"+runtime.GOARCH || len(m.Files) == 0 {
		return nil, errors.New("unsupported or empty bundle manifest")
	}
	bundle := &Bundle{root: root, linuxRuntime: m.LinuxRuntime, manifestHash: strings.ToLower(hex.EncodeToString(digest[:])), files: map[string]fileDigest{}, tools: map[string]Tool{}}
	for _, f := range m.Files {
		portablePath := strings.ToLower(filepath.ToSlash(f.Path))
		if strings.HasPrefix(portablePath, "bin/nmap") || strings.HasPrefix(portablePath, "bin/nselib/") || strings.HasPrefix(portablePath, "bin/scripts/") || portablePath == "bin/nse_main.lua" {
			return nil, fmt.Errorf("Nmap payload path %q is unsupported", f.Path)
		}
		p, err := bundlePath(root, f.Path)
		if err != nil {
			return nil, err
		}
		key := foldPath(f.Path)
		if _, ok := bundle.files[key]; ok {
			return nil, fmt.Errorf("duplicate bundle path %q", f.Path)
		}
		if !validHash(f.SHA256) {
			return nil, fmt.Errorf("invalid digest for %q", f.Path)
		}
		bundle.files[key] = fileDigest{path: f.Path, hash: strings.ToLower(f.SHA256)}
		if err := verifyFile(p, bundle.files[key].hash); err != nil {
			return nil, fmt.Errorf("bundle file %q: %w", f.Path, err)
		}
	}
	for _, t := range m.Tools {
		if strings.EqualFold(strings.TrimSuffix(t.Name, ".exe"), "nmap") || strings.EqualFold(filepath.Base(t.Executable), "nmap") || strings.EqualFold(filepath.Base(t.Executable), "nmap.exe") {
			return nil, errors.New("Nmap is not supported in portable manifests")
		}
		p, err := bundlePath(root, t.Executable)
		if err != nil {
			return nil, err
		}
		if _, ok := bundle.files[foldPath(t.Executable)]; !ok {
			return nil, fmt.Errorf("tool executable %q is not allowlisted", t.Executable)
		}
		if t.Name == "" || t.Version == "" {
			return nil, errors.New("tool name and version are required")
		}
		if _, ok := bundle.tools[t.Name]; ok {
			return nil, fmt.Errorf("duplicate tool %q", t.Name)
		}
		bundle.tools[t.Name] = Tool{path: p, name: t.Name, version: t.Version, bundle: bundle}
	}
	if m.Platform == "windows/amd64" {
		if _, enabled := bundle.tools["obscura"]; enabled {
			for _, name := range []string{"bin/vcruntime140.dll", "bin/vcruntime140_1.dll"} {
				if _, ok := bundle.files[foldPath(name)]; !ok {
					return nil, fmt.Errorf("Windows Obscura runtime is missing %s", name)
				}
			}
		}
	}
	for _, p := range m.NativeCRT {
		dir, err := bundlePath(root, p)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("invalid native CRT directory %q", p)
		}
		bundle.crt = append(bundle.crt, p)
	}
	if err := bundle.validateLinuxRuntime(m.Platform); err != nil {
		return nil, err
	}
	if err := bundle.closedTree(); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (b *Bundle) Tool(name string) (Tool, error) {
	t, ok := b.tools[name]
	if !ok {
		return Tool{}, fmt.Errorf("tool %q is not in bundle", name)
	}
	if err := CheckNativeHTTPX(t.name, t.version); err != nil {
		return Tool{}, err
	}
	if err := CheckNativeHTTPX(filepath.Base(t.path), t.version); err != nil {
		return Tool{}, err
	}
	return t, nil
}
func (b *Bundle) Verify(t Tool) error {
	if err := CheckNativeHTTPX(t.name, t.version); err != nil {
		return err
	}
	if err := CheckNativeHTTPX(filepath.Base(t.path), t.version); err != nil {
		return err
	}
	if err := verifyPathAncestors(b.root); err != nil {
		return err
	}
	if info, err := os.Lstat(b.root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(b.root) {
		return errors.New("bundle root is not a trusted directory")
	}
	if err := verifyRegularNoLink(filepath.Join(b.root, "bundle.json")); err != nil {
		return err
	}
	if t.bundle != b || t.path == "" {
		return errors.New("invalid tool handle")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(b.root, "bundle.json"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(digest[:]) != b.manifestHash {
		return errors.New("bundle manifest changed")
	}
	bases := []string{filepath.Dir(t.path)}
	if b.linuxRuntime != nil && runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		bases = append(bases, filepath.Join(b.root, filepath.FromSlash(b.linuxRuntime.LibraryDir)))
	}
	for _, p := range b.crt {
		bases = append(bases, filepath.Join(b.root, filepath.FromSlash(p)))
	}
	seen := map[string]bool{}
	for _, base := range bases {
		canonical, err := filepath.Abs(base)
		if err != nil {
			return err
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		if err := b.verifyClosure(canonical); err != nil {
			return err
		}
	}
	return nil
}
func (b *Bundle) validateLinuxRuntime(platformName string) error {
	spec := b.linuxRuntime
	if spec == nil {
		return nil
	}
	if platformName != "linux/amd64" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("Linux runtime loader is supported only on linux/amd64")
	}
	if spec.Loader != "bin/linux-runtime/ld-linux-x86-64.so.2" || spec.LibraryDir != "bin/linux-runtime" {
		return errors.New("Linux runtime loader paths must use the fixed bin/linux-runtime layout")
	}
	if strings.Contains(filepath.Join(b.root, filepath.FromSlash(spec.LibraryDir)), ":") {
		return errors.New("Linux runtime library directory cannot contain a colon")
	}
	if len(spec.Tools) == 0 {
		return errors.New("Linux runtime loader must name at least one tool")
	}
	seen := map[string]bool{}
	for _, name := range spec.Tools {
		if name != "subfaster" || seen[name] {
			return fmt.Errorf("unsupported or duplicate Linux runtime tool %q", name)
		}
		seen[name] = true
		t, ok := b.tools[name]
		if !ok {
			return fmt.Errorf("Linux runtime tool %q is not declared", name)
		}
		want := "bin/" + name
		rel, err := filepath.Rel(b.root, t.path)
		if err != nil || filepath.ToSlash(rel) != want {
			return fmt.Errorf("Linux runtime tool %q is not at its fixed path", name)
		}
	}
	if _, ok := b.files[foldPath(spec.Loader)]; !ok {
		return errors.New("Linux runtime loader is not hash-allowlisted")
	}

	sonames := map[string]string{}
	dependencies := map[string][]string{}
	checkELF := func(rel string, shared bool) error {
		filePath := filepath.Join(b.root, filepath.FromSlash(rel))
		f, err := elf.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || shared && f.Type != elf.ET_DYN {
			return errors.New("expected ELF64 x86-64 shared object")
		}
		if values, err := f.DynString(elf.DT_RPATH); err == nil && len(values) != 0 {
			return errors.New("RPATH is forbidden in the Linux runtime closure")
		}
		if values, err := f.DynString(elf.DT_RUNPATH); err == nil && len(values) != 0 {
			return errors.New("RUNPATH is forbidden in the Linux runtime closure")
		}
		needed, err := f.DynString(elf.DT_NEEDED)
		if err != nil && err != elf.ErrNoSymbols {
			return err
		}
		for _, name := range needed {
			if name == "" || strings.ContainsAny(name, "/\\") {
				return fmt.Errorf("unsafe DT_NEEDED entry %q", name)
			}
		}
		dependencies[rel] = needed
		if shared {
			soname, err := f.DynString(elf.DT_SONAME)
			if err != nil || len(soname) != 1 || soname[0] == "" {
				return errors.New("runtime shared object must declare one SONAME")
			}
			if strings.ContainsAny(soname[0], "/\\") {
				return fmt.Errorf("unsafe ELF SONAME %q", soname[0])
			}
			if rel != spec.LibraryDir+"/"+soname[0] {
				return fmt.Errorf("runtime SONAME %q must match its immediate library filename", soname[0])
			}
			if old, exists := sonames[soname[0]]; exists {
				return fmt.Errorf("duplicate runtime SONAME %q in %s and %s", soname[0], old, rel)
			}
			sonames[soname[0]] = rel
		}
		return nil
	}
	if err := checkELF(spec.Loader, true); err != nil {
		return fmt.Errorf("Linux runtime loader: %w", err)
	}
	if sonames["ld-linux-x86-64.so.2"] != spec.Loader {
		return errors.New("Linux runtime loader has an unexpected SONAME")
	}
	if err := requireExecutable(filepath.Join(b.root, filepath.FromSlash(spec.Loader))); err != nil {
		return fmt.Errorf("Linux runtime loader: %w", err)
	}
	libc := false
	var libraries []string
	for _, file := range b.files {
		if !strings.HasPrefix(file.path, spec.LibraryDir+"/") {
			continue
		}
		if filepath.Base(file.path) == "libc.so.6" {
			libc = true
		}
		libraries = append(libraries, file.path)
	}
	if !libc {
		return errors.New("Linux runtime library directory lacks libc.so.6")
	}
	for _, rel := range libraries {
		if rel == spec.Loader {
			continue
		}
		if err := checkELF(rel, true); err != nil {
			return fmt.Errorf("Linux runtime file %q: %w", rel, err)
		}
	}
	if sonames["libc.so.6"] == "" {
		return errors.New("Linux runtime directory lacks the libc.so.6 SONAME")
	}
	for _, name := range spec.Tools {
		t := b.tools[name]
		rel, _ := filepath.Rel(b.root, t.path)
		if err := checkELF(filepath.ToSlash(rel), false); err != nil {
			return fmt.Errorf("Linux runtime tool %q: %w", name, err)
		}
		if err := requireExecutable(t.path); err != nil {
			return fmt.Errorf("Linux runtime tool %q: %w", name, err)
		}
	}
	for file, needed := range dependencies {
		for _, name := range needed {
			if _, ok := sonames[name]; !ok {
				return fmt.Errorf("Linux runtime dependency %q required by %q is not in the allowlisted runtime directory", name, file)
			}
		}
	}
	return nil
}

func requireExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0111 == 0 {
		return errors.New("file is not marked executable")
	}
	return nil
}

func (b *Bundle) closedTree() error {
	seen := map[string]string{}
	return filepath.WalkDir(b.root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == b.root {
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
				return errors.New("bundle root is not a trusted directory")
			}
			return nil
		}
		rel, err := filepath.Rel(b.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
			return fmt.Errorf("bundle symlink forbidden: %s", rel)
		}
		if d.IsDir() {
			return nil
		}
		if rel == "bundle.json" {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular bundle entry: %s", rel)
		}
		folded := foldPath(rel)
		if prior, ok := seen[folded]; ok && prior != rel {
			return fmt.Errorf("case-folding bundle path collision: %s and %s", prior, rel)
		}
		seen[folded] = rel
		entry, ok := b.files[folded]
		if !ok || entry.path != rel {
			return fmt.Errorf("unlisted or case-mismatched bundle file: %s", rel)
		}
		return nil
	})
}
func bundlePath(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.ContainsAny(rel, "\\:\x00") {
		return "", fmt.Errorf("invalid bundle path %q", rel)
	}
	for _, p := range strings.Split(rel, "/") {
		if p == "" || p == "." || p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return "", fmt.Errorf("invalid bundle component %q", p)
		}
		upper := strings.ToUpper(strings.SplitN(p, ".", 2)[0])
		if upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || (len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '0' && upper[3] <= '9') || upper == "COM¹" || upper == "COM²" || upper == "COM³" || upper == "LPT¹" || upper == "LPT²" || upper == "LPT³" {
			return "", fmt.Errorf("reserved bundle component %q", p)
		}
	}
	p := filepath.Join(root, filepath.FromSlash(rel))
	r, err := filepath.Rel(root, p)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("bundle path escapes root")
	}
	return p, nil
}
func verifyFile(path, want string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || isReparsePoint(path) {
		return errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("SHA-256 mismatch")
	}
	return nil
}
func validHash(s string) bool  { b, e := hex.DecodeString(s); return e == nil && len(b) == sha256.Size }
func foldPath(s string) string { return strings.ToLower(filepath.ToSlash(s)) }

func verifyRegularNoLink(path string) error {
	i, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return fmt.Errorf("expected a regular non-link file: %s", path)
	}
	return nil
}
func verifyPathAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		i, e := os.Lstat(current)
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 || isReparsePoint(current) {
			return fmt.Errorf("bundle root ancestor is a link: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

func (b *Bundle) verifyClosure(base string) error {
	if err := verifyPathAncestors(base); err != nil {
		return fmt.Errorf("untrusted tool closure ancestor: %w", err)
	}
	info, err := os.Lstat(base)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(base) {
		return fmt.Errorf("untrusted tool closure directory: %s", base)
	}
	// WalkDir detects unlisted files, but cannot detect an allowlisted file that
	// disappeared. Re-assert every manifest entry belonging to this closure.
	for _, entry := range b.files {
		path := filepath.Join(b.root, filepath.FromSlash(entry.path))
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			continue
		}
		if err := verifyFile(path, entry.hash); err != nil {
			return fmt.Errorf("bundle closure file %q: %w", entry.path, err)
		}
	}
	seen := map[string]string{}
	return filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		meta, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if meta.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
			return fmt.Errorf("link in tool closure: %s", path)
		}
		if d.IsDir() {
			return nil
		}
		if !meta.Mode().IsRegular() {
			return fmt.Errorf("non-regular file in tool closure: %s", path)
		}
		rel, err := filepath.Rel(b.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "bundle.json" {
			if err := verifyRegularNoLink(path); err != nil {
				return err
			}
			manifestBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(manifestBytes)
			if hex.EncodeToString(digest[:]) != b.manifestHash {
				return errors.New("bundle manifest changed")
			}
			return nil
		}
		folded := foldPath(rel)
		if prev, ok := seen[folded]; ok && prev != rel {
			return fmt.Errorf("case-folding closure collision: %s and %s", prev, rel)
		}
		seen[folded] = rel
		entry, ok := b.files[folded]
		if !ok || entry.path != rel {
			return fmt.Errorf("unlisted path in tool closure: %s", rel)
		}
		return verifyFile(path, entry.hash)
	})
}
