package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"asmtool/internal/platform"
	"asmtool/internal/portable"
)

const (
	maxFiles = 5000
	maxBytes = int64(512 << 20)
)

type sourceLock struct {
	ID           string   `json:"id"`
	Path         string   `json:"path"`
	SHA256       string   `json:"sha256"`
	Archive      bool     `json:"archive"`
	Version      string   `json:"version,omitempty"`
	License      string   `json:"license,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type fileLock struct {
	Path       string `json:"path"`
	Source     string `json:"source"`
	Member     string `json:"member,omitempty"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
}

type toolLock struct {
	Name         string   `json:"name"`
	Executable   string   `json:"executable"`
	Version      string   `json:"version"`
	Usage        string   `json:"usage"`
	Capabilities []string `json:"capabilities"`
	License      string   `json:"license"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type payloadLock struct {
	SchemaVersion int                        `json:"schema_version"`
	Platform      string                     `json:"platform"`
	Sources       []sourceLock               `json:"sources"`
	Files         []fileLock                 `json:"files"`
	Tools         []toolLock                 `json:"tools"`
	LinuxRuntime  *platform.LinuxRuntimeSpec `json:"linux_runtime,omitempty"`
}

type stagedFile struct {
	Path       string
	Source     string
	Member     string
	SHA256     string
	Size       int64
	Executable bool
}

type stageResult struct {
	Output           string `json:"output"`
	Platform         string `json:"platform"`
	Files            int    `json:"files"`
	BundleSHA256     string `json:"bundle_sha256"`
	ProvenanceFile   string `json:"provenance_file"`
	ProvenanceSHA256 string `json:"provenance_sha256"`
}

func stage(lockPath, output string) (stageResult, error) {
	parent, base, err := freshOutput(output)
	if err != nil {
		return stageResult{}, err
	}
	lockPath, err = filepath.Abs(lockPath)
	if err != nil {
		return stageResult{}, err
	}
	if err := regularNoLink(lockPath); err != nil {
		return stageResult{}, fmt.Errorf("lock file: %w", err)
	}
	lockBytes, err := readBounded(lockPath, 4<<20)
	if err != nil {
		return stageResult{}, err
	}
	if len(lockBytes) > 4<<20 {
		return stageResult{}, errors.New("source lock exceeds 4 MiB")
	}
	var lock payloadLock
	dec := json.NewDecoder(strings.NewReader(string(lockBytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lock); err != nil {
		return stageResult{}, fmt.Errorf("decode source lock: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return stageResult{}, errors.New("source lock has trailing data")
	}
	if lock.SchemaVersion != 1 || lock.Platform != "linux/amd64" && lock.Platform != "windows/amd64" {
		return stageResult{}, errors.New("source lock requires schema_version 1 and a supported target")
	}
	if len(lock.Files) == 0 || len(lock.Files) > maxFiles || len(lock.Sources) == 0 {
		return stageResult{}, errors.New("source lock has an invalid file or source count")
	}
	for _, item := range lock.Files {
		if isNmapPayloadPath(item.Path) {
			return stageResult{}, fmt.Errorf("Nmap payload path %q is unsupported", item.Path)
		}
	}
	for _, tool := range lock.Tools {
		if strings.EqualFold(strings.TrimSuffix(tool.Name, ".exe"), "nmap") || strings.EqualFold(filepath.Base(tool.Executable), "nmap") || strings.EqualFold(filepath.Base(tool.Executable), "nmap.exe") {
			return stageResult{}, errors.New("Nmap is not supported in portable payload locks")
		}
	}

	sources := make(map[string]sourceLock, len(lock.Sources))
	usedSources := make(map[string]bool)
	for _, src := range lock.Sources {
		if !safeID(src.ID) || src.Path == "" || !validDigest(src.SHA256) {
			return stageResult{}, fmt.Errorf("invalid source identity %q", src.ID)
		}
		if _, exists := sources[src.ID]; exists {
			return stageResult{}, fmt.Errorf("duplicate source id %q", src.ID)
		}
		if src.Version == "" || src.License == "" {
			return stageResult{}, fmt.Errorf("source %q must record version and license", src.ID)
		}
		sources[src.ID] = src
	}

	files := make([]stagedFile, 0, len(lock.Files))
	paths := make(map[string]bool, len(lock.Files))
	var total int64
	for _, item := range lock.Files {
		if !strings.HasPrefix(item.Path, "payload/") || !validManifestPath(strings.TrimPrefix(item.Path, "payload/")) {
			return stageResult{}, fmt.Errorf("unsafe output path %q", item.Path)
		}
		folded := strings.ToLower(item.Path)
		if paths[folded] {
			return stageResult{}, fmt.Errorf("duplicate or case-colliding output path %q", item.Path)
		}
		paths[folded] = true
		if !validDigest(item.SHA256) || item.Size < 0 || item.Size > maxBytes {
			return stageResult{}, fmt.Errorf("invalid size or digest for %q", item.Path)
		}
		src, ok := sources[item.Source]
		if !ok {
			return stageResult{}, fmt.Errorf("file %q references undeclared source id %q", item.Path, item.Source)
		}
		usedSources[item.Source] = true
		member := item.Member
		if src.Archive {
			if !validArchiveName(member) {
				return stageResult{}, fmt.Errorf("file %q has unsafe archive member", item.Path)
			}
		} else if member != "" {
			return stageResult{}, fmt.Errorf("non-archive source %q cannot have a member", item.Source)
		}
		total += item.Size
		if total > maxBytes {
			return stageResult{}, errors.New("staged payload exceeds 512 MiB")
		}
		files = append(files, stagedFile{Path: item.Path, Source: item.Source, Member: member, SHA256: strings.ToLower(item.SHA256), Size: item.Size, Executable: item.Executable})
	}
	for id := range sources {
		if !usedSources[id] {
			return stageResult{}, fmt.Errorf("declared source %q is unused", id)
		}
	}

	resolvedSources := make(map[string]string, len(sources))
	for id, src := range sources {
		p := src.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(lockPath), p)
		}
		p, err = filepath.Abs(p)
		if err != nil {
			return stageResult{}, err
		}
		if err := regularNoLink(p); err != nil {
			return stageResult{}, fmt.Errorf("source %q: %w", id, err)
		}
		info, err := os.Stat(p)
		if err != nil {
			return stageResult{}, err
		}
		if info.Size() > maxBytes {
			return stageResult{}, fmt.Errorf("source %q exceeds 512 MiB", id)
		}
		got, err := hashFile(p)
		if err != nil {
			return stageResult{}, err
		}
		if got != strings.ToLower(src.SHA256) {
			return stageResult{}, fmt.Errorf("source %q SHA-256 mismatch", id)
		}
		resolvedSources[id] = p
	}

	for _, src := range lock.Sources {
		if !src.Archive {
			continue
		}
		members, err := inspectArchive(resolvedSources[src.ID])
		if err != nil {
			return stageResult{}, fmt.Errorf("source %q archive: %w", src.ID, err)
		}
		for _, f := range files {
			if f.Source != src.ID {
				continue
			}
			entry, ok := members[f.Member]
			if !ok {
				return stageResult{}, fmt.Errorf("source %q member %q is missing", src.ID, f.Member)
			}
			if entry.UncompressedSize64 > uint64(maxBytes) || int64(entry.UncompressedSize64) != f.Size {
				return stageResult{}, fmt.Errorf("source %q member %q size mismatch", src.ID, f.Member)
			}
		}
	}

	manifestFiles := make([]portable.TrustedFile, 0, len(files))
	toolSpecs := make([]portable.ToolSpec, 0, len(lock.Tools))
	for _, f := range files {
		manifestFiles = append(manifestFiles, portable.TrustedFile{Path: strings.TrimPrefix(f.Path, "payload/"), SHA256: f.SHA256})
	}
	for _, tool := range lock.Tools {
		if tool.Usage != "qualification-only" || tool.License == "" || len(tool.Capabilities) == 0 {
			return stageResult{}, fmt.Errorf("tool %q requires qualification-only usage, capabilities and license", tool.Name)
		}
		if !validManifestPath(strings.TrimPrefix(tool.Executable, "payload/")) || !strings.HasPrefix(tool.Executable, "payload/") {
			return stageResult{}, fmt.Errorf("tool %q has unsafe executable path", tool.Name)
		}
		listed := false
		for _, f := range files {
			if f.Path == tool.Executable && f.Executable {
				listed = true
			}
		}
		if !listed {
			return stageResult{}, fmt.Errorf("tool %q executable is not declared executable in files", tool.Name)
		}
		toolSpecs = append(toolSpecs, portable.ToolSpec{Name: tool.Name, Executable: strings.TrimPrefix(tool.Executable, "payload/"), Version: tool.Version})
	}
	if lock.LinuxRuntime != nil {
		loaderPath := "payload/" + lock.LinuxRuntime.Loader
		loaderExecutable := false
		for _, f := range files {
			if f.Path == loaderPath && f.Executable {
				loaderExecutable = true
				break
			}
		}
		if !loaderExecutable {
			return stageResult{}, errors.New("fixed Linux runtime loader must be declared executable")
		}
	}
	for _, f := range files {
		if !f.Executable {
			continue
		}
		declared := false
		for _, tool := range lock.Tools {
			if tool.Executable == f.Path {
				declared = true
			}
		}
		if !declared && (lock.LinuxRuntime == nil || lock.Platform != "linux/amd64" || f.Path != "payload/"+lock.LinuxRuntime.Loader) {
			return stageResult{}, fmt.Errorf("executable file %q is not a declared tool or fixed Linux loader", f.Path)
		}
	}
	manifest, bundleHash, err := portable.EncodeManifest(portable.ManifestSpec{Platform: lock.Platform, Files: manifestFiles, Tools: toolSpecs, LinuxRuntime: lock.LinuxRuntime})
	if err != nil {
		return stageResult{}, fmt.Errorf("build portable bundle manifest: %w", err)
	}

	tmp, err := os.MkdirTemp(parent, ".portablepayload-stage-")
	if err != nil {
		return stageResult{}, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Mkdir(filepath.Join(tmp, "payload"), 0700); err != nil {
		return stageResult{}, err
	}
	for _, f := range files {
		data, err := readLockedFile(sources[f.Source], resolvedSources[f.Source], f)
		if err != nil {
			return stageResult{}, err
		}
		if int64(len(data)) != f.Size || digestBytes(data) != f.SHA256 {
			return stageResult{}, fmt.Errorf("staged file %q digest or size mismatch", f.Path)
		}
		dest := filepath.Join(tmp, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return stageResult{}, err
		}
		mode := os.FileMode(0644)
		if f.Executable {
			mode = 0755
		}
		if err := os.WriteFile(dest, data, mode); err != nil {
			return stageResult{}, err
		}
		if err := os.Chmod(dest, mode); err != nil {
			return stageResult{}, err
		}
	}
	// Recheck source identities after extraction to detect replacement while staging.
	for id, path := range resolvedSources {
		got, err := hashFile(path)
		if err != nil {
			return stageResult{}, err
		}
		if got != strings.ToLower(sources[id].SHA256) {
			return stageResult{}, fmt.Errorf("source %q changed while staging", id)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "payload", "bundle.json"), manifest, 0644); err != nil {
		return stageResult{}, err
	}
	provenance := struct {
		SchemaVersion int          `json:"schema_version"`
		Platform      string       `json:"platform"`
		BundleSHA256  string       `json:"bundle_sha256"`
		Sources       []sourceLock `json:"sources"`
		Files         []fileLock   `json:"files"`
		Tools         []toolLock   `json:"tools"`
	}{1, lock.Platform, bundleHash, lock.Sources, lock.Files, lock.Tools}
	encoded, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return stageResult{}, err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(tmp, "payload-provenance.json"), encoded, 0644); err != nil {
		return stageResult{}, err
	}
	readme := []byte(candidateReadme)
	if err := os.WriteFile(filepath.Join(tmp, "README.md"), readme, 0644); err != nil {
		return stageResult{}, err
	}
	final := filepath.Join(parent, base)
	if _, err := os.Lstat(final); err == nil {
		return stageResult{}, errors.New("output appeared during staging; existing output preserved")
	} else if !os.IsNotExist(err) {
		return stageResult{}, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return stageResult{}, err
	}
	return stageResult{Output: final, Platform: lock.Platform, Files: len(files), BundleSHA256: bundleHash, ProvenanceFile: filepath.Join(final, "payload-provenance.json"), ProvenanceSHA256: digestBytes(encoded)}, nil
}

func readLockedFile(src sourceLock, sourcePath string, f stagedFile) ([]byte, error) {
	if !src.Archive {
		data, err := readBounded(sourcePath, maxBytes)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	r, err := zip.OpenReader(sourcePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, item := range r.File {
		name := strings.TrimSuffix(item.Name, "/")
		if name != f.Member {
			continue
		}
		rc, err := item.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, maxBytes+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(data)) > maxBytes {
			return nil, errors.New("archive member exceeds 512 MiB")
		}
		return data, nil
	}
	return nil, fmt.Errorf("archive member %q is absent", f.Member)
}

func isNmapPayloadPath(value string) bool {
	clean := strings.ToLower(filepath.ToSlash(value))
	return strings.HasPrefix(clean, "payload/bin/nmap") || strings.HasPrefix(clean, "payload/bin/nselib/") || strings.HasPrefix(clean, "payload/bin/scripts/") || clean == "payload/bin/nse_main.lua"
}

func inspectArchive(path string) (map[string]*zip.File, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if len(r.File) > maxFiles {
		return nil, errors.New("archive has more than 5000 entries")
	}
	entries := make(map[string]*zip.File, len(r.File))
	folded := make(map[string]string, len(r.File))
	for _, f := range r.File {
		if !utf8.ValidString(f.Name) {
			return nil, errors.New("archive contains a non-UTF-8 member name")
		}
		name := f.Name
		if f.FileInfo().IsDir() {
			name = strings.TrimSuffix(name, "/")
		}
		if !validArchiveName(name) {
			return nil, fmt.Errorf("unsafe archive member %q", f.Name)
		}
		if f.Mode()&os.ModeSymlink != 0 || f.Mode()&os.ModeType != 0 && !f.FileInfo().IsDir() {
			return nil, fmt.Errorf("non-regular archive member %q", f.Name)
		}
		key := strings.ToLower(name)
		if old, ok := folded[key]; ok {
			return nil, fmt.Errorf("duplicate or case-colliding archive members %q and %q", old, name)
		}
		folded[key] = name
		if f.FileInfo().IsDir() {
			continue
		}
		entries[name] = f
	}
	return entries, nil
}

func freshOutput(output string) (string, string, error) {
	if output == "" {
		return "", "", errors.New("output path is required")
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return "", "", err
	}
	parent := filepath.Dir(abs)
	if err := noLinkComponents(parent); err != nil {
		return "", "", err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", "", fmt.Errorf("output parent must already exist: %w", err)
	}
	if !info.IsDir() {
		return "", "", errors.New("output parent is not a directory")
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", "", errors.New("output already exists; refusing to replace it")
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	return parent, filepath.Base(abs), nil
}

func regularNoLink(path string) error {
	if err := noLinkComponents(path); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a regular non-symlink file")
	}
	return nil
}

// Developer-owned paths must not traverse a symlink. Windows reparse/ACL
// behavior still requires native qualification; this is not an OS sandbox.
func noLinkComponents(p string) error {
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	for {
		i, err := os.Lstat(abs)
		if err != nil {
			return err
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink path component %q", abs)
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return nil
		}
		abs = parent
	}
}

func readBounded(p string, limit int64) ([]byte, error) {
	if err := regularNoLink(p); err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file %q exceeds read limit", p)
	}
	return b, nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func safeID(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validManifestPath(s string) bool {
	if s == "" || !utf8.ValidString(s) || strings.ContainsAny(s, "\\:\x00") || strings.HasPrefix(s, "/") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(s))) != s {
		return false
	}
	for _, c := range strings.Split(s, "/") {
		if c == "" || c == "." || c == ".." || strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return false
		}
	}
	return true
}

func validArchiveName(s string) bool { return validManifestPath(s) }

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, maxBytes+1)); err != nil {
		return "", err
	} else if n > maxBytes {
		return "", errors.New("file exceeds hashing limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
