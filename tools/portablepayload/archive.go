package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"asmtool/internal/platform"
	"asmtool/internal/portable"
)

type manifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type manifestTool struct {
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Version    string `json:"version"`
}
type bundleManifest struct {
	SchemaVersion int                        `json:"schema_version"`
	Platform      string                     `json:"platform"`
	Files         []manifestFile             `json:"files"`
	Tools         []manifestTool             `json:"tools"`
	NativeCRT     []string                   `json:"native_crt,omitempty"`
	LinuxRuntime  *platform.LinuxRuntimeSpec `json:"linux_runtime,omitempty"`
}

type archiveFile struct {
	absolute, relative, sha256 string
	size                       int64
	mode                       os.FileMode
}

const candidateReadme = "ASM Tool portable payload staging output. Payload binaries are authenticated by the application's embedded bundle digest. This directory is not qualified for release.\n"

func verifyRoot(root, expectedAppHash, expectedBundleHash, expectedProvenanceHash string) ([]archiveFile, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, "", err
	}
	if err := noLinkComponents(root); err != nil {
		return nil, "", err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("portable root must be a regular directory")
	}
	payloadRoot := filepath.Join(root, "payload")
	manifestPath := filepath.Join(payloadRoot, "bundle.json")
	if err := regularNoLink(manifestPath); err != nil {
		return nil, "", fmt.Errorf("bundle manifest: %w", err)
	}
	manifestBytes, err := readBounded(manifestPath, 1<<20)
	if err != nil {
		return nil, "", err
	}
	if len(manifestBytes) > 1<<20 {
		return nil, "", errors.New("bundle manifest exceeds 1 MiB")
	}
	if digestBytes(manifestBytes) != strings.ToLower(expectedBundleHash) {
		return nil, "", errors.New("bundle manifest digest mismatch")
	}
	var doc bundleManifest
	dec := json.NewDecoder(bytes.NewReader(manifestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, "", fmt.Errorf("decode bundle manifest: %w", err)
	}
	if doc.SchemaVersion != 1 || doc.Platform != "linux/amd64" && doc.Platform != "windows/amd64" || len(doc.Files) == 0 {
		return nil, "", errors.New("unsupported or empty bundle manifest")
	}
	spec := portable.ManifestSpec{Platform: doc.Platform, LinuxRuntime: doc.LinuxRuntime}
	for _, f := range doc.Files {
		spec.Files = append(spec.Files, portable.TrustedFile{Path: f.Path, SHA256: f.SHA256})
	}
	for _, t := range doc.Tools {
		spec.Tools = append(spec.Tools, portable.ToolSpec{Name: t.Name, Executable: t.Executable, Version: t.Version})
	}
	canonical, gotBundleHash, err := portable.EncodeManifest(spec)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(canonical, manifestBytes) || gotBundleHash != strings.ToLower(expectedBundleHash) {
		return nil, "", errors.New("bundle manifest is not canonical or differs from approved schema")
	}
	appName := "asm-tool"
	if doc.Platform == "windows/amd64" {
		appName += ".exe"
	}
	appPath := filepath.Join(root, appName)
	if err := regularNoLink(appPath); err != nil {
		return nil, "", fmt.Errorf("application: %w", err)
	}
	if got, err := hashFile(appPath); err != nil || got != strings.ToLower(expectedAppHash) {
		return nil, "", errors.New("application SHA-256 mismatch")
	}

	approved := map[string]string{"README.md": digestBytes([]byte(candidateReadme)), "payload-provenance.json": strings.ToLower(expectedProvenanceHash), appName: strings.ToLower(expectedAppHash), "payload/bundle.json": strings.ToLower(expectedBundleHash)}
	for _, f := range doc.Files {
		approved["payload/"+f.Path] = strings.ToLower(f.SHA256)
	}
	if len(approved) > maxFiles {
		return nil, "", errors.New("portable tree exceeds 5000 files")
	}
	allowedDirs := map[string]bool{"payload": true}
	for rel := range approved {
		for dir := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel))); dir != "."; dir = filepath.ToSlash(filepath.Dir(filepath.FromSlash(dir))) {
			allowedDirs[dir] = true
		}
	}
	var result []archiveFile
	var total int64
	folded := map[string]string{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !d.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe portable entry %q", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if !allowedDirs[rel] {
				return fmt.Errorf("unlisted directory %q", rel)
			}
			return nil
		}
		want, ok := approved[rel]
		if !ok {
			return fmt.Errorf("unlisted portable file %q", rel)
		}
		key := strings.ToLower(rel)
		if old, ok := folded[key]; ok {
			return fmt.Errorf("case-colliding portable paths %q and %q", old, rel)
		}
		folded[key] = rel
		if rel == "README.md" || rel == "payload-provenance.json" {
			if info.Size() > 4<<20 {
				return fmt.Errorf("metadata file %q is too large", rel)
			}
		}
		{
			got, err := hashFile(path)
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("portable file %q SHA-256 mismatch", rel)
			}
		}
		total += info.Size()
		if total > maxBytes {
			return errors.New("portable tree exceeds 512 MiB")
		}
		mode := os.FileMode(0644)
		if rel == appName {
			mode = 0755
		}
		for _, tool := range doc.Tools {
			if rel == "payload/"+tool.Executable {
				mode = 0755
			}
		}
		if doc.LinuxRuntime != nil && rel == "payload/"+doc.LinuxRuntime.Loader {
			mode = 0755
		}
		result = append(result, archiveFile{absolute: path, relative: rel, sha256: want, size: info.Size(), mode: mode})
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if len(result) != len(approved) {
		return nil, "", fmt.Errorf("portable tree has %d files; reviewed lock expects %d", len(result), len(approved))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].relative < result[j].relative })
	return result, doc.Platform, nil
}

func writeArchive(root, output string, files []archiveFile) error {
	parent, base, err := freshOutput(output)
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	final := filepath.Join(parent, base)
	if rel, err := filepath.Rel(rootAbs, final); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("archive output must be outside the portable root")
	}
	tmp, err := os.CreateTemp(parent, ".portablepayload-*.zip")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	w := zip.NewWriter(tmp)
	stamp := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, item := range files {
		header := &zip.FileHeader{Name: item.relative, Method: zip.Store}
		header.SetModTime(stamp)
		header.SetMode(item.mode.Perm())
		entry, err := w.CreateHeader(header)
		if err != nil {
			_ = w.Close()
			_ = tmp.Close()
			return err
		}
		f, err := os.Open(item.absolute)
		if err != nil {
			_ = w.Close()
			_ = tmp.Close()
			return err
		}
		h := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(entry, h), io.LimitReader(f, maxBytes+1))
		closeErr := f.Close()
		if copyErr != nil {
			_ = w.Close()
			_ = tmp.Close()
			return copyErr
		}
		if closeErr != nil {
			_ = w.Close()
			_ = tmp.Close()
			return closeErr
		}
		if written != item.size || item.sha256 != "" && hex.EncodeToString(h.Sum(nil)) != item.sha256 {
			_ = w.Close()
			_ = tmp.Close()
			return fmt.Errorf("portable file %q changed while archiving", item.relative)
		}
	}
	if err := w.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(final); err == nil {
		return errors.New("archive output appeared while writing; existing output preserved")
	} else if !os.IsNotExist(err) {
		return err
	}
	// Hard-link publication is atomic and refuses any existing destination.
	if err := os.Link(tmpName, final); err != nil {
		return err
	}
	return os.Remove(tmpName)
}
