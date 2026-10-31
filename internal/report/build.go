package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/execution"
	"asmtool/internal/i18n"
	"asmtool/internal/platform"
)

// Outputs names the durable products of a successful report generation.
type Outputs struct {
	JSON          string
	HTML          string
	Typst         string
	PDF           string
	SubdomainsCSV string
	Manifest      string
}

func validateOutputDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("output directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(abs, 0755); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("report output is not a regular directory")
	}
	return abs, nil
}

func verifyPDF(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	header := make([]byte, 5)
	n, err := f.Read(header)
	if err != nil {
		return err
	}
	if n != 5 || !bytes.Equal(header, []byte("%PDF-")) {
		return errors.New("Typst output is not a PDF")
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 64 {
		return errors.New("Typst output PDF is too small")
	}
	return nil
}

// Generate produces all formats from the same persisted read model. The caller
// must pass a verified Typst 0.15.1 bundle handle and a bundled font directory.
// The SQLite writer must be stopped before the snapshot is taken.
func Generate(ctx context.Context, in Input, typst platform.Tool) (out Outputs, retErr error) {
	if ctx == nil {
		return Outputs{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return Outputs{}, err
	}
	if typst.Name() != "typst" || typst.Version() != "0.15.1" {
		return Outputs{}, errors.New("verified Typst 0.15.1 is required")
	}
	if in.FontDir == "" {
		return Outputs{}, errors.New("bundled font directory is required")
	}
	fonts, err := filepath.Abs(in.FontDir)
	if err != nil {
		return Outputs{}, err
	}
	info, err := os.Lstat(fonts)
	if err != nil {
		return Outputs{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Outputs{}, errors.New("invalid bundled font directory")
	}
	dir, err := validateOutputDirectory(in.OutputDir)
	if err != nil {
		return Outputs{}, err
	}
	in.OutputDir = dir
	language, err := i18n.NormalizeLanguage(in.Language)
	if err != nil {
		return Outputs{}, err
	}
	in.Language = language
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		return Outputs{}, err
	}
	reportsDir := filepath.Join(dir, "reports")
	if err := os.MkdirAll(reportsDir, 0700); err != nil {
		return Outputs{}, err
	}
	reportsInfo, err := os.Lstat(reportsDir)
	if err != nil || !reportsInfo.IsDir() || reportsInfo.Mode()&os.ModeSymlink != 0 {
		return Outputs{}, errors.New("invalid report generations directory")
	}
	stage, err := os.MkdirTemp(reportsDir, ".stage-")
	if err != nil {
		return Outputs{}, err
	}
	published := false
	defer func() {
		if !published {
			if cleanupErr := os.RemoveAll(stage); cleanupErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("remove staged report generation: %w", cleanupErr))
			}
		}
	}()
	view, err := makeHumanView(ctx, in, report, stage, csvBytes)
	if err != nil {
		return Outputs{}, err
	}
	reporting := asObject(report["reporting"])
	for _, section := range view.Sections {
		// The complete machine inventory is never presentation-truncated.
		if section.Title == reportSectionName(language, "report.section.subdomains") {
			reporting["subdomains_rendered"] = section.Shown
			reporting["subdomains_truncated"] = section.Shown < section.Total
			reporting["human_subdomain_rows"] = section.Shown
		}
	}
	if len(view.Warnings) > 0 {
		reporting["presentation_warnings"] = view.Warnings
	}
	jsonBytes, err := backends.EncodeJSON(report, true, true, true)
	if err != nil {
		return Outputs{}, err
	}
	decoded, err := backends.DecodeJSON(jsonBytes)
	if err != nil {
		return Outputs{}, err
	}
	if err := backends.ValidateSchema("report", decoded); err != nil {
		return Outputs{}, fmt.Errorf("report schema: %w", err)
	}
	htmlBytes, err := renderHTML(view)
	if err != nil {
		return Outputs{}, err
	}
	typstBytes, err := renderTypst(view)
	if err != nil {
		return Outputs{}, err
	}
	source := filepath.Join(stage, "report.typ")
	if err := backends.WriteBytesAtomic(source, typstBytes, true); err != nil {
		return Outputs{}, err
	}
	pdfPath := filepath.Join(stage, "report.pdf")
	args := []string{"compile", "--root", stage, "--font-path", fonts, "--ignore-system-fonts", source, pdfPath}
	result, err := execution.Run(ctx, typst, args, execution.Options{
		Timeout: 120 * time.Second, MaxOutputBytes: 1 << 20, TailBytes: 4096,
	})
	if err != nil {
		return Outputs{}, fmt.Errorf("Typst compile: %w", err)
	}
	if result.ExitCode != 0 || result.TimedOut || result.OutputLimitExceeded {
		return Outputs{}, fmt.Errorf("Typst compile failed (exit %d): %s", result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	if err := verifyPDF(pdfPath); err != nil {
		return Outputs{}, err
	}
	if err := ctx.Err(); err != nil {
		return Outputs{}, err
	}
	outputs := Outputs{
		JSON: filepath.Join(stage, "final_report.json"), HTML: filepath.Join(stage, "report.html"),
		Typst: source, PDF: pdfPath, SubdomainsCSV: filepath.Join(stage, "subdomains.csv"),
		Manifest: filepath.Join(stage, "report_manifest.json"),
	}
	products := []struct {
		path string
		data []byte
	}{
		{outputs.SubdomainsCSV, csvBytes}, {outputs.JSON, jsonBytes},
		{outputs.HTML, htmlBytes},
	}
	for _, product := range products {
		if err := backends.WriteBytesAtomic(product.path, product.data, true); err != nil {
			return Outputs{}, fmt.Errorf("publish %s: %w", filepath.Base(product.path), err)
		}
	}
	fileDigests, err := generationDigests(stage)
	if err != nil {
		return Outputs{}, err
	}
	manifest := map[string]any{
		"status": "ok", "generated_at_utc": asObject(report["metadata"])["generated_at_utc"],
		"report_language": language, "report_mode": reporting["report_mode"],
		"typst_version": typst.Version(),
		"sha256":        fileDigests,
	}
	manifestBytes, err := backends.EncodeJSON(manifest, true, true, true)
	if err != nil {
		return Outputs{}, err
	}
	if err := backends.WriteBytesAtomic(outputs.Manifest, manifestBytes, true); err != nil {
		return Outputs{}, err
	}
	if err := syncGenerationFiles(ctx, stage); err != nil {
		return Outputs{}, err
	}
	if err := ctx.Err(); err != nil {
		return Outputs{}, err
	}
	finalDir, moved, err := publishGeneration(ctx, reportsDir, stage, manifestBytes, fileDigests)
	if moved {
		published = true
	}
	if err != nil {
		return Outputs{}, err
	}
	if !published {
		if err := os.RemoveAll(stage); err != nil {
			return Outputs{}, fmt.Errorf("remove duplicate staged generation: %w", err)
		}
		published = true
	}
	outputs.JSON = filepath.Join(finalDir, "final_report.json")
	outputs.HTML = filepath.Join(finalDir, "report.html")
	outputs.Typst = filepath.Join(finalDir, "report.typ")
	outputs.PDF = filepath.Join(finalDir, "report.pdf")
	outputs.SubdomainsCSV = filepath.Join(finalDir, "subdomains.csv")
	outputs.Manifest = filepath.Join(finalDir, "report_manifest.json")
	return outputs, nil
}

// publishGeneration exposes a complete staged tree with one directory rename.
// It never replaces a non-empty prior generation. The moved result tells the
// caller whether stage has been consumed or should be cleaned as a duplicate.
func publishGeneration(ctx context.Context, reportsDir, stage string, manifestBytes []byte, expected map[string]string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	finalDir := filepath.Join(reportsDir, "report-"+backends.SHA256(manifestBytes))
	if err := os.Rename(stage, finalDir); err == nil {
		if err := syncDirectory(reportsDir); err != nil {
			return finalDir, true, fmt.Errorf("sync report generations directory: %w", err)
		}
		return finalDir, true, nil
	} else if existingErr := verifyExistingGeneration(ctx, finalDir, manifestBytes, expected); existingErr != nil {
		return "", false, fmt.Errorf("publish report generation: %w", errors.Join(err, existingErr))
	}
	return finalDir, false, nil
}

// generationDigests hashes every staged regular file except the manifest,
// which contains this map. Relative paths are slash-normalized for portability.
func generationDigests(root string) (map[string]string, error) {
	digests := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("report generation contains non-regular file %q", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "report_manifest.json" {
			return nil
		}
		digest, err := backends.SHA256File(path)
		if err != nil {
			return err
		}
		digests[rel] = digest
		return nil
	})
	if err != nil {
		return nil, err
	}
	return digests, nil
}

// syncGenerationFiles flushes process-produced files (notably the PDF) before
// the containing generation becomes visible under its final name.
func syncGenerationFiles(ctx context.Context, root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("report generation contains non-regular file %q", path)
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		return errors.Join(syncErr, closeErr)
	}); err != nil {
		return err
	}
	// Persist nested resource names before the staged tree is atomically exposed.
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncDirectory(directories[i]); err != nil {
			return err
		}
	}
	return nil
}

// Windows does not expose portable directory fsync through os.File.Sync.
// Regular files are flushed there; Linux flushes directory entries as well.
func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

// verifyExistingGeneration allows concurrent identical runs to converge on a
// previously published immutable directory, but never trusts a matching name.
func verifyExistingGeneration(ctx context.Context, dir string, manifestBytes []byte, expected map[string]string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing report generation is not a regular directory")
	}
	actualManifest, err := os.ReadFile(filepath.Join(dir, "report_manifest.json"))
	if err != nil {
		return err
	}
	if !bytes.Equal(actualManifest, manifestBytes) {
		return errors.New("existing report generation manifest mismatch")
	}
	actual := make(map[string]string, len(expected))
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == dir || entry.IsDir() {
			return nil
		}
		fileInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("existing report generation contains non-regular file %q", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "report_manifest.json" {
			return nil
		}
		digest, err := backends.SHA256File(path)
		if err != nil {
			return err
		}
		actual[rel] = digest
		return nil
	})
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return errors.New("existing report generation file set mismatch")
	}
	for name, digest := range expected {
		if actual[name] != digest {
			return fmt.Errorf("existing report generation digest mismatch for %q", name)
		}
	}
	return nil
}

func reportSectionName(language, key string) string {
	t, err := i18n.NewTranslator(language)
	if err != nil {
		return ""
	}
	name, _ := t.Text(key, nil)
	return name
}
