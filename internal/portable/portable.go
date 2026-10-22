// Package portable verifies the read-only payload shipped beside the Go
// application. It does not download, install, or execute bundled tools.
package portable

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"asmtool/internal/discovery/passive"
	"asmtool/internal/platform"
)

const (
	TypstName         = "typst"
	TypstVersion      = "0.15.1"
	SubfasterName     = "subfaster"
	SubfasterVersion  = "2.18.0"
	ObscuraName       = "obscura"
	ObscuraWorkerName = "obscura-worker"
	ObscuraVersion    = "0.2.2"
	BinRelativePath   = "bin"
	FontRelativePath  = "fonts/dejavu"
)

var requiredFonts = map[string]string{
	"DejaVuSans.ttf":             "b4c632e3cdf9acc7f28758fb5a323c8524d7fc6660d46904d9b6cbe2809c419c",
	"DejaVuSans-Bold.ttf":        "e1d733afbbfce842a1b43dced0c9885a76a4e67290dc7e690c4e9b76ebfc7d23",
	"DejaVuSans-Oblique.ttf":     "e6bb3d31b3afd8070753da4bac76ac6f97d99743d0bf070d7fe01336a1f1ae42",
	"DejaVuSans-BoldOblique.ttf": "db536b2436d5823489aec205adfaee70629633dbe6c5c2d135ac6934e522e905",
}

// Payload contains handles to the authenticated runtime assets needed by
// passive work and report generation. Optional tools are nil unless requested.
type Payload struct {
	Bundle        *platform.Bundle
	Typst         platform.Tool
	Subfaster     *platform.Tool
	Obscura       *platform.Tool
	ObscuraWorker *platform.Tool
	FontDir       string
}

// Verify checks a closed, platform-specific payload using the manifest digest
// embedded in the application. The digest must come from a build-time trust
// anchor; it must never be populated from a CLI flag, config file, or payload
// sidecar. The executable should remain outside the payload tree to avoid a
// self-hash cycle.
func Verify(root, embeddedManifestSHA256 string, needSubfaster, needBrowser bool) (Payload, error) {
	if runtime.GOARCH != "amd64" || (runtime.GOOS != "linux" && runtime.GOOS != "windows") {
		return Payload{}, fmt.Errorf("portable runtime is unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if embeddedManifestSHA256 == "" {
		return Payload{}, errors.New("embedded portable payload trust anchor is missing")
	}
	if root == "" {
		return Payload{}, errors.New("portable payload directory is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Payload{}, fmt.Errorf("resolve portable payload directory: %w", err)
	}

	bundle, err := platform.NewBundle(root, embeddedManifestSHA256)
	if err != nil {
		return Payload{}, fmt.Errorf("verify portable payload: %w", err)
	}
	typst, err := bundle.Tool(TypstName)
	if err != nil {
		return Payload{}, fmt.Errorf("portable Typst is unavailable: %w", err)
	}
	if typst.Version() != TypstVersion {
		return Payload{}, fmt.Errorf("portable Typst version %q; require %q", typst.Version(), TypstVersion)
	}
	if err := requireToolPath(root, typst, TypstName); err != nil {
		return Payload{}, err
	}
	if err := typst.Verify(); err != nil {
		return Payload{}, fmt.Errorf("verify portable Typst: %w", err)
	}

	fontDir := filepath.Join(root, filepath.FromSlash(FontRelativePath))
	if err := verifyFontFiles(fontDir, requiredFonts); err != nil {
		return Payload{}, fmt.Errorf("verify portable report fonts: %w", err)
	}

	result := Payload{Bundle: bundle, Typst: typst, FontDir: fontDir}
	if needSubfaster {
		tool, err := bundle.Tool(SubfasterName)
		if err != nil {
			return Payload{}, fmt.Errorf("portable Subfaster is unavailable: %w", err)
		}
		if tool.Version() != SubfasterVersion || tool.Version() != passive.ExpectedSubfasterVersion {
			return Payload{}, fmt.Errorf("portable Subfaster version %q; require %q", tool.Version(), SubfasterVersion)
		}
		if err := requireToolPath(root, tool, SubfasterName); err != nil {
			return Payload{}, err
		}
		if err := tool.Verify(); err != nil {
			return Payload{}, fmt.Errorf("verify portable Subfaster: %w", err)
		}
		result.Subfaster = &tool
	}
	if needBrowser {
		browser, err := bundle.Tool(ObscuraName)
		if err != nil {
			return Payload{}, fmt.Errorf("portable Obscura is unavailable: %w", err)
		}
		if browser.Version() != ObscuraVersion {
			return Payload{}, fmt.Errorf("portable Obscura version %q; require %q", browser.Version(), ObscuraVersion)
		}
		if err := requireToolPath(root, browser, ObscuraName); err != nil {
			return Payload{}, err
		}
		if err := browser.Verify(); err != nil {
			return Payload{}, fmt.Errorf("verify portable Obscura: %w", err)
		}
		worker, err := bundle.Tool(ObscuraWorkerName)
		if err != nil {
			return Payload{}, fmt.Errorf("portable Obscura worker is unavailable: %w", err)
		}
		if worker.Version() != ObscuraVersion {
			return Payload{}, fmt.Errorf("portable Obscura worker version %q; require %q", worker.Version(), ObscuraVersion)
		}
		if err := requireToolPath(root, worker, ObscuraWorkerName); err != nil {
			return Payload{}, err
		}
		if err := worker.Verify(); err != nil {
			return Payload{}, fmt.Errorf("verify portable Obscura worker: %w", err)
		}
		result.Obscura, result.ObscuraWorker = &browser, &worker
	}
	return result, nil
}

func requireToolPath(root string, tool platform.Tool, name string) error {
	relative := toolPath(runtime.GOOS+"/"+runtime.GOARCH, name)
	want := filepath.Join(root, filepath.FromSlash(relative))
	got, err := filepath.Abs(tool.Path())
	if err != nil {
		return fmt.Errorf("resolve portable %s path: %w", name, err)
	}
	if !samePath(got, want) {
		return fmt.Errorf("portable %s must be stored at %s", name, relative)
	}
	return nil
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func verifyFontFiles(dir string, expected map[string]string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("font path is not a regular directory")
	}
	for name, want := range expected {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("font %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("font %s is not a regular file", name)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open font %s: %w", name, err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("hash font %s: %w", name, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close font %s: %w", name, closeErr)
		}
		if got := hex.EncodeToString(hash.Sum(nil)); got != want {
			return fmt.Errorf("font %s SHA-256 mismatch", name)
		}
	}
	return nil
}
