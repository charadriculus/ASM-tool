package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/execution"
)

type ScreenshotArtifact struct {
	Path, SHA256 string
	Bytes        int
}

// SaveScreenshot publishes validated current-page bytes without navigation.
// Existing artifacts are never replaced; staging lives on the same filesystem.
// The artifacts root must be private to this run, as in the existing contract.
func SaveScreenshot(ctx context.Context, root, relative string, data []byte, maxBytes int) (ScreenshotArtifact, error) {
	if ctx == nil {
		return ScreenshotArtifact{}, errors.New("nil screenshot context")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return ScreenshotArtifact{}, err
	}
	if maxBytes <= 0 || maxBytes > 16<<20 || len(data) == 0 || len(data) > maxBytes || !strings.EqualFold(filepath.Ext(relative), ".png") {
		return ScreenshotArtifact{}, errors.New("invalid screenshot size or suffix")
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || uint64(config.Width)*uint64(config.Height) > 64<<20 {
		return ScreenshotArtifact{}, errors.New("invalid or excessive PNG dimensions")
	}
	if err := validateScreenshotPNG(ctx, data); err != nil {
		return ScreenshotArtifact{}, err
	}
	path, err := execution.SafeArtifactPath(root, relative)
	if err != nil {
		return ScreenshotArtifact{}, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return ScreenshotArtifact{}, err
	}
	path, err = execution.SafeArtifactPath(root, relative)
	if err != nil {
		return ScreenshotArtifact{}, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".screenshot-")
	if err != nil {
		return ScreenshotArtifact{}, err
	}
	staged := f.Name()
	defer os.Remove(staged)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return ScreenshotArtifact{}, err
	}
	if err = core.ValidatePNGFile(ctx, staged); err != nil {
		return ScreenshotArtifact{}, err
	}
	if err = ctx.Err(); err != nil {
		return ScreenshotArtifact{}, err
	}
	// Link publishes atomically with exclusive-create semantics on Linux/Windows.
	// Filesystems lacking hardlink support return an explicit error, no fallback.
	if err = os.Link(staged, path); err != nil {
		return ScreenshotArtifact{}, err
	}
	h := sha256.Sum256(data)
	return ScreenshotArtifact{path, hex.EncodeToString(h[:]), len(data)}, nil
}

// Strict standard-library decode checks CRC, complete pixel data and IEND.
// The configured byte/pixel limits bound allocations; context checks accompany
// every compressed read. This strengthens, rather than changes, the core helper.
func validateScreenshotPNG(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || uint64(config.Width)*uint64(config.Height) > 64<<20 {
		return errors.New("invalid PNG dimensions")
	}
	reader := bytes.NewReader(data)
	if _, err = png.Decode(pngContextReader{ctx, reader}); err != nil {
		return err
	}
	if reader.Len() != 0 {
		return errors.New("trailing bytes after PNG")
	}
	return ctx.Err()
}

type pngContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r pngContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
