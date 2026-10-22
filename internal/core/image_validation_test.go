package core

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type pngOracle struct {
	Cases []struct {
		File        string  `json:"file"`
		Valid       bool    `json:"valid"`
		ErrorPrefix *string `json:"error_prefix"`
	} `json:"cases"`
}

func TestValidatePNGFileSourceOracle(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "phase6", "image_validation")
	validFile, err := os.Open(filepath.Join(root, "valid.png"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(validFile)
	closeErr := validFile.Close()
	if err != nil {
		t.Fatalf("stdlib PNG decode: %v", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	r, g, b, a := decoded.At(0, 0).RGBA()
	if r != 0x1212 || g != 0x3434 || b != 0x5656 || a != 0xffff {
		t.Fatalf("decoded pixel = %#x/%#x/%#x/%#x", r, g, b, a)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oracle pngOracle
	if err := json.Unmarshal(manifestBytes, &oracle); err != nil {
		t.Fatal(err)
	}
	for _, tc := range oracle.Cases {
		t.Run(tc.File, func(t *testing.T) {
			err := ValidatePNGFile(context.Background(), filepath.Join(root, tc.File))
			if tc.Valid && err != nil {
				t.Fatalf("source accepts fixture, Go rejected: %v", err)
			}
			if !tc.Valid {
				if err == nil {
					t.Fatal("source rejects fixture, Go accepted")
				}
				if tc.ErrorPrefix != nil && !strings.HasPrefix(err.Error(), *tc.ErrorPrefix) {
					t.Fatalf("got %q, want source reason prefix %q", err, *tc.ErrorPrefix)
				}
			}
		})
	}
}

func TestValidatePNGFileCancellationAndReadErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join("..", "..", "testdata", "phase6", "image_validation", "valid.png")
	if err := ValidatePNGFile(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
	if err := ValidatePNGFile(context.Background(), filepath.Join(t.TempDir(), "missing.png")); err == nil || !strings.HasPrefix(err.Error(), "read_error:") {
		t.Fatalf("missing file error = %v", err)
	}
	if err := ValidatePNGFile(context.Background(), t.TempDir()); err == nil || err.Error() != "not_regular_file" {
		t.Fatalf("directory error = %v", err)
	}
	if err := ValidatePNGFile(nil, path); err == nil || err.Error() != "nil context" {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestPNGIDATReaderCancellationWhileSkippingChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chunks.png")
	var file bytes.Buffer
	file.Write(pngSignature[:])
	writePNGTestChunk(&file, "tEXt", nil)
	writePNGTestChunk(&file, "gAMA", nil)
	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := pngIDATReader{ctx: &cancelOnCheck{cancelAt: 3, done: make(chan struct{})}, f: f, size: int64(file.Len()), pos: 8}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("chunk-scan cancellation error = %v", err)
	}
}

type cancelOnCheck struct {
	checks, cancelAt int
	done             chan struct{}
	canceled         bool
}

func (c *cancelOnCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelOnCheck) Done() <-chan struct{}       { return c.done }
func (c *cancelOnCheck) Err() error {
	c.checks++
	if c.checks >= c.cancelAt {
		if !c.canceled {
			close(c.done)
			c.canceled = true
		}
		return context.Canceled
	}
	return nil
}
func (c *cancelOnCheck) Value(any) any { return nil }

func TestValidatePNGFileHonorsDeadlineWhileInflating(t *testing.T) {
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	block := make([]byte, 32*1024)
	for i := 0; i < 8192; i++ { // 256 MiB decoded from a small local fixture.
		if _, err := zw.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var png bytes.Buffer
	png.Write(pngSignature[:])
	writePNGTestChunk(&png, "IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0})
	writePNGTestChunk(&png, "IDAT", compressed.Bytes())
	writePNGTestChunk(&png, "IEND", nil)
	path := filepath.Join(t.TempDir(), "inflate.png")
	if err := os.WriteFile(path, png.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := ValidatePNGFile(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("inflate deadline error = %v", err)
	}
}

func writePNGTestChunk(dst *bytes.Buffer, kind string, payload []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	dst.Write(size[:])
	dst.WriteString(kind)
	dst.Write(payload)
	crc := crc32.Update(0, crc32.IEEETable, []byte(kind))
	crc = crc32.Update(crc, crc32.IEEETable, payload)
	binary.BigEndian.PutUint32(size[:], crc)
	dst.Write(size[:])
}

func TestValidateReportImageSuffix(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "phase6", "image_validation")
	image, err := os.ReadFile(filepath.Join(root, "valid.png"))
	if err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(t.TempDir(), "valid.PNG")
	if err := os.WriteFile(upper, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReportImage(context.Background(), upper); err != nil {
		t.Fatalf("case-insensitive PNG suffix: %v", err)
	}
	for _, path := range []string{"image.jpg", "image", "IMAGE.JPEG"} {
		err := ValidateReportImage(context.Background(), path)
		if err == nil || !strings.HasPrefix(err.Error(), "unsupported_report_image_format:") {
			t.Fatalf("%q error = %v", path, err)
		}
	}
}
