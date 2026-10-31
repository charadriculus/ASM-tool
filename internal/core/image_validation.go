package core

import (
	"bufio"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var pngSignature = [8]byte{137, 80, 78, 71, 13, 10, 26, 10}

// ValidatePNGFile checks PNG framing, chunk CRCs and a non-empty zlib stream.
// Callers should pass a private staged file and keep it stable through publication.
func ValidatePNGFile(ctx context.Context, path string) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read_error:%T:%w", err, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return errors.New("not_regular_file")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read_error:%T:%w", err, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("read_error:%T:%w", err, err)
	}
	if !st.Mode().IsRegular() || !os.SameFile(pathInfo, st) {
		return errors.New("not_regular_file")
	}
	if st.Size() < int64(len(pngSignature)) {
		return errors.New("invalid_png_signature")
	}
	var sig [8]byte
	if _, err := io.ReadFull(f, sig[:]); err != nil {
		return fmt.Errorf("read_error:%T:%w", err, err)
	}
	if sig != pngSignature {
		return errors.New("invalid_png_signature")
	}

	sawIHDR, sawIDAT, sawIEND := false, false, false
	var idatBytes, iendEnd int64
	crcBuf := make([]byte, 32*1024)
	for offset := int64(8); offset < st.Size(); {
		if err := ctx.Err(); err != nil {
			return err
		}
		if st.Size()-offset < 12 {
			return errors.New("truncated_png_chunk_header")
		}
		var head [8]byte
		if _, err := f.ReadAt(head[:], offset); err != nil {
			return fmt.Errorf("read_error:%T:%w", err, err)
		}
		n := int64(binary.BigEndian.Uint32(head[:4]))
		kind := head[4:]
		end := offset + 8 + n
		crcEnd := end + 4
		label := string(kind)
		if crcEnd > st.Size() || crcEnd < offset {
			return fmt.Errorf("truncated_png_chunk:%s", label)
		}
		crc := crc32.Update(0, crc32.IEEETable, kind)
		payload := io.NewSectionReader(f, offset+8, n)
		remaining := n
		for remaining > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			readSize := int64(len(crcBuf))
			if readSize > remaining {
				readSize = remaining
			}
			if _, err := io.ReadFull(payload, crcBuf[:readSize]); err != nil {
				return fmt.Errorf("read_error:%T:%w", err, err)
			}
			crc = crc32.Update(crc, crc32.IEEETable, crcBuf[:readSize])
			remaining -= readSize
		}
		var got [4]byte
		if _, err := f.ReadAt(got[:], end); err != nil {
			return fmt.Errorf("read_error:%T:%w", err, err)
		}
		actual, expected := crc, binary.BigEndian.Uint32(got[:])
		if actual != expected {
			return fmt.Errorf("png_crc_mismatch:%s:expected=%08x:actual=%08x", label, expected, actual)
		}
		switch label {
		case "IHDR":
			if sawIHDR || n != 13 {
				return errors.New("invalid_png_ihdr")
			}
			var dims [8]byte
			if _, err := f.ReadAt(dims[:], offset+8); err != nil {
				return fmt.Errorf("read_error:%T:%w", err, err)
			}
			if binary.BigEndian.Uint32(dims[:4]) == 0 || binary.BigEndian.Uint32(dims[4:]) == 0 {
				return errors.New("invalid_png_dimensions")
			}
			sawIHDR = true
		case "IDAT":
			sawIDAT = true
			idatBytes += n
		case "IEND":
			if n != 0 {
				return errors.New("invalid_png_iend")
			}
			sawIEND, iendEnd = true, crcEnd
			goto framed
		}
		offset = crcEnd
	}
framed:
	if !sawIHDR {
		return errors.New("missing_png_ihdr")
	}
	if !sawIDAT || idatBytes == 0 {
		return errors.New("missing_png_idat")
	}
	if !sawIEND {
		return errors.New("missing_png_iend")
	}
	if iendEnd != st.Size() {
		return errors.New("trailing_bytes_after_png_iend")
	}

	reader := &pngIDATReader{ctx: ctx, f: f, size: st.Size(), pos: 8}
	zr, err := zlib.NewReader(bufio.NewReaderSize(reader, 32*1024))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("png_idat_decode_error:%T:%w", err, err)
	}
	if err := ctx.Err(); err != nil {
		_ = zr.Close()
		return err
	}
	buf := make([]byte, 32*1024)
	var decoded int64
	for {
		if err := ctx.Err(); err != nil {
			_ = zr.Close()
			return err
		}
		n, readErr := zr.Read(buf)
		decoded += int64(n)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = zr.Close()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("png_idat_decode_error:%T:%w", readErr, readErr)
		}
	}
	if err := zr.Close(); err != nil {
		return fmt.Errorf("png_idat_decode_error:%T:%w", err, err)
	}
	if decoded == 0 {
		return errors.New("empty_png_pixel_stream")
	}
	return nil
}

// ValidateReportImage accepts only .png report image paths.
func ValidateReportImage(ctx context.Context, path string) error {
	suffix := strings.ToLower(filepath.Ext(path))
	if suffix != ".png" {
		if suffix == "" {
			suffix = "<none>"
		}
		return fmt.Errorf("unsupported_report_image_format:%s", suffix)
	}
	return ValidatePNGFile(ctx, path)
}

type pngIDATReader struct {
	ctx                   context.Context
	f                     *os.File
	size, pos             int64
	chunkPos, chunkRemain int64
}

func (r *pngIDATReader) Read(p []byte) (int, error) {
	for len(p) > 0 {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if r.chunkRemain > 0 {
			if int64(len(p)) > r.chunkRemain {
				p = p[:r.chunkRemain]
			}
			n, err := r.f.ReadAt(p, r.chunkPos)
			r.chunkPos += int64(n)
			r.chunkRemain -= int64(n)
			return n, err
		}
		if r.pos >= r.size {
			return 0, io.EOF
		}
		var head [8]byte
		if _, err := r.f.ReadAt(head[:], r.pos); err != nil {
			return 0, err
		}
		n := int64(binary.BigEndian.Uint32(head[:4]))
		kind := string(head[4:])
		start := r.pos + 8
		r.pos = start + n + 4
		if kind == "IDAT" && n != 0 {
			r.chunkPos, r.chunkRemain = start, n
		}
	}
	return 0, io.EOF
}
