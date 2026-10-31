package backends

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

func SHA256(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func SHA256File(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteBytesAtomic publishes through a same-directory temporary file.
func WriteBytesAtomic(path string, data []byte, syncData bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if syncData {
		if err = f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
func WriteJSONAtomic(path string, v any, pretty, sortKeys, newline, syncData bool) error {
	b, e := EncodeJSON(v, pretty, sortKeys, newline)
	if e != nil {
		return e
	}
	return WriteBytesAtomic(path, b, syncData)
}
