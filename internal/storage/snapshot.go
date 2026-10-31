package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

func OpenImmutable(path string) (*sql.DB, error) {
	if e := checkNoSymlink(path, true); e != nil {
		return nil, e
	}
	if _, e := fingerprint(path); e != nil {
		return nil, e
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm", path + "-journal"} {
		if e := checkNoSymlink(sidecar, false); e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	for _, sidecar := range []string{path + "-wal", path + "-journal"} {
		if st, e := os.Stat(sidecar); e == nil && st.Size() > 0 {
			return nil, errors.New("immutable SQLite open refuses nonempty WAL/journal; use CopyLegacySnapshot")
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	dsn, e := sqliteFileDSN(abs, "mode=ro&immutable=1")
	if e != nil {
		return nil, e
	}
	return sql.Open("sqlite", dsn)
}

func sqliteFileDSN(path, query string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	uri := sqliteFileURI(abs, runtime.GOOS == "windows")
	if query != "" {
		uri += "?" + query
	}
	return uri, nil
}

func sqliteFileURI(abs string, windows bool) string {
	p := filepath.ToSlash(abs)
	if windows {
		p = strings.ReplaceAll(abs, "\\", "/")
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

type LegacySnapshot struct {
	DB       *sql.DB
	dir      string
	path     string
	once     sync.Once
	closeErr error
}

func OpenLegacySnapshot(ctx context.Context, source string) (*LegacySnapshot, error) {
	dir, e := os.MkdirTemp(os.TempDir(), "asm-legacy-read-")
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, filepath.Base(source))
	if e = CopyLegacySnapshot(ctx, source, path); e != nil {
		return nil, errors.Join(e, os.RemoveAll(dir))
	}
	db, e := OpenImmutable(path)
	if e == nil {
		e = db.PingContext(ctx)
	}
	if e != nil {
		if db != nil {
			e = errors.Join(e, db.Close())
		}
		return nil, errors.Join(e, os.RemoveAll(dir))
	}
	return &LegacySnapshot{DB: db, dir: dir, path: path}, nil
}
func (s *LegacySnapshot) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.closeErr = s.DB.Close()
		if e := os.RemoveAll(s.dir); s.closeErr == nil {
			s.closeErr = e
		}
	})
	return s.closeErr
}

type sourceFingerprint struct {
	present bool
	size    int64
	hash    string
	info    os.FileInfo
}

// CopyLegacySnapshot requires a stopped writer. Fingerprints detect observed changes;
// they do not lock the source. SQLite recovery runs only against the scratch copy.
func CopyLegacySnapshot(ctx context.Context, source, destination string) (retErr error) {
	src, e := filepath.Abs(source)
	if e != nil {
		return e
	}
	if e = checkNoSymlink(src, true); e != nil {
		return e
	}
	src, e = filepath.EvalSymlinks(src)
	if e != nil {
		return e
	}
	dst, e := filepath.Abs(destination)
	if e != nil {
		return e
	}
	if e = checkNoSymlink(filepath.Dir(dst), true); e != nil {
		return e
	}
	if _, e = os.Lstat(dst); e == nil {
		return errors.New("snapshot destination already exists")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	dstDir, e := filepath.EvalSymlinks(filepath.Dir(dst))
	if e != nil {
		return e
	}
	dst = filepath.Join(dstDir, filepath.Base(dst))
	if dst == src {
		return errors.New("snapshot destination aliases source")
	}

	sidecars := []string{src + "-wal", src + "-shm", src + "-journal"}
	for _, p := range sidecars {
		if e = checkNoSymlink(p, false); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	before, e := sourceHashes(src)
	if e != nil {
		return e
	}
	if !before[src].present {
		return errors.New("legacy SQLite source disappeared before snapshot")
	}
	if before[src+"-journal"].present && before[src+"-journal"].size > 0 {
		return errors.New("nonempty SQLite rollback journal requires offline recovery before snapshot")
	}

	sourceDir := filepath.Dir(src)
	if within(sourceDir, dstDir) {
		return errors.New("snapshot destination must be outside legacy database directory")
	}
	// Staging on the destination filesystem makes publication a single atomic,
	// no-clobber filesystem operation (including destinations on FAT/exFAT).
	scratch, e := os.MkdirTemp(dstDir, ".asm-sqlite-copy-")
	if e != nil {
		return e
	}
	defer func() {
		if cleanupErr := os.RemoveAll(scratch); cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove SQLite snapshot staging: %w", cleanupErr))
		}
	}()

	staged := filepath.Join(scratch, filepath.Base(src))
	for _, p := range append([]string{src}, sidecars...) {
		fp, ok := before[p]
		if !ok || !fp.present {
			continue
		}
		to := staged + strings.TrimPrefix(p, src)
		if e = copyFile(p, to); e != nil {
			return e
		}
		copied, e := fingerprint(to)
		if e != nil {
			return e
		}
		if copied.hash != fp.hash || copied.size != fp.size {
			return fmt.Errorf("copied SQLite input failed fingerprint check: %s", p)
		}
	}
	walFrames := int64(0)
	if fp := before[src+"-wal"]; fp.present && fp.size > 0 {
		walFrames, e = sqliteWALFrameCount(filepath.Join(scratch, filepath.Base(src)+"-wal"))
		if e != nil {
			return e
		}
	}
	// SHM is a rebuildable index. Removing the copied image forces SQLite to
	// validate and reconstruct it from WAL on the private copy.
	if e = os.Remove(staged + "-shm"); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	middle, e := sourceHashes(src)
	if e != nil {
		return e
	}
	if !sameHashes(before, middle) {
		return errors.New("legacy SQLite source changed while being copied")
	}

	stagedDSN, e := sqliteFileDSN(staged, "")
	if e != nil {
		return e
	}
	db, e := sql.Open("sqlite", stagedDSN)
	if e != nil {
		return e
	}
	db.SetMaxOpenConns(1)
	if walFrames > 0 {
		var busy, logFrames, checkpointed int
		if e = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(FULL)").Scan(&busy, &logFrames, &checkpointed); e != nil {
			_ = db.Close()
			return fmt.Errorf("validate copied SQLite WAL: %w", e)
		}
		if busy != 0 || int64(logFrames) != walFrames || logFrames != checkpointed {
			_ = db.Close()
			return fmt.Errorf("incomplete SQLite WAL recovery: busy=%d log=%d checkpointed=%d physical=%d", busy, logFrames, checkpointed, walFrames)
		}
	}
	outputDir := filepath.Join(scratch, "snapshot-output")
	if e = os.Mkdir(outputDir, 0700); e != nil {
		_ = db.Close()
		return e
	}
	vacuumPath := filepath.Join(outputDir, "snapshot.sqlite3")
	_, e = db.ExecContext(ctx, "VACUUM INTO ?", vacuumPath)
	closeErr := db.Close()
	if e != nil {
		return errors.Join(e, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}

	verifyDSN, e := sqliteFileDSN(vacuumPath, "")
	if e != nil {
		return e
	}
	verify, e := sql.Open("sqlite", verifyDSN)
	if e != nil {
		return e
	}
	var integrity string
	e = verify.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity)
	closeErr = verify.Close()
	if e != nil {
		return errors.Join(e, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if integrity != "ok" {
		return fmt.Errorf("snapshot integrity check failed: %s", integrity)
	}
	if e = os.Chmod(vacuumPath, 0600); e != nil {
		return e
	}
	file, e := os.OpenFile(vacuumPath, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	e = file.Sync()
	closeErr = file.Close()
	if e != nil || closeErr != nil {
		return errors.Join(e, closeErr)
	}

	after, e := sourceHashes(src)
	if e != nil {
		return e
	}
	if !sameHashes(before, after) {
		return errors.New("legacy SQLite source changed during snapshot")
	}
	// The platform helper must publish atomically without replacing a racing
	// destination. The temporary directory is removed on return.
	if e = publishSnapshot(vacuumPath, dst); e != nil {
		return fmt.Errorf("publish exclusive SQLite snapshot: %w", e)
	}
	return nil
}

func sqliteWALFrameCount(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var header [32]byte
	if _, err = io.ReadFull(f, header[:]); err != nil {
		return 0, fmt.Errorf("truncated SQLite WAL header: %w", err)
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		return 0, errors.New("invalid SQLite WAL magic")
	}
	if binary.BigEndian.Uint32(header[4:8]) != 3007000 {
		return 0, errors.New("unsupported SQLite WAL format version")
	}
	pageSize := binary.BigEndian.Uint32(header[8:12])
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return 0, errors.New("invalid SQLite WAL page size")
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	frameSize := int64(24 + pageSize)
	payload := st.Size() - 32
	if payload <= 0 || payload%frameSize != 0 {
		return 0, errors.New("SQLite WAL has a truncated or empty frame tail")
	}
	return payload / frameSize, nil
}

func fingerprint(path string) (sourceFingerprint, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return sourceFingerprint{}, e
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return sourceFingerprint{}, fmt.Errorf("refusing non-regular SQLite source file %s", path)
	}
	f, e := os.Open(path)
	if e != nil {
		return sourceFingerprint{}, e
	}
	h := sha256.New()
	size, e := io.Copy(h, f)
	closeErr := f.Close()
	if e != nil {
		return sourceFingerprint{}, e
	}
	if closeErr != nil {
		return sourceFingerprint{}, closeErr
	}
	return sourceFingerprint{present: true, size: size, hash: hex.EncodeToString(h.Sum(nil)), info: st}, nil
}
func sourceHashes(path string) (map[string]sourceFingerprint, error) {
	out := map[string]sourceFingerprint{}
	for _, p := range append([]string{path}, path+"-wal", path+"-shm", path+"-journal") {
		fp, e := fingerprint(p)
		if errors.Is(e, os.ErrNotExist) {
			out[p] = sourceFingerprint{}
			continue
		}
		if e != nil {
			return nil, e
		}
		out[p] = fp
	}
	return out, nil
}
func sameHashes(a, b map[string]sourceFingerprint) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		other, ok := b[k]
		if !ok || v.present != other.present || v.size != other.size || v.hash != other.hash || (v.present && !os.SameFile(v.info, other.info)) {
			return false
		}
	}
	return true
}
func within(parent, path string) bool {
	rel, e := filepath.Rel(parent, path)
	return e == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}
func checkNoSymlink(path string, leafMustExist bool) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	volume := filepath.VolumeName(abs)
	cur := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.Trim(strings.TrimPrefix(abs, volume), string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		st, x := os.Lstat(cur)
		if errors.Is(x, os.ErrNotExist) && !leafMustExist {
			return nil
		}
		if x != nil {
			return x
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink path component %s", cur)
		}
	}
	return nil
}
func copyFile(from, to string) error {
	in, e := os.Open(from)
	if e != nil {
		return e
	}
	defer in.Close()
	info, e := in.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing non-regular SQLite input")
	}
	out, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
