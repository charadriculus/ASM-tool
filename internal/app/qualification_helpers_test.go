package app

import (
	"asmtool/internal/report"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func createFreshEvidenceRoot(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("qualification evidence root must be a regular directory")
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("qualification evidence root must be empty")
	}
	return nil
}

func startQualificationHTTPServer(t *testing.T) (*http.Server, int, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	var requests atomic.Int64
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `<!doctype html><html><title>Local qualification</title><a href="/next">next</a></html>`)
			return
		}
		_, _ = io.WriteString(w, `<!doctype html><html><title>Local page</title><p>qualification fixture</p></html>`)
	})}
	go func() { _ = server.Serve(listener) }()
	return server, port, &requests
}

func reserveThenClosePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func hashFileForQualification(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func reportHashes(t *testing.T, outputs report.Outputs) map[string]string {
	t.Helper()
	result := map[string]string{}
	for name, path := range map[string]string{"json": outputs.JSON, "html": outputs.HTML, "pdf": outputs.PDF, "typst": outputs.Typst, "manifest": outputs.Manifest} {
		if path == "" {
			t.Fatalf("report omitted %s output", name)
		}
		result[name] = hashFileForQualification(t, path)
		result[name+"_path"] = filepath.ToSlash(path)
		if name == "pdf" {
			data, err := os.ReadFile(path)
			if err != nil || len(data) < 5 || string(data[:5]) != "%PDF-" {
				t.Fatalf("invalid PDF output %q: %v", path, err)
			}
		}
		if name == "json" {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var parsed map[string]any
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("invalid JSON report %q: %v", path, err)
			}
		}
	}
	return result
}

func copyTreeNoLinks(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("payload contains a link: %s", path)
		}
		if entry.IsDir() {
			return os.MkdirAll(out, info.Mode().Perm())
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, in)
		closeErr := f.Close()
		return errors.Join(copyErr, closeErr)
	})
}

func qualificationDependencyToTamper(t *testing.T, root string) string {
	t.Helper()
	manifestBytes, err := os.ReadFile(filepath.Join(root, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifestBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, file := range bundle.Files {
		lower := strings.ToLower(file.Path)
		if strings.HasSuffix(lower, ".dll") || (strings.HasPrefix(lower, "bin/linux-runtime/") && strings.Contains(filepath.Base(lower), ".so")) {
			return filepath.Join(root, filepath.FromSlash(file.Path))
		}
	}
	return filepath.Join(root, "fonts", "dejavu", "DejaVuSans.ttf")
}

func countEventTypes(t *testing.T, path string) map[string]int {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	counts := map[string]int{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		var item map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		kind, _ := item["event_type"].(string)
		counts[kind]++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return counts
}
