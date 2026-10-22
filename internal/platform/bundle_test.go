package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func makeBundle(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "tools", "helper with space")
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	payload := []byte("payload")
	if e := os.WriteFile(p, payload, 0700); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(payload)
	m := map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": "tools/helper with space", "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "helper", "executable": "tools/helper with space", "version": "1.0"}}}
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "bundle.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256(b)
	return root, hex.EncodeToString(d[:])
}
func TestBundleDigestAllowlistAndMutation(t *testing.T) {
	root, d := makeBundle(t)
	if _, e := NewBundle(root, "00"); e == nil {
		t.Fatal("accepted wrong trust anchor")
	}
	b, e := NewBundle(root, d)
	if e != nil {
		t.Fatal(e)
	}
	tool, e := b.Tool("helper")
	if e != nil || tool.Path() == "" {
		t.Fatalf("tool: %v", e)
	}
	if e = tool.Verify(); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(tool.Path(), []byte("modified"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = tool.Verify(); e == nil {
		t.Fatal("accepted modified executable")
	}
}

func TestNativeHTTPXIsBlockedAtAcquisitionAndVerification(t *testing.T) {
	root, digest := makeBundle(t)
	b, err := NewBundle(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	base := b.tools["helper"]
	native := Tool{path: base.path, name: "projectdiscovery_httpx", version: "1.8.1", bundle: b}
	b.tools[native.name] = native
	if _, err := b.Tool(native.name); !errors.Is(err, ErrNativeHTTPXBlocked) {
		t.Fatalf("Tool() error=%v", err)
	}
	if err := b.Verify(native); !errors.Is(err, ErrNativeHTTPXBlocked) {
		t.Fatalf("Verify() error=%v", err)
	}
	if err := CheckNativeHTTPX("httpx", "1.8.1"); !errors.Is(err, ErrNativeHTTPXBlocked) {
		t.Fatalf("native executable alias policy error=%v", err)
	}
	windowsAlias := Tool{path: filepath.Join(root, "tools", "httpx.exe"), name: "custom_tool_name", version: "1.8.1", bundle: b}
	b.tools[windowsAlias.name] = windowsAlias
	if _, err := b.Tool(windowsAlias.name); !errors.Is(err, ErrNativeHTTPXBlocked) {
		t.Fatalf("Windows native executable basename policy error=%v", err)
	}
}
func TestBundleRejectsUnlistedAndTraversal(t *testing.T) {
	root, d := makeBundle(t)
	if e := os.WriteFile(filepath.Join(root, "extra"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := NewBundle(root, d); e == nil {
		t.Fatal("accepted unlisted file")
	}
	if _, e := bundlePath(root, "../escape"); e == nil {
		t.Fatal("accepted traversal")
	}
}

func TestVerifyRescansOnlyToolClosureAndRejectsRootReplacement(t *testing.T) {
	root, d := makeBundle(t)
	b, e := NewBundle(root, d)
	if e != nil {
		t.Fatal(e)
	}
	tool, e := b.Tool("helper")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "tools", "unexpected"), []byte("x"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = tool.Verify(); e == nil {
		t.Fatal("accepted new file in tool closure")
	}
	if e = os.Remove(filepath.Join(root, "tools", "unexpected")); e != nil {
		t.Fatal(e)
	}
	moved := root + "-moved"
	if e = os.Rename(root, moved); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(moved, root); e != nil {
		t.Skipf("symlink unsupported: %v", e)
	}
	if e = tool.Verify(); e == nil {
		t.Fatal("accepted replaced bundle root")
	}
}

func TestVerifyRejectsMissingAllowlistedExecutable(t *testing.T) {
	root, digest := makeBundle(t)
	bundle, err := NewBundle(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Tool("helper")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tool.Path()); err != nil {
		t.Fatal(err)
	}
	if err := tool.Verify(); err == nil {
		t.Fatal("accepted missing allowlisted executable")
	}
}

func TestVerifyRehashesNativeCRTAndRejectsMissingFile(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string][]byte{"bin/helper": []byte("exe"), "crt/runtime.dll": []byte("crt")} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := []any{}
	for rel, body := range map[string][]byte{"bin/helper": []byte("exe"), "crt/runtime.dll": []byte("crt")} {
		h := sha256.Sum256(body)
		files = append(files, map[string]any{"path": rel, "sha256": hex.EncodeToString(h[:])})
	}
	manifest, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"files":          files,
		"tools":          []any{map[string]any{"name": "helper", "executable": "bin/helper", "version": "1"}},
		"native_crt":     []string{"crt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifest)
	bundle, err := NewBundle(root, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Tool("helper")
	if err != nil {
		t.Fatal(err)
	}
	if err := tool.Verify(); err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(root, "crt/runtime.dll")
	if err := os.WriteFile(crt, []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := tool.Verify(); err == nil {
		t.Fatal("accepted changed native CRT file")
	}
	if err := os.WriteFile(crt, []byte("crt"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(crt); err != nil {
		t.Fatal(err)
	}
	if err := tool.Verify(); err == nil {
		t.Fatal("accepted missing allowlisted native CRT file")
	}
}

func TestVerifyRejectsReplacedIntermediateAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "bundle-parent")
	root := filepath.Join(parent, "bundle")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "tools", "helper")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("payload"), 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("payload"))
	m, _ := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": "tools/helper", "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "helper", "executable": "tools/helper", "version": "1"}}})
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), m, 0600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(m)
	bundle, err := NewBundle(root, hex.EncodeToString(d[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Tool("helper")
	if err != nil {
		t.Fatal(err)
	}
	moved := parent + "-moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, parent); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := tool.Verify(); err == nil {
		t.Fatal("accepted link introduced in intermediate bundle ancestor")
	}
}

func TestRootLevelToolVerificationAllowsVerifiedManifest(t *testing.T) {
	root := t.TempDir()
	payload := []byte("root-tool")
	toolPath := filepath.Join(root, "helper")
	if err := os.WriteFile(toolPath, payload, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(payload)
	manifest, err := json.Marshal(map[string]any{"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH, "files": []any{map[string]any{"path": "helper", "sha256": hex.EncodeToString(h[:])}}, "tools": []any{map[string]any{"name": "helper", "executable": "helper", "version": "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(manifest)
	bundle, err := NewBundle(root, hex.EncodeToString(d[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Tool("helper")
	if err != nil {
		t.Fatal(err)
	}
	if err := tool.Verify(); err != nil {
		t.Fatalf("root-level tool rejected: %v", err)
	}
}

func TestLinuxRuntimeCommandUsesOnlyFixedLoaderAndKeepsToolPath(t *testing.T) {
	root := t.TempDir()
	bundle := &Bundle{root: root, linuxRuntime: &LinuxRuntimeSpec{
		Loader: "bin/linux-runtime/ld-linux-x86-64.so.2", LibraryDir: "bin/linux-runtime", Tools: []string{"subfaster"},
	}}
	tool := Tool{path: filepath.Join(root, "bin/subfaster"), name: "subfaster", bundle: bundle}
	got := tool.Command([]string{"-version"})
	want := []string{
		filepath.Join(root, "bin/linux-runtime/ld-linux-x86-64.so.2"),
		"--inhibit-cache", "--library-path", filepath.Join(root, "bin/linux-runtime"),
		filepath.Join(root, "bin/subfaster"), "-version",
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		want = []string{tool.Path(), "-version"}
	}
	if len(got) != len(want) {
		t.Fatalf("command=%q want=%q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command=%q want=%q", got, want)
		}
	}
	if got := (Tool{path: filepath.Join(root, "bin/typst"), name: "typst", bundle: bundle}).Command([]string{"--version"}); len(got) != 2 || got[0] != filepath.Join(root, "bin/typst") {
		t.Fatalf("undeclared runtime tool unexpectedly used loader: %q", got)
	}
}

func TestBundleAuthenticatesLinuxRuntimeELFClosure(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Linux x86-64 runtime only")
	}
	loaderSource := firstExisting(t, "/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
	libcSource := firstExisting(t, "/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6")
	toolSource := firstExisting(t, "/bin/true", "/usr/bin/true")
	root := t.TempDir()
	files := map[string]string{
		"bin/linux-runtime/ld-linux-x86-64.so.2": loaderSource,
		"bin/linux-runtime/libc.so.6":            libcSource,
		"bin/subfaster":                          toolSource,
	}
	var manifestFiles []any
	for rel, source := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		var body []byte
		var err error
		body, err = os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0700); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(body)
		manifestFiles = append(manifestFiles, map[string]any{"path": rel, "sha256": hex.EncodeToString(h[:])})
	}
	m, err := json.Marshal(map[string]any{
		"schema_version": 1, "platform": "linux/amd64", "files": manifestFiles,
		"tools":         []any{map[string]any{"name": "subfaster", "executable": "bin/subfaster", "version": "test"}},
		"linux_runtime": map[string]any{"loader": "bin/linux-runtime/ld-linux-x86-64.so.2", "library_dir": "bin/linux-runtime", "tools": []string{"subfaster"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), m, 0600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(m)
	bundle, err := NewBundle(root, hex.EncodeToString(d[:]))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Tool("subfaster")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("nested library cannot fall back to host", func(t *testing.T) {
		var doc map[string]any
		if err := json.Unmarshal(m, &doc); err != nil {
			t.Fatal(err)
		}
		rel := "bin/linux-runtime/nested/libc.so.6"
		dest := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(root, "bin/linux-runtime/libc.so.6"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, body, 0600); err != nil {
			t.Fatal(err)
		}
		for _, v := range doc["files"].([]any) {
			row := v.(map[string]any)
			if row["path"] == "bin/linux-runtime/libc.so.6" {
				row["path"] = rel
			}
		}
		bad, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "bundle.json"), bad, 0600); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(bad)
		if _, err := NewBundle(root, hex.EncodeToString(h[:])); err == nil || !strings.Contains(err.Error(), "immediate library filename") {
			t.Fatalf("nested SONAME accepted or wrong reason: %v", err)
		}
		if err := os.Remove(dest); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "bundle.json"), m, 0600); err != nil {
			t.Fatal(err)
		}
	})
	if err := tool.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/linux-runtime/libc.so.6"), []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := tool.Verify(); err == nil {
		t.Fatal("accepted changed loader library")
	}
}

func firstExisting(t *testing.T, paths ...string) string {
	t.Helper()
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	t.Skip("system Linux loader/libc fixture is unavailable")
	return ""
}

func TestBundlePathAcceptsOrdinaryNamesAndRejectsDevices(t *testing.T) {
	root := t.TempDir()
	for _, valid := range []string{"bin/subfaster", "bin/assets/helper.lua", "bin/LPTx.dat"} {
		if _, err := bundlePath(root, valid); err != nil {
			t.Fatalf("valid Nmap resource %q: %v", valid, err)
		}
	}
	for _, bad := range []string{"bin/COM1.lua", "bin/LPT9", "bin/COM¹.txt"} {
		if _, err := bundlePath(root, bad); err == nil {
			t.Fatalf("device accepted: %q", bad)
		}
	}
}

func TestBundleRejectsNmapManifest(t *testing.T) {
	root := t.TempDir()
	body := []byte("fixture")
	path := filepath.Join(root, "bin", "nmap")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	manifest, err := json.Marshal(map[string]any{
		"schema_version": 1, "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"files": []any{map[string]any{"path": "bin/nmap", "sha256": hex.EncodeToString(digest[:])}},
		"tools": []any{map[string]any{"name": "nmap", "executable": "bin/nmap", "version": "7.98"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	if _, err := NewBundle(root, hex.EncodeToString(manifestDigest[:])); err == nil || !strings.Contains(err.Error(), "Nmap") {
		t.Fatalf("Nmap manifest accepted: %v", err)
	}
}
