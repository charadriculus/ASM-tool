package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"asmtool/internal/backends"
	"asmtool/internal/platform"
	"asmtool/internal/storage"
)

func stagedGeneration(t *testing.T, root string, files map[string][]byte, manifest []byte) (string, map[string]string) {
	t.Helper()
	stage, err := os.MkdirTemp(root, ".stage-test-")
	if err != nil {
		t.Fatal(err)
	}
	digests := make(map[string]string, len(files))
	for name, data := range files {
		path := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		digests[name] = backends.SHA256(data)
	}
	if err := os.WriteFile(filepath.Join(stage, "report_manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	return stage, digests
}

func TestPublishGenerationIsContentAddressedAndPreservesOlderResults(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	firstManifest := []byte(`{"run":1}`)
	firstStage, firstFiles := stagedGeneration(t, reports, map[string][]byte{
		"report.html": []byte("first"), "images/image-a.png": []byte("image"),
	}, firstManifest)
	first, moved, err := publishGeneration(ctx, reports, firstStage, firstManifest, firstFiles)
	if err != nil || !moved {
		t.Fatalf("first publish = (%q,%v,%v)", first, moved, err)
	}
	if filepath.Base(first) != "report-"+backends.SHA256(firstManifest) {
		t.Fatalf("generation path is not deterministic: %s", first)
	}

	duplicateStage, duplicateFiles := stagedGeneration(t, reports, map[string][]byte{
		"report.html": []byte("first"), "images/image-a.png": []byte("image"),
	}, firstManifest)
	duplicate, moved, err := publishGeneration(ctx, reports, duplicateStage, firstManifest, duplicateFiles)
	if err != nil || moved || duplicate != first {
		t.Fatalf("duplicate publish = (%q,%v,%v), want existing generation", duplicate, moved, err)
	}
	if _, err := os.Stat(duplicateStage); err != nil {
		t.Fatalf("duplicate stage should remain caller-owned for cleanup: %v", err)
	}

	secondManifest := []byte(`{"run":2}`)
	secondStage, secondFiles := stagedGeneration(t, reports, map[string][]byte{"report.html": []byte("second")}, secondManifest)
	second, moved, err := publishGeneration(ctx, reports, secondStage, secondManifest, secondFiles)
	if err != nil || !moved || second == first {
		t.Fatalf("second publish = (%q,%v,%v)", second, moved, err)
	}
	for _, path := range []string{first, second} {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Fatalf("published generation %q was not preserved: %v", path, err)
		}
	}
}

func TestPublishGenerationCancellationAndTamperedCollision(t *testing.T) {
	reports := t.TempDir()
	manifest := []byte(`{"run":"cancel"}`)
	stage, files := stagedGeneration(t, reports, map[string][]byte{"report.html": []byte("new")}, manifest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, moved, err := publishGeneration(ctx, reports, stage, manifest, files); !errors.Is(err, context.Canceled) || moved {
		t.Fatalf("canceled publish = moved %v, err %v", moved, err)
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatalf("canceled publish consumed stage: %v", err)
	}

	tamperedManifest := []byte(`{"run":"tamper"}`)
	tamperedStage, tamperedFiles := stagedGeneration(t, reports, map[string][]byte{"report.html": []byte("expected")}, tamperedManifest)
	destination := filepath.Join(reports, "report-"+backends.SHA256(tamperedManifest))
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "foreign.txt"), []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, moved, err := publishGeneration(context.Background(), reports, tamperedStage, tamperedManifest, tamperedFiles); err == nil || moved {
		t.Fatalf("tampered collision = moved %v, err %v", moved, err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "foreign.txt")); err != nil || !bytes.Equal(got, []byte("keep me")) {
		t.Fatalf("foreign generation was changed: %q, %v", got, err)
	}
}

// This test is opt-in because the checked Typst binary and bundled fonts are
// distribution assets. It exercises actual native compilation when supplied.
func TestGenerateWithVerifiedTypstIsReproducible(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the authorized native Typst source is Linux-only")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("the authorized native Typst source is amd64-only")
	}
	typstSource := os.Getenv("ASM_PHASE7_TYPST_SOURCE")
	typstSHA := os.Getenv("ASM_PHASE7_TYPST_SHA256")
	fontDir := os.Getenv("ASM_PHASE7_FONT_DIR")
	evidenceDir := os.Getenv("ASM_PHASE7_EVIDENCE_DIR")
	if typstSource == "" || typstSHA == "" || fontDir == "" || evidenceDir == "" {
		t.Skip("authorized Typst source, font directory and evidence directory are not configured")
	}
	const typstSHA256 = "29273eaa04f6d00edd0c2bec578f565fc9c65be856bfbffc894567c68ed0b237"
	if typstSHA != typstSHA256 {
		t.Fatalf("configured Typst SHA-256 differs from the authorized digest")
	}
	verifyFontDigests(t, fontDir)
	bundleRoot := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundleRoot, 0700); err != nil {
		t.Fatal(err)
	}
	toolPath := filepath.Join(bundleRoot, "typst")
	source, err := os.Open(typstSource)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.OpenFile(toolPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
	closeSourceErr := source.Close()
	closeDestinationErr := destination.Close()
	if err := errors.Join(copyErr, closeSourceErr, closeDestinationErr); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != typstSHA256 {
		t.Fatalf("Typst source SHA-256 %s, want authorized digest %s", got, typstSHA256)
	}
	manifest := map[string]any{
		"schema_version": 1,
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"files":          []any{map[string]any{"path": "typst", "sha256": typstSHA256}},
		"tools":          []any{map[string]any{"name": "typst", "executable": "typst", "version": "0.15.1"}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(manifestBytes)
	bundle, err := platform.NewBundle(bundleRoot, hex.EncodeToString(manifestHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	typst, err := bundle.Tool("typst")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	root := t.TempDir()
	database := filepath.Join(root, "asm.sqlite3")
	db, err := storage.Connect(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	in := sampleInput(database, root)
	in.FontDir = fontDir
	in.Profile = "full"
	in.ConfirmedWebTargets = []ConfirmedWebTarget{{Domain: "example.org", InputTarget: true, DNSEvidence: []string{"input_target"}}}
	in.RowLimits = RowLimits{Domain: 1, Document: 1, Screenshot: 1}
	insertObject(t, ctx, db, "domain:example.org", "domain", "example.org", `[]`, `{}`)
	insertObject(t, ctx, db, "domain:api.example.org", "domain", "api.example.org", `["crt.sh"]`, `{"latest":{"event_type":"subdomain_found","metadata":{"label":"Public API"}}}`)
	insertObject(t, ctx, db, "domain:docs.example.org", "domain", "docs.example.org", `["certspotter"]`, `{"latest":{"event_type":"subdomain_found","metadata":{"label":"Documentation"}}}`)
	insertObject(t, ctx, db, "service:192.0.2.10:443", "service", "192.0.2.10:443", `["shodan_internetdb"]`, `{"latest":{"event_type":"port_observed","metadata":{"ip":"192.0.2.10","port":443,"service":{"name":"HTTPS"},"mapped_in_scope_domains":["api.example.org"],"tags":["tls","edge"]}}}`)
	insertEvent(t, ctx, db, "html-title", "html_analyzed", "crawler", "https://example.org/one", map[string]any{
		"title": "Инструкция \"Тест\" & Résumé", "status_code": 200, "target_domain": "example.org",
	})
	for i, value := range []string{"https://example.org/Отчёт%20№1.pdf?download=1&lang=ru", "https://example.org/Руководство.pdf?format=full"} {
		id := []string{"document-one", "document-two"}[i]
		insertEvent(t, ctx, db, id, "crawler_result", "crawler", value, map[string]any{
			"category": "downloadable_resource_detected", "resource_type": "PDF document", "detection_reason": "content_type",
			"status_code": 200, "title": "Документ \"Пример\" & описание", "page_loaded": false,
		})
	}
	insertEvent(t, ctx, db, "crawler-page", "crawler_result", "crawler", "https://example.org/two", map[string]any{
		"category": "page", "page_loaded": true, "target_domains": []any{"example.org"}, "title": "Crawler page",
	})
	insertEvent(t, ctx, db, "crawler-page-unscreened", "crawler_result", "crawler", "https://example.org/three", map[string]any{
		"category": "page", "page_loaded": true, "target_domains": []any{"example.org"}, "title": "Page without a screenshot",
	})
	imageDir := filepath.Join(root, "artifacts", "screenshots")
	if err := os.MkdirAll(imageDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"one.png", "two.png"} {
		imageBytes := new(bytes.Buffer)
		fixturePNG := image.NewRGBA(image.Rect(0, 0, 8, 5))
		fixturePNG.Set(1, 1, color.RGBA{R: uint8(40 + i), G: 90, B: 170, A: 255})
		if err := png.Encode(imageBytes, fixturePNG); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(imageDir, name), imageBytes.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		url := []string{"https://example.org/one", "https://example.org/two"}[i]
		insertEvent(t, ctx, db, "screenshot-"+name, "screenshot_saved", "crawler", url, map[string]any{
			"path": "artifacts/screenshots/" + name, "url": url, "title": "Снимок \"" + name + "\" & Résumé",
			"target_domain": "example.org", "status_code": 200,
		})
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO dns_validations(event_id,hostname,dns_state,active_eligibility,observed_at,data) VALUES(?,?,?,?,?,?)`, "dns-api", "api.example.org", "resolved_clean_parent", "eligible", "2026-10-13T11:04:00Z", `{"wildcard_parent_state":"clean"}`); err != nil {
		t.Fatal(err)
	}
	insertEvent(t, ctx, db, "web-target", "web_target_status", "httpx", "example.org", map[string]any{
		"stage": "root_verification", "status": "loaded", "page_loaded": true,
		"requested_url": "https://example.org/", "final_url": "https://example.org/", "status_code": 200,
	})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"en", "ru"} {
		var boundedHTML, fullHTML string
		for _, full := range []bool{false, true} {
			label := lang + "-bounded"
			if full {
				label = lang + "-full"
			}
			in.Language, in.FullReport = lang, full
			first, err := Generate(ctx, in, typst)
			if err != nil {
				t.Fatalf("%s first generation: %v", label, err)
			}
			second, err := Generate(ctx, in, typst)
			if err != nil {
				t.Fatalf("%s repeat generation: %v", label, err)
			}
			if filepath.Dir(first.JSON) != filepath.Dir(second.JSON) {
				t.Fatalf("%s identical input published to different paths", label)
			}
			assertGenerationBytesEqual(t, filepath.Dir(first.JSON), filepath.Dir(second.JSON))
			jsonBytes, err := os.ReadFile(first.JSON)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := backends.DecodeJSON(jsonBytes)
			if err != nil {
				t.Fatal(err)
			}
			machine := decoded.(map[string]any)
			if got := len(asList(asObject(machine["assets"])["domains"])); got != 3 {
				t.Errorf("%s machine inventory was presentation-truncated: got %d domains", label, got)
			}
			wantMode := "bounded"
			if full {
				wantMode = "full"
			}
			if got := str(asObject(machine["reporting"])["report_mode"]); got != wantMode {
				t.Errorf("%s report mode = %q, want %q", label, got, wantMode)
			}
			if got := reportInt(asObject(machine["summary"])["screenshots"]); got != 2 {
				t.Errorf("%s summary screenshot count = %v, want 2", label, got)
			}
			coverage := asList(machine["web_coverage"])
			if len(coverage) != 1 || reportInt(asObject(coverage[0])["screenshots"]) != 2 || reportInt(asObject(coverage[0])["pages_loaded"]) != 3 || asObject(coverage[0])["screenshot_complete"] != false {
				t.Errorf("%s web coverage did not account for persisted screenshots: %#v", label, coverage)
			}
			firstHTML, err := os.ReadFile(first.HTML)
			if err != nil {
				t.Fatal(err)
			}
			firstTypst, err := os.ReadFile(first.Typst)
			if err != nil {
				t.Fatal(err)
			}
			htmlText := html.UnescapeString(string(firstHTML))
			for _, raw := range []string{`api.example.org`, `Отчёт%20№1.pdf?download=1&lang=ru`, `Инструкция "Тест" & Résumé`} {
				if !strings.Contains(htmlText, raw) && !strings.Contains(string(firstTypst), raw) {
					t.Errorf("%s generated HTML/Typst omitted fixture %q", label, raw)
				}
			}
			if full && !strings.Contains(htmlText, "docs.example.org") {
				t.Errorf("%s full report omitted the second subdomain", label)
			}
			if !full && strings.Contains(htmlText, "docs.example.org") {
				t.Errorf("%s bounded report exceeded its domain row limit", label)
			}
			if !strings.Contains(string(firstHTML), "images/") || !strings.Contains(string(firstTypst), "images/") {
				t.Errorf("%s generated HTML/Typst omitted screenshot resource", label)
			}
			if !strings.Contains(htmlText, "<thead><tr>") || !strings.Contains(htmlText, "HTTPS") || !strings.Contains(string(firstTypst), "#table(columns:") {
				t.Errorf("%s reports omitted specialized tables or service detail", label)
			}
			copyGeneratedGeneration(t, filepath.Dir(first.JSON), filepath.Join(evidenceDir, label))
			if full {
				fullHTML = htmlText
			} else {
				boundedHTML = htmlText
			}
		}
		if strings.Contains(boundedHTML, "Руководство.pdf") || !strings.Contains(fullHTML, "Руководство.pdf") {
			t.Errorf("%s full-report document rows do not differ from bounded presentation", lang)
		}
		if strings.Contains(boundedHTML, "https://example.org/two") || !strings.Contains(fullHTML, "https://example.org/two") {
			t.Errorf("%s full-report screenshots do not differ from bounded presentation", lang)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func verifyFontDigests(t *testing.T, dir string) {
	t.Helper()
	want := map[string]string{
		"DejaVuSans.ttf":             "b4c632e3cdf9acc7f28758fb5a323c8524d7fc6660d46904d9b6cbe2809c419c",
		"DejaVuSans-Bold.ttf":        "e1d733afbbfce842a1b43dced0c9885a76a4e67290dc7e690c4e9b76ebfc7d23",
		"DejaVuSans-Oblique.ttf":     "e6bb3d31b3afd8070753da4bac76ac6f97d99743d0bf070d7fe01336a1f1ae42",
		"DejaVuSans-BoldOblique.ttf": "db536b2436d5823489aec205adfaee70629633dbe6c5c2d135ac6934e522e905",
	}
	for name, digest := range want {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read authorized font %s: %v", name, err)
		}
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != digest {
			t.Fatalf("font %s SHA-256 mismatch", name)
		}
	}
}

func assertGenerationBytesEqual(t *testing.T, firstRoot, secondRoot string) {
	t.Helper()
	first := map[string][]byte{}
	err := filepath.WalkDir(firstRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("generated output is not a regular file")
		}
		rel, err := filepath.Rel(firstRoot, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		first[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second := map[string][]byte{}
	err = filepath.WalkDir(secondRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("generated output is not a regular file")
		}
		rel, err := filepath.Rel(secondRoot, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		second[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("generation file count differs: %d vs %d", len(first), len(second))
	}
	for name, want := range first {
		if got, ok := second[name]; !ok || !bytes.Equal(got, want) {
			t.Errorf("repeated generation differs at %s", name)
		}
	}
}

func copyGeneratedGeneration(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.RemoveAll(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		out := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(out, 0700)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("generated evidence contains a non-regular file")
		}
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(out, data, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
