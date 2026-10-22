package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"asmtool/internal/core"
)

func TestDownloadableResourceInfoSourceRules(t *testing.T) {
	if _, ok := DownloadableResourceInfo("https://example.test/file.html", "text/html; charset=utf-8", ""); ok {
		t.Fatal("HTML response should not be classified as a download")
	}
	if _, ok := DownloadableResourceInfo("https://example.test/file.json", "application/json", ""); ok {
		t.Fatal("JSON response should not be classified as a download")
	}
	got, ok := DownloadableResourceInfo("https://example.test/file.DOCX?download=1", "", "")
	if !ok || got.ResourceType != "Word document" || got.Extension != ".docx" || got.ContentType == "" {
		t.Fatalf("extension classification = %#v, %v", got, ok)
	}
	got, ok = DownloadableResourceInfo("https://example.test/resource", "image/png; charset=binary", "inline attachment; filename=x")
	if !ok || got.ResourceType != "image" || got.ContentType != "image/png" || got.ContentDisposition != "inline attachment; filename=x" {
		t.Fatalf("response-header classification = %#v, %v", got, ok)
	}
	got, ok = DownloadableResourceInfo("https://example.test/resource", "text/plain", "attachment; filename=x")
	if !ok || got.ResourceType != "downloadable resource" || got.ContentType != "text/plain" {
		t.Fatalf("attachment classification = %#v, %v", got, ok)
	}
}

func TestDownloadableResourceMIMEFallback(t *testing.T) {
	for path, want := range map[string]string{
		"archive.tar.gz": "application/x-tar", "archive.tar.bz2": "application/x-tar",
		"archive.tar.xz": "application/x-tar", "archive.gz": "application/octet-stream",
		"archive.bz2": "application/octet-stream", "archive.xz": "application/octet-stream",
		"report.pdf.gz": "application/pdf", "report.svg.xz": "image/svg+xml",
		"document.docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	} {
		got, ok := DownloadableResourceInfo("https://example.test/"+path, "", "")
		if !ok || got.ContentType != want {
			t.Errorf("%s content type = %q, %v; want %q", path, got.ContentType, ok, want)
		}
	}
}

func TestNewDownloadEventMetadata(t *testing.T) {
	status := 206
	event, err := NewDownloadEvent(DownloadEventInput{
		Module: "crawler", SourceTool: "fixture", URL: "HTTPS://Example.Test/a.zip?x=1",
		TargetDomains: []string{"b.test", "a.test", "a.test"}, Phase: "verify", Depth: 2,
		StatusCode: &status, ContentType: "application/zip; charset=binary", NetworkContacted: true,
		DetectionReason: "response_headers",
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.EventType != core.CrawlerResult || event.ScopeStatus != core.InScope || event.Confidence != 0.9 {
		t.Fatalf("event identity/confidence = %#v", event)
	}
	if event.Metadata["origin"] != "https://example.test" || event.Metadata["category"] != "downloadable_resource_detected" ||
		event.Metadata["target_domains"] == nil || !reflect.DeepEqual(event.Metadata["target_domains"], []string{"a.test", "b.test"}) ||
		event.Metadata["status_code"] != 206 || event.Metadata["downloaded"] != false ||
		event.Metadata["screenshot_expected"] != false || event.Metadata["network_contacted"] != true {
		t.Fatalf("download metadata = %#v", event.Metadata)
	}
}

func TestScreenshotCoverageReconciliation(t *testing.T) {
	dir := t.TempDir()
	writeEvents(t, filepath.Join(dir, "web.jsonl"),
		eventRecord(t, core.HTMLAnalyzed, core.InScope, "https://a.test/z", map[string]any{"target_domain": "a.test"}),
		eventRecord(t, core.HTMLAnalyzed, core.InScope, "https://a.test/a", map[string]any{"target_domains": []string{"a.test"}}),
		eventRecord(t, core.HTMLAnalyzed, core.OutOfScope, "https://a.test/out", map[string]any{"target_domain": "a.test"}),
	)
	writeEvents(t, filepath.Join(dir, "crawler.jsonl"),
		eventRecord(t, core.CrawlerResult, core.InScope, "https://a.test/z", map[string]any{"target_domain": "a.test"}),
		eventRecord(t, core.CrawlerResult, core.InScope, "https://b.test/loaded", map[string]any{"target_domain": "b.test"}),
		eventRecord(t, core.CrawlerResult, core.InScope, "https://b.test/not-loaded", map[string]any{"target_domain": "b.test", "page_loaded": false}),
		eventRecord(t, core.CrawlerResult, core.InScope, "https://b.test/no-screenshot", map[string]any{"target_domain": "b.test", "screenshot_expected": false}),
		eventRecord(t, core.Limitation, core.InScope, "https://a.test/ignored", map[string]any{"target_domain": "a.test"}),
	)
	writeEvents(t, filepath.Join(dir, "screenshots.jsonl"),
		eventRecord(t, core.ScreenshotSaved, core.OutOfScope, "https://a.test/a", map[string]any{"target_domain": "a.test"}),
	)
	got, err := ScreenshotCoverage(dir, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].NormalizedValue != "https://a.test/z" || got[1].NormalizedValue != "https://b.test/loaded" {
		t.Fatalf("missing coverage = %#v", got)
	}
	for _, event := range got {
		if event.EventType != core.Limitation || event.ScopeStatus != core.InScope || event.Confidence != 0 ||
			event.Metadata["page_loaded"] != true || event.Metadata["revisit_performed"] != false || event.Metadata["severity"] != "warning" {
			t.Fatalf("coverage limitation = %#v", event)
		}
	}
	if events, err := ScreenshotCoverage(filepath.Join(dir, "missing"), true, true); err != nil || len(events) != 0 {
		t.Fatalf("passive skip = %v, %v", events, err)
	}
	if events, err := ScreenshotCoverage(filepath.Join(dir, "missing"), false, false); err != nil || len(events) != 0 {
		t.Fatalf("disabled skip = %v, %v", events, err)
	}
}

func TestScreenshotCoverageFailsClosedOnInvalidJSONL(t *testing.T) {
	for name, line := range map[string]string{"malformed": "{", "schema-invalid": `{"unexpected":true}`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			filename := filepath.Join(dir, "crawler.jsonl")
			if err := os.WriteFile(filename, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ScreenshotCoverage(dir, false, true)
			if err == nil || !strings.Contains(err.Error(), filename+":1:") {
				t.Fatalf("error = %v; want path and line context", err)
			}
		})
	}
}

func TestDownloadEventJSONLDoesNotCreateScreenshotCoverage(t *testing.T) {
	dir := t.TempDir()
	event, err := NewDownloadEvent(DownloadEventInput{
		Module: "crawler", SourceTool: "fixture", URL: "https://a.test/file.pdf",
		TargetDomains: []string{"a.test"}, ContentType: "application/pdf",
	})
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, filepath.Join(dir, "crawler.jsonl"), line)
	got, err := ScreenshotCoverage(dir, false, true)
	if err != nil || len(got) != 0 {
		t.Fatalf("download event coverage = %#v, %v", got, err)
	}
}

func eventRecord(t *testing.T, kind core.EventType, scope core.ScopeStatus, value string, metadata map[string]any) []byte {
	t.Helper()
	event, err := core.NewEvent(kind, "fixture", "fixture", value, value, scope)
	if err != nil {
		t.Fatal(err)
	}
	event.Metadata = metadata
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeEvents(t *testing.T, filename string, lines ...[]byte) {
	t.Helper()
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if _, err = f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
