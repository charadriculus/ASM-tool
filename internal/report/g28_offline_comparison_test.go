package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestG28OfflineComparisonViews is an opt-in bridge for the developer-only
// G28 oracle. It renders supplied JSON input only; it does not read SQLite,
// invoke Typst, or perform runtime collection.
func TestG28OfflineComparisonViews(t *testing.T) {
	root := os.Getenv("ASM_G28_DIR")
	if root == "" {
		t.Skip("set ASM_G28_DIR to a fresh G28 evidence directory")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "shared-report-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input  Input          `json:"input"`
		Report map[string]any `json:"report"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Input.TargetDomain == "" || fixture.Report == nil {
		t.Fatal("shared report fixture must supply input.TargetDomain and report")
	}
	stageDir, err := os.MkdirTemp(root, ".g28-stage-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stageDir) })
	for _, language := range []string{"en", "ru"} {
		for _, full := range []bool{false, true} {
			input := fixture.Input
			input.Language, input.FullReport = language, full
			view, err := makeHumanView(context.Background(), input, fixture.Report, stageDir)
			if err != nil {
				t.Fatalf("make view %s full=%t: %v", language, full, err)
			}
			suffix := language + "-bounded"
			if full {
				suffix = language + "-full"
			}
			jsonBytes, err := json.MarshalIndent(view, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			htmlBytes, err := renderHTML(view)
			if err != nil {
				t.Fatalf("render HTML %s: %v", suffix, err)
			}
			typBytes, err := renderTypst(view)
			if err != nil {
				t.Fatalf("render Typst %s: %v", suffix, err)
			}
			for ext, content := range map[string][]byte{"json": append(jsonBytes, '\n'), "html": htmlBytes, "typ": typBytes} {
				path := filepath.Join(root, "go-view-"+suffix+"."+ext)
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					t.Fatalf("create new view %s: %v", path, err)
				}
				if _, err := f.Write(content); err != nil {
					_ = f.Close()
					t.Fatalf("write view %s: %v", path, err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("close view %s: %v", path, err)
				}
			}
		}
	}
}
