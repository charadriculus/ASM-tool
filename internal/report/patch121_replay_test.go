package report

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Reuse the exact accepted comparison counterexample, keeping its raw rows.
func TestPatch121ReplaysConfirmedHumanWarningCounterexample(t *testing.T) {
	b, err := os.ReadFile("../../planning/progress/g28-evidence/oracle-02/shared-report-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input  Input          `json:"input"`
		Report map[string]any `json:"report"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(f.Report)
	for _, lang := range []string{"en", "ru"} {
		for _, full := range []bool{false, true} {
			in := f.Input
			in.Version = "0.12.1-go"
			in.Language = lang
			in.FullReport = full
			view, err := makeHumanView(context.Background(), in, f.Report, filepath.Join(t.TempDir(), "view"), []byte("hostname\n"))
			if err != nil {
				t.Fatal(err)
			}
			if len(view.Limitations) != 1 || view.Limitations[0].Value != "fixture warning" {
				t.Fatalf("%s full=%v: expected one warning from confirmed counterexample, got %#v", lang, full, view.Limitations)
			}
			if _, err := renderHTML(view); err != nil {
				t.Fatal(err)
			}
			if _, err := renderTypst(view); err != nil {
				t.Fatal(err)
			}
			now, _ := json.Marshal(f.Report)
			if !bytes.Equal(original, now) || len(asList(f.Report["limitations"])) != 3 {
				t.Fatal("machine evidence changed")
			}
		}
	}
}
