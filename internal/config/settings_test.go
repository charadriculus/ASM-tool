package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSettingsAtomicRoundTrip(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "Каталог с пробелом", "settings.yml")
	if lang, e := ReadDefaultReportLanguage(destination); lang != "en" || e != nil {
		t.Fatalf("absent settings: %s %v", lang, e)
	}
	for _, language := range []string{"ru", "en"} {
		if got, e := WriteDefaultReportLanguage(language, destination); e != nil || got != destination {
			t.Fatalf("write: %s %v", got, e)
		}
		if got, e := ReadDefaultReportLanguage(destination); e != nil || got != language {
			t.Fatalf("read: %s %v", got, e)
		}
		if runtime.GOOS != "windows" {
			info, e := os.Stat(destination)
			if e != nil {
				t.Fatal(e)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatal("settings not private")
			}
		}
	}
	old, e := os.ReadFile(destination)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = WriteDefaultReportLanguage("de", destination); e == nil {
		t.Fatal("invalid language written")
	}
	after, e := os.ReadFile(destination)
	if e != nil {
		t.Fatal(e)
	}
	if string(old) != string(after) {
		t.Fatal("validation error destroyed old settings")
	}
	names, e := os.ReadDir(filepath.Dir(destination))
	if e != nil {
		t.Fatal(e)
	}
	if len(names) != 1 {
		t.Fatal("temporary file leaked")
	}
	for _, body := range []string{"reporting: [broken", "reporting: []", "reporting: {default_language: de}", "reporting: {default_language: 123}", "[]", strings.Repeat(" ", MaxConfigBytes+1)} {
		if e = os.WriteFile(destination, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if lang, e := ReadDefaultReportLanguage(destination); lang != "en" || e == nil {
			t.Fatalf("bad settings didn't warn: %s %v", lang, e)
		}
	}
}
func TestSettingsReplaceFailurePreservesDestination(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "settings.yml")
	if e := os.Mkdir(destination, 0700); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(destination, "keep")
	if e := os.WriteFile(marker, []byte("old"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := WriteDefaultReportLanguage("ru", destination); e == nil {
		t.Fatal("replaced directory")
	}
	if b, e := os.ReadFile(marker); e != nil || string(b) != "old" {
		t.Fatal("failed replace lost old data")
	}
	names, e := os.ReadDir(filepath.Dir(destination))
	if e != nil || len(names) != 1 {
		t.Fatal("failed replace leaked temporary file")
	}
	if lang, e := ReadDefaultReportLanguage(destination); lang != "en" || e == nil {
		t.Fatal("directory read did not warn")
	}
}
func TestSettingsPermissionFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions require Unix host")
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "settings.yml")
	if e := os.WriteFile(destination, []byte("reporting:\n  default_language: en\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(parent, 0500); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(parent, 0700)
	_, e := WriteDefaultReportLanguage("ru", destination)
	if e == nil {
		t.Skip("host user bypasses directory permissions")
	}
	if b, e := os.ReadFile(destination); e != nil || !strings.Contains(string(b), "en") {
		t.Fatal("permission failure damaged previous settings")
	}
}

func TestSettingsRejectRemovedAIConfiguration(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "settings.yml")
	for _, body := range []string{"ai_review: null\nreporting: {default_language: ru}\n", "modules: {ai_review: false}\nreporting: {default_language: ru}\n"} {
		if err := os.WriteFile(destination, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if language, err := ReadDefaultReportLanguage(destination); language != "en" || err == nil || !strings.Contains(err.Error(), "ai_review") {
			t.Fatalf("removed AI settings were silently accepted: language=%q err=%v", language, err)
		}
	}
}
