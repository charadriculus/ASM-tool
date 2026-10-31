package execution

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsEnvironmentBlockHasUTF16DoubleTerminator(t *testing.T) {
	b, e := windowsEnvBlock(map[string]string{"LANG": "C", "PATH": "C:\\Windows\\System32", "HOME": "C:\\Users\\Имя"})
	if e != nil {
		t.Fatal(e)
	}
	s := string(utf16.Decode(b))
	if !strings.HasSuffix(s, "\x00\x00") || !strings.Contains(s, "Имя") || strings.Count(s, "HOME=") != 1 {
		t.Fatalf("bad environment block %q", s)
	}
	if _, e = windowsEnvBlock(map[string]string{"X": "a\x00b"}); e == nil {
		t.Fatal("accepted embedded NUL")
	}
}

func TestWindowsSearchPathValidationPreservesUnicodeAndRejectsDelimiter(t *testing.T) {
	if err := validateWindowsSearchPaths([]string{`C:\Program Files\Инструменты`, `C:\Runtime`}); err != nil {
		t.Fatalf("rejected legal search paths: %v", err)
	}
	if err := validateWindowsSearchPaths([]string{`C:\Program Files;Injected`}); err == nil {
		t.Fatal("accepted PATH delimiter inside verified directory")
	}
}
