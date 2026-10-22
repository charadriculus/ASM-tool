package path

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSourcePlatformPaths(t *testing.T) {
	home := func() (string, error) { return filepath.FromSlash("/users/Имя с пробелом"), nil }
	env := func(key string) string {
		switch key {
		case "LOCALAPPDATA":
			return filepath.FromSlash("/local/Данные")
		case "XDG_CONFIG_HOME":
			return filepath.FromSlash("/isolated/config")
		}
		return ""
	}
	for _, c := range []struct {
		OS   string
		Fn   func(string, func(string) string, func() (string, error)) (string, error)
		Want string
	}{{"windows", defaultOutputRoot, "/local/Данные/ASM Tool/runs"}, {"windows", settingsPath, "/local/Данные/ASM Tool/config/settings.yml"}, {"linux", defaultOutputRoot, "runs"}, {"linux", settingsPath, "/isolated/config/asm-tool/settings.yml"}} {
		got, e := c.Fn(c.OS, env, home)
		if e != nil || got != filepath.FromSlash(c.Want) {
			t.Errorf("%s got %q %v want %q", c.OS, got, e, c.Want)
		}
	}
	emptyEnv := func(string) string { return "" }
	if got, e := settingsPath("linux", emptyEnv, home); e != nil || got != filepath.FromSlash("/users/Имя с пробелом/.config/asm-tool/settings.yml") {
		t.Fatalf("fallback %q %v", got, e)
	}
	if got, e := defaultOutputRoot("windows", emptyEnv, home); e != nil || got != filepath.FromSlash("/users/Имя с пробелом/AppData/Local/ASM Tool/runs") {
		t.Fatalf("Windows fallback %q %v", got, e)
	}
	failedHome := func() (string, error) { return "", errors.New("missing home") }
	if _, e := settingsPath("linux", emptyEnv, failedHome); e == nil {
		t.Fatal("home error hidden")
	}
	if _, e := defaultOutputRoot("windows", emptyEnv, failedHome); e == nil {
		t.Fatal("Windows home error hidden")
	}
}
