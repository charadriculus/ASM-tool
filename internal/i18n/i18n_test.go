package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
)

func TestEntireSourceCatalog(t *testing.T) {
	pattern := regexp.MustCompile(`\{([^{}]+)\}`)
	for _, language := range []string{"en", "ru"} {
		b, e := os.ReadFile("../../testdata/phase1/catalog_" + language + ".json")
		if e != nil {
			t.Fatal(e)
		}
		var expected map[string]string
		if e = json.Unmarshal(b, &expected); e != nil {
			t.Fatal(e)
		}
		// Retired Nmap labels and the explicitly revised TCP-only wording are
		// excluded from the immutable historical text projection; current keys
		// are pinned separately below.
		for _, key := range []string{"port.nmap", "limitation.nmap_incomplete", "method.verify", "obs.active_ports"} {
			delete(expected, key)
		}
		translator, e := NewTranslator(language)
		if e != nil {
			t.Fatal(e)
		}
		// Historical catalog keys/text stay pinned; later approved runtime keys may be added.
		if len(expected) > len(catalogs[language]) {
			t.Fatal("catalog count differs")
		}
		for key, text := range expected {
			got, e := translator.Text(key, nil)
			if e != nil || got != text {
				t.Errorf("%s/%s changed: %q %v", language, key, got, e)
			}
			values := map[string]any{}
			for _, match := range pattern.FindAllStringSubmatch(text, -1) {
				values[match[1]] = 37
			}
			if len(values) > 0 {
				want := pattern.ReplaceAllString(text, "37")
				got, e = translator.Text(key, values)
				if e != nil || got != want {
					t.Errorf("placeholder %s: %q want %q %v", key, got, want, e)
				}
				delete(values, pattern.FindStringSubmatch(text)[1])
				values["unrelated"] = "x"
				if _, e = translator.Text(key, values); e == nil {
					t.Errorf("missing placeholder accepted: %s", key)
				}
			}
		}
		if _, e = translator.Text("missing.key", nil); e == nil {
			t.Fatal("missing key accepted")
		}
	}
	if e := AssertCatalogEquivalence(); e != nil {
		t.Fatal(e)
	}
}
func TestLanguagePrecedence(t *testing.T) {
	for _, c := range []struct{ Explicit, Saved, Default, Want string }{{"RU", "en", "en", "ru"}, {"", "ru", "en", "ru"}, {"", "", "ru", "ru"}, {"", "", "", "en"}} {
		got, e := ResolveLanguage(c.Explicit, c.Saved, c.Default)
		if e != nil || got != c.Want {
			t.Errorf("%v got %s %v", c, got, e)
		}
	}
	if _, e := ResolveLanguage("invalid", "ru", "en"); e == nil {
		t.Fatal("invalid explicit language hidden")
	}
	if _, e := NewTranslator("de"); e == nil {
		t.Fatal("invalid language accepted")
	}
	if _, e := (Translator{}).Text("report.title", nil); e == nil {
		t.Fatal(fmt.Sprint("invalid zero translator accepted"))
	}
}

func TestIntegrationCatalogHasMatchingLanguages(t *testing.T) {
	if len(catalogs["en"]) != len(catalogs["ru"]) {
		t.Fatal("EN/RU coverage differs")
	}
	for key := range catalogs["en"] {
		if _, exists := catalogs["ru"][key]; !exists {
			t.Fatalf("RU missing %s", key)
		}
	}
}

func TestTCPReachabilityCatalogDoesNotGuessServices(t *testing.T) {
	for language, want := range map[string]map[string]string{
		"en": {"port.tcp_connect": "TCP connect", "port.open": "open", "port.closed": "closed", "port.unknown": "unknown", "obs.active_ports": "Ports with confirmed TCP connections: {count}."},
		"ru": {"port.tcp_connect": "TCP-подключение", "port.open": "открыт", "port.closed": "закрыт", "port.unknown": "неизвестно", "obs.active_ports": "Порты с подтверждённым TCP-подключением: {count}."},
	} {
		tr, err := NewTranslator(language)
		if err != nil {
			t.Fatal(err)
		}
		for key, text := range want {
			got, err := tr.Text(key, nil)
			if err != nil || got != text {
				t.Fatalf("%s %s: %q %v", language, key, got, err)
			}
		}
	}
}
