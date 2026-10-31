package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed en.json ru.json
var catalogFiles embed.FS
var catalogs = loadCatalogs()

func loadCatalogs() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, lang := range []string{"en", "ru"} {
		b, e := catalogFiles.ReadFile(lang + ".json")
		if e != nil {
			panic(e)
		}
		var m map[string]string
		if e = json.Unmarshal(b, &m); e != nil {
			panic(e)
		}
		out[lang] = m
	}
	if e := catalogEquivalence(out); e != nil {
		panic(e)
	}
	return out
}
func NormalizeLanguage(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = "en"
	}
	if value != "en" && value != "ru" {
		return "", fmt.Errorf("report language must be one of: en, ru")
	}
	return value, nil
}
func ResolveLanguage(explicit, saved, installationDefault string) (string, error) {
	for _, v := range []string{explicit, saved, installationDefault} {
		if strings.TrimSpace(v) != "" {
			return NormalizeLanguage(v)
		}
	}
	return "en", nil
}

type Translator struct{ language string }

func NewTranslator(language string) (Translator, error) {
	v, e := NormalizeLanguage(language)
	return Translator{v}, e
}
func (t Translator) Language() string { return t.language }
func (t Translator) Text(key string, values map[string]any) (string, error) {
	catalog, ok := catalogs[t.language]
	if !ok {
		return "", fmt.Errorf("invalid translator language")
	}
	s, ok := catalog[key]
	if !ok {
		return "", fmt.Errorf("missing translation key for %s: %s", t.language, key)
	}
	if len(values) == 0 {
		return s, nil
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		switch s[i] {
		case '{':
			if i+1 < len(s) && s[i+1] == '{' {
				out.WriteByte('{')
				i += 2
				continue
			}
			j := strings.IndexByte(s[i+1:], '}')
			if j < 0 {
				return "", fmt.Errorf("unclosed translation placeholder")
			}
			name := s[i+1 : i+1+j]
			v, ok := values[name]
			if !ok {
				return "", fmt.Errorf("missing translation placeholder: %s", name)
			}
			out.WriteString(fmt.Sprint(v))
			i += j + 2
		case '}':
			if i+1 < len(s) && s[i+1] == '}' {
				out.WriteByte('}')
				i += 2
			} else {
				return "", fmt.Errorf("unmatched translation brace")
			}
		default:
			out.WriteByte(s[i])
			i++
		}
	}
	return out.String(), nil
}
func catalogEquivalence(c map[string]map[string]string) error {
	if len(c["en"]) != len(c["ru"]) {
		return fmt.Errorf("translation catalogs differ")
	}
	for key := range c["en"] {
		if _, ok := c["ru"][key]; !ok {
			return fmt.Errorf("translation catalogs differ at %s", key)
		}
	}
	return nil
}
func AssertCatalogEquivalence() error { return catalogEquivalence(catalogs) }
