package config

import (
	"asmtool/internal/i18n"
	platformpath "asmtool/internal/platform/path"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// ReadDefaultReportLanguage uses English with a visible error when local settings cannot be read.
func ReadDefaultReportLanguage(filename string) (string, error) {
	if filename == "" {
		var e error
		filename, e = platformpath.SettingsPath()
		if e != nil {
			return "en", e
		}
	}
	f, e := os.Open(filename)
	if errors.Is(e, os.ErrNotExist) {
		return "en", nil
	}
	if e != nil {
		return "en", fmt.Errorf("could not read %s; using English: %w", filename, e)
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if e != nil {
		return "en", fmt.Errorf("could not read %s; using English: %w", filename, e)
	}
	language, e := parseSettings(b)
	if e != nil {
		return "en", fmt.Errorf("could not read %s; using English: %w", filename, e)
	}
	return language, nil
}
func parseSettings(b []byte) (string, error) {
	node, e := yamlDocument(b)
	if e != nil {
		return "", e
	}
	reporting := nodeField(node, "reporting")
	if reporting == nil || reporting.Tag == "!!null" {
		return "en", nil
	}
	if reporting.Kind != yaml.MappingNode {
		return "", fmt.Errorf("settings reporting must be a mapping")
	}
	language := nodeField(reporting, "default_language")
	if language == nil || language.Tag == "!!null" {
		return "en", nil
	}
	if language.Tag != "!!str" {
		return "", fmt.Errorf("default_language must be a string")
	}
	return i18n.NormalizeLanguage(language.Value)
}

// WriteDefaultReportLanguage only replaces the old file after the complete new file has been synced.
func WriteDefaultReportLanguage(language, filename string) (string, error) {
	language, e := i18n.NormalizeLanguage(language)
	if e != nil {
		return "", e
	}
	if filename == "" {
		filename, e = platformpath.SettingsPath()
		if e != nil {
			return "", e
		}
	}
	parent := filepath.Dir(filename)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return "", e
	}
	f, e := os.CreateTemp(parent, filepath.Base(filename)+".")
	if e != nil {
		return "", e
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	closeOnError := func(err error) (string, error) { f.Close(); return "", err }
	if runtime.GOOS != "windows" {
		if e = f.Chmod(0600); e != nil {
			return closeOnError(e)
		}
	}
	if _, e = f.WriteString("reporting:\n  default_language: " + language + "\n"); e != nil {
		return closeOnError(e)
	}
	if e = f.Sync(); e != nil {
		return closeOnError(e)
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	if e = os.Rename(temporary, filename); e != nil {
		return "", e
	}
	return filename, nil
}
