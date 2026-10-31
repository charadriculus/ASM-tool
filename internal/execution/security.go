package execution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var secretName = regexp.MustCompile(`(?i)(?:^|_)(?:token|secret|password|passwd|api_?key|authorization|credential|cookie)(?:$|_)`)
var secretFlags = map[string]bool{"--token": true, "-token": true, "--api-key": true, "-api-key": true, "--apikey": true, "-apikey": true, "--password": true, "-password": true, "--passwd": true, "-passwd": true, "--secret": true, "-secret": true, "--authorization": true, "-authorization": true, "--cookie": true, "-cookie": true}

func ValidateArgs(args []string) error {
	if len(args) == 0 || len(args) > 4096 {
		return errors.New("argv must contain 1..4096 arguments")
	}
	for i, s := range args {
		if i == 0 && s == "" {
			return errors.New("empty executable")
		}
		if strings.ContainsAny(s, "\x00\r\n") {
			return fmt.Errorf("argv[%d] contains NUL/CR/LF", i)
		}
		if len(s) > 1<<20 {
			return fmt.Errorf("argv[%d] exceeds 1 MiB", i)
		}
	}
	return nil
}
func sanitizeEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, item := range env {
		k, _, ok := strings.Cut(item, "=")
		if !ok || secretName.MatchString(k) {
			continue
		}
		upper := strings.ToUpper(k)
		switch upper {
		case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "PDCP_API_KEY", "SSH_AUTH_SOCK", "GIT_ASKPASS", "NETRC", "KUBECONFIG":
			continue
		}
		if upper == "PATH" || upper == "HOME" || upper == "TMPDIR" || upper == "TMP" || upper == "TEMP" {
			continue
		}
		out = append(out, item)
	}
	return out
}
func RedactArgs(args []string) []string {
	out := append([]string(nil), args...)
	redact := false
	header := false
	for i, s := range out {
		if redact {
			out[i] = "[REDACTED_SECRET]"
			redact = false
			continue
		}
		if header {
			if sensitiveHeader(s) {
				out[i] = "[REDACTED_SECRET_HEADER]"
			} else {
				out[i] = redactURLCredentials(s)
			}
			header = false
			continue
		}
		lower := strings.ToLower(s)
		if secretFlags[lower] {
			redact = true
			continue
		}
		if lower == "-h" || lower == "--header" || lower == "-header" {
			header = true
			continue
		}
		if key, _, ok := strings.Cut(s, "="); ok && secretFlags[strings.ToLower(key)] {
			out[i] = key + "=[REDACTED_SECRET]"
			continue
		}
		if key, value, ok := strings.Cut(s, "="); ok {
			k := strings.ToLower(key)
			if k == "-h" || k == "--header" || k == "-header" {
				if sensitiveHeader(value) {
					out[i] = key + "=[REDACTED_SECRET_HEADER]"
				} else {
					out[i] = key + "=" + redactURLCredentials(value)
				}
				continue
			}
		}
		if sensitiveHeader(s) {
			out[i] = "[REDACTED_SECRET_HEADER]"
		} else {
			out[i] = redactURLCredentials(s)
		}
	}
	return out
}

var credentialURL = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@`)

func redactURLCredentials(s string) string {
	return credentialURL.ReplaceAllString(s, "${1}[REDACTED_CREDENTIALS]@")
}
func sensitiveHeader(s string) bool {
	return sensitiveHeaderRE.MatchString(s)
}
func SanitizeFilenameComponent(value string) string {
	clean := filenameSafe.ReplaceAllString(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(value), "/", "_"), "\\", "_"), "_")
	clean = strings.Trim(clean, " ._")
	if clean == "" || clean == "." || clean == ".." {
		clean = "artifact"
	}
	if len(clean) > 128 {
		clean = clean[:128]
	}
	return clean
}

var sensitiveHeaderRE = regexp.MustCompile(`(?i)^\s*(authorization|proxy-authorization|cookie|set-cookie)\s*:`)
var filenameSafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func SafeArtifactPath(root, relative string) (string, error) {
	if filepath.IsAbs(relative) {
		return "", errors.New("artifact path must be relative")
	}
	base, e := filepath.Abs(root)
	if e != nil {
		return "", e
	}
	baseReal, e := filepath.EvalSymlinks(base)
	if e != nil {
		return "", e
	}
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return "", errors.New("artifact path contains hidden/dot/parent component")
		}
	}
	candidate := filepath.Join(base, filepath.FromSlash(relative))
	probe := candidate
	for {
		if _, e = os.Lstat(probe); e == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", errors.New("artifact path has no existing ancestor")
		}
		probe = parent
	}
	realProbe, e := filepath.EvalSymlinks(probe)
	if e != nil {
		return "", e
	}
	relProbe, e := filepath.Rel(baseReal, realProbe)
	if e != nil || relProbe == ".." || strings.HasPrefix(relProbe, ".."+string(filepath.Separator)) {
		return "", errors.New("artifact path escapes root through symlink")
	}
	rel, e := filepath.Rel(base, candidate)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("artifact path escapes root")
	}
	return candidate, nil
}
