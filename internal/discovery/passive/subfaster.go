package passive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/execution"
	"asmtool/internal/platform"
)

const ExpectedSubfasterVersion = "2.18.0"
const UnknownAggregate = "unknown_aggregate"

const SubfasterStartupNetworkRisk = "Subfaster 2.18.0 may perform a UDP route probe during startup; this behavior has not been qualified or changed."

// Retained for legacy persisted-status handling; StreamSubfaster no longer returns it.
var ErrSubfasterNetworkSafetyBlocked = errors.New("Subfaster startup network behavior is not qualified")

var subfasterFamilies = map[string]string{"thc": "passive_dns_or_asset_index", "submd": UnknownAggregate, "shodanct": "certificate_transparency", "rapiddns": "public_index", "hackertarget": "public_index", "sitedossier": "public_index"}

type SubfasterRun struct {
	Args                                    []string
	ReturnCode                              int
	Stderr                                  string
	Duration                                time.Duration
	Version                                 string
	PinnedVersion                           string
	ComponentSHA256                         string
	VersionEvidenceStatus                   string
	KnownStartupNetworkRisk                 bool
	StdoutLines, ParsedRows, MalformedLines int
}

func SubfasterFamily(provider string) string {
	if f, ok := subfasterFamilies[provider]; ok {
		return f
	}
	return UnknownAggregate
}
func SubfasterArgs(tool platform.Tool, domain, source string) ([]string, error) {
	if tool.Name() != "subfaster" || tool.Version() != ExpectedSubfasterVersion || strings.TrimSpace(domain) == "" || strings.TrimSpace(source) == "" {
		return nil, errors.New("verified Subfaster, domain and explicit provider are required")
	}
	if _, ok := subfasterFamilies[source]; !ok {
		return nil, errors.New("unsupported Subfaster provider")
	}
	if normalized, err := core.NormalizeDomain(domain); err != nil || normalized != domain {
		return nil, errors.New("Subfaster domain must be normalized")
	}
	return []string{"-d", domain, "-s", source, "-oJ", "-cs"}, nil
}
func ParseSubfasterLine(line, requested string) (string, []string, bool) {
	var obj map[string]any
	d := json.NewDecoder(strings.NewReader(line))
	d.UseNumber()
	if e := d.Decode(&obj); e != nil {
		return "", nil, false
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return "", nil, false
	}
	var host string
	for _, k := range []string{"host", "hostname", "domain", "name"} {
		if v, exists := obj[k]; exists && pythonTruthy(v) {
			text, ok := v.(string)
			if !ok {
				return "", nil, false
			}
			host = text
			break
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", nil, false
	}
	sources := []string{}
	switch v := obj["sources"].(type) {
	case []any:
		for _, x := range v {
			if pythonTruthy(x) {
				sources = append(sources, pythonString(x))
			}
		}
	case string:
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				sources = append(sources, x)
			}
		}
	}
	if v, ok := obj["source"]; ok && pythonTruthy(v) {
		if text, ok := v.(string); ok && strings.TrimSpace(text) != "" {
			sources = append(sources, strings.TrimSpace(text))
		}
	}
	if len(sources) == 0 {
		sources = []string{requested}
	}
	sort.Strings(sources)
	out := sources[:0]
	for _, s := range sources {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return host, out, true
}

// StreamSubfaster validates a request and streams JSONL results from the pinned executable.
func StreamSubfaster(ctx context.Context, tool platform.Tool, domain, provider string, timeout time.Duration, onRow func(context.Context, string, []string) error) (SubfasterRun, error) {
	if provider == "all" || provider == "-all" || provider == "research" || onRow == nil || timeout <= 0 {
		return SubfasterRun{}, errors.New("explicit provider and row callback are required")
	}
	args, err := SubfasterArgs(tool, domain, provider)
	if err != nil {
		return SubfasterRun{}, err
	}
	counts := SubfasterRun{Args: append([]string{tool.Path()}, args...), PinnedVersion: tool.Version()}
	if err := tool.Verify(); err != nil {
		return counts, fmt.Errorf("verify Subfaster: %w", err)
	}
	counts.ComponentSHA256, err = componentSHA256(tool.Path())
	if err != nil {
		return counts, fmt.Errorf("hash Subfaster: %w", err)
	}
	counts.KnownStartupNetworkRisk = true
	counts.VersionEvidenceStatus = "manifest_identity_verified"
	started := time.Now()
	result, runErr := execution.Run(ctx, tool, args, execution.Options{Timeout: timeout, MaxOutputBytes: 64 << 20, TailBytes: 64 << 10, MaxLineBytes: 1 << 20, OnStdoutLine: func(ctx context.Context, line string) error {
		if strings.TrimSpace(line) == "" {
			return nil
		}
		counts.StdoutLines++
		host, sources, ok := ParseSubfasterLine(line, provider)
		if !ok {
			counts.MalformedLines++
			return nil
		}
		counts.ParsedRows++
		return onRow(ctx, host, sources)
	}})
	counts.Duration = time.Since(started)
	counts.Stderr = result.Stderr
	counts.ReturnCode = result.ExitCode
	if runErr != nil {
		var processErr *execution.ProcessError
		if errors.As(runErr, &processErr) {
			counts.ReturnCode = processErr.Result.ExitCode
			counts.Stderr = processErr.Result.Stderr
		}
		return counts, runErr
	}
	if result.ExitCode != 0 {
		return counts, fmt.Errorf("Subfaster exited with status %d: %s", result.ExitCode, result.Stderr)
	}
	return counts, nil
}

func componentSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func pythonTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64)
		return f != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}
func pythonString(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return string(x)
	default:
		return fmt.Sprint(v)
	}
}
