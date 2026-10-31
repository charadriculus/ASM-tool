package backends

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"asmtool/internal/execution"
	"asmtool/internal/platform"
)

type Registry struct {
	bundle      *platform.Bundle
	descriptors map[string]BackendDescriptor
}

func NewProcessRegistry(bundle *platform.Bundle) *Registry {
	return &Registry{bundle: bundle, descriptors: map[string]BackendDescriptor{
		"typst":     {Category: "report_pdf", Name: "typst", Implementation: "typst", Language: "Rust", ExecutionMode: "verified_subprocess", PinnedVersion: "0.15.1"},
		"subfaster": {Category: "passive_subdomain", Name: "subfaster", Implementation: "subfaster", Language: "Go", ExecutionMode: "verified_subprocess", PinnedVersion: "2.18.0"},
	}}
}
func (r *Registry) Descriptor(name string) (BackendDescriptor, bool) {
	d, ok := r.descriptors[name]
	return d, ok
}

var versionPattern = regexp.MustCompile(`(?:^|[^0-9])v?(\d+\.\d+(?:\.\d+)?)(?:$|[^0-9])`)

func (r *Registry) Probe(ctx context.Context, name string) BackendResolution {
	d, ok := r.descriptors[name]
	out := BackendResolution{Category: d.Category, Requested: name, Actual: name, Implementation: d.Implementation, Language: d.Language, ExecutionMode: d.ExecutionMode}
	if !ok {
		out.Status = "not_implemented"
		out.VersionEvidenceStatus = "not_implemented"
		out.Error = "backend has no adapter in this build"
		if name == "projectdiscovery_httpx" {
			out.PinnedVersion = "1.8.1"
			if err := platform.CheckNativeHTTPX(name, out.PinnedVersion); err != nil {
				out.Actual = ""
				out.Status = "blocked"
				out.VersionEvidenceStatus = "blocked_by_policy"
				out.Error = err.Error()
			}
		}
		return out
	}
	if r.bundle == nil {
		out.Status = "unavailable"
		out.VersionEvidenceStatus = "version_unavailable"
		out.Error = "verified bundle is unavailable"
		return out
	}
	tool, e := r.bundle.Tool(name)
	if e != nil {
		out.Status = "unavailable"
		out.VersionEvidenceStatus = "version_unavailable"
		out.Error = e.Error()
		return out
	}
	if name == "subfaster" {
		out.PinnedVersion = d.PinnedVersion
		if tool.Version() != d.PinnedVersion {
			out.Status = "version_mismatch"
			out.VersionEvidenceStatus = "manifest_version_mismatch"
			out.Error = fmt.Sprintf("bundle manifest Subfaster version mismatch: expected=%s declared=%s", d.PinnedVersion, tool.Version())
			return out
		}
		if err := tool.Verify(); err != nil {
			out.Status = "unavailable"
			out.VersionEvidenceStatus = "version_unavailable"
			out.Error = fmt.Sprintf("verify Subfaster: %v", err)
			return out
		}
		hash, err := componentSHA256(tool.Path())
		if err != nil {
			out.Status = "unavailable"
			out.VersionEvidenceStatus = "version_unavailable"
			out.Error = fmt.Sprintf("hash Subfaster: %v", err)
			return out
		}
		out.ComponentSHA256 = hash
		out.Status = "available"
		out.VersionEvidenceStatus = "manifest_identity_verified"
		out.KnownStartupNetworkRisk = true
		out.KnownStartupNetworkRiskDetail = "Subfaster 2.18.0 may perform a UDP route probe during startup; this behavior has not been qualified or changed."
		out.Available = true
		return out
	}
	pinned := d.PinnedVersion
	if pinned == "" {
		pinned = tool.Version()
	}
	out.PinnedVersion = pinned
	flag := "--version"
	res, e := execution.Run(ctx, tool, []string{flag}, execution.Options{Timeout: 10 * time.Second, MaxOutputBytes: 1 << 20, TailBytes: 64 << 10})
	probeErr := e
	if e != nil {
		var pe *execution.ProcessError
		if errors.As(e, &pe) {
			res = pe.Result
		}
	}
	text := strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
	if m := versionPattern.FindStringSubmatch(text); len(m) > 1 {
		out.ActualVersion = m[1]
	}
	if probeErr == nil && res.ExitCode != 0 {
		probeErr = fmt.Errorf("version probe exit=%d", res.ExitCode)
	}
	if probeErr != nil {
		out.Status = "unavailable"
		out.VersionEvidenceStatus = "version_unavailable"
		out.Available = false
		out.Error = probeErr.Error()
		return out
	}
	out.Available = res.ExitCode == 0
	if pinned == "" {
		if out.ActualVersion != "" {
			out.VersionEvidenceStatus = "observed_unpinned"
			out.Status = "ok"
		} else {
			out.VersionEvidenceStatus = "version_unavailable"
			out.Status = "unavailable"
		}
	} else if out.ActualVersion == pinned {
		out.VersionEvidenceStatus = "exact_match"
		out.Status = "ok"
	} else if out.ActualVersion != "" {
		out.VersionEvidenceStatus = "mismatch"
		out.Status = "version_mismatch"
		out.Available = false
		out.Error = fmt.Sprintf("pinned version mismatch: expected=%s actual=%s", pinned, out.ActualVersion)
	} else {
		out.VersionEvidenceStatus = "version_unavailable"
		out.Status = "version_unavailable"
		out.Available = false
		out.Error = "unable to observe backend version"
	}
	return out
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

func (r *Registry) Resolve(ctx context.Context, requested string) BackendResolution {
	return r.Probe(ctx, requested)
}
