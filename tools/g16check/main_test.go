package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateOptionsRequiresExplicitModeAndAcknowledgement(t *testing.T) {
	base := options{kitRoot: "kit", portable: "portable", evidence: "evidence"}
	cases := []struct {
		name string
		cfg  options
		want string
	}{
		{"no-mode", base, "select exactly one"},
		{"both-modes", options{preflight: true, run: true, kitRoot: "kit", portable: "payload", evidence: "evidence"}, "select exactly one"},
		{"preflight-ack", options{preflight: true, ack: approvalToken, kitRoot: "kit", portable: "payload", evidence: "evidence"}, "only with"},
		{"run-no-ack", options{run: true, kitRoot: "kit", portable: "payload", evidence: "evidence"}, "requires --ack"},
		{"run-wrong-ack", options{run: true, ack: "yes", kitRoot: "kit", portable: "payload", evidence: "evidence"}, "requires --ack"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOptions(tc.cfg, "linux", "amd64")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateOptions() error=%v, want substring %q", err, tc.want)
			}
		})
	}
	if err := validateOptions(options{preflight: true, kitRoot: "kit", portable: "payload", evidence: "evidence"}, "linux", "amd64"); err != nil {
		t.Fatalf("valid preflight options: %v", err)
	}
	if err := validateOptions(options{run: true, ack: approvalToken, kitRoot: "kit", portable: "payload", evidence: "evidence"}, "windows", "amd64"); err != nil {
		t.Fatalf("valid acknowledged Windows run options: %v", err)
	}
}

func TestParseOptionsRejectsPositionalsAndAcceptsUnicodePaths(t *testing.T) {
	if _, err := parseOptions([]string{"--preflight", "--kit-root", "Кит с пробелом", "--portable-root", "payload", "--evidence-root", "evidence", "extra"}); err == nil {
		t.Fatal("accepted positional argument")
	}
	cfg, err := parseOptions([]string{"--preflight", "--kit-root", "Кит с пробелом", "--portable-root", "payload", "--evidence-root", "evidence"})
	if err != nil || cfg.kitRoot != "Кит с пробелом" {
		t.Fatalf("Unicode path parse: cfg=%+v err=%v", cfg, err)
	}
}

func TestValidateInputSeparationRejectsNestedRoots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "проверка с пробелом")
	cases := [][3]string{
		{filepath.Join(root, "kit"), filepath.Join(root, "payload"), filepath.Join(root, "kit", "evidence")},
		{filepath.Join(root, "kit"), filepath.Join(root, "payload"), filepath.Join(root, "payload", "evidence")},
		{filepath.Join(root, "same"), filepath.Join(root, "same"), filepath.Join(root, "evidence")},
	}
	for _, paths := range cases {
		if err := validateInputSeparation(paths[0], paths[1], paths[2]); err == nil {
			t.Fatalf("accepted overlapping roots: %#v", paths)
		}
	}
	if err := validateInputSeparation(filepath.Join(root, "kit"), filepath.Join(root, "payload"), filepath.Join(root, "evidence")); err != nil {
		t.Fatalf("rejected separate Unicode roots: %v", err)
	}
}

func TestRequireFreshEvidenceRootNeverReusesResults(t *testing.T) {
	parent := t.TempDir()
	fresh := filepath.Join(parent, "evidence-новый")
	if err := requireFreshEvidenceRoot(fresh); err != nil {
		t.Fatalf("new evidence root: %v", err)
	}
	if err := os.Mkdir(fresh, 0700); err != nil {
		t.Fatal(err)
	}
	if err := requireFreshEvidenceRoot(fresh); err == nil {
		t.Fatal("accepted an existing evidence directory")
	}
}

func TestReadG16ResultRequiresEveryScenarioAndPreservedNotRunStatus(t *testing.T) {
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0700); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(artifacts, "sample.jsonl")
	artifactBody := []byte("{}\n")
	if err := os.WriteFile(artifactPath, artifactBody, 0600); err != nil {
		t.Fatal(err)
	}
	artifactHash := sha256.Sum256(artifactBody)
	bundleSHA := portableBundleAnchor(runtime.GOOS, runtime.GOARCH)
	components := map[string]componentRecord{
		"typst":     {Version: "0.15.1", SHA256: strings.Repeat("a", 64)},
		"subfaster": {Version: "2.18.0", SHA256: strings.Repeat("b", 64)},
		"nmap":      {Version: "7.x", SHA256: strings.Repeat("c", 64)},
	}
	scenarios := make(map[string]json.RawMessage, len(requiredScenarios))
	for _, name := range requiredScenarios {
		body, _ := json.Marshal(map[string]any{
			"status": "PASS", "execution_mode": "streaming", "dns": map[string]any{"status": "PASS"},
			"probe": map[string]any{}, "http": map[string]any{}, "crawler": map[string]any{},
			"network_scope": "loopback-only", "run_status": "complete", "details": map[string]any{"records": 1},
		})
		scenarios[name] = body
	}
	notRun := map[string]string{
		"nmap_runtime": "NOT_RUN", "typst_pdf": "NOT_RUN", "subfaster_runtime": "NOT_RUN",
		"obscura_browser": "BLOCKED_candidate31_FAIL", "external_dns_providers": "NOT_RUN",
		"strict_network_gate": "NOT_RUN",
	}
	result := map[string]any{
		"schema_version": 1, "status": "PASS_FUNCTIONAL_ONLY", "platform": runtime.GOOS + "/amd64",
		"bundle_manifest_sha256": bundleSHA, "execution_boundary": "loopback fixtures only",
		"artifact_preservation": true,
		"verified_components":   components, "scenarios": scenarios, "not_run": notRun,
		"historical": map[string]string{"browser": "BLOCKED; candidate31 FAIL preserved", "linux_strict_network_gate": "FAIL preserved"},
		"artifacts":  map[string]artifactReference{"artifacts/sample.jsonl": {Path: "artifacts/sample.jsonl", SHA256: hex.EncodeToString(artifactHash[:])}},
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "g16-result.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readG16Result(path, bundleSHA, components)
	if err != nil {
		t.Fatalf("valid fixture result rejected: %v", err)
	}
	if len(got.scenarioStatuses) != len(requiredScenarios) {
		t.Fatalf("scenario status count=%d", len(got.scenarioStatuses))
	}
	if err := addHarnessArtifacts(root, got); err != nil {
		t.Fatalf("valid artifact reference rejected: %v", err)
	}

	scenarios[requiredScenarios[0]], _ = json.Marshal(map[string]any{"status": "SKIP"})
	result["scenarios"] = scenarios
	body, _ = json.Marshal(result)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readG16Result(path, bundleSHA, components); err == nil {
		t.Fatal("accepted a skipped/missing scenario")
	}
}

func TestValidateNotRunPreservesBrowserAndLinuxNetworkFailures(t *testing.T) {
	statuses := map[string]string{
		"nmap_runtime": "NOT_RUN", "typst_pdf": "NOT_RUN", "subfaster_runtime": "NOT_RUN",
		"obscura_browser": "BLOCKED_candidate31_FAIL", "external_dns_providers": "NOT_RUN",
		"strict_network_gate": "NOT_RUN",
	}
	if err := validateNotRun(statuses); err != nil {
		t.Fatal(err)
	}
	statuses["obscura_browser"] = "NOT_RUN"
	if err := validateNotRun(statuses); err == nil {
		t.Fatal("accepted a browser result that hides BLOCKED/candidate31 FAIL")
	}
	statuses["obscura_browser"] = "BLOCKED_candidate31_FAIL"
	statuses["strict_network_gate"] = "PASS"
	if runtime.GOOS == "linux" {
		if err := validateNotRun(statuses); err == nil {
			t.Fatal("accepted a Linux network-gate PASS that would overwrite historical FAIL")
		}
	}
}

func TestArtifactReferenceRejectsTraversalAndLinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	result := g16Result{Artifacts: map[string]artifactReference{
		"artifacts/../outside.json": {Path: "artifacts/../outside.json", SHA256: strings.Repeat("0", 64)},
	}}
	if err := addHarnessArtifacts(root, result); err == nil {
		t.Fatal("accepted traversal artifact")
	}
	if runtime.GOOS != "windows" {
		if err := os.Mkdir(filepath.Join(root, "artifacts"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "artifacts", "linkdir")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		result.Artifacts = map[string]artifactReference{"artifacts/linkdir/outside.json": {Path: "artifacts/linkdir/outside.json", SHA256: strings.Repeat("0", 64)}}
		if err := addHarnessArtifacts(root, result); err == nil {
			t.Fatal("accepted artifact reached through a symlinked directory")
		}
	}
}
