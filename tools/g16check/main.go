package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"asmtool/internal/execution"
	"asmtool/internal/platform"
	"asmtool/internal/portable"
)

// kitManifestSHA256 is set by the offline check-kit build command. The runner
// executable is outside checks/ so it is not part of its own manifest closure.
var kitManifestSHA256 string

const (
	linuxBundleSHA256   = "86c83b34d7d62caae5f1a7e8fb54b8163b8df05e7009ef4993ae446296fd2e41"
	windowsBundleSHA256 = "c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479"
	linuxAppSHA256      = "239a377248bfe451088aafc95f634e38dc7ef5c162239a1a078b03d2c7c1015f"
	windowsAppSHA256    = "4e5f35efc9f6dec065a655570ab9c61926e7063a2736365e75078b5483b811e1"
	approvalToken       = "local-fixtures-only"
)

var requiredScenarios = []string{
	"arrival_budget",
	"backpressure_cancel_partial_persistence",
	"batch_ranked_pipeline",
	"loopback_http_crawler",
	"payload_identity_only",
	"shared_http_page_budgets",
	"streaming_pipeline",
}

type options struct {
	preflight bool
	run       bool
	ack       string
	kitRoot   string
	portable  string
	evidence  string
}

type fileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type commandRecord struct {
	Name                string    `json:"name"`
	Executable          string    `json:"executable"`
	Arguments           []string  `json:"arguments"`
	StartedUTC          time.Time `json:"started_utc,omitempty"`
	EndedUTC            time.Time `json:"ended_utc,omitempty"`
	ExitCode            int       `json:"exit_code"`
	TimedOut            bool      `json:"timed_out"`
	OutputLimitExceeded bool      `json:"output_limit_exceeded"`
	StdoutBytes         int64     `json:"stdout_bytes"`
	StderrBytes         int64     `json:"stderr_bytes"`
	StdoutSHA256        string    `json:"stdout_sha256,omitempty"`
	StderrSHA256        string    `json:"stderr_sha256,omitempty"`
	Error               string    `json:"error,omitempty"`
}

type evidenceRecord struct {
	SchemaVersion             int                        `json:"schema_version"`
	Status                    string                     `json:"status"`
	Mode                      string                     `json:"mode"`
	StartedUTC                time.Time                  `json:"started_utc"`
	FinishedUTC               time.Time                  `json:"finished_utc,omitempty"`
	Platform                  string                     `json:"platform"`
	MachineName               string                     `json:"machine_name"`
	OSVersion                 string                     `json:"os_version"`
	Elevated                  bool                       `json:"elevated"`
	ExecutionEnvironment      string                     `json:"execution_environment"`
	KitManifestSHA256         string                     `json:"kit_manifest_sha256"`
	KitExecutables            map[string]componentRecord `json:"kit_executables"`
	PortableManifestSHA256    string                     `json:"portable_manifest_sha256"`
	PortableApplicationSHA256 string                     `json:"portable_application_sha256"`
	KitRoot                   string                     `json:"kit_root"`
	PortableRoot              string                     `json:"portable_root"`
	EvidenceRoot              string                     `json:"evidence_root"`
	Commands                  []commandRecord            `json:"commands"`
	Scenarios                 map[string]string          `json:"scenarios,omitempty"`
	Failure                   string                     `json:"failure,omitempty"`
	Limitations               []string                   `json:"limitations"`
}

func main() {
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "g16check:", err)
		os.Exit(1)
	}
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseOptions(args)
	if err != nil {
		return err
	}
	if err := validateOptions(cfg, runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	if kitManifestSHA256 == "" {
		return errors.New("embedded G-16 check-kit trust anchor is missing")
	}
	root, err := filepath.Abs(cfg.kitRoot)
	if err != nil {
		return fmt.Errorf("resolve kit root: %w", err)
	}
	portableRoot, err := filepath.Abs(cfg.portable)
	if err != nil {
		return fmt.Errorf("resolve portable root: %w", err)
	}
	evidenceRoot, err := filepath.Abs(cfg.evidence)
	if err != nil {
		return fmt.Errorf("resolve evidence root: %w", err)
	}
	if err := validateInputSeparation(root, portableRoot, evidenceRoot); err != nil {
		return err
	}
	for _, candidate := range []string{root, portableRoot, filepath.Dir(evidenceRoot)} {
		if err := checkLocalPath(candidate); err != nil {
			return err
		}
	}
	if err := requireFreshEvidenceRoot(evidenceRoot); err != nil {
		return err
	}
	if err := os.Mkdir(evidenceRoot, 0700); err != nil {
		return fmt.Errorf("create fresh evidence root: %w", err)
	}

	record := evidenceRecord{
		SchemaVersion: 1, Status: "RUNNING", Mode: map[bool]string{true: "preflight", false: "run-approved-local"}[cfg.preflight],
		StartedUTC: time.Now().UTC(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		KitManifestSHA256: strings.ToLower(kitManifestSHA256), KitRoot: root,
		PortableRoot: portableRoot, EvidenceRoot: evidenceRoot,
		Commands: []commandRecord{}, Limitations: []string{
			"No exhaustive host-wide process census is performed; child-tree cleanup is governed by internal/execution.",
			"Linux network-gate and browser security qualification are outside this kit and remain unchanged.",
			"Windows 11 is outside this kit; Windows runtime evidence applies only to accepted Windows 10 builds.",
			"Windows token checks establish a non-elevated token without enabled administrator membership; standard-user account classification must be confirmed by the operator.",
		},
	}
	record.MachineName, _ = os.Hostname()
	finish := func(cause error) error {
		record.FinishedUTC = time.Now().UTC()
		if cause != nil {
			record.Status = "FAIL"
			record.Failure = cause.Error()
		} else if cfg.preflight {
			record.Status = "PREFLIGHT_PASS"
		} else {
			record.Status = "PASS_FUNCTIONAL_ONLY"
		}
		if err := saveJSONExclusive(filepath.Join(evidenceRoot, "runner-result.json"), record); err != nil {
			return errors.Join(cause, fmt.Errorf("write runner result: %w", err))
		}
		if err := writeEvidenceManifest(evidenceRoot); err != nil {
			return errors.Join(cause, fmt.Errorf("write evidence manifest: %w", err))
		}
		if cause != nil {
			return cause
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", record.Status)
		return nil
	}

	hostVersion, elevated, err := checkHost()
	record.OSVersion, record.Elevated = hostVersion, elevated
	record.ExecutionEnvironment = "controlled argv; sanitized child environment; no shell"
	if err != nil {
		return finish(err)
	}
	kit, err := platform.NewBundle(filepath.Join(root, "checks"), kitManifestSHA256)
	if err != nil {
		return finish(fmt.Errorf("verify G-16 check kit: %w", err))
	}
	app, err := kit.Tool("asm-tool")
	if err != nil || app.Version() != "0.12.0-go" {
		return finish(fmt.Errorf("check-kit app identity invalid: %w", errOr(err, "unexpected app version")))
	}
	if err := requireKitToolPath(root, app, "asm-tool"); err != nil {
		return finish(err)
	}
	harness, err := kit.Tool("g16-native.test")
	if err != nil || harness.Version() != "0.12.0-go" {
		return finish(fmt.Errorf("check-kit harness identity invalid: %w", errOr(err, "unexpected harness version")))
	}
	if err := requireKitToolPath(root, harness, "g16-native.test"); err != nil {
		return finish(err)
	}
	if err := app.Verify(); err != nil {
		return finish(fmt.Errorf("verify check-kit app: %w", err))
	}
	if err := harness.Verify(); err != nil {
		return finish(fmt.Errorf("verify check-kit harness: %w", err))
	}
	record.KitExecutables, err = componentDigests(map[string]platform.Tool{"asm-tool": app, "g16-native.test": harness})
	if err != nil {
		return finish(fmt.Errorf("hash check-kit executables: %w", err))
	}
	payloadDir, err := resolvePayloadDir(portableRoot)
	if err != nil {
		return finish(err)
	}
	portableAnchor := portableBundleAnchor(runtime.GOOS, runtime.GOARCH)
	payload, err := portable.Verify(payloadDir, portableAnchor, true, false)
	if err != nil {
		return finish(fmt.Errorf("verify existing portable payload: %w", err))
	}
	record.PortableManifestSHA256 = portableAnchor
	verifiedComponents, err := verifiedComponentDigests(payload)
	if err != nil {
		return finish(err)
	}
	appPath := filepath.Join(portableRoot, "asm-tool")
	if runtime.GOOS == "windows" {
		appPath += ".exe"
	}
	wantApp := portableAppSHA256(runtime.GOOS, runtime.GOARCH)
	if err := verifyFileDigest(appPath, wantApp); err != nil {
		return finish(fmt.Errorf("verify existing portable application: %w", err))
	}
	record.PortableApplicationSHA256, err = fileSHA256(appPath)
	if err != nil {
		return finish(fmt.Errorf("hash existing portable application: %w", err))
	}
	if cfg.preflight {
		return finish(nil)
	}
	if cfg.ack != approvalToken {
		return finish(errors.New("run mode requires --ack=local-fixtures-only"))
	}

	logsRoot := filepath.Join(evidenceRoot, "logs")
	if err := os.Mkdir(logsRoot, 0700); err != nil {
		return finish(fmt.Errorf("create log directory: %w", err))
	}
	signalCtx, stopSignal := runnerSignalContext()
	defer stopSignal()
	runCtx, stopDeadline := context.WithTimeout(signalCtx, 150*time.Second)
	defer stopDeadline()
	for _, check := range []struct {
		name string
		args []string
	}{{"app-help", []string{"--help"}}, {"app-version", []string{"--version"}}} {
		rec, err := executeOne(runCtx, app, check.name, check.args, logsRoot)
		record.Commands = append(record.Commands, rec)
		if err != nil {
			return finish(err)
		}
	}
	currentPayload, err := portable.Verify(payloadDir, portableAnchor, true, false)
	if err != nil {
		return finish(fmt.Errorf("portable payload changed before harness: %w", err))
	}
	currentDigests, err := verifiedComponentDigests(currentPayload)
	if err != nil {
		return finish(fmt.Errorf("rehash portable components before harness: %w", err))
	}
	if err := validateVerifiedComponents(currentDigests, verifiedComponents); err != nil {
		return finish(fmt.Errorf("portable component identities changed before harness: %w", err))
	}
	if err := verifyFileDigest(appPath, wantApp); err != nil {
		return finish(fmt.Errorf("portable application changed before harness: %w", err))
	}
	testArgs := []string{
		"-test.run=^TestG16NativeCheckKit$", "-test.v", "-test.parallel=1", "-test.timeout=100s",
		"-g16-native-approval=" + approvalToken,
		"-g16-native-payload=" + payloadDir,
		"-g16-native-evidence=" + filepath.Join(evidenceRoot, "artifacts"),
	}
	rec, runErr := executeOne(runCtx, harness, "g16-native-local-fixtures", testArgs, logsRoot)
	record.Commands = append(record.Commands, rec)
	if runErr != nil {
		return finish(runErr)
	}
	resultPath := filepath.Join(evidenceRoot, "artifacts", "g16-result.json")
	result, err := readG16Result(resultPath, portableAnchor, verifiedComponents)
	if err != nil {
		return finish(fmt.Errorf("validate G-16 harness result: %w", err))
	}
	record.Scenarios = result.scenarioStatuses
	if err := addHarnessArtifacts(evidenceRoot, result); err != nil {
		return finish(err)
	}
	return finish(nil)
}

func parseOptions(args []string) (options, error) {
	var cfg options
	fs := flag.NewFlagSet("g16check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&cfg.preflight, "preflight", false, "verify local kit and portable inputs only")
	fs.BoolVar(&cfg.run, "run-approved-local", false, "run the local-fixture-only G-16 harness")
	fs.StringVar(&cfg.ack, "ack", "", "required literal local-fixtures-only for approved local mode")
	fs.StringVar(&cfg.kitRoot, "kit-root", "", "G-16 check-kit directory")
	fs.StringVar(&cfg.portable, "portable-root", "", "existing portable application root")
	fs.StringVar(&cfg.evidence, "evidence-root", "", "fresh local evidence directory")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, errors.New("positional arguments are not accepted")
	}
	return cfg, nil
}

func validateOptions(cfg options, goos, goarch string) error {
	if cfg.preflight == cfg.run {
		return errors.New("select exactly one of --preflight or --run-approved-local")
	}
	if goarch != "amd64" || (goos != "linux" && goos != "windows") {
		return fmt.Errorf("G-16 kit supports only linux/amd64 and Windows 10/amd64, got %s/%s", goos, goarch)
	}
	if cfg.kitRoot == "" || cfg.portable == "" || cfg.evidence == "" {
		return errors.New("--kit-root, --portable-root, and --evidence-root are required")
	}
	if strings.HasPrefix(cfg.kitRoot, "//") || strings.HasPrefix(cfg.portable, "//") || strings.HasPrefix(cfg.evidence, "//") ||
		strings.HasPrefix(cfg.kitRoot, `\\`) || strings.HasPrefix(cfg.portable, `\\`) || strings.HasPrefix(cfg.evidence, `\\`) {
		return errors.New("UNC/network-style paths are not accepted")
	}
	if cfg.preflight && cfg.ack != "" {
		return errors.New("--ack is valid only with --run-approved-local")
	}
	if cfg.run && cfg.ack != approvalToken {
		return errors.New("--run-approved-local requires --ack=local-fixtures-only")
	}
	return nil
}

func checkHost() (string, bool, error) {
	if runtime.GOOS == "linux" {
		if os.Geteuid() == 0 {
			return "Linux", true, errors.New("Linux check kit requires an unprivileged user")
		}
		version := "Linux"
		if body, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			version += " " + strings.TrimSpace(string(body))
		}
		return version, false, nil
	}
	if runtime.GOOS != "windows" {
		return runtime.GOOS, false, fmt.Errorf("unsupported host %s", runtime.GOOS)
	}
	return windowsHostFacts()
}

func resolvePayloadDir(root string) (string, error) {
	payload := filepath.Join(root, "payload")
	if st, err := os.Stat(payload); err == nil && st.IsDir() {
		return payload, nil
	}
	return root, nil
}

func portableBundleAnchor(goos, goarch string) string {
	if goos == "linux" && goarch == "amd64" {
		return linuxBundleSHA256
	}
	if goos == "windows" && goarch == "amd64" {
		return windowsBundleSHA256
	}
	return ""
}

func portableAppSHA256(goos, goarch string) string {
	if goos == "linux" && goarch == "amd64" {
		return linuxAppSHA256
	}
	if goos == "windows" && goarch == "amd64" {
		return windowsAppSHA256
	}
	return ""
}

func requireKitToolPath(kitRoot string, tool platform.Tool, name string) error {
	filename := name
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	want := filepath.Join(kitRoot, "checks", "bin", filename)
	got, err := filepath.Abs(tool.Path())
	if err != nil {
		return err
	}
	want, err = filepath.Abs(want)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
			return fmt.Errorf("check-kit tool %q must be at checks/bin/%s", name, filename)
		}
	} else if filepath.Clean(got) != filepath.Clean(want) {
		return fmt.Errorf("check-kit tool %q must be at checks/bin/%s", name, filename)
	}
	return nil
}

func executeOne(ctx context.Context, tool platform.Tool, name string, args []string, logsRoot string) (commandRecord, error) {
	prefix := fmt.Sprintf("%02d-%s", time.Now().UnixNano(), safeName(name))
	stdoutName := prefix + ".stdout.log"
	stderrPath := filepath.Join(logsRoot, prefix+".stderr.log")
	r, err := execution.Run(ctx, tool, args, execution.Options{
		Timeout: 110 * time.Second, MaxOutputBytes: 8 << 20, TailBytes: 8 << 20,
		ArtifactRoot: logsRoot, StdoutArtifact: stdoutName,
	})
	if err != nil {
		var pe *execution.ProcessError
		if errors.As(err, &pe) {
			r = pe.Result
		}
	}
	stderrBytes := []byte(r.Stderr)
	if writeErr := writeExclusive(stderrPath, stderrBytes, 0600); writeErr != nil {
		err = errors.Join(err, fmt.Errorf("persist stderr artifact: %w", writeErr))
	}
	rec := commandRecord{
		Name: name, Executable: tool.Path(), Arguments: append([]string(nil), args...), StartedUTC: r.StartedAt.UTC(), EndedUTC: r.EndedAt.UTC(),
		ExitCode: r.ExitCode, TimedOut: r.TimedOut, OutputLimitExceeded: r.OutputLimitExceeded,
		StdoutBytes: r.StdoutBytes, StderrBytes: r.StderrBytes,
	}
	if r.ArtifactWritten {
		rec.StdoutSHA256, _ = fileSHA256(filepath.Join(logsRoot, stdoutName))
	}
	if _, statErr := os.Stat(stderrPath); statErr == nil {
		rec.StderrSHA256, _ = fileSHA256(stderrPath)
	}
	if err != nil {
		rec.Error = err.Error()
		return rec, fmt.Errorf("%s failed (exit=%d, timeout=%t): %w", name, r.ExitCode, r.TimedOut, err)
	}
	if r.ExitCode != 0 || r.TimedOut || r.OutputLimitExceeded || !r.ArtifactWritten {
		err = fmt.Errorf("%s failed (exit=%d, timeout=%t, output_limit=%t)", name, r.ExitCode, r.TimedOut, r.OutputLimitExceeded)
		rec.Error = err.Error()
		return rec, err
	}
	return rec, nil
}

type g16Result struct {
	SchemaVersion        int                          `json:"schema_version"`
	Status               string                       `json:"status"`
	Platform             string                       `json:"platform"`
	BundleManifestSHA256 string                       `json:"bundle_manifest_sha256"`
	ExecutionBoundary    string                       `json:"execution_boundary"`
	VerifiedComponents   map[string]componentRecord   `json:"verified_components"`
	Scenarios            map[string]json.RawMessage   `json:"scenarios"`
	NotRun               map[string]string            `json:"not_run"`
	Historical           map[string]string            `json:"historical"`
	Artifacts            map[string]artifactReference `json:"artifacts"`
	ArtifactPreservation bool                         `json:"artifact_preservation"`
	scenarioStatuses     map[string]string
}

type componentRecord struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type artifactReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func readG16Result(path, bundleSHA string, verified map[string]componentRecord) (g16Result, error) {
	var result g16Result
	if err := rejectLinkedFile(path); err != nil {
		return result, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return result, errors.New("G-16 result is not a bounded regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return result, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return result, errors.New("G-16 result has trailing data")
	}
	if result.SchemaVersion != 1 || result.Status != "PASS_FUNCTIONAL_ONLY" || result.Platform != runtime.GOOS+"/amd64" || !strings.EqualFold(result.BundleManifestSHA256, bundleSHA) {
		return result, errors.New("G-16 result status, platform, schema, or portable anchor mismatch")
	}
	if !strings.Contains(strings.ToLower(result.ExecutionBoundary), "loopback") || len(result.Historical) == 0 || !result.ArtifactPreservation {
		return result, errors.New("G-16 result lacks loopback boundary, historical declarations, or artifact-preservation confirmation")
	}
	if err := validateHistorical(result.Historical); err != nil {
		return result, err
	}
	if len(result.Scenarios) != len(requiredScenarios) {
		return result, errors.New("G-16 scenario set is incomplete or contains unexpected entries")
	}
	result.scenarioStatuses = make(map[string]string, len(result.Scenarios))
	for _, name := range requiredScenarios {
		var scenario map[string]json.RawMessage
		if err := json.Unmarshal(result.Scenarios[name], &scenario); err != nil || len(scenario) == 0 {
			return result, fmt.Errorf("G-16 scenario %q has an invalid result object", name)
		}
		var status string
		if err := json.Unmarshal(scenario["status"], &status); err != nil || status != "PASS" {
			return result, fmt.Errorf("G-16 scenario %q is missing or not PASS", name)
		}
		for _, required := range []string{"execution_mode", "dns", "probe", "http", "crawler", "network_scope", "run_status"} {
			if len(scenario[required]) == 0 || string(scenario[required]) == "null" {
				return result, fmt.Errorf("G-16 scenario %q lacks %s evidence", name, required)
			}
		}
		result.scenarioStatuses[name] = status
	}
	if err := validateVerifiedComponents(result.VerifiedComponents, verified); err != nil {
		return result, err
	}
	if err := validateNotRun(result.NotRun); err != nil {
		return result, err
	}
	if len(result.Artifacts) == 0 || len(result.Artifacts) > 512 {
		return result, errors.New("G-16 result does not identify evidence artifacts")
	}
	return result, nil
}

func addHarnessArtifacts(root string, result g16Result) error {
	seen := make(map[string]bool, len(result.Artifacts))
	var total int64
	for key, ref := range result.Artifacts {
		rel, want := ref.Path, ref.SHA256
		if key != rel {
			return fmt.Errorf("harness artifact key %q does not match its path %q", key, rel)
		}
		if filepath.IsAbs(rel) || strings.Contains(rel, "\\") || !strings.HasPrefix(rel, "artifacts/") {
			return fmt.Errorf("unsafe harness artifact path %q", rel)
		}
		clean := filepath.Clean(filepath.FromSlash(rel))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.HasPrefix(clean, string(filepath.Separator)) || filepath.ToSlash(clean) != rel {
			return fmt.Errorf("unsafe harness artifact path %q", rel)
		}
		if seen[clean] || filepath.ToSlash(clean) == "artifacts/g16-result.json" {
			return fmt.Errorf("duplicate or self-referential harness artifact %q", rel)
		}
		seen[clean] = true
		path := filepath.Join(root, clean)
		if !within(root, path) {
			return fmt.Errorf("harness artifact escapes evidence root: %q", rel)
		}
		if err := checkNoLinkedAncestors(filepath.Dir(path)); err != nil {
			return fmt.Errorf("harness artifact %q: %w", rel, err)
		}
		if err := rejectLinkedFile(path); err != nil {
			return fmt.Errorf("harness artifact %q: %w", rel, err)
		}
		got, err := fileSHA256(path)
		if err != nil {
			return fmt.Errorf("hash harness artifact %q: %w", rel, err)
		}
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("harness artifact %q SHA-256 mismatch", rel)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > 64<<20 {
			return fmt.Errorf("harness artifact %q is missing or exceeds 64 MiB", rel)
		}
		total += info.Size()
		if total > 512<<20 {
			return errors.New("harness artifacts exceed the 512 MiB evidence bound")
		}
	}
	return nil
}

func validateInputSeparation(kit, payload, evidence string) error {
	if !filepath.IsAbs(kit) || !filepath.IsAbs(payload) || !filepath.IsAbs(evidence) {
		return errors.New("all roots must resolve to absolute paths")
	}
	if rootsOverlap(kit, payload) || rootsOverlap(kit, evidence) || rootsOverlap(payload, evidence) {
		return errors.New("kit, portable payload, and evidence roots must be separate trees")
	}
	return nil
}

func rootsOverlap(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	return within(a, b) || within(b, a)
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

func requireFreshEvidenceRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("evidence root must be an absolute clean path")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("evidence root already exists; choose a new path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("evidence root parent must already exist as a directory")
	}
	return checkNoLinkedAncestors(parent)
}

func checkNoLinkedAncestors(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(current) {
			return fmt.Errorf("path contains symbolic link or reparse point: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func checkLocalPath(path string) error {
	if runtime.GOOS == "windows" {
		if err := checkLocalWindowsPath(path); err != nil {
			return err
		}
	} else if strings.HasPrefix(path, "//") || strings.HasPrefix(path, `\\`) {
		return errors.New("network/UNC-style paths are not accepted")
	}
	return checkNoLinkedAncestors(path)
}

func runnerSignalContext() (context.Context, context.CancelFunc) {
	return signalContext()
}

func verifyFileDigest(path, expected string) error {
	if err := checkNoLinkedAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := rejectLinkedFile(path); err != nil {
		return err
	}
	got, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, expected) {
		return errors.New("SHA-256 mismatch")
	}
	return nil
}

func rejectLinkedFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return errors.New("path is not a regular non-link file")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, f)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func saveJSONExclusive(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusive(path, append(data, '\n'), 0600)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

func writeEvidenceManifest(root string) error {
	var records []fileRecord
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		if entry.Name() == "evidence-manifest.json" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || isReparsePoint(path) {
			return fmt.Errorf("evidence contains a link: %s", path)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("evidence contains a non-regular file: %s", path)
		}
		hash, err := fileSHA256(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		records = append(records, fileRecord{Path: filepath.ToSlash(rel), SHA256: hash, Size: info.Size()})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return saveJSONExclusive(filepath.Join(root, "evidence-manifest.json"), records)
}

func verifiedComponentDigests(payload portable.Payload) (map[string]componentRecord, error) {
	tools := map[string]platform.Tool{"typst": payload.Typst}
	if payload.Subfaster == nil {
		return nil, errors.New("preflight requires verified Subfaster identity")
	}
	tools["subfaster"] = *payload.Subfaster
	return componentDigests(tools)
}

func componentDigests(tools map[string]platform.Tool) (map[string]componentRecord, error) {
	components := make(map[string]componentRecord, len(tools))
	for name, tool := range tools {
		digest, err := fileSHA256(tool.Path())
		if err != nil {
			return nil, fmt.Errorf("hash verified %s: %w", name, err)
		}
		components[name] = componentRecord{Version: tool.Version(), SHA256: digest}
	}
	return components, nil
}

func validateHistorical(history map[string]string) error {
	browser := strings.ToUpper(history["browser"])
	linuxGate := strings.ToUpper(history["linux_strict_network_gate"])
	if !strings.Contains(browser, "BLOCKED") || !strings.Contains(browser, "CANDIDATE31") || !strings.Contains(browser, "FAIL") {
		return errors.New("historical browser BLOCKED/candidate31 FAIL is not preserved")
	}
	if !strings.Contains(linuxGate, "FAIL") {
		return errors.New("historical Linux strict network gate FAIL is not preserved")
	}
	return nil
}

func validateVerifiedComponents(got, want map[string]componentRecord) error {
	if len(got) != len(want) {
		return errors.New("verified component evidence is incomplete or has unexpected entries")
	}
	for name, expected := range want {
		actual, ok := got[name]
		if !ok || actual.Version != expected.Version || !strings.EqualFold(actual.SHA256, expected.SHA256) {
			return fmt.Errorf("verified component %q does not match the authenticated payload", name)
		}
	}
	return nil
}

func validateNotRun(got map[string]string) error {
	keys := []string{"nmap_runtime", "typst_pdf", "subfaster_runtime", "obscura_browser", "external_dns_providers", "strict_network_gate"}
	if len(got) != len(keys) {
		return errors.New("not_run declarations are incomplete or contain unexpected entries")
	}
	for _, key := range keys {
		value, ok := got[key]
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("not_run declaration %q is missing", key)
		}
		upper := strings.ToUpper(value)
		if key == "obscura_browser" {
			if !strings.Contains(upper, "BLOCKED") || !strings.Contains(upper, "CANDIDATE31") {
				return errors.New("browser declaration must preserve BLOCKED/candidate31 FAIL")
			}
		} else if !strings.Contains(upper, "NOT_RUN") && !(key == "strict_network_gate" && runtime.GOOS == "linux" && strings.Contains(upper, "FAIL_PRESERVED")) {
			return fmt.Errorf("%s must be explicitly NOT_RUN (or historical Linux FAIL_PRESERVED)", key)
		}
	}
	return nil
}

func errOr(err error, message string) error {
	if err != nil {
		return err
	}
	return errors.New(message)
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
