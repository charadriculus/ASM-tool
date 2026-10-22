package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Options contains command-line values. Set records the option names the user
// explicitly supplied so configuration files cannot silently override them.
type Options struct {
	Browser                                                                                string
	ConfigPath, Domain, Profile, Ports, OutputDir, Language, PassiveSources, BundleDir     string
	NonInteractive, Authorized, FullReport, AllowHTTPFallback, Help, Version, ValidateOnly bool
	Set                                                                                    map[string]bool
	DNSBudget                                                                              int
	TimeoutSeconds                                                                         int
	PrimaryDomainOnly, IncludeWildcardAmbiguous                                            bool
}

const helpText = `ASM Tool ` + Version + `

Usage:
  asm-tool [start] [options]
  asm-tool run [options]
  asm-tool validate-config [options]
  asm-tool --help | --version

Options:
  --config PATH                 Read a local YAML configuration
  --domain, --target DOMAIN     Target domain
  --profile passive|verify|full Select a run profile (default: passive)
  --passive | --verify | --full Select a run profile
  --ports LIST                  Comma-separated TCP ports
  --output-dir PATH             Output directory
  --language en|ru              Report language (default: en)
  --passive-sources standard|deep
  --full-report                 Include the full report
  --browser disabled|required  Disable browser coverage or require browser coverage
  --allow-http-fallback         Explicitly permit the Go HTTP backend
  --yes, --confirm-authorization Confirm authorized active work
  --non-interactive             Do not prompt for input
  --validate-only               Validate configuration without collecting
  --bundle-dir PATH             Portable runtime bundle directory
  --dns-budget N                Maximum DNS candidates (default: 1000)
  --timeout-seconds N           Whole-run time limit, including reports (default: 3600)
  --primary-domain-only         Restrict active web targets to primary domain
  --include-wildcard-ambiguous  Include ambiguous wildcard candidates
`

// ParseOptions parses the supported user-facing CLI without reading files or
// performing network or process activity.
func ParseOptions(args []string) (Options, error) {
	opts := Options{Profile: "passive", Language: "en", PassiveSources: "standard", DNSBudget: 1000, TimeoutSeconds: 3600, Set: make(map[string]bool)}
	command := "start"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "start", "run":
	case "validate-config":
		opts.ValidateOnly = true
	default:
		return opts, unsupportedCommand(command)
	}

	fs := flag.NewFlagSet("asm-tool", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&opts.Browser, "browser", "", "disabled or required browser policy")
	fs.StringVar(&opts.ConfigPath, "config", "", "configuration file")
	fs.StringVar(&opts.Domain, "domain", "", "target domain")
	fs.StringVar(&opts.Domain, "target", "", "target domain")
	fs.StringVar(&opts.Profile, "profile", opts.Profile, "passive, verify, or full")
	var passive, verify, full bool
	fs.BoolVar(&passive, "passive", false, "select passive profile")
	fs.BoolVar(&verify, "verify", false, "select verify profile")
	fs.BoolVar(&full, "full", false, "select full profile")
	fs.StringVar(&opts.Ports, "ports", "", "TCP ports")
	fs.StringVar(&opts.OutputDir, "output-dir", "", "output directory")
	fs.StringVar(&opts.Language, "language", opts.Language, "en or ru")
	fs.StringVar(&opts.Language, "report-language", opts.Language, "en or ru")
	fs.StringVar(&opts.PassiveSources, "passive-sources", opts.PassiveSources, "standard or deep")
	fs.BoolVar(&opts.FullReport, "full-report", false, "include the full report")
	fs.BoolVar(&opts.AllowHTTPFallback, "allow-http-fallback", false, "explicitly allow Go HTTP backend")
	fs.BoolVar(&opts.Authorized, "yes", false, "confirm active-scope authorization")
	fs.BoolVar(&opts.Authorized, "confirm-authorization", false, "confirm active-scope authorization")
	fs.BoolVar(&opts.NonInteractive, "non-interactive", false, "disable prompts")
	fs.BoolVar(&opts.ValidateOnly, "validate-only", opts.ValidateOnly, "validate configuration only")
	fs.StringVar(&opts.BundleDir, "bundle-dir", "", "portable runtime bundle directory")
	fs.IntVar(&opts.DNSBudget, "dns-budget", opts.DNSBudget, "maximum DNS candidates")
	fs.IntVar(&opts.TimeoutSeconds, "timeout-seconds", opts.TimeoutSeconds, "whole-run time limit")
	fs.BoolVar(&opts.PrimaryDomainOnly, "primary-domain-only", false, "limit active web targets to the primary domain")
	fs.BoolVar(&opts.IncludeWildcardAmbiguous, "include-wildcard-ambiguous", false, "include wildcard-ambiguous candidates")
	fs.BoolVar(&opts.Help, "help", false, "show help")
	fs.BoolVar(&opts.Help, "h", false, "show help")
	fs.BoolVar(&opts.Version, "version", false, "show version")

	if err := fs.Parse(args); err != nil {
		message := err.Error()
		if strings.Contains(message, "ai") || strings.Contains(message, "ollama") || strings.Contains(message, "research") {
			return opts, fmt.Errorf("unsupported option: %s; AI and research options are not supported", message)
		}
		return opts, fmt.Errorf("invalid command line: %w", err)
	}
	if rest := fs.Args(); len(rest) != 0 {
		return opts, fmt.Errorf("unexpected argument %q", rest[0])
	}
	fs.Visit(func(f *flag.Flag) { opts.Set[f.Name] = true })
	if opts.Set["target"] {
		opts.Set["domain"] = true
	}
	if opts.Set["report-language"] {
		opts.Set["language"] = true
	}
	if opts.Set["confirm-authorization"] {
		opts.Set["yes"] = true
	}

	selected := make([]string, 0, 3)
	if passive {
		selected = append(selected, "passive")
	}
	if verify {
		selected = append(selected, "verify")
	}
	if full {
		selected = append(selected, "full")
	}
	if len(selected) > 1 {
		return opts, errors.New("conflicting profile flags; choose only one of --passive, --verify, or --full")
	}
	if len(selected) == 1 {
		if opts.Set["profile"] && opts.Profile != selected[0] {
			return opts, errors.New("conflicting --profile and profile shortcut flags")
		}
		opts.Profile = selected[0]
		opts.Set["profile"] = true
	}
	if opts.Profile != "passive" && opts.Profile != "verify" && opts.Profile != "full" {
		return opts, fmt.Errorf("unsupported profile %q; choose passive, verify, or full", opts.Profile)
	}
	if opts.PassiveSources == "research" || opts.PassiveSources == "research-oriented" {
		return opts, errors.New("research passive sources are unsupported")
	}
	if opts.PassiveSources != "standard" && opts.PassiveSources != "deep" {
		return opts, fmt.Errorf("unsupported passive source set %q; choose standard or deep", opts.PassiveSources)
	}
	if opts.Language != "en" && opts.Language != "ru" {
		return opts, errors.New("unsupported report language; choose en or ru")
	}
	if opts.DNSBudget < 0 {
		return opts, errors.New("--dns-budget must be non-negative")
	}
	if opts.TimeoutSeconds < 1 || opts.TimeoutSeconds > 86400 {
		return opts, errors.New("--timeout-seconds must be between 1 and 86400")
	}
	if opts.Authorized && opts.Profile == "passive" && opts.Set["profile"] {
		return opts, errors.New("authorization confirmation is not applicable to the passive profile")
	}
	if opts.Set["ports"] {
		ports, err := parsePorts(opts.Ports)
		if err != nil {
			return opts, err
		}
		opts.Ports = ports
	}
	if opts.Browser != "" && opts.Browser != "disabled" && opts.Browser != "required" {
		return opts, errors.New("browser policy must be disabled or required")
	}

	return opts, nil
}

func unsupportedCommand(command string) error {
	if strings.Contains(strings.ToLower(command), "ai") || strings.Contains(strings.ToLower(command), "research") || strings.Contains(strings.ToLower(command), "ollama") {
		return fmt.Errorf("unsupported command %q; AI and research commands are not supported", command)
	}
	return fmt.Errorf("unsupported command %q", command)
}

func parsePorts(raw string) (string, error) {
	parts := strings.FieldsFunc(strings.ReplaceAll(raw, ";", ","), func(r rune) bool { return r == ',' })
	ports := make(map[int]bool, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid TCP port %q; ports must be integers from 1 to 65535", part)
		}
		ports[port] = true
	}
	if len(ports) == 0 {
		return "", errors.New("--ports must contain at least one port")
	}
	values := make([]int, 0, len(ports))
	for port := range ports {
		values = append(values, port)
	}
	sort.Ints(values)
	formatted := make([]string, len(values))
	for i, port := range values {
		formatted[i] = strconv.Itoa(port)
	}
	return strings.Join(formatted, ","), nil
}

// RunCLI executes the command using caller-owned streams. It never creates a
// shell command. Exit codes are stable: 0 complete/help, 1 runtime failure,
// 2 input/configuration error, 3 unavailable phase capability,
// 4 incomplete result, 130 cancelled.
func RunCLI(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) int {
	opts, err := ParseOptions(args)
	if err != nil {
		fmt.Fprintln(errout, err)
		return 2
	}
	if opts.Help {
		_, _ = io.WriteString(out, helpText)
		return 0
	}
	if opts.Version {
		fmt.Fprintf(out, "%s %s/%s\n", Version, runtime.GOOS, runtime.GOARCH)
		return 0
	}
	prompts := newPromptReader(in, out)
	if opts.Domain == "" && opts.ConfigPath == "" {
		if opts.NonInteractive {
			fmt.Fprintln(errout, "a target domain is required in non-interactive mode")
			return 2
		}
		domain, promptErr := prompts.line(ctx, "Target domain: ")
		if promptErr != nil {
			if isInterrupted(ctx) {
				return 130
			}
			fmt.Fprintf(errout, "cannot read target domain: %v\n", promptErr)
			return 2
		}
		if isInterrupted(ctx) {
			return 130
		}
		opts.Domain = domain
		opts.Set["domain"] = true
	}
	if !opts.ValidateOnly && opts.Profile != "passive" && !opts.Authorized {
		if opts.NonInteractive {
			fmt.Fprintln(errout, "active profile requires --yes or --confirm-authorization")
			return 2
		}
		answer, promptErr := prompts.line(ctx, "Type AUTHORIZE to confirm that you may actively assess this target: ")
		if isInterrupted(ctx) {
			return 130
		}
		if promptErr != nil || answer != "AUTHORIZE" {
			fmt.Fprintln(errout, "active authorization was not confirmed")
			return 2
		}
		opts.Authorized = true
	}

	plan, err := Prepare(opts)
	if errors.Is(err, ErrAuthorizationRequired) && !opts.Authorized && !opts.NonInteractive && !opts.ValidateOnly {
		answer, promptErr := prompts.line(ctx, "Type AUTHORIZE to confirm that you may actively assess this target: ")
		if isInterrupted(ctx) {
			return 130
		}
		if promptErr != nil || answer != "AUTHORIZE" {
			fmt.Fprintln(errout, "active authorization was not confirmed")
			return 2
		}
		opts.Authorized = true
		opts.Set["yes"] = true
		plan, err = Prepare(opts)
	}
	if err != nil {
		fmt.Fprintln(errout, err)
		return 2
	}
	if opts.ValidateOnly {
		fmt.Fprintln(out, "configuration valid")
		return 0
	}
	result, err := Execute(ctx, plan, errout)
	if err != nil {
		fmt.Fprintln(errout, err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 130
		}
		return 1
	}
	fmt.Fprintf(out, "Run: %s\n", result.RunDir)
	for _, path := range []string{result.Outputs.JSON, result.Outputs.HTML, result.Outputs.PDF} {
		if path == "" {
			continue
		}
		fmt.Fprintf(out, "Report: %s\n", path)
	}
	if result.Incomplete {
		fmt.Fprintln(errout, "Run completed with incomplete results.")
		return 4
	}
	return 0
}

type promptReader struct {
	scanner *bufio.Scanner
	in      io.Reader
	out     io.Writer
}

func newPromptReader(in io.Reader, out io.Writer) *promptReader {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 256), 4096)
	return &promptReader{scanner: scanner, in: in, out: out}
}

func (p *promptReader) line(ctx context.Context, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	_, _ = io.WriteString(p.out, prompt)
	// Closing a closable input lets cancellation interrupt Scanner.Scan without
	// leaving a detached reader goroutine behind. An arbitrary io.Reader has no
	// cancellation contract, so its active Read can only finish on its own.
	stopClose := context.AfterFunc(ctx, func() {
		if closer, ok := p.in.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	defer stopClose()
	if !p.scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := p.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	value := strings.TrimSpace(p.scanner.Text())
	if value == "" {
		return "", errors.New("input cannot be empty")
	}
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("input must be valid UTF-8 without control characters")
	}
	return value, nil
}

func isInterrupted(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded)
}
