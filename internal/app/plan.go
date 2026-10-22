package app

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"asmtool/internal/backends"
	"asmtool/internal/config"
	"asmtool/internal/core"
	platformpath "asmtool/internal/platform/path"
	"asmtool/internal/version"
	"gopkg.in/yaml.v3"
)

// Version is the shared runtime identity used in run artifacts and reports.
const Version = version.Version

// BundleManifestSHA256 is injected into the executable for its exact payload.
// An unset anchor fails closed; runtime configuration cannot replace it.
var BundleManifestSHA256 string

var (
	ErrAuthorizationRequired = errors.New("active profile requires explicit authorization")
)

// Plan is opaque to callers: execution accepts only validated settings.
type Plan struct {
	cfg               config.ToolConfig
	target, bundleDir string
	allowHTTPFallback bool
	timeout           time.Duration
	active            activeSettings
	browserMode       string
}

// Prepare reads configuration only. It does not create output, probe tools,
// resolve DNS, or make network requests.
func Prepare(o Options) (Plan, error) {
	var suppliedYAML []byte
	cfg, err := config.Default()
	if err != nil {
		return Plan{}, err
	}
	if o.ConfigPath != "" {
		data, err := readConfig(o.ConfigPath)
		if err != nil {
			return Plan{}, err
		}
		suppliedYAML = data
		cfg, err = parseRunConfig(data, o)
		if err != nil {
			return Plan{}, fmt.Errorf("configuration: %w", err)
		}
	}
	explicit := func(key string) bool { return o.Set[key] }
	if explicit("profile") {
		cfg.Profile = o.Profile
	}
	if explicit("language") {
		cfg.Reporting.Language = o.Language
	}
	if explicit("full-report") {
		cfg.Reporting.FullReport = o.FullReport
	}
	if explicit("passive-sources") {
		cfg.CollectionPolicy.PassiveProviderProfile = o.PassiveSources
	}
	if explicit("dns-budget") {
		cfg.CollectionPolicy.DNSCandidateBudget = o.DNSBudget
	}
	if explicit("primary-domain-only") {
		cfg.CollectionPolicy.WebPrimaryDomainOnly = o.PrimaryDomainOnly
	}
	if explicit("include-wildcard-ambiguous") {
		cfg.CollectionPolicy.IncludeWildcardAmbiguousActive = o.IncludeWildcardAmbiguous
	}
	if explicit("ports") {
		ports, err := parsePorts(o.Ports)
		if err != nil {
			return Plan{}, err
		}
		cfg.Ports = nil
		for _, s := range strings.Split(ports, ",") {
			n, _ := strconv.Atoi(s)
			cfg.Ports = append(cfg.Ports, n)
		}
	}
	raw := o.Domain
	if raw == "" && !explicit("domain") && cfg.TargetDomain != nil {
		raw = *cfg.TargetDomain
	}
	target, err := targetDomain(raw)
	if err != nil {
		return Plan{}, fmt.Errorf("target: %w", err)
	}
	cfg.TargetDomain = &target
	// CLI-only scope is exactly the input domain; a YAML override never widens it.
	if o.ConfigPath == "" {
		cfg.AllowedDomains = []string{target}
	}
	if (core.ScopeChecker{Policy: cfg.ScopePolicy}).CheckDomain(target).Status != core.InScope {
		return Plan{}, errors.New("target is outside the configured allowed scope")
	}
	if o.Authorized {
		cfg.AuthorizationConfirmed = true
	}
	if cfg.Profile == "passive" && cfg.AuthorizationConfirmed {
		return Plan{}, errors.New("authorization confirmation is not applicable to passive")
	}
	if cfg.DirectTargetInteraction() && !cfg.AuthorizationConfirmed {
		return Plan{}, ErrAuthorizationRequired
	}
	browserMode := "disabled"
	if cfg.DirectTargetInteraction() {
		browserMode = "enabled"
		// Active defaults are applied only to absent YAML module switches.
		if !moduleSupplied(suppliedYAML, "web_probe") {
			cfg.Modules.WebProbe = true
		}
		if !moduleSupplied(suppliedYAML, "crawler") {
			cfg.Modules.Crawler = true
		}
		if moduleSupplied(suppliedYAML, "screenshots") && !cfg.Modules.Screenshots {
			browserMode = "disabled"
		}
		if o.Browser != "" {
			browserMode = o.Browser
		}
		if browserMode == "disabled" && cfg.Modules.Screenshots {
			return Plan{}, errors.New("browser disabled conflicts with requested screenshots; disable screenshots explicitly in YAML")
		}
		if (browserMode != "disabled" || cfg.Modules.WebProbe || cfg.Modules.Crawler || (cfg.Profile == "full" && cfg.Modules.PortScan)) && !cfg.Modules.DomainExpansion {
			return Plan{}, errors.New("active modules require current-run affirmative DNS validation; domain_expansion cannot be disabled")
		}
	} else if o.Browser == "required" {
		return Plan{}, errors.New("passive does not permit browser execution")
	}
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	if browserMode != "disabled" {
		limits := cfg.RateLimits
		if limits.BrowserNavigationTimeoutSeconds < 0.1 || limits.BrowserNavigationTimeoutSeconds > 20 || limits.BrowserScreenshotTimeoutSeconds > 20 || float64(limits.BrowserDomSettleMilliseconds) > limits.BrowserNavigationTimeoutSeconds*1000 {
			return Plan{}, errors.New("browser CDP bounds require navigation timeout 0.1..20 seconds, screenshot timeout <=20 seconds and DOM settle <= navigation timeout")
		}
	}
	if cfg.Profile == "passive" && (cfg.Modules.WebProbe || cfg.Modules.Crawler || cfg.Modules.Screenshots) {
		return Plan{}, errors.New("passive profile cannot enable HTTP, crawler, or screenshots")
	}
	if !cfg.Modules.PDFReport {
		return Plan{}, errors.New("phase-7 reports require pdf_report=true; selective report formats need a separate interface change")
	}
	if len(cfg.ExternalTools) != 0 {
		return Plan{}, errors.New("external_tools overrides are unsupported; use an authenticated portable payload")
	}
	for _, seconds := range []float64{cfg.CollectionPolicy.PassiveConnectTimeoutSeconds, cfg.CollectionPolicy.PassiveReadTimeoutSeconds, cfg.CollectionPolicy.CRTNameConnectTimeoutSeconds, cfg.CollectionPolicy.CRTNameReadTimeoutSeconds} {
		if seconds > 86400 {
			return Plan{}, errors.New("provider timeout exceeds the one-day integration bound")
		}
	}
	if cfg.Backends.NativeSubprocessTimeoutSeconds > 3600 {
		return Plan{}, errors.New("native timeout exceeds the one-hour integration bound")
	}
	if cfg.CollectionPolicy.PassiveCacheTTLHours > 8760 {
		return Plan{}, errors.New("passive cache TTL exceeds one year")
	}
	// A fresh run is mandatory. Explicit directories must be unused; default
	// output is outside the portable payload and identified independently.
	if o.ConfigPath == "" {
		root, err := platformpath.DefaultOutputRoot()
		if err != nil {
			return Plan{}, err
		}
		cfg.OutputDir = filepath.Join(root, target+"-"+time.Now().UTC().Format("20060102T150405.000000000"))
		cfg.DatabasePath = filepath.Join(cfg.OutputDir, "asm.sqlite3")
	}
	if explicit("output-dir") {
		cfg.OutputDir = o.OutputDir
		if o.ConfigPath == "" {
			cfg.DatabasePath = filepath.Join(cfg.OutputDir, "asm.sqlite3")
		}
	}
	cfg.OutputDir, err = absolutePath(cfg.OutputDir)
	if err != nil {
		return Plan{}, err
	}
	cfg.DatabasePath, err = absolutePath(cfg.DatabasePath)
	if err != nil {
		return Plan{}, err
	}
	if !within(cfg.OutputDir, cfg.DatabasePath) {
		return Plan{}, errors.New("database_path must be inside output_dir; set both paths explicitly in YAML")
	}
	bundleDir := o.BundleDir
	if bundleDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return Plan{}, err
		}
		bundleDir = filepath.Join(filepath.Dir(exe), "payload")
	}
	bundleDir, err = absolutePath(bundleDir)
	if err != nil {
		return Plan{}, err
	}
	if within(bundleDir, cfg.OutputDir) || within(cfg.OutputDir, bundleDir) {
		return Plan{}, errors.New("output directory and portable payload must be disjoint")
	}
	if err := safeOutputParents(cfg.OutputDir); err != nil {
		return Plan{}, err
	}
	timeout := o.TimeoutSeconds
	if timeout == 0 {
		timeout = 3600
	}
	if timeout < 1 || timeout > 86400 {
		return Plan{}, errors.New("whole-run timeout must be 1..86400 seconds")
	}
	plan := Plan{cfg: cfg, target: target, bundleDir: bundleDir, allowHTTPFallback: o.AllowHTTPFallback || cfg.Backends.HTTPFallbackAllowed(), timeout: time.Duration(timeout) * time.Second, browserMode: browserMode}
	if cfg.DirectTargetInteraction() {
		plan.active = makeActiveSettings(plan)
	}
	return plan, nil
}

func readConfig(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, config.MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > config.MaxConfigBytes {
		return nil, errors.New("configuration exceeds size limit")
	}
	return data, nil
}

// Apply explicit CLI values before the immutable parser performs semantic
// validation. A temporary authorization bit is used ONLY to validate a pending
// interactive plan; it is removed before returning and never reaches Execute.
func parseRunConfig(data []byte, o Options) (config.ToolConfig, error) {
	var doc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return config.Parse(data)
		}
		return config.ToolConfig{}, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return config.ToolConfig{}, errors.New("multiple YAML documents are unsupported")
	}
	// Keep empty/invalid/multiple-document handling in the canonical parser.
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return config.Parse(data)
	}
	root := doc.Content[0]
	if err := validateOriginalYAML(root); err != nil {
		return config.ToolConfig{}, err
	}
	if err := knownFields(root, reflect.TypeOf(config.ToolConfig{})); err != nil {
		return config.ToolConfig{}, err
	}
	field := func(n *yaml.Node, key string) *yaml.Node {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
		return nil
	}
	set := func(n *yaml.Node, key string, value any) {
		var encoded yaml.Node
		_ = encoded.Encode(value) // Bounded scalar/port-list values supplied by the parser.
		if old := field(n, key); old != nil {
			*old = encoded
			return
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &encoded)
	}
	if o.Set["profile"] {
		set(root, "profile", o.Profile)
	}
	if o.Authorized || o.Set["yes"] {
		set(root, "authorization_confirmed", o.Authorized)
	}
	overlay := func(section, key string, value any) {
		n := field(root, section)
		if n == nil || n.Tag == "!!null" {
			n = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			if old := field(root, section); old != nil {
				*old = *n
				n = old
			} else {
				root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: section}, n)
			}
		}
		if n.Kind == yaml.MappingNode {
			set(n, key, value)
		}
	}
	if o.Set["language"] {
		overlay("reporting", "language", o.Language)
	}
	if o.Set["full-report"] {
		overlay("reporting", "full_report", o.FullReport)
	}
	if o.Set["passive-sources"] {
		overlay("collection_policy", "passive_provider_profile", o.PassiveSources)
	}
	if o.Set["dns-budget"] {
		overlay("collection_policy", "dns_candidate_budget", o.DNSBudget)
	}
	if o.Set["primary-domain-only"] {
		overlay("collection_policy", "web_primary_domain_only", o.PrimaryDomainOnly)
	}
	if o.Set["include-wildcard-ambiguous"] {
		overlay("collection_policy", "include_wildcard_ambiguous_active", o.IncludeWildcardAmbiguous)
	}
	if o.Set["output-dir"] {
		set(root, "output_dir", o.OutputDir)
	}
	if o.Set["ports"] {
		normalized, err := parsePorts(o.Ports)
		if err != nil {
			return config.ToolConfig{}, err
		}
		var ports []int
		for _, value := range strings.Split(normalized, ",") {
			port, _ := strconv.Atoi(value)
			ports = append(ports, port)
		}
		set(root, "ports", ports)
	}
	profile := "passive"
	if n := field(root, "profile"); n != nil && n.Tag == "!!str" {
		profile = strings.ToLower(n.Value)
	}
	auth := field(root, "authorization_confirmed")
	pending := (profile == "verify" || profile == "full") && !o.Authorized &&
		(auth == nil || (auth.Tag == "!!bool" && auth.Value == "false") ||
			(auth.Tag == "!!str" && auth.Style == 0 && (strings.EqualFold(auth.Value, "no") || strings.EqualFold(auth.Value, "off"))))
	if pending {
		set(root, "authorization_confirmed", true)
	}
	// The node retains duplicate keys, aliases and tags for config.Parse to
	// reject. Extra documents have already been rejected from the original bytes.
	normalized, err := yaml.Marshal(&doc)
	if err != nil {
		return config.ToolConfig{}, err
	}
	cfg, err := config.Parse(normalized)
	if pending {
		cfg.AuthorizationConfirmed = false
	}
	return cfg, err
}

// Overrides may change values, but must never erase forbidden YAML syntax
// before the canonical parser can reject it.
func validateOriginalYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return errors.New("YAML aliases are unsupported")
	}
	switch n.Tag {
	case "!!map", "!!seq", "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp":
	default:
		return fmt.Errorf("unsupported YAML tag %q", n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return errors.New("YAML keys must be strings without merges")
			}
			if seen[key.Value] {
				return fmt.Errorf("duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := validateOriginalYAML(child); err != nil {
			return err
		}
	}
	return nil
}
func knownFields(n *yaml.Node, t reflect.Type) error {
	// Preserve phase-1 legacy unquoted boolean semantics when an overlay is
	// marshalled. Quoted strings never become authorization or boolean settings.
	if t.Kind() == reflect.Bool && n.Kind == yaml.ScalarNode && n.Tag == "!!str" && n.Style == 0 {
		switch strings.ToLower(n.Value) {
		case "yes", "on":
			n.Tag, n.Value = "!!bool", "true"
		case "no", "off":
			n.Tag, n.Value = "!!bool", "false"
		}
	}
	if n.Kind != yaml.MappingNode || t.Kind() != reflect.Struct {
		return nil
	}
	fields := map[string]reflect.Type{}
	var addFields func(reflect.Type)
	addFields = func(typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue
			}
			if f.Anonymous {
				addFields(f.Type)
				continue
			}
			key := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if key != "" && key != "-" {
				fields[key] = f.Type
			}
		}
	}
	addFields(t)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		typ, ok := fields[key]
		if !ok {
			return fmt.Errorf("unsupported configuration setting %q", key)
		}
		if err := knownFields(n.Content[i+1], typ); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

func targetDomain(raw string) (string, error) {
	if strings.Contains(raw, "://") {
		u, err := core.ParseHTTPURL(raw)
		if err != nil {
			return "", err
		}
		raw = u.Hostname()
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		return "", errors.New("a domain target is required; IP-only targets are unsupported")
	}
	return core.NormalizeDomain(raw)
}
func absolutePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || !utf8.ValidString(path) || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", errors.New("invalid output or payload path")
	}
	return filepath.Abs(path)
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func safeOutputParents(path string) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("output parent is not a regular directory")
			}
			// EvalSymlinks also detects symlink ancestors of an existing directory.
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				return err
			}
			if !samePath(real, p) {
				return errors.New("output parent contains symlinks")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		if filepath.Dir(p) == p {
			return err
		}
	}
}
func samePath(a, b string) bool {
	// filepath.Rel implements the host's volume/case rules.
	rel, err := filepath.Rel(a, b)
	return err == nil && rel == "."
}

// object preserves JSON numeric precision used by storage and schema adapters.
func object(value any) (map[string]any, error) {
	data, err := backends.EncodeJSON(value, false, true, false)
	if err != nil {
		return nil, err
	}
	decoded, err := backends.DecodeJSON(data)
	if err != nil {
		return nil, err
	}
	obj, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("expected JSON object")
	}
	return obj, nil
}

// moduleSupplied distinguishes a deliberate YAML opt-out from a default false.
// The complete document has already passed known-field/duplicate validation.
func moduleSupplied(data []byte, name string) bool {
	if len(data) == 0 {
		return false
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) != 1 {
		return false
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "modules" {
			continue
		}
		modules := root.Content[i+1]
		for j := 0; j+1 < len(modules.Content); j += 2 {
			if modules.Content[j].Value == name {
				return true
			}
		}
	}
	return false
}
