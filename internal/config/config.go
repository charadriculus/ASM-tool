// Package config parses and validates configuration without runtime probes or backend side effects.
package config

import (
	"asmtool/internal/core"
	"asmtool/internal/i18n"
	platformpath "asmtool/internal/platform/path"
	"asmtool/internal/version"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 1 << 20
const UserAgent = version.UserAgent

type ToolConfig struct {
	core.ScopePolicy             `yaml:",inline"`
	AuthorizationConfirmed       bool              `json:"authorization_confirmed" yaml:"authorization_confirmed"`
	AuditMode                    string            `json:"audit_mode" yaml:"audit_mode"`
	Owner                        string            `json:"owner" yaml:"owner"`
	TicketOrContractID           string            `json:"ticket_or_contract_id" yaml:"ticket_or_contract_id"`
	AggressiveCrawlEnabled       bool              `json:"aggressive_crawl_enabled" yaml:"aggressive_crawl_enabled"`
	AggressiveCrawlAuthorization string            `json:"aggressive_crawl_authorization" yaml:"aggressive_crawl_authorization"`
	Ports                        []int             `json:"ports" yaml:"ports"`
	RateLimits                   RateLimits        `json:"rate_limits" yaml:"rate_limits"`
	Modules                      Modules           `json:"modules" yaml:"modules"`
	Backends                     BackendsConfig    `json:"backends" yaml:"backends"`
	Reporting                    ReportingConfig   `json:"reporting" yaml:"reporting"`
	OutputDir                    string            `json:"output_dir" yaml:"output_dir"`
	DatabasePath                 string            `json:"database_path" yaml:"database_path"`
	UserAgent                    string            `json:"user_agent" yaml:"user_agent"`
	ExternalTools                map[string]string `json:"external_tools" yaml:"external_tools"`
	TargetDomain                 *string           `json:"target_domain" yaml:"target_domain"`
	Profile                      string            `json:"profile" yaml:"profile"`
	CollectionPolicy             CollectionPolicy  `json:"collection_policy" yaml:"collection_policy"`
}

func Default() (ToolConfig, error) {
	root, e := platformpath.DefaultOutputRoot()
	if e != nil {
		return ToolConfig{}, e
	}
	rate, policy, modules, reporting, backends := defaultSections()
	return ToolConfig{Profile: "passive", AuditMode: "authorized_audit", Ports: []int{80, 443}, RateLimits: rate, CollectionPolicy: policy, Modules: modules, Reporting: reporting, Backends: backends, OutputDir: filepath.Join(root, "default"), DatabasePath: filepath.Join(root, "default", "asm.sqlite3"), UserAgent: UserAgent, ExternalTools: map[string]string{}}, nil
}
func (c ToolConfig) EventsDir() string    { return filepath.Join(c.OutputDir, "events") }
func (c ToolConfig) ArtifactsDir() string { return filepath.Join(c.OutputDir, "artifacts") }
func (c ToolConfig) DirectTargetInteraction() bool {
	return c.Profile == "verify" || c.Profile == "full"
}
func (c ToolConfig) RequireActiveAllowed(target, kind string) (core.ScopeDecision, error) {
	return (core.ScopeChecker{Policy: c.ScopePolicy}).RequireActiveAllowed(c.Profile, c.AuthorizationConfirmed, target, kind)
}
func Load(filename string) (ToolConfig, error) {
	f, e := os.Open(filename)
	if e != nil {
		return ToolConfig{}, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if e != nil {
		return ToolConfig{}, e
	}
	return Parse(b)
}
func yamlDocument(data []byte) (*yaml.Node, error) {
	if len(data) > MaxConfigBytes || !utf8.Valid(data) {
		return nil, fmt.Errorf("config exceeds size limit or is not UTF-8")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	e := dec.Decode(&document)
	if e == io.EOF {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	if e != nil {
		return nil, e
	}
	var second yaml.Node
	if e = dec.Decode(&second); e != io.EOF {
		if e == nil {
			return nil, fmt.Errorf("multiple YAML documents are unsupported")
		}
		return nil, e
	}
	if len(document.Content) != 1 {
		return nil, fmt.Errorf("invalid YAML document")
	}
	node := document.Content[0]
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("configuration must be a mapping")
	}
	if e = rejectAISettings(node); e != nil {
		return nil, e
	}
	if e = validateYAML(node); e != nil {
		return nil, e
	}
	return node, nil
}

func validateKnownFields(node *yaml.Node, typ reflect.Type, prefix string) error {
	if node == nil || node.Kind != yaml.MappingNode || typ.Kind() != reflect.Struct {
		return nil
	}
	fields := make(map[string]reflect.Type, typ.NumField())
	var addFields func(reflect.Type)
	addFields = func(current reflect.Type) {
		for i := 0; i < current.NumField(); i++ {
			field := current.Field(i)
			if !field.IsExported() || field.Tag.Get("yaml") == "-" {
				continue
			}
			if field.Anonymous {
				addFields(field.Type)
				continue
			}
			name := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if name != "" {
				fields[name] = field.Type
			}
		}
	}
	addFields(typ)
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		fieldType, ok := fields[name]
		fieldPath := name
		if prefix != "" {
			fieldPath = prefix + "." + name
		}
		if !ok {
			return fmt.Errorf("unknown configuration field %s", fieldPath)
		}
		if err := validateKnownFields(node.Content[i+1], fieldType, fieldPath); err != nil {
			return err
		}
	}
	return nil
}
func rejectAISettings(n *yaml.Node) error {
	if nodeField(n, "ai_review") != nil {
		return fmt.Errorf("ai_review settings are no longer supported; remove ai_review from the configuration")
	}
	if modules := nodeField(n, "modules"); modules != nil && modules.Kind == yaml.MappingNode && nodeField(modules, "ai_review") != nil {
		return fmt.Errorf("modules.ai_review is no longer supported; remove it from the configuration")
	}
	return nil
}
func validateYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are unsupported")
	}
	switch n.Tag {
	case "!!map", "!!seq", "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp":
	default:
		return fmt.Errorf("unsupported YAML tag: %s", n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" {
				return fmt.Errorf("YAML mapping keys must be strings without merges")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate YAML key: %s", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if e := validateYAML(child); e != nil {
			return e
		}
	}
	return nil
}
func nodeField(n *yaml.Node, name string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			return n.Content[i+1]
		}
	}
	return nil
}
func validateScalarFields(n *yaml.Node, t reflect.Type) error {
	if n == nil {
		return nil
	}
	if t.Kind() == reflect.Bool {
		normalizeLegacyBool(n)
		if n.Tag != "!!bool" {
			return fmt.Errorf("must be a YAML boolean")
		}
	}
	if n.Tag == "!!null" {
		if t.Kind() == reflect.Int || t.Kind() == reflect.Float64 || t.Kind() == reflect.String {
			return fmt.Errorf("required scalar cannot be null")
		}
		return nil
	}
	if t.Kind() == reflect.Pointer {
		return validateScalarFields(n, t.Elem())
	}
	if t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode {
		for _, child := range n.Content {
			if e := validateScalarFields(child, t.Elem()); e != nil {
				return e
			}
		}
	}
	if t.Kind() == reflect.Int && n.Tag == "!!float" {
		var value float64
		if e := n.Decode(&value); e != nil {
			return e
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < -math.Exp2(float64(t.Bits()-1)) || value >= math.Exp2(float64(t.Bits()-1)) {
			return fmt.Errorf("integer field requires a finite integral value in range")
		}
	}
	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
			child := nodeField(n, tag)
			if field.Anonymous {
				child = n
			}
			if e := validateScalarFields(child, field.Type); e != nil {
				return fmt.Errorf("%s: %w", field.Name, e)
			}
		}
	}
	return nil
}

// PyYAML treats these plain tokens as booleans; quoted strings must never authorize an action.
func normalizeLegacyBool(n *yaml.Node) {
	if n.Tag != "!!str" || n.Style != 0 {
		return
	}
	switch n.Value {
	case "yes", "Yes", "YES", "on", "On", "ON":
		n.Tag = "!!bool"
		n.Value = "true"
	case "no", "No", "NO", "off", "Off", "OFF":
		n.Tag = "!!bool"
		n.Value = "false"
	}
}
func Parse(data []byte) (ToolConfig, error) {
	node, e := yamlDocument(data)
	if e != nil {
		return ToolConfig{}, e
	}
	// This decoder is also used by the separate user-settings schema. Enforce
	// ToolConfig field names here so settings keys such as reporting.default_language
	// remain valid in their own parser.
	if e = validateKnownFields(node, reflect.TypeOf(ToolConfig{}), ""); e != nil {
		return ToolConfig{}, e
	}
	cfg, e := Default()
	if e != nil {
		return ToolConfig{}, e
	}
	if e = validateScalarFields(node, reflect.TypeOf(cfg)); e != nil {
		return ToolConfig{}, e
	}
	for _, section := range []string{"collection_policy", "rate_limits", "modules", "backends", "reporting"} {
		if n := nodeField(node, section); n != nil && n.Tag != "!!null" && n.Kind != yaml.MappingNode {
			return ToolConfig{}, fmt.Errorf("%s must be a mapping", section)
		}
	}
	if e = node.Decode(&cfg); e != nil {
		return ToolConfig{}, e
	}
	// Python load_config links DB to output on Windows only; Linux retains its independent default.
	if runtime.GOOS == "windows" && nodeField(node, "database_path") == nil {
		cfg.DatabasePath = filepath.Join(cfg.OutputDir, "asm.sqlite3")
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{80, 443}
	}
	if e = cfg.Validate(); e != nil {
		return ToolConfig{}, e
	}
	if backends := nodeField(node, "backends"); backends != nil && backends.Tag != "!!null" {
		if fallback := nodeField(backends, "fallback_policy"); fallback != nil && fallback.Tag != "!!null" {
			cfg.Backends.fallbackPolicyExplicit = true
		}
	}
	return cfg, nil
}
func validateNumbers(v any) error {
	value := reflect.ValueOf(v)
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		name := typ.Field(i).Tag.Get("yaml")
		if field.Kind() == reflect.Pointer {
			if field.IsNil() {
				continue
			}
			field = field.Elem()
		}
		switch field.Kind() {
		case reflect.Float64:
			n := field.Float()
			if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
				return fmt.Errorf("%s must be finite and nonnegative", name)
			}
		case reflect.Int:
			if field.Int() < 0 {
				return fmt.Errorf("%s cannot be negative", name)
			}
		}
	}
	return nil
}
func (c *ToolConfig) Validate() error {
	c.Profile = strings.ToLower(c.Profile)
	if c.Profile != "passive" && c.Profile != "verify" && c.Profile != "full" {
		return fmt.Errorf("profile must be passive, verify or full")
	}
	if c.DirectTargetInteraction() && !c.AuthorizationConfirmed {
		return fmt.Errorf("active profiles require authorization_confirmed=true")
	}
	if e := c.ScopePolicy.Validate(); e != nil {
		return e
	}
	if c.DirectTargetInteraction() && !c.CollectionPolicy.BlockOutOfScopeBrowserRequests {
		return fmt.Errorf("active profiles require block_out_of_scope_browser_requests=true")
	}
	if c.Modules.Masscan {
		return fmt.Errorf("Masscan is disabled by the low-noise policy")
	}
	if c.AggressiveCrawlEnabled && (c.Profile != "full" || strings.TrimSpace(c.AggressiveCrawlAuthorization) == "") {
		return fmt.Errorf("aggressive crawl requires full profile and separate authorization")
	}
	for _, port := range c.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("ports must be between 1 and 65535")
		}
	}
	if strings.TrimSpace(c.OutputDir) == "" || strings.TrimSpace(c.DatabasePath) == "" {
		return fmt.Errorf("output and database paths cannot be empty")
	}
	lang, e := i18n.NormalizeLanguage(c.Reporting.Language)
	if e != nil || strings.TrimSpace(c.Reporting.Language) == "" {
		return fmt.Errorf("reporting.language must be en or ru")
	}
	c.Reporting.Language = lang
	r := reflect.ValueOf(c.Reporting)
	for i := 2; i < r.NumField(); i++ {
		n := r.Field(i).Int()
		if n < 0 || n > 10000 {
			return fmt.Errorf("reporting row limits must be between 0 and 10000")
		}
	}
	for _, v := range []any{c.RateLimits, c.CollectionPolicy, c.Backends} {
		if e := validateNumbers(v); e != nil {
			return e
		}
	}
	l := c.RateLimits
	if l.PassiveSourceRequestsPerSecond <= 0 || l.DNSQueriesPerSecond <= 0 || l.GlobalMaxRequestsPerSecond <= 0 || l.DNSWorkerCount < 1 || l.DNSWorkerCount > 64 || l.HTTPMaxRequestsPerHost < 1 || l.CrawlerMaxPagesPerOrigin < 1 || l.CrawlerMaxTotalPages < 1 || l.HTTPMaxConcurrency < 1 || l.HTTPMaxConcurrencyPerOrigin < 1 || l.BrowserNavigationTimeoutSeconds <= 0 || l.BrowserScreenshotTimeoutSeconds <= 0 || l.BrowserTargetTotalTimeoutSeconds <= 0 || l.ScreenshotMaxConcurrency < 1 || l.TCPMaxConcurrency < 1 || l.TCPMaxConcurrency > 32 || l.TCPMaxRate <= 0 || l.TCPMaxRate > 500 || l.TCPMaxTargets < 1 || l.TCPMaxTargets > 500 || l.TCPConnectTimeoutSeconds <= 0 || l.TCPConnectTimeoutSeconds > 120 {
		return fmt.Errorf("invalid rate/concurrency/timeout limits")
	}
	p := c.CollectionPolicy
	if p.PassiveProviderProfile != "standard" && p.PassiveProviderProfile != "deep" {
		return fmt.Errorf("passive_provider_profile must be standard or deep; research is excluded")
	}
	if p.PassiveInventorySafetyCap < 1 || p.DNSCandidateBudget < 1 || p.PassiveMaxIPs < 1 || p.WildcardProbesPerParent < 3 || p.WildcardMaxParentZones < 1 || p.WildcardMinCandidatesPerParent < 1 || p.PassiveSourceRetries < 1 || p.PassiveConnectTimeoutSeconds <= 0 || p.PassiveReadTimeoutSeconds <= 0 || p.CRTNameConnectTimeoutSeconds <= 0 || p.CRTNameReadTimeoutSeconds <= 0 {
		return fmt.Errorf("invalid collection budgets/timeouts")
	}
	for _, status := range p.StopOnHTTPStatuses {
		if status < 100 || status > 599 {
			return fmt.Errorf("invalid stop HTTP status")
		}
	}
	b := c.Backends
	if b.NativeSubprocessTimeoutSeconds < 1 || b.FallbackPolicy != "explicit" && b.FallbackPolicy != "disabled" {
		return fmt.Errorf("invalid backend timeout/fallback policy")
	}
	for field, allowed := range map[string][]string{"SerializationBackend": {"stdlib_json", "orjson"}, "SchemaBackend": {"python_jsonschema", "fastjsonschema", "rust_jsonschema"}, "PDFBackend": {"typst"}, "HTMLParserBackend": {"beautifulsoup", "lexbor"}, "DNSBackend": {"python_dnspython"}, "HTTPProbeBackend": {"python_requests", "go_net_http", "projectdiscovery_httpx"}, "CrawlerBackend": {"python_crawler"}} {
		value := reflect.ValueOf(b).FieldByName(field).String()
		found := false
		for _, a := range allowed {
			if a == value {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unsupported/excluded backend %s=%q", field, value)
		}
	}
	return nil
}
