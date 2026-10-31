package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"asmtool/internal/backends"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/discovery/passive"
	"asmtool/internal/evidence"
)

const (
	internetDBProvider = "shodan_internetdb"
	maxInternetDBNames = 20
	maxInternetDBPorts = 256
	maxInternetDBText  = 512
)

var webPorts = map[int]bool{80: true, 443: true, 3000: true, 5000: true, 8000: true, 8080: true, 8443: true, 8888: true, 9443: true}
var httpsPorts = map[int]bool{443: true, 8443: true, 9443: true}
var sharedASNKeywords = []string{"cloudflare", "amazon", "akamai", "fastly", "google", "microsoft", "azure", "cloudfront", "digitalocean", "ovh", "hetzner", "hosting", "ru-center", "nic.ru"}
var sharedPTRKeywords = []string{"hosting", "shared", "server", "vps", "nic.ru"}

// collectPortInventory makes bounded passive-only InternetDB lookups for IPs
// already present in the DNS evidence index. It never resolves a target itself.
func collectPortInventory(ctx context.Context, cfg config.ToolConfig, index *evidence.DNSRunIndex, client *passive.Client, emit func(context.Context, core.Event) error) (bool, error) {
	if ctx == nil || emit == nil {
		return false, errors.New("passive port inventory requires a context and evidence sink")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !cfg.CollectionPolicy.InternetdbEnabled {
		return false, nil
	}
	if index == nil {
		return false, errors.New("passive port inventory requires a DNS evidence index")
	}
	if client == nil {
		return false, errors.New("passive port inventory requires a passive source client")
	}

	ips := index.IPs()
	incomplete := false
	if cfg.CollectionPolicy.PassiveMaxIPs > 0 && len(ips) > cfg.CollectionPolicy.PassiveMaxIPs {
		ips = ips[:cfg.CollectionPolicy.PassiveMaxIPs]
		incomplete = true
		event, err := inventoryLimitation("internal", "Passive port inventory was limited by the configured maximum IP count.", "passive_max_ips", "warning", "truncated")
		if err != nil {
			return true, err
		}
		if err := emit(ctx, event); err != nil {
			return true, err
		}
	}
	if len(ips) == 0 {
		event, err := inventoryLimitation("internal", "Passive port inventory was skipped because the root domain has no resolved IP address.", "no resolved IP addresses", "warning", "check_target_dns")
		if err != nil {
			return true, err
		}
		if err := emit(ctx, event); err != nil {
			return true, err
		}
		return true, nil
	}

	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return incomplete, err
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			// The index is expected to contain canonical addresses. Treat corruption
			// as incomplete evidence instead of querying a provider with raw input.
			incomplete = true
			event, eventErr := inventoryLimitation("internal", "A malformed IP address in the DNS evidence index was skipped.", "invalid indexed IP", "warning", "invalid_evidence")
			if eventErr != nil {
				return true, eventErr
			}
			if err := emit(ctx, event); err != nil {
				return true, err
			}
			continue
		}
		ip = addr.String()
		body, meta, err := passive.InternetDB(ctx, client, ip)
		if err != nil {
			if ctx.Err() != nil {
				return incomplete, ctx.Err()
			}
			incomplete = true
			event, eventErr := inventoryLimitation(internetDBProvider, "InternetDB did not return usable prior observations for this IP.", ip, "warning", "unavailable")
			if eventErr != nil {
				return true, eventErr
			}
			event.Metadata["error_type"] = meta.ErrorType
			if err := emit(ctx, event); err != nil {
				return true, err
			}
			continue
		}
		if len(body) == 0 || string(body) == "null" {
			// HTTP 404 is a normal no-observation response, not provider failure.
			event, eventErr := inventoryLimitation(internetDBProvider, "The source completed but has no prior observations for this IP address.", ip, "info", "no_results")
			if eventErr != nil {
				return incomplete, eventErr
			}
			if err := emit(ctx, event); err != nil {
				return incomplete, err
			}
			continue
		}

		observation, err := parseInternetDB(body)
		if err != nil {
			incomplete = true
			event, eventErr := inventoryLimitation(internetDBProvider, "InternetDB returned malformed observation data.", ip, "warning", "invalid_response")
			if eventErr != nil {
				return true, eventErr
			}
			if err := emit(ctx, event); err != nil {
				return true, err
			}
			continue
		}
		if observation.truncated {
			incomplete = true
			event, eventErr := inventoryLimitation(internetDBProvider, "InternetDB observation exceeded the per-response evidence bound.", ip, "warning", "truncated")
			if eventErr != nil {
				return true, eventErr
			}
			if err := emit(ctx, event); err != nil {
				return true, err
			}
		}
		mappedDomains := index.DomainsForIP(ip)
		if len(observation.ports) > 0 && len(mappedDomains) > maxInternetDBNames {
			incomplete = true
			event, eventErr := inventoryLimitation(internetDBProvider, "Passive port attribution was limited to the first 20 DNS-mapped domains for this IP.", ip, "warning", "truncated")
			if eventErr != nil {
				return true, eventErr
			}
			event.Metadata["mapped_domain_count"] = len(mappedDomains)
			event.Metadata["mapped_domain_limit"] = maxInternetDBNames
			if err := emit(ctx, event); err != nil {
				return true, err
			}
		}
		ref, err := persistInternetDBEvidence(cfg, observation.raw)
		if err != nil {
			return true, fmt.Errorf("persist InternetDB evidence: %w", err)
		}
		if err := emitRelatedInternetDBNames(ctx, cfg, ip, observation, ref, emit); err != nil {
			return incomplete, err
		}
		ports := append([]int(nil), observation.ports...)
		sort.Ints(ports)
		for _, port := range ports {
			if err := ctx.Err(); err != nil {
				return incomplete, err
			}
			if err := emitInternetDBPort(ctx, cfg, index, ip, port, observation, ref, emit); err != nil {
				return incomplete, err
			}
		}
	}
	return incomplete, nil
}

type internetDBObservation struct {
	raw       json.RawMessage
	eventRaw  map[string]any
	ports     []int
	hostnames []string
	tags      []string
	cpes      []string
	truncated bool
}

func parseInternetDB(data []byte) (internetDBObservation, error) {
	if _, err := backends.DecodeJSON(data); err != nil {
		return internetDBObservation{}, errors.New("InternetDB response must be valid UTF-8 JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return internetDBObservation{}, errors.New("InternetDB response must be a JSON object")
	}
	out := internetDBObservation{raw: append(json.RawMessage(nil), data...)}
	var err error
	if out.ports, out.truncated, err = parseInternetDBPorts(fields["ports"]); err != nil {
		return internetDBObservation{}, err
	}
	for _, field := range []struct {
		key   string
		dst   *[]string
		limit int
	}{{"hostnames", &out.hostnames, 253}, {"tags", &out.tags, maxInternetDBText}, {"cpes", &out.cpes, maxInternetDBText}} {
		values, cut, e := parseInternetDBStrings(fields[field.key], field.limit)
		if e != nil {
			return internetDBObservation{}, fmt.Errorf("InternetDB %s must be a bounded string array", field.key)
		}
		*field.dst = values
		out.truncated = out.truncated || cut
	}
	out.eventRaw = map[string]any{"ports": out.ports, "hostnames": out.hostnames, "tags": out.tags, "cpes": out.cpes}
	return out, nil
}

func parseInternetDBPorts(raw json.RawMessage) ([]int, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	values, truncated, err := boundedJSONArray(raw, maxInternetDBPorts)
	if err != nil {
		return nil, false, errors.New("InternetDB ports must be an array")
	}
	ports := make([]int, 0, len(values))
	seen := make(map[int]bool)
	for _, value := range values {
		var number json.Number
		dec := json.NewDecoder(strings.NewReader(string(value)))
		dec.UseNumber()
		if err := dec.Decode(&number); err != nil {
			continue // Historical behavior ignored values that were not decimal ports.
		}
		port, err := number.Int64()
		if err != nil {
			var text string
			if json.Unmarshal(value, &text) == nil && text != "" {
				port, err = strconv.ParseInt(text, 10, 64)
			}
		}
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		p := int(port)
		if !seen[p] {
			ports = append(ports, p)
			seen[p] = true
		}
	}
	return ports, truncated, nil
}

func parseInternetDBStrings(raw json.RawMessage, maxBytes int) ([]string, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	values, truncated, err := boundedJSONArray(raw, maxInternetDBNames)
	if err != nil {
		return nil, false, errors.New("expected array")
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return nil, false, errors.New("expected string value")
		}
		text = strings.TrimSpace(text)
		if text != "" {
			bounded, cut := truncateUTF8(text, maxBytes)
			out = append(out, bounded)
			truncated = truncated || cut
		}
	}
	return out, truncated, nil
}

func boundedJSONArray(raw json.RawMessage, limit int) ([]json.RawMessage, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, false, errors.New("expected array")
	}
	values := make([]json.RawMessage, 0, min(limit, 16))
	truncated := false
	for decoder.More() {
		if len(values) == limit {
			truncated = true
			break
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false, err
		}
		values = append(values, value)
	}
	return values, truncated, nil
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true
}

type internetDBEvidenceRef struct {
	Path   string
	SHA256 string
}

func persistInternetDBEvidence(cfg config.ToolConfig, raw json.RawMessage) (internetDBEvidenceRef, error) {
	if strings.TrimSpace(cfg.OutputDir) == "" {
		return internetDBEvidenceRef{}, errors.New("provider evidence requires a configured output directory")
	}
	canonical, err := backends.EncodeJSON(raw, true, true, true)
	if err != nil {
		return internetDBEvidenceRef{}, err
	}
	digest := backends.SHA256(canonical)
	filename := "internetdb-" + digest + ".json"
	path := filepath.Join(cfg.ArtifactsDir(), "internetdb", filename)
	if err := backends.WriteJSONAtomic(path, raw, true, true, true, true); err != nil {
		return internetDBEvidenceRef{}, err
	}
	return internetDBEvidenceRef{Path: filepath.ToSlash(filepath.Join("artifacts", "internetdb", filename)), SHA256: digest}, nil
}

func evidenceReference(ref internetDBEvidenceRef) map[string]any {
	return map[string]any{"provider_evidence_path": ref.Path, "provider_evidence_sha256": ref.SHA256}
}

func emitRelatedInternetDBNames(ctx context.Context, cfg config.ToolConfig, ip string, observation internetDBObservation, ref internetDBEvidenceRef, emit func(context.Context, core.Event) error) error {
	scope := core.ScopeChecker{Policy: cfg.ScopePolicy}
	count := 0
	for _, raw := range observation.hostnames {
		if count >= maxInternetDBNames {
			break
		}
		d := scope.CheckDomain(raw)
		if d.Status == core.InScope || d.NormalizedValue == "" {
			continue
		}
		count++
		event, err := core.NewEvent(core.DomainFound, "port_inventory", internetDBProvider, raw, d.NormalizedValue, d.Status)
		if err != nil {
			return err
		}
		event.Confidence = 0.2
		event.Relations = []map[string]any{{"source_id": "ip:" + ip, "target_id": "domain:" + d.NormalizedValue, "relation_type": "shares_ip_observation", "evidence": map[string]any{"source": internetDBProvider}}}
		event.Metadata = map[string]any{"collection": "passive_osint", "context_only": true, "not_added_to_active_scope": true, "related_via_ip": ip, "attribution_warning": "shared-IP hostname; not proof of relation to target"}
		for key, value := range evidenceReference(ref) {
			event.Metadata[key] = value
		}
		if err := emit(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func emitInternetDBPort(ctx context.Context, cfg config.ToolConfig, index *evidence.DNSRunIndex, ip string, port int, observation internetDBObservation, ref internetDBEvidenceRef, emit func(context.Context, core.Event) error) error {
	domains := index.DomainsForIP(ip)
	domainCount := len(domains)
	if domainCount > maxInternetDBNames {
		domains = domains[:maxInternetDBNames]
	}
	shared := sharedInfrastructureIndicators(cfg.ScopePolicy, index, ip, observation)
	status := core.NeedsManualReview
	confidence := 0.58
	if len(shared) == 0 && len(domains) > 0 {
		status = core.InScope
	} else {
		confidence = 0.44
	}
	metadata := map[string]any{
		"ip": ip, "port": port, "protocol": "tcp", "state": "observed_open",
		"observation_type": "passive_osint", "source_freshness": "provider-maintained; not live-confirmed",
		"cpes": observation.cpes, "tags": observation.tags, "hostnames": observation.hostnames,
		"mapped_in_scope_domains": domains, "mapped_in_scope_domains_total": domainCount,
		"mapped_in_scope_domains_truncated": domainCount > maxInternetDBNames,
		"shared_infrastructure_indicators":  shared,
		"attribution_status":                "ip_level_only",
	}
	if len(shared) > 0 {
		metadata["attribution_status"] = "ip_level_only_shared_possible"
	}
	if len(domains) == 0 {
		metadata["context_only"] = true
		metadata["not_added_to_active_scope"] = true
		metadata["attribution_status"] = "unmapped_ip_context_only"
	}
	for key, value := range evidenceReference(ref) {
		metadata[key] = value
	}
	value := fmt.Sprintf("%s:%d", ip, port)
	event, err := core.NewEvent(core.PortFound, "port_inventory", internetDBProvider, observation.eventRaw, value, status)
	if err != nil {
		return err
	}
	event.Confidence = confidence
	event.Metadata = metadata
	if err := emit(ctx, event); err != nil {
		return err
	}
	if !webPorts[port] {
		return nil
	}
	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	for _, host := range domains {
		if err := ctx.Err(); err != nil {
			return err
		}
		url := fmt.Sprintf("%s://%s/", scheme, host)
		if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
			url = fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		}
		webEvent, err := core.NewEvent(core.WebServiceFound, "port_inventory", internetDBProvider, observation.eventRaw, url, core.InScope)
		if err != nil {
			return err
		}
		webConfidence := 0.52
		if len(shared) > 0 {
			webConfidence = 0.42
		}
		webEvent.Confidence = webConfidence
		webEvent.Relations = []map[string]any{{"source_id": "domain:" + host, "target_id": fmt.Sprintf("service:%s:tcp:%d", ip, port), "relation_type": "possible_service_on_resolved_ip", "evidence": map[string]any{"source": internetDBProvider, "live_confirmed": false}}}
		webEvent.Metadata = map[string]any{"ip": ip, "port": port, "protocol": "tcp", "observation_type": "passive_osint", "url_inferred": true, "url_host_source": "in_scope_dns_mapping", "live_confirmed": false, "shared_infrastructure_indicators": shared}
		for key, value := range evidenceReference(ref) {
			webEvent.Metadata[key] = value
		}
		if err := emit(ctx, webEvent); err != nil {
			return err
		}
	}
	return nil
}

func sharedInfrastructureIndicators(policy core.ScopePolicy, index *evidence.DNSRunIndex, ip string, observation internetDBObservation) []string {
	var indicators []string
	scopeMatches := 0
	for _, host := range observation.hostnames {
		if (core.ScopeChecker{Policy: policy}).CheckDomain(host).Status != core.InScope {
			scopeMatches++
		}
	}
	if scopeMatches > 0 {
		indicators = append(indicators, fmt.Sprintf("InternetDB contains unrelated hostnames (%d)", scopeMatches))
	}
	for _, ptr := range index.PTRNamesForIP(ip) {
		value := strings.ToLower(ptr)
		if containsAny(value, sharedPTRKeywords) {
			indicators = append(indicators, "PTR indicates hosting/shared infrastructure")
			break
		}
	}
	for _, name := range index.ASNNamesForIP(ip) {
		if containsAny(strings.ToLower(name), sharedASNKeywords) {
			indicators = append(indicators, "ASN name indicates hosting/cloud provider")
			break
		}
	}
	return indicators
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func inventoryLimitation(source, raw, normalized, severity, sourceStatus string) (core.Event, error) {
	event, err := core.NewEvent(core.Limitation, "port_inventory", source, raw, normalized, core.InScope)
	if err != nil {
		return core.Event{}, err
	}
	event.Confidence = 1
	event.Metadata = map[string]any{"severity": severity, "source_status": sourceStatus}
	if source != "internal" {
		event.Metadata["collection"] = "passive_osint"
		event.Metadata["target_contacted"] = false
	}
	if sourceStatus == "no_results" {
		event.Metadata["target_contacted"] = false
	}
	if sourceStatus == "check_target_dns" {
		event.Metadata["action"] = "check_target_dns"
	}
	return event, nil
}
