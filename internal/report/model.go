package report

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/i18n"
	"asmtool/internal/storage"
)

// Input describes a stopped, persisted run. The caller supplies run settings;
// reporting never invokes discovery or infers authorization from findings.
type Input struct {
	DatabasePath         string
	OutputDir            string
	Version              string
	Profile              string
	GeneratedAt          time.Time
	TargetDomain         string
	Language             string
	FullReport           bool
	RowLimits            RowLimits
	Scope                map[string]any
	Modules              map[string]any
	CollectionPolicy     map[string]any
	Coverage             map[string]any
	BackendProvenance    map[string]any
	EventFiles           []string
	FontDir              string
	AggressiveEnabled    bool
	AggressiveAuthorized bool
	ConfirmedWebTargets  []ConfirmedWebTarget
}

// RowLimits are presentation limits. Zero selects the historical user default.
type RowLimits struct {
	Domain        int
	IP            int
	Routing       int
	RelatedDomain int
	Port          int
	WebCoverage   int
	Web           int
	Document      int
	Screenshot    int
}

func (l RowLimits) normalized() (RowLimits, error) {
	values := []*int{&l.Domain, &l.IP, &l.Routing, &l.RelatedDomain, &l.Port, &l.WebCoverage, &l.Web, &l.Document, &l.Screenshot}
	defaults := []int{200, 200, 50, 50, 100, 100, 40, 50, 30}
	for i, p := range values {
		if *p < 0 {
			return l, errors.New("negative report row limit")
		}
		if *p == 0 {
			*p = defaults[i]
		}
	}
	return l, nil
}

func (l RowLimits) asMap() map[string]any {
	return map[string]any{
		"domain_rows": l.Domain, "ip_rows": l.IP, "routing_rows": l.Routing,
		"related_domain_rows": l.RelatedDomain, "port_rows": l.Port,
		"web_coverage_rows": l.WebCoverage, "web_rows": l.Web,
		"document_rows": l.Document, "screenshot_rows": l.Screenshot,
	}
}

func readRows(ctx context.Context, db *sql.DB, query string) ([]map[string]any, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0)
	for rows.Next() {
		raw := make([]sql.RawBytes, len(cols))
		dest := make([]any, len(cols))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, name := range cols {
			if raw[i] != nil {
				row[name] = string(raw[i])
			} else {
				row[name] = nil
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func decodeField(row map[string]any, name string, empty any) error {
	value := row[name]
	if value == nil {
		row[name] = empty
		return nil
	}
	s, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s is not text", name)
	}
	v, err := backends.DecodeJSON([]byte(s))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	row[name] = v
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func asList(v any) []any {
	a, _ := v.([]any)
	return a
}

func latest(item map[string]any) map[string]any {
	return asObject(asObject(item["data"])["latest"])
}

func objectEntry(row map[string]any) (map[string]any, error) {
	for _, col := range []string{"sources", "data"} {
		empty := any(map[string]any{})
		if col == "sources" {
			empty = []any{}
		}
		if err := decodeField(row, col, empty); err != nil {
			return nil, err
		}
	}
	if _, ok := row["sources"].([]any); !ok {
		return nil, errors.New("sources must be a JSON array")
	}
	if _, ok := row["data"].(map[string]any); !ok {
		return nil, errors.New("data must be a JSON object")
	}
	for _, source := range asList(row["sources"]) {
		if _, ok := source.(string); !ok {
			return nil, errors.New("sources must contain strings")
		}
	}
	if last, exists := asObject(row["data"])["latest"]; exists {
		event, ok := last.(map[string]any)
		if !ok {
			return nil, errors.New("latest must be a JSON object")
		}
		if meta, exists := event["metadata"]; exists {
			if _, ok := meta.(map[string]any); !ok {
				return nil, errors.New("latest metadata must be a JSON object")
			}
		}
	}
	confidence := any(nil)
	if row["confidence"] != nil {
		f, err := strconv.ParseFloat(str(row["confidence"]), 64)
		if err != nil {
			return nil, fmt.Errorf("confidence: %w", err)
		}
		confidence = f
	}
	return map[string]any{
		"id": row["object_id"], "value": row["value"],
		"scope_status": row["scope_status"], "confidence": confidence,
		"sources": row["sources"], "data": row["data"],
	}, nil
}

func countSummary(assets map[string]any, ports, web, dns, shots, limitations, crawler, webCoverage, sourceHealth []any, target string, validated map[string]bool, browserCoverage map[string]any) map[string]any {
	inZone, subdomains, checked, related := 0, 0, 0, 0
	root := 0
	for _, raw := range asList(assets["domains"]) {
		name := str(asObject(raw)["value"])
		if name == target {
			root++
			inZone++
			continue
		}
		if strings.HasSuffix(name, "."+target) {
			inZone++
			subdomains++
			if validated[name] {
				checked++
			}
		} else {
			related++
		}
	}
	passivePorts, activePorts, tcpClosed, tcpUnknown, tcpAttempted, crawlerPages, downloads := 0, 0, 0, 0, 0, 0, 0
	for _, raw := range ports {
		item := asObject(raw)
		meta := asObject(latest(item)["metadata"])
		tcpResult := str(latest(item)["event_type"]) == "port_scan_result"
		for _, source := range asList(item["sources"]) {
			if source == "shodan_internetdb" {
				passivePorts++
			}
			if source == "tcp_connect" {
				tcpResult = true
			}
		}
		if !tcpResult {
			continue
		}
		if meta["attempted"] == true {
			tcpAttempted++
		}
		switch str(meta["state"]) {
		case "open":
			activePorts++
		case "closed":
			tcpClosed++
		default:
			tcpUnknown++
		}
	}
	for _, raw := range crawler {
		meta := asObject(latest(asObject(raw))["metadata"])
		if meta["category"] == "downloadable_resource_detected" {
			downloads++
		}
		if meta["page_loaded"] == true || (meta["page_loaded"] == nil && meta["category"] != "downloadable_resource_detected") {
			crawlerPages++
		}
	}
	attempted, loaded, withShots, pages := 0, 0, 0, 0
	complete := true
	for _, raw := range webCoverage {
		row := asObject(raw)
		if row["root_status"] != "not_attempted" || row["browser_page_loaded"] == true {
			attempted++
		}
		if row["root_page_loaded"] == true || row["browser_page_loaded"] == true {
			loaded++
		}
		if n, ok := row["screenshots"].(int); ok && n > 0 {
			withShots++
		}
		if n, ok := row["pages_loaded"].(int); ok {
			pages += n
		}
		if row["screenshot_complete"] != true {
			complete = false
		}
	}
	failures := 0
	for _, raw := range sourceHealth {
		if asObject(raw)["status"] == "unavailable" {
			failures++
		}
	}
	if browserCoverage["browser_required"] == true && browserCoverage["browser_availability"] == "security_blocked" {
		complete = false
	}
	result := map[string]any{
		"root_domains": root, "domains": inZone,
		"discovered_subdomains":          subdomains,
		"dns_validated_subdomains":       checked,
		"unvalidated_passive_candidates": subdomains - checked,
		"related_context_domains":        related,
		"ips":                            len(asList(assets["ips"])), "asn": len(asList(assets["asn"])),
		"cidrs": len(asList(assets["cidrs"])), "dns_records": len(dns),
		"ports_total": len(ports), "ports_from_passive_sources": passivePorts, "ports_actively_confirmed": activePorts,
		"ports_tcp_open": activePorts, "ports_tcp_closed": tcpClosed, "ports_tcp_unknown": tcpUnknown, "ports_tcp_attempted": tcpAttempted,
		"web_objects": len(web), "crawler_pages": crawlerPages, "downloadable_resources": downloads,
		"web_targets_planned": len(webCoverage), "web_targets_attempted": attempted, "web_targets_loaded": loaded,
		"web_targets_with_screenshots": withShots, "web_pages_loaded": pages, "screenshot_coverage_complete": complete,
		"screenshots": len(shots), "limitations": len(limitations), "source_failures": failures,
	}
	if mode := str(browserCoverage["browser_mode"]); mode != "" {
		result["browser_mode"] = mode
		result["browser_required"] = browserCoverage["browser_required"]
		result["browser_availability"] = browserCoverage["browser_availability"]
		result["screenshots_status"] = browserCoverage["screenshots_status"]
		for _, key := range []string{"browser_security_status", "browser_known_network_risk"} {
			if v, ok := browserCoverage[key]; ok {
				result[key] = v
			}
		}
	}
	return result
}

func keyObservations(summary map[string]any, shots, web, sourceHealth []any, profile string) []any {
	out := []any{}
	count := func(key string) int { n, _ := summary[key].(int); return n }
	if count("discovered_subdomains") > 0 {
		out = append(out, fmt.Sprintf("Additional subdomains discovered from public sources: %d; validated by public DNS: %d.", count("discovered_subdomains"), count("dns_validated_subdomains")))
	} else {
		out = append(out, "No additional subdomains were discovered from the available passive sources.")
	}
	if count("ips") > 0 {
		out = append(out, fmt.Sprintf("IP addresses associated with the assessed domain names: %d.", count("ips")))
	}
	if count("related_context_domains") > 0 {
		out = append(out, fmt.Sprintf("Related contextual domain names observed: %d; they remain out of scope and require manual ownership review.", count("related_context_domains")))
	}
	if count("ports_from_passive_sources") > 0 {
		out = append(out, fmt.Sprintf("InternetDB supplied %d historical port observations; these are not current TCP connection results.", count("ports_from_passive_sources")))
	}
	if count("ports_actively_confirmed") > 0 {
		out = append(out, fmt.Sprintf("TCP ports with successful connections: %d.", count("ports_actively_confirmed")))
	}
	if count("crawler_pages") > 0 {
		out = append(out, fmt.Sprintf("Pages processed by the crawler in full mode: %d.", count("crawler_pages")))
	}
	reachable := 0
	for _, raw := range web {
		code := reportInt(asObject(latest(asObject(raw))["metadata"])["status_code"])
		if code >= 100 && code < 500 {
			reachable++
		}
	}
	if reachable > 0 {
		out = append(out, fmt.Sprintf("Web resources that responded during limited HTTP verification: %d.", reachable))
	}
	unavailable := []string{}
	for _, raw := range sourceHealth {
		row := asObject(raw)
		if row["status"] == "unavailable" && row["optional"] != true {
			name := str(row["label"])
			if name == "" {
				name = str(row["source"])
			}
			unavailable = append(unavailable, name)
		}
	}
	if len(unavailable) > 0 {
		out = append(out, "Unavailable external sources: "+strings.Join(unavailable, ", ")+".")
	}
	if len(shots) > 0 {
		out = append(out, fmt.Sprintf("Screenshots retained for loaded pages: %d.", len(shots)))
	}
	if count("downloadable_resources") > 0 {
		out = append(out, fmt.Sprintf("Documents/downloadable resources discovered: %d; they were not processed as HTML pages.", count("downloadable_resources")))
	}
	if profile == "verify" || profile == "full" {
		out = append(out, fmt.Sprintf("Mandatory web verification produced a terminal result for %d of %d planned domains; pages loaded: %d, screenshots retained: %d.", count("web_targets_attempted"), count("web_targets_planned"), count("web_pages_loaded"), count("screenshots")))
	}
	return out
}

func providerHealthArtifact(dir, target, version string) ([]any, error) {
	f, err := os.OpenInRoot(dir, filepath.Join("artifacts", "passive_provider_completeness.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return nil, errors.New("invalid passive completeness artifact")
	}
	b, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 8<<20 {
		return nil, errors.New("passive completeness artifact exceeds 8 MiB")
	}
	decoded, err := backends.DecodeJSON(b)
	if err != nil {
		return nil, err
	}
	root, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("passive completeness artifact must be an object")
	}
	if reportString(root["schema_version"]) != "1" || str(root["domain"]) != target || str(root["asm_version"]) != version {
		return nil, errors.New("passive completeness artifact identity mismatch")
	}
	rows, ok := root["providers"].([]any)
	if !ok {
		return nil, errors.New("passive completeness providers must be an array")
	}
	out := make([]any, 0, len(rows))
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("passive completeness provider must be an object")
		}
		provider := str(row["provider"])
		if provider == "" {
			provider = "unknown"
		}
		collector := str(row["collector"])
		if collector == "" {
			collector = "unknown"
		}
		completeness := str(row["completeness_state"])
		if completeness == "" {
			completeness = "collector_success_completeness_unknown"
		}
		anomaly := str(row["anomaly_status"])
		if anomaly == "" {
			anomaly = "not_evaluated_no_comparable_history"
		}
		warning := any(nil)
		if anomaly == "provider_output_anomaly" {
			warning = provider + ": output is substantially below comparable prior observations; current-run source completeness is not confirmed."
		} else if provider == "thc" && completeness != "complete" && completeness != "complete_empty" {
			warning = "THC: the collector completed technically, but current-run provider pagination completeness is not confirmed."
		}
		termination := str(row["termination"])
		if termination == "" {
			termination = "unknown"
		}
		status := str(row["collector_status"])
		if status == "" {
			status = "unknown"
		}
		out = append(out, map[string]any{"provider": provider, "collector": collector, "returned": row["returned"], "accepted": row["accepted"], "unique_contribution": row["unique"], "duplicates": row["duplicates"], "collector_status": status, "completeness_state": completeness, "termination_reason": termination, "anomaly_status": anomaly, "warning": warning})
	}
	return out, nil
}

func joinedSet(values map[string]bool) string {
	var out []string
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

func rankDomains(domains []any, observations []map[string]any) {
	type facts struct {
		providers, families      map[string]bool
		ct, aggregate, firstSeen bool
	}
	byName := map[string]*facts{}
	for _, row := range observations {
		name := str(row["hostname"])
		f := byName[name]
		if f == nil {
			f = &facts{providers: map[string]bool{}, families: map[string]bool{}}
			byName[name] = f
		}
		provider, family := str(row["provider"]), str(row["evidence_family"])
		if provider != "" && provider != "unknown_aggregate" {
			f.providers[provider] = true
		}
		if family != "" && family != "unknown_aggregate" {
			f.families[family] = true
		}
		if provider == "crt.sh" || provider == "certspotter" {
			f.ct = true
		}
		if family == "mixed_third_party_index" {
			f.aggregate = true
		}
		if str(row["first_seen_by_provider"]) != "" {
			f.firstSeen = true
		}
	}
	sort.Slice(domains, func(i, j int) bool {
		a, b := str(asObject(domains[i])["value"]), str(asObject(domains[j])["value"])
		fa, fb := byName[a], byName[b]
		if fa == nil {
			fa = &facts{}
		}
		if fb == nil {
			fb = &facts{}
		}
		if len(fa.providers) != len(fb.providers) {
			return len(fa.providers) > len(fb.providers)
		}
		if len(fa.families) != len(fb.families) {
			return len(fa.families) > len(fb.families)
		}
		if fa.ct != fb.ct {
			return fa.ct
		}
		if fa.aggregate != fb.aggregate {
			return fa.aggregate
		}
		if fa.firstSeen != fb.firstSeen {
			return fa.firstSeen
		}
		return a < b
	})
}

func buildDomainCSV(domains []any, target string, providerRows, dnsRows []map[string]any, dnsObjects []any) ([]byte, int, error) {
	type providerFacts struct {
		providers, collectors, families map[string]bool
		firstSeen                       string
	}
	providers := map[string]*providerFacts{}
	for _, row := range providerRows {
		name := str(row["hostname"])
		p := providers[name]
		if p == nil {
			p = &providerFacts{map[string]bool{}, map[string]bool{}, map[string]bool{}, ""}
			providers[name] = p
		}
		if v := str(row["provider"]); v != "" && v != "unknown_aggregate" {
			p.providers[v] = true
		}
		if v := str(row["collector"]); v != "" {
			p.collectors[v] = true
		}
		if v := str(row["evidence_family"]); v != "" && v != "unknown_aggregate" {
			p.families[v] = true
		}
		if v := str(row["first_seen_by_provider"]); v != "" && (p.firstSeen == "" || v < p.firstSeen) {
			p.firstSeen = v
		}
	}
	dnsState := map[string]map[string]any{}
	for _, row := range dnsRows {
		name := str(row["hostname"])
		if err := decodeField(row, "data", map[string]any{}); err != nil {
			return nil, 0, err
		}
		dnsState[name] = row
	}
	records := map[string]map[string]map[string]bool{}
	for _, raw := range dnsObjects {
		norm := asObject(latest(asObject(raw))["normalized_value"])
		name, kind, value := str(norm["name"]), strings.ToUpper(str(norm["type"])), str(norm["value"])
		if name == "" || value == "" || (kind != "A" && kind != "AAAA" && kind != "CNAME") {
			continue
		}
		if records[name] == nil {
			records[name] = map[string]map[string]bool{}
		}
		if records[name][kind] == nil {
			records[name][kind] = map[string]bool{}
		}
		records[name][kind][value] = true
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"hostname", "scope_status", "rank", "dns_state", "active_eligibility", "providers", "collectors", "evidence_families", "wildcard_state", "A", "AAAA", "CNAME", "first_seen", "deferred_by_dns_budget"}); err != nil {
		return nil, 0, err
	}
	total := 0
	for _, raw := range domains {
		domain := asObject(raw)
		name := str(domain["value"])
		if name == target || !strings.HasSuffix(name, "."+target) {
			continue
		}
		total++
		state := dnsState[name]
		dnsKind := str(state["dns_state"])
		if dnsKind == "" {
			dnsKind = "not_evaluated"
		}
		eligibility := str(state["active_eligibility"])
		if eligibility == "" {
			eligibility = "not_evaluated"
		}
		facts := providers[name]
		if facts == nil {
			facts = &providerFacts{map[string]bool{}, map[string]bool{}, map[string]bool{}, ""}
		}
		wildcard := str(asObject(state["data"])["wildcard_parent_state"])
		if wildcard == "" && strings.HasPrefix(dnsKind, "resolved_wildcard_") {
			wildcard = strings.TrimPrefix(dnsKind, "resolved_")
		}
		fields := []string{name, str(domain["scope_status"]), strconv.Itoa(total),
			dnsKind, eligibility, joinedSet(facts.providers), joinedSet(facts.collectors),
			joinedSet(facts.families), wildcard, joinedSet(records[name]["A"]),
			joinedSet(records[name]["AAAA"]), joinedSet(records[name]["CNAME"]),
			facts.firstSeen, strconv.FormatBool(dnsKind == "deferred_by_dns_budget")}
		if err := w.Write(fields); err != nil {
			return nil, 0, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, 0, err
	}
	return b.Bytes(), total, nil
}

// Load assembles the historical report-schema projection from a read-only
// SQLite snapshot. Unknown or malformed persisted JSON fails closed.
func Load(ctx context.Context, in Input) (map[string]any, []byte, error) {
	if ctx == nil || in.DatabasePath == "" || in.OutputDir == "" || in.Version == "" || in.TargetDomain == "" || in.GeneratedAt.IsZero() {
		return nil, nil, errors.New("database, output directory, version, target and generation time are required")
	}
	if in.Profile != "passive" && in.Profile != "verify" && in.Profile != "full" {
		return nil, nil, errors.New("invalid report profile")
	}
	if in.Scope == nil || in.Modules == nil || in.CollectionPolicy == nil || in.Coverage == nil {
		return nil, nil, errors.New("run scope, modules, collection policy and coverage are required")
	}
	if (in.Profile == "verify" || in.Profile == "full") && in.ConfirmedWebTargets == nil {
		return nil, nil, errors.New("confirmed web target plan is required for web coverage")
	}
	language, err := i18n.NormalizeLanguage(in.Language)
	if err != nil {
		return nil, nil, err
	}
	in.Language = language
	limits, err := in.RowLimits.normalized()
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := storage.OpenLegacySnapshot(ctx, in.DatabasePath)
	if err != nil {
		return nil, nil, fmt.Errorf("SQLite snapshot: %w", err)
	}
	defer snapshot.Close()
	db := snapshot.DB
	objects, err := readRows(ctx, db, "SELECT * FROM objects ORDER BY object_id")
	if err != nil {
		return nil, nil, err
	}
	limitationRows, err := readRows(ctx, db, "SELECT * FROM limitations ORDER BY observed_at,limitation_id")
	if err != nil {
		return nil, nil, err
	}
	relationRows, err := readRows(ctx, db, "SELECT * FROM relations ORDER BY source_id,target_id,relation_type,relation_id")
	if err != nil {
		return nil, nil, err
	}
	providers, err := providerHealthArtifact(in.OutputDir, in.TargetDomain, in.Version)
	if err != nil {
		return nil, nil, fmt.Errorf("passive completeness: %w", err)
	}
	providerObservations, err := readRows(ctx, db, "SELECT hostname,provider,collector,evidence_family,first_seen_by_provider FROM provider_observations ORDER BY hostname,provider,event_id")
	if err != nil {
		return nil, nil, err
	}
	dnsRows, err := readRows(ctx, db, "SELECT hostname,dns_state,active_eligibility,observed_at,data FROM dns_validations ORDER BY observed_at,event_id")
	if err != nil {
		return nil, nil, err
	}
	buildRows, err := readRows(ctx, db, "SELECT key,value FROM build_log ORDER BY key")
	if err != nil {
		return nil, nil, err
	}
	coverageRows, err := webCoverage(ctx, db, in.Profile, in.TargetDomain, in.ConfirmedWebTargets, in.Coverage)
	if err != nil {
		return nil, nil, fmt.Errorf("web coverage: %w", err)
	}
	assets := map[string]any{"domains": []any{}, "ips": []any{}, "cidrs": []any{}, "asn": []any{}}
	dns, tls, ports, web, webTargets, crawler, shots, other := []any{}, []any{}, []any{}, []any{}, []any{}, []any{}, []any{}, []any{}
	for _, row := range objects {
		entry, err := objectEntry(row)
		if err != nil {
			return nil, nil, fmt.Errorf("object %s: %w", str(row["object_id"]), err)
		}
		switch str(row["object_type"]) {
		case "domain":
			assets["domains"] = append(asList(assets["domains"]), entry)
		case "ip":
			assets["ips"] = append(asList(assets["ips"]), entry)
		case "cidr":
			assets["cidrs"] = append(asList(assets["cidrs"]), entry)
		case "asn":
			assets["asn"] = append(asList(assets["asn"]), entry)
		case "service", "port_scan_result":
			ports = append(ports, entry)
		case "web_target":
			webTargets = append(webTargets, entry)
		case "url":
			if eventType := str(latest(entry)["event_type"]); eventType == "crawler_result" || eventType == "aggressive_crawl_result" {
				crawler = append(crawler, entry)
			} else {
				web = append(web, entry)
			}
		case "screenshot":
			shots = append(shots, entry)
		case "dns_record":
			dns = append(dns, entry)
		case "tls_certificate", "tls_name":
			tls = append(tls, entry)
		default:
			other = append(other, entry)
		}
	}
	limitations := make([]any, 0, len(limitationRows))
	for _, row := range limitationRows {
		if err := decodeField(row, "data", map[string]any{}); err != nil {
			return nil, nil, err
		}
		if _, ok := row["data"].(map[string]any); !ok {
			return nil, nil, errors.New("limitation data must be a JSON object")
		}
		limitations = append(limitations, row)
	}
	relations := make([]any, 0, len(relationRows))
	for _, row := range relationRows {
		if err := decodeField(row, "evidence", map[string]any{}); err != nil {
			return nil, nil, err
		}
		if _, ok := row["evidence"].(map[string]any); !ok {
			return nil, nil, errors.New("relation evidence must be a JSON object")
		}
		relations = append(relations, row)
	}
	sourceHealth, err := sourceHealth(ctx, db, in)
	if err != nil {
		return nil, nil, fmt.Errorf("source health: %w", err)
	}
	buildLog := map[string]any{}
	for _, row := range buildRows {
		if err := decodeField(row, "value", nil); err != nil {
			return nil, nil, err
		}
		buildLog[str(row["key"])] = row["value"]
	}
	domains := asList(assets["domains"])
	rankDomains(domains, providerObservations)
	validated := map[string]bool{}
	for _, row := range dnsRows {
		state := str(row["dns_state"])
		validated[str(row["hostname"])] = state == "resolved_clean_parent" || state == "resolved_wildcard_distinct"
	}
	related := []any{}
	for _, raw := range domains {
		entry := asObject(raw)
		name := str(entry["value"])
		if name != in.TargetDomain && !strings.HasSuffix(name, "."+in.TargetDomain) {
			last := latest(entry)
			meta := asObject(last["metadata"])
			context := str(meta["attribution_warning"])
			if context == "" {
				context = str(meta["context_reason"])
			}
			if context == "" && (last["source_tool"] == "dns" || last["source_tool"] == "shodan_internetdb") {
				context = "Reverse-DNS name or shared-IP observation; ownership by the assessed organization is not confirmed."
			}
			if context == "" {
				context = "Related infrastructure context; ownership requires manual review."
			}
			related = append(related, map[string]any{
				"id": entry["id"], "value": name, "scope_status": entry["scope_status"],
				"confidence": entry["confidence"], "sources": entry["sources"],
				"relation_context": context, "related_via_ip": meta["related_via_ip"],
			})
		}
	}
	csvBytes, subdomains, err := buildDomainCSV(domains, in.TargetDomain, providerObservations, dnsRows, dns)
	if err != nil {
		return nil, nil, err
	}
	nowUTC := in.GeneratedAt.UTC().Format(time.RFC3339Nano)
	local := in.GeneratedAt.Format(time.RFC3339Nano)
	mode := "bounded"
	if in.FullReport {
		mode = "full"
	}
	var humanDomainLimit any = limits.Domain
	if in.FullReport {
		humanDomainLimit = nil
	}
	backend := in.BackendProvenance
	if backend == nil {
		backend = map[string]any{}
	}
	summary := countSummary(assets, ports, web, dns, shots, limitations, crawler, coverageRows, sourceHealth, in.TargetDomain, validated, in.Coverage)
	observations := keyObservations(summary, shots, web, sourceHealth, in.Profile)
	report := map[string]any{
		"metadata": map[string]any{"tool": "asm-tool", "version": in.Version, "generated_at": nowUTC,
			"generated_at_utc": nowUTC, "generated_at_local": local, "local_timezone": in.GeneratedAt.Format("-07:00"), "profile": in.Profile},
		"summary":  summary,
		"coverage": in.Coverage, "source_health": sourceHealth, "passive_provider_health": providers,
		"key_observations": observations, "scope": in.Scope, "modules": in.Modules,
		"collection_policy": in.CollectionPolicy, "assets": assets, "related_domains": related,
		"dns": dns, "tls": tls, "ports": ports, "web": web, "web_targets": webTargets,
		"web_coverage": coverageRows, "crawler": map[string]any{"enabled": in.Modules["crawler"], "aggressive_enabled": in.AggressiveEnabled, "results": crawler},
		"screenshots": shots, "relations": relations, "limitations": limitations,
		"aggressive_mode": map[string]any{"enabled": in.AggressiveEnabled, "authorization_present": in.AggressiveAuthorized}, "other_objects": other,
		"provenance": map[string]any{"event_files": in.EventFiles, "backends": backend},
		"reporting": map[string]any{"report_language": in.Language, "report_mode": mode,
			"subdomains_csv": "subdomains.csv", "subdomains_csv_sha256": backends.SHA256(csvBytes),
			"subdomains_total": subdomains, "human_subdomain_row_limit": humanDomainLimit,
			"human_presentation_limits": limits.asMap()},
		"build_log": buildLog,
	}
	if err := backends.ValidateSchema("report", report); err != nil {
		return nil, nil, fmt.Errorf("report schema: %w", err)
	}
	return report, csvBytes, nil
}
