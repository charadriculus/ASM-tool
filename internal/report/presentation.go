package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"asmtool/internal/i18n"
)

func sortedKeysFromObjects(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func humanWebItems(report map[string]any) []any {
	byURL := map[string]any{}
	for _, raw := range asList(report["web"]) {
		item := asObject(raw)
		kind := str(latest(item)["event_type"])
		name := str(item["value"])
		if name == "" || (kind != "html_analyzed" && kind != "web_service_found") {
			continue
		}
		if _, exists := byURL[name]; !exists || kind == "html_analyzed" {
			byURL[name] = raw
		}
	}
	rows := []any{}
	for _, key := range sortedKeysFromObjects(byURL) {
		rows = append(rows, byURL[key])
	}
	return rows
}

func humanScreenshotItems(report map[string]any) []any {
	items := append([]any{}, asList(report["screenshots"])...)
	sort.SliceStable(items, func(i, j int) bool {
		key := func(raw any) string {
			item := asObject(raw)
			meta := asObject(latest(item)["metadata"])
			names := sourcesText(meta["target_domains"])
			if names == "" {
				names = str(meta["target_domain"])
			}
			return names + "\x00" + str(meta["url"]) + "\x00" + str(item["id"])
		}
		return key(items[i]) < key(items[j])
	})
	return items
}

// The CSV is the canonical domain read model; use its existing historical
// fields without changing the persisted objects in the machine report.
func domainPresentation(inputs [][]byte) (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	if len(inputs) == 0 {
		return result, nil
	}
	rows, err := csv.NewReader(bytes.NewReader(inputs[0])).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("missing domain CSV header")
	}
	for _, fields := range rows[1:] {
		row := map[string]string{}
		for i, key := range rows[0] {
			row[key] = fields[i]
		}
		result[row["hostname"]] = row
	}
	return result, nil
}

func presentationLabels(t i18n.Translator, key string) ([]string, string, error) {
	keys := map[string][]string{
		"report.section.subdomains":            {"table.rank", "table.domain", "table.validation", "table.confidence", "table.sources"},
		"report.section.network":               {"table.ip", "table.related_domains", "table.source"},
		"report.section.routing":               {"table.type", "table.value", "table.description"},
		"report.section.related":               {"table.name", "table.source", "table.context"},
		"report.section.ports":                 {"table.host", "table.port", "table.observation", "table.attribution", "table.details"},
		"report.section.web_coverage":          {"table.domain", "table.root_check", "table.http", "table.crawling", "table.pages", "table.screenshots", "table.completeness"},
		"report.section.web":                   {"URL", "table.status", "table.http", "table.title"},
		"report.section.documents":             {"URL", "table.resource_type", "table.detection", "table.http"},
		"report.section.source_health":         {"table.source", "table.status", "table.result"},
		"report.section.provider_completeness": {"table.provider", "table.collector", "table.returned", "table.unique", "table.completeness", "table.status"},
	}
	headers := []string{}
	for _, header := range keys[key] {
		if header == "URL" {
			headers = append(headers, header)
			continue
		}
		label, err := t.Text(header, nil)
		if err != nil {
			return nil, "", err
		}
		headers = append(headers, label)
	}
	notes := map[string]string{"report.section.routing": "copy.routing_context", "report.section.related": "copy.related_warning", "report.section.ports": "copy.ports_context", "report.section.documents": "copy.documents_note"}
	if noteKey := notes[key]; noteKey != "" {
		note, err := t.Text(noteKey, nil)
		return headers, note, err
	}
	return headers, "", nil
}

func display(v any) string {
	text := reportString(v)
	if text == "" {
		return "—"
	}
	return text
}

func domainsForIP(report map[string]any, ip string) string {
	values := map[string]bool{}
	for _, raw := range asList(report["relations"]) {
		r := asObject(raw)
		if r["relation_type"] == "resolves_to" && r["target_id"] == "ip:"+ip {
			if name := strings.TrimPrefix(str(r["source_id"]), "domain:"); name != "" {
				values[name] = true
			}
		}
	}
	return strings.Join(sortedKeys(values), ", ")
}

func presentationCells(t i18n.Translator, key string, item map[string]any, row humanRow, report map[string]any, facts map[string]map[string]string) ([]string, error) {
	meta := asObject(latest(item)["metadata"])
	label := func(key string) string {
		value, err := t.Text(key, nil)
		if err != nil {
			return key
		}
		return value
	}
	switch key {
	case "report.section.subdomains":
		f := facts[str(item["value"])]
		validation := "domain.validation.passive_candidate"
		if f["dns_state"] == "resolved_clean_parent" || f["dns_state"] == "resolved_wildcard_distinct" {
			validation = "domain.validation.dns_validated"
		} else if f["dns_state"] == "deferred_by_dns_budget" {
			validation = "domain.validation.deferred_budget"
		}
		confidence := "—"
		if number, err := strconv.ParseFloat(reportString(item["confidence"]), 64); err == nil {
			confidence = fmt.Sprintf("%.0f%%", number*100)
		}
		sources := f["providers"]
		if sources == "" {
			sources = f["collectors"]
		}
		if sources == "" {
			sources = sourcesText(item["sources"])
		}
		return []string{display(f["rank"]), row.Value, label(validation), confidence, sources}, nil
	case "report.section.network":
		return []string{row.Value, display(domainsForIP(report, row.Value)), sourcesText(item["sources"])}, nil
	case "report.section.routing":
		kind, description := "ASN", str(meta["as_name"])
		if strings.HasPrefix(str(item["id"]), "cidr:") {
			kind, description = "CIDR", label("routing.prefix")
			if meta["asn"] != nil {
				text, err := t.Text("routing.announced_by", map[string]any{"asn": meta["asn"]})
				if err != nil {
					return nil, err
				}
				description += "; " + text
			}
		} else if description == "" {
			description = label("routing.autonomous_system")
		}
		return []string{kind, row.Value, description}, nil
	case "report.section.related":
		return []string{row.Value, sourcesText(item["sources"]), label("related.unconfirmed") + " " + str(item["relation_context"])}, nil
	case "report.section.ports":
		ip, port := str(meta["ip"]), display(meta["port"])
		if ip == "" || port == "—" {
			raw := str(item["value"])
			if index := strings.LastIndex(raw, ":"); index >= 0 {
				ip, port = raw[:index], raw[index+1:]
			}
		}
		tcpResult := latest(item)["event_type"] == "port_scan_result"
		for _, source := range asList(item["sources"]) {
			if source == "tcp_connect" {
				tcpResult = true
			}
		}
		if tcpResult {
			state := str(meta["state"])
			stateKey := "port.unknown"
			if state == "open" || state == "closed" {
				stateKey = "port." + state
			}
			details := []string{strings.ToUpper(str(meta["protocol"])), label(stateKey)}
			if meta["attempted"] == false {
				details = append(details, "not attempted")
			}
			if reason := str(meta["reason"]); reason != "" {
				details = append(details, reason)
			}
			if failure := str(meta["error"]); failure != "" {
				details = append(details, failure)
			}
			if duration := meta["duration_ms"]; duration != nil {
				details = append(details, fmt.Sprintf("%v ms", duration))
			}
			attribution := sourcesText(meta["validated_domains"])
			if attribution == "" {
				attribution = label("port.ip_only")
			}
			return []string{display(ip), port, label("port.tcp_connect"), attribution, strings.Join(details, "; ")}, nil
		}
		attribution := sourcesText(meta["mapped_in_scope_domains"])
		if attribution == "" {
			attribution = domainsForIP(report, ip)
		}
		if attribution == "" {
			attribution = label("port.ip_only")
		}
		if len(asList(meta["shared_infrastructure_indicators"])) > 0 {
			attribution += "; " + label("port.shared_possible")
		}
		details := []string{"TCP"}
		if tags := asList(meta["tags"]); len(tags) > 0 {
			if len(tags) > 4 {
				tags = tags[:4]
			}
			details = append(details, label("port.tag")+": "+sourcesText(tags))
		}
		return []string{display(ip), port, label("port.internetdb"), attribution, strings.Join(details, "; ")}, nil

	case "report.section.web_coverage":
		root, crawl := str(item["root_status"]), str(item["crawl_status"])
		if text, err := t.Text("web.root."+root, nil); err == nil {
			root = text
		}
		if text, err := t.Text("web.crawl."+crawl, nil); err == nil {
			crawl = text
		}
		coverageKey := "web.coverage.screenshot_missing"
		if reportInt(item["pages_loaded"]) == 0 {
			coverageKey = "web.coverage.not_loaded"
		} else if item["screenshot_complete"] == true {
			coverageKey = "web.coverage.complete"
		}
		if item["browser_status"] != nil || item["screenshot_status"] != nil {
			browserKey := "web.browser." + str(item["browser_status"])
			screenshotKey := "web.screenshot." + str(item["screenshot_status"])
			coverage := []string{}
			if value := str(item["browser_status"]); value != "" {
				coverage = append(coverage, label(browserKey))
			}
			if value := str(item["screenshot_status"]); value != "" {
				coverage = append(coverage, label(screenshotKey))
			}
			if reason := str(item["reason"]); reason == "candidate31_preconnect_security_failure" {
				coverage = append(coverage, label("web.browser.candidate31_reason"))
			}
			return []string{row.Value, root, display(item["http_status"]), crawl, display(item["pages_loaded"]), display(item["screenshots"]), strings.Join(coverage, "; ")}, nil
		}
		return []string{row.Value, root, display(item["http_status"]), crawl, display(item["pages_loaded"]), display(item["screenshots"]), label(coverageKey)}, nil
	case "report.section.web":
		kind, status, title := label("web.passive_endpoint"), label("web.not_checked"), "—"
		if latest(item)["event_type"] == "html_analyzed" {
			kind, status, title = label("web.current_browser"), display(meta["status_code"]), display(meta["title"])
			if meta["browser_dom"] == false {
				kind = label("web.current_http")
			}
		}
		return []string{row.Value, kind, status, title}, nil
	case "report.section.documents":
		types := map[string]string{"PDF document": "pdf", "Word document": "word", "text document": "text", "Excel spreadsheet": "excel", "spreadsheet": "spreadsheet", "presentation": "presentation", "archive": "archive", "image": "image", "audio file": "audio", "media file": "media", "video file": "video", "executable": "executable", "installer package": "installer", "application package": "application", "disk image": "disk_image", "downloadable resource": "downloadable"}
		resourceType := str(meta["resource_type"])
		if resourceType == "" {
			resourceType = "downloadable resource"
		}
		if suffix := types[resourceType]; suffix != "" {
			resourceType = label("document.type." + suffix)
		}
		detection, err := t.Text("document."+str(meta["detection_reason"]), nil)
		if err != nil {
			detection = label("document.non_html")
		}
		name := row.Value
		if name == "" {
			name = str(latest(item)["normalized_value"])
		}
		return []string{name, resourceType, detection, display(meta["status_code"])}, nil
	case "report.section.source_health":
		details := []string{label("source.items") + ": " + display(item["items"])}
		if item["known_startup_network_risk"] == true {
			details = append(details, label("risk.subfaster"))
		}
		if item["http_attempts"] != nil {
			details = append(details, label("source.http_attempts")+": "+display(item["http_attempts"]))
		}
		errors := asList(item["errors"])
		if len(errors) > 0 {
			// Keep distinct provider causes visible while suppressing exact repeats
			// from this source only. The machine-readable report remains untouched.
			seen := make(map[string]bool, len(errors))
			distinct := make([]any, 0, len(errors))
			for _, value := range errors {
				text := reportString(value)
				if text == "" || seen[text] {
					continue
				}
				seen[text] = true
				distinct = append(distinct, value)
			}
			if len(distinct) > 0 {
				details = append(details, label("source.last_error")+": "+label("source.error.technical")+" — "+sourcesText(distinct))
			}
		} else if item["technical_error"] != nil || item["fallback_after_error"] != nil {
			details = append(details, label("source.last_error")+": "+label("source.error.technical"))
		}
		if item["last_http_status"] != nil {
			details = append(details, "HTTP: "+display(item["last_http_status"]))
		}
		if item["cache_hit"] == true || item["cache_stale"] == true || item["cache_age_seconds"] != nil {
			yesNo := "common.no"
			if item["cache_stale"] == true {
				yesNo = "common.yes"
			}
			details = append(details, label("source.stale_cache")+": "+label(yesNo))
			if item["cache_age_seconds"] != nil {
				seconds := reportInt(item["cache_age_seconds"])
				text, err := t.Text("source.cache_age_value", map[string]any{"hours": seconds / 3600, "minutes": seconds % 3600 / 60})
				if err != nil {
					return nil, err
				}
				details = append(details, label("source.cache_age")+": "+text)
			}
		}
		return []string{row.Value, row.Context, strings.Join(details, "; ")}, nil
	case "report.section.provider_completeness":
		return []string{row.Value, display(item["collector"]), display(item["returned"]), display(item["unique_contribution"]), row.Context, display(item["collector_status"])}, nil
	}
	return nil, nil
}
