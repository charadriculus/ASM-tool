package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"asmtool/internal/core"
	"asmtool/internal/i18n"
)

type humanRow struct {
	Value    string
	Context  string
	Sources  string
	Image    string
	ImageURL string
	Cells    []string
}

type humanSection struct {
	Key     string
	Title   string
	Total   int
	Shown   int
	Rows    []humanRow
	Headers []string
	Note    string
}

type summaryCard struct{ Label, Value string }

type humanView struct {
	Language         string
	Title            string
	Lead             string
	TargetLabel      string
	ProfileLabel     string
	GeneratedLabel   string
	VersionLabel     string
	ValueLabel       string
	StatusLabel      string
	SourcesLabel     string
	LimitationsLabel string
	Target           string
	Profile          string
	GeneratedAt      string
	Version          string
	Sections         []humanSection
	Limitations      []humanRow
	Warnings         []string
	Cards            []summaryCard
	Methodology      string
	LimitationsIntro string
}

type sectionSpec struct {
	key   string
	data  []any
	limit int
}

func localized(t i18n.Translator, key string, values map[string]any) (string, error) {
	return t.Text(key, values)
}

func reportString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func sourcesText(v any) string {
	var s []string
	for _, x := range asList(v) {
		s = append(s, reportString(x))
	}
	return strings.Join(s, ", ")
}

func warningMeaning(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func warningIdentity(source, meaning string) string {
	if source == "" || meaning == "" {
		return ""
	}
	return source + "\x00" + warningMeaning(meaning)
}

func genericTransportStatus(reason string) (int, bool) {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(reason)))
	var statusText string
	switch {
	case len(fields) == 3 && fields[1] == "transport" && fields[2] == "issue":
		statusText = fields[0]
	case len(fields) == 4 && fields[0] == "http" && fields[2] == "transport" && fields[3] == "issue":
		statusText = fields[1]
	default:
		return 0, false
	}
	status, err := strconv.Atoi(statusText)
	return status, err == nil && status >= 400 && status <= 599
}

func sourceHealthHTTPStatusSet(report map[string]any, rowLimit int, fullReport bool) map[string]map[int]bool {
	seen := map[string]map[int]bool{}
	rows := asList(report["source_health"])
	if !fullReport && rowLimit >= 0 && len(rows) > rowLimit {
		rows = rows[:rowLimit]
	}
	for _, raw := range rows {
		row := asObject(raw)
		status := str(row["status"])
		if status != "partial" && status != "temporary_failure" && status != "unavailable" && status != "security_blocked" {
			continue
		}
		code := reportInt(row["last_http_status"])
		source := str(row["source"])
		if source != "" && code >= 400 && code <= 599 {
			if seen[source] == nil {
				seen[source] = map[int]bool{}
			}
			seen[source][code] = true
		}
	}
	return seen
}

func sourceHealthWarningSet(report map[string]any, rowLimit int, fullReport bool) map[string]bool {
	seen := map[string]bool{}
	rows := asList(report["source_health"])
	if !fullReport && rowLimit >= 0 && len(rows) > rowLimit {
		rows = rows[:rowLimit]
	}
	for _, raw := range rows {
		row := asObject(raw)
		status := str(row["status"])
		if status != "partial" && status != "temporary_failure" && status != "unavailable" && status != "security_blocked" {
			continue
		}
		source := str(row["source"])
		for _, rawError := range asList(row["errors"]) {
			if key := warningIdentity(source, reportString(rawError)); key != "" {
				seen[key] = true
			}
		}
	}
	return seen
}

func localizedObservations(t i18n.Translator, report map[string]any) ([]any, error) {
	s := asObject(report["summary"])
	count := func(key string) int { n, _ := s[key].(int); return n }
	out := []any{}
	add := func(key string, values map[string]any) error {
		text, err := t.Text(key, values)
		if err != nil {
			return err
		}
		out = append(out, text)
		return nil
	}
	if count("discovered_subdomains") > 0 {
		if err := add("obs.subdomains", map[string]any{"found": count("discovered_subdomains"), "validated": count("dns_validated_subdomains")}); err != nil {
			return nil, err
		}
	} else if err := add("obs.no_subdomains", nil); err != nil {
		return nil, err
	}
	for _, item := range []struct{ field, key string }{{"ips", "obs.ips"}, {"related_context_domains", "obs.related"}, {"ports_from_passive_sources", "obs.passive_ports"}, {"ports_actively_confirmed", "obs.active_ports"}, {"crawler_pages", "obs.crawler"}, {"screenshots", "obs.screenshots"}, {"downloadable_resources", "obs.documents"}} {
		if count(item.field) > 0 {
			if err := add(item.key, map[string]any{"count": count(item.field)}); err != nil {
				return nil, err
			}
		}
	}
	reachable := 0
	for _, raw := range asList(report["web"]) {
		code := reportInt(asObject(latest(asObject(raw))["metadata"])["status_code"])
		if code >= 100 && code < 500 {
			reachable++
		}
	}
	if reachable > 0 {
		if err := add("obs.web", map[string]any{"count": reachable}); err != nil {
			return nil, err
		}
	}
	unavailable := []string{}
	for _, raw := range asList(report["source_health"]) {
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
		if err := add("obs.unavailable", map[string]any{"sources": strings.Join(unavailable, ", ")}); err != nil {
			return nil, err
		}
	}
	profile := str(asObject(report["metadata"])["profile"])
	if profile == "verify" || profile == "full" {
		if err := add("obs.web_completion", map[string]any{"attempted": count("web_targets_attempted"), "planned": count("web_targets_planned"), "pages": count("web_pages_loaded"), "screenshots": count("screenshots")}); err != nil {
			return nil, err
		}
	}
	switch s["browser_mode"] {
	case "blocked":
		if err := add("obs.browser_blocked", nil); err != nil {
			return nil, err
		}
	case "disabled":
		if err := add("obs.browser_disabled", nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func sectionItems(report map[string]any, limits RowLimits, target string) []sectionSpec {
	assets := asObject(report["assets"])
	crawler := asObject(report["crawler"])
	documents := map[string]any{}
	for _, raw := range asList(crawler["results"]) {
		item := asObject(raw)
		if asObject(latest(item)["metadata"])["category"] == "downloadable_resource_detected" {
			name := str(item["value"])
			if name == "" {
				name = str(latest(item)["normalized_value"])
			}
			if name != "" {
				documents[name] = raw
			}
		}
	}
	documentRows := []any{}
	for _, name := range sortedKeysFromObjects(documents) {
		documentRows = append(documentRows, documents[name])
	}
	subdomains := []any{}
	for _, raw := range asList(assets["domains"]) {
		name := str(asObject(raw)["value"])
		if name != target && strings.HasSuffix(name, "."+target) {
			subdomains = append(subdomains, raw)
		}
	}
	return []sectionSpec{
		{"report.section.subdomains", subdomains, limits.Domain},
		{"report.section.network", asList(assets["ips"]), limits.IP},
		{"report.section.routing", append(append([]any{}, asList(assets["asn"])...), asList(assets["cidrs"])...), limits.Routing},
		{"report.section.related", asList(report["related_domains"]), limits.RelatedDomain},
		{"report.section.ports", asList(report["ports"]), limits.Port},
		{"report.section.web_coverage", asList(report["web_coverage"]), limits.WebCoverage},
		{"report.section.web", humanWebItems(report), limits.Web},
		{"report.section.documents", documentRows, limits.Document},
		{"report.section.screenshots", humanScreenshotItems(report), limits.Screenshot},
		{"report.section.source_health", asList(report["source_health"]), limits.WebCoverage},
		{"report.section.provider_completeness", asList(report["passive_provider_health"]), limits.WebCoverage},
		{"report.section.observations", asList(report["key_observations"]), limits.WebCoverage},
	}
}

func safeImage(ctx context.Context, outputDir, stageDir string, item map[string]any) (string, string) {
	meta := asObject(latest(item)["metadata"])
	raw := str(meta["absolute_path"])
	if raw == "" {
		raw = str(meta["path"])
	}
	if raw == "" {
		return "", "missing screenshot path"
	}
	base, err := filepath.Abs(outputDir)
	if err != nil {
		return "", err.Error()
	}
	rel := raw
	if filepath.IsAbs(raw) {
		rel, err = filepath.Rel(base, raw)
		if err != nil {
			return "", err.Error()
		}
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "screenshot path outside run directory"
	}
	if !strings.EqualFold(filepath.Ext(rel), ".png") {
		return "", "unsupported screenshot extension"
	}
	f, err := os.OpenInRoot(base, rel)
	if err != nil {
		return "", err.Error()
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", "screenshot is not a regular file"
	}
	const maxImageBytes = 32 << 20
	if info.Size() > maxImageBytes {
		return "", "screenshot exceeds 32 MiB"
	}
	imageDir := filepath.Join(stageDir, "images")
	if err := os.MkdirAll(imageDir, 0700); err != nil {
		return "", err.Error()
	}
	dst, err := os.CreateTemp(imageDir, ".image-*.png")
	if err != nil {
		return "", err.Error()
	}
	dstPath := dst.Name()
	digest := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(dst, digest), io.LimitReader(f, maxImageBytes+1))
	if copyErr == nil && n > maxImageBytes {
		copyErr = errors.New("screenshot exceeds 32 MiB")
	}
	if copyErr == nil {
		copyErr = dst.Sync()
	}
	closeErr := dst.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(dstPath)
		return "", copyErr.Error()
	}
	imageHash := hex.EncodeToString(digest.Sum(nil))
	if expected := str(meta["sha256"]); expected != "" && !strings.EqualFold(expected, imageHash) {
		_ = os.Remove(dstPath)
		return "", "screenshot SHA-256 mismatch"
	}
	stablePath := filepath.Join(imageDir, imageHash+".png")
	if err := os.Rename(dstPath, stablePath); err != nil {
		_ = os.Remove(dstPath)
		return "", "cannot stage screenshot"
	}
	dstPath = stablePath
	imageCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := core.ValidateReportImage(imageCtx, dstPath); err != nil {
		_ = os.Remove(dstPath)
		return "", "invalid screenshot PNG"
	}
	return "images/" + filepath.Base(dstPath), ""
}

func rowFor(ctx context.Context, outputDir, stageDir string, raw any) (humanRow, string) {
	if s, ok := raw.(string); ok {
		return humanRow{Value: s}, ""
	}
	item := asObject(raw)
	row := humanRow{Value: str(item["value"]), Context: str(item["scope_status"]), Sources: sourcesText(item["sources"])}
	if row.Value == "" {
		row.Value = str(item["domain"])
	}
	if row.Value == "" {
		row.Value = str(item["hostname"])
	}
	if row.Value == "" {
		row.Value = str(item["source"])
	}
	if row.Value == "" {
		row.Value = str(item["provider"])
	}
	if row.Value == "" {
		row.Value = str(item["reason"])
	}
	if row.Value == "" {
		row.Value = reportString(item)
	}
	if status := str(item["status"]); status != "" {
		row.Context = status
	}
	if status := str(item["completeness_state"]); status != "" {
		row.Context = status
	}
	if warning := str(item["warning"]); warning != "" {
		row.Sources = warning
	}
	if details := asObject(item["data"]); len(details) > 0 {
		row.Sources = reportString(details)
	}
	if strings.HasPrefix(str(item["id"]), "screenshot:") {
		image, reason := safeImage(ctx, outputDir, stageDir, item)
		row.Image = image
		if image != "" {
			row.ImageURL = "./" + (&url.URL{Path: image}).EscapedPath()
		}
		return row, reason
	}
	return row, ""
}

func makeHumanView(ctx context.Context, in Input, report map[string]any, stageDir string, domainCSV ...[]byte) (humanView, error) {
	t, err := i18n.NewTranslator(in.Language)
	if err != nil {
		return humanView{}, err
	}
	limits, err := in.RowLimits.normalized()
	if err != nil {
		return humanView{}, err
	}
	title, err := localized(t, "report.title", nil)
	if err != nil {
		return humanView{}, err
	}
	lead, err := localized(t, "copy.lead", nil)
	if err != nil {
		return humanView{}, err
	}
	profile, err := localized(t, "profile."+in.Profile, nil)
	if err != nil {
		return humanView{}, err
	}
	v := humanView{Language: t.Language(), Title: title, Lead: lead,
		Target: in.TargetDomain, Profile: profile, GeneratedAt: str(asObject(report["metadata"])["generated_at_local"]), Version: in.Version}
	warningSeen := map[string]bool{}
	appendWarning := func(source, meaning, display string) {
		key := warningIdentity(source, meaning)
		if key != "" && warningSeen[key] {
			return
		}
		if key != "" {
			warningSeen[key] = true
		}
		v.Warnings = append(v.Warnings, display)
	}
	if mode := str(asObject(report["coverage"])["browser_mode"]); mode == "enabled" || mode == "required" {
		text, e := t.Text("risk.browser", nil)
		if e != nil {
			return humanView{}, e
		}
		appendWarning("browser", "candidate31_preconnect_security_failure", text)
	}
	for _, raw := range asList(report["source_health"]) {
		if asObject(raw)["known_startup_network_risk"] == true {
			text, e := t.Text("risk.subfaster", nil)
			if e != nil {
				return humanView{}, e
			}
			appendWarning("subfaster", "startup_network_probe", text)
		}
	}
	for _, card := range []struct{ field, key string }{{"discovered_subdomains", "report.card.discovered"}, {"dns_validated_subdomains", "report.card.dns_validated"}, {"ips", "report.card.ips"}, {"ports_total", "report.card.ports"}} {
		label, e := t.Text(card.key, nil)
		if e != nil {
			return humanView{}, e
		}
		v.Cards = append(v.Cards, summaryCard{label, reportString(asObject(report["summary"])[card.field])})
	}
	v.Methodology, err = t.Text("method."+in.Profile, nil)
	if err != nil {
		return humanView{}, err
	}
	v.LimitationsIntro, err = t.Text("copy.limitations_intro", nil)
	if err != nil {
		return humanView{}, err
	}
	domainFacts, err := domainPresentation(domainCSV)
	if err != nil {
		return humanView{}, err
	}
	observations, err := localizedObservations(t, report)
	if err != nil {
		return humanView{}, err
	}
	for _, pair := range []struct {
		key  string
		dest *string
	}{
		{"report.meta.target", &v.TargetLabel}, {"report.meta.profile", &v.ProfileLabel},
		{"report.meta.generated", &v.GeneratedLabel}, {"report.meta.version", &v.VersionLabel},
		{"table.value", &v.ValueLabel}, {"table.status", &v.StatusLabel},
		{"table.sources", &v.SourcesLabel}, {"report.section.limitations", &v.LimitationsLabel},
	} {
		*pair.dest, err = localized(t, pair.key, nil)
		if err != nil {
			return humanView{}, err
		}
	}
	for _, spec := range sectionItems(report, limits, in.TargetDomain) {
		if err := ctx.Err(); err != nil {
			return humanView{}, err
		}
		if spec.key == "report.section.observations" {
			spec.data = observations
		}
		name, err := localized(t, spec.key, nil)
		if err != nil {
			return humanView{}, err
		}
		section := humanSection{Key: spec.key, Title: name, Total: len(spec.data)}
		section.Headers, section.Note, err = presentationLabels(t, spec.key)
		if err != nil {
			return humanView{}, err
		}
		max := len(spec.data)
		if !in.FullReport && max > spec.limit {
			max = spec.limit
		}
		for _, raw := range spec.data[:max] {
			if err := ctx.Err(); err != nil {
				return humanView{}, err
			}
			row, warning := rowFor(ctx, in.OutputDir, stageDir, raw)
			item := asObject(raw)
			switch spec.key {
			case "report.section.web_coverage":
				row.Value = str(item["domain"])
				rootStatus, crawlStatus := str(item["root_status"]), str(item["crawl_status"])
				if label, e := t.Text("web.root."+rootStatus, nil); e == nil {
					rootStatus = label
				}
				if label, e := t.Text("web.crawl."+crawlStatus, nil); e == nil {
					crawlStatus = label
				}
				row.Context = rootStatus + " / " + crawlStatus
				pagesLabel, e := t.Text("table.pages", nil)
				if e != nil {
					return humanView{}, e
				}
				shotsLabel, e := t.Text("table.screenshots", nil)
				if e != nil {
					return humanView{}, e
				}
				coverageKey := "web.coverage.screenshot_missing"
				if item["pages_loaded"] == 0 {
					coverageKey = "web.coverage.not_loaded"
				} else if item["screenshot_complete"] == true {
					coverageKey = "web.coverage.complete"
				}
				coverageText, e := t.Text(coverageKey, nil)
				if e != nil {
					return humanView{}, e
				}
				row.Sources = fmt.Sprintf("%s: %v; %s: %v; %s", pagesLabel, item["pages_loaded"], shotsLabel, item["screenshots"], coverageText)
				if item["http_status"] != nil {
					row.Sources += fmt.Sprintf("; HTTP: %v", item["http_status"])
				}
				if reason := str(item["reason"]); reason != "" {
					row.Sources += "; " + reason
				}
			case "report.section.provider_completeness":
				state := str(item["completeness_state"])
				if state != "" {
					if row.Context, err = t.Text("provider."+state, nil); err != nil {
						return humanView{}, err
					}
				}
				collectorLabel, e := t.Text("table.collector", nil)
				if e != nil {
					return humanView{}, e
				}
				returnedLabel, e := t.Text("table.returned", nil)
				if e != nil {
					return humanView{}, e
				}
				uniqueLabel, e := t.Text("table.unique", nil)
				if e != nil {
					return humanView{}, e
				}
				row.Sources = fmt.Sprintf("%s: %s; %s: %v; %s: %v; %s", collectorLabel, str(item["collector"]), returnedLabel, item["returned"], uniqueLabel, item["unique_contribution"], str(item["termination_reason"]))
				if item["anomaly_status"] == "provider_output_anomaly" {
					warning, err = t.Text("provider.warning.anomaly", map[string]any{"provider": item["provider"]})
					if err != nil {
						return humanView{}, err
					}
				} else if item["provider"] == "thc" && state != "complete" && state != "complete_empty" {
					warning, err = t.Text("provider.warning.thc", nil)
					if err != nil {
						return humanView{}, err
					}
				}
			case "report.section.source_health":
				if label := str(item["label"]); label != "" {
					row.Value = label
				}
				if status := str(item["status"]); status != "" {
					if row.Context, err = t.Text("source.status."+status, nil); err != nil {
						return humanView{}, err
					}
				}
				returnedLabel, e := t.Text("table.returned", nil)
				if e != nil {
					return humanView{}, e
				}
				row.Sources = fmt.Sprintf("%s: %v", returnedLabel, item["items"])
				if errs := asList(item["errors"]); len(errs) > 0 {
					row.Sources += "; " + sourcesText(errs)
				}
			case "report.section.related":
				ownership, e := t.Text("copy.related_warning", nil)
				if e != nil {
					return humanView{}, e
				}
				row.Sources = ownership
				if context := str(item["relation_context"]); context != "" {
					row.Sources += " " + context
				}
			case "report.section.screenshots":
				meta := asObject(latest(item)["metadata"])
				row.Value = str(meta["url"])
				if row.Value == "" {
					row.Value = str(latest(item)["normalized_value"])
				}
				row.Context = str(meta["title"])
				row.Sources = sourcesText(meta["target_domains"])
				if row.Sources == "" {
					row.Sources = str(meta["target_domain"])
				}
				if meta["status_code"] != nil {
					row.Sources += "; HTTP: " + reportString(meta["status_code"])
				}
				row.Sources += "; " + str(latest(item)["observed_at"])
				if warning != "" {
					warning, err = t.Text("report.screenshot.missing", nil)
					if err != nil {
						return humanView{}, err
					}
				}
			}
			row.Cells, err = presentationCells(t, spec.key, item, row, report, domainFacts)
			if err != nil {
				return humanView{}, err
			}
			section.Rows = append(section.Rows, row)
			if warning != "" {
				source := str(item["provider"])
				if source == "" {
					source = spec.key
				}
				appendWarning(source, warning, row.Value+": "+warning)
			}
		}
		section.Shown = len(section.Rows)
		if section.Shown < section.Total {
			word := "shown"
			if t.Language() == "ru" {
				word = "показано"
			}
			meaning := fmt.Sprintf("%s: %s %d/%d", name, word, section.Shown, section.Total)
			appendWarning("section:"+spec.key, meaning, meaning)
		}
		v.Sections = append(v.Sections, section)
	}
	healthWarningSeen := sourceHealthWarningSet(report, limits.WebCoverage, in.FullReport)
	healthHTTPStatusSeen := sourceHealthHTTPStatusSet(report, limits.WebCoverage, in.FullReport)
	limitationSeen := map[string]bool{}
	for _, raw := range asList(report["limitations"]) {
		row := asObject(raw)
		detail := asObject(row["data"])
		reason := str(row["reason"])
		source := str(detail["source_tool"])
		metadata := asObject(detail["metadata"])
		if source == "" {
			source = str(metadata["provider"])
		}
		if metadata["severity"] == "info" || metadata["source_status"] == "no_results" {
			continue
		}
		if status, generic := genericTransportStatus(str(row["reason"])); generic && healthHTTPStatusSeen[source][status] {
			continue
		}
		low := strings.ToLower(reason)
		if strings.Contains(low, "download is starting") || strings.Contains(low, "download started") {
			continue
		}
		limitationKey := ""
		switch {
		case strings.Contains(low, "timed out") || strings.Contains(low, "timeout"):
			limitationKey = "limitation.timeout"
		case source == "crt.sh" && strings.Contains(low, "404"):
			limitationKey = "limitation.crtsh_404"
		case strings.Contains(low, "502") || strings.Contains(low, "503") || strings.Contains(low, "504"):
			limitationKey = "limitation.server_error"
		}
		if limitationKey != "" {
			reason, err = localized(t, limitationKey, nil)
			if err != nil {
				return humanView{}, err
			}
		}
		if reason == "" {
			reason = reportString(detail)
		}
		key := warningIdentity(source, str(row["reason"]))
		if key != "" && (healthWarningSeen[key] || limitationSeen[key] || warningSeen[key]) {
			continue
		}
		if key != "" {
			limitationSeen[key] = true
		}
		v.Limitations = append(v.Limitations, humanRow{Value: reason, Context: source})
	}
	return v, nil
}

var htmlReport = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>body{font:10pt/1.45 "DejaVu Sans",sans-serif;color:#1f2937;max-width:1100px;margin:2rem auto;padding:0 1rem}h1{font-size:21pt}h2{margin-top:2rem;border-bottom:1px solid #cbd5e1}table{border-collapse:collapse;width:100%;margin-bottom:1.2rem;table-layout:fixed}th,td{border:1px solid #cbd5e1;padding:.35rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}img{max-width:100%;max-height:70vh}.warning{border-left:3px solid #f59e0b;background:#fffbeb;padding:.5rem;margin:.4rem 0}.muted{color:#64748b}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}.card{padding:1rem;background:#f1f5f9}.card strong{display:block;font-size:20pt}@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}</style></head><body>
<h1>{{.Title}}</h1><p>{{.Lead}}</p>
<table><tr><th>{{.TargetLabel}}</th><td>{{.Target}}</td></tr><tr><th>{{.ProfileLabel}}</th><td>{{.Profile}}</td></tr><tr><th>{{.GeneratedLabel}}</th><td>{{.GeneratedAt}}</td></tr><tr><th>{{.VersionLabel}}</th><td>{{.Version}}</td></tr></table>
<div class="cards">{{range .Cards}}<div class="card"><strong>{{.Value}}</strong>{{.Label}}</div>{{end}}</div><p>{{.Methodology}}</p>
{{range .Warnings}}<p class="warning">{{.}}</p>{{end}}
{{range .Sections}}<h2>{{.Title}}</h2><p class="muted">{{.Shown}} / {{.Total}}</p>
{{if .Note}}<p>{{.Note}}</p>{{end}}
{{if .Headers}}<table><thead><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr></thead><tbody>{{range .Rows}}<tr>{{range .Cells}}<td>{{.}}</td>{{end}}</tr>{{end}}</tbody></table>
{{else}}{{range .Rows}}<p>{{.Value}}{{if .Context}} — {{.Context}}{{end}}{{if .Sources}} ({{.Sources}}){{end}}</p>{{if .ImageURL}}<figure><img src="{{.ImageURL}}" alt="{{.Value}}"><figcaption>{{.Value}}; {{.Context}}; {{.Sources}}</figcaption></figure>{{end}}{{end}}{{end}}
{{end}}
<h2>{{.LimitationsLabel}}</h2><p>{{.LimitationsIntro}}</p>{{range .Limitations}}<p class="warning">{{.Context}}: {{.Value}}</p>{{end}}
</body></html>`))

func renderHTML(v humanView) ([]byte, error) {
	var b bytes.Buffer
	if err := htmlReport.Execute(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func typstString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, "\\u{%x}", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func renderTypst(v humanView) ([]byte, error) {
	if v.Language != "ru" && v.Language != "en" {
		return nil, errors.New("unsupported report language")
	}
	var b strings.Builder
	b.WriteString("#set document(date: none)\n#set page(paper: \"a4\", margin: 16mm)\n#set text(font: \"DejaVu Sans\", size: 10pt)\n")
	b.WriteString("#text(size: 21pt, weight: \"bold\", " + typstString(v.Title) + ")\n#parbreak()\n")
	b.WriteString("#text(" + typstString(v.Lead) + ")\n#parbreak()\n")
	for _, line := range []string{v.TargetLabel + ": " + v.Target, v.ProfileLabel + ": " + v.Profile, v.GeneratedLabel + ": " + v.GeneratedAt, v.VersionLabel + ": " + v.Version} {
		b.WriteString("#text(" + typstString(line) + ")\n#linebreak()\n")
	}
	for _, card := range v.Cards {
		b.WriteString("#text(weight: \"bold\", " + typstString(card.Value+" "+card.Label) + ")\n#linebreak()\n")
	}
	b.WriteString("#parbreak()\n#text(" + typstString(v.Methodology) + ")\n#parbreak()\n")
	for _, warning := range v.Warnings {
		b.WriteString("#block(fill: rgb(\"#fffbeb\"), inset: 6pt)[#text(" + typstString(warning) + ")]\n")
	}
	for _, section := range v.Sections {
		b.WriteString("\n#heading(level: 2, numbering: none)[#text(" + typstString(section.Title) + ")]\n")
		b.WriteString("#block(sticky: true)[#text(" + typstString(strconv.Itoa(section.Shown)+" / "+strconv.Itoa(section.Total)) + ")]\n")
		if section.Note != "" {
			b.WriteString("#block(sticky: true)[#text(" + typstString(section.Note) + ")]\n")
		}
		if len(section.Headers) > 0 {
			b.WriteString(fmt.Sprintf("#table(columns: %d, inset: 3pt, stroke: 0.4pt + rgb(\"#cbd5e1\"), table.header(", len(section.Headers)))
			for _, header := range section.Headers {
				b.WriteString("text(size: 8pt, weight: \"bold\", " + typstString(header) + "),")
			}
			b.WriteString("),\n")
			for _, row := range section.Rows {
				for _, cell := range row.Cells {
					b.WriteString("text(size: 8pt, " + typstString(cell) + "),\n")
				}
			}
			b.WriteString(")\n#parbreak()\n")
			continue
		}
		for _, row := range section.Rows {
			if row.Image != "" {
				b.WriteString("#block(breakable: false)[\n")
			}
			b.WriteString("#text(weight: \"bold\", " + typstString(row.Value) + ")\n")
			if row.Context != "" {
				b.WriteString("#text(" + typstString(" — "+row.Context) + ")\n")
			}
			if row.Sources != "" {
				b.WriteString("#text(" + typstString(" ("+row.Sources+")") + ")\n")
			}
			b.WriteString("#parbreak()\n")
			if row.Image != "" {
				b.WriteString("#image(" + typstString(row.Image) + ", width: 90%, height: 150mm, fit: \"contain\")\n]\n#parbreak()\n")
			}
		}
	}
	b.WriteString("\n#heading(level: 2, numbering: none)[#text(" + typstString(v.LimitationsLabel) + ")]\n")
	b.WriteString("#text(" + typstString(v.LimitationsIntro) + ")\n#parbreak()\n")
	for _, row := range v.Limitations {
		b.WriteString("#text(" + typstString(row.Context+": "+row.Value) + ")\n#parbreak()\n")
	}
	return []byte(b.String()), nil
}
