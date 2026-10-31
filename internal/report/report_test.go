package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/i18n"
	"asmtool/internal/storage"
)

func sampleInput(path, dir string) Input {
	return Input{
		DatabasePath: path, OutputDir: dir, Version: "0.12.0-dev",
		Profile: "passive", GeneratedAt: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
		TargetDomain: "example.org", Language: "ru",
		Scope:   map[string]any{"target_domain": "example.org"},
		Modules: map[string]any{}, CollectionPolicy: map[string]any{}, Coverage: map[string]any{},
		RowLimits: RowLimits{Domain: 1},
	}
}

func openReportDB(t *testing.T) (context.Context, string, string, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "asm.sqlite3")
	db, err := storage.Connect(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return ctx, dir, path, db
}

func insertObject(t *testing.T, ctx context.Context, db *sql.DB, id, kind, value, sources, data string) {
	t.Helper()
	_, err := db.ExecContext(ctx, "INSERT INTO objects(object_id,object_type,value,sources,data,scope_status) VALUES(?,?,?,?,?,?)", id, kind, value, sources, data, "in_scope")
	if err != nil {
		t.Fatal(err)
	}
}

func insertEvent(t *testing.T, ctx context.Context, db *sql.DB, id, eventType, source, normalized string, metadata map[string]any) {
	t.Helper()
	_, err := storage.IngestEvent(ctx, db, map[string]any{
		"event_id": id, "event_type": eventType, "module": "report-fixture", "source_tool": source,
		"observed_at": "2026-10-13T11:00:00Z", "raw_value": normalized, "normalized_value": normalized,
		"scope_status": "in_scope", "confidence": 1.0, "evidence": map[string]any{},
		"relations": []any{}, "metadata": metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func humanSectionByKey(t *testing.T, language, key string, view humanView) humanSection {
	t.Helper()
	tr, err := i18n.NewTranslator(language)
	if err != nil {
		t.Fatal(err)
	}
	want, err := tr.Text(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range view.Sections {
		if section.Title == want {
			return section
		}
	}
	t.Fatalf("section %q (%q) missing in %#v", key, want, view.Sections)
	return humanSection{}
}

func TestFullReportChangesPresentationOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "asm.sqlite3")
	db, err := storage.Connect(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.example.org", "b.example.org"} {
		_, err = db.ExecContext(ctx, "INSERT INTO objects(object_id,object_type,value,sources,data) VALUES(?,?,?,?,?)",
			"domain:"+name, "domain", name, `["crt.sh"]`, `{}`)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	in := sampleInput(path, dir)
	in.Modules = map[string]any{"subdomains": true}
	in.CollectionPolicy = map[string]any{"crtsh_enabled": true}
	bounded, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if asObject(bounded["summary"])["discovered_subdomains"] != 2 {
		t.Fatalf("machine summary was truncated: %#v", bounded["summary"])
	}
	if !strings.Contains(string(csvBytes), "a.example.org") || !strings.Contains(string(csvBytes), "b.example.org") {
		t.Fatalf("CSV inventory was truncated: %s", csvBytes)
	}
	boundedView, err := makeHumanView(ctx, in, bounded, filepath.Join(dir, "stage-bounded"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	if boundedView.Sections[0].Shown != 1 {
		t.Fatalf("bounded view: %d", boundedView.Sections[0].Shown)
	}
	in.FullReport = true
	full, fullCSV, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if asObject(full["reporting"])["human_subdomain_row_limit"] != nil {
		t.Fatal("full report must not advertise a presentation cap")
	}
	fullView, err := makeHumanView(ctx, in, full, filepath.Join(dir, "stage-full"), fullCSV)
	if err != nil {
		t.Fatal(err)
	}
	if fullView.Sections[0].Shown != 2 {
		t.Fatalf("full view: %d", fullView.Sections[0].Shown)
	}
}

func TestLargeInventoryBoundsPresentationButPreservesFullReport(t *testing.T) {
	const inventorySize = 1500
	ctx, dir, path, db := openReportDB(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO objects(object_id,object_type,value,sources,data,scope_status) VALUES(?,?,?,?,?,?)")
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for i := 0; i < inventorySize; i++ {
		name := fmt.Sprintf("sub%04d.example.org", i)
		if _, err := stmt.ExecContext(ctx, "domain:"+name, "domain", name, `["crt.sh"]`, `{}`, "in_scope"); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			t.Fatalf("insert row %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	in := sampleInput(path, dir)
	in.RowLimits = RowLimits{} // Exercise the historical default, currently 200 domains.
	bounded, boundedCSV, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if asObject(bounded["summary"])["discovered_subdomains"] != inventorySize || len(asList(asObject(bounded["assets"])["domains"])) != inventorySize {
		t.Fatalf("machine inventory was truncated: summary=%#v assets=%d", bounded["summary"], len(asList(asObject(bounded["assets"])["domains"])))
	}
	csvRows, err := csv.NewReader(strings.NewReader(string(boundedCSV))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(csvRows) != inventorySize+1 || len(csvRows[len(csvRows)-1]) == 0 || csvRows[len(csvRows)-1][0] != "sub1499.example.org" {
		t.Fatalf("CSV inventory is incomplete: rows=%d last=%v", len(csvRows), csvRows[len(csvRows)-1])
	}
	boundedView, err := makeHumanView(ctx, in, bounded, filepath.Join(dir, "stage-bounded"), boundedCSV)
	if err != nil {
		t.Fatal(err)
	}
	boundedDomains := humanSectionByKey(t, "ru", "report.section.subdomains", boundedView)
	if boundedDomains.Total != inventorySize || boundedDomains.Shown != 200 || boundedDomains.Rows[len(boundedDomains.Rows)-1].Value != "sub0199.example.org" {
		t.Fatalf("default bounded domain view = total %d, shown %d, last %q", boundedDomains.Total, boundedDomains.Shown, boundedDomains.Rows[len(boundedDomains.Rows)-1].Value)
	}
	boundedHTML, err := renderHTML(boundedView)
	if err != nil {
		t.Fatal(err)
	}
	boundedTypst, err := renderTypst(boundedView)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(boundedHTML), "sub1499.example.org") || strings.Contains(string(boundedTypst), "sub1499.example.org") {
		t.Fatal("bounded HTML or Typst contains a presentation-truncated domain")
	}
	if !strings.Contains(string(boundedHTML), "200/1500") || !strings.Contains(string(boundedTypst), "200/1500") {
		t.Fatal("bounded HTML or Typst omitted the row-limit notice")
	}

	in.FullReport = true
	full, fullCSV, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bounded["summary"], full["summary"]) || !bytes.Equal(boundedCSV, fullCSV) {
		t.Fatal("full-report changed the machine summary or CSV inventory")
	}
	fullView, err := makeHumanView(ctx, in, full, filepath.Join(dir, "stage-full"), fullCSV)
	if err != nil {
		t.Fatal(err)
	}
	fullDomains := humanSectionByKey(t, "ru", "report.section.subdomains", fullView)
	if fullDomains.Total != inventorySize || fullDomains.Shown != inventorySize || fullDomains.Rows[inventorySize-1].Value != "sub1499.example.org" {
		t.Fatalf("full report omitted rows: total=%d shown=%d last=%q", fullDomains.Total, fullDomains.Shown, fullDomains.Rows[len(fullDomains.Rows)-1].Value)
	}
	fullHTML, err := renderHTML(fullView)
	if err != nil {
		t.Fatal(err)
	}
	fullTypst, err := renderTypst(fullView)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fullHTML), "sub1499.example.org") || !strings.Contains(string(fullTypst), "sub1499.example.org") {
		t.Fatal("full HTML or Typst omitted the last inventory row")
	}
	if strings.Contains(strings.Join(fullView.Warnings, "\n"), "200/1500") {
		t.Fatal("full report retained a bounded-row warning")
	}
}

func TestLoadSchemaGoldenAndUnicode(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	insertObject(t, ctx, db, "domain:example.org", "domain", "example.org", `[]`, `{}`)
	insertObject(t, ctx, db, "domain:api.example.org", "domain", "api.example.org", `["crt.sh"]`, `{"latest":{"event_type":"subdomain_found","metadata":{"label":"Привет 世界"}}}`)
	insertEvent(t, ctx, db, "health-1", "source_health", "crt.sh", "api.example.org", map[string]any{"status": "failed", "technical_error": "offline fixture"})
	if _, err := db.ExecContext(ctx, `INSERT INTO limitations(limitation_id,observed_at,reason,data) VALUES(?,?,?,?)`,
		"limit-1", "2026-10-13T11:30:00Z", "Ошибка проверки 東京", `{}`); err != nil {
		t.Fatal(err)
	}
	in := sampleInput(path, dir)
	in.Modules = map[string]any{"subdomains": true}
	in.CollectionPolicy = map[string]any{"crtsh_enabled": true}
	got, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := backends.ValidateSchema("report", got); err != nil {
		t.Fatalf("report schema: %v", err)
	}
	projection := map[string]any{
		"profile":       asObject(got["metadata"])["profile"],
		"target_domain": asObject(got["scope"])["target_domain"],
		"summary":       got["summary"],
		"reporting": map[string]any{
			"report_language":  asObject(got["reporting"])["report_language"],
			"report_mode":      asObject(got["reporting"])["report_mode"],
			"subdomains_total": asObject(got["reporting"])["subdomains_total"],
		},
	}
	actual, err := json.MarshalIndent(projection, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	goldenPath := filepath.Join("testdata", "phase7", "load-summary.golden.json")
	if os.Getenv("UPDATE_PHASE7_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, actual, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden fixture: %v (set UPDATE_PHASE7_GOLDEN=1 only when intentionally refreshing)", err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("report projection differs from golden\nactual:\n%s\nwant:\n%s", actual, want)
	}
	if !strings.Contains(string(csvBytes), "api.example.org") {
		t.Fatalf("CSV dropped Unicode fixture domain: %s", csvBytes)
	}
	view, err := makeHumanView(ctx, in, got, filepath.Join(dir, "stage"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	markerBytes, err := os.ReadFile(filepath.Join("testdata", "phase7", "render-markers.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var renderMarkers map[string][]string
	if err := json.Unmarshal(markerBytes, &renderMarkers); err != nil {
		t.Fatal(err)
	}
	for _, language := range []string{"en", "ru"} {
		in.Language = language
		localized, err := makeHumanView(ctx, in, got, filepath.Join(dir, "stage-"+language), csvBytes)
		if err != nil {
			t.Fatal(err)
		}
		title, err := i18n.NewTranslator(language)
		if err != nil {
			t.Fatal(err)
		}
		wantTitle, err := title.Text("report.title", nil)
		if err != nil {
			t.Fatal(err)
		}
		htmlBytes, err := renderHTML(localized)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(htmlBytes), wantTitle) {
			t.Errorf("%s HTML missing localized title %q", language, wantTitle)
		}
		if !strings.Contains(string(htmlBytes), "Ошибка проверки 東京") {
			t.Errorf("%s HTML lost Unicode evidence", language)
		}
		typstBytes, err := renderTypst(localized)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(typstBytes), wantTitle) {
			t.Errorf("%s Typst missing localized title %q", language, wantTitle)
		}
		if !strings.Contains(string(typstBytes), "Ошибка проверки 東京") {
			t.Errorf("%s Typst lost Unicode evidence", language)
		}
		for _, marker := range renderMarkers[language] {
			if !strings.Contains(string(htmlBytes), marker) {
				t.Errorf("%s HTML missing golden marker %q", language, marker)
			}
			if !strings.Contains(string(typstBytes), marker) {
				t.Errorf("%s Typst missing golden marker %q", language, marker)
			}
		}
	}
	if !strings.Contains(view.Sections[0].Rows[0].Value, "api.example.org") {
		t.Fatalf("Unicode domain missing from human view: %#v", view.Sections[0])
	}
	if asObject(got["summary"])["source_failures"] != 1 {
		t.Fatalf("source health failure was not reflected in summary: %#v", got["summary"])
	}
}

func TestCrawlerDocumentsAppearInDocumentSection(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	insertObject(t, ctx, db, "url:manual", "url", "https://example.org/guide.pdf", `["crawler"]`, `{"latest":{"event_type":"crawler_result","metadata":{"category":"downloadable_resource_detected","resource_type":"application/pdf","page_loaded":false}}}`)
	insertObject(t, ctx, db, "url:manual-duplicate", "url", "https://example.org/guide.pdf", `["crawler"]`, `{"latest":{"event_type":"crawler_result","metadata":{"category":"downloadable_resource_detected","resource_type":"application/pdf","page_loaded":false}}}`)
	in := sampleInput(path, dir)
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	view, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	documents := humanSectionByKey(t, "ru", "report.section.documents", view)
	if documents.Total != 1 || documents.Shown != 1 || documents.Rows[0].Value != "https://example.org/guide.pdf" {
		t.Fatalf("crawler document missing from documents section: %#v", documents)
	}
	htmlBytes, err := renderHTML(view)
	if err != nil {
		t.Fatal(err)
	}
	typstBytes, err := renderTypst(view)
	if err != nil {
		t.Fatal(err)
	}
	for format, data := range map[string][]byte{"HTML": htmlBytes, "Typst": typstBytes} {
		if !strings.Contains(string(data), "https://example.org/guide.pdf") {
			t.Errorf("crawler document absent from %s output", format)
		}
	}
}

func TestVerifyCoverageIncludesFailuresAndZeroPageStatus(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	insertEvent(t, ctx, db, "root-failed", "web_target_status", "http", "example.org", map[string]any{
		"stage": "root_verification", "status": "connection_failed", "requested_url": "https://example.org/",
		"status_code": 0, "reason": "connection refused", "page_loaded": false,
	})
	insertEvent(t, ctx, db, "shop-crawl-failed", "web_target_status", "crawler", "shop.example.org", map[string]any{
		"stage": "crawl", "status": "failed", "reason": "blocked by fixture",
	})
	in := sampleInput(path, dir)
	in.Profile = "verify"
	in.ConfirmedWebTargets = []ConfirmedWebTarget{
		{Domain: "example.org", InputTarget: true},
		{Domain: "shop.example.org", DNSEvidence: []string{"fixture"}},
	}
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	coverage := asList(report["web_coverage"])
	if len(coverage) != 2 {
		t.Fatalf("coverage rows lost: %#v", coverage)
	}
	root, shop := asObject(coverage[0]), asObject(coverage[1])
	if root["root_status"] != "connection_failed" || root["reason"] != "connection refused" || root["pages_loaded"] != 0 {
		t.Fatalf("failed root coverage was lost: %#v", root)
	}
	if shop["root_status"] != "not_attempted" || shop["crawl_status"] != "failed" || shop["reason"] != "blocked by fixture" {
		t.Fatalf("failed crawler coverage was lost: %#v", shop)
	}
	view, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	section := humanSectionByKey(t, "ru", "report.section.web_coverage", view)
	if len(section.Rows) != 2 {
		t.Fatalf("web coverage rows not presented: %#v", section)
	}
	tr, err := i18n.NewTranslator("ru")
	if err != nil {
		t.Fatal(err)
	}
	failedLabel, _ := tr.Text("web.root.connection_failed", nil)
	notLoadedLabel, _ := tr.Text("web.coverage.not_loaded", nil)
	if section.Rows[0].Cells[1] != failedLabel || section.Rows[0].Cells[4] != "0" || section.Rows[0].Cells[6] != notLoadedLabel {
		t.Fatalf("failed zero-page coverage has incorrect localized cells: %#v", section.Rows[0].Cells)
	}
	unattemptedLabel, _ := tr.Text("web.root.not_attempted", nil)
	if section.Rows[1].Cells[1] != unattemptedLabel || section.Rows[1].Cells[6] != notLoadedLabel {
		t.Fatalf("unattempted target missing from coverage: %#v", section.Rows[1].Cells)
	}
}

func TestSpecializedRussianTablesAndProviderWarning(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	insertObject(t, ctx, db, "domain:example.org", "domain", "example.org", `[]`, `{}`)
	insertObject(t, ctx, db, "domain:api.example.org", "domain", "api.example.org", `["crt.sh"]`, `{}`)
	insertObject(t, ctx, db, "domain:shared.other.net", "domain", "shared.other.net", `["shodan_internetdb"]`, `{"latest":{"metadata":{"context_reason":"shared IP context"}}}`)
	insertObject(t, ctx, db, "ip:192.0.2.10", "ip", "192.0.2.10", `["tcp_connect"]`, `{}`)
	insertObject(t, ctx, db, "asn:AS64500", "asn", "AS64500", `["team_cymru_dns"]`, `{"latest":{"metadata":{"as_name":"Example AS"}}}`)
	insertObject(t, ctx, db, "tcp:192.0.2.10:443", "port_scan_result", "192.0.2.10:443", `["tcp_connect"]`, `{"latest":{"event_type":"port_scan_result","metadata":{"ip":"192.0.2.10","port":443,"protocol":"tcp","state":"open","attempted":true,"duration_ms":7,"validated_domains":["api.example.org"],"shared_infrastructure_indicators":["shared hosting"]}}}`)
	insertObject(t, ctx, db, "url:guide", "url", "https://example.org/guide.pdf", `["crawler"]`, `{"latest":{"event_type":"crawler_result","metadata":{"category":"downloadable_resource_detected","resource_type":"PDF document","detection_reason":"non_html","status_code":200,"page_loaded":false}}}`)
	if _, err := db.ExecContext(ctx, `INSERT INTO relations(relation_id,source_id,target_id,relation_type,evidence) VALUES(?,?,?,?,?)`,
		"rel-1", "domain:api.example.org", "ip:192.0.2.10", "resolves_to", `{}`); err != nil {
		t.Fatal(err)
	}
	artifact := `{"schema_version":1,"domain":"example.org","asm_version":"0.12.0-dev","providers":[{"provider":"thc","collector":"thc","returned":3,"accepted":2,"unique":1,"duplicates":1,"collector_status":"ok","completeness_state":"collector_success_completeness_unknown","termination":"unknown","anomaly_status":"not_evaluated_no_comparable_history"}]}`
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifacts", "passive_provider_completeness.json"), []byte(artifact), 0644); err != nil {
		t.Fatal(err)
	}
	in := sampleInput(path, dir)
	// A normalized value present as both a domain and a TLS name is retained in
	// each typed machine bucket, while the domain table remains deduplicated.
	insertObject(t, ctx, db, "tlsname:api.example.org", "tls_name", "api.example.org", `["certificate"]`, `{}`)
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(asList(asObject(report["assets"])["domains"])) != 3 || len(asList(report["tls"])) != 1 {
		t.Fatalf("domain/TLS normalized-value collision was lost or duplicated: %#v / %#v", asObject(report["assets"]), report["tls"])
	}
	view, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		key     string
		headers []string
		cell    int
		value   string
	}{
		{"report.section.network", []string{"IP-адрес", "Связанные домены в области исследования", "Источник данных"}, 1, "api.example.org"},
		{"report.section.routing", []string{"Тип", "Значение", "Описание"}, 1, "AS64500"},
		{"report.section.ports", []string{"Узел", "Порт", "Тип наблюдения", "Привязка к домену", "Сведения"}, 3, "api.example.org"},
		{"report.section.related", []string{"Имя", "Источник данных", "Контекст"}, 0, "shared.other.net"},
		{"report.section.documents", []string{"URL", "Тип ресурса", "Способ обнаружения", "HTTP"}, 0, "https://example.org/guide.pdf"},
	}
	for _, check := range checks {
		section := humanSectionByKey(t, "ru", check.key, view)
		if !reflect.DeepEqual(section.Headers, check.headers) {
			t.Errorf("%s headers: %#v", check.key, section.Headers)
		}
		found := false
		for _, row := range section.Rows {
			if len(row.Cells) > check.cell && strings.Contains(row.Cells[check.cell], check.value) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s expected cell %q at column %d: %#v", check.key, check.value, check.cell, section.Rows)
		}
	}
	provider := humanSectionByKey(t, "ru", "report.section.provider_completeness", view)
	tr, _ := i18n.NewTranslator("ru")
	warningText, _ := tr.Text("provider.warning.thc", nil)
	if len(provider.Rows) != 1 || !strings.Contains(strings.Join(view.Warnings, "\n"), warningText) {
		t.Fatalf("localized incomplete-provider warning missing: %#v; warnings=%#v", provider, view.Warnings)
	}
	htmlBytes, err := renderHTML(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(htmlBytes), "Таблица") && !strings.Contains(string(htmlBytes), "Порты и сетевые сервисы") {
		t.Fatal("specialized Russian report sections were not rendered")
	}
}

func TestTCPScanReportPreservesAllStatesAndCountsOnlyOpenAsActive(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	for _, row := range []struct {
		id, state string
		attempted bool
	}{
		{"tcp:192.0.2.1:80", "open", true},
		{"tcp:192.0.2.1:81", "closed", true},
		{"tcp:192.0.2.1:82", "unknown", true},
	} {
		port := strings.Split(row.id, ":")[2]
		metadata := fmt.Sprintf(`{"ip":"192.0.2.1","protocol":"tcp","port":%s,"state":%q,"attempted":%t,"reason":"fixture","validated_domains":["api.example.org"]}`, port, row.state, row.attempted)
		data := fmt.Sprintf(`{"latest":{"event_type":"port_scan_result","metadata":%s}}`, metadata)
		insertObject(t, ctx, db, row.id, "port_scan_result", "192.0.2.1:"+port, `["tcp_connect"]`, data)
	}
	in := sampleInput(path, dir)
	in.RowLimits.Port = 2
	for _, full := range []bool{false, true} {
		in.FullReport = full
		for _, language := range []string{"ru", "en"} {
			in.Language = language
			report, csvBytes, err := Load(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			summary := asObject(report["summary"])
			if summary["ports_actively_confirmed"] != 1 || summary["ports_tcp_open"] != 1 || summary["ports_tcp_closed"] != 1 || summary["ports_tcp_unknown"] != 1 || len(asList(report["ports"])) != 3 {
				t.Fatalf("full=%v %s summary or machine states changed: %#v; ports=%#v", full, language, summary, report["ports"])
			}
			view, err := makeHumanView(ctx, in, report, filepath.Join(dir, fmt.Sprintf("stage-%v-%s", full, language)), csvBytes)
			if err != nil {
				t.Fatal(err)
			}
			section := humanSectionByKey(t, language, "report.section.ports", view)
			wantRows := 2
			if full {
				wantRows = 3
			}
			if section.Total != 3 || section.Shown != wantRows {
				t.Fatalf("full=%v %s port rows=%d/%d", full, language, section.Shown, section.Total)
			}
			if full {
				html, err := renderHTML(view)
				if err != nil {
					t.Fatal(err)
				}
				typst, err := renderTypst(view)
				if err != nil {
					t.Fatal(err)
				}
				for _, state := range []string{"open", "closed", "unknown"} {
					localized, err := i18n.NewTranslator(language)
					if err != nil {
						t.Fatal(err)
					}
					label, err := localized.Text("port."+state, nil)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(html), label) || !strings.Contains(string(typst), label) {
						t.Errorf("%s full output missing TCP state %s", language, state)
					}
				}
				if strings.Contains(string(html), "Nmap") || strings.Contains(string(typst), "Nmap") || strings.Contains(string(html), "SHOULD_NOT_INFER_SERVICE") {
					t.Fatal("TCP result contains obsolete scanner/service inference label")
				}
			}
		}
	}
}

func TestHumanLimitationsDeduplicateOnlyExactSameSourceHealthWarnings(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	in := sampleInput(path, dir)
	for _, full := range []bool{false, true} {
		in.FullReport = full
		for _, language := range []string{"ru", "en"} {
			in.Language = language
			report := map[string]any{
				"metadata":      map[string]any{"generated_at_local": "2026-10-20"},
				"summary":       map[string]any{},
				"source_health": []any{map[string]any{"source": "crt.sh", "label": "crt.sh", "status": "partial", "items": 0, "last_http_status": 503, "errors": []any{"same source failed"}}},
				"limitations": []any{
					map[string]any{"reason": "same source failed", "data": map[string]any{"source_tool": "crt.sh", "metadata": map[string]any{}}},
					map[string]any{"reason": "same source failed", "data": map[string]any{"source_tool": "certspotter", "metadata": map[string]any{}}},
					map[string]any{"reason": "different crt.sh failure", "data": map[string]any{"source_tool": "crt.sh", "metadata": map[string]any{}}},
					map[string]any{"reason": "503 transport issue", "data": map[string]any{"source_tool": "crt.sh", "metadata": map[string]any{}}},
					map[string]any{"reason": "503 response from /admin needs separate review", "data": map[string]any{"source_tool": "crt.sh", "metadata": map[string]any{}}},
				},
			}
			before, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			csvFixture := []byte("hostname,scope_status,rank,dns_state,active_eligibility,providers,collectors,evidence_families,wildcard_state,A,AAAA,CNAME,first_seen,deferred_by_dns_budget\n")
			view, err := makeHumanView(ctx, in, report, filepath.Join(dir, fmt.Sprintf("stage-%v-%s", full, language)), csvFixture)
			if err != nil {
				t.Fatal(err)
			}
			if len(view.Limitations) != 3 {
				t.Fatalf("full=%v language=%s limitations=%#v; only exact or generic same-source/status overlaps may be hidden", full, language, view.Limitations)
			}
			seen := map[string]bool{}
			for _, row := range view.Limitations {
				seen[row.Context+"\x00"+row.Value] = true
			}
			localizedError := "An external source was temporarily unavailable; collection continued with available alternatives."
			if language == "ru" {
				localizedError = "Внешний источник временно недоступен; сбор продолжен с использованием доступных альтернатив."
			}
			if !seen["certspotter\x00same source failed"] || !seen["crt.sh\x00different crt.sh failure"] || !seen["crt.sh\x00"+localizedError] {
				t.Fatalf("full=%v language=%s distinct errors/sources were lost: %#v", full, language, view.Limitations)
			}
			after, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || len(asList(report["limitations"])) != 5 {
				t.Fatal("human warning dedup mutated machine-readable limitations")
			}
		}
	}
	_ = db
}

func TestSecurityBlockedSubfasterStatusAndReasonRemainVisible(t *testing.T) {
	ctx, dir, path, _ := openReportDB(t)
	in := sampleInput(path, dir)
	in.RowLimits.WebCoverage = 1
	causes := []string{
		"Subfaster is blocked by network safety policy before process creation",
		"Subfaster executable provenance remains available for review",
		"provider transport failed independently",
	}
	for _, full := range []bool{false, true} {
		in.FullReport = full
		for _, language := range []string{"ru", "en"} {
			in.Language = language
			report := map[string]any{
				"metadata":      map[string]any{"generated_at_local": "2026-10-20"},
				"summary":       map[string]any{},
				"source_health": []any{map[string]any{"source": "thc", "label": "THC passive source", "status": "security_blocked", "items": 0, "errors": []any{causes[0], causes[1], causes[2], causes[0]}}},
				"limitations": []any{
					map[string]any{"reason": causes[0], "data": map[string]any{"source_tool": "thc", "metadata": map[string]any{"security_status": "security_blocked"}}},
					map[string]any{"reason": causes[1], "data": map[string]any{"source_tool": "thc", "metadata": map[string]any{"security_status": "security_blocked"}}},
					map[string]any{"reason": causes[2], "data": map[string]any{"source_tool": "thc", "metadata": map[string]any{"security_status": "security_blocked"}}},
				},
			}
			before, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			csvFixture := []byte("hostname,scope_status,rank,dns_state,active_eligibility,providers,collectors,evidence_families,wildcard_state,A,AAAA,CNAME,first_seen,deferred_by_dns_budget\n")
			view, err := makeHumanView(ctx, in, report, filepath.Join(dir, fmt.Sprintf("stage-security-%v-%s", full, language)), csvFixture)
			if err != nil {
				t.Fatal(err)
			}
			section := humanSectionByKey(t, language, "report.section.source_health", view)
			if len(section.Rows) != 1 || len(view.Limitations) != 0 {
				t.Fatalf("full=%v %s security reasons were hidden or duplicated: section=%#v limitations=%#v", full, language, section.Rows, view.Limitations)
			}
			tr, err := i18n.NewTranslator(language)
			if err != nil {
				t.Fatal(err)
			}
			blockedLabel, err := tr.Text("source.status.security_blocked", nil)
			if err != nil {
				t.Fatal(err)
			}
			if section.Rows[0].Context != blockedLabel {
				t.Fatalf("%s source health omitted explicit block status: %#v", language, section.Rows[0])
			}
			html, err := renderHTML(view)
			if err != nil {
				t.Fatal(err)
			}
			typst, err := renderTypst(view)
			if err != nil {
				t.Fatal(err)
			}
			for _, output := range []struct {
				name string
				data []byte
			}{{"HTML", html}, {"Typst", typst}} {
				for _, cause := range causes {
					if got := strings.Count(string(output.data), cause); got != 1 {
						t.Errorf("full=%v %s %s output contains cause %q %d times, want exactly once", full, language, output.name, cause, got)
					}
				}
				if !strings.Contains(string(output.data), blockedLabel) {
					t.Errorf("full=%v %s %s output omitted localized security-blocked status", full, language, output.name)
				}
			}
			after, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || len(asList(report["limitations"])) != 3 {
				t.Fatal("rendering human warnings mutated machine-readable report data")
			}
		}
	}
}

func TestBoundedHiddenHealthFailureDoesNotSuppressLimitation(t *testing.T) {
	ctx, dir, path, _ := openReportDB(t)
	in := sampleInput(path, dir)
	in.RowLimits.WebCoverage = 1
	report := map[string]any{
		"metadata": map[string]any{"generated_at_local": "2026-10-20"},
		"summary":  map[string]any{},
		"source_health": []any{
			map[string]any{"source": "visible.source", "label": "Visible", "status": "partial", "items": 0, "errors": []any{"visible failure"}},
			map[string]any{"source": "hidden.source", "label": "Hidden", "status": "partial", "items": 0, "errors": []any{"hidden failure"}},
		},
		"limitations": []any{map[string]any{"reason": "hidden failure", "data": map[string]any{"source_tool": "hidden.source", "metadata": map[string]any{}}}},
	}
	csvFixture := []byte("hostname,scope_status,rank,dns_state,active_eligibility,providers,collectors,evidence_families,wildcard_state,A,AAAA,CNAME,first_seen,deferred_by_dns_budget\n")
	view, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage-bounded"), csvFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Limitations) != 1 || view.Limitations[0].Context != "hidden.source" {
		t.Fatalf("limitation for bounded-hidden health row was incorrectly suppressed: %#v", view.Limitations)
	}
	in.FullReport = true
	fullView, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage-full"), csvFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullView.Limitations) != 0 {
		t.Fatalf("full view should deduplicate exact health/limitation overlap: %#v", fullView.Limitations)
	}
}

func TestScreenshotResourcesAreDeterministicAndContained(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 20, G: 80, B: 130, A: 255})
	var encoded strings.Builder
	if err := png.Encode(&encoded, img); err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(dir, "artifacts", "screenshots", "capture.png")
	if err := os.MkdirAll(filepath.Dir(imagePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(imagePath, []byte(encoded.String()), 0644); err != nil {
		t.Fatal(err)
	}
	insertObject(t, ctx, db, "screenshot:one", "screenshot", "https://example.org/", `["crawler"]`, `{"latest":{"event_type":"screenshot_saved","metadata":{"path":"artifacts/screenshots/capture.png","target_domain":"example.org","url":"https://example.org/"}}}`)
	in := sampleInput(path, dir)
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	first, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage-one"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	second, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage-two"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	shots1 := humanSectionByKey(t, "ru", "report.section.screenshots", first)
	shots2 := humanSectionByKey(t, "ru", "report.section.screenshots", second)
	if len(shots1.Rows) != 1 || shots1.Rows[0].Image == "" || shots1.Rows[0].Image != shots2.Rows[0].Image || shots1.Rows[0].ImageURL != shots2.Rows[0].ImageURL {
		t.Fatalf("image references vary or are missing: %#v / %#v", shots1, shots2)
	}
	if !strings.HasPrefix(shots1.Rows[0].Image, "images/") {
		t.Fatalf("image reference escaped generation directory: %q", shots1.Rows[0].Image)
	}
	if _, err := os.Stat(filepath.Join(dir, "stage-one", filepath.FromSlash(shots1.Rows[0].Image))); err != nil {
		t.Fatal(err)
	}
	firstHTML, err := renderHTML(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHTML, err := renderHTML(second)
	if err != nil {
		t.Fatal(err)
	}
	firstTypst, err := renderTypst(first)
	if err != nil {
		t.Fatal(err)
	}
	secondTypst, err := renderTypst(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstHTML, secondHTML) || !bytes.Equal(firstTypst, secondTypst) {
		t.Fatal("same persisted evidence produced different HTML or Typst bytes")
	}
	firstImage, err := os.ReadFile(filepath.Join(dir, "stage-one", filepath.FromSlash(shots1.Rows[0].Image)))
	if err != nil {
		t.Fatal(err)
	}
	secondImage, err := os.ReadFile(filepath.Join(dir, "stage-two", filepath.FromSlash(shots2.Rows[0].Image)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstImage, secondImage) {
		t.Fatal("staged image bytes changed across repeated rendering")
	}
	digest := sha256.Sum256(firstImage)
	if filepath.Base(shots1.Rows[0].Image) != hex.EncodeToString(digest[:])+".png" {
		t.Fatalf("staged resource name is not content-addressed: %q", shots1.Rows[0].Image)
	}

	// A persisted absolute path outside the run tree must never be copied.
	outside := filepath.Join(t.TempDir(), "outside.png")
	if err := os.WriteFile(outside, []byte(encoded.String()), 0644); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"data": map[string]any{"latest": map[string]any{"metadata": map[string]any{"absolute_path": outside}}}}
	got, warning := safeImage(ctx, dir, filepath.Join(dir, "stage-outside"), row)
	if got != "" || warning == "" {
		t.Fatalf("outside image accepted: %q, %q", got, warning)
	}
	wrongHash := map[string]any{"data": map[string]any{"latest": map[string]any{"metadata": map[string]any{"path": "artifacts/screenshots/capture.png", "sha256": strings.Repeat("0", 64)}}}}
	if got, warning := safeImage(ctx, dir, filepath.Join(dir, "stage-hash"), wrongHash); got != "" || !strings.Contains(warning, "SHA-256") {
		t.Fatalf("image with mismatched evidence digest accepted: %q, %q", got, warning)
	}
	corruptPath := filepath.Join(dir, "artifacts", "screenshots", "corrupt.png")
	if err := os.WriteFile(corruptPath, []byte("not a PNG"), 0644); err != nil {
		t.Fatal(err)
	}
	corrupt := map[string]any{"data": map[string]any{"latest": map[string]any{"metadata": map[string]any{"path": "artifacts/screenshots/corrupt.png"}}}}
	if got, warning := safeImage(ctx, dir, filepath.Join(dir, "stage-corrupt"), corrupt); got != "" || warning == "" {
		t.Fatalf("corrupt PNG accepted: %q, %q", got, warning)
	}
}

func TestMalformedPersistedShapesAndCompletenessFailClosed(t *testing.T) {
	for _, test := range []struct{ name, sources, data string }{
		{"sources-object", `{}`, `{}`},
		{"data-array", `[]`, `[]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, dir, path, db := openReportDB(t)
			insertObject(t, ctx, db, "domain:bad.example.org", "domain", "bad.example.org", test.sources, test.data)
			if _, _, err := Load(ctx, sampleInput(path, dir)); err == nil {
				t.Fatal("malformed persisted shape accepted")
			}
		})
	}
	t.Run("bad-provider-artifact", func(t *testing.T) {
		ctx, dir, path, _ := openReportDB(t)
		artifactDir := filepath.Join(dir, "artifacts")
		if err := os.MkdirAll(artifactDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(artifactDir, "passive_provider_completeness.json"), []byte(`{"schema_version":1,"domain":"elsewhere.org","asm_version":"0.12.0-dev","providers":[]}`), 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(ctx, sampleInput(path, dir)); err == nil {
			t.Fatal("mismatched evidence identity accepted")
		}
	})
}

func TestUntrustedReportTextStaysText(t *testing.T) {
	v := humanView{Language: "en", Title: `<script>alert(1)</script>`, LimitationsLabel: "Limitations",
		Sections: []humanSection{{Title: "Findings", Rows: []humanRow{{Value: `</td><script>alert(1)</script>`}}}}}
	html, err := renderHTML(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>") {
		t.Fatalf("unescaped HTML: %s", html)
	}
	v.Sections[0].Rows[0].Value = `"); #import "/etc/passwd"; //`
	typ, err := renderTypst(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(typ), `\"); #import`) {
		t.Fatalf("Typst text was not quoted: %s", typ)
	}
}

func TestMalformedPersistedObjectStopsReport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "asm.sqlite3")
	db, err := storage.Connect(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, "INSERT INTO objects(object_id,object_type,value,sources,data) VALUES(?,?,?,?,?)",
		"domain:a.example.org", "domain", "a.example.org", "[", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = Load(ctx, sampleInput(path, dir))
	if err == nil {
		t.Fatal("malformed object JSON must not be published")
	}
}

func TestMalformedPersistedEventStopsReport(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	_, err := db.ExecContext(ctx, `INSERT INTO events(event_id,event_type,module,source_tool,observed_at,raw_value,normalized_value,scope_status,confidence,evidence,relations,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		"broken", "source_health", "report-fixture", "crt.sh", "2026-10-13T11:00:00Z", "x", `"x"`, "in_scope", 1.0, `{}`, `[]`, `[broken`)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(ctx, sampleInput(path, dir)); err == nil {
		t.Fatal("malformed persisted event JSON must fail closed")
	}
}

func TestLimitationsAreLocalizedForRUAndENWithoutChangingMachineEvidence(t *testing.T) {
	ctx, dir, path, db := openReportDB(t)
	rows := []struct {
		id, reason, data string
	}{
		{"01-info", "INFO_ONLY_SENTINEL", `{"source_tool":"crawler","metadata":{"severity":"info"}}`},
		{"02-empty", "NO_RESULTS_SENTINEL", `{"source_tool":"crt.sh","metadata":{"source_status":"no_results"}}`},
		{"03-download", "Download is starting; DOWNLOAD_SENTINEL", `{"source_tool":"crawler","metadata":{}}`},
		{"04-timeout", "certificate source timed out; TIMEOUT_RAW_SENTINEL", `{"source_tool":"certspotter","metadata":{}}`},
		{"05-crtsh", "crt.sh returned HTTP 404; CRTSH_RAW_SENTINEL", `{"source_tool":"crt.sh","metadata":{}}`},
		{"06-http", "upstream HTTP 503; HTTP_RAW_SENTINEL", `{"source_tool":"certspotter","metadata":{}}`},
		{"07-tcp", "TCP connection timed out; TCP_TIMEOUT_RAW_SENTINEL", `{"source_tool":"tcp_connect","metadata":{"state":"unknown","attempted":true,"reason":"timeout"}}`},
	}
	for i, row := range rows {
		if _, err := db.ExecContext(ctx, `INSERT INTO limitations(limitation_id,observed_at,reason,data) VALUES(?,?,?,?)`, row.id, fmt.Sprintf("2026-10-13T11:%02d:00Z", i), row.reason, row.data); err != nil {
			t.Fatal(err)
		}
	}
	in := sampleInput(path, dir)
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	machineRows := asList(report["limitations"])
	if len(machineRows) != len(rows) {
		t.Fatalf("machine evidence count = %d, want %d", len(machineRows), len(rows))
	}
	for i, expected := range rows {
		if got := str(asObject(machineRows[i])["reason"]); got != expected.reason {
			t.Errorf("machine limitation %d changed: %q, want %q", i, got, expected.reason)
		}
	}
	for _, language := range []string{"ru", "en"} {
		in.Language = language
		view, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage-"+language), csvBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(view.Limitations) != 4 {
			t.Fatalf("%s visible limitation count = %d, want four warnings", language, len(view.Limitations))
		}
		htmlBytes, err := renderHTML(view)
		if err != nil {
			t.Fatal(err)
		}
		typstBytes, err := renderTypst(view)
		if err != nil {
			t.Fatal(err)
		}
		tr, err := i18n.NewTranslator(language)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"limitation.timeout", "limitation.crtsh_404", "limitation.server_error"} {
			localized, err := tr.Text(key, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(htmlBytes), localized) || !strings.Contains(string(typstBytes), localized) {
				t.Errorf("%s output missing localized %s: %q", language, key, localized)
			}
		}
		for _, hidden := range []string{"INFO_ONLY_SENTINEL", "NO_RESULTS_SENTINEL", "DOWNLOAD_SENTINEL", "TIMEOUT_RAW_SENTINEL", "CRTSH_RAW_SENTINEL", "HTTP_RAW_SENTINEL", "TCP_TIMEOUT_RAW_SENTINEL"} {
			if strings.Contains(string(htmlBytes), hidden) || strings.Contains(string(typstBytes), hidden) {
				t.Errorf("%s report rendered non-warning marker %q", language, hidden)
			}
		}
	}
	if len(asList(report["limitations"])) != len(rows) || str(asObject(asList(report["limitations"])[3])["reason"]) != rows[3].reason {
		t.Fatal("rendering mutated machine-readable limitation evidence")
	}
}
