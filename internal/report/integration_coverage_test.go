package report

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"asmtool/internal/storage"
)

func browserCoverageReport(t *testing.T, required bool, targetCount int, language string) (map[string]any, []byte, Input, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "asm.sqlite3")
	db, err := storage.Connect(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	in := sampleInput(database, dir)
	in.Profile = "full"
	in.Language = language
	in.ConfirmedWebTargets = []ConfirmedWebTarget{}
	in.Coverage = map[string]any{
		"browser_mode": "blocked", "browser_required": required,
		"browser_availability": "security_blocked",
		"screenshots_status":   "security_blocked",
	}
	if !required {
		in.Coverage["browser_mode"] = "disabled"
		in.Coverage["screenshots_status"] = "not_requested"
	}
	for i, domain := range []string{"example.org", "shop.example.org"}[:targetCount] {
		in.ConfirmedWebTargets = append(in.ConfirmedWebTargets, ConfirmedWebTarget{Domain: domain, InputTarget: i == 0, DNSEvidence: []string{"input_target"}})
		url := "https://" + domain + "/"
		insertEvent(t, ctx, db, "root-http-"+domain, "web_target_status", "http", domain, map[string]any{
			"stage": "root_verification", "status": "loaded", "requested_url": url,
			"final_url": url, "status_code": 200, "page_loaded": true,
		})
		insertEvent(t, ctx, db, "http-html-"+domain, "html_analyzed", "http", url, map[string]any{
			"target_domain": domain, "status_code": 200, "title": "HTTP-only page", "browser_dom": false,
		})
		browserStatus, screenshotStatus := "security_blocked", "security_blocked"
		if !required {
			browserStatus, screenshotStatus = "disabled_by_policy", "not_requested"
		}
		insertEvent(t, ctx, db, "browser-policy-"+domain, "web_target_status", "browser_policy", domain, map[string]any{
			"stage": "browser", "status": browserStatus, "browser_required": required,
			"screenshot_status": screenshotStatus, "reason": "candidate31_preconnect_security_failure",
			"page_loaded": false, "target_service_contacted": false,
		})
	}
	report, csvBytes, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	return report, csvBytes, in, dir
}

func TestBrowserCoveragePersistsBlockedAndOptOutSemantics(t *testing.T) {
	for _, tc := range []struct {
		name               string
		required           bool
		wantComplete       bool
		status, screenshot string
	}{
		{"required_blocked", true, false, "security_blocked", "security_blocked"},
		{"deliberate_optout", false, true, "disabled_by_policy", "not_requested"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, _, _, _ := browserCoverageReport(t, tc.required, 1, "en")
			rows := asList(report["web_coverage"])
			if len(rows) != 1 {
				t.Fatalf("coverage rows = %d, want 1", len(rows))
			}
			row := asObject(rows[0])
			if row["root_status"] != "loaded" || row["crawl_status"] != "not_started" || row["pages_loaded"] != 1 {
				t.Fatalf("browser status changed HTTP/crawl coverage: %#v", row)
			}
			if row["browser_status"] != tc.status || row["screenshot_status"] != tc.screenshot || row["screenshot_complete"] != tc.wantComplete {
				t.Fatalf("unexpected browser coverage: %#v", row)
			}
			if tc.required && row["reason"] != "candidate31_preconnect_security_failure" {
				t.Fatalf("browser reason missing: %#v", row)
			}
			summary := asObject(report["summary"])
			if summary["screenshot_coverage_complete"] != tc.wantComplete {
				t.Fatalf("summary screenshot completeness = %v", summary["screenshot_coverage_complete"])
			}
		})
	}
}

func TestRequiredBrowserBlockIsIncompleteWithoutEligibleTargets(t *testing.T) {
	report, _, _, _ := browserCoverageReport(t, true, 0, "en")
	if got := asObject(report["summary"])["screenshot_coverage_complete"]; got != false {
		t.Fatalf("zero-target blocked browser coverage = %v, want false", got)
	}
	if _, present := asObject(report["summary"])["browser_availability"]; !present {
		t.Fatal("global browser availability missing from summary")
	}
}

func TestBrowserCoverageLocalizationUsesSharedHTMLAndTypstView(t *testing.T) {
	for _, tc := range []struct {
		language, marker string
		required         bool
	}{
		{"en", "Browser availability:", true},
		{"ru", "Доступность браузера:", true},
		{"en", "deliberately disabled", false},
		{"ru", "намеренно отключены", false},
	} {
		t.Run(tc.language+"_"+map[bool]string{true: "blocked", false: "disabled"}[tc.required], func(t *testing.T) {
			report, csvBytes, in, dir := browserCoverageReport(t, tc.required, 0, tc.language)
			view, err := makeHumanView(context.Background(), in, report, filepath.Join(dir, "stage"), csvBytes)
			if err != nil {
				t.Fatal(err)
			}
			htmlBytes, err := renderHTML(view)
			if err != nil {
				t.Fatal(err)
			}
			typstBytes, err := renderTypst(view)
			if err != nil {
				t.Fatal(err)
			}
			for format, body := range map[string][]byte{"HTML": htmlBytes, "Typst": typstBytes} {
				if !bytes.Contains(body, []byte(tc.marker)) {
					t.Errorf("%s omitted localized browser coverage marker %q", format, tc.marker)
				}
			}
			if strings.Contains(string(htmlBytes), "candidate31_preconnect_security_failure") {
				t.Error("HTML exposed internal reason token")
			}
		})
	}
}

func TestBrowserCoverageBoundedAndFullRowsRetainSameCounts(t *testing.T) {
	report, csvBytes, in, dir := browserCoverageReport(t, false, 2, "en")
	in.RowLimits.WebCoverage = 1
	bounded, err := makeHumanView(context.Background(), in, report, filepath.Join(dir, "stage-bounded"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	fullInput := in
	fullInput.FullReport = true
	full, err := makeHumanView(context.Background(), fullInput, report, filepath.Join(dir, "stage-full"), csvBytes)
	if err != nil {
		t.Fatal(err)
	}
	boundedSection := humanSectionByKey(t, "en", "report.section.web_coverage", bounded)
	fullSection := humanSectionByKey(t, "en", "report.section.web_coverage", full)
	if boundedSection.Total != 2 || boundedSection.Shown != 1 || len(boundedSection.Rows) != 1 {
		t.Fatalf("bounded rows = total %d, shown %d", boundedSection.Total, boundedSection.Shown)
	}
	if fullSection.Total != 2 || fullSection.Shown != 2 || len(fullSection.Rows) != 2 {
		t.Fatalf("full rows = total %d, shown %d", fullSection.Total, fullSection.Shown)
	}
	if asObject(report["summary"])["web_targets_planned"] != 2 || asObject(report["summary"])["web_pages_loaded"] != 2 {
		t.Fatalf("coverage counts changed by presentation limit: %#v", report["summary"])
	}
	if len(bounded.Warnings) == 0 || !strings.Contains(bounded.Warnings[0], "1/2") {
		t.Fatalf("bounded report omitted row-limit note: %#v", bounded.Warnings)
	}
	boundedHTML, err := renderHTML(bounded)
	if err != nil {
		t.Fatal(err)
	}
	boundedTypst, err := renderTypst(bounded)
	if err != nil {
		t.Fatal(err)
	}
	for format, body := range map[string][]byte{"HTML": boundedHTML, "Typst": boundedTypst} {
		if !bytes.Contains(body, []byte("1/2")) {
			t.Errorf("%s omitted row-limit note", format)
		}
	}
}

func TestPassiveReportKeepsLegacyBrowserSummaryShape(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "asm.sqlite3")
	db, err := storage.Connect(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	in := sampleInput(database, dir)
	report, _, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := asObject(report["summary"])["browser_mode"]; present {
		t.Fatal("legacy passive report unexpectedly gained browser summary fields")
	}
	if asObject(report["summary"])["screenshot_coverage_complete"] != true {
		t.Fatal("empty passive screenshot coverage should remain complete")
	}
}

func TestHTTPResponseNeverClaimsBrowserLoad(t *testing.T) {
	for _, language := range []string{"en", "ru"} {
		t.Run(language, func(t *testing.T) {
			data, csv, in, dir := browserCoverageReport(t, false, 1, language)
			view, err := makeHumanView(context.Background(), in, data, filepath.Join(dir, "stage"), csv)
			if err != nil {
				t.Fatal(err)
			}
			html, err := renderHTML(view)
			if err != nil {
				t.Fatal(err)
			}
			typst, err := renderTypst(view)
			if err != nil {
				t.Fatal(err)
			}
			marker := "verified by current HTTP response"
			falseClaim := "verified by current browser load"
			if language == "ru" {
				marker = "проверен текущим HTTP-ответом"
				falseClaim = "проверен текущей браузерной загрузкой"
			}
			for name, body := range map[string][]byte{"HTML": html, "Typst": typst} {
				if !bytes.Contains(body, []byte(marker)) || bytes.Contains(body, []byte(falseClaim)) {
					t.Fatalf("%s claims wrong provenance", name)
				}
			}
		})
	}
}

func TestRestoredBrowserCoverageAndRiskRemainDistinct(t *testing.T) {
	for _, language := range []string{"ru", "en"} {
		t.Run(language, func(t *testing.T) {
			ctx, dir, database, db := openReportDB(t)
			in := sampleInput(database, dir)
			in.Language = language
			in.Profile = "verify"
			in.Coverage = map[string]any{"browser_mode": "required", "browser_required": true, "browser_availability": "available", "screenshots_status": "saved", "browser_security_status": "NOT_QUALIFIED", "browser_known_network_risk": "candidate31_preconnect_security_failure"}
			in.ConfirmedWebTargets = []ConfirmedWebTarget{{Domain: "example.org", InputTarget: true}}
			url := "https://example.org/"
			insertEvent(t, ctx, db, "http", "html_analyzed", "http", url, map[string]any{"target_domain": "example.org", "browser_dom": false})
			insertEvent(t, ctx, db, "dom", "html_analyzed", "obscura", url, map[string]any{"target_domain": "example.org", "browser_dom": true, "screenshot_expected": true})
			insertEvent(t, ctx, db, "shot", "screenshot_saved", "obscura", "artifacts/screenshots/example.png", map[string]any{"target_domain": "example.org", "url": url})
			insertEvent(t, ctx, db, "status", "web_target_status", "browser", "example.org", map[string]any{"stage": "browser", "status": "loaded", "screenshot_status": "saved", "page_loaded": true})
			report, csv, err := Load(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			row := asObject(asList(report["web_coverage"])[0])
			summary := asObject(report["summary"])
			if row["pages_loaded"] != 1 || row["screenshot_complete"] != true || summary["web_targets_loaded"] != 1 || summary["browser_security_status"] != "NOT_QUALIFIED" {
				t.Fatalf("wrong functional/security coverage: %#v %#v", row, summary)
			}
			for _, full := range []bool{false, true} {
				in.FullReport = full
				view, err := makeHumanView(ctx, in, report, filepath.Join(dir, "stage"), csv)
				if err != nil {
					t.Fatal(err)
				}
				html, err := renderHTML(view)
				if err != nil {
					t.Fatal(err)
				}
				typst, err := renderTypst(view)
				if err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string][]byte{"html": html, "typst": typst} {
					if !bytes.Contains(body, []byte("candidate31")) {
						t.Fatalf("%s lost known risk", name)
					}
					if bytes.Contains(body, []byte("candidate31_preconnect_security_failure")) {
						t.Fatalf("%s leaked raw reason", name)
					}
				}
			}
		})
	}
}

func TestRestoredScreenshotCoverageDoesNotHideMissingOutput(t *testing.T) {
	ctx, dir, database, db := openReportDB(t)
	in := sampleInput(database, dir)
	in.Profile = "verify"
	in.Coverage = map[string]any{"browser_mode": "enabled", "screenshots_status": "failed"}
	in.ConfirmedWebTargets = []ConfirmedWebTarget{{Domain: "example.org", InputTarget: true}}
	insertEvent(t, ctx, db, "dom", "html_analyzed", "obscura", "https://example.org/", map[string]any{"target_domain": "example.org", "browser_dom": true, "screenshot_expected": true})
	report, _, err := Load(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if asObject(report["summary"])["screenshot_coverage_complete"] != false {
		t.Fatal("missing screenshot reported complete")
	}
}
