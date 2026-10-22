package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"asmtool/internal/backends"
	"asmtool/internal/storage"
)

// ConfirmedWebTarget is the persisted run's eligible target plan supplied by
// its caller. Results alone cannot reconstruct targets that were never tried.
type ConfirmedWebTarget struct {
	Domain      string
	InputTarget bool
	DNSEvidence []string
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func webCoverage(ctx context.Context, db *sql.DB, profile, root string, targets []ConfirmedWebTarget, global map[string]any) ([]any, error) {
	events, err := storage.IterEvents(ctx, db, []string{"web_target_status", "html_analyzed", "crawler_result", "screenshot_saved"})
	if err != nil {
		return nil, err
	}
	type state struct {
		row                                         map[string]any
		direct, crawler, screenshots, expectedShots map[string]bool
	}
	coverage := map[string]*state{}
	for _, target := range targets {
		if target.Domain == "" {
			return nil, errors.New("empty confirmed web target")
		}
		if _, exists := coverage[target.Domain]; exists {
			return nil, errors.New("duplicate confirmed web target")
		}
		crawl := "not_started"
		if profile != "full" {
			crawl = "not_applicable"
		}
		coverage[target.Domain] = &state{row: map[string]any{"domain": target.Domain, "input_target": target.InputTarget,
			"dns_evidence": append([]string{}, target.DNSEvidence...), "root_status": "not_attempted", "crawl_status": crawl,
			"requested_url": nil, "final_url": nil, "http_status": nil, "root_page_loaded": false, "reason": nil},
			direct: map[string]bool{}, crawler: map[string]bool{}, screenshots: map[string]bool{}, expectedShots: map[string]bool{}}
	}
	for _, event := range events {
		if err := backends.ValidateEvent(event); err != nil {
			return nil, fmt.Errorf("persisted coverage event %s: %w", str(event["event_id"]), err)
		}
		meta := asObject(event["metadata"])
		name := str(event["normalized_value"])
		switch event["event_type"] {
		case "web_target_status":
			row := coverage[name]
			if row == nil {
				continue
			}
			switch meta["stage"] {
			case "root_verification":
				status := str(meta["status"])
				if status == "" {
					status = "unknown"
				}
				row.row["root_status"] = status
				row.row["requested_url"], row.row["final_url"], row.row["http_status"], row.row["reason"] = meta["requested_url"], meta["final_url"], meta["status_code"], meta["reason"]
				loaded, ok := meta["page_loaded"].(bool)
				if !ok {
					loaded = status == "loaded" || status == "blocked_response"
				}
				row.row["root_page_loaded"] = loaded
			case "browser":
				if status := str(meta["status"]); status != "" {
					row.row["browser_status"] = status
				}
				if status := str(meta["screenshot_status"]); status != "" {
					row.row["screenshot_status"] = status
				}
				if reason := str(meta["reason"]); reason != "" {
					row.row["reason"] = reason
				}
			case "crawl":
				status := str(meta["status"])
				if status == "" {
					status = "unknown"
				}
				row.row["crawl_status"] = status
				if meta["reason"] != nil {
					row.row["reason"] = meta["reason"]
				}
			}
		case "html_analyzed":
			if row := coverage[str(meta["target_domain"])]; row != nil && name != "" {
				row.direct[name] = true
				if meta["browser_dom"] == true {
					row.row["browser_page_loaded"] = true
					if meta["screenshot_expected"] == true {
						row.expectedShots[name] = true
					}
				}
			}
		case "crawler_result":
			if meta["page_loaded"] == false {
				continue
			}
			for _, domain := range asList(meta["target_domains"]) {
				if row := coverage[str(domain)]; row != nil && name != "" {
					row.crawler[name] = true
				}
			}
		case "screenshot_saved":
			domains := asList(meta["target_domains"])
			if domains == nil && str(meta["target_domain"]) != "" {
				domains = []any{meta["target_domain"]}
			}
			url := str(meta["url"])
			if url == "" {
				url = name
			}
			for _, domain := range domains {
				if row := coverage[str(domain)]; row != nil && url != "" {
					row.screenshots[url] = true
				}
			}
		}
	}
	names := make([]string, 0, len(coverage))
	for name := range coverage {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == root {
			return true
		}
		if names[j] == root {
			return false
		}
		return names[i] < names[j]
	})
	out := make([]any, 0, len(names))
	for _, name := range names {
		s := coverage[name]
		if mode := str(global["browser_mode"]); mode != "" {
			if s.row["browser_status"] == nil {
				if mode == "blocked" {
					s.row["browser_status"] = "security_blocked"
				} else if mode == "disabled" {
					s.row["browser_status"] = "disabled_by_policy"
				} else {
					s.row["browser_status"] = "not_attempted"
				}
			}
			if s.row["screenshot_status"] == nil {
				s.row["screenshot_status"] = global["screenshots_status"]
			}
			if s.row["reason"] == nil && mode == "blocked" {
				s.row["reason"] = "candidate31_preconnect_security_failure"
			}
		}
		direct, crawler, screenshots := sortedKeys(s.direct), sortedKeys(s.crawler), sortedKeys(s.screenshots)
		directCount := len(direct)
		if directCount == 0 && s.row["root_page_loaded"] == true {
			directCount = 1
		}
		pages := directCount + len(crawler)
		activeBrowser := global["browser_mode"] == "enabled" || global["browser_mode"] == "required"
		if activeBrowser {
			unique := map[string]bool{}
			for url := range s.direct {
				unique[url] = true
			}
			for url := range s.crawler {
				unique[url] = true
			}
			pages = len(unique)
			if pages == 0 && s.row["root_page_loaded"] == true {
				pages = 1
			}
		}
		s.row["direct_urls"], s.row["crawler_pages"], s.row["pages_loaded"] = direct, len(crawler), pages
		complete := pages == len(screenshots)
		if activeBrowser {
			complete = len(s.expectedShots) > 0
			for url := range s.expectedShots {
				if !s.screenshots[url] {
					complete = false
				}
			}
			if s.row["screenshot_status"] == "failed" || s.row["browser_status"] == "failed" {
				complete = false
			}
		}
		if s.row["screenshot_status"] == "not_requested" || s.row["screenshot_status"] == "disabled_by_config" {
			complete = true
		}
		if s.row["screenshot_status"] == "security_blocked" {
			complete = false
		}
		s.row["screenshot_urls"], s.row["screenshots"], s.row["screenshot_complete"] = screenshots, len(screenshots), complete
		out = append(out, s.row)
	}
	return out, nil
}
