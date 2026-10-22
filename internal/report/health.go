package report

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"asmtool/internal/backends"
	"asmtool/internal/storage"
)

type healthState struct {
	items     map[string]bool
	errors    []string
	temporary bool
	telemetry map[string]any
}

func reportInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case interface{ String() string }:
		var n int
		_, _ = fmt.Sscan(x.String(), &n)
		return n
	default:
		return 0
	}
}

func sourceHealth(ctx context.Context, db *sql.DB, in Input) ([]any, error) {
	order := []string{"crt.sh", "certspotter", "crt.name", "thc", "dns", "team_cymru_dns", "shodan_internetdb"}
	labels := map[string]string{"crt.sh": "Certificate Transparency: crt.sh", "certspotter": "Certificate Transparency: Cert Spotter", "crt.name": "Certificate Transparency index: crt.name", "thc": "THC passive source", "dns": "Public DNS correlation", "team_cymru_dns": "ASN/CIDR: Team Cymru DNS", "shodan_internetdb": "Passive port inventory: InternetDB"}
	enabled := map[string]bool{
		"crt.sh":            in.Modules["subdomains"] == true && in.CollectionPolicy["crtsh_enabled"] == true,
		"certspotter":       in.Modules["subdomains"] == true && in.CollectionPolicy["certspotter_enabled"] == true,
		"crt.name":          in.Modules["subdomains"] == true && in.CollectionPolicy["crt_name_enabled"] == true,
		"thc":               in.Modules["subdomains"] == true && in.CollectionPolicy["thc_enabled"] == true,
		"dns":               in.Modules["domain_expansion"] == true,
		"team_cymru_dns":    in.Modules["domain_expansion"] == true,
		"shodan_internetdb": in.Modules["port_scan"] == true && in.CollectionPolicy["internetdb_enabled"] == true,
	}
	states := map[string]*healthState{}
	for _, name := range order {
		states[name] = &healthState{items: map[string]bool{}}
	}
	events, err := storage.IterEvents(ctx, db, nil)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if err := backends.ValidateEvent(event); err != nil {
			return nil, fmt.Errorf("persisted event %s: %w", str(event["event_id"]), err)
		}
		meta := asObject(event["metadata"])
		if event["event_type"] == "limitation" {
			state := states[str(event["source_tool"])]
			if state == nil || meta["source_status"] == "no_results" || (meta["severity"] == "info" && meta["known_startup_network_risk"] == true) {
				continue
			}
			if meta["source_status"] == "temporary_failure" {
				state.temporary = true
			}
			message := str(event["raw_value"])
			if message == "" {
				message = "source unavailable"
			}
			state.errors = append(state.errors, message)
			continue
		}
		names := map[string]bool{}
		for _, raw := range asList(meta["sources"]) {
			if name := str(raw); name != "" {
				names[name] = true
			}
		}
		if name := str(meta["provider"]); name != "" {
			names[name] = true
		}
		for _, name := range strings.Split(str(event["source_tool"]), "+") {
			if name != "" {
				names[name] = true
			}
		}
		for name := range names {
			if state := states[name]; state != nil {
				if event["event_type"] == "source_health" {
					state.telemetry = meta
				} else {
					state.items[reportString(event["normalized_value"])] = true
				}
			}
		}
	}
	out := make([]any, 0, len(order))
	for _, name := range order {
		state := states[name]
		telemetry := state.telemetry
		if telemetry == nil {
			telemetry = map[string]any{}
		}
		count := len(state.items)
		if n := reportInt(telemetry["accepted_in_scope"]); n > count {
			count = n
		}
		if n := reportInt(telemetry["returned_total"]); n > count {
			count = n
		}
		status := "no_results"
		providerStatus := str(telemetry["status"])
		switch {
		case !enabled[name]:
			status = "not_used"
			count = 0
			telemetry = map[string]any{}
		case telemetry["cache_stale"] == true && telemetry["fallback_after_error"] != nil && telemetry["fallback_after_error"] != "":
			status = "partial"
		case providerStatus == "ok" || providerStatus == "fallback_not_needed":
			if count > 0 {
				status = "ok"
			}
		case providerStatus == "no_data" || providerStatus == "skipped":
			status = "no_results"
		case providerStatus == "security_blocked":
			status = "security_blocked"
		case providerStatus == "timeout" || providerStatus == "rate_limited" || providerStatus == "temporary_failure":
			status = "temporary_failure"
		case providerStatus == "failed" || providerStatus == "unavailable" || providerStatus == "error":
			if count > 0 {
				status = "partial"
			} else {
				status = "unavailable"
			}
		case count > 0 && len(state.errors) > 0:
			status = "partial"
		case count > 0:
			status = "ok"
		case len(state.errors) > 0 && state.temporary:
			status = "temporary_failure"
		case len(state.errors) > 0:
			status = "unavailable"
		}
		message := "The source completed without additional data."
		switch status {
		case "not_used":
			message = "Source disabled by configuration."
		case "ok":
			message = fmt.Sprintf("Items retrieved: %d.", count)
		case "partial":
			message = fmt.Sprintf("Items retrieved: %d; source coverage is partial.", count)
		case "temporary_failure":
			message = "The source was temporarily unavailable; retries and available alternatives were used."
		case "unavailable":
			message = "The source did not respond or failed; available alternatives were used."
		case "security_blocked":
			message = "The source was blocked by network safety policy before process creation."
		}
		technical := telemetry["technical_error"]
		if technical == nil {
			technical = telemetry["fallback_after_error"]
		}
		if technical != nil && reportString(technical) != "" {
			state.errors = append([]string{reportString(technical)}, state.errors...)
		}
		errors := []any{}
		seen := map[string]bool{}
		for _, e := range state.errors {
			if !seen[e] && len(errors) < 3 {
				errors = append(errors, e)
				seen[e] = true
			}
		}
		httpStatus := telemetry["last_http_status"]
		if httpStatus == nil {
			httpStatus = telemetry["status_code"]
		}
		provider := telemetry["provider"]
		if provider == nil || provider == "" {
			provider = name
		}
		row := map[string]any{"source": name, "label": labels[name], "status": status, "items": count,
			"message": message, "errors": errors, "optional": false, "collector": telemetry["collector"], "provider": provider,
			"http_attempts": telemetry["http_attempts"], "http_logical_requests": telemetry["http_logical_requests"], "last_http_status": httpStatus,
			"error_type": telemetry["error_type"], "timeout_phase": telemetry["timeout_phase"], "cache_hit": telemetry["cache_hit"] == true,
			"cache_stale": telemetry["cache_stale"] == true, "cache_age_seconds": telemetry["cache_age_seconds"],
			"fallback_after_error": telemetry["fallback_after_error"], "technical_error": telemetry["technical_error"]}
		for _, key := range []string{"known_startup_network_risk", "known_startup_network_risk_detail"} {
			if v, ok := telemetry[key]; ok {
				row[key] = v
			}
		}
		out = append(out, row)
	}
	return out, nil
}
