package core

import (
	"crypto/rand"
	"fmt"
	"time"
)

type ScopeStatus string

const (
	InScope           ScopeStatus = "in_scope"
	OutOfScope        ScopeStatus = "out_of_scope"
	Excluded          ScopeStatus = "excluded"
	NeedsManualReview ScopeStatus = "needs_manual_review"
)

type ScopeDecision struct {
	Status          ScopeStatus `json:"status"`
	Reason          string      `json:"reason"`
	NormalizedValue string      `json:"normalized_value"`
}
type EventType string

const (
	DomainFound              EventType = "domain_found"
	SubdomainFound           EventType = "subdomain_found"
	DNSRecordFound           EventType = "dns_record_found"
	IPFound                  EventType = "ip_found"
	ASNFound                 EventType = "asn_found"
	CIDRFound                EventType = "cidr_found"
	TLSCertificateFound      EventType = "tls_certificate_found"
	TLSNameFound             EventType = "tls_name_found"
	PortFound                EventType = "port_found"
	PortScanResult           EventType = "port_scan_result"
	WebServiceFound          EventType = "web_service_found"
	WebTargetStatus          EventType = "web_target_status"
	HTTPProbeResult          EventType = "http_probe_result"
	URLFound                 EventType = "url_found"
	HTMLAnalyzed             EventType = "html_analyzed"
	JSEndpointFound          EventType = "js_endpoint_found"
	RobotsRuleFound          EventType = "robots_rule_found"
	RobotsDisallowedURLFound EventType = "robots_disallowed_url_found"
	MetaRobotsFound          EventType = "meta_robots_found"
	ScreenshotSaved          EventType = "screenshot_saved"
	CrawlerResult            EventType = "crawler_result"
	AggressiveCrawlResult    EventType = "aggressive_crawl_result"
	FindingCandidate         EventType = "finding_candidate"
	SourceHealth             EventType = "source_health"
	DNSValidation            EventType = "dns_validation"
	Limitation               EventType = "limitation"
)

type Event struct {
	EventType       EventType        `json:"event_type"`
	Module          string           `json:"module"`
	SourceTool      string           `json:"source_tool"`
	RawValue        any              `json:"raw_value"`
	NormalizedValue any              `json:"normalized_value"`
	ScopeStatus     ScopeStatus      `json:"scope_status"`
	Confidence      float64          `json:"confidence"`
	Evidence        map[string]any   `json:"evidence"`
	Relations       []map[string]any `json:"relations"`
	Metadata        map[string]any   `json:"metadata"`
	ObservedAt      string           `json:"observed_at"`
	ObservedAtLocal string           `json:"observed_at_local"`
	EventID         string           `json:"event_id"`
}

func UTCNow() string   { return time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00") }
func LocalNow() string { return time.Now().Format("2006-01-02T15:04:05.000000-07:00") }
func NewEvent(kind EventType, module, source string, raw, normalized any, status ScopeStatus) (Event, error) {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return Event{}, e
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return Event{EventType: kind, Module: module, SourceTool: source, RawValue: raw, NormalizedValue: normalized, ScopeStatus: status, Confidence: 0.5, Evidence: map[string]any{}, Relations: []map[string]any{}, Metadata: map[string]any{}, ObservedAt: UTCNow(), ObservedAtLocal: LocalNow(), EventID: fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])}, nil
}

type CommandResult struct {
	Args            []string `json:"args"`
	ReturnCode      int      `json:"returncode"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	DurationSeconds float64  `json:"duration_seconds"`
}
