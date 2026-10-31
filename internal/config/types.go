package config

type RateLimits struct {
	PassiveSourceRequestsPerSecond   float64 `json:"passive_source_requests_per_second" yaml:"passive_source_requests_per_second"`
	DNSQueriesPerSecond              float64 `json:"dns_queries_per_second" yaml:"dns_queries_per_second"`
	DNSWorkerCount                   int     `json:"dns_worker_count" yaml:"dns_worker_count"`
	HTTPDelaySeconds                 float64 `json:"http_delay_seconds" yaml:"http_delay_seconds"`
	HTTPMaxRequestsPerHost           int     `json:"http_max_requests_per_host" yaml:"http_max_requests_per_host"`
	CrawlerMaxPagesPerOrigin         int     `json:"crawler_max_pages_per_origin" yaml:"crawler_max_pages_per_origin"`
	CrawlerMaxTotalPages             int     `json:"crawler_max_total_pages" yaml:"crawler_max_total_pages"`
	CrawlerMaxDepth                  int     `json:"crawler_max_depth" yaml:"crawler_max_depth"`
	ExternalJSMaxFiles               int     `json:"external_js_max_files" yaml:"external_js_max_files"`
	TCPMaxConcurrency                int     `json:"tcp_max_concurrency" yaml:"tcp_max_concurrency"`
	TCPMaxRate                       int     `json:"tcp_max_rate" yaml:"tcp_max_rate"`
	TCPMaxTargets                    int     `json:"tcp_max_targets" yaml:"tcp_max_targets"`
	TCPConnectTimeoutSeconds         float64 `json:"tcp_connect_timeout_seconds" yaml:"tcp_connect_timeout_seconds"`
	GlobalMaxRequestsPerSecond       float64 `json:"global_max_requests_per_second" yaml:"global_max_requests_per_second"`
	HTTPMaxConcurrency               int     `json:"http_max_concurrency" yaml:"http_max_concurrency"`
	HTTPMaxConcurrencyPerOrigin      int     `json:"http_max_concurrency_per_origin" yaml:"http_max_concurrency_per_origin"`
	HTTPStartIntervalSeconds         float64 `json:"http_start_interval_seconds" yaml:"http_start_interval_seconds"`
	BrowserNavigationTimeoutSeconds  float64 `json:"browser_navigation_timeout_seconds" yaml:"browser_navigation_timeout_seconds"`
	BrowserScreenshotTimeoutSeconds  float64 `json:"browser_screenshot_timeout_seconds" yaml:"browser_screenshot_timeout_seconds"`
	BrowserTargetTotalTimeoutSeconds float64 `json:"browser_target_total_timeout_seconds" yaml:"browser_target_total_timeout_seconds"`
	BrowserDomSettleMilliseconds     int     `json:"browser_dom_settle_milliseconds" yaml:"browser_dom_settle_milliseconds"`
	ScreenshotMaxConcurrency         int     `json:"screenshot_max_concurrency" yaml:"screenshot_max_concurrency"`
}

type CollectionPolicy struct {
	PassiveProviderProfile         string  `json:"passive_provider_profile" yaml:"passive_provider_profile"`
	PassiveInventorySafetyCap      int     `json:"passive_inventory_safety_cap" yaml:"passive_inventory_safety_cap"`
	DNSCandidateBudget             int     `json:"dns_candidate_budget" yaml:"dns_candidate_budget"`
	PassiveMaxIPs                  int     `json:"passive_max_ips" yaml:"passive_max_ips"`
	InternetdbEnabled              bool    `json:"internetdb_enabled" yaml:"internetdb_enabled"`
	CRTNameEnabled                 bool    `json:"crt_name_enabled" yaml:"crt_name_enabled"`
	THCEnabled                     bool    `json:"thc_enabled" yaml:"thc_enabled"`
	SubMDFallbackEnabled           bool    `json:"submd_fallback_enabled" yaml:"submd_fallback_enabled"`
	CRTShEnabled                   bool    `json:"crtsh_enabled" yaml:"crtsh_enabled"`
	CertspotterEnabled             bool    `json:"certspotter_enabled" yaml:"certspotter_enabled"`
	PassiveSourceRetries           int     `json:"passive_source_retries" yaml:"passive_source_retries"`
	PassiveCacheTTLHours           int     `json:"passive_cache_ttl_hours" yaml:"passive_cache_ttl_hours"`
	PassiveConnectTimeoutSeconds   float64 `json:"passive_connect_timeout_seconds" yaml:"passive_connect_timeout_seconds"`
	PassiveReadTimeoutSeconds      float64 `json:"passive_read_timeout_seconds" yaml:"passive_read_timeout_seconds"`
	CRTNameConnectTimeoutSeconds   float64 `json:"crt_name_connect_timeout_seconds" yaml:"crt_name_connect_timeout_seconds"`
	CRTNameReadTimeoutSeconds      float64 `json:"crt_name_read_timeout_seconds" yaml:"crt_name_read_timeout_seconds"`
	WildcardEnabled                bool    `json:"wildcard_enabled" yaml:"wildcard_enabled"`
	WildcardProbesPerParent        int     `json:"wildcard_probes_per_parent" yaml:"wildcard_probes_per_parent"`
	WildcardMaxParentZones         int     `json:"wildcard_max_parent_zones" yaml:"wildcard_max_parent_zones"`
	WildcardMinCandidatesPerParent int     `json:"wildcard_min_candidates_per_parent" yaml:"wildcard_min_candidates_per_parent"`
	IncludeWildcardAmbiguousActive bool    `json:"include_wildcard_ambiguous_active" yaml:"include_wildcard_ambiguous_active"`
	StopOnHTTPStatuses             []int   `json:"stop_on_http_statuses" yaml:"stop_on_http_statuses"`
	ObeyRobots                     bool    `json:"obey_robots" yaml:"obey_robots"`
	FollowMetaNofollow             bool    `json:"follow_meta_nofollow" yaml:"follow_meta_nofollow"`
	BlockOutOfScopeBrowserRequests bool    `json:"block_out_of_scope_browser_requests" yaml:"block_out_of_scope_browser_requests"`
	WebPrimaryDomainOnly           bool    `json:"web_primary_domain_only" yaml:"web_primary_domain_only"`
	StreamingPipelineEnabled       bool    `json:"streaming_pipeline_enabled" yaml:"streaming_pipeline_enabled"`
	DynamicDiscoveryFromHTML       bool    `json:"dynamic_discovery_from_html" yaml:"dynamic_discovery_from_html"`
	DynamicDiscoveryMaxRounds      int     `json:"dynamic_discovery_max_rounds" yaml:"dynamic_discovery_max_rounds"`
	DynamicDiscoveryMaxNewDomains  int     `json:"dynamic_discovery_max_new_domains" yaml:"dynamic_discovery_max_new_domains"`
	HTTPFallbackAfterTimeout       bool    `json:"http_fallback_after_timeout" yaml:"http_fallback_after_timeout"`
}

type Modules struct {
	Subdomains      bool `json:"subdomains" yaml:"subdomains"`
	DomainExpansion bool `json:"domain_expansion" yaml:"domain_expansion"`
	PortScan        bool `json:"port_scan" yaml:"port_scan"`
	Masscan         bool `json:"masscan" yaml:"masscan"`
	WebProbe        bool `json:"web_probe" yaml:"web_probe"`
	Crawler         bool `json:"crawler" yaml:"crawler"`
	Screenshots     bool `json:"screenshots" yaml:"screenshots"`
	PDFReport       bool `json:"pdf_report" yaml:"pdf_report"`
}

type ReportingConfig struct {
	Language          string `json:"language" yaml:"language"`
	FullReport        bool   `json:"full_report" yaml:"full_report"`
	DomainRows        int    `json:"domain_rows" yaml:"domain_rows"`
	IPRows            int    `json:"ip_rows" yaml:"ip_rows"`
	RoutingRows       int    `json:"routing_rows" yaml:"routing_rows"`
	RelatedDomainRows int    `json:"related_domain_rows" yaml:"related_domain_rows"`
	PortRows          int    `json:"port_rows" yaml:"port_rows"`
	WebCoverageRows   int    `json:"web_coverage_rows" yaml:"web_coverage_rows"`
	WebRows           int    `json:"web_rows" yaml:"web_rows"`
	DocumentRows      int    `json:"document_rows" yaml:"document_rows"`
	ScreenshotRows    int    `json:"screenshot_rows" yaml:"screenshot_rows"`
}

type BackendsConfig struct {
	SerializationBackend           string `json:"serialization_backend" yaml:"serialization_backend"`
	SchemaBackend                  string `json:"schema_backend" yaml:"schema_backend"`
	PDFBackend                     string `json:"pdf_backend" yaml:"pdf_backend"`
	HTMLParserBackend              string `json:"html_parser_backend" yaml:"html_parser_backend"`
	DNSBackend                     string `json:"dns_backend" yaml:"dns_backend"`
	HTTPProbeBackend               string `json:"http_probe_backend" yaml:"http_probe_backend"`
	CrawlerBackend                 string `json:"crawler_backend" yaml:"crawler_backend"`
	FallbackPolicy                 string `json:"fallback_policy" yaml:"fallback_policy"`
	RecordProvenance               bool   `json:"record_provenance" yaml:"record_provenance"`
	RecordMetrics                  bool   `json:"record_metrics" yaml:"record_metrics"`
	NativeSubprocessTimeoutSeconds int    `json:"native_subprocess_timeout_seconds" yaml:"native_subprocess_timeout_seconds"`
	fallbackPolicyExplicit         bool
}

// HTTPFallbackAllowed reports a supplied, validated YAML opt-in. The
// compatibility default "explicit" alone does not authorize a backend switch.
func (b BackendsConfig) HTTPFallbackAllowed() bool {
	return b.fallbackPolicyExplicit && b.FallbackPolicy == "explicit"
}

// Operational defaults are copied from the immutable source; backend names are requests only.
func defaultSections() (RateLimits, CollectionPolicy, Modules, ReportingConfig, BackendsConfig) {
	return RateLimits{PassiveSourceRequestsPerSecond: 1.0, DNSQueriesPerSecond: 4.0, DNSWorkerCount: 8, HTTPDelaySeconds: 2.0, HTTPMaxRequestsPerHost: 6, CrawlerMaxPagesPerOrigin: 6, CrawlerMaxTotalPages: 150, CrawlerMaxDepth: 1, ExternalJSMaxFiles: 2, TCPMaxConcurrency: 1, TCPMaxRate: 10, TCPMaxTargets: 500, TCPConnectTimeoutSeconds: 10, GlobalMaxRequestsPerSecond: 1.0, HTTPMaxConcurrency: 2, HTTPMaxConcurrencyPerOrigin: 1, HTTPStartIntervalSeconds: 2.0, BrowserNavigationTimeoutSeconds: 10.0, BrowserScreenshotTimeoutSeconds: 10.0, BrowserTargetTotalTimeoutSeconds: 20.0, BrowserDomSettleMilliseconds: 500, ScreenshotMaxConcurrency: 1},
		CollectionPolicy{PassiveProviderProfile: "standard", PassiveInventorySafetyCap: 250000, DNSCandidateBudget: 1000, PassiveMaxIPs: 100, InternetdbEnabled: true, CRTNameEnabled: true, THCEnabled: true, SubMDFallbackEnabled: true, CRTShEnabled: true, CertspotterEnabled: true, PassiveSourceRetries: 3, PassiveCacheTTLHours: 24, PassiveConnectTimeoutSeconds: 10.0, PassiveReadTimeoutSeconds: 45.0, CRTNameConnectTimeoutSeconds: 10.0, CRTNameReadTimeoutSeconds: 300.0, WildcardEnabled: true, WildcardProbesPerParent: 3, WildcardMaxParentZones: 2000, WildcardMinCandidatesPerParent: 1, IncludeWildcardAmbiguousActive: false, StopOnHTTPStatuses: []int{401, 403, 429}, ObeyRobots: true, FollowMetaNofollow: false, BlockOutOfScopeBrowserRequests: true, WebPrimaryDomainOnly: false, StreamingPipelineEnabled: true, DynamicDiscoveryFromHTML: true, DynamicDiscoveryMaxRounds: 2, DynamicDiscoveryMaxNewDomains: 100, HTTPFallbackAfterTimeout: false},
		Modules{Subdomains: true, DomainExpansion: true, PortScan: true, Masscan: false, WebProbe: false, Crawler: false, Screenshots: false, PDFReport: true},
		ReportingConfig{Language: "en", FullReport: false, DomainRows: 200, IPRows: 200, RoutingRows: 50, RelatedDomainRows: 50, PortRows: 100, WebCoverageRows: 100, WebRows: 40, DocumentRows: 50, ScreenshotRows: 30},
		BackendsConfig{SerializationBackend: "orjson", SchemaBackend: "rust_jsonschema", PDFBackend: "typst", HTMLParserBackend: "beautifulsoup", DNSBackend: "python_dnspython", HTTPProbeBackend: "python_requests", CrawlerBackend: "python_crawler", FallbackPolicy: "explicit", RecordProvenance: true, RecordMetrics: true, NativeSubprocessTimeoutSeconds: 120}
}
