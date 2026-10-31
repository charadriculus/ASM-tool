package backends

type BackendDescriptor struct {
	Category       string `json:"category"`
	Name           string `json:"name"`
	Implementation string `json:"implementation"`
	Language       string `json:"language"`
	ExecutionMode  string `json:"execution_mode"`
	PinnedVersion  string `json:"pinned_version,omitempty"`
}
type BackendResolution struct {
	Category                      string `json:"category"`
	Requested                     string `json:"requested"`
	Actual                        string `json:"actual"`
	Status                        string `json:"status"`
	Available                     bool   `json:"available"`
	ActualVersion                 string `json:"actual_version,omitempty"`
	PinnedVersion                 string `json:"pinned_version,omitempty"`
	ComponentSHA256               string `json:"component_sha256,omitempty"`
	VersionEvidenceStatus         string `json:"version_evidence_status"`
	KnownStartupNetworkRisk       bool   `json:"known_startup_network_risk,omitempty"`
	KnownStartupNetworkRiskDetail string `json:"known_startup_network_risk_detail,omitempty"`
	Implementation                string `json:"implementation"`
	Language                      string `json:"language"`
	ExecutionMode                 string `json:"execution_mode"`
	FallbackUsed                  bool   `json:"fallback_used"`
	FallbackReason                string `json:"fallback_reason,omitempty"`
	Error                         string `json:"error,omitempty"`
}
