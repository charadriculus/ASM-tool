package dns

import (
	"context"
	"fmt"

	"asmtool/internal/core"
)

// QuickValidationResult is the caller-facing projection used by streaming DNS
// admission. Map preserves the legacy validate_domain_quick result keys.
type QuickValidationResult struct {
	Domain               string
	Validated            bool
	Eligible             bool
	ActiveEligibility    string
	DNSState             string
	Records              []map[string]any
	IPs                  []string
	Reused               bool
	Error                string
	ParentZone           *string
	WildcardParentState  *string
	includeResumeDetails bool
}

func (r QuickValidationResult) Map() map[string]any {
	out := map[string]any{"domain": r.Domain, "validated": r.Validated, "eligible": r.Eligible, "records": r.Records, "ips": r.IPs, "dns_state": r.DNSState}
	if r.Error != "" {
		out["error"] = r.Error
	}
	if r.ActiveEligibility != "" {
		out["active_eligibility"] = r.ActiveEligibility
	}
	if r.Reused {
		out["reused"] = true
	}
	if r.includeResumeDetails {
		out["parent_zone"] = quickOptionalString(r.ParentZone)
		out["wildcard_parent_state"] = quickOptionalString(r.WildcardParentState)
	}
	return out
}

func quickOptionalString(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

// ValidateQuick performs the wildcard-aware DNS check consumed by streaming
// candidate admission. It reuses the existing validation, event and index paths.
func ValidateQuick(ctx context.Context, c ExpansionConfig, analyzer *WildcardAnalyzer, rawName string) (QuickValidationResult, error) {
	if err := ctx.Err(); err != nil {
		return QuickValidationResult{}, err
	}
	name, err := core.NormalizeDomain(rawName)
	if err != nil {
		return QuickValidationResult{Domain: rawName, DNSState: "dns_error", Error: err.Error(), Records: []map[string]any{}, IPs: []string{}}, nil
	}
	scope := core.ScopeChecker{Policy: c.Policy}
	if scope.CheckDomain(name).Status != core.InScope {
		return QuickValidationResult{Domain: name, DNSState: "out_of_scope", Error: "out_of_scope", Records: []map[string]any{}, IPs: []string{}}, nil
	}
	if c.Index != nil {
		if existing := c.Index.ExistingValidation(name); existing != nil {
			ips := quickStringList(existing["terminal_ips"])
			eligibility := quickString(existing["active_eligibility"])
			out := QuickValidationResult{
				Domain: name, Validated: len(ips) > 0, Eligible: eligibility == "eligible" || eligibility == "eligible_override",
				ActiveEligibility: eligibility, DNSState: quickString(existing["dns_state"]),
				Records: quickMapList(existing["validation_records"]), IPs: ips, Reused: true,
			}
			return out, ctx.Err()
		}
	}
	root, err := core.NormalizeDomain(c.Root)
	if err != nil {
		return QuickValidationResult{}, err
	}
	if c.Client == nil {
		return QuickValidationResult{}, fmt.Errorf("DNS client is required")
	}
	if c.Index == nil {
		return QuickValidationResult{}, fmt.Errorf("DNS evidence index is required")
	}
	if c.Emit == nil {
		return QuickValidationResult{}, fmt.Errorf("DNS event sink is required")
	}
	if analyzer == nil {
		parents := PrioritizedParents([]string{name}, root, c.WildcardParentBudget)
		analyzer, err = NewWildcardAnalyzer(root, c.Client, c.WildcardProbes, c.WildcardParentBudget, c.WildcardEnabled, parents)
		if err != nil {
			return QuickValidationResult{}, err
		}
	} else if name != root {
		if err := analyzer.AllowParent(immediateParent(name, root)); err != nil {
			return QuickValidationResult{}, err
		}
	}
	r, err := validateOne(ctx, c, scope, analyzer, root, name)
	if err != nil {
		return QuickValidationResult{Domain: name, DNSState: "cancelled", Records: validationRecords(r), IPs: r.IPs}, err
	}
	state, parent, err := analyzer.Classify(ctx, name, r, name == root)
	if err != nil {
		return QuickValidationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return QuickValidationResult{}, err
	}
	eligibility := ActiveEligibility(state, r, name == root, c.IncludeWildcardAmbiguous)
	out := QuickValidationResult{
		Domain: name, Validated: len(r.IPs) > 0, Eligible: eligibility == "eligible" || eligibility == "eligible_override",
		ActiveEligibility: eligibility, DNSState: state, Records: validationRecords(r), IPs: quickStringList(r.IPs), includeResumeDetails: true,
	}
	if parent != nil {
		out.ParentZone, out.WildcardParentState = &parent.Parent, &parent.State
	}
	return out, nil
}

func quickString(v any) string { s, _ := v.(string); return s }

func quickStringList(v any) []string {
	switch x := v.(type) {
	case []string:
		if x == nil {
			return []string{}
		}
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

func quickMapList(v any) []map[string]any {
	switch x := v.(type) {
	case []map[string]any:
		return append([]map[string]any(nil), x...)
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}
