package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"asmtool/internal/core"
)

type RRQuery struct {
	Name       string   `json:"name"`
	RType      string   `json:"rtype"`
	Backend    string   `json:"backend"`
	Status     string   `json:"status"`
	Values     []string `json:"values,omitempty"`
	TTL        *uint32  `json:"ttl,omitempty"`
	Resolver   string   `json:"resolver,omitempty"`
	RCode      string   `json:"rcode,omitempty"`
	Error      string   `json:"error,omitempty"`
	ObservedAt string   `json:"observed_at"`
}

const ResolverBackend = "go_dns_wire/dnsmessage"

type HostResolution struct {
	Hostname               string                `json:"hostname"`
	Queries                []RRQuery             `json:"queries"`
	IPs                    []string              `json:"ips"`
	CNAMEChain             []string              `json:"cname_chain"`
	TerminalName           string                `json:"terminal_name"`
	Resolved               bool                  `json:"resolved"`
	DNSError               bool                  `json:"dns_error"`
	WildcardAnalysis       *WildcardParentResult `json:"-"`
	SystemFallbackIPs      []string              `json:"-"`
	SystemFallbackResolver string                `json:"-"`
}

func (r HostResolution) ToMap() map[string]any {
	b, _ := json.Marshal(r)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	out["signature"] = r.Signature()
	return out
}
func (r HostResolution) Signature() map[string][]string {
	sets := map[string]map[string]bool{"A": {}, "AAAA": {}, "CNAME": {}}
	for _, q := range r.Queries {
		if q.Status == "answer" {
			if set := sets[q.RType]; set != nil {
				for _, v := range q.Values {
					if q.RType == "CNAME" {
						v = strings.TrimSuffix(strings.ToLower(v), ".")
					}
					set[v] = true
				}
			}
		}
	}
	out := map[string][]string{"A": {}, "AAAA": {}, "CNAME": {}}
	for k, set := range sets {
		for v := range set {
			out[k] = append(out[k], v)
		}
		sort.Strings(out[k])
	}
	return out
}
func queryRR(ctx context.Context, c *Client, name, typ string) RRQuery {
	q := RRQuery{Name: name, RType: typ, Backend: ResolverBackend, Status: "error", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var t uint16
	switch typ {
	case "A":
		t = 1
	case "CNAME":
		t = 5
	case "SOA":
		t = 6
	case "PTR":
		t = 12
	case "MX":
		t = 15
	case "TXT":
		t = 16
	case "AAAA":
		t = 28
	case "NS":
		t = 2
	default:
		q.Error = "unsupported record type"
		return q
	}
	a, err := c.Query(ctx, name, t)
	if err != nil {
		q.Error = err.Error()
		if ctx.Err() != nil {
			q.Status = "cancelled"
		} else if errors.Is(err, context.DeadlineExceeded) {
			q.Status = "timeout"
		} else {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				q.Status = "timeout"
			}
		}
		return q
	}
	q.Resolver = a.Resolver
	q.RCode = rcodeName(a.RCode)
	if a.RCode == 2 {
		q.Status = "servfail"
		q.Error = "DNS resolver returned SERVFAIL"
		return q
	}
	if a.RCode == 5 {
		q.Status = "refused"
		q.Error = "DNS resolver refused the query"
		return q
	}
	if a.RCode != 0 && a.RCode != 3 {
		q.Status = "error"
		q.Error = "DNS resolver returned " + q.RCode
		return q
	}
	if a.Negative {
		q.Status = "nxdomain"
		return q
	}
	if len(a.Records) == 0 {
		q.Status = "nodata"
		return q
	}
	q.Status = "answer"
	values := map[string]bool{}
	var ttl uint32
	hasTTL := false
	for _, r := range a.Records {
		if r.Type != typ {
			continue
		}
		value := r.Value
		if typ == "CNAME" || typ == "MX" || typ == "NS" || typ == "PTR" {
			if !isASCII(value) {
				continue
			}
			value = strings.TrimSuffix(strings.ToLower(value), ".")
		}
		values[value] = true
		if !hasTTL || r.TTL < ttl {
			ttl = r.TTL
			hasTTL = true
		}
	}
	if len(values) == 0 {
		q.Status = "nodata"
		return q
	}
	for v := range values {
		q.Values = append(q.Values, v)
	}
	sort.Strings(q.Values)
	q.TTL = &ttl
	return q
}

func rcodeName(n uint16) string {
	switch n {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", n)
	}
}
func ResolveHost(ctx context.Context, c *Client, raw string, maxDepth int) (HostResolution, error) {
	if err := ctx.Err(); err != nil {
		return HostResolution{}, err
	}
	name, err := core.NormalizeDomain(raw)
	if err != nil {
		return HostResolution{}, err
	}
	if c == nil {
		return HostResolution{}, fmt.Errorf("DNS client is required")
	}
	if maxDepth < 0 {
		maxDepth = 0
	}
	if maxDepth > 8 {
		maxDepth = 8
	}
	r := HostResolution{Hostname: name, TerminalName: name, Queries: []RRQuery{}, CNAMEChain: []string{}}
	visited := map[string]bool{name: true}
	ips := map[string]bool{}
	hadErr := false
	for depth := 0; depth <= maxDepth; depth++ {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		a := queryRR(ctx, c, r.TerminalName, "A")
		r.Queries = append(r.Queries, a)
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		if a.Status == "nxdomain" {
			break
		}
		if isQueryError(a.Status) {
			hadErr = true
		}
		addIPs(ips, a.Values, 4)
		if a.Status != "nxdomain" {
			q := queryRR(ctx, c, r.TerminalName, "AAAA")
			r.Queries = append(r.Queries, q)
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			if isQueryError(q.Status) {
				hadErr = true
			}
			addIPs(ips, q.Values, 6)
		}
		q := queryRR(ctx, c, r.TerminalName, "CNAME")
		r.Queries = append(r.Queries, q)
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		if isQueryError(q.Status) {
			hadErr = true
		}
		if len(ips) > 0 || len(q.Values) == 0 {
			break
		}
		next, e := core.NormalizeDomain(q.Values[0])
		if e != nil {
			hadErr = true
			break
		}
		if visited[next] {
			r.CNAMEChain = append(r.CNAMEChain, next)
			hadErr = true
			break
		}
		if depth == maxDepth {
			hadErr = true
			break
		}
		r.CNAMEChain = append(r.CNAMEChain, next)
		visited[next] = true
		r.TerminalName = next
	}
	for ip := range ips {
		r.IPs = append(r.IPs, ip)
	}
	sort.Strings(r.IPs)
	r.Resolved = len(r.IPs) > 0
	r.DNSError = hadErr && !r.Resolved
	return r, ctx.Err()
}
func addIPs(dst map[string]bool, values []string, version int) {
	for _, v := range values {
		ip, e := netip.ParseAddr(v)
		if e == nil && ((version == 4 && ip.Is4()) || (version == 6 && ip.Is6())) {
			dst[ip.String()] = true
		}
	}
}
func isQueryError(s string) bool {
	return s == "error" || s == "timeout" || s == "servfail" || s == "refused" || s == "cancelled"
}
func immediateParent(host, root string) string {
	h, e := core.NormalizeDomain(host)
	if e != nil {
		return root
	}
	r, e := core.NormalizeDomain(root)
	if e != nil || h == r {
		return r
	}
	p := strings.SplitN(h, ".", 2)
	if len(p) == 2 && core.DomainMatches(p[1], r) {
		return p[1]
	}
	return r
}

func validationRecords(r HostResolution) []map[string]any {
	out := []map[string]any{}
	for _, q := range r.Queries {
		for _, value := range q.Values {
			out = append(out, map[string]any{"name": q.Name, "type": q.RType, "value": value, "resolver": q.Resolver, "ttl": q.TTL, "rcode": q.RCode, "status": q.Status})
		}
	}
	for _, ip := range r.SystemFallbackIPs {
		out = append(out, map[string]any{"name": r.Hostname, "type": "SYSTEM", "value": ip, "resolver": r.SystemFallbackResolver, "resolver_backend": ResolverBackend, "ttl": nil, "rcode": nil, "status": "answer"})
	}
	return out
}
