package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	activehttp "asmtool/internal/active/http"
	"asmtool/internal/backends"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
)

func TestProbeUsesFinalURLForAnchorDiscoveryAndPersistsResponseContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final/base", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Fixture", "yes")
		_, _ = w.Write([]byte(`<html><head><meta name="robots" content="noindex,nofollow"><title>ready</title></head><body><!-- observed --><a href="https://deep.example.test/child">child</a><script>fetch('https://js.example.test/endpoint')</script></body></html>`))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	idx := evidence.NewDNSRunIndex(policy)
	idx.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	var events []core.Event
	client, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: idx, Emit: func(e core.Event) error { events = append(events, e); return nil }, UserAgent: "fixture", PerHostRequests: 5, GlobalConcurrency: 2, PerOriginConcurrency: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Domain: "example.test", TerminalIPs: []string{"127.0.0.1"}}
	result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(e core.Event) error { events = append(events, e); return nil }, TLS: activehttp.VerifiedTLS, MaxRedirects: 2}, target, "http://example.test:"+port+"/start")
	if err != nil {
		t.Fatal(err)
	}
	if result.HTTP.FinalURL != "http://example.test:"+port+"/final/base" {
		t.Fatalf("final URL: %s", result.HTTP.FinalURL)
	}
	if len(result.DiscoveredDomains) != 1 || result.DiscoveredDomains[0] != "deep.example.test" {
		t.Fatalf("active candidates must come from final-page anchors only: %v", result.DiscoveredDomains)
	}
	var html, meta, link bool
	for _, event := range events {
		switch event.EventType {
		case core.HTMLAnalyzed:
			bodySum, htmlSum := sha256.Sum256(result.HTTP.Body), sha256.Sum256([]byte(result.HTTP.Text))
			html = event.Confidence == 0.9 && event.Metadata["status_code"] == http.StatusOK && event.Metadata["content_type"] != "" && event.Metadata["body_sha256"] == hex.EncodeToString(bodySum[:]) && event.Metadata["html_sha256"] == hex.EncodeToString(htmlSum[:]) && event.Metadata["content_length"] != nil && event.Metadata["body_truncated"] == false && event.Metadata["partial"] == false && event.Metadata["browser_dom"] == false && event.Metadata["requested_url"] == "http://example.test:"+port+"/start" && event.Metadata["final_url"] == result.HTTP.FinalURL && event.Metadata["depth"] == 0 && event.Metadata["screenshot_saved"] == false && event.Metadata["observation_type"] == "active_low_noise_validation" && strings.Contains(event.Metadata["limitation"].(string), "phase 6") && len(event.Metadata["comments"].([]string)) == 1
		case core.MetaRobotsFound:
			meta = event.Confidence == 0.8 && event.Metadata["content"] == "noindex,nofollow" && event.Metadata["browser_dom"] == false
		case core.URLFound:
			link = event.Confidence == 0.6 && strings.Contains(event.NormalizedValue.(string), "deep.example.test/child") && event.Metadata["source_url"] == result.HTTP.FinalURL
		case core.JSEndpointFound:
			if event.Confidence != 0.35 {
				t.Errorf("JS endpoint confidence=%v want 0.35", event.Confidence)
			}
		case core.WebTargetStatus:
			if event.Confidence != 0.9 || event.Metadata["partial"] != false {
				t.Errorf("web status projection: confidence=%v metadata=%+v", event.Confidence, event.Metadata)
			}
		}
	}
	if !html || !meta || !link {
		t.Fatalf("missing response provenance events: html=%v meta=%v link=%v events=%+v", html, meta, link, events)
	}
}

func TestProbeMarksActualBodyCapAsPartial(t *testing.T) {
	body := `<a href="https://deep.example.test/before">before</a>` + strings.Repeat("x", activehttp.MaxResponseBytes) + `<a href="https://deep.example.test/after">after</a>`
	client, _, policy, targetURL := probeFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
	var htmlEvent, statusEvent core.Event
	result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(e core.Event) error {
		if e.EventType == core.HTMLAnalyzed {
			htmlEvent = e
		}
		if e.EventType == core.WebTargetStatus {
			statusEvent = e
		}
		return nil
	}}, Target{Domain: "example.test"}, targetURL)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HTTP.BodyTruncated || !result.Partial || result.Status != "loaded" || result.Features == nil || len(result.Features.AnchorHrefs) != 1 {
		t.Fatalf("actual HTTP cap was reported complete: result=%+v", result)
	}
	if htmlEvent.Metadata["body_truncated"] != true || htmlEvent.Metadata["partial"] != true || statusEvent.Metadata["partial"] != true {
		t.Fatalf("truncation completeness missing from evidence: html=%+v status=%+v", htmlEvent, statusEvent)
	}
}

func TestProbeFailedStatusUsesNullCodeAndSourceConfidence(t *testing.T) {
	client, server, policy, targetURL := probeFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server.Close()
	var status core.Event
	result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(e core.Event) error {
		if e.EventType == core.WebTargetStatus {
			status = e
		}
		return nil
	}}, Target{Domain: "example.test"}, targetURL)
	if !errors.Is(err, activehttp.ErrCollection) || result.Status != "http_error" || status.Metadata["status_code"] != nil || status.Confidence != 0.45 {
		t.Fatalf("failed web status projection: result=%+v status=%+v err=%v", result, status, err)
	}
}

func probeFixture(t *testing.T, handler http.HandlerFunc) (*activehttp.Client, *httptest.Server, core.ScopePolicy, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	u, _ := url.Parse(server.URL)
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	index := evidence.NewDNSRunIndex(policy)
	index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []any{"127.0.0.1"}}})
	client, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: func(core.Event) error { return nil }, PerHostRequests: 8, GlobalConcurrency: 2, PerOriginConcurrency: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return client, server, policy, "http://example.test:" + u.Port() + "/"
}

func TestProbeStatusPrecedenceForBlockedNonHTMLAndRefusedRedirect(t *testing.T) {
	t.Run("blocked non-html", func(t *testing.T) {
		client, _, policy, targetURL := probeFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"blocked":true}`))
		})
		result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(core.Event) error { return nil }}, Target{Domain: "example.test"}, targetURL)
		if err != nil || result.Status != "blocked_response" || result.Features != nil {
			t.Fatalf("blocked response precedence: result=%+v err=%v", result, err)
		}
	})
	t.Run("refused redirect", func(t *testing.T) {
		client, _, policy, targetURL := probeFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "http://outside.test/")
			w.WriteHeader(http.StatusFound)
		})
		result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(core.Event) error { return nil }, MaxRedirects: 0}, Target{Domain: "example.test"}, targetURL)
		if err != nil || result.Status != "redirect_out_of_scope" || !result.Partial || result.Features != nil {
			t.Fatalf("refused redirect status: result=%+v err=%v", result, err)
		}
	})
	t.Run("invalid redirect scheme", func(t *testing.T) {
		client, _, policy, targetURL := probeFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "javascript:alert(1)")
			w.WriteHeader(http.StatusFound)
		})
		result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(core.Event) error { return nil }, MaxRedirects: 0}, Target{Domain: "example.test"}, targetURL)
		if err != nil || result.Status != "redirect_out_of_scope" || !result.HTTP.RedirectOutOfScope {
			t.Fatalf("invalid redirect projection: result=%+v err=%v", result, err)
		}
	})
}

func TestProbeRedactsSavedCommentsAndHeadersWithSourceLimits(t *testing.T) {
	client, _, policy, targetURL := probeFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Fixture", "mail alex@example.com phone +1 212-555-1234 password=abcdefghi")
		var body strings.Builder
		body.WriteString("<!-- mail alex@example.com phone +1 212-555-1234 password=abcdefghi ")
		body.WriteString(strings.Repeat("x", 600))
		body.WriteString(" -->")
		for i := 1; i < 22; i++ {
			body.WriteString("<!-- ordinary -->")
		}
		_, _ = w.Write([]byte(body.String()))
	})
	var analyzed core.Event
	var httpRecord core.Event
	if err := client.SetEventSink(func(e core.Event) error {
		if e.EventType == core.HTTPProbeResult {
			httpRecord = e
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result, err := Probe(context.Background(), client, ProbeConfig{Policy: policy, Emit: func(e core.Event) error {
		if e.EventType == core.HTMLAnalyzed {
			analyzed = e
		}
		return nil
	}}, Target{Domain: "example.test"}, targetURL)
	if err != nil {
		t.Fatal(err)
	}
	comments := analyzed.Metadata["comments"].([]string)
	if len(comments) != 20 || len([]rune(comments[0])) != 500 {
		t.Fatalf("comment caps not applied: count=%d first runes=%d", len(comments), len([]rune(comments[0])))
	}
	for _, secret := range []string{"alex@example.com", "+1 212-555-1234", "abcdefghi"} {
		if strings.Contains(comments[0], secret) {
			t.Fatalf("comment secret persisted: %q", comments[0])
		}
	}
	if !strings.Contains(comments[0], "[REDACTED_EMAIL]") || !strings.Contains(comments[0], "[REDACTED_PHONE]") || !strings.Contains(comments[0], "[REDACTED_SECRET]") {
		t.Fatalf("source redaction placeholders missing: %q", comments[0])
	}
	header := analyzed.Metadata["headers"].(map[string]string)["x-fixture"]
	if strings.Contains(header, "alex@example.com") || strings.Contains(header, "abcdefghi") || !strings.Contains(header, "[REDACTED_EMAIL]") || !strings.Contains(header, "[REDACTED_SECRET]") {
		t.Fatalf("sensitive response header persisted: %q", header)
	}
	if strings.Contains(result.HTTP.Headers["x-fixture"], "[REDACTED_EMAIL]") {
		t.Fatal("transport response headers were mutated in memory")
	}
	storedHeader := httpRecord.Metadata["headers"].(map[string]string)["x-fixture"]
	if strings.Contains(storedHeader, "abcdefghi") || !strings.Contains(storedHeader, "[REDACTED_SECRET]") {
		t.Fatalf("HTTP result stored an unredacted header: %q", storedHeader)
	}
}

func TestPhase5WebTargetPlanningOracleAllModesAndStreamingEligibility(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups struct {
			Planning struct {
				Input struct {
					Root    string           `json:"root"`
					Events  []map[string]any `json:"dns_validation_events"`
					Primary []bool           `json:"primary_only"`
				} `json:"input"`
				Expected map[string][]struct {
					Domain   string   `json:"domain"`
					Evidence []string `json:"evidence"`
					Input    bool     `json:"is_input_target"`
				} `json:"expected"`
			} `json:"web_target_planning"`
		} `json:"groups"`
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Groups.Planning.Input.Events) != 7 || len(f.Groups.Planning.Input.Primary) != 2 {
		t.Fatalf("unexpected source oracle counts: planning events=%d modes=%d", len(f.Groups.Planning.Input.Events), len(f.Groups.Planning.Input.Primary))
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	for mode, primary := range f.Groups.Planning.Input.Primary {
		idx := evidence.NewDNSRunIndex(policy)
		for _, ev := range f.Groups.Planning.Input.Events {
			meta := ev["metadata"].(map[string]any)
			meta["terminal_ips"] = []any{"192.0.2.1"} // absent from the historical planner fixture; required by pinned admission.
			if ev["normalized_value"] == f.Groups.Planning.Input.Root {
				meta["input_target"] = true
			}
			idx.Ingest(ev)
		}
		got, err := EligibleTargets(idx, f.Groups.Planning.Input.Root, policy, primary)
		if err != nil {
			t.Fatal(err)
		}
		want := f.Groups.Planning.Expected[map[bool]string{false: "false", true: "true"}[primary]]
		if len(got) != len(want) {
			t.Fatalf("mode %d targets=%d want=%d: %+v", mode, len(got), len(want), got)
		}
		for i := range got {
			if got[i].Domain != want[i].Domain || got[i].InputTarget != want[i].Input || !reflect.DeepEqual(got[i].DNSEvidence, want[i].Evidence) {
				t.Errorf("mode %d target[%d]=%+v want=%+v", mode, i, got[i], want[i])
			}
		}
	}
}

func TestPlanURLsPrioritizesStandardPortsWithoutDroppingConfiguredPorts(t *testing.T) {
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}}
	targets := []Target{{Domain: "example.test", InputTarget: true}, {Domain: "sub.example.test"}}
	known := []string{
		"http://example.test:8080/nonstandard-http", "http://example.test/plain",
		"https://example.test/secure", "https://example.test:8443/nonstandard-tls",
		"https://sub.example.test/child",
	}
	got := PlanURLs(targets, known, policy, 4)
	want := []string{"https://example.test/secure", "http://example.test/plain", "https://example.test:8443/nonstandard-tls", "http://example.test:8080/nonstandard-http", "https://sub.example.test/child"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("URL plan=%q want=%q", got, want)
	}
}

func TestPhase5HTMLSemanticOracleBothObservations(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups struct {
			HTML struct {
				Input struct {
					Base    string `json:"base_url"`
					Samples map[string]struct {
						Inline []string `json:"inline_scripts"`
					} `json:"feature_samples"`
				} `json:"input"`
				Expected map[string]struct {
					Semantic struct {
						Raw      []string `json:"dynamic_candidates_raw"`
						Resolved []string `json:"dynamic_candidates"`
					} `json:"semantic"`
				} `json:"expected"`
			} `json:"html_semantics"`
		} `json:"groups"`
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Groups.HTML.Input.Samples) != 2 || len(f.Groups.HTML.Expected) != 2 {
		t.Fatalf("HTML semantic source cases=%d expected=%d, want 2 each", len(f.Groups.HTML.Input.Samples), len(f.Groups.HTML.Expected))
	}
	base, err := url.Parse(f.Groups.HTML.Input.Base)
	if err != nil {
		t.Fatal(err)
	}
	for name, sample := range f.Groups.HTML.Input.Samples {
		raw := backends.DynamicCandidates(backends.HTMLFeatures{InlineScripts: sample.Inline})
		want := f.Groups.HTML.Expected[name].Semantic
		if !reflect.DeepEqual(raw, want.Raw) {
			t.Errorf("%s raw candidates=%q want=%q", name, raw, want.Raw)
		}
		var resolved []string
		for _, candidate := range raw {
			if value, ok := resolve(base, candidate); ok {
				resolved = append(resolved, value)
			}
		}
		if !reflect.DeepEqual(resolved, want.Resolved) {
			t.Errorf("%s normalized candidates=%q want=%q", name, resolved, want.Resolved)
		}
	}
}
