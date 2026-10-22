// Command g28probe emits bounded, local-only observations from the Go
// configuration, validation, and HTTP crawler contracts for G28 comparison.
// It never starts an application run or an external tool.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"asmtool/internal/active/crawler"
	activehttp "asmtool/internal/active/http"
	"asmtool/internal/app"
	"asmtool/internal/config"
	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"gopkg.in/yaml.v3"
)

type output struct {
	ConfigProjection map[string]any `json:"config_projection"`
	PrepareCases     []prepareCase  `json:"prepare_cases"`
	Crawler          crawlOutput    `json:"crawler"`
}
type prepareCase struct {
	Name       string `json:"name"`
	Accepted   bool   `json:"accepted"`
	Error      string `json:"error,omitempty"`
	Validation string `json:"validation"`
}
type crawlOutput struct {
	Results        []crawler.Result `json:"results"`
	Events         []core.Event     `json:"events"`
	Requests       []string         `json:"requests"`
	TerminalStatus map[string]int   `json:"terminal_status_counts"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("g28probe", flag.ContinueOnError)
	outFlag := flags.String("out", "", "new absolute output directory")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *outFlag == "" || flags.NArg() != 0 {
		return errors.New("usage: g28probe --out ABSOLUTE_FRESH_DIRECTORY")
	}
	if !filepath.IsAbs(*outFlag) {
		return errors.New("--out must be absolute")
	}
	outDir, err := filepath.Abs(*outFlag)
	if err != nil {
		return err
	}
	if err := os.Mkdir(outDir, 0700); err != nil {
		return fmt.Errorf("create fresh output directory: %w", err)
	}
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	projection := map[string]any{
		"rate_limits": cfg.RateLimits, "collection_policy": cfg.CollectionPolicy,
		"modules": cfg.Modules, "reporting": cfg.Reporting, "backends": cfg.Backends,
	}
	cases, err := prepareCases(outDir, cfg)
	if err != nil {
		return err
	}
	crawl, err := runCrawlFixture()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(output{projection, cases, crawl}, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(outDir, "g28-go-observations.json"), append(data, '\n'))
}

func prepareCases(outDir string, defaults config.ToolConfig) ([]prepareCase, error) {
	cases := []struct{ name, suffix string }{
		{"resource_monitor_enabled", "resource_monitor:\n  enabled: true\n"},
		{"external_tools_override", ""},
		{"unknown_ordinary_key", "historical_unrecognized_setting: true\n"},
		{"ai_review_removed", "ai_review:\n  mode: balanced\n"},
	}
	out := make([]prepareCase, 0, len(cases))
	for i, tc := range cases {
		cfg := defaults
		cfg.AllowedDomains = []string{"example.test"}
		target := "example.test"
		cfg.TargetDomain = &target
		cfg.OutputDir = filepath.Join(outDir, fmt.Sprintf("prepare-%02d", i))
		cfg.DatabasePath = filepath.Join(cfg.OutputDir, "asm.sqlite3")
		suffix := tc.suffix
		if tc.name == "external_tools_override" {
			cfg.ExternalTools = map[string]string{"nmap": "/unused/nmap"}
		}
		base, err := yaml.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		configPath := filepath.Join(outDir, fmt.Sprintf("case-%02d.yaml", i))
		if err := writeNew(configPath, append(append(base, '\n'), []byte(suffix)...)); err != nil {
			return nil, err
		}
		_, validationErr := app.Prepare(app.Options{ConfigPath: configPath, Domain: "example.test", Set: map[string]bool{"domain": true}})
		row := prepareCase{Name: tc.name, Accepted: validationErr == nil, Validation: "app.Prepare configuration validation only"}
		if validationErr != nil {
			row.Error = validationErr.Error()
		}
		out = append(out, row)
	}
	return out, nil
}

func runCrawlFixture() (crawlOutput, error) {
	var mu sync.Mutex
	requests := []string{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/robots.txt":
			http.Redirect(w, r, "/policy/robots.txt", http.StatusFound)
		case "/policy/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		case "/":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="/child">child</a><a href="/private">private</a>`))
		case "/child", "/private":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<title>fixture</title>"))
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		return crawlOutput{}, err
	}
	_, port, found := strings.Cut(u.Host, ":")
	if !found {
		return crawlOutput{}, errors.New("loopback fixture did not expose a port")
	}
	policy := core.ScopePolicy{AllowedDomains: []string{"example.test"}, AllowedCIDRs: []string{"127.0.0.0/8"}}
	index := evidence.NewDNSRunIndex(policy)
	index.Ingest(map[string]any{"event_type": "dns_validation", "normalized_value": "example.test", "observed_at": "1", "metadata": map[string]any{"dns_state": "resolved_clean_parent", "active_eligibility": "eligible", "terminal_ips": []string{"127.0.0.1"}}})
	client, err := activehttp.NewClient(activehttp.Config{Policy: policy, Profile: "verify", Authorized: true, Index: index, Emit: func(core.Event) error { return nil }, UserAgent: "ASM-G28-local-fixture", PerHostRequests: 12, GlobalConcurrency: 1, PerOriginConcurrency: 1, Timeout: 2 * time.Second, StopStatuses: []int{401, 403, 429}})
	if err != nil {
		return crawlOutput{}, err
	}
	var events []core.Event
	results, crawlErr := crawler.Crawl(context.Background(), client, crawler.Config{Policy: policy, Emit: func(ev core.Event) error { events = append(events, ev); return nil }, UserAgent: "ASM-G28-local-fixture", ObeyRobots: true, MaxPagesPerOrigin: 5, MaxTotalPages: 8, MaxDepth: 1}, []string{"http://example.test:" + port + "/", "http://example.test:" + port + "/private"})
	if crawlErr != nil {
		return crawlOutput{}, crawlErr
	}
	mu.Lock()
	requestCopy := append([]string(nil), requests...)
	mu.Unlock()
	statuses := map[string]int{}
	for _, ev := range events {
		if ev.EventType == core.WebTargetStatus {
			status, _ := ev.Metadata["status"].(string)
			statuses[status]++
		}
	}
	return crawlOutput{Results: results, Events: events, Requests: requestCopy, TerminalStatus: statuses}, nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}
