// Package browser contains pure event contracts shared by future browser and
// crawler callers. It performs no navigation or network activity.
package browser

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"asmtool/internal/core"
	"asmtool/internal/evidence"
	"asmtool/internal/resource"
)

// Download contracts are shared with independent Go HTTP/crawler execution.
type DownloadInfo = resource.DownloadInfo
type DownloadEventInput = resource.DownloadEventInput

func DownloadableResourceInfo(rawURL, contentType, contentDisposition string) (DownloadInfo, bool) {
	return resource.DownloadableResourceInfo(rawURL, contentType, contentDisposition)
}
func NewDownloadEvent(in DownloadEventInput) (core.Event, error) {
	return resource.NewDownloadEvent(in)
}

// ScreenshotCoverage reads existing event files and returns missing-coverage
// limitations without revisiting pages. Events are ordered by first-seen domain,
// then URL, matching source iteration and URL sorting.
func ScreenshotCoverage(eventsDir string, passive, enabled bool) ([]core.Event, error) {
	if passive || !enabled {
		return nil, nil
	}
	loaded, err := urlsByDomain(eventsDir, true, "web.jsonl", "crawler.jsonl")
	if err != nil {
		return nil, err
	}
	captured, err := urlsByDomain(eventsDir, false, "screenshots.jsonl")
	if err != nil {
		return nil, err
	}
	var missing []core.Event
	for _, domain := range loaded.order {
		var urls []string
		for value := range loaded.values[domain] {
			if !captured.values[domain][value] {
				urls = append(urls, value)
			}
		}
		sort.Strings(urls)
		for _, value := range urls {
			e, eErr := core.NewEvent(core.Limitation, "screenshots", "coverage_reconciliation", "The page loaded but no screenshot was saved.", value, core.InScope)
			if eErr != nil {
				return nil, eErr
			}
			e.Confidence = 0
			e.Metadata = map[string]any{"target_domain": domain, "url": value, "page_loaded": true, "revisit_performed": false, "severity": "warning"}
			missing = append(missing, e)
		}
	}
	return missing, nil
}

type domainURLs struct {
	order  []string
	values map[string]map[string]bool
}

func urlsByDomain(dir string, loaded bool, files ...string) (domainURLs, error) {
	result := domainURLs{values: map[string]map[string]bool{}}
	for _, name := range files {
		file := filepath.Join(dir, name)
		err := evidence.IterJSONL(file, func(record evidence.JSONLRecord) error {
			if record.Err != nil {
				return fmt.Errorf("%s:%d: %w", record.Path, record.Line, record.Err)
			}
			event := record.Event
			eventType := asString(event["event_type"])
			if loaded {
				if event["scope_status"] != string(core.InScope) || (eventType != string(core.HTMLAnalyzed) && eventType != string(core.CrawlerResult)) {
					return nil
				}
				if eventType == string(core.CrawlerResult) {
					metadata, ok := event["metadata"].(map[string]any)
					if ok && (metadata["page_loaded"] == false || metadata["screenshot_expected"] == false) {
						return nil
					}
				}
			} else if eventType != string(core.ScreenshotSaved) {
				return nil
			}
			value, ok := event["normalized_value"].(string)
			metadata, metadataOK := event["metadata"].(map[string]any)
			if !ok || !metadataOK {
				return nil
			}
			domains := eventDomains(metadata)
			for _, domain := range domains {
				if _, ok := result.values[domain]; !ok {
					result.values[domain] = map[string]bool{}
					result.order = append(result.order, domain)
				}
				result.values[domain][value] = true
			}
			return nil
		})
		if err != nil {
			return domainURLs{}, fmt.Errorf("read screenshot coverage %s: %w", file, err)
		}
	}
	return result, nil
}

func eventDomains(metadata map[string]any) []string {
	if domains, ok := metadata["target_domains"].([]any); ok {
		out := make([]string, 0, len(domains))
		for _, domain := range domains {
			if domain == nil {
				out = append(out, "None")
			} else {
				out = append(out, fmt.Sprint(domain))
			}
		}
		return out
	}
	if domains, ok := metadata["target_domains"].([]string); ok {
		return domains
	}
	if domain, ok := metadata["target_domain"].(string); ok && domain != "" {
		return []string{domain}
	}
	return nil
}

func asString(value any) string {
	s, _ := value.(string)
	return s
}

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "://"
	}
	// Python urlsplit().netloc includes userinfo, so preserve it here as well.
	authority := strings.ToLower(u.Host)
	if u.User != nil {
		authority = strings.ToLower(u.User.String()) + "@" + authority
	}
	return strings.ToLower(u.Scheme) + "://" + authority
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
