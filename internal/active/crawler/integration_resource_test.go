package crawler

import (
	"asmtool/internal/core"
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestIntegrationDownloadLinkDetectedWithoutContact(t *testing.T) {
	var contacts []string
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacts = append(contacts, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/документ.pdf">PDF</a><a href="/next">next</a>`))
	}))
	root := "http://example.test:" + mustURLPort(t, server.URL) + "/"
	var documents []core.Event
	_, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(ev core.Event) error {
		if ev.Metadata["category"] == "downloadable_resource_detected" {
			documents = append(documents, ev)
		}
		return nil
	}, MaxPagesPerOrigin: 3, MaxTotalPages: 3, MaxDepth: 1}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range contacts {
		if path == "/документ.pdf" {
			t.Fatal("download link contacted")
		}
	}
	if len(documents) != 1 || documents[0].Metadata["network_contacted"] != false || documents[0].Metadata["page_loaded"] != false || documents[0].Metadata["resource_type"] != "PDF document" {
		t.Fatalf("documents=%+v", documents)
	}
}

func TestIntegrationMIMEDownloadIsNeverLoadedPage(t *testing.T) {
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Write([]byte("%PDF fixture"))
	}))
	var events []core.Event
	_, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(ev core.Event) error { events = append(events, ev); return nil }, MaxPagesPerOrigin: 1, MaxTotalPages: 1}, []string{"http://example.test:" + mustURLPort(t, server.URL) + "/attachment"})
	if err != nil {
		t.Fatal(err)
	}
	docs := 0
	for _, ev := range events {
		if ev.EventType == core.CrawlerResult {
			if ev.Metadata["page_loaded"] == true {
				t.Fatal("MIME document marked loaded HTML page")
			}
			if ev.Metadata["category"] == "downloadable_resource_detected" {
				docs++
			}
		}
	}
	if docs != 1 {
		t.Fatalf("documents=%d", docs)
	}
}
func TestIntegrationDocumentBudgetAndCrossDomainEvidence(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/a.pdf">pdf</a><a href="/b">b</a><a href="http://child.example.test/">child</a>`))
	}))
	child := false
	documents := 0
	results, err := Crawl(context.Background(), client, Config{Policy: policy, Emit: func(ev core.Event) error {
		if ev.EventType == core.URLFound && ev.NormalizedValue == "http://child.example.test/" {
			child = true
		}
		if ev.Metadata["category"] == "downloadable_resource_detected" {
			documents++
		}
		return nil
	}, MaxPagesPerOrigin: 2, MaxTotalPages: 10, MaxDepth: 1}, []string{"http://example.test:" + mustURLPort(t, server.URL) + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !child {
		t.Fatal("scope child URL not available to dynamic DNS admission")
	}
	if documents != 1 || !reflect.DeepEqual(requests, []string{"/", "/b"}) {
		t.Fatalf("document detection spent HTML page budget or contacted a document: documents=%d requests=%v", documents, requests)
	}
	if len(results) != 1 || results[0].Partial || len(results[0].Pages) != 2 || strings.Contains(results[0].Pages[0].URL, ".pdf") {
		t.Fatalf("document incorrectly counted as an HTML page: %+v", results)
	}
}

func TestDocumentDetectionDoesNotConsumeHTMLPageBudget(t *testing.T) {
	var requests []string
	client, server, policy := crawlerClient(t, []string{"example.test"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<a href="/report.pdf">report</a><a href="/child">child</a>`))
			return
		}
		_, _ = w.Write([]byte(`<html><title>child</title></html>`))
	}))
	var documentEvents int
	results, err := Crawl(context.Background(), client, Config{
		Policy: policy,
		Emit: func(ev core.Event) error {
			if ev.Metadata["category"] == "downloadable_resource_detected" {
				documentEvents++
			}
			return nil
		},
		MaxPagesPerOrigin: 2,
		MaxTotalPages:     2,
		MaxDepth:          1,
	}, []string{"http://example.test:" + mustURLPort(t, server.URL) + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if documentEvents != 1 {
		t.Fatalf("document detections=%d, want 1", documentEvents)
	}
	if !reflect.DeepEqual(requests, []string{"/", "/child"}) {
		t.Fatalf("HTTP requests=%v, want root and child only", requests)
	}
	if len(results) != 1 || len(results[0].Pages) != 2 {
		t.Fatalf("HTML page budget accounting: results=%+v", results)
	}
}
