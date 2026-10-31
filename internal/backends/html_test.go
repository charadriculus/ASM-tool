package backends

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseHTMLExtractsObservablePageFeatures(t *testing.T) {
	got, err := ParseHTML(`<!doctype html><html><head><title>  Пример
 страница </title><meta name="robots" content="noindex,nofollow"><link rel="canonical" href="/canonical"><script src="/app.js"></script></head><body><p>Тест   café<br>страница</p><a href="/café?q=2&amp;a=1" rel="nofollow">ссылка</a><form action="../submit" method="POST"><input type="text" name="q" value="a"></form><script>fetch('/api/v1');</script><!-- comment --></body></html>`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Пример страница" || got.ExtractedText != "Пример страница Тест café страница ссылка" {
		t.Fatalf("normalized title/text mismatch: title=%q text=%q", got.Title, got.ExtractedText)
	}
	if !reflect.DeepEqual(got.AnchorHrefs, []string{"/café?q=2&a=1"}) || len(got.Forms) != 1 || len(got.FormFields) != 1 {
		t.Fatalf("page links/forms not parsed: %+v", got)
	}
	if got.CanonicalURL == nil || *got.CanonicalURL != "/canonical" || len(got.MetaRobots) != 1 || got.MetaRobots[0]["content"] != "noindex,nofollow" {
		t.Fatalf("page metadata not parsed: %+v", got)
	}
	if len(got.ScriptSrcs) != 1 || len(got.InlineScripts) != 1 || len(got.Comments) != 1 {
		t.Fatalf("scripts/comments not parsed: %+v", got)
	}
}

func TestPhase5FixtureDynamicCandidates(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase5/fixtures/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Groups struct {
			HTML struct {
				Input struct {
					Samples map[string]struct {
						InlineScripts []string `json:"inline_scripts"`
					} `json:"feature_samples"`
				} `json:"input"`
				Expected map[string]struct {
					Candidates [][2]string `json:"dynamic_candidates"`
				} `json:"expected"`
			} `json:"html_semantics"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for name, sample := range fixture.Groups.HTML.Input.Samples {
		var got []string
		for _, body := range sample.InlineScripts {
			got = append(got, DynamicCandidates(HTMLFeatures{InlineScripts: []string{body}})...)
		}
		var want []string
		for _, pair := range fixture.Groups.HTML.Expected[name].Candidates {
			want = append(want, pair[0])
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s dynamic candidates: got %q want %q", name, got, want)
		}
	}
}

func TestDynamicCandidateScanLimitCountsUnicodeCharacters(t *testing.T) {
	script := strings.Repeat("é", 249970) + " fetch('/afterprefix');"
	got := DynamicCandidates(HTMLFeatures{InlineScripts: []string{script}})
	if !reflect.DeepEqual(got, []string{"/afterprefix"}) {
		t.Fatalf("250,000-character scan boundary differs from source: %q", got)
	}
}
