package backends

import (
	"bytes"
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

// HTMLFeatures is syntax extracted from a response. It makes no scope or
// authorization decision; those belong to active/web.
type HTMLFeatures struct {
	AnchorHrefs        []string            `json:"anchor_hrefs"`
	ScriptSrcs         []string            `json:"script_srcs"`
	InlineScripts      []string            `json:"inline_scripts"`
	Comments           []string            `json:"comments"`
	Forms              []map[string]any    `json:"forms"`
	FormFields         []map[string]any    `json:"form_fields"`
	MetaRobots         []map[string]string `json:"meta_robots"`
	Metadata           []map[string]string `json:"metadata"`
	RelevantAttributes []map[string]any    `json:"relevant_attributes"`
	CanonicalURL       *string             `json:"canonical_url"`
	Title              string              `json:"title"`
	ExtractedText      string              `json:"extracted_text"`
}

var dynamicURL = regexp.MustCompile(`(https?://|/)[A-Za-z0-9_./?=&:%#@+-]+`)

func ParseHTML(source string) (HTMLFeatures, error) {
	root, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return HTMLFeatures{}, err
	}
	var out HTMLFeatures
	var textParts []string
	var titleDepth, scriptDepth, styleDepth int
	var script strings.Builder
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.CommentNode {
			out.Comments = append(out.Comments, n.Data)
		}
		if n.Type == html.TextNode {
			if titleDepth > 0 {
				out.Title += n.Data
			}
			if scriptDepth > 0 {
				script.WriteString(n.Data)
			}
			if scriptDepth == 0 && styleDepth == 0 {
				textParts = append(textParts, n.Data)
			}
		}
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			attrs := attrMap(n.Attr)
			switch tag {
			case "title":
				titleDepth++
			case "script":
				scriptDepth++
				if src, ok := attrs["src"]; ok {
					out.ScriptSrcs = append(out.ScriptSrcs, src)
				}
			case "style":
				styleDepth++
			case "a":
				if href, ok := attrs["href"]; ok {
					out.AnchorHrefs = append(out.AnchorHrefs, href)
				}
			case "form":
				out.Forms = append(out.Forms, selectValues(attrs, "action", "method", "id", "name"))
			case "input", "select", "textarea":
				out.FormFields = append(out.FormFields, selectAttrs(tag, attrs, fieldAttrs(tag)...))
			case "meta":
				row := selectMeta(attrs)
				out.Metadata = append(out.Metadata, row)
				// Match the source contract: lower() without trimming.
				if strings.ToLower(attrs["name"]) == "robots" {
					out.MetaRobots = append(out.MetaRobots, map[string]string{"name": "robots", "content": attrs["content"]})
				}
			case "link":
				if out.CanonicalURL == nil && attrs["href"] != "" && hasToken(attrs["rel"], "canonical") {
					v := attrs["href"]
					out.CanonicalURL = &v
				}
			}
			if selected, ok := relevantTag[tag]; ok {
				out.RelevantAttributes = append(out.RelevantAttributes, selectAttrs(tag, attrs, selected...))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "title":
				titleDepth--
			case "script":
				scriptDepth--
				if attrsSrc(n.Attr) == "" {
					out.InlineScripts = append(out.InlineScripts, script.String())
				}
				script.Reset()
			case "style":
				styleDepth--
			}
		}
	}
	visit(root)
	out.Title = strings.TrimSpace(strings.Join(strings.Fields(out.Title), " "))
	out.ExtractedText = strings.TrimSpace(strings.Join(strings.Fields(strings.Join(textParts, " ")), " "))
	return out, nil
}

// DecodeHTML converts a bounded response body according to its declared or
// detected HTML encoding. Callers retain and hash the original response bytes.
func DecodeHTML(body []byte, contentType string) (string, error) {
	r, err := charset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		return "", err
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

var relevantTag = map[string][]string{"a": {"href", "rel", "target"}, "script": {"src", "type"}, "form": {"action", "method", "id", "name"}, "input": {"type", "name", "value", "id", "checked"}, "select": {"name", "id", "multiple"}, "textarea": {"name", "id"}, "meta": {"name", "property", "http-equiv", "charset", "content"}, "link": {"rel", "href", "type"}}

func fieldAttrs(tag string) []string {
	switch tag {
	case "input":
		return []string{"type", "name", "value", "id", "checked"}
	case "select":
		return []string{"name", "id", "multiple"}
	default:
		return []string{"name", "id"}
	}
}
func attrMap(a []html.Attribute) map[string]string {
	m := make(map[string]string, len(a))
	for _, v := range a {
		m[strings.ToLower(v.Key)] = v.Val
	}
	return m
}
func selectAttrs(tag string, a map[string]string, names ...string) map[string]any {
	m := map[string]any{"tag": tag}
	for _, k := range names {
		if v, ok := a[k]; ok {
			m[k] = v
		}
	}
	return m
}
func selectValues(a map[string]string, names ...string) map[string]any {
	m := map[string]any{}
	for _, k := range names {
		if v, ok := a[k]; ok {
			m[k] = v
		}
	}
	return m
}
func selectMeta(a map[string]string) map[string]string {
	m := map[string]string{}
	for _, k := range []string{"name", "property", "http-equiv", "charset", "content"} {
		if v, ok := a[k]; ok {
			m[k] = v
		}
	}
	return m
}
func hasToken(v, w string) bool {
	for _, x := range strings.Fields(strings.ToLower(v)) {
		if x == w {
			return true
		}
	}
	return false
}
func attrsSrc(a []html.Attribute) string {
	for _, x := range a {
		if strings.EqualFold(x.Key, "src") {
			return x.Val
		}
	}
	return ""
}

// DynamicCandidates returns raw inline-script URL strings, capped at the
// source's 250,000 byte scan boundary. URL resolution is owned by active/web.
func DynamicCandidates(features HTMLFeatures) []string {
	var out []string
	for _, body := range features.InlineScripts {
		runes := []rune(body)
		if len(runes) > 250000 {
			body = string(runes[:250000])
		}
		for _, m := range dynamicURL.FindAllString(body, -1) {
			out = append(out, m)
		}
	}
	return out
}
