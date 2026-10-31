package backends

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var schemaFiles embed.FS
var schemaCache = map[string]schemaResult{}
var schemaMu sync.Mutex

type schemaResult struct {
	s   *jsonschema.Schema
	err error
}

type denyExternalLoader struct{}

func (denyExternalLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference is disabled: %s", url)
}

func CompileSchema(name string) (*jsonschema.Schema, error) {
	if name != "event" && name != "report" {
		return nil, fmt.Errorf("unknown schema %q", name)
	}
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if cached, ok := schemaCache[name]; ok {
		return cached.s, cached.err
	}
	b, e := schemaFiles.ReadFile("schemas/" + name + ".schema.json")
	if e != nil {
		schemaCache[name] = schemaResult{err: e}
		return nil, e
	}
	var doc any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&doc); e != nil {
		return nil, e
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyExternalLoader{})
	loc := "urn:asm-tool:schema:" + name
	if e = c.AddResource(loc, doc); e != nil {
		schemaCache[name] = schemaResult{err: e}
		return nil, e
	}
	s, e := c.Compile(loc)
	schemaCache[name] = schemaResult{s, e}
	return s, e
}
func ValidateSchema(name string, v any) error {
	s, e := CompileSchema(name)
	if e != nil {
		return e
	}
	if e = finite(v); e != nil {
		return e
	}
	return s.Validate(v)
}
func ValidateEvent(v map[string]any) error { return ValidateSchema("event", v) }

// SchemaSourceHash helps callers record the schema bytes that governed validation.
func SchemaSourceHash(name string) (string, error) {
	if name != "event" && name != "report" {
		return "", fmt.Errorf("unknown schema %q", name)
	}
	b, e := schemaFiles.ReadFile("schemas/" + name + ".schema.json")
	if e != nil {
		return "", e
	}
	return SHA256(b), nil
}
