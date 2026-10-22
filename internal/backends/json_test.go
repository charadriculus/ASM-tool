package backends

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type badJSON struct{}

func (badJSON) MarshalJSON() ([]byte, error) { return []byte(`"\ud800"`), nil }

type badKey int

func (badKey) MarshalText() ([]byte, error) { return []byte{0xff}, nil }

func TestEncoderRejectsCyclesDepthAndInvalidEmittedText(t *testing.T) {
	if _, err := EncodeJSON([1]int{1}, false, true, false); err != nil {
		t.Fatalf("array reflection rejected: %v", err)
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := EncodeJSON(cycle, false, true, false); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Fatalf("cycle result: %v", err)
	}
	var deep any = "end"
	for i := 0; i < 140; i++ {
		deep = []any{deep}
	}
	if _, err := EncodeJSON(deep, false, true, false); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep value result: %v", err)
	}
	if _, err := EncodeJSON(badJSON{}, false, true, false); err == nil {
		t.Fatal("custom MarshalJSON emitted an unpaired surrogate")
	}
	if _, err := EncodeJSON(map[badKey]string{1: "value"}, false, true, false); err == nil {
		t.Fatal("TextMarshaler emitted invalid UTF-8 map key")
	}
}

func TestSerializationSourceFixtureBytes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "phase2", "legacy_contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecodeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	rows := v.(map[string]any)["serialization"].([]any)
	for _, row := range rows {
		m := row.(map[string]any)
		options := m["options"].(map[string]any)
		got, err := EncodeJSON(m["value"], options["indent"] != nil, options["sort_keys"] == true, false)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(m["utf8_hex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s bytes differ: %x != %x", m["name"], got, want)
		}
	}
}

func TestJSONBoundariesSchemaAndFailedEncodingPreserveInput(t *testing.T) {
	for _, input := range [][]byte{{0xff}, []byte(`{} {}`), []byte(`"\ud800"`), []byte(`"\udc00"`)} {
		if _, err := DecodeJSON(input); err == nil {
			t.Errorf("DecodeJSON accepted invalid boundary input %q", input)
		}
	}
	decoded, err := DecodeJSON([]byte(`{"n":9007199254740993,"s":"\u2028"}`))
	if err != nil {
		t.Fatal(err)
	}
	n := decoded.(map[string]any)["n"].(json.Number)
	if string(n) != "9007199254740993" {
		t.Fatalf("large integer precision lost: %s", n)
	}
	if err = ValidateEvent(map[string]any{"event_id": "e", "event_type": "fixture", "module": "test", "source_tool": "fixture", "observed_at": "now", "raw_value": nil, "normalized_value": "x", "scope_status": "in_scope", "confidence": 0.5, "evidence": map[string]any{}, "relations": []any{}, "metadata": map[string]any{}}); err != nil {
		t.Fatalf("valid source event rejected: %v", err)
	}
	invalid := map[string]any{"event_id": "e", "event_type": "fixture", "module": "test", "source_tool": "fixture", "observed_at": "now", "raw_value": nil, "normalized_value": "x", "scope_status": "in_scope", "confidence": 1.1, "evidence": map[string]any{}, "relations": []any{}, "metadata": map[string]any{}}
	if err = ValidateEvent(invalid); err == nil {
		t.Fatal("schema accepted confidence above one")
	}
	missing := map[string]any{"event_id": "e"}
	if err = ValidateEvent(missing); err == nil {
		t.Fatal("event schema accepted missing required fields")
	}
	if _, err = CompileSchema("unknown"); err == nil {
		t.Fatal("unknown embedded schema accepted")
	}

	shared := map[string]any{"nested": map[string]any{"value": "before"}, "bad": math.NaN()}
	before := shared["nested"].(map[string]any)["value"]
	if _, err = EncodeJSON(shared, false, true, false); err == nil {
		t.Fatal("encoder accepted non-finite value")
	}
	if shared["nested"].(map[string]any)["value"] != before {
		t.Fatal("failed serialization mutated caller input")
	}
}

func TestAtomicJSONPreservesExistingDestinationAndCleansFailedTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	old := []byte(`{"state":"previous"}`)
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONAtomic(path, map[string]any{"invalid": math.NaN()}, true, true, false, true); err == nil {
		t.Fatal("non-finite JSON unexpectedly wrote")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(old) {
		t.Fatalf("failed encoding changed prior destination: %q err=%v", got, err)
	}
	assertNoAtomicTemps(t, dir)

	// A destination directory forces the final rename to fail after the temp
	// file was written; its existing contents must remain intact.
	destinationDir := filepath.Join(dir, "destination")
	if err = os.Mkdir(destinationDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(destinationDir, "previous.json")
	if err = os.WriteFile(marker, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err = WriteBytesAtomic(destinationDir, []byte(`{"state":"new"}`), true); err == nil {
		t.Fatal("atomic replace of directory unexpectedly succeeded")
	}
	got, err = os.ReadFile(marker)
	if err != nil || string(got) != string(old) {
		t.Fatalf("failed replace changed prior bytes: %q err=%v", got, err)
	}
	assertNoAtomicTemps(t, dir)
}

func assertNoAtomicTemps(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("atomic writer left temporary files: %v", files)
	}
}
