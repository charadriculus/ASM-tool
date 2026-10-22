package passive

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestSourceJSONLLines(t *testing.T) {
	b, e := os.ReadFile("../../../testdata/phase3/fixtures/contracts.json")
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Inputs struct {
			Subfaster struct {
				Lines    []string `json:"jsonl_lines"`
				Provider string   `json:"requested_source"`
				Unknown  string   `json:"unrecognized_provider"`
			} `json:"subfaster"`
		} `json:"inputs"`
		Outputs struct {
			Subfaster struct {
				Rows          [][]any           `json:"rows"`
				Families      map[string]string `json:"provider_families"`
				UnknownFamily string            `json:"unknown_provider_family"`
			} `json:"subfaster"`
		} `json:"outputs"`
	}
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	if len(c.Inputs.Subfaster.Lines) != len(c.Outputs.Subfaster.Rows) {
		t.Fatal("fixture line count mismatch")
	}
	for i, line := range c.Inputs.Subfaster.Lines {
		host, sources, ok := ParseSubfasterLine(line, c.Inputs.Subfaster.Provider)
		want := c.Outputs.Subfaster.Rows[i]
		if want == nil {
			if ok {
				t.Fatalf("line %d unexpectedly parsed", i)
			}
			continue
		}
		if !ok || host != want[0] {
			t.Fatalf("line %d: got %q,%v,%v want %v", i, host, sources, ok, want)
		}
		var expected []string
		for _, v := range want[1].([]any) {
			expected = append(expected, v.(string))
		}
		if len(sources) != len(expected) {
			t.Fatalf("line %d sources %v want %v", i, sources, expected)
		}
		for n := range sources {
			if sources[n] != expected[n] {
				t.Fatalf("line %d sources %v want %v", i, sources, expected)
			}
		}
	}
	for name, want := range c.Outputs.Subfaster.Families {
		if got := SubfasterFamily(name); got != want {
			t.Errorf("family %s=%s want %s", name, got, want)
		}
	}
	if got := SubfasterFamily(c.Inputs.Subfaster.Unknown); got != c.Outputs.Subfaster.UnknownFamily {
		t.Fatalf("unknown family=%s", got)
	}
}

func TestSubfasterPythonTruthinessAndStrictJSON(t *testing.T) {
	cases := []struct {
		line    string
		ok      bool
		host    string
		sources []string
	}{{`{"host":[],"hostname":"valid.example.test"}`, true, "valid.example.test", []string{"requested"}}, {`{"host":{"x":1},"hostname":"fallback.example.test"}`, false, "", nil}, {`{"host":"valid.example.test","sources":[false,0,"",true,3]}`, true, "valid.example.test", []string{"3", "True"}}, {`{"host":"valid.example.test"} trailing`, false, "", nil}}
	for _, c := range cases {
		h, s, ok := ParseSubfasterLine(c.line, "requested")
		if ok != c.ok || h != c.host || !reflect.DeepEqual(s, c.sources) {
			t.Errorf("%s => %q %v %v want %q %v %v", c.line, h, s, ok, c.host, c.sources, c.ok)
		}
	}
}
