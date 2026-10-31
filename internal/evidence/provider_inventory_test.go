package evidence

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestProviderInventorySourceFixture(t *testing.T) {
	b, e := os.ReadFile("../../testdata/phase3/fixtures/contracts.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Inputs struct {
			Provider struct {
				Events []map[string]any `json:"events"`
				Root   string           `json:"root"`
			} `json:"provider.inventory"`
		} `json:"inputs"`
		Outputs struct {
			Provider ProviderInventoryEntry `json:"provider.inventory"`
		} `json:"outputs"`
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	got, e := ProviderInventory(fixture.Inputs.Provider.Events, fixture.Inputs.Provider.Root)
	if e != nil {
		t.Fatal(e)
	}
	want := fixture.Outputs.Provider
	entry := got[want.Hostname]
	if !reflect.DeepEqual(entry, want) {
		t.Fatalf("got %#v want %#v", entry, want)
	}
	entry = got["node.example.test"]
	if !reflect.DeepEqual(entry.Providers, []string{"crt.sh"}) || !reflect.DeepEqual(entry.EvidenceFamilies, []string{"certificate_transparency"}) || !reflect.DeepEqual(entry.Collectors, []string{"asm_http", "subfaster"}) {
		t.Fatalf("unknown aggregate contributed independent vote: %#v", entry)
	}
}
