package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestFixturesSourceIdentity(t *testing.T) {
	var p struct {
		Commit string
		SHA256 map[string]string `json:"sha256"`
	}
	if e := json.Unmarshal(fixture(t, "provenance.json"), &p); e != nil {
		t.Fatal(e)
	}
	if p.Commit != "3007642c302c7d1f61daa8f45ee5e33c2557aa02" {
		t.Fatal("unexpected reference identity")
	}
	for name, want := range p.SHA256 {
		b, e := os.ReadFile("../../reference/windows-0.11.3-development/asm_tool/" + name)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("source fixture drift: %s", name)
		}
	}
}
