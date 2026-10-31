package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Developer-only configuration comparison. Prepare never executes collection.
func TestG28OfflineModePlans(t *testing.T) {
	root := os.Getenv("ASM_G28_DIR")
	if root == "" {
		t.Skip("G28 comparison opt-in absent")
	}
	observations := map[string]any{}
	for _, mode := range []string{"passive", "verify", "full"} {
		args := []string{"--domain", "example.test", "--profile", mode, "--non-interactive", "--output-dir", filepath.Join(root, "unexecuted-"+mode), "--bundle-dir", filepath.Join(root, "unexecuted-payload")}
		if mode != "passive" {
			args = append(args, "--yes")
		}
		opts, err := ParseOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := Prepare(opts)
		if err != nil {
			t.Fatal(err)
		}
		observations[mode] = map[string]any{"config": plan.cfg, "browser_mode": plan.browserMode, "execution": "NOT_RUN; Prepare only"}
	}
	data, err := json.MarshalIndent(observations, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(root, "go-mode-plans.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
