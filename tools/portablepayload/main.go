// Command portablepayload stages and verifies reviewed portable payloads.
// It is developer tooling: it never downloads or executes payload binaries.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: portablepayload <stage|verify|archive> [options]")
	}
	switch args[0] {
	case "stage":
		fs := flag.NewFlagSet("stage", flag.ContinueOnError)
		lockPath := fs.String("lock", "", "reviewed JSON source lock")
		out := fs.String("out", "", "new output directory (must not exist)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *lockPath == "" || *out == "" || fs.NArg() != 0 {
			return errors.New("stage requires --lock and --out")
		}
		result, err := stage(*lockPath, *out)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "verify", "archive":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		root := fs.String("root", "", "portable root containing application and payload/")
		appHash := fs.String("app-sha256", "", "independently recorded application SHA-256")
		bundleHash := fs.String("bundle-sha256", "", "independently recorded embedded bundle SHA-256")
		provenanceHash := fs.String("provenance-sha256", "", "independently recorded provenance SHA-256")
		out := fs.String("out", "", "new archive path (archive only; must not exist)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *root == "" || !validDigest(*appHash) || !validDigest(*bundleHash) || !validDigest(*provenanceHash) || fs.NArg() != 0 {
			return errors.New(args[0] + " requires --root, valid --app-sha256 --bundle-sha256 and --provenance-sha256")
		}
		files, platform, err := verifyRoot(*root, *appHash, *bundleHash, *provenanceHash)
		if err != nil {
			return err
		}
		if args[0] == "archive" {
			if *out == "" {
				return errors.New("archive requires --out")
			}
			if err := writeArchive(*root, *out, files); err != nil {
				return err
			}
		} else if *out != "" {
			return errors.New("verify does not accept --out")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "verified_offline", "platform": platform, "files": len(files)})
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "portablepayload:", err)
		os.Exit(2)
	}
}
