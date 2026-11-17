// Command vrvectors writes the validator registry schema v1 vectors (go generate ./vrschema).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/vrschema"
)

func main() {
	out := flag.String("out", "testvectors/validator-registry", "output directory")
	flag.Parse()
	files, err := vrschema.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// storage-forge.json is imported from unicity-pos-contracts (test/vr/fixtures, written by forge); the manifest covers it too
	manifested := map[string][]byte{}
	for k, v := range files {
		manifested[k] = v
	}
	if b, err := os.ReadFile(filepath.Join(*out, vrschema.ForgeFixture)); err == nil {
		manifested[vrschema.ForgeFixture] = b
	}
	files["MANIFEST.sha256"] = vrschema.Manifest(manifested)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	for _, name := range []string{"encoding.json", "statemachine.json", "arithmetic.json", "storage.json"} {
		c, _ := vrschema.Counts(files[name])
		fmt.Println(name, c)
	}
}
