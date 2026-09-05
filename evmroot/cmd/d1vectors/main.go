// Command d1vectors regenerates the D1 canonical root-input vector set.
//
//	go run ./evmroot/cmd/d1vectors            # print to stdout
//	go run ./evmroot/cmd/d1vectors -update    # overwrite evmroot/testdata/vectors.json
//
// The committed file evmroot/testdata/vectors.json is the golden reference
// TestVectorsMatchGolden checks against. Regenerate it deliberately, review
// the diff, and record the reason in the D1 issue when a change is
// intentional.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/evmroot"
)

func main() {
	update := flag.Bool("update", false, "overwrite evmroot/testdata/vectors.json instead of printing")
	out := flag.String("o", "evmroot/testdata/vectors.json", "path to write when -update is set")
	flag.Parse()

	data, err := evmroot.MarshalVectors(evmroot.BuildVectors())
	if err != nil {
		fmt.Fprintln(os.Stderr, "d1vectors:", err)
		os.Exit(1)
	}

	if !*update {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "d1vectors:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // world-readable test fixture
		fmt.Fprintln(os.Stderr, "d1vectors:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote", *out)
}
