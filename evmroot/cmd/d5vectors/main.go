// Command d5vectors regenerates the D5 accountability / retirement / inbox vector set.
//
//	go run ./evmroot/cmd/d5vectors            # print to stdout
//	go run ./evmroot/cmd/d5vectors -update    # overwrite evmroot/testdata/d5-vectors.json
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/evmroot"
)

func main() {
	update := flag.Bool("update", false, "overwrite evmroot/testdata/d5-vectors.json instead of printing")
	out := flag.String("o", "evmroot/testdata/d5-vectors.json", "path to write when -update is set")
	flag.Parse()

	data, err := evmroot.MarshalD5Vectors(evmroot.BuildD5Vectors())
	if err != nil {
		fmt.Fprintln(os.Stderr, "d5vectors:", err)
		os.Exit(1)
	}
	if !*update {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "d5vectors:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // world-readable test fixture
		fmt.Fprintln(os.Stderr, "d5vectors:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote", *out)
}
