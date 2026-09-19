// Command p1matrix regenerates the P1 staking-component reuse matrix fixture.
//
//	go run ./evmroot/cmd/p1matrix            # print to stdout
//	go run ./evmroot/cmd/p1matrix -update    # overwrite evmroot/testdata/p1-reuse-matrix.json
//
// The matrix is also validated (evmroot.ReuseMatrix.Validate) before it is
// printed or written, so a broken assessment fails here too, not only in the
// test.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/evmroot"
)

func main() {
	update := flag.Bool("update", false, "overwrite evmroot/testdata/p1-reuse-matrix.json instead of printing")
	out := flag.String("o", "evmroot/testdata/p1-reuse-matrix.json", "path to write when -update is set")
	flag.Parse()

	m := evmroot.BuildP1ReuseMatrix()
	if err := m.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "p1matrix: assessment is inconsistent:", err)
		os.Exit(1)
	}
	data, err := evmroot.MarshalP1ReuseMatrix(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "p1matrix:", err)
		os.Exit(1)
	}
	if !*update {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "p1matrix:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // world-readable fixture
		fmt.Fprintln(os.Stderr, "p1matrix:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote", *out)
}
