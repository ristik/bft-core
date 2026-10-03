// Command b1vectors writes the B1 builtin test-vector manifest for a seed.
//
//	go run ./cmd/b1vectors -seed b1-oracle-v1 -out b1ref/testdata/b1-vectors-v1.json
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

func main() {
	seed := flag.String("seed", "b1-oracle-v1", "explicit seed for every key, hash and tree")
	out := flag.String("out", "", "output file (default stdout)")
	flag.Parse()
	b, err := b1gen.Build(*seed).JSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "" {
		os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
