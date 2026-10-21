// Command genbench writes the BRIDGE_COMPOSE_V1 benchmark cases of B7 PR 3 (briefs/dev4-b7-pr3-plan.md) as one JSON array: each case's
// compose input, the registry words and pins its B1 reads, and the oracle's status and gas with real B1.
//
//	go run ./cmd/genbench -out cases.json [case ...]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/unicitynetwork/bft-core/bridgeprofile"
)

func main() {
	out := flag.String("out", "", "file to write the cases to (required)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "genbench: -out is required")
		os.Exit(2)
	}
	cases, err := bridgeprofile.BenchCases(flag.Args()...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genbench:", err)
		os.Exit(1)
	}
	b, err := json.Marshal(cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genbench:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "genbench:", err)
		os.Exit(1)
	}
	for _, c := range cases {
		fmt.Printf("%-22s leaves %4d anchors %4d input %8d gas %10d status %d\n", c.ID, c.Leaves, c.Anchors, c.InputBytes, c.Gas, c.Status)
	}
}
