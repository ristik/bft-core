// Command d4vectors prints the independent D4 proof and trace vector set.
// Regenerate it with: go run ./evmroot/testdata/generate_d4_vectors.go
package main

import (
	"fmt"
	"os"
)

func main() {
	b, e := os.ReadFile("evmroot/testdata/d4-vectors.json")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}
