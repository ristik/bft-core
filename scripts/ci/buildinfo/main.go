// Command buildinfo prints the module and build information embedded in Go binaries, in the format of `go version -m`, so a CI run job can verify a
// downloaded binary's vcs.revision and vcs.modified without a Go toolchain.
package main

import (
	"debug/buildinfo"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: buildinfo FILE...")
		os.Exit(2)
	}
	rc := 0
	for _, f := range os.Args[1:] {
		bi, err := buildinfo.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "buildinfo: %s: %v\n", f, err)
			rc = 1
			continue
		}
		// `go version -m` prints "<file>: <go version>" and then the module lines indented by a tab
		fmt.Printf("%s: %s\n", f, bi.GoVersion)
		for _, l := range splitLines(bi.String()) {
			fmt.Println(l)
		}
	}
	os.Exit(rc)
}

// splitLines drops the leading "go<version>" line of buildinfo.String (already printed) and keeps the module lines.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	if len(out) > 0 {
		out = out[1:]
	}
	return out
}
