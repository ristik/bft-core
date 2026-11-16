// Command nb2vectors writes the native bridge v2 vector file and its digest:
//
//	go run ./nb2ref/cmd/nb2vectors -out <native-bridge-plugins>/protocol/vectors/nb2
//
// It writes nb2-vectors.json and nb2-vectors.json.sha256 (the SHA-256 of the file, hex, newline). The output is a pure function of
// the code: rerunning it reproduces the same bytes. nb2ref/testdata/nb2-vectors.json.sha256 pins the digest in bft-core.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-core/nb2ref"
)

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()
	f, err := nb2ref.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := f.Encode()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	digest := nb2ref.Digest(b)
	if err := os.WriteFile(filepath.Join(*out, "nb2-vectors.json"), b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*out, "nb2-vectors.json.sha256"), []byte(digest+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%s  nb2-vectors.json (%d bytes, %d verifier, %d seal receipt, %d gap, %d fold, %d vault vectors)\n", digest, len(b),
		len(f.Verifier), len(f.Seal), len(f.Gap), len(f.Folds), len(f.Vault))
}
