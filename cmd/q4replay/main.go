// Command q4replay checks exported Q4 #51 run bundles offline, independently of the run that produced them (see
// rootchain/consensus/q4replay). It is a test-evidence tool and is not part of the ubft binary.
//
//	q4replay check [-equivocators a,b] bundle.json...
//
// It prints one JSON report per bundle and exits 1 if any bundle violates a check, 2 on a usage or read error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4replay"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut *os.File) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(errOut, "usage: q4replay check [-equivocators a,b] bundle.json...")
		return 2
	}
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	eq := fs.String("equivocators", "", "comma separated member names that must be exactly the recomputed equivocators (omit for no claim)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() == 0 {
		return 2
	}
	status := 0
	for _, path := range fs.Args() {
		b, err := q4replay.Load(path)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		rep := q4replay.Check(b)
		if *eq != "" {
			names := strings.Split(*eq, ",")
			if err := rep.ExpectEquivocators(names...); err != nil {
				rep.Errors = append(rep.Errors, err.Error())
			}
		}
		raw, _ := json.MarshalIndent(map[string]any{"bundle": path, "ok": rep.Err() == nil && len(rep.Errors) == 0, "report": rep}, "", " ")
		fmt.Fprintln(out, string(raw))
		if rep.Err() != nil || len(rep.Errors) != 0 {
			status = 1
		}
	}
	return status
}
