// pos-supply-auditor reads a standard genesis file and a full-state accounting snapshot.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/unicitynetwork/bft-core/supplyaudit"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pos-supply-auditor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	genesisPath := flags.String("genesis", "", "standard genesis JSON file")
	snapshotPath := flags.String("state-dump", "", "complete certified-block state/accounting snapshot JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *genesisPath == "" || *snapshotPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: pos-supply-auditor --genesis genesis.json --state-dump certified-state.json")
		return 2
	}
	genesis, err := os.ReadFile(*genesisPath)
	if err != nil {
		return writeInputError(stdout, fmt.Errorf("read genesis: %w", err))
	}
	snapshot, err := os.ReadFile(*snapshotPath)
	if err != nil {
		return writeInputError(stdout, fmt.Errorf("read state dump: %w", err))
	}
	result, err := supplyaudit.Audit(genesis, snapshot)
	if err != nil {
		return writeInputError(stdout, err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return 2
	}
	switch result.Status {
	case "pass":
		return 0
	case "fail":
		return 1
	case "inconclusive":
		return 2
	default:
		fmt.Fprintf(stderr, "unexpected audit status %q\n", result.Status)
		return 2
	}
}

func writeInputError(w io.Writer, err error) int {
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}{"invalid", err.Error()})
	if errors.Is(err, supplyaudit.ErrInput) {
		return 2
	}
	return 2
}
