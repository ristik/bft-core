package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
)

// newPosCandidateCmd is `ubft pos-relayer candidate`: the primary candidate (canonical encoding) of an assembled plan, built the way a root
// builds it for the Prepare, so the members can sign their EVM possession proofs over it (`pos-relayer sign-pop --candidate`) before the
// proofs are submitted to the election. Nothing here is authoritative: the root rebuilds the candidate from the plan it is given.
func newPosCandidateCmd() *cobra.Command {
	var contextFile, assignment, nextTrustBase, out string
	cmd := &cobra.Command{
		Use:   "candidate",
		Short: "build the primary candidate of an assembled plan, for signing the members' EVM possession proofs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, pop, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			proposal, err := readEVMAssignment(assignment)
			if err != nil {
				return err
			}
			if proposal.Kind == evmassign.KindRecovery {
				return fmt.Errorf("%w: a recovery has no possession proofs to sign", ErrPosRelayer)
			}
			tb, err := readTrustBase(nextTrustBase)
			if err != nil {
				return err
			}
			var next []evmassign.RootMember
			for _, n := range tb.RootNodes {
				next = append(next, evmassign.RootMember{NodeID: n.NodeID, Key: append([]byte(nil), n.SigKey...), Weight: n.Stake})
			}
			sortRootMembers(next)
			succ, err := evmassign.NewSuccessor(c.Installed, proposal.Validators)
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			lc := evmassign.Lifecycle{Kind: evmassign.KindPrimary, Identities: proposal.Identities, Authorization: proposal.Authorization}
			cand, err := evmassign.NewCandidateWith(weightvalidation.EVMRules(weightvalidation.ModeWeighted), pop, next, c.Installed, succ, proposal.PoPs, nil,
				proposal.Bindings, lc, proposal.Changes)
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			enc, err := cand.Encode()
			if err != nil {
				return errors.Join(ErrPosRelayer, err)
			}
			return os.WriteFile(out, []byte(hex.EncodeToString(enc)+"\n"), 0o600)
		},
	}
	cmd.Flags().StringVar(&contextFile, "context", "", "the context JSON from `root handoff evm-context`")
	cmd.Flags().StringVar(&assignment, "assignment", "", "the assembled plan (`root handoff evm-assemble --out`), without the EVM possession proofs yet")
	cmd.Flags().StringVar(&nextTrustBase, "next-trust-base", "", "the next root trust base (its members are the candidate's root members)")
	cmd.Flags().StringVar(&out, "out", "", "output file (hex)")
	for _, f := range []string{"context", "assignment", "next-trust-base", "out"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func sortRootMembers(m []evmassign.RootMember) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0 && m[j].NodeID < m[j-1].NodeID; j-- {
			m[j], m[j-1] = m[j-1], m[j]
		}
	}
}
