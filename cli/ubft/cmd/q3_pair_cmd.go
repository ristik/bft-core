package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/engineapi"
)

// The pair commands of the Q3 acceptance lane read what a co-hosted BFT/EVM pair retained, show the exact refusal of a tampered binding,
// and drive the restart admission. They talk to one execution client and nothing else.

func readJWTSecret(path string) (engineapi.Secret, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local secret file
	if err != nil {
		return engineapi.Secret{}, err
	}
	return engineapi.ParseSecret(string(raw))
}

func newQ3PairCmds() []*cobra.Command {
	var ethURL, engineURL, jwtFile string

	var number uint64
	var rootInputOut, transitionsOut, stateOut string
	export := &cobra.Command{Use: "pair-export", Short: "Write what a pair retained for a block: its canonical root input, its transition bytes and its execution state",
		Long: "Reads the root input and transition bytes the pair's execution client retained in the block's companion, and the block's execution\n" +
			"head, state root and number. Two pairs that verified the same history independently export identical bytes for the same block.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			latest := !cmd.Flags().Changed("block-number")
			e, err := engineapi.ExportPairBlock(cmd.Context(), ethURL, number, latest)
			if err != nil {
				return err
			}
			if err := os.WriteFile(rootInputOut, e.RootInput, 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(transitionsOut, e.Transitions, 0o600); err != nil {
				return err
			}
			return writeJSONFile(stateOut, map[string]any{"number": e.Number, "head": "0x" + hex.EncodeToString(e.Head[:]),
				"parent": "0x" + hex.EncodeToString(e.Parent[:]), "stateRoot": "0x" + hex.EncodeToString(e.StateRoot[:])})
		}}
	export.Flags().StringVar(&ethURL, "eth-url", "", "the pair's execution client plain endpoint")
	export.Flags().Uint64Var(&number, "block-number", 0, "the block to export (default: the latest)")
	export.Flags().StringVar(&rootInputOut, "root-input-out", "", "file for the canonical root input")
	export.Flags().StringVar(&transitionsOut, "transitions-out", "", "file for the canonical transition array")
	export.Flags().StringVar(&stateOut, "state-out", "", "file for the block's {number, head, parent, stateRoot} JSON")
	for _, f := range []string{"eth-url", "root-input-out", "transitions-out", "state-out"} {
		_ = export.MarkFlagRequired(f)
	}

	var kind string
	control := &cobra.Command{Use: "pair-control", Short: "Submit the pair's latest build with exactly one thing changed and report the execution client's answer",
		Long: "Kinds: accept (nothing changed; must be accepted), wrong-parent, wrong-job, substituted-input, missing-evidence. A refused control\n" +
			"prints the execution client's refusal (its typed cause) and exits non-zero; an accepted one exits zero. A control job that is accepted\n" +
			"starts a payload build that nothing collects.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, err := readJWTSecret(jwtFile)
			if err != nil {
				return err
			}
			out, err := engineapi.RunPairControl(cmd.Context(), engineURL, secret, ethURL, engineapi.PairControl(kind))
			if err != nil {
				return err
			}
			if out.Accepted {
				note := ""
				if out.GateOnly {
					note = " by the pair gate (the engine then refused the build below its finalized block: " + strings.TrimSpace(out.Detail) + ")"
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "pair control %s: accepted%s\n", kind, note)
				return err
			}
			return fmt.Errorf("pair control %s: refused: %s", kind, strings.TrimSpace(out.Detail))
		}}
	control.Flags().StringVar(&kind, "kind", "", "accept | wrong-parent | wrong-job | substituted-input | missing-evidence")
	control.Flags().StringVar(&engineURL, "engine-url", "", "the pair's execution client Engine endpoint")
	control.Flags().StringVar(&jwtFile, "jwt-secret", "", "the Engine endpoint's JWT secret file")
	control.Flags().StringVar(&ethURL, "eth-url", "", "the pair's execution client plain endpoint")
	for _, f := range []string{"kind", "engine-url", "jwt-secret", "eth-url"} {
		_ = control.MarkFlagRequired(f)
	}

	admit := &cobra.Command{Use: "pair-admit", Short: "Present the pair's latest block to its execution client's restart admission",
		Long: "After a restart the execution client resolves no cached accounting until the head is admitted. This presents the binding the client\n" +
			"retained for its latest block, as an import binding of that block: it exercises the client's gate. It is the OPERATOR presenting the\n" +
			"retained evidence, not the node's own reauthentication of the head from its verified history, which a real restart must supply.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, err := readJWTSecret(jwtFile)
			if err != nil {
				return err
			}
			if err := engineapi.AdmitHeadFromRetained(cmd.Context(), engineURL, secret, ethURL); err != nil {
				return errors.New("restart admission refused: " + err.Error())
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "restart admission: head admitted (presented by the operator from retained evidence)")
			return err
		}}
	admit.Flags().StringVar(&engineURL, "engine-url", "", "the pair's execution client Engine endpoint")
	admit.Flags().StringVar(&jwtFile, "jwt-secret", "", "the Engine endpoint's JWT secret file")
	admit.Flags().StringVar(&ethURL, "eth-url", "", "the pair's execution client plain endpoint")
	for _, f := range []string{"engine-url", "jwt-secret", "eth-url"} {
		_ = admit.MarkFlagRequired(f)
	}
	return []*cobra.Command{export, control, admit}
}
