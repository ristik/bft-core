package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-go-base/types"
)

// evmAssignmentContextOperator is the local read of the possession-proof context.
type evmAssignmentContextOperator interface {
	EVMAssignmentContext(frozenParent []byte) (consensus.EVMAssignmentContext, error)
}

type evmContextRequest struct {
	FrozenParent string `json:"frozenParent"`
}

func rootHandoffEVMContextHandler(operator evmAssignmentContextOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var request evmContextRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&request) != nil {
			http.Error(w, "invalid EVM assignment context request", http.StatusBadRequest)
			return
		}
		parent, err := parseHandoffID(request.FrozenParent)
		if err != nil {
			http.Error(w, "invalid frozen parent", http.StatusBadRequest)
			return
		}
		out, err := operator.EVMAssignmentContext(parent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// readEVMAssignment reads an operator's proposal file and rejects an unusable shape early. Everything in it is
// re-verified by the root validators; the CLI check only avoids a wasted round trip.
func readEVMAssignment(path string) (*evmassign.Proposal, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, fmt.Errorf("reading --next-evm-assignment %q: %w", path, err)
	}
	var p evmassign.Proposal
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("decoding --next-evm-assignment %q: %w", path, err)
	}
	if len(p.Validators) == 0 {
		return nil, errors.New("--next-evm-assignment names no successor validators")
	}
	if len(p.Bindings) != len(p.Validators) {
		return nil, fmt.Errorf("--next-evm-assignment has %d root-entity bindings for %d successor validators: every validator is the delegated EVM key of one root entity", len(p.Bindings), len(p.Validators))
	}
	if len(p.PoPs) != len(p.Validators) {
		return nil, fmt.Errorf("--next-evm-assignment has %d proofs of possession for %d successor validators: every successor key, retained ones included, must prove possession", len(p.PoPs), len(p.Validators))
	}
	return &p, nil
}

// checkCoupledProposal refuses before any endorsement a proposal whose EVM participants are not the coupled image of the
// next root committee (one delegated EVM key per root entity, same weight, distinct keys).
func checkCoupledProposal(next *types.RootTrustBaseV1, p *evmassign.Proposal) error {
	root := make([]evmassign.RootMember, 0, len(next.RootNodes))
	for _, n := range next.RootNodes {
		if n == nil {
			return errors.New("--next-trust-base has an empty root node")
		}
		root = append(root, evmassign.RootMember{NodeID: n.NodeID, Key: n.SigKey, Weight: n.Stake})
	}
	sort.Slice(root, func(i, j int) bool { return root[i].NodeID < root[j].NodeID })
	succ := &types.PartitionDescriptionRecord{Validators: p.Validators}
	if err := evmassign.ValidateCoupling(root, succ, p.Bindings); err != nil {
		return fmt.Errorf("--next-evm-assignment is not coupled to --next-trust-base (validator-set changes are always coupled): %w", err)
	}
	return nil
}

func readBindings(path string) ([]evmassign.Binding, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var b []evmassign.Binding
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("decoding bindings %q: %w", path, err)
	}
	sort.Slice(b, func(i, j int) bool { return b[i].RootNodeID < b[j].RootNodeID })
	return b, nil
}

func newEVMContextCmd() *cobra.Command {
	var parent, rootRPC, out string
	cmd := &cobra.Command{Use: "evm-context", Short: "Print the proof-of-possession context for a prospective EVM assignment change",
		Long: "Reads the possession-proof context (network, predecessor root body, attempt, frozen parent) and the installed EVM assignment from a\n" +
			"local old validator. Every successor key signs a message over exactly this context (`handoff evm-pop`), so a proof cannot be\n" +
			"replayed for another attempt, predecessor or frozen parent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := json.Marshal(evmContextRequest{FrozenParent: parent})
			if err != nil {
				return err
			}
			endpoint := strings.TrimRight(strings.Split(rootRPC, ",")[0], "/") + "/api/v1/handoff/evm-assignment/context"
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			var result consensus.EVMAssignmentContext
			if err := handoffPost(ctx, &http.Client{Timeout: 10 * time.Second}, endpoint, body, &result); err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				return os.WriteFile(out, encoded, 0o600)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
			return err
		}}
	cmd.Flags().StringVar(&parent, "frozen-parent", "", "certified EVM parent block hash (32-byte hex) the handoff will freeze")
	cmd.Flags().StringVar(&rootRPC, "root-rpc", "", "local old validator RPC URL")
	cmd.Flags().StringVar(&out, "out", "", "write the context JSON here instead of stdout")
	_ = cmd.MarkFlagRequired("frozen-parent")
	_ = cmd.MarkFlagRequired("root-rpc")
	return cmd
}

func readContextFile(path string) (consensus.EVMAssignmentContext, evmassign.PoPContext, error) {
	var c consensus.EVMAssignmentContext
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return c, evmassign.PoPContext{}, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, evmassign.PoPContext{}, fmt.Errorf("decoding context %q: %w", path, err)
	}
	if len(c.Predecessor) != 32 || len(c.FrozenParent) != 32 || c.Installed == nil {
		return c, evmassign.PoPContext{}, fmt.Errorf("context %q is incomplete", path)
	}
	pop := evmassign.PoPContext{Network: c.Network, Attempt: c.Attempt}
	copy(pop.Predecessor[:], c.Predecessor)
	copy(pop.Parent[:], c.FrozenParent)
	return c, pop, nil
}

func readValidators(path string) ([]*types.NodeInfo, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var v []*types.NodeInfo
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decoding validators %q: %w", path, err)
	}
	return v, nil
}

func newEVMPoPCmd() *cobra.Command {
	var contextFile, validatorsFile, nodeID, keyFile string
	cmd := &cobra.Command{Use: "evm-pop", Short: "Sign a proof of possession for one successor EVM validator key",
		Long: "Run by the holder of a successor signing key, offline. It signs the domain-separated possession message for the successor\n" +
			"assignment and the context printed by `handoff evm-context`. Retained keys must sign too.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, pop, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			validators, err := readValidators(validatorsFile)
			if err != nil {
				return err
			}
			succ, err := evmassign.NewSuccessor(c.Installed, validators)
			if err != nil {
				return err
			}
			if err := evmassign.ValidateAssignment(succ); err != nil {
				return err
			}
			raw, err := os.ReadFile(keyFile) // #nosec G304 -- operator supplied local key file
			if err != nil {
				return err
			}
			var conf KeyConf
			if err := json.Unmarshal(raw, &conf); err != nil {
				return fmt.Errorf("decoding key configuration %q: %w", keyFile, err)
			}
			signer, err := conf.Signer()
			if err != nil {
				return err
			}
			var validator *types.NodeInfo
			for _, v := range succ.Validators {
				if v.NodeID == nodeID {
					validator = v
				}
			}
			if validator == nil {
				return fmt.Errorf("node %q is not a successor validator", nodeID)
			}
			proof, err := evmassign.SignPoP(signer, pop, succ, nodeID)
			if err != nil {
				return err
			}
			// The key must be the validator's own: refuse to hand out a proof that would be rejected later.
			if !bytes.Equal(proof.Key, validator.SigKey) {
				return fmt.Errorf("the signing key is not the successor key of node %q", nodeID)
			}
			encoded, err := json.MarshalIndent(proof, "", "  ")
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
			return err
		}}
	cmd.Flags().StringVar(&contextFile, "context", "", "context JSON from `handoff evm-context`")
	cmd.Flags().StringVar(&validatorsFile, "validators", "", "JSON array of the successor validators (nodeId, sigKey, stake)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "successor validator this key belongs to")
	cmd.Flags().StringVar(&keyFile, "key-conf", "", "key configuration holding the validator's signing key")
	for _, f := range []string{"context", "validators", "node-id", "key-conf"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func newEVMAssembleCmd() *cobra.Command {
	var contextFile, validatorsFile, pops, out, bindingsFile string
	var supersede bool
	cmd := &cobra.Command{Use: "evm-assemble", Short: "Collect proofs of possession into a --next-evm-assignment file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, pop, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			validators, err := readValidators(validatorsFile)
			if err != nil {
				return err
			}
			succ, err := evmassign.NewSuccessor(c.Installed, validators)
			if err != nil {
				return err
			}
			byID := map[string]evmassign.PoP{}
			for _, path := range strings.Split(pops, ",") {
				raw, err := os.ReadFile(strings.TrimSpace(path)) // #nosec G304 -- operator supplied local file
				if err != nil {
					return err
				}
				var p evmassign.PoP
				if err := json.Unmarshal(raw, &p); err != nil {
					return fmt.Errorf("decoding proof %q: %w", path, err)
				}
				byID[p.NodeID] = p
			}
			ordered := make([]evmassign.PoP, 0, len(succ.Validators))
			for _, v := range succ.Validators {
				p, ok := byID[v.NodeID]
				if !ok {
					return fmt.Errorf("no proof of possession for successor validator %q", v.NodeID)
				}
				ordered = append(ordered, p)
			}
			if err := evmassign.VerifyPoPs(pop, succ, ordered); err != nil {
				return err
			}
			if supersede && !c.Pending {
				return errors.New("--supersede needs an installed assignment whose acknowledgement is pending")
			}
			bindings, err := readBindings(bindingsFile)
			if err != nil {
				return err
			}
			if len(bindings) != len(succ.Validators) {
				return fmt.Errorf("%d bindings for %d successor validators", len(bindings), len(succ.Validators))
			}
			encoded, err := json.MarshalIndent(evmassign.Proposal{Validators: succ.Validators, PoPs: ordered, Supersede: supersede, Bindings: bindings}, "", "  ")
			if err != nil {
				return err
			}
			if out == "" {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return err
			}
			if err := os.WriteFile(out, encoded, 0o600); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s: assignment epoch %d for %d validators, %s\n", out, succ.Epoch, len(succ.Validators),
				"assignment hash "+mustAssignmentHash(succ))
			return err
		}}
	cmd.Flags().StringVar(&contextFile, "context", "", "context JSON from `handoff evm-context`")
	cmd.Flags().StringVar(&validatorsFile, "validators", "", "JSON array of the successor validators")
	cmd.Flags().StringVar(&pops, "pops", "", "comma-separated proof-of-possession JSON files, one per successor validator")
	cmd.Flags().StringVar(&out, "out", "", "output file for --next-evm-assignment (default: stdout)")
	cmd.Flags().StringVar(&bindingsFile, "bindings", "", "JSON array of {rootNodeId, evmNodeId}: the delegated EVM validator of each successor root entity")
	cmd.Flags().BoolVar(&supersede, "supersede", false, "replace the installed assignment, whose acknowledgement is still pending, on the same frozen parent")
	for _, f := range []string{"context", "validators", "pops", "bindings"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func mustAssignmentHash(succ *types.PartitionDescriptionRecord) string {
	h, err := evmassign.AssignmentHash(succ)
	if err != nil {
		return "unavailable"
	}
	return "0x" + hex.EncodeToString(h[:])
}
