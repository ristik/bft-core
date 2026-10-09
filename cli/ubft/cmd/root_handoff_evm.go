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
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// evmAssignmentContextOperator is the local read of the possession-proof context.
type evmAssignmentContextOperator interface {
	EVMAssignmentContext() (consensus.EVMAssignmentContext, error)
}

func rootHandoffEVMContextHandler(operator evmAssignmentContextOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		out, err := operator.EVMAssignmentContext()
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
	if p.Kind == evmassign.KindRecovery {
		// A recovery is derived from the committed primary: nothing else may be supplied.
		if len(p.Validators) != 0 || len(p.Bindings) != 0 || len(p.PoPs) != 0 || len(p.Identities) != 0 || p.Authorization != nil || !p.Supersede {
			return nil, errors.New("--next-evm-assignment of kind recovery is derived and supersedes: it carries no validators, bindings, proofs, identities or authorization")
		}
		return &p, nil
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
	if len(p.Identities) != len(p.Validators) || p.Authorization == nil {
		return nil, errors.New("--next-evm-assignment needs one identity record per successor validator and the recovery authorization")
	}
	return &p, nil
}

// checkCoupledProposal refuses before any endorsement a proposal whose EVM participants are not the coupled image of the
// next root committee (one delegated EVM key per root entity, same weight, distinct keys). A recovery is derived by the root and is not checked here.
func checkCoupledProposal(next *types.RootTrustBaseV1, p *evmassign.Proposal) error {
	if p.Kind == evmassign.KindRecovery {
		// A recovery carries no validators or bindings: the root derives exactly K from the committed primary and verifies the coupling of that derived
		// set to the next committee itself. There is nothing here to compare, and an empty set is not an uncoupled one.
		return nil
	}
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

func readInstalledPDR(path string) (*types.PartitionDescriptionRecord, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var pdr types.PartitionDescriptionRecord
	if err := json.Unmarshal(raw, &pdr); err != nil {
		return nil, fmt.Errorf("decoding installed shard configuration %q: %w", path, err)
	}
	return &pdr, nil
}

func readChange(path string) (evmassign.Change, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return evmassign.Change{}, err
	}
	var ch evmassign.Change
	if err := json.Unmarshal(raw, &ch); err != nil {
		return ch, fmt.Errorf("decoding change %q: %w", path, err)
	}
	return ch, nil
}

// newShardAssembleCmd assembles one aggregator node-key replacement: the successor of the installed shard configuration (only
// validators and epoch change; proof_type and every other setting are carried unchanged) and one possession proof per key.
func newShardAssembleCmd() *cobra.Command {
	var contextFile, installedFile, validatorsFile, pops, out string
	cmd := &cobra.Command{Use: "shard-assemble", Short: "Assemble an aggregator node-key replacement for a handoff",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, pop, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			installed, err := readInstalledPDR(installedFile)
			if err != nil {
				return err
			}
			validators, err := readValidators(validatorsFile)
			if err != nil {
				return err
			}
			succ, err := evmassign.NewSuccessor(installed, validators)
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
			change, err := evmassign.EncodeReplaceShardValidators(installed.PartitionID, installed.ShardID, installed, succ, ordered)
			if err != nil {
				return err
			}
			if _, err := evmassign.ValidateChanges([]evmassign.Change{change}, nil, pop, evmroot.D4ControlPartition); err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(change, "", "  ")
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
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s: partition %d shard epoch %d for %d validators\n", out, succ.PartitionID, succ.Epoch, len(succ.Validators))
			return err
		}}
	cmd.Flags().StringVar(&contextFile, "context", "", "context JSON from `handoff evm-context` (the possession context of this attempt)")
	cmd.Flags().StringVar(&installedFile, "installed", "", "installed shard configuration JSON of the aggregator shard")
	cmd.Flags().StringVar(&validatorsFile, "validators", "", "JSON array of the successor validators (nodeId, sigKey, stake)")
	cmd.Flags().StringVar(&pops, "pops", "", "comma-separated proof-of-possession files from `handoff evm-pop --installed`, one per successor validator")
	cmd.Flags().StringVar(&out, "out", "", "output file (default: stdout)")
	for _, f := range []string{"context", "installed", "validators", "pops"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func newEVMContextCmd() *cobra.Command {
	var rootRPC, out string
	cmd := &cobra.Command{Use: "evm-context", Short: "Print the proof-of-possession context for a prospective EVM assignment change",
		Long: "Reads the possession-proof context (network, predecessor root body, attempt) and the installed EVM assignment from a\n" +
			"local old validator. Every successor key signs a message over exactly this context (`handoff evm-pop`), so a proof cannot be\n" +
			"replayed for another attempt or predecessor. It names no EVM parent: the root binds the frozen parent when it orders the\n" +
			"Prepare, after the proofs are collected.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			body := []byte("{}")
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
	cmd.Flags().StringVar(&rootRPC, "root-rpc", "", "local old validator RPC URL")
	cmd.Flags().StringVar(&out, "out", "", "write the context JSON here instead of stdout")
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
	if len(c.Predecessor) != 32 || c.Installed == nil {
		return c, evmassign.PoPContext{}, fmt.Errorf("context %q is incomplete", path)
	}
	pop := evmassign.PoPContext{Network: c.Network, Attempt: c.Attempt}
	copy(pop.Predecessor[:], c.Predecessor)
	return c, pop, nil
}

// readIdentities reads the frozen identity records a primary assignment commits to (operator payees included) and returns them with
// their digest, the value every possession proof signs.
func readIdentities(path string) ([]evmassign.Identity, [32]byte, error) {
	var none [32]byte
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, none, err
	}
	var ids []evmassign.Identity
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, none, fmt.Errorf("decoding identities %q: %w", path, err)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i].StakingID, ids[j].StakingID) < 0 })
	digest, err := evmassign.IdentitiesDigest(ids)
	return ids, digest, err
}

func readAuthorization(path string) (*evmassign.Authorization, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var a evmassign.Authorization
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("decoding authorization %q: %w", path, err)
	}
	return &a, nil
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

// errBothKeyHolders refuses a possession proof request that names two holders for one key.
var errBothKeyHolders = errors.New("give either --key-conf or the signing authority flags, not both: a key is signed for by exactly one holder")

func newEVMPoPCmd() *cobra.Command {
	var contextFile, validatorsFile, nodeID, keyFile, installedFile, authoritySocket, authorityCredential, identitiesFile string
	cmd := &cobra.Command{Use: "evm-pop", Short: "Sign a proof of possession for one successor EVM validator key",
		Long: "Run by the holder of a successor signing key, offline. It signs the domain-separated possession message for the successor\n" +
			"assignment and the context printed by `handoff evm-context`. Retained keys must sign too.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, pop, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			if installedFile == "" { // an EVM assignment proof signs the identity records, operator payees included
				if identitiesFile == "" {
					return errors.New("--identities is required: a possession proof signs the frozen identity records")
				}
				if _, pop.Identities, err = readIdentities(identitiesFile); err != nil {
					return err
				}
			}
			validators, err := readValidators(validatorsFile)
			if err != nil {
				return err
			}
			installed := c.Installed
			if installedFile != "" { // an aggregator shard's installed configuration instead of the EVM one
				if installed, err = readInstalledPDR(installedFile); err != nil {
					return err
				}
			}
			succ, err := evmassign.NewSuccessor(installed, validators)
			if err != nil {
				return err
			}
			// the weighted bounds, not the unit rule: the proof only proves possession, and the root judges the assignment under the mode of
			// the epoch it is installed in (a weighted rotation from a unit epoch signs weights the unit rule would refuse)
			if err := evmassign.ValidateAssignmentWith(weightvalidation.EVMRules(weightvalidation.ModeWeighted), succ); err != nil {
				return err
			}
			if keyFile != "" && (authoritySocket != "" || authorityCredential != "") {
				return errBothKeyHolders
			}
			if authoritySocket != "" && authorityCredential == "" {
				return errors.New("--authority-socket needs --authority-credential")
			}
			var signer abcrypto.Signer
			if authoritySocket == "" {
				if keyFile == "" {
					return errors.New("give --key-conf, or --authority-socket and --authority-credential for an authority-backed validator")
				}
				raw, err := os.ReadFile(keyFile) // #nosec G304 -- operator supplied local key file
				if err != nil {
					return err
				}
				var conf KeyConf
				if err := json.Unmarshal(raw, &conf); err != nil {
					return fmt.Errorf("decoding key configuration %q: %w", keyFile, err)
				}
				if signer, err = conf.Signer(); err != nil {
					return err
				}
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
			var proof evmassign.PoP
			if authoritySocket != "" {
				// An authority-backed validator's key never leaves its signing authority: the operator channel signs the proof for
				// its own key, in this context and for this successor binding, and nothing else.
				credential, err := readCredentialFile(authorityCredential)
				if err != nil {
					return fmt.Errorf("loading the authority operator credential: %w", err)
				}
				operator, err := service.NewOperatorClient(service.ClientConfig{Dial: service.UnixDialer(authoritySocket), Credential: credential, Timeout: 15 * time.Second})
				if err != nil {
					return err
				}
				defer func() { _ = operator.Close() }()
				if proof, err = operator.SignHandoffPoP(cmd.Context(), signingauthority.HandoffPoPRequest{Domain: evmassign.PoPDomain, Context: pop, Successor: succ, NodeID: nodeID}); err != nil {
					return fmt.Errorf("the signing authority refused the possession proof: %w", err)
				}
			} else if proof, err = evmassign.SignPoP(signer, pop, succ, nodeID); err != nil {
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
	cmd.Flags().StringVar(&installedFile, "installed", "", "installed shard configuration JSON of an aggregator shard whose node keys are replaced (default: the EVM assignment in the context)")
	cmd.Flags().StringVar(&identitiesFile, "identities", "", "JSON array of the successor's frozen identity records (staking id, bindings, weight, operator payee, exposure)")
	cmd.Flags().StringVar(&authoritySocket, "authority-socket", "", "operator socket of the validator's signing authority (instead of --key-conf)")
	cmd.Flags().StringVar(&authorityCredential, "authority-credential", "", "path to the signing authority's operator credential")
	for _, f := range []string{"context", "validators", "node-id"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func newEVMAssembleCmd() *cobra.Command {
	var contextFile, validatorsFile, pops, out, bindingsFile, changesFiles, identitiesFile, authorizationFile, evmPopsFile string
	var supersede, recovery bool
	cmd := &cobra.Command{Use: "evm-assemble", Short: "Collect proofs of possession into a --next-evm-assignment file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, pop, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			if recovery {
				if !supersede || !c.Pending {
					return errors.New("--recovery replaces the installed, unacknowledged primary: give --supersede on a pending assignment")
				}
				return writeProposal(cmd, out, evmassign.Proposal{Kind: evmassign.KindRecovery, Supersede: true}, "recovery (derived from the committed primary)")
			}
			if identitiesFile == "" || authorizationFile == "" || validatorsFile == "" || pops == "" || bindingsFile == "" {
				return errors.New("--identities, --authorization, --validators, --pops and --bindings are required for a primary assignment")
			}
			identities, identitiesDigest, err := readIdentities(identitiesFile)
			if err != nil {
				return err
			}
			pop.Identities = identitiesDigest
			authorization, err := readAuthorization(authorizationFile)
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
			var changes []evmassign.Change
			for _, path := range strings.Split(changesFiles, ",") {
				if strings.TrimSpace(path) == "" {
					continue
				}
				ch, err := readChange(strings.TrimSpace(path))
				if err != nil {
					return err
				}
				changes = append(changes, ch)
			}
			if supersede && len(changes) != 0 {
				return errors.New("--changes cannot accompany --supersede: a supersession carries no aggregator changes")
			}
			aggregatorPop := pop
			aggregatorPop.Identities = [32]byte{} // an aggregator replacement has no identity records
			if _, err := evmassign.ValidateChanges(changes, nil, aggregatorPop, evmroot.D4ControlPartition); err != nil {
				return err
			}
			var evmPops []evmassign.EVMPoP
			if evmPopsFile != "" {
				if evmPops, err = readEVMPoPs(evmPopsFile); err != nil {
					return err
				}
			}
			return writeProposal(cmd, out, evmassign.Proposal{Kind: evmassign.KindPrimary, Validators: succ.Validators, PoPs: ordered, Supersede: supersede,
				Bindings: bindings, Changes: changes, Identities: identities, Authorization: authorization, EVMPoPs: evmPops},
				fmt.Sprintf("assignment epoch %d for %d validators, assignment hash %s", succ.Epoch, len(succ.Validators), mustAssignmentHash(succ, identitiesDigest)))
		}}
	cmd.Flags().StringVar(&contextFile, "context", "", "context JSON from `handoff evm-context`")
	cmd.Flags().StringVar(&validatorsFile, "validators", "", "JSON array of the successor validators")
	cmd.Flags().StringVar(&pops, "pops", "", "comma-separated proof-of-possession JSON files, one per successor validator")
	cmd.Flags().StringVar(&out, "out", "", "output file for --next-evm-assignment (default: stdout)")
	cmd.Flags().StringVar(&changesFiles, "changes", "", "comma-separated aggregator key-replacement files from `handoff shard-assemble` (optional)")
	cmd.Flags().StringVar(&bindingsFile, "bindings", "", "JSON array of {rootNodeId, evmNodeId}: the delegated EVM validator of each successor root entity")
	cmd.Flags().StringVar(&identitiesFile, "identities", "", "JSON array of the successor's frozen identity records (operator payees included)")
	cmd.Flags().StringVar(&authorizationFile, "authorization", "", "JSON recovery authorization (K) published with this primary")
	cmd.Flags().StringVar(&evmPopsFile, "evm-pops", "", "the members' EVM possession proofs (`ubft pos-relayer proposal --evm-pops` writes them): carried in the plan for the Freeze's EVM proof; needed on a chain that judges primary candidates")
	cmd.Flags().BoolVar(&recovery, "recovery", false, "derive the recovery candidate (exactly K) for the installed, unacknowledged primary; needs --supersede")
	cmd.Flags().BoolVar(&supersede, "supersede", false, "replace the installed assignment, whose acknowledgement is still pending, on the same frozen parent")
	_ = cmd.MarkFlagRequired("context")
	return cmd
}

func writeProposal(cmd *cobra.Command, out string, p evmassign.Proposal, what string) error {
	encoded, err := json.MarshalIndent(p, "", "  ")
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
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s: %s\n", out, what)
	return err
}

func mustAssignmentHash(succ *types.PartitionDescriptionRecord, identities [32]byte) string {
	h, err := evmassign.AssignmentHash(succ, identities)
	if err != nil {
		return "unavailable"
	}
	return "0x" + hex.EncodeToString(h[:])
}

func readEVMPoPs(path string) ([]evmassign.EVMPoP, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var pops []evmassign.EVMPoP
	if err := json.Unmarshal(raw, &pops); err != nil {
		return nil, fmt.Errorf("decoding EVM possession proofs %q: %w", path, err)
	}
	if _, err := evmassign.EncodePoPs(pops); err != nil {
		return nil, fmt.Errorf("EVM possession proofs %q: %w", path, err)
	}
	return pops, nil
}
