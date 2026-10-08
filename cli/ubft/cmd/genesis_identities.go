package cmd

// The genesis committee's identity records and the recovery authorization of the first coupled handoff, for a deployment that runs under
// proof of authority (docs/design/h3-evm-assignment.md, "Amendment: #85 lifecycle").
//
// A coupled EVM assignment must carry the identity records of its committee and an Authorization whose K is the exact last acknowledged
// committee. Before any rotation that committee is the genesis one, and the orchestration keeps it only if the root recorded it at genesis
// (partitions.Orchestration.SetGenesisIdentities). Under PoA there is no staking contract to read it from: the operator provisions it, and
// the staking ids, operator payees and exposure digests are operator-assigned DEV values (deterministic here, so every operator derives
// the same file), not placeholders for something else. Under proof of stake the genesis manifest supplies the same records and this file
// is not used.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrGenesisIdentities is returned when the provisioned genesis identity records are not the one coupled set of this deployment's
	// genesis: no coupled EVM shard to record them for, or records that differ from the trust base or the shard configuration.
	ErrGenesisIdentities = errors.New("genesis identity records do not describe this deployment's genesis committee")
	// ErrGenesisIdentitiesConflict is returned when the orchestration already holds a different genesis committee: the baseline is recorded
	// once.
	ErrGenesisIdentitiesConflict = errors.New("genesis identity records conflict with the recorded baseline")
)

// coupledGenesisShard is the one genesis shard configuration that requires coupled committee changes.
func coupledGenesisShard(shardConfs []*types.PartitionDescriptionRecord) (*types.PartitionDescriptionRecord, error) {
	var coupled *types.PartitionDescriptionRecord
	for _, conf := range shardConfs {
		if !evmassign.CouplingRequired(conf) {
			continue
		}
		if coupled != nil {
			return nil, fmt.Errorf("%w: more than one genesis shard requires coupled changes", ErrGenesisIdentities)
		}
		coupled = conf
	}
	if coupled == nil {
		return nil, fmt.Errorf("%w: no genesis shard configuration has %s=true", ErrGenesisIdentities, evmassign.CouplingParam)
	}
	return coupled, nil
}

// genesisCommittee is the root committee of the genesis trust base in the order evmassign validates it against.
func genesisCommittee(tb *types.RootTrustBaseV1) []evmassign.RootMember {
	out := make([]evmassign.RootMember, 0, len(tb.RootNodes))
	for _, n := range tb.RootNodes {
		out = append(out, evmassign.RootMember{NodeID: n.NodeID, Key: append([]byte(nil), n.SigKey...), Weight: n.Stake})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func bindingsOf(ids []evmassign.Identity) []evmassign.Binding {
	out := make([]evmassign.Binding, 0, len(ids))
	for _, i := range ids {
		out = append(out, evmassign.Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RootNodeID < out[j].RootNodeID })
	return out
}

// checkGenesisIdentities verifies the records against the genesis trust base and the coupled shard's genesis validators exactly as every
// later candidate's records are verified (evmassign.ValidateIdentities and ValidateCoupling): one record per root member and per EVM
// validator, keys and weights equal, bound one to one.
func checkGenesisIdentities(ids []evmassign.Identity, tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord) error {
	root, bindings := genesisCommittee(tb), bindingsOf(ids)
	if err := evmassign.ValidateCoupling(root, conf, bindings); err != nil {
		return errors.Join(ErrGenesisIdentities, err)
	}
	if err := evmassign.ValidateIdentities(ids, root, conf, bindings); err != nil {
		return errors.Join(ErrGenesisIdentities, err)
	}
	return nil
}

// seedGenesisIdentities records the operator-provisioned genesis committee in the orchestration, once. The same records again are a
// no-op (a restart); different records are a conflict, never an overwrite.
func seedGenesisIdentities(orchestration *partitions.Orchestration, tb *types.RootTrustBaseV1, shardConfs []*types.PartitionDescriptionRecord, path string) error {
	conf, err := coupledGenesisShard(shardConfs)
	if err != nil {
		return err
	}
	ids, _, err := readIdentities(path)
	if err != nil {
		return errors.Join(ErrGenesisIdentities, err)
	}
	if err := checkGenesisIdentities(ids, tb, conf); err != nil {
		return err
	}
	if err := orchestration.SetGenesisIdentities(conf.PartitionID, conf.ShardID, ids); err != nil {
		if errors.Is(err, partitions.ErrDerivedConflict) {
			return errors.Join(ErrGenesisIdentitiesConflict, err)
		}
		return err
	}
	return nil
}

// ---- the operator-assigned DEV values ------------------------------------------------------------------------------------------------------

const (
	poaStakingDomain  = "UNICITY_POA_STAKING_ID"
	poaPayeeDomain    = "UNICITY_POA_OPERATOR_PAYEE"
	poaExposureDomain = "UNICITY_POA_EXPOSURE"
)

func poaDigest(domain string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// poaIdentity is the identity record of one coupled entity under PoA. The staking id, the operator payee and the exposure digest are all
// derived from the entity's root node id, as the test fixtures derive them (internal/testutils/identityfix), so none of them moves when
// a later handoff changes the entity's weight: the weight lives in the record, the identity and its payee do not.
func poaIdentity(root evmassign.RootMember, evm *types.NodeInfo) evmassign.Identity {
	staking := poaDigest(poaStakingDomain, []byte(root.NodeID))
	payee := poaDigest(poaPayeeDomain, []byte(root.NodeID))
	exposure := poaDigest(poaExposureDomain, staking[:])
	return evmassign.Identity{StakingID: staking[:evmassign.StakingIDLen], Generation: 1, RootNodeID: root.NodeID, RootKey: root.Key,
		EVMNodeID: evm.NodeID, EVMKey: append([]byte(nil), evm.SigKey...), Weight: root.Weight, OperatorPayee: payee[:evmassign.PayeeLen],
		ExposureDigest: exposure[:]}
}

// poaGenesisIdentities builds the genesis records from the trust base, the coupled shard configuration and the root-to-EVM bindings.
func poaGenesisIdentities(tb *types.RootTrustBaseV1, conf *types.PartitionDescriptionRecord, bindings []evmassign.Binding) ([]evmassign.Identity, error) {
	roots := map[string]evmassign.RootMember{}
	for _, m := range genesisCommittee(tb) {
		roots[m.NodeID] = m
	}
	evms := map[string]*types.NodeInfo{}
	for _, v := range conf.Validators {
		evms[v.NodeID] = v
	}
	ids := make([]evmassign.Identity, 0, len(bindings))
	for _, b := range bindings {
		r, okR := roots[b.RootNodeID]
		v, okE := evms[b.EVMNodeID]
		if !okR || !okE {
			return nil, fmt.Errorf("%w: binding %q -> %q names a node that is not in the genesis", ErrGenesisIdentities, b.RootNodeID, b.EVMNodeID)
		}
		ids = append(ids, poaIdentity(r, v))
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i].StakingID, ids[j].StakingID) < 0 })
	if err := checkGenesisIdentities(ids, tb, conf); err != nil {
		return nil, err
	}
	return ids, nil
}

// newGenesisIdentitiesCmd is `ubft genesis-identities generate`.
func newGenesisIdentitiesCmd() *cobra.Command {
	root := &cobra.Command{Use: "genesis-identities", Short: "Genesis committee identity records for a proof-of-authority deployment"}
	var trustBaseFile, shardConfFile, bindingsFile, out string
	generate := &cobra.Command{Use: "generate", Short: "Derive the genesis identity records (operator-assigned DEV values) of the coupled genesis committee",
		Long: "Writes the identity records that `root-node run --genesis-identities` records as the incumbent baseline, so the first coupled handoff\n" +
			"can name the genesis committee as K. The staking id, operator payee and exposure digest of each entity are derived from its root node id:\n" +
			"operator-assigned values for a PoA deployment, reproducible from the genesis alone. A later weight change edits the record's weight only.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tb, err := readTrustBase(trustBaseFile)
			if err != nil {
				return err
			}
			conf, err := readShardConf(shardConfFile)
			if err != nil {
				return err
			}
			bindings, err := readBindings(bindingsFile)
			if err != nil {
				return err
			}
			ids, err := poaGenesisIdentities(tb, conf, bindings)
			if err != nil {
				return err
			}
			return writeJSONFile(out, ids)
		}}
	generate.Flags().StringVar(&trustBaseFile, "trust-base", "", "the genesis root trust base")
	generate.Flags().StringVar(&shardConfFile, "shard-conf", "", "the coupled EVM shard's genesis (full) shard configuration")
	generate.Flags().StringVar(&bindingsFile, "bindings", "", "JSON array of {rootNodeId, evmNodeId}: one per entity")
	generate.Flags().StringVar(&out, "out", "", "file to write")
	for _, f := range []string{"trust-base", "shard-conf", "bindings", "out"} {
		_ = generate.MarkFlagRequired(f)
	}
	root.AddCommand(generate)
	return root
}

func readTrustBase(path string) (*types.RootTrustBaseV1, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var tb types.RootTrustBaseV1
	if err := json.Unmarshal(raw, &tb); err != nil {
		return nil, fmt.Errorf("decoding trust base %q: %w", path, err)
	}
	return &tb, nil
}

func readShardConf(path string) (*types.PartitionDescriptionRecord, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var conf types.PartitionDescriptionRecord
	if err := json.Unmarshal(raw, &conf); err != nil {
		return nil, fmt.Errorf("decoding shard configuration %q: %w", path, err)
	}
	return &conf, nil
}

// ---- the recovery authorization of the first coupled handoff ------------------------------------------------------------------------------

const (
	poaContractsDomain = "UNICITY_POA_CONTRACTS"
	poaResultDomain    = "UNICITY_POA_ELECTION_RESULT"
	poaSnapshotDomain  = "UNICITY_POA_SNAPSHOT"
	poaPoliciesDomain  = "UNICITY_POA_POLICIES"
)

// poaAuthorization is the recovery Authorization the operator publishes with a primary candidate over the given incumbent committee K: K
// itself, the root body and assignment hash it is based on (read from the context the root reports), and operator-assigned digests for
// the election inputs a proof-of-stake deployment would read from its contracts.
func poaAuthorization(c consensus.EVMAssignmentContext, chain uint64, incumbent []evmassign.Identity) (*evmassign.Authorization, error) {
	if c.Installed == nil || len(c.Predecessor) != evmassign.DigestLen {
		return nil, fmt.Errorf("%w: the context is incomplete", ErrGenesisIdentities)
	}
	k := append([]evmassign.Identity(nil), incumbent...)
	sort.Slice(k, func(i, j int) bool { return bytes.Compare(k[i].StakingID, k[j].StakingID) < 0 })
	kd, err := evmassign.IdentitiesDigest(k)
	if err != nil {
		return nil, err
	}
	base, err := evmassign.AssignmentHash(c.Installed, kd)
	if err != nil {
		return nil, err
	}
	exposure, err := evmassign.ExposureCommit(k)
	if err != nil {
		return nil, err
	}
	var net, ch, att [8]byte
	binary.BigEndian.PutUint64(net[:], c.Network)
	binary.BigEndian.PutUint64(ch[:], chain)
	binary.BigEndian.PutUint64(att[:], c.Attempt)
	contracts := poaDigest(poaContractsDomain, net[:], ch[:])
	result := poaDigest(poaResultDomain, net[:], c.Predecessor, att[:])
	snapshot := poaDigest(poaSnapshotDomain, net[:], c.Predecessor, att[:], kd[:])
	policies := poaDigest(poaPoliciesDomain, net[:], ch[:])
	a := &evmassign.Authorization{Network: c.Network, Chain: chain, Contracts: contracts[:], ResultID: result[:], SnapshotDigest: snapshot[:],
		BaseRootBodyID: append([]byte(nil), c.Predecessor...), BaseAssignmentHash: base[:], K: k, ExposureDigest: exposure[:], Policies: policies[:]}
	if _, err := a.Digest(); err != nil {
		return nil, err
	}
	return a, nil
}

// newEVMAuthorizationCmd is `root handoff evm-authorization`.
func newEVMAuthorizationCmd() *cobra.Command {
	var contextFile, incumbentFile, out string
	var chain uint64
	cmd := &cobra.Command{Use: "evm-authorization", Short: "Derive the recovery authorization of a primary EVM assignment from the incumbent committee (proof of authority)",
		Long: "K is the identity records of the last acknowledged committee: the genesis file before any rotation, the previous assignment's identities\n" +
			"afterwards. The root body and assignment hash it is based on come from the context `handoff evm-context` printed, so the authorization is\n" +
			"for exactly that attempt. Under proof of authority the election inputs it commits to are operator-assigned DEV digests.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := readContextFile(contextFile)
			if err != nil {
				return err
			}
			incumbent, _, err := readIdentities(incumbentFile)
			if err != nil {
				return err
			}
			a, err := poaAuthorization(c, chain, incumbent)
			if err != nil {
				return err
			}
			return writeJSONFile(out, a)
		}}
	cmd.Flags().StringVar(&contextFile, "context", "", "the context printed by `handoff evm-context`")
	cmd.Flags().StringVar(&incumbentFile, "incumbent", "", "identity records of the last acknowledged committee")
	cmd.Flags().Uint64Var(&chain, "chain", 0, "the EVM chain id")
	cmd.Flags().StringVar(&out, "out", "", "file to write")
	for _, f := range []string{"context", "incumbent", "chain", "out"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}
