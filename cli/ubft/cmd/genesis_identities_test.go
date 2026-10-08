package cmd

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

const genesisNetwork = types.NetworkID(5)

// genesisDeployment is a four-entity PoA genesis: the root trust base, the coupled EVM shard's genesis configuration and the bindings.
type genesisDeployment struct {
	tb       *types.RootTrustBaseV1
	conf     *types.PartitionDescriptionRecord
	bindings []evmassign.Binding
}

func newGenesisDeployment(t *testing.T) genesisDeployment {
	t.Helper()
	_, roots := testutils.CreateTestNodes(t, 4)
	_, evms := testutils.CreateTestNodes(t, 4)
	for i := range roots {
		roots[i].Stake, evms[i].Stake = 1, 1
	}
	d := genesisDeployment{
		tb: &types.RootTrustBaseV1{NetworkID: genesisNetwork, Epoch: 1, RootNodes: roots, QuorumThreshold: 3},
		conf: &types.PartitionDescriptionRecord{Version: 1, NetworkID: genesisNetwork, PartitionID: 8, ShardID: types.ShardID{}, PartitionTypeID: 8,
			TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500 * time.Millisecond, Validators: evms, Epoch: 0, EpochStart: 1,
			PartitionParams: map[string]string{evmassign.CouplingParam: "true",
				// the DEV continuity budget (D <= 1/4) does not allow any reweighting of a four-member committee; a weighted rotation commits its own
				storage.ParamContinuityMaxDist: "1/1"}},
	}
	for i := range roots {
		d.bindings = append(d.bindings, evmassign.Binding{RootNodeID: roots[i].NodeID, EVMNodeID: evms[i].NodeID})
	}
	return d
}

func (d genesisDeployment) orchestration(t *testing.T) *partitions.Orchestration {
	t.Helper()
	o, err := partitions.NewOrchestration(genesisNetwork, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	o.EnableHandoffProfile()
	require.NoError(t, o.InitGenesisShardConfigs(d.conf))
	return o
}

func (d genesisDeployment) file(t *testing.T, ids []evmassign.Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "genesis-identities.json")
	require.NoError(t, writeJSONFile(path, ids))
	return path
}

func TestThePoAGenesisIdentitiesAreDerivedFromTheCommitteeAndAreValid(t *testing.T) {
	d := newGenesisDeployment(t)
	ids, err := poaGenesisIdentities(d.tb, d.conf, d.bindings)
	require.NoError(t, err)
	require.Len(t, ids, 4)
	for _, i := range ids {
		require.Len(t, i.StakingID, evmassign.StakingIDLen)
		require.Len(t, i.OperatorPayee, evmassign.PayeeLen)
		require.EqualValues(t, 1, i.Generation)
		require.EqualValues(t, 1, i.Weight)
	}
	again, err := poaGenesisIdentities(d.tb, d.conf, d.bindings)
	require.NoError(t, err)
	require.Equal(t, ids, again, "reproducible from the genesis alone")

	// a weight change moves the record's weight only: the staking id, payee and exposure stay the entity's own
	d.tb.RootNodes[0].Stake, d.conf.Validators[0].Stake = 6, 6
	heavy, err := poaGenesisIdentities(d.tb, d.conf, d.bindings)
	require.NoError(t, err)
	byRoot := func(ids []evmassign.Identity, id string) evmassign.Identity {
		for _, i := range ids {
			if i.RootNodeID == id {
				return i
			}
		}
		t.Fatalf("no record for %s", id)
		return evmassign.Identity{}
	}
	before, after := byRoot(ids, d.tb.RootNodes[0].NodeID), byRoot(heavy, d.tb.RootNodes[0].NodeID)
	require.EqualValues(t, 6, after.Weight)
	before.Weight = after.Weight
	require.Equal(t, before, after)

	for name, tc := range map[string]struct {
		mutate func(*genesisDeployment)
		cause  error
	}{
		"a binding to a node that is not in the genesis": {func(d *genesisDeployment) { d.bindings[0].EVMNodeID = "nobody" }, ErrGenesisIdentities},
		"an EVM validator that is not bound":             {func(d *genesisDeployment) { d.bindings = d.bindings[:3] }, evmassign.ErrCoupling},
		"unequal weights across a pair":                  {func(d *genesisDeployment) { d.conf.Validators[1].Stake = 2 }, evmassign.ErrCoupling},
	} {
		bad := newGenesisDeployment(t)
		tc.mutate(&bad)
		_, err := poaGenesisIdentities(bad.tb, bad.conf, bad.bindings)
		require.ErrorIs(t, err, ErrGenesisIdentities, name)
		require.ErrorIs(t, err, tc.cause, name)
	}
}

func TestTheGenesisBaselineIsRecordedOnceAndServedAsTheAcknowledgedCommittee(t *testing.T) {
	d := newGenesisDeployment(t)
	o := d.orchestration(t)
	ids, err := poaGenesisIdentities(d.tb, d.conf, d.bindings)
	require.NoError(t, err)
	path := d.file(t, ids)

	_, _, err = o.AcknowledgedIdentities(8, types.ShardID{}, 0)
	require.ErrorIs(t, err, partitions.ErrNoBaseline, "nothing records the baseline before the file is consumed")

	require.NoError(t, seedGenesisIdentities(o, d.tb, []*types.PartitionDescriptionRecord{d.conf}, path))
	got, hash, err := o.AcknowledgedIdentities(8, types.ShardID{}, 0)
	require.NoError(t, err)
	require.Equal(t, ids, got)
	digest, err := evmassign.IdentitiesDigest(ids)
	require.NoError(t, err)
	want, err := evmassign.AssignmentHash(d.conf, digest)
	require.NoError(t, err)
	require.Equal(t, want, hash)

	require.NoError(t, seedGenesisIdentities(o, d.tb, []*types.PartitionDescriptionRecord{d.conf}, path), "a restart records the same set again")

	// a different committee is a conflict, never an overwrite: another payee for one entity, otherwise valid
	other := append([]evmassign.Identity(nil), ids...)
	other[0].OperatorPayee = bytes.Repeat([]byte{0x7e}, evmassign.PayeeLen)
	err = seedGenesisIdentities(o, d.tb, []*types.PartitionDescriptionRecord{d.conf}, d.file(t, other))
	require.ErrorIs(t, err, ErrGenesisIdentitiesConflict)
	require.ErrorIs(t, err, partitions.ErrDerivedConflict)
	got, _, err = o.AcknowledgedIdentities(8, types.ShardID{}, 0)
	require.NoError(t, err)
	require.Equal(t, ids, got, "the recorded baseline is unchanged")
}

// Each refusal differs from the control in one thing; nothing is recorded.
func TestTheGenesisIdentitiesFileIsRefusedWhenItIsNotThisGenesis(t *testing.T) {
	control := newGenesisDeployment(t)
	ids, err := poaGenesisIdentities(control.tb, control.conf, control.bindings)
	require.NoError(t, err)

	refused := func(name string, cause error, records func([]evmassign.Identity) []evmassign.Identity, confs func(*genesisDeployment) []*types.PartitionDescriptionRecord) {
		t.Helper()
		d := newGenesisDeployment(t)
		d.tb, d.conf, d.bindings = control.tb, control.conf, control.bindings
		o := d.orchestration(t)
		list := []*types.PartitionDescriptionRecord{d.conf}
		if confs != nil {
			list = confs(&d)
		}
		err := seedGenesisIdentities(o, d.tb, list, d.file(t, records(append([]evmassign.Identity(nil), ids...))))
		require.ErrorIs(t, err, ErrGenesisIdentities, name)
		require.ErrorIs(t, err, cause, name)
		_, _, err = o.AcknowledgedIdentities(8, types.ShardID{}, 0)
		require.ErrorIs(t, err, partitions.ErrNoBaseline, "%s: nothing is recorded", name)
	}
	same := func(ids []evmassign.Identity) []evmassign.Identity { return ids }
	require.NoError(t, seedGenesisIdentities(control.orchestration(t), control.tb, []*types.PartitionDescriptionRecord{control.conf}, control.file(t, same(ids))), "control")

	refused("a root key that is not the trust base's", evmassign.ErrIdentity, func(ids []evmassign.Identity) []evmassign.Identity {
		ids[0].RootKey = bytes.Repeat([]byte{0x02}, evmassign.KeyLen)
		return ids
	}, nil)
	refused("an EVM key that is not the validator's", evmassign.ErrIdentity, func(ids []evmassign.Identity) []evmassign.Identity {
		ids[1].EVMKey = bytes.Repeat([]byte{0x03}, evmassign.KeyLen)
		return ids
	}, nil)
	refused("a weight that is not the member's", evmassign.ErrIdentity, func(ids []evmassign.Identity) []evmassign.Identity {
		ids[2].Weight = 5
		return ids
	}, nil)
	refused("a record for a root node that is not in the genesis", evmassign.ErrCoupling, func(ids []evmassign.Identity) []evmassign.Identity {
		ids[3].RootNodeID = "stranger"
		return ids
	}, nil)
	refused("a committee record missing", evmassign.ErrCoupling, func(ids []evmassign.Identity) []evmassign.Identity { return ids[:3] }, nil)
	refused("no coupled genesis shard", ErrGenesisIdentities, same, func(d *genesisDeployment) []*types.PartitionDescriptionRecord {
		plain := *d.conf
		plain.PartitionParams = map[string]string{}
		return []*types.PartitionDescriptionRecord{&plain}
	})
	refused("two coupled genesis shards", ErrGenesisIdentities, same, func(d *genesisDeployment) []*types.PartitionDescriptionRecord {
		second := *d.conf
		second.PartitionID = 9
		return []*types.PartitionDescriptionRecord{d.conf, &second}
	})
}

// The first coupled handoff: the authorization derived from the context and the genesis committee is admitted by the root's own lifecycle
// check against the baseline the root recorded, and each way K can differ from that baseline is refused with its own sentinel.
func TestTheFirstCoupledHandoffAuthorizationIsAdmittedAgainstTheRecordedBaseline(t *testing.T) {
	d := newGenesisDeployment(t)
	o := d.orchestration(t)
	ids, err := poaGenesisIdentities(d.tb, d.conf, d.bindings)
	require.NoError(t, err)
	require.NoError(t, seedGenesisIdentities(o, d.tb, []*types.PartitionDescriptionRecord{d.conf}, d.file(t, ids)))

	predecessor := bytes.Repeat([]byte{0xb0}, 32)
	ectx := consensus.EVMAssignmentContext{Network: uint64(genesisNetwork), Predecessor: predecessor, Attempt: 0, Installed: d.conf}
	a, err := poaAuthorization(ectx, 31337, ids)
	require.NoError(t, err)

	lifecycle, err := storage.LifecycleFor(o, 8, types.ShardID{}, 0, d.conf)
	require.NoError(t, err)
	// the successor committee: the same entities and keys, one reweighted within the continuity budget the genesis configuration commits
	successor := append([]evmassign.Identity(nil), ids...)
	successor[0].Weight = 2
	candidate := func(a *evmassign.Authorization, base []byte) evmassign.Candidate {
		return evmassign.Candidate{Version: evmassign.CandidateVersion, Kind: evmassign.KindPrimary, Network: uint64(genesisNetwork), Predecessor: base,
			Identities: successor, Authorization: a}
	}
	require.NoError(t, evmassign.VerifyLifecycle(candidate(a, predecessor), lifecycle), "the control is admitted")

	// K is not the recorded committee: one entity's payee differs
	otherK := append([]evmassign.Identity(nil), ids...)
	otherK[0].OperatorPayee = bytes.Repeat([]byte{0x7e}, evmassign.PayeeLen)
	wrongK, err := poaAuthorization(ectx, 31337, otherK)
	require.NoError(t, err)
	require.ErrorIs(t, evmassign.VerifyLifecycle(candidate(wrongK, predecessor), lifecycle), evmassign.ErrNotIncumbent)

	// the authorization is based on another assignment: the context's installed configuration is not the acknowledged one
	otherConf := *d.conf
	otherConf.T2Timeout = 3 * time.Second
	wrongBase, err := poaAuthorization(consensus.EVMAssignmentContext{Network: uint64(genesisNetwork), Predecessor: predecessor, Installed: &otherConf}, 31337, ids)
	require.NoError(t, err)
	require.ErrorIs(t, evmassign.VerifyLifecycle(candidate(wrongBase, predecessor), lifecycle), evmassign.ErrNotIncumbent)

	// the candidate's predecessor is not the root body the authorization is based on
	require.ErrorIs(t, evmassign.VerifyLifecycle(candidate(a, bytes.Repeat([]byte{0xc1}, 32)), lifecycle), evmassign.ErrAuthorization)

	// an incomplete context yields no authorization
	_, err = poaAuthorization(consensus.EVMAssignmentContext{Network: uint64(genesisNetwork)}, 31337, ids)
	require.ErrorIs(t, err, ErrGenesisIdentities)
}

func TestTheGenesisIdentitiesAndAuthorizationCommandsWriteTheFilesTheRootConsumes(t *testing.T) {
	d := newGenesisDeployment(t)
	dir := t.TempDir()
	tbFile, confFile, bindFile := filepath.Join(dir, "trust-base.json"), filepath.Join(dir, "shard-conf.json"), filepath.Join(dir, "bindings.json")
	require.NoError(t, writeJSONFile(tbFile, d.tb))
	require.NoError(t, writeJSONFile(confFile, d.conf))
	require.NoError(t, writeJSONFile(bindFile, d.bindings))
	idsFile := filepath.Join(dir, "ids.json")

	_, err := runCLI(t, "genesis-identities", "generate", "--trust-base", tbFile, "--shard-conf", confFile, "--bindings", bindFile, "--out", idsFile)
	require.NoError(t, err)
	ids, _, err := readIdentities(idsFile)
	require.NoError(t, err)
	want, err := poaGenesisIdentities(d.tb, d.conf, d.bindings)
	require.NoError(t, err)
	require.Equal(t, want, ids)
	require.NoError(t, seedGenesisIdentities(d.orchestration(t), d.tb, []*types.PartitionDescriptionRecord{d.conf}, idsFile), "the generated file is the one the root accepts")

	ctxFile, authFile := filepath.Join(dir, "context.json"), filepath.Join(dir, "authorization.json")
	require.NoError(t, writeJSONFile(ctxFile, consensus.EVMAssignmentContext{Network: uint64(genesisNetwork), Predecessor: bytes.Repeat([]byte{0xb0}, 32), Installed: d.conf}))
	_, err = runCLI(t, "root", "handoff", "evm-authorization", "--context", ctxFile, "--incumbent", idsFile, "--chain", "31337", "--out", authFile)
	require.NoError(t, err)
	a, err := readAuthorization(authFile)
	require.NoError(t, err)
	_, err = a.Digest()
	require.NoError(t, err)
	require.EqualValues(t, 31337, a.Chain)
	require.Equal(t, ids, a.K)

	// a binding that names a node outside the genesis: no file
	bad := append([]evmassign.Binding(nil), d.bindings...)
	bad[0].RootNodeID = "stranger"
	require.NoError(t, writeJSONFile(bindFile, bad))
	_, err = runCLI(t, "genesis-identities", "generate", "--trust-base", tbFile, "--shard-conf", confFile, "--bindings", bindFile, "--out", filepath.Join(dir, "no.json"))
	require.ErrorIs(t, err, ErrGenesisIdentities)
	require.NoFileExists(t, filepath.Join(dir, "no.json"))
}

// The root records the provisioned baseline after the genesis shard configurations are loaded and before it serves anything: a helper test
// cannot see the call being dropped or moved.
func TestRootNodeRunRecordsTheGenesisIdentitiesAfterTheShardConfigurations(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "root_node.go", nil, 0)
	require.NoError(t, err)
	first := map[string]token.Pos{}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				if _, seen := first[id.Name]; !seen {
					first[id.Name] = call.Pos()
				}
			}
		}
		return true
	})
	for _, name := range []string{"loadShardConfs", "seedGenesisIdentities"} {
		require.Contains(t, first, name)
	}
	require.Less(t, first["loadShardConfs"], first["seedGenesisIdentities"])
}
