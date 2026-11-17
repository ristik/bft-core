package storage_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Live partition configuration from VR through the real block executor (VT-06d AddPartition, VT-06e UpdatePartition; design sections 6.1
// and 6.2): a VR output binds an AddPartition of partition 10 and an UpdatePartition of the aggregator shard of partition 9 (a new T2
// timeout and a new partition parameter); the Freeze v5 admits them with the fold's verdicts over the real VR witness; H commits; the epoch
// switch installs both configurations with the EVM assignment from the retained candidate v6; and the first block of the new epoch creates
// the new partition's shard state and advances the updated shard, whose root-side T2 timeout and parameters reload at once.

var (
	vxAgg   = types.PartitionShardID{PartitionID: 9, ShardID: types.ShardID{}.Key()}
	vxAdded = types.PartitionShardID{PartitionID: 10, ShardID: types.ShardID{}.Key()}
)

// vxRetained are the artifacts an admitted Freeze v5 retains (the derived body, the v5 view and the candidate v6), by body id.
type vxRetained struct {
	body, v5, v6 map[string][]byte
}

func (r vxRetained) HandoffBody(id []byte) ([]byte, error)        { return r.body[string(id)], nil }
func (r vxRetained) HandoffCandidate(id []byte) ([]byte, error)   { return r.v5[string(id)], nil }
func (r vxRetained) HandoffVRCandidate(id []byte) ([]byte, error) { return r.v6[string(id)], nil }

type vxPartitions struct {
	*vxFixture
	agg, aggNext, added *types.PartitionDescriptionRecord
}

func vxNodeInfo(t *testing.T, seed byte, id string) *types.NodeInfo {
	return &types.NodeInfo{NodeID: id, SigKey: vxMkKey(t, seed).pub, Stake: 1}
}

// newVXPartitions is the VR fixture with the EVM shard at its genesis epoch (so a real orchestration holds its whole history), an
// aggregator shard of partition 9 installed and acknowledged next to it, and the two partition changes bound after CommitteeLimits.
// mutate edits the update's successor before it is encoded; stale makes the update name a configuration that is not the installed one.
func newVXPartitions(t *testing.T, mutate func(*types.PartitionDescriptionRecord), stale bool) *vxPartitions {
	f := &vxPartitions{vxFixture: newVXFixture(t)}
	f.current.Epoch, f.current.EpochStart = 0, 1
	succ, err := evmassign.NewSuccessor(f.current, f.succ.Validators)
	require.NoError(t, err)
	f.succ = succ
	kd, err := evmassign.IdentitiesDigest(f.k)
	require.NoError(t, err)
	f.baseHash, err = evmassign.AssignmentHash(f.current, kd)
	require.NoError(t, err)

	f.agg = &types.PartitionDescriptionRecord{Version: 1, NetworkID: vxNetwork, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1, PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"},
		Validators: []*types.NodeInfo{vxNodeInfo(t, 40, "agg-1")}}
	f.aggNext, err = evmassign.NewSuccessor(f.agg, f.agg.Validators)
	require.NoError(t, err)
	f.aggNext.T2Timeout = 7 * time.Second
	f.aggNext.PartitionParams["fee_floor"] = "12"
	if mutate != nil {
		mutate(f.aggNext)
	}
	f.added = &types.PartitionDescriptionRecord{Version: 1, NetworkID: vxNetwork, PartitionID: 10, PartitionTypeID: 10, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 3 * time.Second, Epoch: 0, PartitionParams: map[string]string{"proof_type": "none"},
		Validators: []*types.NodeInfo{vxNodeInfo(t, 41, "new-1"), vxNodeInfo(t, 42, "new-2")}}

	addRaw, err := types.Cbor.Marshal(f.added)
	require.NoError(t, err)
	var pops []evmassign.PoP
	for i, seed := range []byte{41, 42} {
		v := f.added.Validators[i]
		msg, err := vrschema.ChangePoPMessage(vxNetwork, vrschema.ValidatorRegistry, 5, 10, f.added.ShardID.Bytes(), addRaw, v.NodeID)
		require.NoError(t, err)
		sig, err := vxMkKey(t, seed).signer.SignBytes(msg)
		require.NoError(t, err)
		pops = append(pops, evmassign.PoP{NodeID: v.NodeID, Key: v.SigKey, Signature: sig})
	}
	popRaw, err := types.Cbor.Marshal(pops)
	require.NoError(t, err)
	add, err := vrschema.EncodeChange(vrschema.KindAddPartition, addRaw, popRaw)
	require.NoError(t, err)
	replaced := f.agg
	if stale {
		moved := *f.agg
		moved.T2Timeout += time.Second
		replaced = &moved
	}
	expected, err := evmassign.PDRHash(replaced)
	require.NoError(t, err)
	succRaw, err := types.Cbor.Marshal(f.aggNext)
	require.NoError(t, err)
	update, err := vrschema.EncodeChange(vrschema.KindUpdatePartition, uint64(9), f.agg.ShardID.Bytes(), expected, succRaw)
	require.NoError(t, err)
	f.extraShards = []*types.PartitionDescriptionRecord{f.agg}
	f.extraChanges = []vrschema.RegistryChange{{ID: 5, Kind: uint64(vrschema.KindAddPartition), Payload: add}, {ID: 6, Kind: uint64(vrschema.KindUpdatePartition), Payload: update}}
	if stale {
		f.extraChanges[1].Verdict = uint64(vrschema.VerdictConflict)
	}
	f.build()
	f.orch = f.realOrchestration(t)
	return f
}

// realOrchestration holds the genesis configurations of the EVM and aggregator shards and the EVM shard's genesis identities.
func (f *vxPartitions) realOrchestration(t *testing.T) *partitions.Orchestration {
	o, err := partitions.NewOrchestration(vxNetwork, filepath.Join(t.TempDir(), "orch.db"), logger.New(t), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	require.NoError(t, o.AddShardConfig(f.current))
	require.NoError(t, o.AddShardConfig(f.agg))
	require.NoError(t, o.SetGenesisIdentities(f.current.PartitionID, f.current.ShardID, f.k))
	return o
}

// committed runs Prepare, Freeze v5, Commit and the committed suffix through the executor, and returns the suffix (the old epoch's
// checkpoint), the committed H and what the Freeze retained.
func (f *vxPartitions) committed(t *testing.T) (*storage.ExecutedBlock, evmroot.OrderedHandoffRecord, vxRetained) {
	g := f.genesis()
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	fz := f.must(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	body, _, v5, v6, ok := storage.VRRetainedForTest(fz)
	require.True(t, ok)
	id := f.q3.Identity()
	retained := vxRetained{body: map[string][]byte{string(id[:]): body}, v5: map[string][]byte{string(id[:]): v5}, v6: map[string][]byte{string(id[:]): v6}}
	f.candidates[string(id[:])] = v5

	commit := f.record("freeze", 0, 13)
	commit.Kind = "commit"
	tr, err := storage.ExpectedCommitTRForTest(f.candidates, commit, fz.ShardState.States[vxShard])
	require.NoError(t, err)
	commit.SuccessorTRHash = tr
	h := f.must(fz, f.block(fz, 13, 1_030, [][]byte{commit.Bytes()}))
	require.Equal(t, "committed", h.ShardState.Control.Phase)
	suffix := f.must(h, f.block(h, 14, 1_040, nil))
	return suffix, commit, retained
}

// activate executes the first block of the new epoch on the epoch anchor over the old checkpoint, as InstallEpochAnchor installs it.
func (f *vxPartitions) activate(t *testing.T, checkpoint *storage.ExecutedBlock, record evmroot.OrderedHandoffRecord, retained vxRetained) (*storage.ExecutedBlock, error) {
	a := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{0x6e}, 32), Epoch: 2, Slot: record.ActivationRound - 1, StateRoot: bytes.Clone(checkpoint.RootHash)}
	anchorRoot := *checkpoint
	anchorRoot.BlockData = &rctypes.BlockData{Version: rctypes.VersionHandoff, Epoch: 2, Round: a.Slot, Timestamp: checkpoint.BlockData.Timestamp,
		Payload: &rctypes.Payload{Version: rctypes.VersionHandoff}, Anchor: a}
	first := &rctypes.BlockData{Version: rctypes.VersionHandoff, Epoch: 2, Round: record.ActivationRound, Timestamp: 2_000,
		Payload: &rctypes.Payload{Version: rctypes.VersionHandoff, PosControls: []rctypes.PosControl{f.closure(t, record)}}, Anchor: a}
	return storage.ExtendForTest(&anchorRoot, first, f.orch, f.auth, retained, f.svc)
}

// closure is the CloseLiability of the old epoch the first block of the new one must carry (the closure duty is always on in VR mode),
// over a closure authority that vouches for it.
func (f *vxPartitions) closure(t *testing.T, record evmroot.OrderedHandoffRecord) rctypes.PosControl {
	asg := [32]byte{0xa5}
	ids := []evmassign.Identity{f.k[0], f.k[1]}
	ed, err := evmassign.AssignmentExposureDigest(evmassign.Deployment{NetworkWord: f.dep.NetworkWord, ChainID: f.dep.ChainID, Custody: f.dep.Registry}, asg, ids)
	require.NoError(t, err)
	kd, err := evmassign.KeyHistoryDigest(ids)
	require.NoError(t, err)
	hRec, tRoot := [32]byte{0x4a}, [32]byte{0x7e}
	data := storage.ClosureData{AssignmentID: asg, HRound: record.OrderedRound, HRecordID: hRec, TerminalRoot: tRoot, ExposureDigest: ed, KeyHistoryDigest: kd}.Encode()
	bundle := []byte("bundle")
	f.witnesses[sha256.Sum256(bundle)] = bundle
	f.svc.Authority = vxClosures{facts: storage.ClosureFacts{ClosedEpoch: 1, BundleID: [32]byte{0xb0}, HRecordID: hRec, HRound: record.OrderedRound,
		TerminalRoot: tRoot, AssignmentID: asg, Closed: ids}}
	return rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 2, OrderingRound: record.ActivationRound,
		Op: rctypes.OpCloseLiability, Close: &rctypes.CloseContext{ClosedEpoch: 1, BundleSemanticID: [32]byte{0xb0}}, Data: data, WitnessHash: sha256.Sum256(bundle)}
}

func confHash(t *testing.T, p *types.PartitionDescriptionRecord) []byte {
	h, err := p.Hash(crypto.SHA256)
	require.NoError(t, err)
	return h
}

func TestVRAddAndUpdatePartitionThroughTheExecutor(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	checkpoint, commit, retained := f.committed(t)
	require.Zero(t, vradmitStaged(t, checkpoint), "both changes Accepted: the staged rejectedBitmap is empty")

	// nothing is installed from an uncommitted or not yet activated handoff
	before, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.NotContains(t, before, vxAdded)
	require.EqualValues(t, 0, before[vxAgg].Epoch)

	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit))
	confs, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.EqualValues(t, 1, confs[vxShard].Epoch, "the EVM assignment J installs with them")
	require.EqualValues(t, 0, confs[vxAdded].Epoch)
	require.EqualValues(t, commit.ActivationRound, confs[vxAdded].EpochStart, "the new partition starts at the committed activation round")
	require.EqualValues(t, 1, confs[vxAgg].Epoch)
	require.EqualValues(t, commit.ActivationRound, confs[vxAgg].EpochStart)
	require.Equal(t, 7*time.Second, confs[vxAgg].T2Timeout)
	earlier, err := f.orch.ShardConfigs(commit.ActivationRound - 1)
	require.NoError(t, err)
	require.NotContains(t, earlier, vxAdded, "absent before the activation round")
	require.EqualValues(t, 0, earlier[vxAgg].Epoch, "the old configuration stays in effect before the activation round")
	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit), "the install is idempotent (startup repair)")

	first, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	added := first.ShardState.States[vxAdded]
	require.NotNil(t, added, "the first block of the epoch creates the new partition's shard state")
	require.Equal(t, confHash(t, confs[vxAdded]), []byte(added.ShardConfHash))
	require.EqualValues(t, 0, added.TR.Epoch)
	require.Equal(t, 3*time.Second, added.T2Timeout)
	require.Contains(t, first.ShardState.Changed, vxAdded, "certified in this block: the new partition's first UC comes from the roots")
	agg := first.ShardState.States[vxAgg]
	require.Equal(t, confHash(t, confs[vxAgg]), []byte(agg.ShardConfHash), "the updated shard switches at the boundary")
	require.EqualValues(t, 1, agg.TR.Epoch)
	require.Equal(t, 7*time.Second, agg.T2Timeout, "the root's T2 handling reads the reloaded timeout")
	require.Equal(t, "12", agg.PartitionParams["fee_floor"], "and the reloaded partition parameters")
	require.Equal(t, confHash(t, confs[vxShard]), []byte(first.ShardState.States[vxShard].ShardConfHash))

	// replay and a second root: the same committed bytes derive the same configurations and the same block
	again, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	require.Equal(t, first.RootHash, again.RootHash, "replay")
	other := f.realOrchestration(t)
	require.NoError(t, storage.InstallCommittedForTest(retained, other, checkpoint, commit))
	otherConfs, err := other.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	for _, k := range []types.PartitionShardID{vxShard, vxAgg, vxAdded} {
		require.Equal(t, confHash(t, confs[k]), confHash(t, otherConfs[k]), "another root installs the identical configuration of %v", k)
	}
	f.orch = other
	onOther, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	require.Equal(t, first.RootHash, onOther.RootHash, "and executes the identical first block")

	// recovery: a root that never ordered the Freeze retains the delivered body and candidate v6 (InstallVerifiedEpoch's path) as the
	// Freeze would have, and installs the identical configurations from its own store
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store, err := storage.New(crypto.SHA256, db, storage.NewMockOrchestrationForTest(func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
	}, nil), logger.New(t), storage.ProfileHandoff)
	require.NoError(t, err)
	id := commit.NextBodyID
	require.NoError(t, store.RetainHandoffArtifacts(id, retained.body[string(id)], retained.v6[string(id)]))
	v5, err := db.HandoffCandidate(id)
	require.NoError(t, err)
	require.Equal(t, retained.v5[string(id)], v5, "the v5 view under the candidate key")
	v6, err := db.HandoffVRCandidate(id)
	require.NoError(t, err)
	require.Equal(t, retained.v6[string(id)], v6, "the candidate v6 beside it")
	recovered := f.realOrchestration(t)
	require.NoError(t, storage.InstallCommittedForTest(db, recovered, checkpoint, commit))
	recoveredConfs, err := recovered.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	for _, k := range []types.PartitionShardID{vxShard, vxAgg, vxAdded} {
		require.Equal(t, confHash(t, confs[k]), confHash(t, recoveredConfs[k]), "the recovered root installs the identical configuration of %v", k)
	}
}

func vradmitStaged(t *testing.T, b *storage.ExecutedBlock) uint16 {
	return rootState(t, b).StagedBitmap
}

// An UpdatePartition whose expected hash is not the installed configuration's is Rejected(Conflict) by every root at the Freeze: the
// Boundary's bitmap rejects it, and the epoch switch installs the addition only.
func TestVRUpdatePartitionWithAStaleExpectedHashIsRejected(t *testing.T) {
	f := newVXPartitions(t, nil, true)
	checkpoint, commit, retained := f.committed(t)
	require.EqualValues(t, 0b100, vradmitStaged(t, checkpoint), "the third bound change (the update) is rejected")
	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit))
	confs, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.EqualValues(t, 0, confs[vxAgg].Epoch, "the rejected update installs nothing")
	require.Contains(t, confs, vxAdded)
	first, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	require.EqualValues(t, 0, first.ShardState.States[vxAgg].TR.Epoch)
	require.Equal(t, 2500*time.Millisecond, first.ShardState.States[vxAgg].T2Timeout)

	// a candidate that claims Accepted for it is not what the fold gives: the Freeze is refused
	g := newVXPartitions(t, nil, true)
	g.extraChanges[1].Verdict = uint64(vrschema.VerdictAccepted)
	g.build()
	g.orch = g.realOrchestration(t)
	gen := g.genesis()
	prep := g.must(gen, g.block(gen, 11, 1_010, [][]byte{g.record("prepare", 0, 11).Bytes()}))
	_, err = g.exec(prep, g.block(prep, 12, 1_020, [][]byte{g.record("freeze", 0, 12).Bytes(), g.freezeV5(0)}))
	require.ErrorIs(t, err, vradmit.ErrVerdicts)
}

// The acknowledgement gate covers an UpdatePartition: a target shard whose last configuration is not acknowledged refuses the Freeze.
func TestVRUpdatePartitionWaitsForTheShardsAcknowledgement(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	g := f.genesis()
	g.ShardState.States[vxAgg].TR.Epoch++ // a configuration certified, its input record not yet at that epoch
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	_, err := f.exec(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	require.ErrorIs(t, err, vradmit.ErrAckGate)
}

// The install reads only committed, consistent artifacts: a v5 view that is not the retained candidate v6's, a missing v6 (the v5 view
// does not bind the body) and an installed configuration other than the one the update replaces all refuse the epoch switch.
func TestVRPartitionInstallRefusesInconsistentHistory(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	checkpoint, commit, retained := f.committed(t)
	id := string(commit.NextBodyID)

	tampered := vxRetained{body: retained.body, v5: map[string][]byte{id: append(bytes.Clone(retained.v5[id]), 0)}, v6: retained.v6}
	require.ErrorIs(t, storage.InstallCommittedForTest(tampered, f.realOrchestration(t), checkpoint, commit), storage.ErrAssignmentHistory)

	v5only := vxRetained{body: retained.body, v5: retained.v5, v6: map[string][]byte{}}
	require.ErrorIs(t, storage.InstallCommittedForTest(v5only, f.realOrchestration(t), checkpoint, commit), storage.ErrAssignmentHistory,
		"the successor body binds the candidate v6, not its view")

	moved := *f.agg
	moved.T2Timeout += time.Second
	o, err := partitions.NewOrchestration(vxNetwork, filepath.Join(t.TempDir(), "moved.db"), logger.New(t), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = o.Close() })
	require.NoError(t, o.AddShardConfig(f.current))
	require.NoError(t, o.AddShardConfig(&moved))
	require.NoError(t, o.SetGenesisIdentities(f.current.PartitionID, f.current.ShardID, f.k))
	err = storage.InstallCommittedForTest(retained, o, checkpoint, commit)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	require.ErrorIs(t, err, vradmit.ErrInstall, "an old-hash mismatch at install is refused, never installed")
	confs, err := o.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.NotContains(t, confs, vxAdded, "nothing of the handoff is installed")
}
