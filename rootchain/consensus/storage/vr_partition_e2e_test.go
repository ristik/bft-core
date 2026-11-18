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

	add := f.addPayload(t)
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

// addPayload is the AddPartition of f.added (change id 5) with both validators' VR-context PoPs.
func (f *vxPartitions) addPayload(t *testing.T) []byte {
	addRaw, err := types.Cbor.Marshal(f.added)
	require.NoError(t, err)
	var pops []evmassign.PoP
	for i, seed := range []byte{41, 42} {
		v := f.added.Validators[i]
		msg, err := vrschema.ChangePoPMessage(vxNetwork, vrschema.ValidatorRegistry, 5, uint32(f.added.PartitionID), f.added.ShardID.Bytes(), addRaw, v.NodeID)
		require.NoError(t, err)
		sig, err := vxMkKey(t, seed).signer.SignBytes(msg)
		require.NoError(t, err)
		pops = append(pops, evmassign.PoP{NodeID: v.NodeID, Key: v.SigKey, Signature: sig})
	}
	popRaw, err := types.Cbor.Marshal(pops)
	require.NoError(t, err)
	add, err := vrschema.EncodeChange(vrschema.KindAddPartition, addRaw, popRaw)
	require.NoError(t, err)
	return add
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

// rootStore is a root's block store holding the retained artifacts as a root that delivered them (RetainHandoffArtifacts) holds them: the
// candidate source the production executor reads (the block store itself), not the test's map.
func (f *vxPartitions) rootStore(t *testing.T, record evmroot.OrderedHandoffRecord, retained vxRetained) (*storage.BlockStore, storage.BoltDB) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store, err := storage.New(crypto.SHA256, db, storage.NewMockOrchestrationForTest(func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
	}, nil), logger.New(t), storage.ProfileHandoff)
	require.NoError(t, err)
	id := record.NextBodyID
	require.NoError(t, store.RetainHandoffArtifacts(id, retained.body[string(id)], retained.v6[string(id)]))
	return store, db
}

// activate executes the first block of the new epoch on the epoch anchor over the old checkpoint, as InstallEpochAnchor installs it, with
// the root's block store as the executor's candidate source (as in production).
func (f *vxPartitions) activate(t *testing.T, checkpoint *storage.ExecutedBlock, record evmroot.OrderedHandoffRecord, retained vxRetained) (*storage.ExecutedBlock, error) {
	store, _ := f.rootStore(t, record, retained)
	shards, err := storage.DerivedChangeShardsForTest(store, record)
	require.NoError(t, err)
	if len(retained.v6) != 0 && f.acceptedUpdate() {
		require.Contains(t, shards, vxAgg, "the block store serves the candidate v6: the boundary takes the VR branch and its strict check")
	}
	a := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{0x6e}, 32), Epoch: 2, Slot: record.ActivationRound - 1, StateRoot: bytes.Clone(checkpoint.RootHash)}
	anchorRoot := *checkpoint
	anchorRoot.BlockData = &rctypes.BlockData{Version: rctypes.VersionHandoff, Epoch: 2, Round: a.Slot, Timestamp: checkpoint.BlockData.Timestamp,
		Payload: &rctypes.Payload{Version: rctypes.VersionHandoff}, Anchor: a}
	first := &rctypes.BlockData{Version: rctypes.VersionHandoff, Epoch: 2, Round: record.ActivationRound, Timestamp: 2_000,
		Payload: &rctypes.Payload{Version: rctypes.VersionHandoff, PosControls: []rctypes.PosControl{f.closure(t, record)}}, Anchor: a}
	return storage.ExtendForTest(&anchorRoot, first, f.orch, f.auth, store, f.svc)
}

// acceptedUpdate reports whether the fixture's UpdatePartition is Accepted.
func (f *vxPartitions) acceptedUpdate() bool {
	return f.extraChanges[len(f.extraChanges)-1].Verdict == uint64(vrschema.VerdictAccepted)
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
	// the startup reconciliation of an archived handoff derives the same configurations from the configurations of its ordering round,
	// and a caller without them is refused, never given the EVM assignment alone
	at, err := f.orch.ShardConfigs(commit.OrderedRound)
	require.NoError(t, err)
	bid := string(commit.NextBodyID)
	derived, _, err := storage.DeriveActivatedConfigsAt(commit, retained.body[bid], retained.v6[bid], at)
	require.NoError(t, err)
	require.Len(t, derived, 3)
	for i, k := range []types.PartitionShardID{vxShard, vxAdded, vxAgg} {
		require.Equal(t, confHash(t, confs[k]), confHash(t, derived[i]), "the reconciled configuration of %v", k)
	}
	_, _, err = storage.DeriveActivatedConfigsAt(commit, retained.body[bid], retained.v6[bid], nil)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)

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
	_, db := f.rootStore(t, commit, retained)
	id := commit.NextBodyID
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

// FD-29 through the real executor: an UpdatePartition of the partition the same output adds is Rejected(Invalid) by every root, the
// Freeze is admitted (the acknowledgement gate covers Accepted changes only), and the epoch switch installs the addition alone, at epoch 0.
func TestVRAChangeOfAPartitionAddedInTheSameOutputIsRejectedInvalid(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	succ, err := evmassign.NewSuccessor(f.added, f.added.Validators)
	require.NoError(t, err)
	succ.T2Timeout = 9 * time.Second
	expected, err := evmassign.PDRHash(f.added)
	require.NoError(t, err)
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	update, err := vrschema.EncodeChange(vrschema.KindUpdatePartition, uint64(f.added.PartitionID), f.added.ShardID.Bytes(), expected, raw)
	require.NoError(t, err)
	f.extraChanges[1] = vrschema.RegistryChange{ID: 6, Kind: uint64(vrschema.KindUpdatePartition), Payload: update, Verdict: uint64(vrschema.VerdictInvalid)}
	f.build()
	f.orch = f.realOrchestration(t)
	checkpoint, commit, retained := f.committed(t)
	require.EqualValues(t, 0b100, vradmitStaged(t, checkpoint), "the third bound change (the update of the added partition) is rejected")
	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit))
	confs, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.EqualValues(t, 0, confs[vxAdded].Epoch, "the addition activates at epoch 0")
	require.Equal(t, 3*time.Second, confs[vxAdded].T2Timeout, "with its own parameters: the rejected update composes nothing")
	require.EqualValues(t, 0, confs[vxAgg].Epoch)
	first, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	require.EqualValues(t, 0, first.ShardState.States[vxAdded].TR.Epoch)

	// a candidate that claims Accepted for it is not what the fold gives: the Freeze is refused
	g := newVXPartitions(t, nil, false)
	g.extraChanges[1] = vrschema.RegistryChange{ID: 6, Kind: uint64(vrschema.KindUpdatePartition), Payload: update}
	g.build()
	g.orch = g.realOrchestration(t)
	gen := g.genesis()
	prep := g.must(gen, g.block(gen, 11, 1_010, [][]byte{g.record("prepare", 0, 11).Bytes()}))
	_, err = g.exec(prep, g.block(prep, 12, 1_020, [][]byte{g.record("freeze", 0, 12).Bytes(), g.freezeV5(0)}))
	require.ErrorIs(t, err, vradmit.ErrVerdicts)
}

// vxEntry is the verified history's entry of the fixture's committed handoff (the trusted activation interface), over the body and record
// the real Freeze and Commit produced.
type vxEntry struct {
	f      *vxPartitions
	record evmroot.OrderedHandoffRecord
}

func (e vxEntry) Handoff() (evmroot.VerifiedHandoff, evmroot.EpochGenesis, bool) {
	return evmroot.VerifiedHandoff{Record: e.record}, evmroot.EpochGenesis{}, true
}
func (e vxEntry) Epoch() uint64              { return e.record.Epoch + 1 }
func (e vxEntry) Start() uint64              { return e.record.ActivationRound }
func (e vxEntry) EarliestActivation() uint64 { return e.f.q3.EarliestActivation }
func (e vxEntry) BodyID() [32]byte           { return e.f.q3.Identity() }
func (e vxEntry) RootOnly() bool             { return false }
func (e vxEntry) ActivationCommitID() [32]byte {
	var id [32]byte
	copy(id[:], e.record.ID())
	return id
}
func (e vxEntry) Projection() *types.RootTrustBaseV1 {
	p := &types.RootTrustBaseV1{ChangeRecordHash: e.f.q3.ChangeRecordHash}
	for _, m := range e.f.q3.Members {
		p.RootNodes = append(p.RootNodes, &types.NodeInfo{NodeID: m.NodeID, SigKey: m.ConsensusKey, Stake: m.Weight})
	}
	return p
}

// The request constructors read a VR handoff's Accepted root-side changes: the updated shard gets its real activation (never an
// "unchanged" continuation with the old configuration), the new partition its anchor at the adding handoff, and only the v6 bytes the
// body binds authenticate (the v5 view does not).
func TestVRRequestActivationsOfPartitionChanges(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	_, record, retained := f.committed(t)
	entry := vxEntry{f, record}
	id := string(record.NextBodyID)
	v6, v5 := retained.v6[id], retained.v5[id]
	_, err := storage.ActivationFromVerifiedV3(entry, record, v6, crypto.SHA256, 1)
	require.NoError(t, err, "the bound candidate v6 activates")
	_, err = storage.ActivationFromVerifiedV3(entry, record, v5, crypto.SHA256, 1)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "the v5 view is not what the body binds")

	previous, err := storage.NewRequestAnchor(f.agg, crypto.SHA256, record.Epoch, record.PredecessorBodyID, 1)
	require.NoError(t, err)
	_, err = storage.RequestContinuationFromVerifiedV3(previous, entry, v6, crypto.SHA256, 1)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "an Accepted UpdatePartition never proves the shard unchanged")
	act, ok, err := storage.RegistryActivationFromVerifiedV3(previous, entry, record, v6, crypto.SHA256, 1)
	require.NoError(t, err)
	require.True(t, ok)
	activated, err := evmassign.Activate(f.aggNext, record.ActivationRound)
	require.NoError(t, err)
	require.Equal(t, confHash(t, activated), act.PDRHash())

	stale, err := storage.NewRequestAnchor(f.current, crypto.SHA256, record.Epoch, record.PredecessorBodyID, 1)
	require.NoError(t, err)
	_, ok, err = storage.RegistryActivationFromVerifiedV3(stale, entry, record, v6, crypto.SHA256, 1)
	require.NoError(t, err)
	require.False(t, ok, "a shard the candidate does not change has no registry activation")

	addedConf, err := evmassign.Activate(f.added, record.ActivationRound)
	require.NoError(t, err)
	anchor, err := storage.NewPartitionRequestAnchor(addedConf, entry, record, v6, crypto.SHA256, 1)
	require.NoError(t, err)
	require.Equal(t, confHash(t, addedConf), anchor.PDRHash())
	other := *addedConf
	other.T2Timeout += time.Second
	_, err = storage.NewPartitionRequestAnchor(&other, entry, record, v6, crypto.SHA256, 1)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "the anchor must be the committed addition")
	_, err = storage.NewPartitionRequestAnchor(f.agg, entry, record, v6, crypto.SHA256, 1)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "partition 9 is not added")
}

// FD-30 through the real executor: an AddPartition of a one-bit shard is Rejected(Invalid) by every root, so the boundary installs nothing
// for it and the first block of the epoch executes (before the correction every root halted there: a single non-empty shard is not a
// sharding scheme). A candidate that claims Accepted for it is refused at the Freeze.
func TestVRAnAdditionOfASplitShardIsRejectedInvalid(t *testing.T) {
	half, _ := types.ShardID{}.Split()
	split := func(verdict uint8) *vxPartitions {
		f := newVXPartitions(t, nil, false)
		f.added.ShardID = half
		f.extraChanges[0].Payload, f.extraChanges[0].Verdict = f.addPayload(t), uint64(verdict)
		f.build()
		f.orch = f.realOrchestration(t)
		return f
	}
	f := split(vrschema.VerdictInvalid)
	checkpoint, commit, retained := f.committed(t)
	require.EqualValues(t, 0b010, vradmitStaged(t, checkpoint), "the addition (the second bound change) is rejected")
	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit))
	confs, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	for k := range confs {
		require.NotEqual(t, vxAdded.PartitionID, k.PartitionID, "nothing of partition 10 is installed")
	}
	require.EqualValues(t, 1, confs[vxAgg].Epoch, "the other changes install as usual")
	first, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err, "the first block of the epoch executes")
	require.Nil(t, first.ShardState.States[vxAdded])

	g := split(vrschema.VerdictAccepted)
	gen := g.genesis()
	prep := g.must(gen, g.block(gen, 11, 1_010, [][]byte{g.record("prepare", 0, 11).Bytes()}))
	_, err = g.exec(prep, g.block(prep, 12, 1_020, [][]byte{g.record("freeze", 0, 12).Bytes(), g.freezeV5(0)}))
	require.ErrorIs(t, err, vradmit.ErrVerdicts)
}

// The new partition's first certificate: the first block of the epoch creates the added shard from the installed configuration (the empty
// initial input record, technical round 1, epoch 0) and certifies it; the UC verifies under the successor root trust base and the
// installed configuration hash, and under no other configuration.
func TestVRTheNewPartitionsFirstCertificate(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	checkpoint, record, retained := f.committed(t)
	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, record))
	first, err := f.activate(t, checkpoint, record, retained)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: vxNetwork, Epoch: 2, RootChainRoundNumber: first.GetRound(), Timestamp: types.GenesisTime + first.BlockData.Timestamp,
		Hash: bytes.Clone(first.RootHash), PreviousHash: bytes.Repeat([]byte{1}, 32)}
	var nodes []*types.NodeInfo
	for _, m := range f.q3.Members {
		nodes = append(nodes, &types.NodeInfo{NodeID: m.NodeID, SigKey: m.ConsensusKey, Stake: m.Weight})
		for _, key := range f.members {
			if key.root == m.NodeID {
				require.NoError(t, seal.Sign(m.NodeID, key.rk.signer))
			}
		}
	}
	tb, err := types.NewTrustBase(vxNetwork, nodes, types.WithEpoch(2), types.WithEpochStart(record.ActivationRound))
	require.NoError(t, err)
	require.NoError(t, seal.Verify(tb))
	certs, err := first.GenerateCertificates(&rctypes.QuorumCert{LedgerCommitInfo: seal, Signatures: seal.Signatures})
	require.NoError(t, err)
	installed, err := f.orch.ShardConfigs(record.ActivationRound)
	require.NoError(t, err)
	found := false
	for _, cr := range certs {
		if cr.Partition != vxAdded.PartitionID {
			continue
		}
		found = true
		require.NoError(t, cr.UC.Verify(tb, crypto.SHA256, cr.Partition, cr.Shard, confHash(t, installed[vxAdded])))
		require.EqualValues(t, record.ActivationRound, cr.UC.UnicitySeal.RootChainRoundNumber)
		require.EqualValues(t, 2, cr.UC.UnicitySeal.Epoch)
		require.EqualValues(t, 0, cr.UC.InputRecord.RoundNumber)
		require.EqualValues(t, 0, cr.Technical.Epoch)
		require.EqualValues(t, 1, cr.Technical.Round)
		require.Empty(t, cr.UC.InputRecord.Hash, "the first UC certifies the empty initial state")
		require.Error(t, cr.UC.Verify(tb, crypto.SHA256, cr.Partition, cr.Shard, bytes.Repeat([]byte{7}, 32)), "another first configuration is not authenticated")
	}
	require.True(t, found, "the new partition is certified in the first block of the epoch")
}

// The public reconciliation derivation keeps "no configurations known" (nil) apart from a known empty set: an addition-only VR handoff
// derives the EVM assignment and the new partition from the ordering round's configurations, and from a known empty set too (an addition
// needs no installed predecessor), while nil is refused, never answered with the EVM assignment alone.
func TestVRReconciliationOfAnAdditionOnlyHandoff(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	f.extraChanges = f.extraChanges[:1] // the AddPartition alone
	f.build()
	f.orch = f.realOrchestration(t)
	_, commit, retained := f.committed(t)
	id := string(commit.NextBodyID)
	at, err := f.orch.ShardConfigs(commit.OrderedRound)
	require.NoError(t, err)
	derived, _, err := storage.DeriveActivatedConfigsAt(commit, retained.body[id], retained.v6[id], at)
	require.NoError(t, err)
	require.Len(t, derived, 2)
	require.EqualValues(t, vxEVM, derived[0].PartitionID)
	require.EqualValues(t, vxAdded.PartitionID, derived[1].PartitionID)
	require.EqualValues(t, commit.ActivationRound, derived[1].EpochStart)
	empty, _, err := storage.DeriveActivatedConfigsAt(commit, retained.body[id], retained.v6[id], map[types.PartitionShardID]*types.PartitionDescriptionRecord{})
	require.NoError(t, err, "a known empty set")
	require.Equal(t, confHash(t, derived[1]), confHash(t, empty[1]))
	_, _, err = storage.DeriveActivatedConfigsAt(commit, retained.body[id], retained.v6[id], nil)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "nil is no configurations known")
}

// The retained layout is the same however a root came to hold the handoff: the admitting root (the Freeze v5 retention) and a root that
// got it by delivery (RetainHandoffArtifacts with the candidate v6) both hold the v5 view under the candidate key and the v6 bytes behind
// the committed-preimage accessor, so the request history and the activation evidence read identical bytes on both and derive the same
// activations (#1185 review F5).
func TestVRDeliveredAndAdmittingRootsRetainTheSameLayout(t *testing.T) {
	f := newVXPartitions(t, nil, false)
	g := f.genesis()
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	freezeBlock := f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)})
	fz := f.must(prep, freezeBlock)
	_, record, retained := f.committed(t)
	id := record.NextBodyID

	newStore := func(name string) (*storage.BlockStore, storage.BoltDB) {
		db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), name), storage.WithNoSync())
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		s, err := storage.New(crypto.SHA256, db, storage.NewMockOrchestrationForTest(func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
			return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
		}, nil), logger.New(t), storage.ProfileHandoff)
		require.NoError(t, err)
		return s, db
	}
	admitting, _ := newStore("admitting.db")
	require.NoError(t, storage.RetainVRFreezeForTest(admitting, freezeBlock, fz))
	delivered, _ := newStore("delivered.db")
	require.NoError(t, delivered.RetainHandoffArtifacts(id, retained.body[string(id)], retained.v6[string(id)]))

	for _, read := range []struct {
		name string
		get  func(*storage.BlockStore) ([]byte, error)
		want []byte
	}{
		{"HandoffCandidate is the v5 view", func(s *storage.BlockStore) ([]byte, error) { return s.HandoffCandidate(id) }, retained.v5[string(id)]},
		{"HandoffVRCandidate is the v6 bytes", func(s *storage.BlockStore) ([]byte, error) { return s.HandoffVRCandidate(id) }, retained.v6[string(id)]},
		{"HandoffCommittedPreimage is the v6 bytes", func(s *storage.BlockStore) ([]byte, error) { return s.HandoffCommittedPreimage(id) }, retained.v6[string(id)]},
		{"HandoffBody is the derived body", func(s *storage.BlockStore) ([]byte, error) { return s.HandoffBody(id) }, retained.body[string(id)]},
	} {
		a, err := read.get(admitting)
		require.NoError(t, err)
		d, err := read.get(delivered)
		require.NoError(t, err)
		require.Equal(t, read.want, a, "admitting root: %s", read.name)
		require.Equal(t, read.want, d, "delivered root: %s", read.name)
	}

	// the request history's constructors over each root's committed preimage derive the same activations
	entry := vxEntry{f, record}
	previous, err := storage.NewRequestAnchor(f.agg, crypto.SHA256, record.Epoch, record.PredecessorBodyID, 1)
	require.NoError(t, err)
	var hashes [][]byte
	for _, s := range []*storage.BlockStore{admitting, delivered} {
		pre, err := s.HandoffCommittedPreimage(id)
		require.NoError(t, err)
		evm, err := storage.ActivationFromVerifiedV3(entry, record, pre, crypto.SHA256, 1)
		require.NoError(t, err)
		agg, ok, err := storage.RegistryActivationFromVerifiedV3(previous, entry, record, pre, crypto.SHA256, 1)
		require.NoError(t, err)
		require.True(t, ok)
		hashes = append(hashes, append(evm.PDRHash(), agg.PDRHash()...))
	}
	require.Equal(t, hashes[0], hashes[1])
}
