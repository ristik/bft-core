package storage

import (
	"bytes"
	"crypto"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

// switchFixture is two shards under a schedule: A (partition 1) is idle and has configurations of epochs 0..3 starting at rounds
// 1, 30, 45 and 55 (a different validator set each); B (partition 2) is never reconfigured and keeps executing.
type switchFixture struct {
	t        *testing.T
	confsA   []*types.PartitionDescriptionRecord
	confB    *types.PartitionDescriptionRecord
	keyA     types.PartitionShardID
	keyB     types.PartitionShardID
	signersB []*testutils.TestNode
	orch     mockOrchestration
	verifier mockIRVerifier
}

func newSwitchFixture(t *testing.T) *switchFixture {
	f := &switchFixture{t: t}
	for epoch, start := range []uint64{1, 30, 45, 55} {
		_, infos := testutils.CreateTestNodes(t, 3)
		f.confsA = append(f.confsA, &types.PartitionDescriptionRecord{PartitionID: 1, ShardID: types.ShardID{}, Epoch: uint64(epoch), EpochStart: start, Validators: infos})
	}
	nodesB, infosB := testutils.CreateTestNodes(t, 3)
	f.signersB = nodesB
	f.confB = &types.PartitionDescriptionRecord{PartitionID: 2, ShardID: types.ShardID{}, Epoch: 0, EpochStart: 1, Validators: infosB}
	f.keyA = types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}
	f.keyB = types.PartitionShardID{PartitionID: 2, ShardID: types.ShardID{}.Key()}
	f.orch = mockOrchestration{shardConfigs: func(round uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		confA := f.confsA[0]
		for _, c := range f.confsA {
			if c.EpochStart <= round {
				confA = c
			}
		}
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{f.keyA: confA, f.keyB: f.confB}, nil
	}}
	f.verifier = mockIRVerifier{verify: func(_ uint64, req *drctypes.IRChangeReq) (*types.InputRecord, error) {
		if len(req.Requests) == 0 { // a T2 timeout repeats the shard's certified input record
			return &types.InputRecord{Version: 1}, nil
		}
		return req.Requests[0].InputRecord, nil
	}}
	return f
}

// start is the block at round 2 over the epoch 0 configurations, with A's current-epoch fees non-zero.
func (f *switchFixture) start() *ExecutedBlock {
	g := genesisBlockWithShard(f.t, f.confsA[0])
	b, err := g.Extend(&drctypes.BlockData{Round: 2, Timestamp: 12, Payload: &drctypes.Payload{}}, f.verifier, f.orch, crypto.SHA256, logger.New(f.t))
	require.NoError(f.t, err)
	require.Contains(f.t, b.ShardState.States, f.keyB, "B is introduced")
	for node := range b.ShardState.States[f.keyA].Fees {
		b.ShardState.States[f.keyA].Fees[node] = 7
	}
	return b
}

func (f *switchFixture) requestB(round uint64) *drctypes.IRChangeReq {
	req := &certification.BlockCertificationRequest{PartitionID: 2, ShardID: types.ShardID{}, NodeID: f.signersB[0].PeerConf.ID.String(),
		InputRecord: &types.InputRecord{Version: 1, PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}, RoundNumber: round, SumOfEarnedFees: 3}}
	require.NoError(f.t, req.Sign(f.signersB[0].Signer))
	return &drctypes.IRChangeReq{Partition: 2, CertReason: drctypes.Quorum, Requests: []*certification.BlockCertificationRequest{req}}
}

func (f *switchFixture) extend(parent *ExecutedBlock, round uint64, reqs ...*drctypes.IRChangeReq) (*ExecutedBlock, error) {
	return parent.Extend(&drctypes.BlockData{Round: round, Timestamp: 12 + round, Payload: &drctypes.Payload{Requests: reqs}}, f.verifier, f.orch, crypto.SHA256, logger.New(f.t))
}

// A shard idle across scheduled starts: the block at which a configuration becomes effective switches it, driven by the root's
// execution; other partitions keep executing in that very block.
func TestIdleShardSwitchesAtEveryScheduledStartWhileOthersExecute(t *testing.T) {
	f := newSwitchFixture(t)
	prev := f.start()
	for _, tc := range []struct {
		round, epoch uint64
		switches     bool
	}{{20, 0, false}, {29, 0, false}, {30, 1, true}, {31, 1, false}, {44, 1, false}, {45, 2, true}, {54, 2, false}, {55, 3, true}, {56, 3, false}} {
		before := prev.ShardState.States[f.keyA]
		b, err := f.extend(prev, tc.round, f.requestB(tc.round))
		require.NoError(t, err, "round %d", tc.round)
		a := b.ShardState.States[f.keyA]
		require.Equal(t, tc.epoch, a.TR.Epoch, "round %d", tc.round)
		require.Contains(t, b.ShardState.Changed, f.keyB, "round %d: the executing shard continues in the block that switches another", tc.round)
		if tc.switches {
			require.Contains(t, b.ShardState.Changed, f.keyA, "round %d: the transition is certified without any request", tc.round)
			require.Equal(t, before.TR.Round+1, a.TR.Round, "round %d: the shard round advances once", tc.round)
			require.NotEqual(t, before.ShardConfHash, a.ShardConfHash)
			require.Equal(t, before.IR, a.IR, "round %d: an old IR is valid under the newly announced assignment", tc.round)
			require.Equal(t, before.RootHash, a.RootHash)
		} else {
			require.NotContains(t, b.ShardState.Changed, f.keyA, "round %d", tc.round)
			require.Equal(t, before.TR, a.TR, "round %d: nothing moves in an idle shard", tc.round)
			require.Equal(t, before.PrevEpochFees, a.PrevEpochFees, "round %d: the accounting is not rotated again", tc.round)
		}
		prev = b
	}
}

// The newest effective configuration is installed directly when several starts passed unobserved: no intermediate state, no
// synthetic credit; the previous-epoch slot holds the previous APPLIED epoch (the parent's own accounting), once.
func TestShardJumpsOverSeveralScheduledStartsDirectly(t *testing.T) {
	f := newSwitchFixture(t)
	parent := f.start()
	before := parent.ShardState.States[f.keyA]
	wantFees, err := types.Cbor.Marshal(before.Fees)
	require.NoError(t, err)
	b, err := f.extend(parent, 60) // rounds 30, 45 and 55 all passed: epoch 3 is effective
	require.NoError(t, err)
	a := b.ShardState.States[f.keyA]
	require.EqualValues(t, 3, a.TR.Epoch, "directly to the newest effective configuration")
	require.Equal(t, before.TR.Round+1, a.TR.Round, "one round, not one per skipped epoch")
	require.Equal(t, types.RawCBOR(wantFees), a.PrevEpochFees, "the previous applied epoch's accumulators; nothing is fabricated for the skipped epochs")
	require.Len(t, a.Fees, 3)
	for node, fee := range a.Fees {
		require.Zero(t, fee, node)
	}
	require.Contains(t, b.ShardState.Changed, f.keyA)
	h3, err := f.confsA[3].Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, h3, a.ShardConfHash)

	// the idle blocks after it, old IR and T2 repeats included, neither switch nor rotate again
	cur := b
	for i, round := range []uint64{61, 62, 63} {
		var reqs []*drctypes.IRChangeReq
		if i > 0 { // a T2 timeout request of the shard: no certification request, the IR stays the old one
			reqs = append(reqs, &drctypes.IRChangeReq{Partition: 1, Shard: types.ShardID{}, CertReason: drctypes.T2Timeout})
		}
		next, err := f.extend(cur, round, reqs...)
		require.NoError(t, err, "round %d", round)
		na := next.ShardState.States[f.keyA]
		require.Equal(t, a.PrevEpochFees, na.PrevEpochFees, "round %d: rotated exactly once", round)
		require.Equal(t, a.PrevEpochStat, na.PrevEpochStat)
		require.EqualValues(t, 3, na.TR.Epoch)
		if i == 0 {
			require.Equal(t, a.IR, na.IR)
		}
		if i > 0 {
			require.Equal(t, cur.ShardState.States[f.keyA].TR.Round+1, na.TR.Round, "a normal timeout attempt advances the round")
			require.Contains(t, next.ShardState.Changed, f.keyA)
		}
		cur = next
	}
}

// Outgoing validators' amounts survive into the previous-epoch slot; the hash commitments of the technical record are those of the
// new accumulators and equal across planning (successorTechnicalRecord) and execution.
func TestSwitchRotatesNonzeroAccountingOnceAndPlanningEqualsExecution(t *testing.T) {
	f := newSwitchFixture(t)
	parent := f.start()
	si := parent.ShardState.States[f.keyA]
	si.Stat.Blocks, si.Stat.BlockFees = 4, 21
	next, err := f.extend(parent, 30)
	require.NoError(t, err)
	a := next.ShardState.States[f.keyA]
	prevFees, err := types.Cbor.Marshal(si.Fees)
	require.NoError(t, err)
	prevStat, err := types.Cbor.Marshal(si.Stat)
	require.NoError(t, err)
	require.Equal(t, types.RawCBOR(prevFees), a.PrevEpochFees)
	require.Equal(t, types.RawCBOR(prevStat), a.PrevEpochStat)
	require.Equal(t, certification.StatisticalRecord{}, a.Stat)
	feeHash, err := a.feeHash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, feeHash, []byte(a.TR.FeeHash))
	statHash, err := a.statHash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, statHash, []byte(a.TR.StatHash))

	// planning (H's successor record) is the same operation as the execution of the switching block
	planned, err := successorTechnicalRecord(si, f.confsA[1], crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, a.TR, planned, "configuration, members, leader and TR hash equal across planning and execution")
	// the plan is the +1 admission: a forged multi-step successor is refused, although the operation itself could jump
	_, err = successorTechnicalRecord(si, f.confsA[2], crypto.SHA256)
	require.ErrorIs(t, err, ErrAssignmentHistory)
	// and the switch set the proposer excludes is the one the executor refuses
	set, err := switchingShards(parent.ShardState, map[types.PartitionShardID]*types.PartitionDescriptionRecord{f.keyA: f.confsA[1], f.keyB: f.confB}, crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, ShardSet{f.keyA: {}}, set)
}

// No request, and no T2 timeout request, is applied to a shard in the block that switches it; the others are not affected.
func TestSwitchingShardGetsNoRequestInTheSwitchingBlock(t *testing.T) {
	f := newSwitchFixture(t)
	parent := f.start()
	reqA := func(reason drctypes.IRChangeReason) *drctypes.IRChangeReq {
		return &drctypes.IRChangeReq{Partition: 1, Shard: types.ShardID{}, CertReason: reason}
	}
	_, err := f.extend(parent, 30, reqA(drctypes.T2Timeout))
	require.ErrorIs(t, err, ErrShardSwitching, "a T2 repeat of the switching shard")
	_, err = f.extend(parent, 30, f.requestB(30), reqA(drctypes.T2Timeout))
	require.ErrorIs(t, err, ErrShardSwitching, "refused whole: not silently skipped")
	b, err := f.extend(parent, 30, f.requestB(30))
	require.NoError(t, err)
	require.Contains(t, b.ShardState.Changed, f.keyB)
	// the parent is not affected by any attempt
	require.EqualValues(t, 0, parent.ShardState.States[f.keyA].TR.Epoch)
}

func TestShardRoundOverflowIsAnErrorNotAWrap(t *testing.T) {
	f := newSwitchFixture(t)
	parent := f.start()
	parent.ShardState.States[f.keyA].TR.Round = math.MaxUint64
	_, err := f.extend(parent, 30)
	require.ErrorIs(t, err, ErrShardRoundOverflow)
	si := parent.ShardState.States[f.keyB]
	si.TR.Round = math.MaxUint64
	require.ErrorIs(t, si.nextRound(nil), ErrShardRoundOverflow)
}

// A backward epoch, the same epoch under another configuration, and a hash the trusted history does not name are errors, never "unchanged".
func TestSwitchRefusesBackwardSameEpochAndUnknownAppliedConfiguration(t *testing.T) {
	f := newSwitchFixture(t)
	parent := f.start()
	si := parent.ShardState.States[f.keyA]

	older := *f.confsA[1]
	next, _, err := advanceShardConfiguration(si, &older, crypto.SHA256)
	require.NoError(t, err)
	_, _, err = advanceShardConfiguration(next, f.confsA[0], crypto.SHA256)
	require.ErrorIs(t, err, ErrShardEpoch, "backward")
	other := *f.confsA[1]
	other.T2Timeout++
	_, _, err = advanceShardConfiguration(next, &other, crypto.SHA256)
	require.ErrorIs(t, err, ErrShardEpoch, "the same epoch, another configuration")

	confs := map[types.PartitionShardID]*types.PartitionDescriptionRecord{f.keyA: f.confsA[1]}
	_, _, err = parent.ShardState.nextBlockSwitching(confs, crypto.SHA256, historyOf())
	require.ErrorIs(t, err, ErrConfigHistory, "a missing history is not 'unchanged'")
	_, _, err = parent.ShardState.nextBlockSwitching(confs, crypto.SHA256, historyOf(f.confsA[0]))
	require.NoError(t, err)
	wrongEpoch := *f.confsA[0]
	wrongEpoch.Epoch = 9
	_, _, err = parent.ShardState.nextBlockSwitching(confs, crypto.SHA256, corruptHistory{&wrongEpoch})
	require.ErrorIs(t, err, ErrShardEpoch, "the hash names a configuration of another epoch than the state's")
	// unchanged shards never consult the history: no scan on every block
	same := map[types.PartitionShardID]*types.PartitionDescriptionRecord{f.keyA: f.confsA[0]}
	_, switched, err := parent.ShardState.nextBlockSwitching(same, crypto.SHA256, historyOf())
	require.NoError(t, err)
	require.Empty(t, switched)
	_ = bytes.Equal
}

type testHistory struct {
	confs []*types.PartitionDescriptionRecord
}

func historyOf(confs ...*types.PartitionDescriptionRecord) testHistory { return testHistory{confs} }

func (h testHistory) ShardConfigByHash(_ types.PartitionID, _ types.ShardID, hash []byte, alg crypto.Hash) (*types.PartitionDescriptionRecord, error) {
	for _, c := range h.confs {
		if got, err := c.Hash(alg); err == nil && bytes.Equal(got, hash) {
			return c, nil
		}
	}
	return nil, ErrAssignmentHistory
}

// corruptHistory answers every hash with one configuration (a corrupted history: the hash does not name what is stored).
type corruptHistory struct {
	conf *types.PartitionDescriptionRecord
}

func (h corruptHistory) ShardConfigByHash(types.PartitionID, types.ShardID, []byte, crypto.Hash) (*types.PartitionDescriptionRecord, error) {
	return h.conf, nil
}

// The proposer's view of the same plan: from the exact proposal parent, the shards whose configuration becomes effective at the block's
// round; a terminal suffix executes nothing, so nothing switches there.
func TestSwitchingShardsForBlockIsThePlanFromTheProposalParent(t *testing.T) {
	s := profileStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	cur, err := s.orchestration.ShardConfigs(1)
	require.NoError(t, err)
	var key types.PartitionShardID
	var conf0 *types.PartitionDescriptionRecord
	for k, c := range cur {
		key, conf0 = k, c
	}
	_, infos := testutils.CreateTestNodes(t, 2)
	conf1 := *conf0
	conf1.Epoch, conf1.EpochStart, conf1.Validators = 1, 30, infos
	s.orchestration = mockOrchestration{shardConfigs: func(round uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		if round >= 30 {
			return map[types.PartitionShardID]*types.PartitionDescriptionRecord{key: &conf1}, nil
		}
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{key: conf0}, nil
	}}
	set, err := s.SwitchingShardsForBlock(1, 29)
	require.NoError(t, err)
	require.Empty(t, set)
	set, err = s.SwitchingShardsForBlock(1, 30)
	require.NoError(t, err)
	require.Equal(t, ShardSet{key: {}}, set)
	set, err = s.SwitchingShardsForBlock(1, 500)
	require.NoError(t, err, "however far the round is: the exact parent decides")
	require.Equal(t, ShardSet{key: {}}, set)
	_, err = s.SwitchingShardsForBlock(77, 30)
	require.Error(t, err, "an unknown parent is an error, not an empty plan")

	root := s.blockTree.Root()
	root.ShardState.Control.Phase = "committed"
	set, err = s.SwitchingShardsForBlock(1, 30)
	require.NoError(t, err)
	require.Empty(t, set, "the old-epoch terminal suffix keeps its state: nothing switches there")
}
