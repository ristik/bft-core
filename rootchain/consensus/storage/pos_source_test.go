package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-go-base/types"
)

func posOfBlock(t *testing.T, b *ExecutedBlock) rootrecords.State {
	t.Helper()
	require.NotNil(t, b.ShardState.Control)
	s, err := rootrecords.DecodeState(b.ShardState.Control.Pos)
	require.NoError(t, err)
	return s
}

func word32(b []byte, i int) uint64 {
	var v uint64
	for _, x := range b[32*i+24 : 32*i+32] {
		v = v<<8 | uint64(x)
	}
	return v
}

// The root's source state is committed in the control state: the genesis carries it, H fixes the successor's offset, the first
// successor block ends the freeze, the certified acknowledgement projects its record at the acknowledging block's progress and time,
// and ordinary and empty blocks leave the committed digest alone.
func TestRootSourceProjectsTheAcknowledgementOfACommittedAssignment(t *testing.T) {
	genesis, err := NewGenesisBlock(5, crypto.SHA256, ProfileHandoff)
	require.NoError(t, err)
	g := posOfBlock(t, genesis)
	require.EqualValues(t, 1, g.Epoch)
	require.EqualValues(t, rctypes.GenesisRootRound+1, g.First, "ordinary rounds follow the genesis round")
	require.Zero(t, g.Offset)

	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)

	// H was ordered at round 4: the old epoch froze at p(1,4), the successor starts at the next offset on the activation round.
	suffix := mustBlock(t, f.store, 5)
	frozen := posOfBlock(t, suffix)
	first := rctypes.GenesisRootRound + 1
	require.True(t, frozen.Frozen)
	require.EqualValues(t, 4-first, frozen.Endpoint)
	require.Len(t, frozen.Pending, 1)
	pend := frozen.Pending[0]
	require.EqualValues(t, 4, pend.HRound)
	require.EqualValues(t, 4-first+1, pend.Offset)
	require.EqualValues(t, h.commit.ActivationRound, pend.First)
	require.EqualValues(t, 2, pend.RootEpoch)
	require.Equal(t, h.commit.NextBodyID, pend.BodyID[:])
	require.Zero(t, frozen.Count, "the acknowledgement has not been certified yet")

	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	b7 := f.addSuccessorBlock(t, s, 7, anchor)
	started := posOfBlock(t, b7)
	require.False(t, started.Frozen, "the first successor block at the activation round ends the freeze")
	require.EqualValues(t, 2, started.Epoch)
	require.Equal(t, pend.Offset, started.Offset)
	require.Equal(t, pend.First, started.First)
	require.Equal(t, frozen.Pending, started.Pending, "the pending acknowledgement survives")
	require.Empty(t, b7.ShardState.Records)

	// the EVM certifies its acknowledgement in round 8
	pending := b7.ShardState.States[f.shard]
	ack := &types.InputRecord{Version: 1, RoundNumber: pending.TR.Round, Epoch: pending.TR.Epoch,
		BlockHash: bytes.Repeat([]byte{0x77}, 32), PreviousHash: pending.IR.Hash, Hash: bytes.Repeat([]byte{0x78}, 32)}
	_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 2, Timestamp: 1_000,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: b7.RootHash}}},
		mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) { return ack, nil }})
	require.NoError(t, err)
	b8 := mustBlock(t, s, 8)
	require.Len(t, b8.ShardState.Records, 1)
	rec := b8.ShardState.Records[0]
	require.Equal(t, rootrecords.KindAck, rec.Kind)
	require.EqualValues(t, 0, rec.Index)
	require.Equal(t, h.candidate.ResultID(), [32]byte(rec.Data[:32]), "the election result of the retained candidate")
	require.EqualValues(t, 4, word32(rec.Data, 1), "the replaced H round")
	require.EqualValues(t, pend.Offset, word32(rec.Data, 2), "the offset fixed when H was ordered, read again here")
	require.EqualValues(t, pend.First, word32(rec.Data, 3))
	require.EqualValues(t, pend.Offset+(8-pend.First), rec.Progress, "progress of the acknowledging block")
	require.EqualValues(t, 1_000, rec.UCTime, "the committed timestamp of the acknowledging block")
	require.NoError(t, rootrecords.Verify(b8.ShardState.Records))

	after := posOfBlock(t, b8)
	require.Empty(t, after.Pending)
	require.EqualValues(t, 1, after.Count)
	require.Equal(t, rec.ID, after.Tip)
	require.NotEqual(t, b7.ShardState.Control.Digest(), b8.ShardState.Control.Digest())

	// an empty block leaves the committed digest, and with it the control leaf, alone
	b9 := f.addSuccessorBlock(t, s, 9, nil)
	require.Equal(t, b8.ShardState.Control.Digest(), b9.ShardState.Control.Digest())
	require.Empty(t, b9.ShardState.Records)
}

func TestPosStepIsOffWithoutASourceState(t *testing.T) {
	p, err := loadPos(&evmroot.ControlState{})
	require.NoError(t, err)
	require.False(t, p.on)
	require.NoError(t, p.block(1, 5))
	require.NoError(t, p.commit(evmroot.OrderedHandoffRecord{}, true))
	require.False(t, p.pendingAck())
	c := &evmroot.ControlState{}
	p.store(c)
	require.Empty(t, c.Pos)
	_, err = loadPos(nil)
	require.NoError(t, err)
}

func TestPosStepRefusesAnUndecodableSourceState(t *testing.T) {
	_, err := loadPos(&evmroot.ControlState{Pos: []byte{1, 2, 3}})
	require.ErrorIs(t, err, ErrPosSource)
}

type fixedCandidates map[string][]byte

func (f fixedCandidates) HandoffCandidate(id []byte) ([]byte, error) { return f[string(id)], nil }

func TestPosStepAckNeedsTheRetainedCandidates(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 32)
	st, err := rootrecords.NewState(1, 2).Commit(5, 2, 9, true, [32]byte(body))
	require.NoError(t, err)
	raw := &evmroot.ControlState{Pos: st.Bytes()}
	p, err := loadPos(raw)
	require.NoError(t, err)
	require.True(t, p.pendingAck())
	require.ErrorIs(t, p.ack(nil, 9, 1_000, 1), ErrPosSource, "no candidate source")
	require.ErrorIs(t, p.ack(fixedCandidates{}, 9, 1_000, 1), ErrPosSource, "the candidate of the pending handoff is not retained")
	require.ErrorIs(t, p.ack(fixedCandidates{string(body): {0x01}}, 9, 1_000, 1), ErrPosSource, "an undecodable candidate")
	require.Empty(t, p.records)
	_ = evmassign.KindPrimary
}

func TestOnlyTheEVMShardsCatchUpIsTheAcknowledgement(t *testing.T) {
	st, err := rootrecords.NewState(1, 2).Commit(5, 2, 9, true, [32]byte{7})
	require.NoError(t, err)
	p, err := loadPos(&evmroot.ControlState{Pos: st.Bytes()})
	require.NoError(t, err)
	evm, other := types.PartitionShardID{PartitionID: 8}, types.PartitionShardID{PartitionID: 9}
	require.True(t, p.acknowledges(true, 3, 3, evm, evm, true))
	require.False(t, p.acknowledges(false, 3, 3, evm, evm, true), "the shard was not awaiting its epoch")
	require.False(t, p.acknowledges(true, 2, 3, evm, evm, true), "the IR epoch has not caught up")
	require.False(t, p.acknowledges(true, 3, 3, other, evm, true), "another shard's epoch change is not the assignment's acknowledgement")
	require.False(t, p.acknowledges(true, 3, 3, evm, evm, false), "no designated EVM shard")
	none, err := loadPos(&evmroot.ControlState{})
	require.NoError(t, err)
	require.False(t, none.acknowledges(true, 3, 3, evm, evm, true), "no handoff awaits")
}

// The records a committed block projected are retained, in order, when it commits, and read back from the store.
func TestCommitRetainsTheProjectedRecords(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	b7 := f.addSuccessorBlock(t, s, 7, anchor)
	pending := b7.ShardState.States[f.shard]
	ack := &types.InputRecord{Version: 1, RoundNumber: pending.TR.Round, Epoch: pending.TR.Epoch,
		BlockHash: bytes.Repeat([]byte{0x77}, 32), PreviousHash: pending.IR.Hash, Hash: bytes.Repeat([]byte{0x78}, 32)}
	_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 2, Timestamp: 1_000,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: b7.RootHash}}},
		mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) { return ack, nil }})
	require.NoError(t, err)
	b8 := mustBlock(t, s, 8)
	f.addSuccessorBlock(t, s, 9, nil)

	db := f.store.storage.(BoltDB)
	n, err := db.RecordCount()
	require.NoError(t, err)
	require.Zero(t, n, "an uncommitted block's records are not retained")

	// commit block 9 (its parent path covers rounds 8 and 9)
	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 10, ParentRoundNumber: 9, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 9, Epoch: 2, Hash: mustBlock(t, s, 9).RootHash}})
	require.NoError(t, err)
	n, err = db.RecordCount()
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	got, err := db.Records(0, 10)
	require.NoError(t, err)
	require.Equal(t, b8.ShardState.Records, got)
	require.NoError(t, rootrecords.Verify(got))
	// a repeated append is idempotent; a conflicting or gapped one is refused
	require.NoError(t, db.AppendRecords(got))
	changed := got[0]
	changed.Progress++
	require.ErrorIs(t, db.AppendRecords([]rootrecords.Record{changed}), ErrRecordLog)
	gap := got[0]
	gap.Index = 5
	require.ErrorIs(t, db.AppendRecords([]rootrecords.Record{gap}), ErrRecordLog)
	next := rootrecords.Record{Index: 1, Predecessor: [32]byte{9}, Kind: rootrecords.KindSessionClosed, Progress: 9, UCTime: 9, Data: make([]byte, 32)}
	next.ID = rootrecords.RecordID(next.Index, next.Predecessor, next.Kind, next.Progress, next.UCTime, next.Data)
	require.ErrorIs(t, db.AppendRecords([]rootrecords.Record{next}), ErrRecordLog, "does not link to the tip")
	next.Predecessor = got[0].ID
	require.ErrorIs(t, db.AppendRecords([]rootrecords.Record{next}), ErrRecordLog, "identifier no longer matches")
	next.ID = rootrecords.RecordID(next.Index, next.Predecessor, next.Kind, next.Progress, next.UCTime, next.Data)
	require.NoError(t, db.AppendRecords([]rootrecords.Record{next}))
	page, err := db.Records(1, 1)
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, next, page[0])
	none, err := db.Records(5, 3)
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestCommittedRecordsFollowTheLogOrderOfTheBlocks(t *testing.T) {
	mk := func(idx uint64) rootrecords.Record { return rootrecords.Record{Index: idx} }
	newest := &ExecutedBlock{ShardState: ShardStates{Records: []rootrecords.Record{mk(2), mk(3)}}}
	middle := &ExecutedBlock{ShardState: ShardStates{}}
	oldest := &ExecutedBlock{ShardState: ShardStates{Records: []rootrecords.Record{mk(1)}}}
	got := committedRecords([]*ExecutedBlock{newest, middle, oldest}) // the path lists the newest first
	require.Equal(t, []rootrecords.Record{mk(1), mk(2), mk(3)}, got)
	require.Empty(t, committedRecords(nil))
}

func TestAppendRecordsRefusesAnIndexJumpThatLinksAndHashes(t *testing.T) {
	db, err := NewBoltStorage(t.TempDir()+"/records.db", WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	r0 := rootrecords.Record{Index: 0, Kind: rootrecords.KindSessionClosed, Progress: 1, UCTime: 1, Data: make([]byte, 32)}
	r0.ID = rootrecords.RecordID(r0.Index, r0.Predecessor, r0.Kind, r0.Progress, r0.UCTime, r0.Data)
	require.NoError(t, db.AppendRecords([]rootrecords.Record{r0}))
	// index 2 with the right predecessor and a matching identifier still skips index 1
	r2 := rootrecords.Record{Index: 2, Predecessor: r0.ID, Kind: rootrecords.KindSessionClosed, Progress: 2, UCTime: 2, Data: make([]byte, 32)}
	r2.ID = rootrecords.RecordID(r2.Index, r2.Predecessor, r2.Kind, r2.Progress, r2.UCTime, r2.Data)
	require.ErrorIs(t, db.AppendRecords([]rootrecords.Record{r2}), ErrRecordLog)
	n, err := db.RecordCount()
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

// the recovery carries its primary's authorization, so both name one election result; a pending pair that does not is refused
func TestPosStepRefusesARecoveryOfAnotherResult(t *testing.T) {
	f := newAssignmentFixture(t)
	c1 := f.candidate(t)
	c2 := c1
	auth := *c1.Authorization
	auth.ResultID = bytes.Repeat([]byte{0x99}, 32)
	c2.Authorization = &auth
	enc1, err := c1.Encode()
	require.NoError(t, err)
	enc2, err := c2.Encode()
	require.NoError(t, err)
	b1, b2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	st, err := rootrecords.NewState(1, 2).Commit(5, 2, 9, true, [32]byte(b1))
	require.NoError(t, err)
	st, err = st.Block(2, 12)
	require.NoError(t, err)
	st, err = st.Commit(14, 3, 20, true, [32]byte(b2))
	require.NoError(t, err)
	p, err := loadPos(&evmroot.ControlState{Pos: st.Bytes()})
	require.NoError(t, err)

	same := fixedCandidates{string(b1): enc1, string(b2): enc1}
	require.NoError(t, (&posStep{on: p.on, raw: p.raw, state: p.state}).ack(same, 22, 1_000, 2), "control: one result for both")
	other := fixedCandidates{string(b1): enc1, string(b2): enc2}
	q := &posStep{on: p.on, raw: p.raw, state: p.state}
	require.ErrorIs(t, q.ack(other, 22, 1_000, 2), ErrPosSource)
	require.Empty(t, q.records)
}

// a block that projected records cannot commit on a store that cannot retain them
type hiddenRecords struct{ PersistentStore }

func TestCommitRefusesToDropProjectedRecords(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	b7 := f.addSuccessorBlock(t, s, 7, anchor)
	pending := b7.ShardState.States[f.shard]
	ack := &types.InputRecord{Version: 1, RoundNumber: pending.TR.Round, Epoch: pending.TR.Epoch,
		BlockHash: bytes.Repeat([]byte{0x77}, 32), PreviousHash: pending.IR.Hash, Hash: bytes.Repeat([]byte{0x78}, 32)}
	_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 2, Timestamp: 1_000,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: b7.RootHash}}},
		mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) { return ack, nil }})
	require.NoError(t, err)
	rootBefore := s.blockTree.Root().GetRound()

	db := f.store.storage.(BoltDB)
	s.blockTree.blocksDB = hiddenRecords{PersistentStore: db}
	qc := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 9, ParentRoundNumber: 8, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 8, Epoch: 2, Hash: mustBlock(t, s, 8).RootHash}}
	_, err = s.blockTree.Commit(qc)
	require.ErrorIs(t, err, ErrNoRecordStore)
	require.Equal(t, rootBefore, s.blockTree.Root().GetRound(), "the block did not become the root")
	n, err := db.RecordCount()
	require.NoError(t, err)
	require.Zero(t, n)

	// a block without records still commits on such a store
	s.blockTree.blocksDB = db
	_, err = s.blockTree.Commit(qc)
	require.NoError(t, err)
}

var _ RecordStore = BoltDB{}
