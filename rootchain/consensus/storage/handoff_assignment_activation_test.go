package storage

import (
	"bytes"
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func (f *assignmentFixture) useRealOrchestration(t *testing.T) {
	t.Helper()
	orch, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orch.db"), logger.New(t), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = orch.Close() })
	// The handoff profile is not enabled here: tests add further genesis shards (addAggregator) and the derived install does not
	// depend on it. freshOrchestration (profile on, one atomic genesis) covers the profile's refusals.
	require.NoError(t, orch.AddShardConfig(f.current))
	f.orch = orch
	f.store.orchestration = orch
}

// seedFees gives the frozen shard nonzero fees so a repeated epoch switch is
// observable: each switch would move the (reset) current fees into PrevEpochFees.
func (f *assignmentFixture) seedFees(t *testing.T) {
	t.Helper()
	f.installShard(t, f.current, func(si *ShardInfo) {
		si.IR.BlockHash = bytes.Clone(f.parent)
		si.Fees["ev-a"] = 7
		var err error
		si.TR.FeeHash, err = si.feeHash(crypto.SHA256)
		require.NoError(t, err)
	})
}

type committedAssignment struct {
	built      builtFreeze
	commit     evmroot.OrderedHandoffRecord
	candidate  evmassign.Candidate
	activated  *types.PartitionDescriptionRecord
	successorT []byte
	head       *abdrc.CommittedBlock
	verified   evmroot.VerifiedHandoff
	genesis    evmroot.EpochGenesis
}

func (f *assignmentFixture) commitAssignment(t *testing.T) committedAssignment {
	t.Helper()
	c := f.candidate(t)
	b := f.build(t, c)
	addProfileBlock(t, f.store, 2, [][]byte{b.prepare.Bytes()})
	parent, err := f.store.Block(2)
	require.NoError(t, err)
	_, err = f.store.Add(&rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{b.freeze.Bytes(), b.companion}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
	require.NoError(t, err)

	frozen := f.store.blockTree.Root().ShardState.States[f.shard]
	activated, err := evmassign.Activate(f.succ, b.freeze.ActivationRound)
	require.NoError(t, err)
	tr, err := successorTechnicalRecord(frozen, activated, crypto.SHA256)
	require.NoError(t, err)
	trHash, err := tr.Hash()
	require.NoError(t, err)
	commit := b.freeze
	commit.Kind, commit.OrderedRound, commit.SuccessorTRHash = "commit", 4, trHash

	// A commit that binds anything but the derived successor record is refused.
	wrong := commit
	own, err := frozen.TR.Hash()
	require.NoError(t, err)
	wrong.SuccessorTRHash = own
	_, err = f.store.Add(&rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{wrong.Bytes()}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1, CurrentRootHash: mustBlock(t, f.store, 3).RootHash}}}, nil)
	require.ErrorIs(t, err, ErrHandoffRecord)
	require.ErrorIs(t, err, ErrAssignmentHistory)

	h := addProfileBlock(t, f.store, 4, [][]byte{commit.Bytes()})
	suffix := addProfileBlock(t, f.store, 5, nil)
	_, err = f.store.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 4, Epoch: 1, Hash: h.RootHash}})
	require.NoError(t, err)
	head := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	head.ShardInfo, err = toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	v := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: 4, CommitSealRound: 5, Epoch: 1}
	g := evmroot.EpochGenesis{Network: 5, Epoch: 2, Start: 7, OrderedRound: 4, NextBodyID: commit.NextBodyID,
		RecordID: commit.ID(), Root: suffix.RootHash, ControlDigest: v.ControlDigest, FrozenID: commit.FrozenID, SuccessorTRHash: trHash}
	return committedAssignment{built: b, commit: commit, candidate: c, activated: activated, successorT: trHash, head: head, verified: v, genesis: g}
}

func (f *assignmentFixture) addSuccessorBlock(t *testing.T, s *BlockStore, round uint64, anchor *rctypes.EpochAnchor) *ExecutedBlock {
	t.Helper()
	block := &rctypes.BlockData{Version: 2, Round: round, Epoch: 2, Payload: &rctypes.Payload{Version: 2}}
	if anchor != nil {
		block.Anchor = anchor
	} else {
		prior, err := s.Block(round - 1)
		require.NoError(t, err)
		block.Qc = &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 2, CurrentRootHash: prior.RootHash}}
	}
	_, err := s.Add(block, nil)
	require.NoError(t, err)
	return mustBlock(t, s, round)
}

func TestEVMAssignmentActivatesOnceFromCommittedHistoryAndSurvivesRestart(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	oldConf, err := f.orch.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 0, oldConf[f.shard].Epoch, "nothing is installed from an uncommitted candidate")

	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	before, err := f.orch.ShardConfigs(6)
	require.NoError(t, err)
	require.EqualValues(t, 0, before[f.shard].Epoch, "the retired set stays authoritative before the activation round")
	after, err := f.orch.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 1, after[f.shard].Epoch)
	require.EqualValues(t, 7, after[f.shard].EpochStart)
	require.Equal(t, h.activated.Validators[1].NodeID, after[f.shard].Validators[1].NodeID)
	// Installing again is a no-op.
	_, err = f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)

	restart := func() *BlockStore {
		s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		return s
	}
	s := restart()
	first := f.addSuccessorBlock(t, s, 7, anchor)
	newConfHash, err := evmassign.PDRHash(h.activated)
	require.NoError(t, err)
	check := func(block *ExecutedBlock, rounds string) {
		t.Helper()
		si := block.ShardState.States[f.shard]
		require.Equal(t, newConfHash[:], []byte(si.ShardConfHash), rounds)
		require.EqualValues(t, 1, si.TR.Epoch, rounds)
		require.EqualValues(t, 0, si.IR.Epoch, rounds+": P keeps its original IR until the acknowledgement")
		require.Equal(t, bytes.Repeat([]byte{5}, 32), []byte(si.IR.BlockHash), rounds)
		trHash, err := si.TR.Hash()
		require.NoError(t, err)
		require.Equal(t, h.successorT, trHash, rounds+": the installed TR is exactly the one H committed")
		require.Contains(t, si.nodeIDs, "ev-e", rounds)
		require.NotContains(t, si.nodeIDs, "ev-b", rounds+": a retired key is not in the shard's trust base")
		require.ErrorIs(t, si.Verify("ev-b", func(abcrypto.Verifier) error { return nil }), ErrNodeNotInTrustBase, rounds)
		var prev map[string]uint64
		require.NoError(t, types.Cbor.Unmarshal(si.PrevEpochFees, &prev), rounds)
		require.EqualValues(t, 7, prev["ev-a"], rounds+": the retired epoch's fees are rolled exactly once")
		require.Zero(t, si.Fees["ev-a"], rounds)
	}
	check(first, "activation block")
	for round := uint64(8); round <= 10; round++ {
		check(f.addSuccessorBlock(t, s, round, nil), "later block")
	}
	// A restart reloads the new set, never the retired one.
	s = restart()
	check(mustBlock(t, s, 10), "after restart")
	for _, retired := range []string{"ev-b", "ev-c", "ev-d"} {
		require.NotContains(t, mustBlock(t, s, 10).ShardState.States[f.shard].nodeIDs, retired)
	}
}

func freshOrchestration(t *testing.T, f *assignmentFixture, extra ...*types.PartitionDescriptionRecord) *partitions.Orchestration {
	t.Helper()
	orch, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "fresh.db"), logger.New(t), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = orch.Close() })
	orch.EnableHandoffProfile()
	require.NoError(t, orch.InitGenesisShardConfigs(append([]*types.PartitionDescriptionRecord{f.current}, extra...)...))
	return orch
}

func TestCrashBetweenAnchorAndDerivedEntryIsRepairedFromCommittedData(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)

	// The anchor is durable but the derived index was lost: a fresh orchestration
	// holds only the genesis configuration.
	lost := freshOrchestration(t, f)
	before, err := lost.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 0, before[f.shard].Epoch)
	s, err := New(crypto.SHA256, f.store.storage, lost, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	repaired, err := lost.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 1, repaired[f.shard].Epoch)
	repairedHash, err := evmassign.PDRHash(repaired[f.shard])
	require.NoError(t, err)
	activatedHash, err := evmassign.PDRHash(h.activated)
	require.NoError(t, err)
	require.Equal(t, activatedHash, repairedHash, "the repaired entry is the identical derived configuration")
	first := f.addSuccessorBlock(t, s, 7, anchor)
	require.Equal(t, h.successorT, mustTRHash(t, first.ShardState.States[f.shard]))
	// Repairing again is idempotent.
	_, err = New(crypto.SHA256, f.store.storage, lost, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
}

func mustTRHash(t *testing.T, si *ShardInfo) []byte {
	t.Helper()
	h, err := si.TR.Hash()
	require.NoError(t, err)
	return h
}

func TestConflictingDerivedEntryRefusesStartup(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	h := f.commitAssignment(t)
	_, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)

	conflicting := freshOrchestration(t, f)
	other, err := evmassign.NewSuccessor(f.current, []*types.NodeInfo{f.nextKeys[1].info})
	require.NoError(t, err)
	rogue, err := evmassign.Activate(other, 7)
	require.NoError(t, err)
	rogueProvenance, err := evmassign.Provenance{RecordID: bytes.Repeat([]byte{9}, 32), CandidateDigest: bytes.Repeat([]byte{8}, 32), RootEpoch: 2}.Bytes()
	require.NoError(t, err)
	require.NoError(t, conflicting.InstallDerivedShardConfig(rogue, rogueProvenance))
	_, err = New(crypto.SHA256, f.store.storage, conflicting, logger.New(t), ProfileHandoff)
	require.ErrorIs(t, err, partitions.ErrDerivedConflict)
	// The unrelated REST/config path cannot write an EVM epoch after genesis.
	require.ErrorIs(t, conflicting.AddShardConfig(rogue), partitions.ErrDerivedOnly)
}

type withoutCandidates struct{ PersistentStore }

func TestMissingCandidateRefusesActivationAndStartup(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	h := f.commitAssignment(t)
	lost := freshOrchestration(t, f)
	// Anchor installation through a store that cannot return the retained
	// candidate must refuse, not fall back to the retired configuration.
	blind, err := New(crypto.SHA256, withoutCandidates{f.store.storage}, lost, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	_, err = blind.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.ErrorIs(t, err, ErrAssignmentHistory)
	after, err := lost.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 0, after[f.shard].Epoch, "nothing is installed from missing history")
}

func TestInitBlockRefusesAConfigurationThatIsNotTheStoredOne(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	block := f.addSuccessorBlock(t, s, 7, anchor)
	old := mockOrchestration{shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{f.shard: f.current}, nil
	}}
	require.ErrorIs(t, initBlock(block, old), ErrAssignmentHistory,
		"a restart that resolved the retired configuration must refuse readiness")
	require.NoError(t, initBlock(block, f.orch))
}

func TestAbortThenRetryWithAnotherAssignmentInstallsOnlyTheRetry(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)

	// Attempt 0: prepare, freeze, then an old-quorum abort.
	first := f.build(t, f.candidate(t))
	require.NoError(t, f.admit(t, first))
	abort := first.freeze
	abort.Kind, abort.OrderedRound = "abort", 4
	abortCompanion := f.abortCompanionFor(t, abort)
	parent := mustBlock(t, f.store, 3)
	_, err := f.store.Add(&rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{abort.Bytes(), abortCompanion}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
	require.NoError(t, err)
	require.Equal(t, "aborted", mustBlock(t, f.store, 4).ShardState.Control.Phase)

	// Attempt 1 carries a different successor set and fresh proofs of possession.
	f.pop.Attempt = 1
	f.base = 5
	f.nextKeys = []evmKey{f.oldKeys[0], newEVMKey(t, "ev-h"), newEVMKey(t, "ev-i"), newEVMKey(t, "ev-j")}
	infos := make([]*types.NodeInfo, 0, 4)
	for _, k := range f.nextKeys {
		infos = append(infos, k.info)
	}
	f.succ, err = evmassign.NewSuccessor(f.current, infos)
	require.NoError(t, err)
	retry := f.build(t, f.candidate(t))
	require.NotEqual(t, first.freeze.NextBodyID, retry.freeze.NextBodyID)
	f.addAt(t, 5, retry.prepare.Bytes())
	f.addAt(t, 6, retry.freeze.Bytes(), retry.companion)

	frozen := mustBlock(t, f.store, 6).ShardState.States[f.shard]
	activated, err := evmassign.Activate(f.succ, retry.freeze.ActivationRound)
	require.NoError(t, err)
	tr, err := successorTechnicalRecord(frozen, activated, crypto.SHA256)
	require.NoError(t, err)
	commit := retry.freeze
	commit.Kind, commit.OrderedRound, commit.SuccessorTRHash = "commit", 7, mustTRHash2(t, &tr)
	f.addAt(t, 7, commit.Bytes())
	suffix := f.addAt(t, 8)
	_, err = f.store.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 8, ParentRoundNumber: 7, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 7, Epoch: 1, Hash: mustBlock(t, f.store, 7).RootHash}})
	require.NoError(t, err)
	head := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	head.ShardInfo, err = toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	v := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: 7, CommitSealRound: 8, Epoch: 1}
	g := evmroot.EpochGenesis{Network: 5, Epoch: 2, Start: commit.ActivationRound, OrderedRound: 7, NextBodyID: commit.NextBodyID,
		RecordID: commit.ID(), Root: suffix.RootHash, ControlDigest: v.ControlDigest, FrozenID: commit.FrozenID, SuccessorTRHash: commit.SuccessorTRHash}
	_, err = f.store.InstallEpochAnchor(head, v, g)
	require.NoError(t, err)

	installed, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	var ids []string
	for _, n := range installed[f.shard].Validators {
		ids = append(ids, n.NodeID)
	}
	require.Contains(t, ids, "ev-h", "only attempt 1's assignment is installed")
	require.NotContains(t, ids, "ev-e", "the aborted attempt's assignment is never installed")
	require.EqualValues(t, 1, installed[f.shard].Epoch)
	aborted, err := f.store.HandoffCandidate(first.freeze.NextBodyID)
	require.NoError(t, err)
	require.Equal(t, first.preimage, aborted, "the aborted candidate stays retained as history but is not derived")
}

func mustTRHash2(t *testing.T, tr interface{ Hash() ([]byte, error) }) []byte {
	t.Helper()
	h, err := tr.Hash()
	require.NoError(t, err)
	return h
}

func (f *assignmentFixture) addAt(t *testing.T, round uint64, records ...[]byte) *ExecutedBlock {
	t.Helper()
	parent := mustBlock(t, f.store, round-1)
	payload := &rctypes.Payload{Version: 2}
	if len(records) > 0 {
		payload.HandoffRecords = records
	}
	_, err := f.store.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 1, Payload: payload,
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
	require.NoError(t, err)
	return mustBlock(t, f.store, round)
}

func (f *assignmentFixture) abortCompanionFor(t *testing.T, r evmroot.OrderedHandoffRecord) []byte {
	t.Helper()
	message, err := AbortEndorsementBytes(r)
	require.NoError(t, err)
	sigs := map[string]hex.Bytes{}
	for _, name := range []string{"old-a", "old-b", "old-c"} {
		sig, err := f.signers[name].SignBytes(message)
		require.NoError(t, err)
		sigs[name] = sig
	}
	encoded, err := (AbortAuthorization{Version: 1, Signatures: sigs}).Bytes()
	require.NoError(t, err)
	return encoded
}

func TestAcknowledgementEndsThePendingStateAndRetiredKeysStayRefused(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchor)
	pending := mustBlock(t, s, 7).ShardState.States[f.shard]
	require.NotEqual(t, pending.TR.Epoch, pending.IR.Epoch, "installed but not acknowledged")
	require.True(t, pending.TR.Epoch != pending.IR.Epoch)

	// The successor set certifies its acknowledgement: IR now carries the new
	// shard epoch and the same configuration stays installed.
	prior := mustBlock(t, s, 7)
	ack := &types.InputRecord{Version: 1, RoundNumber: pending.TR.Round, Epoch: pending.TR.Epoch,
		BlockHash: bytes.Repeat([]byte{0x77}, 32), PreviousHash: pending.IR.Hash, Hash: bytes.Repeat([]byte{0x78}, 32)}
	_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 2,
		Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: prior.RootHash}}},
		mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) { return ack, nil }})
	require.NoError(t, err)
	acked := mustBlock(t, s, 8).ShardState.States[f.shard]
	require.Equal(t, acked.TR.Epoch, acked.IR.Epoch, "no assignment acknowledgement is pending any more")
	require.Equal(t, pending.ShardConfHash, acked.ShardConfHash)
	var prev map[string]uint64
	require.NoError(t, types.Cbor.Unmarshal(acked.PrevEpochFees, &prev))
	require.EqualValues(t, 7, prev["ev-a"], "certifying the ack does not run the epoch switch again")
	f.addSuccessorBlock(t, s, 9, nil)

	// After a restart the retired keys are still outside the trust base, so a
	// request signed by them with the new epoch field cannot be admitted.
	s, err = New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	si := mustBlock(t, s, 9).ShardState.States[f.shard]
	for _, retired := range []string{"ev-b", "ev-c", "ev-d"} {
		err = si.ValidRequest(&certification.BlockCertificationRequest{PartitionID: 8, NodeID: retired,
			InputRecord: &types.InputRecord{Version: 1, Epoch: si.TR.Epoch}})
		require.ErrorIs(t, err, ErrNodeNotInTrustBase, retired)
	}
}

func TestActivationRefusesACheckpointWhoseCommittedRecordIsNotTheDerivedOne(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	_, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	root := f.store.blockTree.Root()
	configs, err := f.orch.ShardConfigs(7)
	require.NoError(t, err)
	record := h.commit
	_, err = activateEVMAssignment(root.ShardState.States, configs, record, 7, crypto.SHA256, nil)
	require.NoError(t, err)
	wrong := record
	wrong.SuccessorTRHash = bytes.Repeat([]byte{0x99}, 32)
	_, err = activateEVMAssignment(root.ShardState.States, configs, wrong, 7, crypto.SHA256, nil)
	require.ErrorIs(t, err, ErrControlCheckpoint)
	require.ErrorContains(t, err, "differs from the derived assignment")
	_, err = activateEVMAssignment(root.ShardState.States, configs, record, 8, crypto.SHA256, nil)
	require.ErrorIs(t, err, ErrControlCheckpoint, "the derived configuration activates only at its own boundary")
}

func TestAssignmentActivationRefusesADerivedRecordThatIsNotH(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	h := f.commitAssignment(t)
	root := f.store.blockTree.Root()
	wrong := h.commit
	wrong.SuccessorTRHash = bytes.Repeat([]byte{0x99}, 32)
	fresh := freshOrchestration(t, f)
	err := installCommittedAssignmentFrom(f.store.storage, fresh, crypto.SHA256, snapshotRootOf(t, f, h), wrong, h.genesis.OrderedRound)
	_ = root
	require.ErrorIs(t, err, ErrAssignmentHistory)
	require.ErrorContains(t, err, "derived successor technical record differs from H")
}

func snapshotRootOf(t *testing.T, f *assignmentFixture, h committedAssignment) *ExecutedBlock {
	t.Helper()
	block, err := NewRootBlock(h.head, crypto.SHA256, f.orch, ProfileHandoff)
	require.NoError(t, err)
	return block
}

func TestDeriveActivatedPDRIsolatedRefusals(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	c := f.candidate(t)
	b := f.build(t, c)
	body := b.body
	record := b.freeze
	record.Kind = "commit"
	_, _, err := DeriveActivatedPDR(record, body, b.preimage, f.parent)
	require.NoError(t, err)

	// S12: the body names another candidate context, but the record is re-linked to that body's identity, so
	// only the D4 change-record check can refuse it.
	other := body
	other.ChangeRecordHash = bytes.Repeat([]byte{1}, 32)
	relinked := record
	otherID := other.Identity()
	relinked.NextBodyID = otherID[:]
	_, _, err = DeriveActivatedPDR(relinked, other, b.preimage, f.parent)
	require.ErrorIs(t, err, ErrAssignmentHistory)
	wrongAttempt := record
	wrongAttempt.Attempt = 3
	_, _, err = DeriveActivatedPDR(wrongAttempt, body, b.preimage, f.parent)
	require.ErrorIs(t, err, ErrAssignmentHistory)
	wrongBody := record
	wrongBody.NextBodyID = bytes.Repeat([]byte{2}, 32)
	_, _, err = DeriveActivatedPDR(wrongBody, body, b.preimage, f.parent)
	require.ErrorIs(t, err, ErrAssignmentHistory)
}
