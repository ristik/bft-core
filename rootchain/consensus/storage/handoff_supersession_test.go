package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// fixedParentAuthority admits any freeze for the epoch-2 root, naming the frozen
// parent the companion carries. The candidate's static binding is exercised
// against the real authority elsewhere; supersession evidence is checked by
// block execution regardless of the authority.
type fixedParentAuthority struct {
	predecessor, parent []byte
	root                []evmassign.RootMember
}

func (a fixedParentAuthority) Predecessor() []byte { return a.predecessor }
func (a fixedParentAuthority) VerifyFreeze(evmroot.OrderedHandoffRecord, []byte) ([]byte, error) {
	return a.parent, nil
}
func (a fixedParentAuthority) CurrentRoot() []evmassign.RootMember                  { return a.root }
func (fixedParentAuthority) VerifyAbort(evmroot.OrderedHandoffRecord, []byte) error { return nil }

type pendingAssignment struct {
	f         *assignmentFixture
	first     committedAssignment
	store     *BlockStore
	installed *types.PartitionDescriptionRecord // the pending s=1 configuration
	body1     []byte
}

// installPendingAssignment drives the first EVM-only handoff to activation and
// returns a root-epoch-2 store whose EVM shard has TR.Epoch 1, IR.Epoch 0.
func installPendingAssignment(t *testing.T) pendingAssignment {
	t.Helper()
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchor)
	f.store = s
	return pendingAssignment{f: f, first: h, store: s, installed: h.activated, body1: h.commit.NextBodyID}
}

// supersession builds a root-epoch-2 handoff (prepare, freeze, commit) that
// replaces the pending s=1 assignment on the same frozen parent.
type supersession struct {
	p        pendingAssignment
	built    builtFreeze
	commit   evmroot.OrderedHandoffRecord
	preimage []byte
}

func (p pendingAssignment) chain(t *testing.T) evmassign.Chain {
	t.Helper()
	pending := mustBlock(t, p.store, 7).ShardState.States[p.f.shard]
	chain, err := CommittedChain(p.f.orch, 8, types.ShardID{}, pending.IR.Epoch)
	require.NoError(t, err)
	require.Len(t, chain.Steps, 1)
	return chain
}

func (p pendingAssignment) supersede(t *testing.T, mutate func(*evmassign.Supersession)) supersession {
	t.Helper()
	binding, err := p.chain(t).Supersession()
	require.NoError(t, err)
	if mutate != nil {
		mutate(binding)
	}
	return p.supersedeWith(t, binding, 8)
}

func (p pendingAssignment) supersedeWith(t *testing.T, binding *evmassign.Supersession, base uint64) supersession {
	t.Helper()
	f := p.f
	var err error
	infos := []*types.NodeInfo{f.oldKeys[0].info}
	f.nextKeys = []evmKey{f.oldKeys[0], newEVMKey(t, "ev-k"), newEVMKey(t, "ev-l"), newEVMKey(t, "ev-m")}
	infos = infos[:0]
	for _, k := range f.nextKeys {
		infos = append(infos, k.info)
	}
	// The replacement is a second coupled handoff: the committee of root epoch 2 changes again.
	f.baseCommittee = f.successorRoot()
	f.nextRootKey = newEVMKey(t, "new-f")
	f.current0 = p.installed
	f.succ, err = evmassign.NewSuccessor(p.installed, infos)
	require.NoError(t, err)
	f.supersedes = binding
	f.rootEpoch = 2
	f.predecessor = p.body1
	f.pop = evmassign.PoPContext{Network: 5, Attempt: 0}
	copy(f.pop.Predecessor[:], p.body1)
	f.base = base
	built := f.build(t, f.candidate(t))
	return supersession{p: p, built: built, preimage: built.preimage}
}

func (s *supersession) addEpoch2(t *testing.T, store *BlockStore, round uint64, records ...[]byte) (*ExecutedBlock, error) {
	t.Helper()
	parent := mustBlock(t, store, round-1)
	payload := &rctypes.Payload{Version: 2}
	if len(records) > 0 {
		payload.HandoffRecords = records
	}
	_, err := store.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 2, Payload: payload,
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 2, CurrentRootHash: parent.RootHash}}}, nil)
	if err != nil {
		return nil, err
	}
	return mustBlock(t, store, round), nil
}

func (s *supersession) admit(t *testing.T) error {
	t.Helper()
	store := s.p.store
	store.handoffAuth = fixedParentAuthority{predecessor: s.p.body1, parent: s.p.f.parent, root: s.p.f.baseCommittee}
	if _, err := s.addEpoch2(t, store, 8, s.built.prepare.Bytes()); err != nil {
		return err
	}
	_, err := s.addEpoch2(t, store, 9, s.built.freeze.Bytes(), s.built.companion)
	return err
}

func TestSupersessionReplacesAnUnacknowledgedAssignmentOnTheSameParent(t *testing.T) {
	p := installPendingAssignment(t)
	pending := mustBlock(t, p.store, 7).ShardState.States[p.f.shard]
	require.EqualValues(t, 1, pending.TR.Epoch)
	require.EqualValues(t, 0, pending.IR.Epoch)
	sup := p.supersede(t, nil)
	require.NoError(t, sup.admit(t), "a replacement of the pending assignment is admitted without any s=1 signature")

	frozen := mustBlock(t, p.store, 9).ShardState.States[p.f.shard]
	activated, err := evmassign.Activate(p.f.succ, sup.built.freeze.ActivationRound)
	require.NoError(t, err)
	tr, err := successorTechnicalRecord(frozen, activated, crypto.SHA256)
	require.NoError(t, err)
	require.EqualValues(t, 2, tr.Epoch, "each replacement advances the installed shard epoch exactly once")
	commit := sup.built.freeze
	commit.Kind, commit.OrderedRound, commit.SuccessorTRHash = "commit", 10, mustTRHash2(t, &tr)
	_, err = sup.addEpoch2(t, p.store, 10, commit.Bytes())
	require.NoError(t, err)
	suffix, err := sup.addEpoch2(t, p.store, 11)
	require.NoError(t, err)
	_, err = p.store.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 11, ParentRoundNumber: 10, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 10, Epoch: 2, Hash: mustBlock(t, p.store, 10).RootHash}})
	require.NoError(t, err)
	head := &abdrc.CommittedBlock{Block: suffix.BlockData, Control: suffix.ShardState.Control,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: suffix.RootHash}}}
	head.ShardInfo, err = toRecoveryShardInfo(suffix)
	require.NoError(t, err)
	v := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: suffix.RootHash,
		ControlDigest: suffix.ShardState.Control.Digest(), OrderRound: 10, CommitSealRound: 11, Epoch: 2}
	g := evmroot.EpochGenesis{Network: 5, Epoch: 3, Start: commit.ActivationRound, OrderedRound: 10, NextBodyID: commit.NextBodyID,
		RecordID: commit.ID(), Root: suffix.RootHash, ControlDigest: v.ControlDigest, FrozenID: commit.FrozenID, SuccessorTRHash: commit.SuccessorTRHash}
	anchor, err := p.store.InstallEpochAnchor(head, v, g)
	require.NoError(t, err)

	chain, err := CommittedChain(p.f.orch, 8, types.ShardID{}, 0)
	require.NoError(t, err)
	require.Len(t, chain.Steps, 2, "the root keeps the supersession chain")
	require.EqualValues(t, 1, chain.BaseRootEpoch)
	require.EqualValues(t, 0, chain.BaseShardEpoch)
	require.EqualValues(t, 2, chain.Steps[1].ShardEpoch)
	require.EqualValues(t, 3, chain.Steps[1].RootEpoch)

	s, err := New(crypto.SHA256, p.store.storage, p.f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	block := &rctypes.BlockData{Version: 2, Round: commit.ActivationRound, Epoch: 3, Payload: &rctypes.Payload{Version: 2}, Anchor: anchor}
	_, err = s.Add(block, nil)
	require.NoError(t, err)
	si := mustBlock(t, s, commit.ActivationRound).ShardState.States[p.f.shard]
	require.EqualValues(t, 2, si.TR.Epoch)
	require.EqualValues(t, 0, si.IR.Epoch, "P's acknowledged state is untouched")
	require.Equal(t, bytes.Repeat([]byte{5}, 32), []byte(si.IR.BlockHash), "same frozen parent")
	require.Contains(t, si.nodeIDs, "ev-k")
	for _, superseded := range []string{"ev-e", "ev-f", "ev-g"} {
		require.NotContains(t, si.nodeIDs, superseded, "the superseded set cannot certify a late acknowledgement")
		err := si.ValidRequest(&certification.BlockCertificationRequest{PartitionID: 8, NodeID: superseded,
			InputRecord: &types.InputRecord{Version: 1, Epoch: si.TR.Epoch}})
		require.ErrorContains(t, err, "not in the trustbase of the shard", superseded)
	}
}

func TestSupersessionEvidenceIsolatedMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*evmassign.Supersession)
	}{
		{"superseded H", func(s *evmassign.Supersession) { s.SupersededH = bytes.Repeat([]byte{1}, 32) }},
		{"base root epoch", func(s *evmassign.Supersession) { s.BaseRootEpoch++ }},
		{"base shard epoch", func(s *evmassign.Supersession) { s.BaseShardEpoch++ }},
		{"base active hash", func(s *evmassign.Supersession) { s.BaseActiveHash = bytes.Repeat([]byte{1}, 32) }},
		{"chain length", func(s *evmassign.Supersession) { s.ChainLen++ }},
		{"chain commitment", func(s *evmassign.Supersession) { s.ChainCommitment = bytes.Repeat([]byte{1}, 32) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := installPendingAssignment(t)
			sup := p.supersede(t, tc.mutate)
			err := sup.admit(t)
			require.ErrorIs(t, err, ErrHandoffRecord)
			require.ErrorIs(t, err, ErrSupersessionInvalid)
			require.ErrorIs(t, err, evmassign.ErrContext)
			require.ErrorContains(t, err, "supersession differs from the committed chain")
		})
	}
	t.Run("an acknowledged assignment cannot be superseded", func(t *testing.T) {
		p := installPendingAssignment(t)
		stale, err := p.chain(t).Supersession()
		require.NoError(t, err)
		// Acknowledge the pending assignment first: IR now carries the shard epoch
		// and names the acknowledgement block as the certified parent.
		prior := mustBlock(t, p.store, 7)
		pending := prior.ShardState.States[p.f.shard]
		ackBlock := bytes.Repeat([]byte{0x77}, 32)
		ack := &types.InputRecord{Version: 1, RoundNumber: pending.TR.Round, Epoch: pending.TR.Epoch,
			BlockHash: ackBlock, Hash: bytes.Repeat([]byte{0x78}, 32)}
		_, err = p.store.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 2,
			Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{{Partition: 8}}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: prior.RootHash}}},
			mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) { return ack, nil }})
		require.NoError(t, err)
		p.f.parent = ackBlock
		sup := p.supersedeWith(t, stale, 9)
		p.store.handoffAuth = fixedParentAuthority{predecessor: p.body1, parent: ackBlock, root: p.f.baseCommittee}
		_, err = sup.addEpoch2(t, p.store, 9, sup.built.prepare.Bytes())
		require.NoError(t, err)
		_, err = sup.addEpoch2(t, p.store, 10, sup.built.freeze.Bytes(), sup.built.companion)
		require.ErrorIs(t, err, ErrHandoffRecord)
		require.ErrorIs(t, err, ErrSupersessionInvalid)
		require.ErrorIs(t, err, ErrNothingToSupersede, "S3: the acknowledged state is refused by its own guard, not by the empty chain")
	})
}
