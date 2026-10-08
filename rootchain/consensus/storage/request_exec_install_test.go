package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// activeHistory is the committed history of a shard whose second assignment is authorised by root epoch 2.
type activeHistory struct {
	chain []*RequestActivation
	body  []byte
}

func (h activeHistory) Chain(types.PartitionID, types.ShardID) ([]*RequestActivation, error) {
	return h.chain, nil
}
func (h activeHistory) Network() uint64 { return 5 }
func (h activeHistory) Version() uint64 { return fxVersion }
func (h activeHistory) RootIdentity(uint64) (uint64, []byte, error) {
	return 2, h.body, nil
}

// The production path of the pending acknowledgement: the successor assignment is installed by block execution (InstallEpochAnchor and
// the first block, including the Control-path recomputation of the fee/stat commitments), several T2 timeout proofs then execute through
// Extend under the view-aware verifier while the acknowledgement is withheld, and a valid acknowledgement from the installed members
// executes afterwards. Both parents of the repeat UCs are covered: the predecessor epoch's last certified record, and the successor-epoch
// record a generated repeat UC leaves behind. Follower verification is a second store that reopens the same state and executes the same
// blocks to the same roots.
func TestPendingAcknowledgementExecutesUnderTheViewThroughRepeatUCs(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.installShard(t, f.current, func(si *ShardInfo) {
		si.IR.BlockHash = bytes.Clone(f.parent)
		si.Fees["ev-a"] = 7
		var err error
		si.TR.FeeHash, err = si.feeHash(crypto.SHA256)
		require.NoError(t, err)
		// the predecessor epoch's last certified record, at root round 1
		ir := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, Epoch: si.TR.Epoch, PreviousHash: []byte{1}, Hash: si.RootHash,
			BlockHash: bytes.Clone(f.parent), SummaryValue: []byte{3}, Timestamp: fxTimestamp}
		trHash, err := si.TR.Hash()
		require.NoError(t, err)
		si.LastCR = &certification.CertificationResponse{Partition: si.PartitionID, Shard: si.ShardID, Technical: si.TR,
			UC: types.UnicityCertificate{Version: 1, InputRecord: ir, TRHash: trHash,
				UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: si.PartitionID}, UnicitySeal: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 1,
					Timestamp: fxTimestamp, Hash: []byte{4}}}}
	})
	h := f.commitAssignment(t)
	anchorBlock, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchorBlock)

	genesisAnchor, err := NewRequestAnchor(f.current, crypto.SHA256, 1, f.predecessor, fxVersion)
	require.NoError(t, err)
	body := bytes.Clone(h.commit.NextBodyID)
	activation, err := newRequestActivation(h.activated, crypto.SHA256, quorumweight.PolicyUnit, nil, h.genesis.Epoch, body, h.genesis.Start, h.successorT, fxVersion)
	require.NoError(t, err)
	hist := activeHistory{chain: []*RequestActivation{genesisAnchor, activation}, body: body}
	verifier := func() *viewVerifier { return &viewVerifier{t: t, history: hist} }

	// blocks are added to the store on their parent (the follower's path: execution, then the store's own verification)
	onParent := func(parent *ExecutedBlock, round uint64, reqs ...*rctypes.IRChangeReq) *rctypes.BlockData {
		return &rctypes.BlockData{Version: 2, Round: round, Epoch: 2, Timestamp: 1_000 + round, Payload: &rctypes.Payload{Version: 2, Requests: reqs},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: parent.GetRound(), Epoch: 2, CurrentRootHash: parent.RootHash}}}
	}
	timeout := func(parent *ExecutedBlock, round uint64) *rctypes.BlockData {
		return onParent(parent, round, &rctypes.IRChangeReq{Partition: f.current.PartitionID, CertReason: rctypes.T2Timeout})
	}
	add := func(parent *ExecutedBlock, b *rctypes.BlockData) (*ExecutedBlock, error) {
		if _, err := s.Add(b, verifier()); err != nil {
			return nil, err
		}
		return mustBlock(t, s, b.Round), nil
	}
	commitAndCertify := func(b *ExecutedBlock) {
		t.Helper()
		qc := &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: b.GetRound(), Epoch: 2,
			Timestamp: 1_000 + b.GetRound(), Hash: b.RootHash}}
		_, err := b.GenerateCertificates(qc)
		require.NoError(t, err)
	}

	e := mustBlock(t, s, 7)
	pending := e.ShardState.States[f.shard]
	require.NotEqual(t, pending.TR.Epoch, pending.IR.Epoch, "installed by block execution, acknowledgement withheld")
	require.EqualValues(t, 0, pending.LastCR.Technical.Epoch, "the parent's last certified record is the predecessor epoch's")

	// 1. timeouts while the predecessor's record is the last certified one: each is another round of the same installed assignment
	var seen [][]byte
	for round := uint64(8); round <= 9; round++ {
		child, err := add(e, timeout(e, round))
		require.NoError(t, err, "round %d", round)
		si := child.ShardState.States[f.shard]
		require.Contains(t, child.ShardState.Changed, f.shard, "the timeout is a repeat UC")
		require.EqualValues(t, pending.TR.Epoch, si.TR.Epoch)
		require.Equal(t, pending.ShardConfHash, si.ShardConfHash, "no second installation")
		require.NotContains(t, seen, []byte(child.RootHash), "every timeout is another state")
		seen = append(seen, []byte(child.RootHash))
		e = child
	}
	// 2. a generated repeat UC leaves the successor epoch's record: the next timeout resolves through the certified-record branch
	commitAndCertify(e)
	require.EqualValues(t, pending.TR.Epoch, e.ShardState.States[f.shard].LastCR.Technical.Epoch)
	e2, err := add(e, timeout(e, 20))
	require.NoError(t, err)
	require.Contains(t, e2.ShardState.Changed, f.shard)

	// a timeout younger than T2 is refused under the same view, whichever record is the parent
	_, err = add(e, timeout(e, e.GetRound()+1))
	require.ErrorIs(t, err, rctypes.ErrInvalidRequest, "idle rounds below T2")

	// 3. the acknowledgement from the installed members executes, a request signed by a retired key does not count
	commitAndCertify(e2) // the last timeout's repeat UC leaves the pipeline
	cur := e2.ShardState.States[f.shard]
	ack := func(keys ...evmKey) *rctypes.BlockData {
		var reqs []*certification.BlockCertificationRequest
		for _, k := range keys {
			r := &certification.BlockCertificationRequest{PartitionID: f.current.PartitionID, ShardID: types.ShardID{}, NodeID: k.id,
				InputRecord: &types.InputRecord{Version: 1, RoundNumber: cur.TR.Round, Epoch: cur.TR.Epoch, PreviousHash: bytes.Clone(cur.IR.Hash),
					Hash: bytes.Repeat([]byte{0x78}, 32), BlockHash: bytes.Repeat([]byte{0x77}, 32), SummaryValue: []byte{3}, Timestamp: cur.LastCR.UC.UnicitySeal.Timestamp}}
			require.NoError(t, r.Sign(k.signer))
			reqs = append(reqs, r)
		}
		return onParent(e2, e2.GetRound()+1, &rctypes.IRChangeReq{Partition: f.current.PartitionID, CertReason: rctypes.Quorum, Requests: reqs})
	}
	retired := ack(f.nextKeys[0], f.nextKeys[1], f.oldKeys[3])
	ignored, err := add(e2, retired)
	require.NoError(t, err)
	require.NotContains(t, ignored.ShardState.Changed, f.shard, "a proof with a retired signer changes nothing")
	require.NotEqual(t, ignored.ShardState.States[f.shard].TR.Epoch, ignored.ShardState.States[f.shard].IR.Epoch)
	good := ack(f.nextKeys[0], f.nextKeys[1], f.nextKeys[3])
	good.Round++
	accepted, err := add(e2, good)
	require.NoError(t, err)
	got := accepted.ShardState.States[f.shard]
	require.Equal(t, got.TR.Epoch, got.IR.Epoch, "the acknowledgement ends the pending state")
	require.Equal(t, pending.ShardConfHash, got.ShardConfHash)

	// 4. follower: a reopened store executes the same blocks to the same roots
	reopened, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	r7 := mustBlock(t, reopened, 7)
	again, err := r7.Extend(timeout(r7, 8), verifier(), f.orch, crypto.SHA256, logger.New(t))
	require.NoError(t, err)
	require.Equal(t, seen[0], []byte(again.RootHash))
}
