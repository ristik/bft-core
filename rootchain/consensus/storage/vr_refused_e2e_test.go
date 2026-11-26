package storage_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1306 through the real executor and the real admission code: a published result whose candidate is an EVM-only change (the root
// committee unchanged, the EVM validators changed) is refused by item (5) of admission. The leader-side check over the Prepare's parent
// refuses it with the error every root's Freeze admission returns, so no Prepare is ordered; an ordinary child of that parent executes with
// an EVM certification, so the EVM keeps certifying while R waits for its RejectResult.

type evmVerifier struct{ round uint64 }

func (v *evmVerifier) VerifyIRChangeReq(round, _ uint64, r *rctypes.IRChangeReq) (*types.InputRecord, error) {
	v.round = round
	return &types.InputRecord{Version: 1, RoundNumber: round, Epoch: 0, Hash: bytes.Repeat([]byte{byte(round)}, 32), BlockHash: bytes.Repeat([]byte{0xb0 + byte(round)}, 32),
		PreviousHash: bytes.Repeat([]byte{0x33}, 32), SummaryValue: []byte{}, Timestamp: 961}, nil
}

func TestVRRefusedCandidateIsNotPreparedAndTheEVMKeepsCertifying(t *testing.T) {
	f := newVXReal(t)
	g := f.g
	b1 := f.must(g, f.block(g, 11, 960, nil, f.view(11, 1)))
	f.certificate(1)

	// the honest candidate passes the check
	require.NoError(t, b1.VRCandidateCheck(f.orch, f.auth, 12, f.cand, f.body, 0, f.body0()))

	// the EVM-only change: the current root committee is the candidate's own
	var successorRoot []evmassign.RootMember
	for _, m := range f.body.Members {
		successorRoot = append(successorRoot, evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight})
	}
	f.auth.Root = successorRoot
	check := b1.VRCandidateCheck(f.orch, f.auth, 12, f.cand, f.body, 0, f.body0())
	require.ErrorIs(t, check, vradmit.ErrH3)
	require.ErrorIs(t, check, evmassign.ErrEVMOnly)

	// the check predicts the executor: a Prepare would execute, and every root would refuse its Freeze with the same error, the EVM frozen
	prep := f.must(b1, f.block(b1, 12, 961, [][]byte{f.rec("prepare", 12).Bytes()}))
	require.Equal(t, "prepared", prep.ShardState.Control.Phase)
	_, err := f.exec(prep, f.block(prep, 13, 962, [][]byte{f.rec("freeze", 13).Bytes(), f.fzRaw}))
	require.ErrorIs(t, err, vradmit.ErrH3)
	require.ErrorIs(t, err, evmassign.ErrEVMOnly)
	require.ErrorContains(t, err, check.Error(), "the Freeze is refused with exactly the leader-side check's refusal")
	_, err = storage.ExtendVerifiedForTest(prep, evmBlock(f, prep, 13), f.orch, f.auth, f.candidates, f.svc, &evmVerifier{})
	require.ErrorIs(t, err, storage.ErrHandoffFrozen, "after a Prepare the EVM is frozen")

	// what the leader orders instead: an ordinary child of the same parent, and the EVM certifies in it and after it
	v := &evmVerifier{}
	next, err := storage.ExtendVerifiedForTest(b1, evmBlock(f, b1, 12), f.orch, f.auth, f.candidates, f.svc, v)
	require.NoError(t, err)
	require.Equal(t, "idle", next.ShardState.Control.Phase)
	require.Contains(t, next.ShardState.Changed, vxShard, "the EVM shard is certified")
	require.Equal(t, bytes.Repeat([]byte{0xb0 + 12}, 32), []byte(next.ShardState.States[vxShard].IR.BlockHash))
	again, err := storage.ExtendVerifiedForTest(next, evmBlock(f, next, 13), f.orch, f.auth, f.candidates, f.svc, v)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xb0 + 13}, 32), []byte(again.ShardState.States[vxShard].IR.BlockHash), "and keeps certifying")
	// and the check, over the later parent, still refuses: the leader still orders no Prepare for R
	require.ErrorIs(t, again.VRCandidateCheck(f.orch, f.auth, 14, f.cand, f.body, 0, f.body0()), vradmit.ErrH3)
}

// evmBlock is the ordinary child of parent at round that certifies the EVM shard.
func evmBlock(f *vxReal, parent *storage.ExecutedBlock, round uint64) *rctypes.BlockData {
	b := f.block(parent, round, 960+round-11, nil)
	b.Payload.Requests = []*rctypes.IRChangeReq{{Partition: vxShard.PartitionID, Shard: types.ShardID{}, CertReason: rctypes.Quorum}}
	return b
}
