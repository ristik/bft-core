package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// certifyingBlock is the block of round that certifies a new EVM input record on top of the parent's: a state change (block hash and root)
// or, with quiet, a quiet round that keeps the root and carries no block hash.
func certifyingBlock(t *testing.T, parent *ExecutedBlock, round uint64, quiet bool, controls ...rctypes.PosControl) (*rctypes.BlockData, mockIRVerifier) {
	t.Helper()
	require.Len(t, parent.ShardState.States, 1)
	var si *ShardInfo
	for _, v := range parent.ShardState.States {
		si = v
	}
	next := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, Epoch: si.TR.Epoch, PreviousHash: si.IR.Hash, Hash: bytes.Repeat([]byte{0x7a}, 32),
		BlockHash: bytes.Repeat([]byte{0x79}, 32)}
	if quiet {
		next.Hash, next.BlockHash = si.IR.Hash, nil
	}
	return &rctypes.BlockData{Version: 3, Round: round, Epoch: 2, Timestamp: 1_001,
			Payload: &rctypes.Payload{Version: 3, Requests: []*rctypes.IRChangeReq{{Partition: 8}}, PosControls: controls},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 2, CurrentRootHash: parent.RootHash}}},
		mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) { return next, nil }}
}

func controlOf(b *rctypes.BlockData) rctypes.PosControl { return b.Payload.PosControls[0] }

// The proposer's parent tuple is the one the executor judges a Retirement against, and a child that certifies a newer EVM block (P+1) does
// not change the tuple of its own Retirement: the control names the parent's, the child's certification is applied after the controls.
func TestRetirementParentIsTheTupleTheExecutorAccepts(t *testing.T) {
	good, root := bytes.Repeat([]byte{0x77}, 32), bytes.Repeat([]byte{0x78}, 32)
	evm := &fakeEVM{retire: retirable()}
	s, svc, b8 := ackedEpochTwo(t, evm, 8)

	parent, ok, err := s.RetirementParent(8, 9)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, EVMParent{StateRoot: [32]byte(root), BlockHash: [32]byte(good)}, parent)

	// the child certifies P+1 in the same block that carries the Retirement of P
	child := retirementAt(svc, b8, 9, parent.BlockHash[:], parent.StateRoot[:])
	block, verifier := certifyingBlock(t, b8, 9, false, controlOf(child))
	_, err = s.Add(block, verifier)
	require.NoError(t, err, "exactly the parent's tuple is accepted while the child certifies P+1")
	b9 := mustBlock(t, s, 9)
	require.Len(t, b9.ShardState.Records, 1)
	require.Equal(t, [][32]byte{[32]byte(root)}, evm.roots, "judged against the parent's root, not the child's")

	// the tuple of the next proposal is the child's new state
	next, ok, err := s.RetirementParent(9, 10)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, EVMParent{StateRoot: [32]byte(bytes.Repeat([]byte{0x7a}, 32)), BlockHash: [32]byte(bytes.Repeat([]byte{0x79}, 32))}, next)
	require.NotEqual(t, parent, next)

	// the branch that ordered the Retirement knows it; the parent branch does not; nothing is committed yet
	require.True(t, s.RetirementOrdered(9, 3, 2))
	require.False(t, s.RetirementOrdered(8, 3, 2))
	require.False(t, s.RetirementOrdered(9, 3, 3))
	require.False(t, s.RetirementCommitted(3, 2))
}

// A Retirement built for an obsolete tuple is refused, never accepted late: the tuple must be the parent's.
func TestRetirementOfAnObsoleteTupleIsRefused(t *testing.T) {
	evm := &fakeEVM{retire: retirable()}
	s, svc, b8 := ackedEpochTwo(t, evm, 8)
	old, ok, err := s.RetirementParent(8, 9)
	require.NoError(t, err)
	require.True(t, ok)

	// round 9 certifies P+1, with no control
	block, verifier := certifyingBlock(t, b8, 9, false)
	_, err = s.Add(block, verifier)
	require.NoError(t, err)
	b9 := mustBlock(t, s, 9)

	stale := retirementAt(svc, b9, 10, old.BlockHash[:], old.StateRoot[:])
	_, err = s.Add(stale, nil)
	require.ErrorIs(t, err, ErrNotLatestEVM, "a tuple that is no longer the parent's")
	require.Empty(t, evm.seen, "refused before any witness was judged")

	cur, ok, err := s.RetirementParent(9, 10)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = s.Add(retirementAt(svc, b9, 10, cur.BlockHash[:], cur.StateRoot[:]), nil)
	require.NoError(t, err, "the same Retirement for the parent's current tuple")
}

// A quiet parent round keeps the EVM state root and carries no block hash: the tuple names the root and the zero hash, and a Retirement for
// it is accepted. A quiet parent alone does not make the proof obsolete; only a missing usable record does.
func TestRetirementParentOfAQuietRoundKeepsTheRootAndHasNoBlockHash(t *testing.T) {
	root := bytes.Repeat([]byte{0x78}, 32)
	evm := &fakeEVM{retire: retirable()}
	s, svc, b8 := ackedEpochTwo(t, evm, 8)
	block, verifier := certifyingBlock(t, b8, 9, true)
	_, err := s.Add(block, verifier)
	require.NoError(t, err)
	b9 := mustBlock(t, s, 9)

	quiet, ok, err := s.RetirementParent(9, 10)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, EVMParent{StateRoot: [32]byte(root)}, quiet, "the retained root, and the zero block hash")
	_, err = s.Add(retirementAt(svc, b9, 10, quiet.BlockHash[:], quiet.StateRoot[:]), nil)
	require.NoError(t, err)

}

// A parent without a usable EVM record (the chain has no P85 state, or the parent is not on the tree) has no tuple.
func TestRetirementParentIsAbsentWithoutAUsableRecord(t *testing.T) {
	evm := &fakeEVM{retire: retirable()}
	s, _, _ := ackedEpochTwo(t, evm, 7)
	_, ok, err := s.RetirementParent(7, 8)
	require.NoError(t, err)
	require.False(t, ok, "an acknowledgement is owed: a handoff is in flight")
	_, _, err = s.RetirementParent(99, 100)
	require.Error(t, err, "an unknown parent")
}
