package storage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The commit observer (VT-05b) sees every committed block once, oldest first, each the child of the one before: a commit that also
// commits an earlier uncommitted block hands both over in chain order.
func TestTheCommitObserverSeesEveryCommittedBlockInOrder(t *testing.T) {
	irVer := mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) {
		return nil, errors.New("no IR changes in this test")
	}}
	bs := initBlockStoreFromGenesis(t, nil)
	var seen [][2]uint64 // (round, parent round)
	bs.SetCommitObserver(func(blocks []*ExecutedBlock) {
		for _, b := range blocks {
			seen = append(seen, [2]uint64{b.GetRound(), b.BlockData.GetParentRound()})
		}
	})
	rh2, err := bs.Add(&rctypes.BlockData{Round: 2, Payload: &rctypes.Payload{}, Qc: bs.GetHighQc()}, irVer)
	require.NoError(t, err)
	qc2 := qcFor(2, 1, rh2, 0)
	_, err = bs.ProcessQc(qc2)
	require.NoError(t, err)
	rh3, err := bs.Add(&rctypes.BlockData{Round: 3, Payload: &rctypes.Payload{}, Qc: qc2}, irVer)
	require.NoError(t, err)
	qc3 := qcFor(3, 2, rh3, 0) // certifies 3 without committing 2
	_, err = bs.ProcessQc(qc3)
	require.NoError(t, err)
	require.Empty(t, seen)
	rh4, err := bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
	require.NoError(t, err)
	_, err = bs.ProcessQc(qcFor(4, 3, rh4, 3)) // commits 3, and 2 with it
	require.NoError(t, err)
	require.Equal(t, [][2]uint64{{2, 1}, {3, 2}}, seen, "both committed blocks, oldest first, each the child of the one before")
}
