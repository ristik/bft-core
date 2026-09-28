package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	base "github.com/unicitynetwork/bft-go-base/types"
)

func testEpochAnchor() *EpochAnchor {
	return &EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 12, StateRoot: bytes.Repeat([]byte{2}, 32)}
}

func TestEpochAnchorProposalWireAndEpoch(t *testing.T) {
	a := testEpochAnchor()
	b := &BlockData{Version: 2, Round: 13, Epoch: 2, Payload: &Payload{Version: 2}, Anchor: a}
	require.NoError(t, b.IsValid())
	raw, err := base.Cbor.Marshal(b)
	require.NoError(t, err)
	var restored BlockData
	require.NoError(t, base.Cbor.Unmarshal(raw, &restored))
	require.Equal(t, a, restored.Anchor)
	require.EqualValues(t, 12, restored.GetParentRound())
	b.Epoch = 1
	require.ErrorIs(t, b.IsValid(), ErrEpochAnchor)
	b.Epoch = 2
	b.Qc = &QuorumCert{}
	require.ErrorIs(t, b.IsValid(), ErrEpochAnchor)
}

func TestEpochAnchorTimeoutVotesRankBelowOrdinaryQC(t *testing.T) {
	a := testEpochAnchor()
	anchorTimeout := NewAnchorTimeout(13, a)
	require.NoError(t, anchorTimeout.IsValid())
	tc := &TimeoutCert{Timeout: anchorTimeout, Signatures: map[string]*TimeoutVote{}}
	require.NoError(t, tc.Add("a", anchorTimeout, []byte{1}))
	ordinary := NewTimeout(13, 2, &QuorumCert{VoteInfo: &RoundInfo{RoundNumber: 13, Epoch: 2}})
	// A highQC must predate the timeout; use an ordinary QC at slot 12 to
	// show that kind outranks the anchor even when their numeric rounds match.
	ordinary.HighQc.VoteInfo.RoundNumber = 12
	require.NoError(t, tc.Add("b", ordinary, []byte{2}))
	require.Same(t, ordinary, tc.Timeout)
	require.NotNil(t, tc.Signatures["a"].Anchor)
}
