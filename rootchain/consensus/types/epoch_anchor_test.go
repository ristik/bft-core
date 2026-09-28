package types

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
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
	require.Error(t, base.Cbor.Unmarshal([]byte{0xff}, &restored))
	b.Epoch = 1
	require.ErrorIs(t, b.IsValid(), ErrEpochAnchor)
	b.Epoch = 2
	b.Qc = &QuorumCert{}
	require.ErrorIs(t, b.IsValid(), ErrEpochAnchor)
}

func TestEpochAnchorProposalValidationBoundaries(t *testing.T) {
	a := testEpochAnchor()
	b := &BlockData{Version: 2, Round: a.Slot, Epoch: a.Epoch, Payload: &Payload{Version: 2}, Anchor: a}
	require.ErrorIs(t, b.IsValid(), ErrEpochAnchor)
	b.Round++
	require.NoError(t, b.IsValid())

	// Once an ordinary QC replaces the bootstrap anchor, its epoch must be
	// the successor epoch even when the QC is otherwise valid.
	b.Anchor = nil
	b.Qc = &QuorumCert{VoteInfo: &RoundInfo{ParentRoundNumber: a.Slot - 1, RoundNumber: a.Slot, Epoch: a.Epoch, Timestamp: 1},
		LedgerCommitInfo: &base.UnicitySeal{Version: 1, PreviousHash: []byte{1}}}
	require.NoError(t, b.IsValid())
	b.Qc.VoteInfo.Epoch--
	require.ErrorContains(t, b.IsValid(), "ordinary parent QC epochs differ")
}

func TestEpochAnchorBlockVersionWireGuards(t *testing.T) {
	b := &BlockData{Round: 1, Payload: &Payload{}}
	_, err := b.MarshalCBOR()
	require.NoError(t, err)
	require.EqualValues(t, 1, b.Version)

	invalid, err := base.Cbor.MarshalTaggedValue(base.RootPartitionBlockDataTag, blockDataLegacyWire{
		Version: 3, Round: 1, Payload: &Payload{},
	})
	require.NoError(t, err)
	var restored BlockData
	require.Error(t, restored.UnmarshalCBOR(invalid))
}

func TestEpochAnchorTimeoutVotesRankBelowOrdinaryQC(t *testing.T) {
	a := testEpochAnchor()
	boundaryTimeout := NewAnchorTimeout(a.Slot, a)
	require.ErrorIs(t, boundaryTimeout.IsValid(), ErrEpochAnchor)
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
	other := *a
	other.GenesisID = bytes.Repeat([]byte{9}, 32)
	require.ErrorIs(t, tc.Add("c", NewAnchorTimeout(13, &other), []byte{3}), ErrEpochAnchor)
}

func TestEpochAnchorTimeoutWireAndCertificateGuards(t *testing.T) {
	a := testEpochAnchor()
	for _, timeout := range []*Timeout{NewAnchorTimeout(13, a), NewTimeout(14, 2, &QuorumCert{})} {
		encoded, err := base.Cbor.Marshal(timeout)
		require.NoError(t, err)
		var restored Timeout
		require.NoError(t, base.Cbor.Unmarshal(encoded, &restored))
		require.Equal(t, timeout, &restored)
		require.Error(t, base.Cbor.Unmarshal([]byte{0xff}, &restored))
	}
	for _, vote := range []*TimeoutVote{{HqcRound: a.Slot, Signature: []byte{1}, Anchor: a}, {HqcRound: 12, Signature: []byte{2}}} {
		encoded, err := base.Cbor.Marshal(vote)
		require.NoError(t, err)
		var restored TimeoutVote
		require.NoError(t, base.Cbor.Unmarshal(encoded, &restored))
		require.Equal(t, vote, &restored)
		require.Error(t, base.Cbor.Unmarshal([]byte{0xff}, &restored))
	}
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	old := testtrustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{"node": signer}).(*base.RootTrustBaseV1)
	store, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, store.Store(old))
	oldID, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	projected, err := base.NewTrustBase(old.NetworkID, old.RootNodes, base.WithEpoch(2),
		base.WithEpochStart(13), base.WithPreviousTrustBaseHash(oldID))
	require.NoError(t, err)
	_, err = store.InstallV2Projection(projected)
	require.NoError(t, err)
	timeout := NewAnchorTimeout(13, a)
	makeVote := func(anchor *EpochAnchor, hqcRound uint64) *TimeoutVote {
		vote := &TimeoutVote{HqcRound: hqcRound, Anchor: anchor}
		vote.Signature, err = signer.SignBytes(BytesFromTimeoutVote(timeout, "node", vote))
		require.NoError(t, err)
		return vote
	}
	tc := &TimeoutCert{Timeout: timeout, Signatures: map[string]*TimeoutVote{"node": makeVote(a, a.Slot)}}
	require.NoError(t, tc.Verify(store))
	tc.Signatures["node"] = makeVote(nil, a.Slot)
	require.ErrorIs(t, tc.Verify(store), ErrEpochAnchor)
	tc.Signatures["node"] = makeVote(nil, 0)
	require.ErrorIs(t, tc.Verify(store), ErrEpochAnchor)
	wrong := *a
	wrong.GenesisID = bytes.Repeat([]byte{9}, 32)
	tc.Signatures["node"] = makeVote(&wrong, wrong.Slot)
	require.ErrorIs(t, tc.Verify(store), ErrEpochAnchor)
	wrong = *a
	wrong.Slot++
	tc.Signatures["node"] = makeVote(&wrong, wrong.Slot)
	require.ErrorIs(t, tc.Verify(store), ErrEpochAnchor)
}
