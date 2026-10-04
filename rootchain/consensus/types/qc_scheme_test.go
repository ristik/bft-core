package types

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

func TestQuorumCertWireForms(t *testing.T) {
	var qc QuorumCert
	require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x03, 0xf6}, &qc), votesig.ErrScheme, "unknown wrapper version")
	require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x18, 0x02, 0xf6}, &qc), votesig.ErrNotCanonical)
	require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x02, 0xf6}, &qc), votesig.ErrStatement, "a wrapper with a null payload has no commit info")
	for name, raw := range map[string][]byte{
		"neither form":                      {0x01},
		"a payload of the wrong arity":      {0x82, 0x02, 0x80},
		"a payload that is not a list":      {0x82, 0x02, 0x01},
		"a payload with too many items":     {0x82, 0x02, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"a legacy array of the wrong arity": {0x81, 0x01},
	} {
		var bad QuorumCert
		require.ErrorIs(t, types.Cbor.Unmarshal(raw, &bad), ErrMalformedQC, name)
	}

	// the isolated case: the valid scheme 2 certificate below with only its LedgerCommitInfo set to null is refused with the
	// statement sentinel, while the unchanged certificate decodes
	valid := QuorumCert{Scheme: votesig.SchemeDomainBound,
		VoteInfo:         &RoundInfo{Version: 1, RoundNumber: 8, Epoch: 2, ParentRoundNumber: 7, CurrentRootHash: make([]byte, 32)},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}},
		Signatures:       map[string]hex.Bytes{"a": {1}}, SealSignatures: map[string]hex.Bytes{"a": {2}}}
	rawValid, err := types.Cbor.Marshal(valid)
	require.NoError(t, err)
	var control QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(rawValid, &control), "control: the unmodified four-field payload decodes")
	noCommit := valid
	noCommit.LedgerCommitInfo = nil
	rawNoCommit, err := types.Cbor.Marshal(noCommit)
	require.NoError(t, err)
	var refused QuorumCert
	err = types.Cbor.Unmarshal(rawNoCommit, &refused)
	require.ErrorIs(t, err, ErrMalformedQC, "only LedgerCommitInfo is null")
	require.ErrorIs(t, err, votesig.ErrStatement, "only LedgerCommitInfo is null")

	// a scheme 2 certificate without vote info cannot be written
	_, err = (QuorumCert{Scheme: votesig.SchemeDomainBound}).MarshalCBOR()
	require.ErrorIs(t, err, votesig.ErrStatement)

	// scheme 2 round trip keeps the form, both signature maps and the four signed fields
	v2 := &QuorumCert{Scheme: votesig.SchemeDomainBound,
		VoteInfo:         &RoundInfo{Version: 1, RoundNumber: 8, Epoch: 2, ParentRoundNumber: 7, CurrentRootHash: make([]byte, 32)},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}},
		Signatures:       map[string]hex.Bytes{"a": {1}}, SealSignatures: map[string]hex.Bytes{"a": {2}}}
	raw, err := types.Cbor.Marshal(v2)
	require.NoError(t, err)
	require.NoError(t, types.Cbor.Unmarshal(raw, &qc))
	require.EqualValues(t, votesig.SchemeDomainBound, qc.Scheme)
	require.Equal(t, v2.Signatures, qc.Signatures)
	require.Equal(t, v2.SealSignatures, qc.SealSignatures)
	require.EqualValues(t, 8, qc.VoteInfo.RoundNumber)
	require.Zero(t, qc.VoteInfo.Timestamp, "a scheme 2 certificate has no timestamp")
	require.NoError(t, qc.IsValid())

	// and decoding a legacy form afterwards leaves no trace of the scheme 2 form in the same value
	legacy := &QuorumCert{VoteInfo: &RoundInfo{Version: 1, RoundNumber: 8, Epoch: 2, Timestamp: 5, ParentRoundNumber: 7, CurrentRootHash: []byte{1}},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}}, Signatures: map[string]hex.Bytes{"a": {1}}}
	raw, err = types.Cbor.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, types.Cbor.Unmarshal(raw, &qc))
	require.Zero(t, qc.Scheme)
	require.Nil(t, qc.SealSignatures)
}

func TestQuorumCertIsValidByScheme(t *testing.T) {
	good := func() *QuorumCert {
		return &QuorumCert{Scheme: votesig.SchemeDomainBound,
			VoteInfo:         &RoundInfo{Version: 1, RoundNumber: 8, Epoch: 2, ParentRoundNumber: 7, CurrentRootHash: make([]byte, 32)},
			LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}}}
	}
	require.NoError(t, good().IsValid())
	for name, tc := range map[string]struct {
		mutate func(*QuorumCert)
		want   error
	}{
		"round zero":        {func(q *QuorumCert) { q.VoteInfo.RoundNumber = 0 }, votesig.ErrStatement},
		"parent not below":  {func(q *QuorumCert) { q.VoteInfo.ParentRoundNumber = 8 }, votesig.ErrStatement},
		"short exec":        {func(q *QuorumCert) { q.VoteInfo.CurrentRootHash = []byte{1} }, votesig.ErrStatement},
		"no vote info hash": {func(q *QuorumCert) { q.LedgerCommitInfo.PreviousHash = nil }, errInvalidRoundInfoHash},
		"no commit info":    {func(q *QuorumCert) { q.LedgerCommitInfo = nil }, errLedgerCommitInfoIsNil},
	} {
		q := good()
		tc.mutate(q)
		require.ErrorIs(t, q.IsValid(), tc.want, name)
	}
	q := good()
	q.VoteInfo.RoundNumber = 0
	require.ErrorIs(t, q.IsValid(), votesig.ErrStatement)

	// the zero signing configuration is the legacy scheme, which refuses a scheme 2 certificate
	require.ErrorIs(t, good().VerifyScheme(nil, votesig.Config{}), votesig.ErrScheme)
	require.ErrorIs(t, good().VerifyScheme(nil, votesig.Config{Scheme: votesig.SchemeLegacy}), votesig.ErrScheme)
	var none *QuorumCert
	require.Equal(t, votesig.SchemeLegacy, none.signingScheme())
}
