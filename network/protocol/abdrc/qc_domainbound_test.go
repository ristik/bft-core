package abdrc

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// qcV2 is a scheme 2 QC of epoch 2, round 12, made of the votes of the given signers.
func (f *dbFixture) qcV2(t *testing.T, committing bool, signers ...string) *drctypes.QuorumCert {
	t.Helper()
	var first *VoteMsg
	qc := &drctypes.QuorumCert{Scheme: votesig.SchemeDomainBound, Signatures: map[string]hex.Bytes{}}
	if committing {
		qc.SealSignatures = map[string]hex.Bytes{}
	}
	for _, id := range signers {
		v := f.voteV2(t, id, 2, 12, committing, nil)
		if first == nil {
			first = v
			qc.VoteInfo, qc.LedgerCommitInfo = v.VoteInfo, v.LedgerCommitInfo
		}
		qc.Signatures[id] = v.Signature
		if committing {
			qc.SealSignatures[id] = v.SealSignature
		}
	}
	return qc
}

func TestDomainBoundQCVerifiesByTheRuleOfItsEpoch(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)

	for _, committing := range []bool{true, false} {
		for _, signers := range [][]string{{"1", "2", "3"}, {"1", "2", "3", "4"}} {
			qc := f.qcV2(t, committing, signers...)
			require.NoError(t, qc.VerifyWith(f.store), "committing=%v signers=%d", committing, len(signers))
			raw, err := types.Cbor.Marshal(qc)
			require.NoError(t, err)
			require.Equal(t, []byte{0x82, 0x02}, raw[:2])
			var back drctypes.QuorumCert
			require.NoError(t, types.Cbor.Unmarshal(raw, &back))
			require.EqualValues(t, votesig.SchemeDomainBound, back.Scheme)
			require.Equal(t, qc.Signatures, back.Signatures)
			require.NoError(t, back.VerifyWith(f.store))
		}
		require.ErrorIs(t, f.qcV2(t, committing, "1", "2").VerifyWith(f.store), quorumweight.ErrQuorumNotReached, "two of four")
	}

	t.Run("the form must be the scheme of the certificate's epoch", func(t *testing.T) {
		v2 := f.qcV2(t, true, "1", "2", "3")
		g := newDBFixture(t) // nothing activated
		require.ErrorIs(t, v2.VerifyWith(g.store), votesig.ErrScheme, "scheme 2 form in a legacy epoch")
		require.ErrorIs(t, f.legacyQC(t, 2, 11).VerifyWith(f.store), votesig.ErrScheme, "legacy form in a domain-bound epoch")
		require.NoError(t, f.legacyQC(t, 1, 11).VerifyWith(f.store), "a certificate of the earlier legacy epoch keeps its own rule")
		require.ErrorIs(t, v2.Verify(nil), votesig.ErrScheme, "the legacy entry point never verifies a scheme 2 certificate")
	})
}

func TestDomainBoundQCNegatives(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	base := func(committing bool) *drctypes.QuorumCert { return f.qcV2(t, committing, "1", "2", "3") }
	stranger := fixedSigner(t, "stranger")

	t.Run("paired maps", func(t *testing.T) {
		qc := base(true)
		qc.SealSignatures["4"] = f.qcV2(t, true, "4").SealSignatures["4"]
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrSignerSets, "a seal signer that did not sign the vote")

		qc = base(true)
		qc.Signatures["4"] = f.qcV2(t, true, "4").Signatures["4"]
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrSignerSets, "a vote signer without a seal signature")

		qc = base(true)
		delete(qc.SealSignatures, "3")
		qc.SealSignatures["4"] = f.qcV2(t, true, "4").SealSignatures["4"]
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrSignerSets, "same sizes, different signers")

		qc = base(true)
		qc.SealSignatures = nil
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrSignerSets, "a committing certificate needs both maps")

		qc = base(false)
		qc.SealSignatures = map[string]hex.Bytes{"1": qc.Signatures["1"]}
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrStatement, "a non-committing certificate has no seal signatures")

		qc = base(true)
		qc.Signatures, qc.SealSignatures = qc.SealSignatures, qc.Signatures
		require.ErrorIs(t, qc.VerifyWith(f.store), quorumweight.ErrInvalidSignature, "swapped maps")
	})

	t.Run("a bad or unknown signature is refused even after a valid quorum", func(t *testing.T) {
		for _, committing := range []bool{true, false} {
			qc := f.qcV2(t, committing, "1", "2", "3", "4")
			qc.Signatures["4"] = bytes.Clone(qc.Signatures["4"])
			qc.Signatures["4"][5] ^= 1
			require.ErrorIs(t, qc.VerifyWith(f.store), quorumweight.ErrInvalidSignature, "committing=%v: strict, unlike v1", committing)
		}
		qc := base(true)
		qc.SealSignatures["2"] = bytes.Clone(qc.SealSignatures["2"])
		qc.SealSignatures["2"][5] ^= 1
		require.ErrorIs(t, qc.VerifyWith(f.store), quorumweight.ErrInvalidSignature, "a bad seal signature")

		qc = base(false)
		pv, _, _, err := drctypes.DomainBoundStatement(f.cfg, qc.VoteInfo, qc.LedgerCommitInfo, false)
		require.NoError(t, err)
		sig, err := stranger.SignBytes(pv)
		require.NoError(t, err)
		qc.Signatures["stranger"] = sig
		require.ErrorIs(t, qc.VerifyWith(f.store), quorumweight.ErrUnknownSigner)

		qc = base(true)
		qc.Signatures["4"], qc.SealSignatures["4"] = f.qcV2(t, true, "4").Signatures["4"], f.qcV2(t, true, "4").SealSignatures["4"]
		qc.Signatures["4"] = highS(t, qc.Signatures["4"])
		require.ErrorIs(t, qc.VerifyWith(f.store), quorumweight.ErrInvalidSignature, "high-s")
	})

	t.Run("signature shape", func(t *testing.T) {
		qc := base(true)
		qc.Signatures["1"] = qc.Signatures["1"][:63]
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrSignatureShape)
		qc = base(true)
		qc.SealSignatures["1"] = append(bytes.Clone(qc.SealSignatures["1"][:64]), 2)
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrSignatureShape, "forbidden recovery byte")
	})

	t.Run("the statement", func(t *testing.T) {
		mutate := func(committing bool, fn func(qc *drctypes.QuorumCert)) error {
			qc := base(committing)
			fn(qc)
			return qc.VerifyWith(f.store)
		}
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.VoteInfo.RoundNumber++ }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.VoteInfo.ParentRoundNumber-- }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{1}, 32) }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.VoteInfo.CurrentRootHash = []byte{1} }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.NetworkID = 6 }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.PreviousHash = bytes.Repeat([]byte{1}, 32) }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.Hash = bytes.Repeat([]byte{2}, 32) }), quorumweight.ErrInvalidSignature, "the commit hash is signed")
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.Timestamp++ }), quorumweight.ErrInvalidSignature, "the seal timestamp is signed by the seal signatures")
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.Hash = nil }), votesig.ErrStatement, "half-empty commit pair")
		require.ErrorIs(t, mutate(false, func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.Epoch = 2 }), votesig.ErrStatement)
		require.ErrorIs(t, mutate(true, func(q *drctypes.QuorumCert) { q.VoteInfo.RoundNumber, q.VoteInfo.ParentRoundNumber = 1, 0 }), drctypes.ErrNotGenesisQC, "no scheme 2 genesis")
		other := f.cfg
		other.Genesis = sha256.Sum256([]byte("another root chain"))
		qc := base(false)
		vi := votesig.VoteInfo{Epoch: 2, Round: 12, Parent: 11}
		copy(vi.Exec[:], qc.VoteInfo.CurrentRootHash)
		vh, err := other.VoteInfoHash(vi)
		require.NoError(t, err)
		qc.LedgerCommitInfo.PreviousHash = vh[:]
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrStatement, "a certificate of another root chain")
	})

	t.Run("a mixed-version certificate at the boundary", func(t *testing.T) {
		// legacy signatures (over the native seal bytes) in the vote map of a scheme 2 certificate
		qc := base(true)
		bs, err := qc.LedgerCommitInfo.SigBytes()
		require.NoError(t, err)
		legacySig, err := f.signers["3"].SignBytes(bs)
		require.NoError(t, err)
		qc.Signatures["3"] = legacySig
		require.ErrorIs(t, qc.VerifyWith(f.store), quorumweight.ErrInvalidSignature)
		// the legacy certificate of the activated epoch itself
		require.ErrorIs(t, f.legacyQC(t, 2, 11).VerifyWith(f.store), votesig.ErrScheme)
	})
}

func TestUnknownQCWireVersionIsRefusedBeforeVerification(t *testing.T) {
	var qc drctypes.QuorumCert
	require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x03, 0xf6}, &qc), votesig.ErrScheme)
	require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x18, 0x02, 0xf6}, &qc), votesig.ErrNotCanonical)
}

// The legacy QC form is byte-for-byte what it was.
func TestLegacyQCWireFormIsUnchanged(t *testing.T) {
	f := newDBFixture(t)
	qc := f.legacyQC(t, 1, 11)
	type legacyQC struct {
		_                struct{} `cbor:",toarray"`
		VoteInfo         *drctypes.RoundInfo
		LedgerCommitInfo *types.UnicitySeal
		Signatures       map[string]hex.Bytes
	}
	want, err := types.Cbor.Marshal(legacyQC{VoteInfo: qc.VoteInfo, LedgerCommitInfo: qc.LedgerCommitInfo, Signatures: qc.Signatures})
	require.NoError(t, err)
	got, err := types.Cbor.Marshal(qc)
	require.NoError(t, err)
	require.Equal(t, want, got)
	var back drctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(got, &back))
	require.Zero(t, back.Scheme)
	require.Nil(t, back.SealSignatures)
	require.NoError(t, back.VerifyWith(f.store))
}

// A StateMsg's QCs are verified in the form of their own epoch, and the path that has no signing configuration is legacy only.
func TestStateQCDispatchByEpoch(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	tb2, err := f.store.GetByEpoch(2)
	require.NoError(t, err)
	tb1, err := f.store.GetByEpoch(1)
	require.NoError(t, err)

	require.NoError(t, verifyStateQC(f.qcV2(t, true, "1", "2", "3"), tb2, f.store, nil))
	require.ErrorIs(t, verifyStateQC(f.legacyQC(t, 2, 11), tb2, f.store, nil), votesig.ErrScheme)
	require.NoError(t, verifyStateQC(f.legacyQC(t, 1, 11), tb1, f.store, nil))
	require.ErrorIs(t, verifyStateQC(f.qcV2(t, true, "1", "2", "3"), tb2, nil, nil), votesig.ErrScheme, "no signing configuration: legacy only")
	require.NoError(t, verifyStateQC(f.legacyQC(t, 2, 11), tb2, nil, nil))
}
