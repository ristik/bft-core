package b1ref_test

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// nativeClaim packs a native UC as a CERT_BATCH_V2 claim of its own partition and shard.
func nativeClaim(t *testing.T, uc *types.UnicityCertificate) []byte {
	t.Helper()
	raw, err := uc.MarshalCBOR()
	require.NoError(t, err)
	shard := uc.ShardTreeCertificate.Shard.Bytes()
	ir, err := uc.InputRecord.Bytes()
	require.NoError(t, err)
	irHash := sha256.Sum256(ir)
	out := binary.BigEndian.AppendUint32(nil, uint32(uc.UnicityTreeCertificate.Partition))
	out = binary.BigEndian.AppendUint16(out, uint16(len(shard)))
	out = append(out, shard...)
	out = append(out, uc.ShardConfHash...)
	out = append(out, uc.InputRecord.Hash...)
	out = append(out, irHash[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(raw)))
	return append(out, raw...)
}

// TestNativeSigningSchemes: certificates exported by the root's own QC to UC path (storage.ExecutedBlock.GenerateCertificates, via
// q3fixture) verify against registry entries derived by the native history: the genesis epoch signing with scheme 1 and the first
// activated epoch signing with scheme 2, alone and mixed in one batch. A scheme 2 UC whose seal signature map is replaced by its QC's
// vote signatures (the same voters over the domain-bound vote preimage) is false. Contract section 7a.5.
func TestNativeSigningSchemes(t *testing.T) {
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	uc1 := second.Prev.Snapshot.ShardInfo[0].UC
	uc2 := second.Snapshot.ShardInfo[0].UC
	qc2 := second.Snapshot.CommitQc
	require.Equal(t, uint64(2), qc2.Scheme, "the second commit is a scheme 2 QC")
	require.NotEqual(t, uc1.UnicitySeal.Epoch, uc2.UnicitySeal.Epoch)

	h, err := q3format.NewHistory(first.Old)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(first.Envelope)
	require.NoError(t, err)
	h, err = h.VerifyEnvelope(second.Envelope)
	require.NoError(t, err)
	tip := h.Tip()
	entries, err := h.B1Entries(tip.Start())
	require.NoError(t, err)
	for i := range entries[:len(entries)-1] {
		end := entries[i+1].Start
		entries[i].End = &end
	}
	schemes := map[uint64]uint64{}
	for _, e := range entries {
		schemes[e.Epoch] = e.SigningScheme
	}
	require.Equal(t, uint64(1), schemes[uc1.UnicitySeal.Epoch], "the first UC's epoch signs with scheme 1")
	require.Equal(t, uint64(2), schemes[uc2.UnicitySeal.Epoch], "the second UC's epoch signs with scheme 2")

	last := entries[len(entries)-1]
	model := b1ref.Model{GenesisCommitment: [32]byte{7}, ProfileHash: [32]byte{9}, Phase: 2, Network: uint16(uc1.UnicitySeal.NetworkID),
		GenesisEpoch: entries[0].Epoch, ImportedTip: last.Epoch, OriginReady: true, Origin: last.Epoch, RootRound: last.Start + 100, Epochs: entries}
	st, pins := model.Words(), b1ref.Pins{GenesisCommitment: model.GenesisCommitment, ProfileHash: model.ProfileHash}
	cert := func(claims ...[]byte) (b1ref.Verdict, error) {
		in := []byte{2, 0, 0, byte(len(claims))}
		for _, c := range claims {
			in = append(in, c...)
		}
		return b1ref.Cert(in, st, pins)
	}
	c1, c2 := nativeClaim(t, uc1), nativeClaim(t, uc2)
	for name, claims := range map[string][][]byte{"scheme 1": {c1}, "scheme 2": {c2}, "mixed epochs": {c1, c2}} {
		v, err := cert(claims...)
		require.NoError(t, err, name)
		require.True(t, v.Valid, "%s: %v", name, v.Why)
	}

	forged := *uc2
	seal := *uc2.UnicitySeal
	seal.Signatures = map[string]hex.Bytes{}
	for id, sig := range qc2.Signatures {
		seal.Signatures[id] = sig
	}
	forged.UnicitySeal = &seal
	v, err := cert(nativeClaim(t, &forged))
	require.NoError(t, err)
	require.False(t, v.Valid)
	require.True(t, errors.Is(v.Why, b1ref.ErrSigInvalid), "%v", v.Why)
}
