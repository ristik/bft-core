package handoffdelivery

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
)

// Two roots hold the same handoff with different quorum subsets: one witness identity. A non-canonical encoding is not a witness.
func TestTheV3WitnessIdentityDoesNotDependOnWhichQuorumSigned(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	w := WitnessV3{Proof: f.Proof, Body: f.Body.Encode(), Snapshot: f.Snapshot, Candidate: f.Candidate}
	want, err := witnessV3Identity(w)
	require.NoError(t, err)

	other := w
	qc := *f.Proof.CommitQC
	qc.Signatures, qc.SealSignatures = nil, nil
	other.Proof.CommitQC = &qc
	got, err := witnessV3Identity(other)
	require.NoError(t, err)
	require.Equal(t, want, got)

	changed := w
	changed.Body = append([]byte{}, w.Body...)
	changed.Body[len(changed.Body)-1] ^= 1
	diff, err := witnessV3Identity(changed)
	require.NoError(t, err)
	require.NotEqual(t, want, diff, "a different body is a different witness")

	raw, err := EncodeWitnessV3(w)
	require.NoError(t, err)
	_, ok := decodeWitnessV3(raw)
	require.True(t, ok)
	_, ok = decodeWitnessV3(append(append([]byte{}, raw...), 0))
	require.False(t, ok, "trailing bytes are not canonical")
}
