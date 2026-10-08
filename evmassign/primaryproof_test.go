package evmassign

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrimaryProofCodec(t *testing.T) {
	p := PrimaryProof{Witness: []byte("w"), PoPs: []EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}}}
	raw, err := p.Encode()
	require.NoError(t, err)
	got, err := DecodePrimaryProof(raw)
	require.NoError(t, err)
	require.Equal(t, p.Witness, got.Witness)
	require.Equal(t, p.PoPs, got.PoPs)

	for name, bad := range map[string][]byte{
		"empty":       nil,
		"trailing":    append(bytes.Clone(raw), 0),
		"truncated":   raw[:len(raw)-1],
		"oversized":   bytes.Repeat([]byte{0x80}, MaxPrimaryProofBytes+1),
		"not-a-proof": {0xf6},
	} {
		_, err := DecodePrimaryProof(bad)
		require.ErrorIs(t, err, ErrPrimaryProofEncoding, name)
	}
	for name, bad := range map[string]PrimaryProof{
		"no witness": {PoPs: p.PoPs},
		"no pops":    {Witness: p.Witness},
		"too many":   {Witness: p.Witness, PoPs: make([]EVMPoP, MaxPrimaryPoPs+1)},
		"huge":       {Witness: make([]byte, MaxPrimaryWitnessBytes+1), PoPs: p.PoPs},
	} {
		_, err := bad.Encode()
		require.ErrorIs(t, err, ErrPrimaryProofEncoding, name)
	}
}
