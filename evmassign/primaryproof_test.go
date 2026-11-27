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

func TestPoPListCodec(t *testing.T) {
	pops := []EVMPoP{{ID: 2, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}}
	raw, err := EncodePoPs(pops)
	require.NoError(t, err)
	got, err := DecodePoPs(raw)
	require.NoError(t, err)
	require.Equal(t, pops, got)
	for name, bad := range map[string][]byte{"empty": nil, "trailing": append(bytes.Clone(raw), 0), "null": {0xf6}, "empty list": {0x80}} {
		_, err := DecodePoPs(bad)
		require.ErrorIs(t, err, ErrPrimaryProofEncoding, name)
	}
	_, err = EncodePoPs(make([]EVMPoP, MaxPrimaryPoPs+1))
	require.ErrorIs(t, err, ErrPrimaryProofEncoding)
}

// §49: the committee ceiling of a primary proof is 256 (a native resource bound); the whole-proof bound is recomputed from it.
func TestTheLargestPrimaryProofFitsItsBound(t *testing.T) {
	require.Equal(t, 256, MaxPrimaryPoPs)
	require.Equal(t, 556544, MaxPrimaryProofBytes, "512 KiB witness + 256*(8+33+65+16) + 1,024")
	pops := make([]EVMPoP, MaxPrimaryPoPs)
	for i := range pops {
		pops[i] = EVMPoP{ID: uint64(i+1) << 40, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}
	}
	p := PrimaryProof{Witness: bytes.Repeat([]byte{7}, MaxPrimaryWitnessBytes), PoPs: pops}
	raw, err := p.Encode()
	require.NoError(t, err)
	require.LessOrEqual(t, len(raw), MaxPrimaryProofBytes)
	require.Greater(t, len(raw), MaxPrimaryWitnessBytes+MaxPrimaryPoPs*(33+65))
	got, err := DecodePrimaryProof(raw)
	require.NoError(t, err)
	require.Len(t, got.PoPs, MaxPrimaryPoPs)
	// 257 are refused, as are the PoPs alone
	p.PoPs = append(pops, pops[0])
	_, err = p.Encode()
	require.ErrorIs(t, err, ErrPrimaryProofEncoding)
	list, err := EncodePoPs(pops)
	require.NoError(t, err)
	got2, err := DecodePoPs(list)
	require.NoError(t, err)
	require.Len(t, got2, MaxPrimaryPoPs)
}
