package inputcarrier_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/inputcarrier"
	"github.com/unicitynetwork/bft-go-base/types"
)

func sampleEnvelope() inputcarrier.Envelope {
	return inputcarrier.Envelope{
		Version:         inputcarrier.Version,
		ShardRound:      5,
		BlockHash:       bytes.Repeat([]byte{0xb5}, 32),
		Certificate:     []byte{0x80, 0x01, 0x02},
		TechnicalRecord: []byte{0x80},
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	e := sampleEnvelope()
	b, err := inputcarrier.Encode(e, inputcarrier.DefaultLimits)
	require.NoError(t, err)
	got, err := inputcarrier.Decode(b, inputcarrier.DefaultLimits)
	require.NoError(t, err)
	require.Equal(t, e, got)

	// The decoded envelope owns its slices.
	b[len(b)-1] ^= 0xff
	require.Equal(t, e, got)
}

func TestDecodeRefusals(t *testing.T) {
	l := inputcarrier.DefaultLimits
	good, err := inputcarrier.Encode(sampleEnvelope(), l)
	require.NoError(t, err)
	_, err = inputcarrier.Decode(good, l)
	require.NoError(t, err, "premise: the unmodified encoding decodes")

	e := sampleEnvelope()
	raw := func(fields ...any) []byte {
		b, err := types.Cbor.Marshal(fields)
		require.NoError(t, err)
		return b
	}
	cases := map[string][]byte{
		"empty":                      nil,
		"over the frame bound":       make([]byte, l.FrameBytes()+1),
		"unknown version":            raw(uint64(2), e.ShardRound, e.BlockHash, e.Certificate, e.TechnicalRecord),
		"block hash of 31 bytes":     raw(e.Version, e.ShardRound, e.BlockHash[:31], e.Certificate, e.TechnicalRecord),
		"empty certificate":          raw(e.Version, e.ShardRound, e.BlockHash, []byte{}, e.TechnicalRecord),
		"empty technical record":     raw(e.Version, e.ShardRound, e.BlockHash, e.Certificate, []byte{}),
		"certificate over its bound": raw(e.Version, e.ShardRound, e.BlockHash, make([]byte, l.MaxCertificateBytes+1), e.TechnicalRecord),
		"technical record over its bound": raw(e.Version, e.ShardRound, e.BlockHash, e.Certificate,
			make([]byte, l.MaxTechnicalRecordBytes+1)),
		"an extra array element":  raw(e.Version, e.ShardRound, e.BlockHash, e.Certificate, e.TechnicalRecord, uint64(0)),
		"a missing array element": raw(e.Version, e.ShardRound, e.BlockHash, e.Certificate),
		"trailing bytes":          append(bytes.Clone(good), 0x00),
		// good begins 0x85 0x01: an array of five, then version 1. 0x18 0x01 is the same value in a
		// non-minimal two-byte form.
		"non-minimal integer": append([]byte{0x85, 0x18, 0x01}, good[2:]...),
		// 0x9f opens an indefinite-length array, closed by 0xff.
		"indefinite-length array": append(append([]byte{0x9f}, good[1:]...), 0xff),
	}
	require.Equal(t, []byte{0x85, 0x01}, good[:2], "premise: the canonical prefix the byte-level cases edit")
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := inputcarrier.Decode(b, l)
			require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
		})
	}
}

// TestLimitsCompose checks that the frame bound is exactly the largest valid envelope, across the
// byte-string header size boundaries, so a transport bounded by FrameBytes never refuses an envelope
// the field bounds allow.
func TestLimitsCompose(t *testing.T) {
	for _, l := range []inputcarrier.Limits{
		inputcarrier.DefaultLimits,
		{MaxCertificateBytes: 23, MaxTechnicalRecordBytes: 24},
		{MaxCertificateBytes: 255, MaxTechnicalRecordBytes: 256},
		{MaxCertificateBytes: 65535, MaxTechnicalRecordBytes: 65536},
	} {
		largest := inputcarrier.Envelope{
			Version:         inputcarrier.Version,
			ShardRound:      math.MaxUint64,
			BlockHash:       bytes.Repeat([]byte{0xff}, 32),
			Certificate:     bytes.Repeat([]byte{0xcc}, l.MaxCertificateBytes),
			TechnicalRecord: bytes.Repeat([]byte{0x77}, l.MaxTechnicalRecordBytes),
		}
		b, err := inputcarrier.Encode(largest, l)
		require.NoError(t, err)
		require.Equal(t, l.FrameBytes(), len(b), "limits %+v", l)
		_, err = inputcarrier.Decode(b, l)
		require.NoError(t, err)

		over := largest
		over.Certificate = append(bytes.Clone(largest.Certificate), 0xcc)
		_, err = inputcarrier.Encode(over, l)
		require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	}
}

func TestEncodeRefusesInvalidLimits(t *testing.T) {
	_, err := inputcarrier.Encode(sampleEnvelope(), inputcarrier.Limits{})
	require.Error(t, err)
	_, err = inputcarrier.Decode([]byte{0x85}, inputcarrier.Limits{MaxCertificateBytes: 1})
	require.Error(t, err)
}
