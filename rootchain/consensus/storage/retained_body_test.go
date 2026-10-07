package storage

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
)

func v3Retained(t *testing.T, domain string, fields []any) []byte {
	t.Helper()
	raw, err := types.Cbor.Marshal([]any{domain, fields})
	require.NoError(t, err)
	return raw
}

// The facts a derivation reads of a retained V3 body are its identity (the SHA-256 of exactly the retained bytes, which the
// derivation compares with the committed NextBodyID), epoch, earliest activation and change-record hash, under the weighted rules.
// Anything that is not that shape is not a V3 body and falls to the V2 reader, which refuses it.
func TestRetainedV3BodyFacts(t *testing.T) {
	crh := bytes.Repeat([]byte{7}, 32)
	valid := []any{uint64(3), uint64(5), uint64(2), uint64(20), []any{}, uint64(7), nil, crh, nil, []any{}}
	raw := v3Retained(t, "UNICITY_TRUSTBASE_V3", valid)
	got, err := decodeRetainedBody(raw)
	require.NoError(t, err, "acceptance control")
	id := sha256.Sum256(raw)
	require.Equal(t, id[:], got.id)
	require.EqualValues(t, 2, got.epoch)
	require.EqualValues(t, 20, got.earliest)
	require.Equal(t, crh, got.changeRecordHash)
	require.Equal(t, weightvalidation.ModeWeighted, got.mode)

	mutate := func(f func([]any)) []byte {
		fields := append([]any(nil), valid...)
		f(fields)
		return v3Retained(t, "UNICITY_TRUSTBASE_V3", fields)
	}
	for name, bad := range map[string][]byte{
		"another body version":         mutate(func(f []any) { f[0] = uint64(2) }),
		"a non-integer epoch":          mutate(func(f []any) { f[2] = "2" }),
		"a non-integer earliest":       mutate(func(f []any) { f[3] = "20" }),
		"a change-record hash of text": mutate(func(f []any) { f[7] = "x" }),
		"nine fields":                  v3Retained(t, "UNICITY_TRUSTBASE_V3", valid[:9]),
		"another domain":               v3Retained(t, "UNICITY_TRUSTBASE_V4", valid),
		"not an array":                 {0x01},
		"empty":                        nil,
	} {
		_, err := decodeRetainedBody(bad)
		require.ErrorIs(t, err, ErrHandoffRecord, name)
	}
}
