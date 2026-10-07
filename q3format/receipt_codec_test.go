package q3format

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReceiptSetCodecRoundTripsAndRefusesEachMalformation(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 65)
	good := []Receipt{{NodeID: "b", Signature: sig}, {NodeID: "a", Signature: sig}}
	raw, err := EncodeReceipts(good)
	require.NoError(t, err)
	back, err := DecodeReceipts(raw)
	require.NoError(t, err)
	require.Equal(t, []Receipt{{NodeID: "a", Signature: sig}, {NodeID: "b", Signature: sig}}, back, "encoded in node-id order")

	_, err = EncodeReceipts(nil)
	require.ErrorIs(t, err, ErrFormat)
	_, err = EncodeReceipts([]Receipt{{NodeID: "a", Signature: sig}, {NodeID: "a", Signature: sig}})
	require.ErrorIs(t, err, ErrReceiptDuplicate)
	_, err = EncodeReceipts([]Receipt{{NodeID: "a", Signature: make([]byte, maxSignature+1)}})
	require.ErrorIs(t, err, ErrTooLarge)

	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"empty":         {nil, ErrFormat},
		"trailing byte": {append(append([]byte(nil), raw...), 0), ErrFormat},
		"unordered":     {enc([]any{"b", sig}, []any{"a", sig}), ErrFormat},
		"duplicate":     {enc([]any{"a", sig}, []any{"a", sig}), ErrFormat},
		"empty set":     {enc(), ErrFormat},
		"wrong shape":   {enc([]any{"a"}), ErrFormat},
		"not canonical": {append([]byte{0x9f}, append(raw[1:], 0xff)...), ErrFormat},
	} {
		_, err := DecodeReceipts(tc.raw)
		require.ErrorIs(t, err, tc.want, name)
	}
}
