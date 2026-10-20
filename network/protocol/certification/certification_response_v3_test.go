package certification

import (
	"bytes"
	"github.com/fxamacker/cbor/v2"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func v3Base(t *testing.T) *CertificationResponse {
	cr := &CertificationResponse{
		Partition: 1,
		UC:        types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1}},
		Status:    CertStatusRequestInvalid,
		Message:   "stale round",
	}
	require.NoError(t, cr.SetTechnicalRecord(TechnicalRecord{Round: 99, Epoch: 8, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	return cr
}

func entryBytes(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func TestResponseV3RoundTripsAndKeepsTheLegacyMeaning(t *testing.T) {
	base := v3Base(t)
	v3 := NewCertificationResponseV3(base, [][]byte{entryBytes(1, 300), entryBytes(2, 310)})
	require.NoError(t, v3.IsValid())
	raw, err := types.Cbor.Marshal(v3)
	require.NoError(t, err)
	var back CertificationResponseV3
	require.NoError(t, types.Cbor.Unmarshal(raw, &back))
	again, err := types.Cbor.Marshal(&back)
	require.NoError(t, err)
	require.True(t, bytes.Equal(raw, again), "the encoding is stable")
	require.Len(t, back.TrustBaseUpdates, 2)
	legacy := back.Legacy()
	require.NoError(t, legacy.IsValid())
	require.Equal(t, base.Status, legacy.Status)
	require.Equal(t, base.Message, legacy.Message)
	require.Equal(t, base.Technical.Round, legacy.Technical.Round)
	require.True(t, bytes.Equal(base.UC.TRHash, legacy.UC.TRHash), "the certificate and record are exactly the legacy response's")
	require.False(t, back.Legacy().IsAccepted(), "valid entries do not turn a rejection into an acceptance")

	t.Run("no entries", func(t *testing.T) {
		raw, err := types.Cbor.Marshal(NewCertificationResponseV3(base, nil))
		require.NoError(t, err)
		var b CertificationResponseV3
		require.NoError(t, types.Cbor.Unmarshal(raw, &b))
		require.Empty(t, b.TrustBaseUpdates)
	})
}

func TestResponseV3IsNotTheLegacyFormAndNeverGuessedFromArity(t *testing.T) {
	base := v3Base(t)
	v3raw, err := types.Cbor.Marshal(NewCertificationResponseV3(base, [][]byte{entryBytes(1, 10)}))
	require.NoError(t, err)
	legacyRaw, err := types.Cbor.Marshal(base)
	require.NoError(t, err)

	var legacy CertificationResponse
	require.Error(t, types.Cbor.Unmarshal(v3raw, &legacy), "a legacy reader refuses the version 3 bytes")
	var v3 CertificationResponseV3
	require.Error(t, types.Cbor.Unmarshal(legacyRaw, &v3), "and a version 3 reader refuses the 6-element legacy bytes")
	old := struct {
		_         struct{} `cbor:",toarray"`
		Partition types.PartitionID
		Shard     types.ShardID
		Technical TechnicalRecord
		UC        types.UnicityCertificate
	}{Partition: base.Partition, Technical: base.Technical, UC: base.UC}
	oldRaw, err := types.Cbor.Marshal(old)
	require.NoError(t, err)
	require.Error(t, types.Cbor.Unmarshal(oldRaw, &v3), "and the 4-element one")
}

func TestResponseV3Bounds(t *testing.T) {
	base := v3Base(t)
	for name, updates := range map[string][][]byte{
		"three entries":  {entryBytes(1, 10), entryBytes(2, 10), entryBytes(3, 10)},
		"an empty entry": {nil},
		"an oversize":    {entryBytes(1, MaxTrustBaseUpdateBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			v3 := NewCertificationResponseV3(base, updates)
			require.ErrorIs(t, v3.IsValid(), ErrResponseV3)
			_, err := types.Cbor.Marshal(v3)
			require.ErrorIs(t, err, ErrResponseV3, "a sender cannot produce what no receiver accepts")
		})
	}
	require.NoError(t, NewCertificationResponseV3(base, [][]byte{entryBytes(1, MaxTrustBaseUpdateBytes), entryBytes(2, 1)}).IsValid())

	t.Run("a wrong version, hand-built", func(t *testing.T) {
		v3 := NewCertificationResponseV3(base, nil)
		v3.Version = 2
		require.ErrorIs(t, v3.IsValid(), ErrResponseV3)
		type wire CertificationResponseV3
		raw, err := types.Cbor.Marshal(wire(*v3))
		require.NoError(t, err)
		var back CertificationResponseV3
		require.ErrorIs(t, types.Cbor.Unmarshal(raw, &back), ErrResponseV3)
	})
	t.Run("three entries, hand-built on the wire", func(t *testing.T) {
		type wire CertificationResponseV3
		v3 := NewCertificationResponseV3(base, [][]byte{entryBytes(1, 10), entryBytes(2, 10), entryBytes(3, 10)})
		raw, err := types.Cbor.Marshal(wire(*v3))
		require.NoError(t, err)
		var back CertificationResponseV3
		require.ErrorIs(t, types.Cbor.Unmarshal(raw, &back), ErrResponseV3)
	})
	t.Run("trailing bytes", func(t *testing.T) {
		raw, err := types.Cbor.Marshal(NewCertificationResponseV3(base, nil))
		require.NoError(t, err)
		var back CertificationResponseV3
		require.Error(t, types.Cbor.Unmarshal(append(raw, 0), &back))
	})
	t.Run("the legacy checks still apply", func(t *testing.T) {
		bad := v3Base(t)
		bad.Partition = 2
		require.Error(t, NewCertificationResponseV3(bad, nil).IsValid())
		var nilResp *CertificationResponseV3
		require.ErrorIs(t, nilResp.IsValid(), ErrResponseV3)
	})
}

// The view of a V3 message is an opaque canonical byte string that is null when omitted: an empty string, a string over the view limit, an
// indefinite-length string and a tagged string are refused by the decoder, and the constructor omits a view over the limit instead of sending it.
// (Hand-built frames: a good message with the view element replaced.)
func TestResponseV3ViewGuards(t *testing.T) {
	base := v3Base(t)
	frame := func(view []byte) []byte {
		t.Helper()
		version, err := types.Cbor.Marshal(CertificationResponseV3Version)
		require.NoError(t, err)
		resp, err := types.Cbor.Marshal(base)
		require.NoError(t, err)
		// [version, response, view, null]: the view bytes are spliced in as they are (the encoder would not write the indefinite form)
		out := append([]byte{0x84}, version...)
		out = append(out, resp...)
		out = append(out, view...)
		return append(out, 0xf6)
	}
	bstr := func(n int) []byte { // definite-length byte string of n bytes
		b, err := cbor.Marshal(bytes.Repeat([]byte{7}, n))
		require.NoError(t, err)
		return b
	}
	decode := func(view []byte) error {
		var v3 CertificationResponseV3
		return types.Cbor.Unmarshal(frame(view), &v3)
	}

	require.NoError(t, decode([]byte{0xf6}), "control: null")
	require.NoError(t, decode(bstr(1)), "control: a non-empty view")
	require.NoError(t, decode(bstr(MaxPartitionViewSize)), "control: a view of exactly the limit")

	require.ErrorIs(t, decode([]byte{0x40}), ErrResponseV3, "an empty byte string is not an omitted view")
	require.ErrorIs(t, decode(bstr(MaxPartitionViewSize+1)), ErrResponseV3, "a view over the limit")
	require.ErrorIs(t, decode([]byte{0x5f, 0x41, 0x01, 0xff}), ErrResponseV3, "an indefinite-length byte string")
	require.ErrorIs(t, decode([]byte{0xc2, 0x41, 0x01}), ErrResponseV3, "a tagged byte string")
	require.ErrorIs(t, decode([]byte{0x81, 0x01}), ErrResponseV3, "an array")

	// the constructor omits a view over the limit; the envelope check refuses one that is there anyway
	over := *base
	over.PartitionView = bytes.Repeat([]byte{7}, MaxPartitionViewSize+1)
	require.Nil(t, NewCertificationResponseV3(&over, nil).PartitionView, "an over-limit view is omitted, never sent")
	fits := *base
	fits.PartitionView = bytes.Repeat([]byte{7}, MaxPartitionViewSize)
	require.Len(t, NewCertificationResponseV3(&fits, nil).PartitionView, MaxPartitionViewSize)
	hand := NewCertificationResponseV3(base, nil)
	hand.PartitionView = bytes.Repeat([]byte{7}, MaxPartitionViewSize+1)
	require.ErrorIs(t, hand.IsValid(), ErrResponseV3)
	_, err := types.Cbor.Marshal(hand)
	require.ErrorIs(t, err, ErrResponseV3, "a sender cannot produce an over-limit view")
	hand.PartitionView = []byte{}
	require.ErrorIs(t, hand.IsValid(), ErrResponseV3, "an empty view is null or absent, never an empty string")
}
