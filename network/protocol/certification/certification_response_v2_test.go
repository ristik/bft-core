package certification

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func v2Base(t *testing.T) *CertificationResponse {
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

func TestResponseV2RoundTripsAndKeepsTheLegacyMeaning(t *testing.T) {
	base := v2Base(t)
	v2 := NewCertificationResponseV2(base, [][]byte{entryBytes(1, 300), entryBytes(2, 310)})
	require.NoError(t, v2.IsValid())
	raw, err := types.Cbor.Marshal(v2)
	require.NoError(t, err)
	var back CertificationResponseV2
	require.NoError(t, types.Cbor.Unmarshal(raw, &back))
	again, err := types.Cbor.Marshal(&back)
	require.NoError(t, err)
	require.True(t, bytes.Equal(raw, again), "the encoding is stable")
	require.Len(t, back.TrustBaseUpdates, 2)
	legacy := back.Response()
	require.NoError(t, legacy.IsValid())
	require.Equal(t, base.Status, legacy.Status)
	require.Equal(t, base.Message, legacy.Message)
	require.Equal(t, base.Technical.Round, legacy.Technical.Round)
	require.True(t, bytes.Equal(base.UC.TRHash, legacy.UC.TRHash), "the certificate and record are exactly the legacy response's")
	require.False(t, back.Response().IsAccepted(), "valid entries do not turn a rejection into an acceptance")

	t.Run("no entries", func(t *testing.T) {
		raw, err := types.Cbor.Marshal(NewCertificationResponseV2(base, nil))
		require.NoError(t, err)
		var b CertificationResponseV2
		require.NoError(t, types.Cbor.Unmarshal(raw, &b))
		require.Empty(t, b.TrustBaseUpdates)
	})
}

func TestResponseV2IsNotTheLegacyFormAndNeverGuessedFromArity(t *testing.T) {
	base := v2Base(t)
	v2raw, err := types.Cbor.Marshal(NewCertificationResponseV2(base, [][]byte{entryBytes(1, 10)}))
	require.NoError(t, err)
	legacyRaw, err := types.Cbor.Marshal(base)
	require.NoError(t, err)

	var legacy CertificationResponse
	require.Error(t, types.Cbor.Unmarshal(v2raw, &legacy), "a legacy reader refuses the version 2 bytes")
	var v2 CertificationResponseV2
	require.Error(t, types.Cbor.Unmarshal(legacyRaw, &v2), "and a version 2 reader refuses the 6-element legacy bytes")
	old := struct {
		_         struct{} `cbor:",toarray"`
		Partition types.PartitionID
		Shard     types.ShardID
		Technical TechnicalRecord
		UC        types.UnicityCertificate
	}{Partition: base.Partition, Technical: base.Technical, UC: base.UC}
	oldRaw, err := types.Cbor.Marshal(old)
	require.NoError(t, err)
	require.Error(t, types.Cbor.Unmarshal(oldRaw, &v2), "and the 4-element one")
}

func TestResponseV2Bounds(t *testing.T) {
	base := v2Base(t)
	for name, updates := range map[string][][]byte{
		"three entries":  {entryBytes(1, 10), entryBytes(2, 10), entryBytes(3, 10)},
		"an empty entry": {nil},
		"an oversize":    {entryBytes(1, MaxTrustBaseUpdateBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			v2 := NewCertificationResponseV2(base, updates)
			require.ErrorIs(t, v2.IsValid(), ErrResponseV2)
			_, err := types.Cbor.Marshal(v2)
			require.ErrorIs(t, err, ErrResponseV2, "a sender cannot produce what no receiver accepts")
		})
	}
	require.NoError(t, NewCertificationResponseV2(base, [][]byte{entryBytes(1, MaxTrustBaseUpdateBytes), entryBytes(2, 1)}).IsValid())

	t.Run("a wrong version, hand-built", func(t *testing.T) {
		v2 := NewCertificationResponseV2(base, nil)
		v2.Version = 3
		require.ErrorIs(t, v2.IsValid(), ErrResponseV2)
		type wire CertificationResponseV2
		raw, err := types.Cbor.Marshal(wire(*v2))
		require.NoError(t, err)
		var back CertificationResponseV2
		require.ErrorIs(t, types.Cbor.Unmarshal(raw, &back), ErrResponseV2)
	})
	t.Run("three entries, hand-built on the wire", func(t *testing.T) {
		type wire CertificationResponseV2
		v2 := NewCertificationResponseV2(base, [][]byte{entryBytes(1, 10), entryBytes(2, 10), entryBytes(3, 10)})
		raw, err := types.Cbor.Marshal(wire(*v2))
		require.NoError(t, err)
		var back CertificationResponseV2
		require.ErrorIs(t, types.Cbor.Unmarshal(raw, &back), ErrResponseV2)
	})
	t.Run("trailing bytes", func(t *testing.T) {
		raw, err := types.Cbor.Marshal(NewCertificationResponseV2(base, nil))
		require.NoError(t, err)
		var back CertificationResponseV2
		require.Error(t, types.Cbor.Unmarshal(append(raw, 0), &back))
	})
	t.Run("the legacy checks still apply", func(t *testing.T) {
		bad := v2Base(t)
		bad.Partition = 2
		require.Error(t, NewCertificationResponseV2(bad, nil).IsValid())
		var nilResp *CertificationResponseV2
		require.ErrorIs(t, nilResp.IsValid(), ErrResponseV2)
	})
}
