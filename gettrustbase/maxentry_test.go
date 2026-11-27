package gettrustbase

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The shared maximum-size fixture (bft-go-base testdata/trust-base-v2/max-entry/v1/max-entry.json, vendored byte for byte): a genesis of 256 members with
// 128-byte node ids and an epoch 2 signed by all 256 of them, 95,365 bytes. The per-entry cap (128 KiB) must accept it; the 64 KiB cap did not.
func TestTheLargestValidEntryFitsThePageCodecAndAnItemOverTheCapIsRefused(t *testing.T) {
	data, err := os.ReadFile("testdata/max-entry-v1.json")
	require.NoError(t, err)
	var f struct {
		Entry      string `json:"entry"`
		EntryBytes int    `json:"entryBytes"`
		Bundle     string `json:"bundle"`
		GenesisID  string `json:"genesisId"`
	}
	require.NoError(t, json.Unmarshal(data, &f))
	entry, err := hex.DecodeString(f.Entry)
	require.NoError(t, err)
	require.Equal(t, f.EntryBytes, len(entry))
	require.Greater(t, len(entry), 64<<10, "the old cap refused this entry")
	require.Less(t, len(entry), types.MaxTrustBaseEntryBytes)

	bundle, err := hex.DecodeString(f.Bundle)
	require.NoError(t, err)
	resp, entries, err := types.DecodeTrustBaseResponse(bundle, types.TrustBasePageLimits)
	require.NoError(t, err, "a page of the genesis and the largest valid entry")
	require.Len(t, entries, 2)
	require.Len(t, entries[1].RootNodes, 256)
	require.Equal(t, types.TrustBaseStatusOK, resp.Status)

	// a well-formed item over the cap is refused
	junk, err := types.Cbor.Marshal(make([]byte, types.MaxTrustBaseEntryBytes))
	require.NoError(t, err)
	id, err := hex.DecodeString(f.GenesisID)
	require.NoError(t, err)
	over := &types.TrustBaseResponse{Version: 1, Network: 5, Status: types.TrustBaseStatusOK, FromEpoch: 1, EffectiveEnd: 1, EndEntryID: id, Entries: []cbor.RawMessage{junk}}
	b, err := over.Encode()
	require.NoError(t, err)
	_, _, err = types.DecodeTrustBaseResponse(b, types.TrustBaseLimits{MaxBytes: len(b), MaxEntries: 4})
	require.ErrorIs(t, err, types.ErrTrustBaseResponse)
	require.Contains(t, err.Error(), "entry of")
}
