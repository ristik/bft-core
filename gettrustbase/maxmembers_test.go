package gettrustbase

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// §49: the offline verifier admits the shared maximum-size chain (256 members with 128-byte node ids, all 256 predecessor signatures); the member
// ceiling used to be the B1 registry's 16 and refused it. A damaged signature of any one of them still refuses the bundle.
func TestVerifyBundleAdmitsThe256MemberChain(t *testing.T) {
	data, err := os.ReadFile("testdata/max-entry-v1.json")
	require.NoError(t, err)
	var f struct {
		Bundle    string `json:"bundle"`
		GenesisID string `json:"genesisId"`
	}
	require.NoError(t, json.Unmarshal(data, &f))
	raw, err := hex.DecodeString(f.Bundle)
	require.NoError(t, err)
	pinBytes, err := hex.DecodeString(f.GenesisID)
	require.NoError(t, err)
	var pin [types.TrustBaseV2IDLen]byte
	copy(pin[:], pinBytes)

	b, err := DecodeBundle(raw, BundleLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 16})
	require.NoError(t, err)
	require.Len(t, b.Entries[1].RootNodes, 256)
	require.NoError(t, VerifyBundle(b, pin))

	// one damaged signature of the 256: refused
	for id, sig := range b.Entries[1].Signatures {
		sig[3] ^= 1
		b.Entries[1].Signatures[id] = sig
		break
	}
	require.ErrorIs(t, VerifyBundle(b, pin), ErrBundleChain)
}
