package frontierclient

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// The frontier reply authentication is the strict variant of the checked quorum: unlike a certificate under v1/D3, a reply
// carrying any invalid signature, even one of a known member, is unauthentic, and the weights decide the quorum.
func TestStrictSignaturesRefuseAnyInvalidSignatureAndWeighByStake(t *testing.T) {
	data := []byte("frontier statement")
	trust := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, QuorumThreshold: 7}
	signers := map[string]abcrypto.Signer{}
	for id, stake := range map[string]uint64{"heavy": 6, "l1": 1, "l2": 1, "l3": 1} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		signers[id] = s
		trust.RootNodes = append(trust.RootNodes, &types.NodeInfo{NodeID: id, SigKey: bytes.Clone(key), Stake: stake})
	}
	// members are looked up by binary search
	for i := range trust.RootNodes {
		for j := i + 1; j < len(trust.RootNodes); j++ {
			if trust.RootNodes[j].NodeID < trust.RootNodes[i].NodeID {
				trust.RootNodes[i], trust.RootNodes[j] = trust.RootNodes[j], trust.RootNodes[i]
			}
		}
	}
	sign := func(ids ...string) map[string]hex.Bytes {
		out := map[string]hex.Bytes{}
		for _, id := range ids {
			sig, err := signers[id].SignBytes(data)
			require.NoError(t, err)
			out[id] = sig
		}
		return out
	}

	require.NoError(t, strictSignatures(trust, sign("heavy", "l1"), data), "2 of 4 by count, 7 of 9 by weight")
	require.ErrorIs(t, strictSignatures(trust, sign("l1", "l2", "l3"), data), ErrUnauthentic, "3 of 4 by count, 3 of 9 by weight")

	extra := sign("heavy", "l1", "l2")
	extra["l2"] = bytes.Repeat([]byte{1}, 65)
	require.ErrorIs(t, strictSignatures(trust, extra, data), ErrUnauthentic, "an invalid signature of a known member refuses the reply")
	unknown := sign("heavy", "l1")
	unknown["stranger"] = bytes.Clone(unknown["heavy"])
	require.ErrorIs(t, strictSignatures(trust, unknown, data), ErrUnauthentic)
}
