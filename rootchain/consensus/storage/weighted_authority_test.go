package storage

import (
	"math"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// weightedAuthority: sorted ids; the first weighs `heavy`, the others 1; the threshold is set explicitly.
func weightedAuthority(t *testing.T, n int, heavy, threshold uint64) (*v1HandoffAuthority, []string, map[string]abcrypto.Signer) {
	t.Helper()
	signers := map[string]abcrypto.Signer{}
	var nodes []*types.NodeInfo
	for i := 0; i < n; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id := string(rune('a'+i)) + "-node"
		signers[id] = s
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	nodes[0].Stake = heavy
	ids := make([]string, len(nodes))
	for i, nd := range nodes {
		ids[i] = nd.NodeID
	}
	tb := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, RootNodes: nodes, QuorumThreshold: threshold}
	return &v1HandoffAuthority{trust: tb}, ids, signers
}

func signedBy(t *testing.T, signers map[string]abcrypto.Signer, msg []byte, ids ...string) map[string]hex.Bytes {
	out := map[string]hex.Bytes{}
	for _, id := range ids {
		sig, err := signers[id].SignBytes(msg)
		require.NoError(t, err)
		out[id] = sig
	}
	return out
}

func TestHandoffVerifyQuorumIsWeightedNotCounted(t *testing.T) {
	a, ids, signers := weightedAuthority(t, 4, 6, 7) // total 9
	msg := []byte("freeze")
	require.NoError(t, a.verifyQuorum(msg, signedBy(t, signers, msg, ids[0], ids[1])), "2 of 4 by count, 7 of 9 by weight")
	require.ErrorIs(t, a.verifyQuorum(msg, signedBy(t, signers, msg, ids[1:]...)), ErrHandoffRecord, "3 of 4 by count, 3 of 9 by weight")
}

func TestHandoffVerifyQuorumRefusesBadUnknownAndOverflow(t *testing.T) {
	a, ids, signers := weightedAuthority(t, 4, 6, 7)
	msg := []byte("freeze")
	good := signedBy(t, signers, msg, ids[0], ids[1])

	bad := signedBy(t, signers, msg, ids[0], ids[1])
	bad[ids[2]] = []byte{1, 2, 3}
	require.ErrorIs(t, a.verifyQuorum(msg, bad), ErrHandoffRecord, "an invalid extra signature fails the set")

	unknown := signedBy(t, signers, msg, ids[0], ids[1])
	unknown["stranger"] = good[ids[0]]
	require.ErrorIs(t, a.verifyQuorum(msg, unknown), ErrHandoffRecord, "an unknown extra signer fails the set")

	huge, hids, hsigners := weightedAuthority(t, 2, math.MaxUint64, 5)
	require.ErrorIs(t, huge.verifyQuorum(msg, signedBy(t, hsigners, msg, hids...)), ErrHandoffRecord, "weights that overflow fail closed")
}
