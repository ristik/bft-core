package handoff

import (
	"crypto"
	"math"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// oldQC returns a QC signed by every member and a trust base where the first (sorted) member weighs `heavy`.
func oldQC(t *testing.T, n int, heavy, threshold uint64) (*rctypes.QuorumCert, *types.RootTrustBaseV1, []string) {
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
		id := string(rune('a' + i))
		signers[id] = s
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	nodes[0].Stake = heavy
	ids := make([]string, len(nodes))
	for i, nd := range nodes {
		ids[i] = nd.NodeID
	}
	stamp := types.NewTimestamp()
	root := make([]byte, 32)
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: 5, Epoch: 1, Timestamp: stamp, ParentRoundNumber: 4, CurrentRootHash: root}
	vh, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 4, Epoch: 1, Timestamp: stamp, Hash: root, PreviousHash: vh}
	signed, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, id := range ids {
		sig, err := signers[id].SignBytes(signed)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	return qc, &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 1, RootNodes: nodes, QuorumThreshold: threshold}, ids
}

func keepSigs(qc *rctypes.QuorumCert, ids ...string) {
	kept := map[string]hex.Bytes{}
	for _, id := range ids {
		kept[id] = qc.Signatures[id]
	}
	qc.Signatures = kept
}

func TestVerifyOldQCIsWeightedNotCounted(t *testing.T) {
	qc, tb, ids := oldQC(t, 4, 6, 7) // total 9
	all := qc.Signatures
	keepSigs(qc, ids[0], ids[1])
	require.NoError(t, verifyOldQC(qc, tb), "2 of 4 by count, 7 of 9 by weight")
	qc.Signatures = all
	keepSigs(qc, ids[1:]...)
	require.ErrorIs(t, verifyOldQC(qc, tb), ErrProof, "3 of 4 by count, 3 of 9 by weight")
}

func TestVerifyOldQCRefusesBadUnknownAndOverflow(t *testing.T) {
	qc, tb, ids := oldQC(t, 4, 6, 7)
	all := qc.Signatures
	keepSigs(qc, ids[0], ids[1])
	qc.Signatures[ids[2]] = []byte{1, 2, 3}
	require.ErrorIs(t, verifyOldQC(qc, tb), ErrProof, "an invalid extra signature fails the QC")
	qc.Signatures = all
	keepSigs(qc, ids[0], ids[1])
	qc.Signatures["stranger"] = all[ids[0]]
	require.ErrorIs(t, verifyOldQC(qc, tb), ErrProof, "an unknown extra signer fails the QC")

	hqc, htb, _ := oldQC(t, 2, math.MaxUint64, 5)
	require.ErrorIs(t, verifyOldQC(hqc, htb), ErrProof, "weights that overflow fail closed")
}
