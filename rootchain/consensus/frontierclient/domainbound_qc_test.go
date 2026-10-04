package frontierclient

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// The collector verifies a covering QC in the wire form of the epoch it was built for: the signing configuration of its profile.
func TestCollectorVerifiesTheCoveringQCInTheFormOfItsEpoch(t *testing.T) {
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("collector-test"))}
	trust := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 2, QuorumThreshold: 3}
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"a", "b", "c", "d"} {
		k := sha256.Sum256([]byte("collector-key/" + id))
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		signers[id] = s
		trust.RootNodes = append(trust.RootNodes, &types.NodeInfo{NodeID: id, SigKey: key, Stake: 1})
	}

	// a committing scheme 2 QC of epoch 2: vote round 8 commits round 7
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: 8, Epoch: 2, ParentRoundNumber: 7, CurrentRootHash: bytes.Repeat([]byte{9}, 32)}
	vi := votesig.VoteInfo{Epoch: 2, Round: 8, Parent: 7}
	copy(vi.Exec[:], info.CurrentRootHash)
	vh, err := cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, PreviousHash: vh[:], RootChainRoundNumber: 7, Epoch: 2, Timestamp: types.GenesisTime + 5, Hash: bytes.Repeat([]byte{8}, 32)}
	pv, sealBytes, _, err := drctypes.DomainBoundStatement(cfg, info, seal, true)
	require.NoError(t, err)
	qc := &drctypes.QuorumCert{Scheme: votesig.SchemeDomainBound, VoteInfo: info, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}, SealSignatures: map[string]hex.Bytes{}}
	for _, id := range []string{"a", "b", "c"} {
		sig, err := signers[id].SignBytes(pv)
		require.NoError(t, err)
		sealSig, err := signers[id].SignBytes(sealBytes)
		require.NoError(t, err)
		qc.Signatures[id], qc.SealSignatures[id] = sig, sealSig
	}
	collector := func(signing votesig.Config) *Collector {
		return &Collector{trust: trust, signing: signing, context: frontiercodec.Context{NetworkID: 5, RootEpoch: 2}}
	}

	require.NoError(t, collector(cfg).verifyQC(qc))
	require.ErrorIs(t, collector(votesig.Config{}).verifyQC(qc), ErrUnauthentic, "a legacy profile does not take a scheme 2 certificate")
	bad := *qc
	bad.SealSignatures = map[string]hex.Bytes{"a": qc.SealSignatures["a"], "b": qc.SealSignatures["b"], "d": qc.SealSignatures["c"]}
	require.ErrorIs(t, collector(cfg).verifyQC(&bad), ErrUnauthentic, "unequal signer sets")
}
