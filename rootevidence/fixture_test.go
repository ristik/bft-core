package rootevidence

import (
	"bytes"
	gocrypto "crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// fixture is a root committee of four fixed keys with trust bases for epochs 1 to 3; epoch 2 signs with the domain-bound scheme.
type fixture struct {
	store   *trustbase.TrustBaseStore
	signers map[string]abcrypto.Signer
	ids     []string
	cfg     votesig.Config
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{signers: map[string]abcrypto.Signer{}, cfg: votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("rootevidence-test-genesis"))}}
	var nodes []*types.NodeInfo
	for _, id := range []string{"1", "2", "3", "4"} {
		k := sha256.Sum256([]byte("rootevidence-test-key/" + id))
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		f.signers[id] = s
		f.ids = append(f.ids, id)
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: key, Stake: 1})
	}
	store, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	var prev *types.RootTrustBaseV1
	for epoch, start := uint64(1), uint64(1); epoch <= 3; epoch, start = epoch+1, start+9 {
		opts := []types.Option{types.WithEpoch(epoch), types.WithEpochStart(start)}
		if prev != nil {
			h, err := prev.Hash(gocrypto.SHA256)
			require.NoError(t, err)
			opts = append(opts, types.WithPreviousTrustBaseHash(h))
		}
		cp := make([]*types.NodeInfo, len(nodes))
		for i, n := range nodes {
			cp[i] = &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: n.Stake}
		}
		tb, err := types.NewTrustBase(5, cp, opts...)
		require.NoError(t, err)
		for _, id := range f.ids {
			require.NoError(t, tb.Sign(id, f.signers[id]))
		}
		require.NoError(t, store.Store(tb))
		prev = tb
	}
	require.NoError(t, store.ActivateSigning(2, f.cfg))
	f.store = store
	return f
}

// vote is a scheme 2 vote of the author; exec makes two votes of one slot differ. A committing vote also carries a seal signature.
func (f *fixture) vote(t *testing.T, author string, epoch, round uint64, committing bool, exec byte) *abdrc.VoteMsg {
	t.Helper()
	execHash := bytes.Repeat([]byte{exec}, 32)
	vi := votesig.VoteInfo{Epoch: epoch, Round: round, Parent: round - 1}
	copy(vi.Exec[:], execHash)
	vh, err := f.cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, PreviousHash: vh[:]}
	if committing {
		seal = &types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(f.cfg.Network), PreviousHash: vh[:], RootChainRoundNumber: round - 1,
			Epoch: epoch, Timestamp: 4242, Hash: bytes.Repeat([]byte{0xc0}, 32)}
	}
	v := &abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: round, Epoch: epoch, ParentRoundNumber: round - 1, CurrentRootHash: execHash},
		LedgerCommitInfo: seal, Author: author}
	require.NoError(t, v.SignDomainBound(f.signers[author], f.cfg))
	return v
}

func (f *fixture) observe(t *testing.T, author string, epoch, round uint64, committing bool, exec byte) *Observation {
	t.Helper()
	o, err := Observe(f.vote(t, author, epoch, round, committing, exec), f.store)
	require.NoError(t, err)
	return o
}
