package shardnode_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"golang.org/x/sync/errgroup"

	testobs "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func peerIDOf(t *testing.T) peer.ID {
	t.Helper()
	return testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)).ID()
}

func nodesOf(ids ...peer.ID) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(ids))
	for i, id := range ids {
		out[i] = &types.NodeInfo{NodeID: id.String(), SigKey: bytes.Repeat([]byte{byte(i + 2)}, 33), Stake: 1}
	}
	return out
}

// Block dissemination addresses the validators of the ACTIVE assignment as of each publish: after a rotation {A,B} -> {A,C}, the leader
// reaches the successor C and no longer the retired B.
func TestBlockDisseminationFollowsTheInstalledAssignment(t *testing.T) {
	obs := testobs.NewFactory(t)
	mt, err := obs.Observability("", "")
	require.NoError(t, err)
	obsv := testObservability{MeterAndTracer: mt, log: obs.DefaultLogger()}

	leader := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	retained := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))  // B: in the genesis set, retired by the step
	successor := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)) // C: joins with the step
	leader.Network().Peerstore().AddAddrs(retained.ID(), retained.MultiAddresses(), peerstore.PermanentAddrTTL)
	leader.Network().Peerstore().AddAddrs(successor.ID(), successor.MultiAddresses(), peerstore.PermanentAddrTTL)
	active, err := shardnode.NewActivePeers(leader.ID(), nodesOf(leader.ID(), retained.ID()))
	require.NoError(t, err)

	leaderDiss, err := shardnode.NewNetDisseminatorFrom(leader, obsv, active)
	require.NoError(t, err)
	retainedDiss, err := shardnode.NewNetDisseminator(retained, obsv, nil)
	require.NoError(t, err)
	successorDiss, err := shardnode.NewNetDisseminator(successor, obsv, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	for _, d := range []*shardnode.NetDisseminator{leaderDiss, retainedDiss, successorDiss} {
		d := d
		g.Go(func() error { return d.Run(gctx) })
	}
	block := shardnode.Block{Number: 1, Hash: shardnode.Hash{1}, StateRoot: shardnode.Hash{2}, ParentHash: shardnode.Hash{3}, Raw: []byte("a")}

	await := func(d *shardnode.NetDisseminator, round uint64, within time.Duration) error {
		c, cancel := context.WithTimeout(ctx, within)
		defer cancel()
		_, err := d.Await(c, round)
		return err
	}
	require.NoError(t, leaderDiss.Publish(ctx, 1, block))
	require.NoError(t, await(retainedDiss, 1, 5*time.Second), "before the step the genesis set is addressed")
	require.Error(t, await(successorDiss, 1, 500*time.Millisecond))

	require.NoError(t, active.Install(1, nodesOf(leader.ID(), successor.ID())), "the verified step is installed")
	require.NoError(t, leaderDiss.Publish(ctx, 2, block))
	require.NoError(t, await(successorDiss, 2, 5*time.Second), "after the step the successor is addressed")
	require.Error(t, await(retainedDiss, 2, 500*time.Millisecond), "and the retired validator is not")
}

// Evidence providers and journal-suffix providers follow the same source, and the journal server's allowlist is the active set (held
// until the replay is done).
func TestEvidenceProvidersAndTheJournalAllowlistFollowTheInstalledAssignment(t *testing.T) {
	self, kept, retired, joiner := peerIDOf(t), peerIDOf(t), peerIDOf(t), peerIDOf(t)
	active, err := shardnode.NewActivePeers(self, nodesOf(self, kept, retired))
	require.NoError(t, err)
	require.ElementsMatch(t, []peer.ID{kept, retired}, active.EvidenceProviders())

	require.NoError(t, active.Install(1, nodesOf(self, kept, joiner)))
	require.ElementsMatch(t, []peer.ID{kept, joiner}, active.EvidenceProviders(), "providers follow the step")
	require.NotContains(t, active.EvidenceProviders(), self, "never this node")

	// the allowlist the journal server is given is the same set, and a held set authorizes nobody
	require.True(t, active.Allowed(joiner))
	require.False(t, active.Allowed(retired))
	active.Hold()
	require.False(t, active.Allowed(kept), "held: nobody until the replay is done")
	require.ElementsMatch(t, []peer.ID{kept, joiner}, active.Peers(), "while the outbound list is still the installed one")
	active.Release()
	require.True(t, active.Allowed(kept))

	// an older epoch never moves the set backwards, a different set for the active epoch conflicts
	require.NoError(t, active.Install(0, nodesOf(self, retired)))
	require.ElementsMatch(t, []peer.ID{kept, joiner}, active.Peers())
	require.ErrorIs(t, active.Install(1, nodesOf(self, kept)), shardnode.ErrActivePeersConflict)
}
