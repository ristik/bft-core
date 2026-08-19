package shardnode_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	testobs "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// testObservability combines the test factory's MeterAndTracer with a
// logger to satisfy network.Observability's three methods — the test
// factory alone has no Logger(), the same gap aggregator-go's own
// internal/bft/network.go fills for the same reason.
type testObservability struct {
	observability.MeterAndTracer
	log *slog.Logger
}

func (o testObservability) Logger() *slog.Logger { return o.log }

// TestNetDisseminator_TwoRealPeers proves Publish/Await over an actual
// libp2p connection between two independent hosts on loopback TCP — not a
// mock, not in-process channels. This is the same transport a real
// multi-validator deployment uses; only the addresses are local.
func TestNetDisseminator_TwoRealPeers(t *testing.T) {
	obs := testobs.NewFactory(t)
	mt, err := obs.Observability("", "")
	require.NoError(t, err)
	obsv := testObservability{MeterAndTracer: mt, log: obs.DefaultLogger()}

	leaderPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	followerPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))

	// Each side needs to know how to dial the other — mirrors
	// network/network_test.go's own pattern for connecting two test peers.
	leaderPeer.Network().Peerstore().AddAddrs(followerPeer.ID(), followerPeer.MultiAddresses(), peerstore.PermanentAddrTTL)
	followerPeer.Network().Peerstore().AddAddrs(leaderPeer.ID(), leaderPeer.MultiAddresses(), peerstore.PermanentAddrTTL)

	leaderDiss, err := shardnode.NewNetDisseminator(leaderPeer, obsv, []peer.ID{followerPeer.ID()})
	require.NoError(t, err)
	followerDiss, err := shardnode.NewNetDisseminator(followerPeer, obsv, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return leaderDiss.Run(gctx) })
	g.Go(func() error { return followerDiss.Run(gctx) })

	block := shardnode.Block{
		Number:     5,
		Hash:       shardnode.Hash{0xAA, 0xBB},
		StateRoot:  shardnode.Hash{0xCC, 0xDD},
		ParentHash: shardnode.Hash{0xEE, 0xFF},
		Raw:        []byte("proposal envelope bytes"),
		BlockSize:  42,
		StateSize:  7,
	}

	require.NoError(t, leaderDiss.Publish(ctx, 5, block))

	awaitCtx, awaitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer awaitCancel()
	got, err := followerDiss.Await(awaitCtx, 5)
	require.NoError(t, err)
	require.Equal(t, block.Number, got.Number)
	require.Equal(t, block.Hash, got.Hash)
	require.Equal(t, block.StateRoot, got.StateRoot)
	require.Equal(t, block.ParentHash, got.ParentHash)
	require.Equal(t, block.Raw, got.Raw)
	require.Equal(t, block.BlockSize, got.BlockSize)
	require.Equal(t, block.StateSize, got.StateSize)

	cancel()
	_ = g.Wait() // Run returns ctx.Err() on cancellation; not a test failure
}

// TestNetDisseminator_AwaitTimesOutIfNothingArrives proves the abstention
// path a missed proposal needs (see docs/engine-api-adapter-plan.md C2.5):
// Await must return, not hang forever, when nothing is ever published for
// the round it's waiting on.
func TestNetDisseminator_AwaitTimesOutIfNothingArrives(t *testing.T) {
	obs := testobs.NewFactory(t)
	mt, err := obs.Observability("", "")
	require.NoError(t, err)
	obsv := testObservability{MeterAndTracer: mt, log: obs.DefaultLogger()}

	p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	d, err := shardnode.NewNetDisseminator(p, obsv, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	awaitCtx, awaitCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer awaitCancel()
	_, err = d.Await(awaitCtx, 999)
	require.Error(t, err)
}
