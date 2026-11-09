package consensus

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// #976 part 2 (spike): real shard nodes (the production shardnode.Node: BFTClient, round driver, net disseminator, a deterministic fake executor) for the
// fixture's EVM validators, on the same libp2p transport as the roots.

type managerTrust struct{ m *ConsensusManager }

func (s managerTrust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	tb := s.m.trustBase.Load()
	if tb.Epoch != epoch {
		return nil, fmt.Errorf("trust base epoch %d unavailable (have %d)", epoch, tb.Epoch)
	}
	return tb, nil
}

type realShard struct {
	id     string
	node   *shardnode.Node
	exec   *executortest.Fake
	cancel context.CancelFunc
	done   chan error
}

// addRealShards is liveTransport.addShards with a production shard node behind each validator's shard network instead of a receipt goroutine.
func addRealShards(t *testing.T, x *liveTransport, c *q4bLive, opts shardnode.BFTClientOptions) map[string]*realShard {
	t.Helper()
	f := c.nodes[0].r.f
	m := c.nodes[0].r.manager
	si := m.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	require.NotNil(t, si)
	luc := si.LastCR.UC
	genesis := shardnode.BlockRef{Number: 0, Hash: shardnode.Hash(luc.InputRecord.BlockHash), StateRoot: shardnode.Hash(luc.InputRecord.Hash)}
	t.Logf("shard genesis for the fake executor: block hash %x state root %x", genesis.Hash, genesis.StateRoot)
	ids := make([]string, 0, len(f.ShardNodes))
	for id := range f.ShardNodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	peers := make([]peer.ID, 0, len(ids))
	hosts := map[string]*shardHost{}
	for _, id := range ids {
		p := x.newPeer(f.ShardNodes[id].PeerConf)
		t.Cleanup(func() { _ = p.Close() })
		n, err := network.NewShardNetwork(p, x.obs, network.DefaultShardNetworkOptions)
		require.NoError(t, err)
		h := &shardHost{peer: p, net: n}
		x.shards[id] = h
		hosts[id] = h
		peers = append(peers, p.ID())
	}
	out := map[string]*realShard{}
	for _, id := range ids {
		h := hosts[id]
		diss, err := shardnode.NewNetDisseminator(h.peer, x.obs, peers)
		require.NoError(t, err)
		exec := executortest.NewAt(genesis)
		node, err := shardnode.New(h.peer, h.net, f.EVMSigners[id], q3fixture.PartitionID, types.ShardID{}, si.ShardConfHash, managerTrust{m}, exec, diss, nil,
			slog.New(slog.NewTextHandler(&testLogWriter{t: t, prefix: id[len(id)-6:]}, &slog.HandlerOptions{Level: slog.LevelInfo})), opts)
		require.NoError(t, err)
		out[id] = &realShard{id: id, node: node, exec: exec}
	}
	_ = crypto.SHA256
	return out
}

type testLogWriter struct {
	t      *testing.T
	prefix string
	mu     sync.Mutex
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "level=ERROR") || strings.Contains(line, "level=WARN") {
		w.t.Logf("shard %s: %s", w.prefix, line)
	}
	return len(p), nil
}

func (s *realShard) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done = cancel, make(chan error, 1)
	go func() { s.done <- s.node.Run(ctx) }()
}

func TestSpikeRealShardsOnLiveRoots(t *testing.T) {
	T := 2 * time.Second
	transport := newLiveTransport(t)
	c := newEqualLiveRate(t, T, phaseLockBlockRate, q3fixture.Options{PeerEVM: true}, transport.install, "H", "a", "b", "c")
	shards := addRealShards(t, transport, c, shardnode.DefaultBFTClientOptions)
	transport.up(c, c.all()...)
	c.start(c.all()...)
	c.warm(8, c.all()...)
	for _, s := range shards {
		s.start()
		defer func(s *realShard) { s.cancel(); <-s.done }(s)
	}
	h := c.nodes[c.idx("H")].r.manager
	before := shardCertOf(h)
	t.Logf("before: seal %d", before.seal)
	require.Eventually(t, func() bool {
		s := shardCertOf(h)
		return s != nil && s.seal > before.seal+5
	}, 2*time.Minute, 500*time.Millisecond, "the real shard validators get certificates from the roots")
	t.Logf("after: %+v", shardCertOf(h))
}
