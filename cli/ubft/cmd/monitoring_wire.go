package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/monitoring"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// the peers watcher's cadence: the gauges are read at scrape time, the node.peers.* events are logged from this loop, and a set must stay
// below the expected count for the grace period before it is an event (a restart's reconnect is not one)
const (
	peersWatchEvery = 10 * time.Second
	peersWatchGrace = 30 * time.Second
)

// registerRootMonitoring registers the root node's node-level unicity_* metrics and starts the peers watcher. The consensus manager
// registered its own (round, epoch, lag, votes, proposals). Without --metrics prometheus the registry is empty and nothing is read.
func registerRootMonitoring(ctx context.Context, flags *rootNodeRunFlags, log *slog.Logger, host *network.Peer, cm interface{ Validators() peer.IDSlice }) {
	mon := monitoring.New(flags.observe.PrometheusRegisterer())
	monitoring.RegisterBuildInfo(mon, "root")
	if flags.baseFlags != nil {
		monitoring.RegisterDisk(mon, log, monitoring.Volume{Name: "home", Path: flags.HomeDir})
	}
	peers := monitoring.RegisterPeers(mon, log, host.Network(), host.ID(), monitoring.PeerSet{Network: "root", Expected: func() []peer.ID { return cm.Validators() }})
	go peers.Watch(ctx, peersWatchEvery, peersWatchGrace)
}

// registerShardMonitoring registers the shard node's unicity_* metrics: its health snapshot, the execution client's head, the disk of its
// home, and the peers of its shard and of the root network.
func registerShardMonitoring(ctx context.Context, flags *shardNodeRunFlags, log *slog.Logger, host *network.Peer, node *shardnode.Node,
	exec shardnode.Executor, shardPeers, rootPeers func() []peer.ID) {
	mon := monitoring.New(flags.observe.PrometheusRegisterer())
	monitoring.RegisterBuildInfo(mon, "shard")
	shardnode.RegisterUnicityMetrics(mon, node.Health(), exec)
	if flags.baseFlags != nil {
		monitoring.RegisterDisk(mon, log, monitoring.Volume{Name: "home", Path: flags.HomeDir})
	}
	sets := []monitoring.PeerSet{}
	if shardPeers != nil {
		sets = append(sets, monitoring.PeerSet{Network: "shard", Expected: shardPeers})
	}
	if rootPeers != nil {
		sets = append(sets, monitoring.PeerSet{Network: "root", Expected: rootPeers})
	}
	peers := monitoring.RegisterPeers(mon, log, host.Network(), host.ID(), sets...)
	go peers.Watch(ctx, peersWatchEvery, peersWatchGrace)
}
