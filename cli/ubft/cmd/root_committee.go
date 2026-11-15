package cmd

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network"
)

/*
The root committee keeper (#1082).

A root reaches the others of its committee over libp2p connections, opened on demand by whoever sends first. A member that cannot be
dialled (behind NAT, or an isolated bridge whose private addresses the others cannot reach) is reached only over a connection it opened
itself, and after an install every root has restarted: the connections are gone, and a member dialled while it was restarting is in
the swarm's dial backoff for 5 s and more. In the first rounds of a new epoch that cost a joiner's leader slots two round timeouts (~20 s)
on staging.

So a member of the installed epoch, before it starts consensus in it (after the verified activation, before the first successor round):

  - dials every other member itself and keeps those connections, protected from trimming, re-dialling a member it lost within one
    interval and past the dial backoff (network.MemberProtector.Maintain); the others reach it over these connections whichever side
    can dial, and nothing in the leader schedule changes;
  - waits a bounded warm-up for the committee to be connected, so its first round does not start with votes and proposals that can reach
    nobody. A member that is down costs at most the warm-up, once.

A root that is not a member of the installed epoch (a follower, a leaver) keeps no committee: it never dials a committee it is not in.
*/

// committeeKeep paces the keeper (astra on #1088): a member is retried every 250 ms for the first 30 s (the handoff, when every root
// restarts), then with exponential backoff capped at 10 s with jitter; a host starts at most 8 dials per tick (32/s) and holds at most
// network.MaxMemberDials in flight, however large the committee.
var committeeKeep = network.MaintainConfig{Interval: 250 * time.Millisecond, RapidWindow: 30 * time.Second, BackoffMax: 10 * time.Second,
	DialTimeout: 5 * time.Second, PerTick: 8}

const (
	// committeeWarmupDefault bounds the wait before the first round: the members of a parallel install come up within about one restart of
	// each other.
	committeeWarmupDefault = 3 * time.Second
)

// rootCommittee is the keeper of one root's committee connections.
type rootCommittee struct {
	epoch   uint64
	member  bool
	members []peer.ID // the others of the committee
	keeper  *network.MemberProtector
}

// committeePeers is the committee of tb other than self, and whether self is in it.
func committeePeers(tb *types.RootTrustBaseV1, self peer.ID) ([]peer.ID, bool) {
	var out []peer.ID
	member := false
	for _, n := range tb.RootNodes {
		if n == nil {
			continue
		}
		id, err := peer.Decode(n.NodeID)
		if err != nil {
			continue
		}
		if id == self {
			member = true
			continue
		}
		out = append(out, id)
	}
	return out, member
}

// keepRootCommittee starts keeping the committee of tb (the installed epoch's) connected until ctx ends, and waits up to warmup for every
// other member to be connected. It returns the keeper for the status endpoint; a non-member keeps nothing.
func keepRootCommittee(ctx context.Context, log *slog.Logger, host *network.Peer, tb *types.RootTrustBaseV1, warmup time.Duration) *rootCommittee {
	members, member := committeePeers(tb, host.ID())
	c := &rootCommittee{epoch: tb.Epoch, member: member, members: members}
	if !member {
		return c
	}
	c.keeper = host.NewMemberProtector("root-committee")
	c.keeper.Set(ctx, members)
	go c.keeper.Maintain(ctx, committeeKeep)
	start := time.Now()
	deadline := time.NewTimer(warmup)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(c.keeper.Disconnected()) != 0 {
		select {
		case <-ctx.Done():
			return c
		case <-deadline.C:
			log.Warn("starting consensus with root committee members unreachable (#1082): their rounds may time out until they connect",
				"epoch", tb.Epoch, "missing", peerStrings(c.keeper.Disconnected()), "waited", time.Since(start))
			return c
		case <-tick.C:
		}
	}
	log.Info("root committee connected", "epoch", tb.Epoch, "members", len(members)+1, "waited", time.Since(start))
	return c
}

// rootCommitteeStatus is the status endpoint's answer: the installed epoch, whether this root is in its committee, and which other members
// it is connected to now. A joiner's readiness is that it reports no member missing.
type rootCommitteeStatus struct {
	Epoch     uint64   `json:"epoch"`
	Member    bool     `json:"member"`
	Connected []string `json:"connected"`
	Missing   []string `json:"missing"`
}

func (c *rootCommittee) status() rootCommitteeStatus {
	out := rootCommitteeStatus{Epoch: c.epoch, Member: c.member, Connected: []string{}, Missing: []string{}}
	if c.keeper == nil {
		return out
	}
	missing := c.keeper.Disconnected()
	for _, id := range c.members {
		if slices.Contains(missing, id) {
			out.Missing = append(out.Missing, id.String())
		} else {
			out.Connected = append(out.Connected, id.String())
		}
	}
	return out
}

func peerStrings(ids []peer.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	slices.Sort(out)
	return out
}
