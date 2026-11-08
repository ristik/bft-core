package consensus

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// withoutHistory is a node's own selector, which from a round on answers HistoryUnavailable, as a node does whose committed state does not
// cover the cutoffs the others' states cover. It stands in for that state: the manager is what these tests judge, not how a node falls behind.
// Lifted (from = 0), it answers as the real selector again.
type withoutHistory struct {
	Leader
	from atomic.Uint64
}

func (w *withoutHistory) GetLeaderForRound(round uint64) (peer.ID, error) {
	if from := w.from.Load(); from != 0 && round >= from {
		return "", drctypes.ErrHistoryUnavailable
	}
	return w.Leader.GetLeaderForRound(round)
}

func (w *withoutHistory) RecoveryRunStart(round uint64) bool {
	r, ok := w.Leader.(interface{ RecoveryRunStart(uint64) bool })
	return ok && r.RecoveryRunStart(round)
}

// installWithoutHistory wraps the named nodes' selectors; call it before the nodes start.
func installWithoutHistory(c *q4bLive, names ...string) map[string]*withoutHistory {
	out := map[string]*withoutHistory{}
	for _, name := range names {
		m := c.nodes[c.idx(name)].r.manager
		w := &withoutHistory{Leader: m.leaderSelector}
		m.leaderSelector = w
		out[name] = w
	}
	return out
}

// timeoutTally counts the timeout votes each author sends, per round, from the moment it is armed.
type timeoutTally struct {
	armed  atomic.Bool
	mu     sync.Mutex
	rounds map[string]map[uint64]bool
}

func (x *timeoutTally) install(c *q4bLive) {
	x.rounds = map[string]map[uint64]bool{}
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if tm, ok := msg.(*abdrc.TimeoutMsg); ok && x.armed.Load() {
			x.mu.Lock()
			if x.rounds[from.String()] == nil {
				x.rounds[from.String()] = map[uint64]bool{}
			}
			x.rounds[from.String()][tm.Timeout.Round] = true
			x.mu.Unlock()
		}
		return base(from, to, msg)
	}
}

func (x *timeoutTally) count(author peer.ID) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.rounds[author.String()])
}

// requireNoFault: whatever recovery a node did, it latched no frontier fault and still serves its shard info.
func requireNoFault(t *testing.T, c *q4bLive, name string) {
	t.Helper()
	m := c.nodes[c.idx(name)].r.manager
	require.True(t, m.frontier == nil || !m.frontier.faulted.Load(), "%s: no frontier fault", name)
	_, err := m.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err, "%s serves its shard info", name)
}

// requireServing checks B2 at a node whose only trouble is missing history: no state recovery, no frontier fault, its APIs usable, and a
// request taken and retained.
func requireServing(t *testing.T, c *q4bLive, name string, hash []byte) {
	t.Helper()
	m := c.nodes[c.idx(name)].r.manager
	require.False(t, m.recovery.InRecovery(), "%s: missing history alone is not state recovery", name)
	requireNoFault(t, c, name)
	_, enabled, err := m.RequestView(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err, "%s serves its request view", name)
	require.True(t, enabled)
	proof := phaseLockProof(t, c, c.nodes[c.idx(name)].r, hash)
	require.NotNil(t, proof)
	require.NoError(t, m.RequestCertification(context.Background(), *proof), "%s takes a certification request", name)
}

// #886 gate 4, a minority without history: one of four equal members cannot name any leader from a round on, while the others' committed state
// can. Three phases:
//  1. it hears nothing from the others (every message to it is dropped), so missing history is all it has: it times its round out at once (B1),
//     enters no state recovery, latches no fault and keeps serving (B2); a request it takes is retained, not forwarded (it knows no next leader)
//     and not dropped. Its timeouts alone weigh no more than f: the others go on committing by QC.
//  2. it hears them again, still without history: their proposals carry QCs of blocks it never executed, authenticated evidence of missing
//     certified state, so it may enter real state recovery (the design's "others supply a QC/state-recovery trigger"). It still times every
//     round out at once, and still forces no TC: the others commit on.
//  3. its history is back: it names the others' leaders, votes and commits with them, and the request it retained certifies.
func TestMinorityWithoutHistoryFollowsTheQuorum(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	const minority = "c"
	gap := installWithoutHistory(c, minority)[minority]
	var tally timeoutTally
	tally.install(c)
	var deaf atomic.Bool
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if deaf.Load() && to == c.id(minority) {
			return true // dropped
		}
		return base(from, to, msg)
	}
	c.start(c.all()...)
	lag := uint64(4*len(c.nodes) + 4)
	c.warm(lag+2, c.all()...)
	quorum := c.except(minority)
	watch := quorum[0]
	const window = 40

	// 1: missing history and nothing else
	deaf.Store(true)
	mark := c.mark()
	from := c.state(watch).Round
	tally.armed.Store(true)
	gap.from.Store(c.state(minority).Round)
	require.Eventually(t, func() bool { return c.state(watch).Round >= from+window }, 3*q4bDeadline, 20*time.Millisecond, "the rounds go on")
	_, err := c.nodes[c.idx(minority)].r.manager.leaderSelector.GetLeaderForRound(c.state(minority).Round)
	require.ErrorIs(t, err, drctypes.ErrHistoryUnavailable, "premise: the minority has no leader for its round")
	require.Positive(t, tally.count(c.id(minority)), "B1: the minority times its round out")
	commits := len(c.commitsSince(c.idx(watch), mark))
	t.Logf("phase 1: %d rounds, %d commits at %s; the minority timed out %d rounds", c.state(watch).Round-from, commits, watch, tally.count(c.id(minority)))
	require.GreaterOrEqual(t, commits, window/4, "the quorum commits on, by QC")
	hash := bytes.Repeat([]byte{0x83}, 32)
	requireServing(t, c, minority, hash)
	held := c.state(watch).Round
	require.Eventually(t, func() bool { return c.state(watch).Round >= held+8 }, q4bDeadline, 20*time.Millisecond)
	require.False(t, c.certifiedHash(watch, hash), "with no next leader known, the minority forwards nothing")
	require.False(t, c.nodes[c.idx(minority)].r.manager.recovery.InRecovery(), "still no state recovery")

	// 2: the others' QCs reach it, still without history
	deaf.Store(false)
	mark = c.mark()
	from = c.state(watch).Round
	before := tally.count(c.id(minority))
	require.Eventually(t, func() bool { return c.state(watch).Round >= from+window }, 3*q4bDeadline, 20*time.Millisecond, "the rounds go on")
	commits = len(c.commitsSince(c.idx(watch), mark))
	timeouts := tally.count(c.id(minority)) - before
	t.Logf("phase 2: %d rounds, %d commits at %s; the minority timed out %d more rounds (the others: %d, %d, %d in all); in recovery now: %v", c.state(watch).Round-from, commits, watch,
		timeouts, tally.count(c.id(quorum[0])), tally.count(c.id(quorum[1])), tally.count(c.id(quorum[2])), c.nodes[c.idx(minority)].r.manager.recovery.InRecovery())
	require.GreaterOrEqual(t, timeouts, window/4, "B1: it times out the rounds it now hears of")
	// a lone timeout weighs 1 of 4 (f = 1): with it forcing a TC every round would end by TC and nothing would commit
	require.GreaterOrEqual(t, commits, window/4, "the quorum commits on, by QC")
	requireNoFault(t, c, minority)

	// 3: history back
	gap.from.Store(0)
	back := c.mark()
	require.Eventually(t, func() bool { return len(c.commitsSince(c.idx(minority), back)) >= 3 }, q4bDeadline, 20*time.Millisecond, "the minority commits again")
	require.Eventually(t, func() bool { return c.certifiedHash(watch, hash) }, q4bDeadline, 10*time.Millisecond, "the request the minority retained certifies")
	r := c.state(watch).Round + 1
	mine, err := c.nodes[c.idx(minority)].r.manager.leaderSelector.GetLeaderForRound(r)
	require.NoError(t, err)
	theirs, err := c.nodes[c.idx(watch)].r.manager.leaderSelector.GetLeaderForRound(r)
	require.NoError(t, err)
	require.Equal(t, theirs, mine)
	c.requireChainsAgree(c.all()...)
	requireNoFault(t, c, minority)
	c.stopAll()
}

// #886 gate 4, weighted timeout escalation in a live (3,2,2,2,2) committee, quorum 8 and f = 3, with the B1 timeouts of members without history:
//   - weight 3 (the heavy member) without history is at most f: the others, weight 8, still commit by QC, and its timeouts do not move them to
//     the timeout state (it may recover state from their QCs, which is authenticated evidence, not its missing history);
//   - weight 5 (the heavy member and one light) is more than f: no QC is possible (6 < 8), and their immediate timeouts escalate the others,
//     which time out at once instead of after T, so the rounds advance by TC at certificate speed with nothing committed.
//
// Counting votes instead of weight would get both wrong: one member is at most f by count, and two of five are more. T is 5 s, so a round at
// certificate speed is far from a round that waits for the timer even on a loaded machine.
func TestWeightedTimeoutEscalationOfMembersWithoutHistory(t *testing.T) {
	const timeout = 5 * time.Second
	weights := []uint64{3, 2, 2, 2, 2}
	names := []string{"H", "a", "b", "c", "d"}
	for _, tc := range []struct {
		name    string
		without []string
	}{{"weight 3, at most f", []string{"H"}}, {"weight 5, more than f", []string{"H", "a"}}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			q4Slot(t)
			c := newEqualLiveOptions(t, timeout, q3fixture.Options{Weights: weights}, names...)
			gaps := installWithoutHistory(c, tc.without...)
			c.start(c.all()...)
			lag := uint64(4*len(c.nodes) + 4)
			c.warm(lag+2, c.all()...)
			rest := c.except(tc.without...)
			watch := rest[0]
			for _, g := range gaps {
				g.from.Store(c.state(watch).Round)
			}
			// a commit already under way when the history went is not this window's: start two rounds later
			settle := c.state(watch).Round + 2
			require.Eventually(t, func() bool { return c.state(watch).Round >= settle }, q4bDeadline, 5*time.Millisecond)
			mark := c.mark()
			head := c.state(watch).Committed
			from := c.state(watch).Round
			const window = 30
			began := time.Now()
			require.Eventually(t, func() bool { return c.state(watch).Round >= from+window }, 3*q4bDeadline, 5*time.Millisecond, "the rounds go on")
			elapsed := time.Since(began)
			commits := len(c.commitsSince(c.idx(watch), mark))
			t.Logf("%s without history: %d rounds in %s (%s a round), %d commits", tc.without, window, elapsed.Round(time.Millisecond), elapsed/window, commits)
			if c.weight(tc.without...) <= 3 {
				require.GreaterOrEqual(t, commits, window/4, "weight at most f: the rest commit by QC")
			} else {
				require.Less(t, elapsed, window*timeout, "weight over f escalates: the rounds end at certificate speed, not after T each")
				require.EqualValues(t, head, c.state(watch).Committed, "and no QC: nothing commits")
			}
			if c.weight(tc.without...) <= 3 {
				requireNoFault(t, c, tc.without[0]) // it executes none of the others' blocks, and their QCs are evidence: it may recover
			} else {
				requireServing(t, c, tc.without[0], bytes.Repeat([]byte{0x84}, 32)) // nothing committed: missing history is all there is
			}
			for _, g := range gaps {
				g.from.Store(0)
			}
			back := c.mark()
			require.Eventually(t, func() bool { return len(c.commitsSince(c.idx(watch), back)) >= 3 }, q4bDeadline, 20*time.Millisecond, "with history back, commits resume")
			c.requireChainsAgree(c.all()...)
			c.stopAll()
		})
	}
}
