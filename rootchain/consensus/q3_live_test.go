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

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// q3Live is the live cluster of the activated weighted epoch: the four validators of a real coupled Q3 activation (6,1,1,1, W=9,
// Q=7, scheme 2), each with durable stores (fsync on), the install journal and the verified history, running their real manager
// loops over the skewed network of #401 with the weighted leader policy of #403 activated for the epoch. Delivery is lossless and
// ordered; the firewall drops everything from and to an offline node. Every scheme 2 vote and timeout that is delivered is recorded
// by its signed statement, so that two different statements of one author for one round are visible.
type q3Live struct {
	t        *testing.T
	f        *q3fixture.Fixture
	net      *skewedNet
	replicas []*q3Replica // heavy first
	cfg      votesig.Config
	offline  sync.Map // peer.ID -> struct{}
	// cutOn is the author whose next delivered epoch-2 timeout is lost and whose node crashes with it: the timeout was signed and
	// recorded by the safety module, and never left the node.
	cutOn atomic.Value // string

	mu       sync.Mutex
	observed map[observedKey]map[string]struct{}
	lost     map[observedKey]string // the statement of a message the crash swallowed
	lostSig  map[observedKey][]byte // and its signature
	cancel   map[int]context.CancelFunc
	done     map[int]chan error
}

func newQ3Live(t *testing.T) *q3Live {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	c := &q3Live{t: t, f: f, net: newSkewedNet(t), observed: map[observedKey]map[string]struct{}{}, lost: map[observedKey]string{}, lostSig: map[observedKey][]byte{},
		cancel: map[int]context.CancelFunc{}, done: map[int]chan error{}}
	c.cfg = votesig.Config{Scheme: votesig.SchemeDomainBound, Network: q3fixture.Network, Genesis: f.Genesis}
	for _, n := range f.NewNodes {
		r := newQ3Replica(t, f, n)
		r.link, r.durable = c.net.connect(n.PeerConf.ID), true
		r.mustOpen(true)
		t.Cleanup(r.close)
		c.replicas = append(c.replicas, r)
		c.offline.Store(n.PeerConf.ID, struct{}{}) // nobody is online until started
	}
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if _, off := c.offline.Load(from); off {
			return true
		}
		if _, off := c.offline.Load(to); off {
			return true
		}
		if tm, ok := msg.(*abdrc.TimeoutMsg); ok && tm.Timeout.Epoch == 2 {
			if author, _ := c.cutOn.Load().(string); author != "" && author == tm.Author {
				c.lose(tm) // the crash is pinned to this timeout: it is the node's last message, and it is never delivered
				c.offline.Store(from, struct{}{})
				c.cutOn.Store("")
				return true
			}
		}
		c.observe(msg)
		return false
	}
	t.Cleanup(c.stopAll)
	return c
}

func (c *q3Live) statement(msg any) (observedKey, string, bool) {
	switch m := msg.(type) {
	case *abdrc.VoteMsg:
		if m.VoteInfo == nil || m.VoteInfo.Epoch != 2 || m.Scheme != votesig.SchemeDomainBound {
			return observedKey{}, "", false
		}
		pv, _, _, err := rctypes.DomainBoundStatement(c.cfg, m.VoteInfo, m.LedgerCommitInfo, len(m.SealSignature) != 0)
		require.NoError(c.t, err)
		return observedKey{m.Author, m.VoteInfo.RoundNumber, "vote"}, string(pv), true
	case *abdrc.TimeoutMsg:
		if m.Timeout == nil || m.Timeout.Epoch != 2 || m.Scheme != votesig.SchemeDomainBound {
			return observedKey{}, "", false
		}
		pre, err := m.Preimage(c.cfg)
		require.NoError(c.t, err)
		return observedKey{m.Author, m.Timeout.Round, "timeout"}, string(pre), true
	}
	return observedKey{}, "", false
}

func (c *q3Live) observe(msg any) {
	key, statement, ok := c.statement(msg)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observed[key] == nil {
		c.observed[key] = map[string]struct{}{}
	}
	c.observed[key][statement] = struct{}{}
}

func (c *q3Live) lose(msg *abdrc.TimeoutMsg) {
	key, statement, _ := c.statement(msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lost[key] = statement
	c.lostSig[key] = bytes.Clone(msg.Signature)
}

func (c *q3Live) doubleSigned() []observedKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	var keys []observedKey
	for k, statements := range c.observed {
		if len(statements) != 1 {
			keys = append(keys, k)
		}
	}
	return keys
}

func (c *q3Live) lostStatement() (observedKey, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, s := range c.lost {
		return k, s, true
	}
	return observedKey{}, "", false
}

func (c *q3Live) delivered(key observedKey) map[string]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]struct{}{}
	for s := range c.observed[key] {
		out[s] = struct{}{}
	}
	return out
}

// start runs the manager of replica i; the node is online from now on.
func (c *q3Live) start(i int) {
	c.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cm := c.replicas[i].manager
	c.mu.Lock()
	c.cancel[i], c.done[i] = cancel, done
	c.mu.Unlock()
	c.offline.Delete(c.replicas[i].id())
	go func() { done <- cm.Run(ctx) }()
}

// stop takes the node off the network and ends its loop. Whatever it had not persisted is gone once its stores are released.
func (c *q3Live) stop(i int) {
	c.offline.Store(c.replicas[i].id(), struct{}{})
	c.mu.Lock()
	cancel, done := c.cancel[i], c.done[i]
	delete(c.cancel, i)
	delete(c.done, i)
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(c.t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		c.t.Fatalf("node %d did not stop", i)
	}
}

func (c *q3Live) stopAll() {
	for i := range c.replicas {
		c.stop(i)
	}
}

// restart is a process restart: the loop ends, the stores are released and opened again from disk (fsync on), the verified history
// is rebuilt from the journal and every installation checked, and a new manager runs over them.
func (c *q3Live) restart(i int) {
	c.t.Helper()
	c.stop(i)
	r := c.replicas[i]
	r.close()
	r.mustOpen(true)
	require.NoError(c.t, r.rt.Recover(context.Background()))
	c.start(i)
}

func (c *q3Live) committedRound(i int) uint64 {
	m := c.replicas[i].manager
	state, err := m.blockStore.GetState()
	if err != nil {
		return 0
	}
	return state.CommittedHead.Block.Round
}

func (c *q3Live) highQCRound(i int) uint64 {
	return c.replicas[i].manager.blockStore.GetHighQc().GetRound()
}

// activate installs the activation in every node and restarts every node, so that the managers are built over the installed epoch
// with the weighted leader policy the replicas activate at start (the manager takes its selector from the epoch's policy).
func (c *q3Live) activate() {
	c.t.Helper()
	ctx := context.Background()
	for _, r := range c.replicas {
		require.NoError(c.t, r.rt.Recover(ctx))
		require.NoError(c.t, r.rt.Activate(ctx, r.bundle()))
	}
	for i, r := range c.replicas {
		r.close()
		r.mustOpen(true)
		require.NoError(c.t, r.rt.Recover(ctx))
		_ = i
	}
}

// Live, in the activated weighted epoch: the heavy validator signs a timeout that never leaves it and crashes, the three others are
// below the quorum, and the restarted heavy validator rebroadcasts exactly the statement it recorded, so that the TC forms (verified
// under scheme 2 and the epoch's weights) and commits resume. Before the fix of #398 the restarted node built a fresh timeout from the
// current HighQC, which the recorded decision refuses, and the cluster stayed at weight 2 of 7 for good.
func TestLiveWeightedEpochHeavyValidatorRestartRebroadcastsItsRecordedTimeout(t *testing.T) {
	c := newQ3Live(t)
	c.activate()
	heavy, light1 := c.replicas[0], c.replicas[1]
	for i := range c.replicas {
		c.start(i)
	}
	anchorSlot := heavy.manager.epochAnchor.Slot
	require.Eventually(t, func() bool {
		for i := range c.replicas {
			if c.committedRound(i) < anchorSlot+4 {
				return false
			}
		}
		return true
	}, 60*time.Second, 50*time.Millisecond, "the four validators commit live in the activated epoch")

	t.Run("the weighted policy and scheme 2 are in force", func(t *testing.T) {
		qc := heavy.manager.blockStore.GetHighQc()
		require.EqualValues(t, 2, qc.VoteInfo.Epoch)
		require.EqualValues(t, votesig.SchemeDomainBound, qc.Scheme)
		require.NoError(t, qc.VerifyWith(heavy.trust))
		led := map[string]int{}
		for r := uint64(100); r < 109; r++ { // one full cycle of W=9
			l, err := heavy.manager.leaderSelector.GetLeaderForRound(r)
			require.NoError(t, err)
			led[l.String()]++
		}
		require.Equal(t, 6, led[heavy.id().String()], "the heavy validator leads its weight's share of a cycle")
	})

	// a light validator goes down: the rounds it leads time out, the heavy validator times out with the two others
	c.stop(1)
	c.cutOn.Store(heavy.id().String())
	require.Eventually(t, func() bool { _, off := c.offline.Load(heavy.id()); return off }, 60*time.Second, 20*time.Millisecond,
		"the heavy validator's first timeout of the epoch was signed, recorded and never left it")
	key, original, ok := c.lostStatement()
	require.True(t, ok)
	require.Equal(t, heavy.id().String(), key.author)
	c.stop(0) // the crash

	t.Run("without the heavy validator the others are below the quorum and nothing moves", func(t *testing.T) {
		committed, high := c.committedRound(2), c.highQCRound(2)
		time.Sleep(3 * time.Second) // more than two local timeouts of the cluster
		require.Equal(t, committed, c.committedRound(2))
		require.Equal(t, high, c.highQCRound(2), "weight 2 of 7 forms no QC and no TC")
	})

	committed := c.committedRound(2)
	c.restart(0)

	t.Run("the restarted heavy validator rebroadcasts the original statement and the TC forms", func(t *testing.T) {
		require.Eventually(t, func() bool { _, seen := c.delivered(key)[original]; return seen }, 60*time.Second, 50*time.Millisecond,
			"the recorded timeout is delivered after the restart, byte for byte the statement that was lost")
		require.Len(t, c.delivered(key), 1, "no other statement of the author for that round was ever delivered")
		require.Eventually(t, func() bool {
			return c.highQCRound(2) > key.round || c.replicas[2].manager.pacemaker.GetCurrentRound() > key.round
		}, 60*time.Second, 50*time.Millisecond,
			"the TC formed and the round moved on")
	})

	t.Run("the TC is scheme 2, verified under the epoch's weights, and carries the heavy validator's recorded signature", func(t *testing.T) {
		var tc *rctypes.TimeoutCert
		require.Eventually(t, func() bool {
			got, err := c.replicas[2].manager.blockStore.GetLastTC()
			if err == nil && got != nil && got.Timeout.Round == key.round {
				tc = got
			}
			return tc != nil
		}, 60*time.Second, 5*time.Millisecond, "the TC of the stuck round was read from a light validator's store")
		require.EqualValues(t, votesig.SchemeDomainBound, tc.Scheme)
		require.NoError(t, tc.Verify(c.replicas[2].trust))
		epoch2, err := c.replicas[2].trust.GetByEpoch(2)
		require.NoError(t, err)
		var weight uint64
		for id := range tc.Signatures {
			for _, n := range epoch2.RootNodes {
				if n.NodeID == id {
					weight += n.Stake
				}
			}
		}
		require.GreaterOrEqual(t, weight, uint64(7), "the TC is a weighted quorum of 7 of 9")
		vote := tc.Signatures[heavy.id().String()]
		require.NotNil(t, vote, "the heavy validator's timeout is in the TC: the others alone are weight 2")
		c.mu.Lock()
		want := c.lostSig[key]
		c.mu.Unlock()
		require.Equal(t, want, []byte(vote.Signature), "it is the signature of the timeout that was lost, not a new one")
	})

	t.Run("commits resume and no author signed two statements for one round", func(t *testing.T) {
		require.Eventually(t, func() bool { return c.committedRound(2) >= committed+3 }, 90*time.Second, 100*time.Millisecond)
		require.Empty(t, c.doubleSigned())
	})
	_ = light1
}
