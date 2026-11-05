package consensus

import (
	"bytes"
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #886 gate 7, the shape that reaches the design's second covered stretch: exactly one certified block after the stop, the repeat, so no committed
// record names the live set before the first live run. X times out with the others, which the rounds need, and until past the covered rounds its
// votes count only for the last live pair's block. Three outcomes, by id order and phase, all seen: the fresh request certifies at once, or at the
// end of the stretch (about 18 rounds), or the stretch ends with no three live leaders in a row and it waits for the next recovery run that is not
// the dead member's (about 511 rounds). So stage two's limit is the same traversal as stage one's, not the design's D+1+4: see #886. Most of those
// rounds pass at certificate speed, so at production timing the cost is in tau, not in timeouts. Takes 5 to 25 minutes: set BFT_GATE7_STRETCH=1.
func TestRollingRestartOneCertifiedBlockAfterTheStop(t *testing.T) {
	if os.Getenv("BFT_GATE7_STRETCH") == "" {
		t.Skip("set BFT_GATE7_STRETCH=1: minutes of rounds at T = 2 s, and the outcome depends on the id order")
	}
	t.Parallel()
	q4Slot(t)
	const hold = 1
	c := newPhaseLockLive(t, 2*time.Second)
	x, d := "c", "b"
	var withhold atomic.Bool
	const lagOf = 20 // D at four members: past it the live run needs X's votes
	var target atomic.Uint64
	var repeatMu sync.Mutex
	repeats := map[uint64]bool{} // every round the filter saw a T2 repeat proposed in, whichever block ends up certified
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if withhold.Load() {
			// X's votes count for the target's block alone until the live run, past the covered rounds: the run's own votes need X
			if v, ok := msg.(*abdrc.VoteMsg); ok && from == c.id(x) && v.VoteInfo.RoundNumber != target.Load() && v.VoteInfo.RoundNumber <= target.Load()+lagOf {
				return true
			}
			if p, ok := msg.(*abdrc.ProposalMsg); ok && p.Block.Payload != nil {
				for _, req := range p.Block.Payload.Requests {
					if req.CertReason == drctypes.T2Timeout {
						repeatMu.Lock()
						repeats[p.Block.Round] = true
						repeatMu.Unlock()
					}
				}
			}
		}
		return base(from, to, msg)
	}
	first := c.except(x)
	c.start(first...)
	n := uint64(len(c.nodes))
	lag := 4*n + 4
	c.warm(lag+2, first...)
	survivors := c.except(x, d)
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	ingress := survivors[0]
	lastUC := func() uint64 {
		si := m(ingress).blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		if si == nil || si.LastCR == nil {
			return 0
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
	}
	target.Store(1 << 62)
	withhold.Store(true)
	c.stop(d)
	head, _, _ := m(ingress).blockStore.LeaderHead()
	leaderOf := func(round uint64) peer.ID {
		l, err := m(ingress).leaderSelector.GetLeaderForRound(round)
		if err != nil {
			return ""
		}
		return l
	}
	// the last pair of live leaders while the leaders are known
	var r uint64
	for at := head + lag - 1; at > head; at-- {
		a, b := leaderOf(at), leaderOf(at+1)
		if a != "" && b != "" && a != c.id(d) && b != c.id(d) && a != c.id(x) && b != c.id(x) {
			r = at
			break
		}
	}
	require.NotZero(t, r, "a live pair among the covered rounds")
	target.Store(r)
	c.start(x)
	start, startUC := c.state(ingress).Round, lastUC()
	t.Logf("head %d, covered to %d, target %d, start %d", head, head+lag, r, start)
	require.Eventually(t, func() bool { return c.state(ingress).HighQC == r }, q4bDeadline, 5*time.Millisecond, "the block of round %d is certified, and no other", r)
	repeatMu.Lock()
	certifiedRepeat := repeats[r]
	repeatMu.Unlock()
	require.True(t, certifiedRepeat, "the certified block of round %d is a repeat", r)
	require.EqualValues(t, startUC, lastUC())
	hash := bytes.Repeat([]byte{0x81}, 32)
	held := phaseLockProof(t, c, c.nodes[c.idx(ingress)].r, hash)
	require.NotNil(t, held)
	require.NoError(t, m(ingress).RequestCertification(context.Background(), *held))
	t.Logf("round %d certified with its repeat, request held at round %d", r, c.state(ingress).Round)

	stage1 := start + rollingRestartRounds(n)
	began := time.Now()
	for lastUC() == startUC {
		require.LessOrEqual(t, c.state(ingress).Round, stage1, "stage one")
		time.Sleep(5 * time.Millisecond)
	}
	committed := c.state(ingress).Round
	require.False(t, c.certifiedHash(ingress, hash))
	t.Logf("repeat committed by round %d, %d after start, limit %d, %s", committed, committed-start, stage1-start, time.Since(began).Round(time.Second))
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, ok := c.chains[c.idx(ingress)][r]
		return ok
	}, 10*time.Second, 5*time.Millisecond, "the repeat of round %d is in the committed chain", r)
	view, enabled, err := m(ingress).RequestView(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.True(t, enabled)
	require.NotEqual(t, held.Requests[0].InputRecord.RoundNumber, view.ExpectedTR().Round, "the repeat moved the expected shard round: the held proof is stale")
	var deadSlots, xSlots []uint64
	for at := committed; at < committed+lag+leader.RecoveryRun; at++ {
		switch leaderOf(at) {
		case c.id(d):
			deadSlots = append(deadSlots, at)
		case c.id(x):
			xSlots = append(xSlots, at)
		}
	}
	t.Logf("in the %d rounds from the commit, D leads %v and X leads %v", lag+leader.RecoveryRun, deadSlots, xSlots)

	for c.state(ingress).Round < committed+hold {
		time.Sleep(5 * time.Millisecond)
	}
	began = time.Now()
	sends, sentUnder, freshAt, stage2 := 0, uint64(0), uint64(0), uint64(0)
	for !c.certifiedHash(ingress, hash) {
		if under := lastUC(); sends == 0 || under != sentUnder {
			if proof := phaseLockProof(t, c, c.nodes[c.idx(ingress)].r, hash); proof != nil && m(ingress).RequestCertification(context.Background(), *proof) == nil {
				if sends == 0 {
					freshAt = c.state(ingress).Round
					stage2 = freshAt + rollingRestartRounds(n)
				}
				sends++
				sentUnder = under
			}
		}
		if stage2 != 0 {
			require.LessOrEqual(t, c.state(ingress).Round, stage2, "stage two: not certified within the stretch, a dead run and a live run")
		}
		require.LessOrEqual(t, c.state(ingress).Round, committed+hold+rollingRestartRounds(n), "stage two: the fresh request was never accepted")
		time.Sleep(5 * time.Millisecond)
	}
	end := c.state(ingress).Round
	t.Logf("fresh request at round %d, certified by %d: %d rounds, limit %d, %s, %d sends, %d rounds after start", freshAt, end, end-freshAt, stage2-freshAt, time.Since(began).Round(time.Second), sends, end-start)
	for _, name := range survivors {
		require.False(t, m(name).recovery.InRecovery(), "%s entered state recovery with no missing certified state", name)
	}
}
