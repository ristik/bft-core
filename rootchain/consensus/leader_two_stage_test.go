package consensus

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
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
// votes count only for the last live pair's block. Outcomes, by id order and phase (TestTwoStageAllowanceOverEveryOrderAndPhase enumerates them): it certifies soon, or at the
// end of the stretch (about 18 rounds), or the stretch ends with no three live leaders in a row and it waits for the next recovery run that is not
// the dead member's (about 255 or 511 rounds). So stage two's limit is the same traversal as stage one's, not the design's D+1+4: see #886. Most of those
// rounds pass at certificate speed, so at production timing the cost is in tau, not in timeouts. Takes 5 to 25 minutes: set BFT_GATE7_STRETCH=1.
func TestRollingRestartOneCertifiedBlockAfterTheStop(t *testing.T) {
	if os.Getenv("BFT_GATE7_STRETCH") == "" {
		t.Skip("set BFT_GATE7_STRETCH=1: minutes of rounds at T = 2 s, and the outcome depends on the id order")
	}
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	lag := 4*uint64(len(c.nodes)) + 4
	// R = 8 rounds: one round lands in the run's own tail, and a real shard is not that fast
	twoStageRun(t, c, "c", "b", lag+2, 8)
}

// The outcome no short warm-up reaches: the first live run commits the repeat, and stage two then waits about 255 rounds for the next recovery run. With X
// first and D second in id order, the enumeration gives 255 rounds at R = 1 for a head well inside the fourth period (232 of its 256 positions), and the head's
// exact position does not matter. Takes about 37 minutes, most of it the warm-up: set BFT_GATE7_WARMED=1.
func TestRollingRestartStageTwoWaitsForTheNextRun(t *testing.T) {
	if os.Getenv("BFT_GATE7_WARMED") == "" {
		t.Skip("set BFT_GATE7_WARMED=1: over 900 warm rounds and then the two stages")
	}
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	lag := 4*uint64(len(c.nodes)) + 4
	names := c.all()
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(c.id(a).String(), c.id(b).String()) }) // the selector's member order
	stageTwo := twoStageRun(t, c, names[0], names[1], 1+lag+3*leader.RecoverySpacing+128, 1)
	require.GreaterOrEqual(t, stageTwo, uint64(254), "the enumeration's outcome for this order and head is 255 rounds")
	require.LessOrEqual(t, stageTwo, uint64(256), "the enumeration's outcome for this order and head is 255 rounds")
}

// twoStageRun warms the cluster with X down to warm rounds past the anchor, then runs the shape; hold is R in root rounds after the commit. It returns stage two's rounds.
func twoStageRun(t *testing.T, c *q4bLive, x, d string, warm, hold uint64) uint64 {
	t.Helper()
	const noDeadRun, withDeadRun, joint = 281, 541, 822
	n := uint64(len(c.nodes))
	lag := 4*n + 4
	var withhold atomic.Bool
	var target atomic.Uint64
	var repeatMu sync.Mutex
	repeats := map[uint64]bool{} // every round the filter saw a T2 repeat proposed in, whichever block ends up certified
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if withhold.Load() {
			// X's votes count for the target's block alone until the live run, past the covered rounds: the run's own votes need X
			if v, ok := msg.(*abdrc.VoteMsg); ok && from == c.id(x) && v.VoteInfo.RoundNumber != target.Load() && v.VoteInfo.RoundNumber <= target.Load()+lag {
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
	anchor := c.nodes[0].r.manager.epochAnchor.Slot
	require.Eventually(t, func() bool {
		for _, name := range first {
			if c.committedRound(name) < anchor+warm {
				return false
			}
		}
		return true
	}, q4bDeadline+time.Duration(warm)*2*time.Second, 50*time.Millisecond, "the cluster commits live in the activated epoch")
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
	// the round trace of the design's gate 7, from the ingress's view: unknown leader, or a known one that got a QC, or a known one that did not, which is a full timer
	type roundClass struct{ unknown, certified, timer, unseen int }
	var classes [3]roundClass
	stage, seenTo := 0, c.state(ingress).Round
	leaderKnown := map[uint64]bool{}
	sample := func() {
		st := c.state(ingress)
		if _, seen := leaderKnown[st.Round]; !seen {
			leaderKnown[st.Round] = leaderOf(st.Round) != ""
		}
		for ; seenTo < st.Round; seenTo++ {
			known, seen := leaderKnown[seenTo]
			switch {
			case !seen:
				classes[stage].unseen++
			case !known:
				classes[stage].unknown++
			case st.HighQC >= seenTo:
				classes[stage].certified++
			default:
				classes[stage].timer++
			}
		}
	}
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
	stage = 1
	for lastUC() == startUC {
		sample()
		require.LessOrEqual(t, c.state(ingress).Round, stage1, "stage one")
		time.Sleep(5 * time.Millisecond)
	}
	committed := c.state(ingress).Round
	require.False(t, c.certifiedHash(ingress, hash))
	t.Logf("repeat committed by round %d, %d after start, limit %d, %s", committed, committed-start, stage1-start, time.Since(began).Round(time.Second))
	// exactly one certified block after the stop: the committed chain has r and then only the run, past the covered rounds
	var after []uint64
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		after = after[:0]
		for round := range c.chains[c.idx(ingress)] {
			if round > start { // a block up to start was certified before the stop, and only commits with the run
				after = append(after, round)
			}
		}
		slices.Sort(after)
		return len(after) >= 2
	}, 10*time.Second, 5*time.Millisecond, "the run's commit reaches the chain")
	require.Equal(t, r, after[0], "the first committed block after the stop, of %v", after)
	require.Greater(t, after[1], head+lag, "no other certified block before the run, of %v", after)
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

	stage = 2
	for c.state(ingress).Round < committed+hold {
		sample()
		require.False(t, c.certifiedHash(ingress, hash), "certified with no fresh request: the held proof was not stale")
		time.Sleep(5 * time.Millisecond)
	}
	began = time.Now()
	sends, sentUnder, freshAt, stage2 := 0, uint64(0), uint64(0), uint64(0)
	for !c.certifiedHash(ingress, hash) {
		sample()
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
	selector, ok := m(ingress).leaderSelector.(*leader.EpochReputation)
	require.True(t, ok)
	// every recovery run on the way, its owner read from the selector, and the allocation: one stage has the dead run's allowance at most, the other the plain one
	deadIn := [3]int{}
	var runs []string
	for round := head + 1; round < end; round++ {
		if !selector.RecoveryRunStart(round) {
			continue
		}
		owner, ok := map[peer.ID]string{c.id(d): "D", c.id(x): "X"}[leaderOf(round)]
		if !ok {
			owner = "live"
		}
		runs = append(runs, fmt.Sprintf("%d:%s", round, owner))
		if owner == "D" {
			if round <= committed {
				deadIn[1]++
			} else {
				deadIn[2]++
			}
		}
	}
	stageOne, stageTwo := committed-start, end-freshAt
	limit := func(dead int) uint64 {
		if dead > 0 {
			return withDeadRun
		}
		return noDeadRun
	}
	t.Logf("fresh request at round %d after R=%d rounds, certified by %d: stage one %d rounds, stage two %d, total %d of %d, %s, %d sends", freshAt, hold, end, stageOne, stageTwo, stageOne+stageTwo, joint, time.Since(began).Round(time.Second), sends)
	t.Logf("recovery runs %v; rounds by class, stage one %+v, stage two %+v", runs, classes[1], classes[2])
	require.LessOrEqual(t, deadIn[1]+deadIn[2], 1, "a dead run in each stage: %v", runs)
	require.LessOrEqual(t, stageOne, limit(deadIn[1]), "stage one, runs %v", runs)
	require.LessOrEqual(t, stageTwo, limit(deadIn[2]), "stage two, runs %v", runs)
	require.LessOrEqual(t, stageOne+stageTwo, uint64(joint), "the joint allowance")
	for _, name := range survivors {
		require.False(t, m(name).recovery.InRecovery(), "%s entered state recovery with no missing certified state", name)
	}
	return stageTwo
}
