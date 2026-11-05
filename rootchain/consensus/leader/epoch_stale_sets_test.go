package leader

import (
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The rolling restart's two stages for committees whose stale set can lack a live triple with more than one member down (#886 gate 7, rev's seven/two and ten/three):
// b members are stopped and the b that were down return before any committed record names them, so the stale voters are the live set's n-2b plus the stopped b.
// Every placement of both sets, by the head's position. It takes no timing, and these counts are derived here: the design's 281/541/822 is for four roots, one down.
// One stage may pass d dead recovery runs: D+1 covered rounds, then a traversal per dead run and one to the live run, plus their slots.
func stageAllowance(lag uint64, dead int) uint64 {
	return lag + 1 + uint64(dead+1)*RecoverySpacing + 4*uint64(dead) + 4
}

// The two stages together: until the second live commit the window holds at most b+2 recovery runs, fewer than n in these committees, so no identity owns two and the stages
// share at most b dead runs. The design adopts this as N_joint, for adjacent stages only, with timely resubmission and no further invalidating repeat: 822, 1106 and 1390 rounds.
func jointAllowance(lag uint64, down int) uint64 {
	return 2*(lag+1) + uint64(down+2)*RecoverySpacing + 4*uint64(down) + 8
}

// twoStageWalk is the abstract chain of the two stages. leaderOf answers from the committed head as the selector does, -1 when the round's leader is unknown; commit records a committed block with the live voters.
type twoStageWalk struct {
	stage1, stage2       uint64
	dead1, dead2         int
	noLivePair, noCommit bool
}

func walkTwoStages(leaderOf func(uint64) int, commitOnly func(uint64), commitLive func(uint64), runStart func(uint64) bool, isDead, isReturner uint32, headAt, lag, resubmit, limit uint64) twoStageWalk {
	var w twoStageWalk
	member := func(r uint64, set uint32) bool { l := leaderOf(r); return l >= 0 && set&(1<<l) != 0 }
	up := func(r uint64) bool { l := leaderOf(r); return l >= 0 && isDead&(1<<l) == 0 }
	var only uint64
	for r := headAt + lag - 1; r > headAt && only == 0; r-- {
		if leaderOf(r) >= 0 && leaderOf(r+1) >= 0 && !member(r, isDead|isReturner) && !member(r+1, isDead|isReturner) {
			only = r
		}
	}
	if only == 0 {
		w.noLivePair = true
		return w
	}
	first := only + 1
	for !(up(first) && up(first+1) && up(first+2)) {
		first++
		if first > headAt+limit {
			w.noCommit = true
			return w
		}
	}
	deadRuns := func(from, to uint64) (count int) {
		for r := from; r <= to; r++ {
			if runStart(r) && member(r, isDead) {
				count++
			}
		}
		return count
	}
	w.stage1 = first + 1 - headAt
	w.dead1 = deadRuns(headAt+1, first+1)
	commitOnly(only)
	commitLive(first)
	at := first + 1
	fresh := at + resubmit
	r := at + 1
	for {
		if up(r-1) && up(r) && up(r+1) {
			commitLive(r - 1)
			if r-1 > fresh {
				break
			}
		}
		r++
		if r > fresh+limit {
			w.noCommit = true
			return w
		}
	}
	w.stage2 = r - fresh
	w.dead2 = deadRuns(fresh, r)
	return w
}

type staleCommittee struct {
	n, quorum uint64
	down      int
	lag       uint64
	start     uint64
	ids       []peer.ID
	e         *EpochReputation
	head      *LeaderHead
	index     map[peer.ID]int
	tables    map[uint32][]int8 // per voter set, the leader of a round by (round-start) modulo the table's length
}

func newStaleCommittee(t *testing.T, n, quorum uint64, down int) *staleCommittee {
	t.Helper()
	weights := make([]uint64, n)
	for i := range weights {
		weights[i] = 1
	}
	nodes := erNodes(t, weights...)
	lag, err := rctypes.LeaderLag(n)
	require.NoError(t, err)
	c := &staleCommittee{n: n, quorum: quorum, down: down, lag: lag, start: 100, ids: sortedIDs(t, nodes), head: &LeaderHead{}, index: map[peer.ID]int{}, tables: map[uint32][]int8{}}
	c.e = erSelector(t, nodes, c.start, quorum, c.head)
	for i, id := range c.ids {
		c.index[id] = i
	}
	return c
}

func (c *staleCommittee) bitmap(set uint32) []byte {
	out := make([]byte, (c.n+7)/8)
	for i := range c.ids {
		if set&(1<<i) != 0 {
			out[i/8] |= 1 << (i % 8)
		}
	}
	return out
}

// table is the weighted table of a voter set as a slice of member indices. The set is by the selector's node order, the same as ids here: unit weights, sorted.
func (c *staleCommittee) table(t *testing.T, set uint32) []int8 {
	t.Helper()
	if tb, ok := c.tables[set]; ok {
		return tb
	}
	w, err := c.e.table(c.bitmap(set))
	require.NoError(t, err)
	tb := make([]int8, len(w.table))
	for i, m := range w.table {
		tb[i] = int8(c.index[w.members[m]])
	}
	c.tables[set] = tb
	return tb
}

// modelWalk answers leaders from the tables without a ring: a recovery run's owner, else the table of the newest record at or below the cutoff, unknown above head+lag.
func (c *staleCommittee) modelWalk(t *testing.T, stale, live uint32, headAt, resubmit, limit uint64) twoStageWalk {
	staleT, liveT := c.table(t, stale), c.table(t, live)
	head, firstLive := headAt, uint64(1<<62)
	leaderOf := func(r uint64) int {
		off := r - c.start - c.lag
		if off%RecoverySpacing >= RecoverySpacing-RecoveryRun {
			return int((off / RecoverySpacing) % c.n)
		}
		if r > head+c.lag {
			return -1
		}
		if r-c.lag >= firstLive {
			return int(liveT[(r-c.start)%uint64(len(liveT))])
		}
		return int(staleT[(r-c.start)%uint64(len(staleT))])
	}
	runStart := func(r uint64) bool {
		return (r-c.start-c.lag)%RecoverySpacing == RecoverySpacing-RecoveryRun
	}
	return walkTwoStages(leaderOf, func(r uint64) { head = max(head, r) }, func(r uint64) {
		head = max(head, r)
		firstLive = min(firstLive, r)
	}, runStart, (1<<c.n-1)&^live, (1<<c.n-1)&^stale, headAt, c.lag, resubmit, limit)
}

// realWalk answers from the real selector and ring.
func (c *staleCommittee) realWalk(t *testing.T, stale, live uint32, headAt, resubmit, limit uint64) twoStageWalk {
	state := erRing(t, c.n, c.start)
	var err error
	commit := func(round uint64, voters []byte) {
		state, err = state.Next(round, voters)
		require.NoError(t, err)
		*c.head = LeaderHead{Round: round, State: state}
	}
	for r := c.start + 1; r <= headAt; r++ {
		commit(r, c.bitmap(stale))
	}
	leaderOf := func(r uint64) int {
		l, err := c.e.GetLeaderForRound(r)
		if err != nil {
			require.True(t, errors.Is(err, rctypes.ErrHistoryUnavailable), "round %d: %v", r, err)
			return -1
		}
		return c.index[l]
	}
	return walkTwoStages(leaderOf, func(r uint64) { commit(r, c.bitmap(stale)) }, func(r uint64) { commit(r, c.bitmap(live)) }, c.e.RecoveryRunStart, (1<<c.n-1)&^live, (1<<c.n-1)&^stale, headAt, c.lag, resubmit, limit)
}

func subsets(n uint64, size int) (out []uint32) {
	for s := uint32(0); s < 1<<n; s++ {
		if bits.OnesCount32(s) == size {
			out = append(out, s)
		}
	}
	return out
}

// The model must answer as the real selector does: the four-root table enumerated on the real ring in TestTwoStageAllowanceOverEveryOrderAndPhase, and a sample of each larger committee on the real ring here.
func TestStaleSetModelAgreesWithTheSelector(t *testing.T) {
	c := newStaleCommittee(t, 4, 3, 1)
	full := uint32(1<<c.n - 1)
	seen := map[uint64]int{}
	for _, dead := range subsets(c.n, 1) {
		for _, x := range subsets(c.n, 1) {
			if dead == x {
				continue
			}
			for headAt := c.start + c.lag + 2; headAt < c.start+c.lag+2+RecoverySpacing*12; headAt++ {
				w := c.modelWalk(t, full&^x, full&^dead, headAt, 1, 2000)
				require.False(t, w.noCommit || w.noLivePair)
				seen[w.stage2]++
			}
		}
	}
	require.Equal(t, map[uint64]int{2: 12248, 17: 12416, 254: 32, 255: 9128, 510: 16, 511: 3024}, seen, "the table of the real ring")
	for _, tc := range []struct {
		n      uint64
		down   int
		joint  uint64
		timers uint64 // 2*(D+1) + 4*b, the full timers the design charges
	}{{4, 1, 822, 46}, {7, 2, 1106, 74}, {10, 3, 1390, 102}} {
		lag, err := rctypes.LeaderLag(tc.n)
		require.NoError(t, err)
		require.Equal(t, tc.joint, jointAllowance(lag, tc.down), "the design's joint allowance, %d members", tc.n)
		require.Equal(t, tc.timers, 2*(lag+1)+4*uint64(tc.down), "the design's full timers, %d members", tc.n)
	}
	for _, tc := range []struct {
		n, quorum uint64
		down      int
	}{{7, 5, 2}, {10, 7, 3}} {
		c := newStaleCommittee(t, tc.n, tc.quorum, tc.down)
		full := uint32(1<<c.n - 1)
		deads, xs := subsets(c.n, tc.down), subsets(c.n, tc.down)
		checked := 0
		for i := 0; i < 60; i++ {
			dead, x := deads[(i*17)%len(deads)], xs[(i*29+3)%len(xs)]
			if dead&x != 0 {
				continue
			}
			headAt := c.start + c.lag + 2 + uint64(i)*197
			want := c.modelWalk(t, full&^x, full&^dead, headAt, 1, 4000)
			got := c.realWalk(t, full&^x, full&^dead, headAt, 1, 4000)
			require.Equal(t, got, want, "n %d dead %b x %b head %d", tc.n, dead, x, headAt)
			checked++
		}
		require.NotZero(t, checked)
		t.Logf("n=%d: %d sampled shapes agree on the real ring", tc.n, checked)
	}
}

// Model shapes, not live runs: most do not execute the real ring and none has timing. Ten/three samples the head's position, every 13th over its 70 periods; it is not exhaustive. Many
// stale sets have a live triple and commit early: the log counts those that do not apart.
func TestTwoStagesOfLargerStaleSets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		n, quorum uint64
		down      int
		headStep  uint64
		periods   uint64
	}{
		{"seven/two", 7, 5, 2, 1, 35},
		{"ten/three", 10, 7, 3, 13, 70},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newStaleCommittee(t, tc.n, tc.quorum, tc.down)
			full := uint32(1<<c.n - 1)
			limit := stageAllowance(c.lag, tc.down) + 2*RecoverySpacing
			var shapes, noPair, noTriple, headPositions int
			var longestNoTriple uint64
			var longest1, longest2, longestJoint uint64
			maxDead := 0
			outcomes := map[string]int{}
			for headAt := c.start + c.lag + 2; headAt < c.start+c.lag+2+RecoverySpacing*tc.periods; headAt += tc.headStep {
				headPositions++
			}
			for _, dead := range subsets(c.n, tc.down) {
				for _, x := range subsets(c.n, tc.down) {
					if dead&x != 0 {
						continue
					}
					// the case the design names: the stale table has no three live leaders in a row anywhere in its cycle. Otherwise the walk can commit early on the table alone.
					staleTable := c.table(t, full&^x)
					liveTriple := false
					for i := range staleTable {
						at := func(k int) uint32 { return uint32(1) << staleTable[(i+k)%len(staleTable)] }
						liveTriple = liveTriple || (at(0)|at(1)|at(2))&dead == 0
					}
					for headAt := c.start + c.lag + 2; headAt < c.start+c.lag+2+RecoverySpacing*tc.periods; headAt += tc.headStep {
						w := c.modelWalk(t, full&^x, full&^dead, headAt, 1, limit)
						require.False(t, w.noCommit, "dead %b x %b head %d: no commit within %d rounds", dead, x, headAt, limit)
						if w.noLivePair {
							noPair++
							continue
						}
						shapes++
						require.LessOrEqual(t, w.stage1, stageAllowance(c.lag, w.dead1), "dead %b x %b head %d: stage one, %d dead runs", dead, x, headAt, w.dead1)
						require.LessOrEqual(t, w.stage2, stageAllowance(c.lag, w.dead2), "dead %b x %b head %d: stage two, %d dead runs", dead, x, headAt, w.dead2)
						require.LessOrEqual(t, w.dead1, tc.down)
						require.LessOrEqual(t, w.dead2, tc.down)
						require.LessOrEqual(t, w.dead1+w.dead2, tc.down, "dead %b x %b head %d: dead runs in the two stages", dead, x, headAt)
						require.LessOrEqual(t, w.stage1+w.stage2, jointAllowance(c.lag, tc.down), "dead %b x %b head %d: joint", dead, x, headAt)
						if !liveTriple {
							noTriple++
							longestNoTriple = max(longestNoTriple, w.stage1+w.stage2)
						}
						longest1, longest2, longestJoint = max(longest1, w.stage1), max(longest2, w.stage2), max(longestJoint, w.stage1+w.stage2)
						maxDead = max(maxDead, w.dead1+w.dead2)
						outcomes[fmt.Sprintf("dead runs %d then %d", w.dead1, w.dead2)]++
					}
				}
			}
			require.NotZero(t, shapes)
			for _, k := range slices.Sorted(maps.Keys(outcomes)) {
				t.Logf("%8d  %s", outcomes[k], k)
			}
			t.Logf("%s: %d head positions stepped by %d over %d periods, %d shapes, %d with no live pair among the covered rounds; longest stage one %d of %d with all %d dead runs, stage two %d, joint %d of %d; most dead runs in a shape %d", tc.name, headPositions, tc.headStep, tc.periods, shapes, noPair, longest1, stageAllowance(c.lag, tc.down), tc.down, longest2, longestJoint, jointAllowance(c.lag, tc.down), maxDead)
			t.Logf("%s: %d of those shapes have no three live leaders in a row anywhere in the stale table, longest joint %d", tc.name, noTriple, longestNoTriple)
		})
	}
}
