package leader

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #973: weighted stake and larger committees, on the real epoch selector's tables. In memory, no timing: model shapes, counted in rounds. The one-stage window (no commit
// until three live leaders in a row), the rescue (the part of it beyond the covered rounds, where only the recovery runs are known) and the two-stage allowance are three
// separate counts. Nothing here is a wall-clock claim: the 360 s and 75 s targets need tau, rho and delivery premises that a model does not have, and larger or weighted
// profiles do not inherit them.
//
// Quorum is the authenticated full-committee one, floor(2W/3)+1, asserted against the trust base's own construction; it is never recomputed from a subset. Two sets are
// checked separately: the old committed voters (everyone but the returners X) must hold quorum weight, and the responsive set (everyone but the dead D) must; D and X are
// disjoint, nonempty, and need not have equal size or any quorum in their intersection.

type wProfile struct {
	name    string
	weights []uint64
	// control profiles are the supported claims of the design (equal four/five, seven/two, ten/three, (3,2,2,2,2)): a violation fails the test. The others are reported, and their counts are pinned in wExpect as regression fixtures.
	control bool
	// maxPairs bounds the (dead, returner) pairs: 0 means every pair. Otherwise a deterministic sample of that many, from the seed.
	maxPairs int
	// budget is the number of shapes (pair x head phase) per profile.
	budget int
}

func ones(n int) []uint64 { return slices.Repeat([]uint64{1}, n) }

func heavyAt(n, at int, w uint64) []uint64 {
	out := ones(n)
	out[at] = w
	return out
}

func graded(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(i + 1)
	}
	return out
}

func wProfiles() []wProfile {
	p := []wProfile{
		{name: "4 equal (control)", weights: ones(4), control: true, budget: 300000},
		{name: "5 equal (control)", weights: ones(5), control: true, budget: 300000},
		{name: "7 equal (control)", weights: ones(7), control: true, maxPairs: 60, budget: 150000},
		{name: "10 equal (control)", weights: ones(10), control: true, maxPairs: 60, budget: 150000},
		{name: "5 (3,2,2,2,2) (control)", weights: []uint64{3, 2, 2, 2, 2}, control: true, budget: 300000},
	}
	for _, at := range []int{0, 1, 3} {
		p = append(p, wProfile{name: fmt.Sprintf("4 heavy 6 at %d", at), weights: heavyAt(4, at, 6), budget: 300000})
	}
	for _, at := range []int{0, 3} {
		p = append(p, wProfile{name: fmt.Sprintf("4 heavy 7 at %d", at), weights: heavyAt(4, at, 7), budget: 300000})
	}
	for _, at := range []int{1, 4} {
		w := []uint64{2, 2, 2, 2, 2}
		w[at] = 3
		p = append(p, wProfile{name: fmt.Sprintf("5 (3,2,2,2,2) heavy at %d", at), weights: w, budget: 300000})
	}
	for _, hv := range []uint64{2, 5} {
		for _, at := range []int{0, 2, 5} {
			p = append(p, wProfile{name: fmt.Sprintf("6 heavy %d at %d", hv, at), weights: heavyAt(6, at, hv), maxPairs: 400, budget: 150000})
		}
	}
	p = append(p,
		wProfile{name: "6 (3,3,1,1,1,1)", weights: []uint64{3, 3, 1, 1, 1, 1}, maxPairs: 400, budget: 150000},
		wProfile{name: "6 (4,3,2,2,1,1)", weights: []uint64{4, 3, 2, 2, 1, 1}, maxPairs: 400, budget: 150000},
		wProfile{name: "6 equal", weights: ones(6), maxPairs: 400, budget: 150000},
		wProfile{name: "16 equal", weights: ones(16), maxPairs: 300, budget: 150000},
		wProfile{name: "16 (15,1x15)", weights: heavyAt(16, 0, 15), maxPairs: 300, budget: 150000},
		wProfile{name: "16 (30,1x15)", weights: heavyAt(16, 0, 30), maxPairs: 300, budget: 150000},
		wProfile{name: "16 (31,1x15)", weights: heavyAt(16, 0, 31), maxPairs: 300, budget: 150000},
		wProfile{name: "16 (1..16)", weights: graded(16), maxPairs: 300, budget: 150000},
	)
	return p
}

func lcm(a, b uint64) uint64 { return a / gcd(a, b) * b }

// wRng is a fixed generator (a 64-bit LCG) so every sample is reproducible from the profile's index.
type wRng uint64

func (r *wRng) next() uint64 {
	*r = *r*6364136223846793005 + 1442695040888963407
	return uint64(*r >> 17)
}

// wWalks are the model's walks. modelOne is the one-stage window: no commit until the first three live leaders in a row after the head, under the stale voters' table
// and the recovery runs; the rescue part is the rounds past head+lag, where only the runs' owners are known.
type oneStage struct {
	rounds, rescue uint64 // rounds from the head to the commit's round; of those, rounds beyond the covered stretch
	deadRuns       int
	noCommit       bool
}

func (c *staleCommittee) modelOne(t *testing.T, stale, dead uint32, headAt, limit uint64) oneStage {
	staleT := c.table(t, stale)
	leaderOf := func(r uint64) int {
		if owner, ok := c.runOwner(r); ok {
			return owner
		}
		if r > headAt+c.lag {
			return -1
		}
		return c.tableLeader(staleT, r)
	}
	return walkOne(leaderOf, func(r uint64) bool { return (r-c.start-c.lag)%RecoverySpacing == RecoverySpacing-RecoveryRun }, dead, headAt, c.lag, limit)
}

func walkOne(leaderOf func(uint64) int, runStart func(uint64) bool, dead uint32, headAt, lag, limit uint64) oneStage {
	up := func(r uint64) bool { l := leaderOf(r); return l >= 0 && dead&(1<<l) == 0 }
	first := headAt + 1
	for !(up(first) && up(first+1) && up(first+2)) {
		first++
		if first > headAt+limit {
			return oneStage{noCommit: true}
		}
	}
	o := oneStage{rounds: first + 1 - headAt}
	if first+1 > headAt+lag {
		o.rescue = first + 1 - (headAt + lag)
	}
	for r := headAt + 1; r <= first+1; r++ {
		if l := leaderOf(r); runStart(r) && l >= 0 && dead&(1<<l) != 0 {
			o.deadRuns++
		}
	}
	return o
}

func (c *staleCommittee) realOne(t *testing.T, stale, dead uint32, headAt, limit uint64) oneStage {
	state := erRing(t, c.n, c.start)
	var err error
	for r := c.start + 1; r <= headAt; r++ {
		state, err = state.Next(r, c.bitmap(stale))
		require.NoError(t, err)
		*c.head = LeaderHead{Round: r, State: state}
	}
	leaderOf := func(r uint64) int {
		l, err := c.e.GetLeaderForRound(r)
		if err != nil {
			require.True(t, errors.Is(err, rctypes.ErrHistoryUnavailable), "round %d: %v", r, err)
			return -1
		}
		return c.index[l]
	}
	return walkOne(leaderOf, c.e.RecoveryRunStart, dead, headAt, c.lag, limit)
}

type wStat struct{ vals []uint64 }

func (s *wStat) add(v uint64) { s.vals = append(s.vals, v) }
func (s *wStat) max() uint64 {
	if len(s.vals) == 0 {
		return 0
	}
	return slices.Max(s.vals)
}
func (s *wStat) median() uint64 {
	if len(s.vals) == 0 {
		return 0
	}
	v := slices.Clone(s.vals)
	slices.Sort(v)
	return v[len(v)/2]
}

// wResult is the count per profile, the fixture the expected values pin.
type wResult struct {
	Pairs, Shapes, Exhaustive                              int
	NoLivePair, NoCommit1, NoCommit2                       int // the two-stage helper's preceding repeat could not be built; no commit within the horizon (one-stage; two-stage)
	NoWindow, Window                                       int // one-stage shapes with a live triple inside the covered rounds, and the ones that leave it
	OneStageOver, Stage1Over, Stage2Over, JointOver        int // allowance violations
	DeadRunsOver                                           int // d1+d2 > b
	OwnerRepeat                                            int // an identity owns two run starts in the two-stage window (premise: b+2 < n; b+2 == n is not a repeat)
	MaxOneStage, MaxRescue, MaxStage1, MaxStage2, MaxJoint uint64
	MaxOneDead, MaxTwoDead                                 int // most dead recovery runs met in a one-stage window; in the two stages together
}

type wCounterexample struct {
	kind                string
	stale, dead, headAt uint32
	phase               uint64
}

func weightOf(weights []uint64, set uint32) (w uint64) {
	for i, x := range weights {
		if set&(1<<i) != 0 {
			w += x
		}
	}
	return w
}

// wSets lists the valid sets: nonempty, leaving the complement at quorum weight.
func wSets(weights []uint64, quorum uint64) (out []uint32) {
	n := uint(len(weights))
	for s := uint32(1); s < 1<<n; s++ {
		if weightOf(weights, uint32(1<<n-1)&^s) >= quorum {
			out = append(out, s)
		}
	}
	return out
}

func quorumOf(t *testing.T, weights []uint64) (total, q uint64, b int) {
	t.Helper()
	nodes := erNodes(t, weights...)
	for i, n := range nodes {
		n.Stake = weights[i]
	}
	total, err := quorumweight.TotalWeight(nodes)
	require.NoError(t, err)
	q = 2*total/3 + 1
	got, err := quorumweight.Threshold(total)
	require.NoError(t, err)
	require.Equal(t, q, got, "floor(2W/3)+1")
	tb, err := quorumweight.NewTrustBase(1, nodes)
	require.NoError(t, err)
	require.Equal(t, q, tb.QuorumThreshold, "the trust base's own quorum")
	for _, s := range wSets(weights, q) {
		b = max(b, bits.OnesCount32(s))
	}
	return total, q, b
}

func runProfile(t *testing.T, idx int, p wProfile) (wResult, []wCounterexample) {
	t.Helper()
	total, q, b := quorumOf(t, p.weights)
	n := uint64(len(p.weights))
	c := newWeightedStaleCommittee(t, p.weights, q, b)
	full := uint32(1<<n - 1)
	sets := wSets(p.weights, q)
	var pairs [][2]uint32 // dead, returners
	if p.maxPairs == 0 {
		for _, d := range sets {
			for _, x := range sets {
				if d&x == 0 {
					pairs = append(pairs, [2]uint32{d, x})
				}
			}
		}
	} else {
		rng := wRng(uint64(idx)*7919 + 17)
		for len(pairs) < p.maxPairs {
			d, x := sets[rng.next()%uint64(len(sets))], sets[rng.next()%uint64(len(sets))]
			if d&x == 0 {
				pairs = append(pairs, [2]uint32{d, x})
			}
		}
		// the corner pairs are always in: the largest dead and the largest returner sets
		for _, big := range []uint32{slices.MaxFunc(sets, func(a, b uint32) int { return bits.OnesCount32(a) - bits.OnesCount32(b) })} {
			for _, x := range sets {
				if big&x == 0 {
					pairs = append(pairs, [2]uint32{big, x})
					pairs = append(pairs, [2]uint32{x, big})
					break
				}
			}
		}
	}
	require.NotEmpty(t, pairs, "no valid dead/returner pair: an empty shape class")
	limit := stageAllowance(c.lag, b) + 2*RecoverySpacing
	var res wResult
	var cex []wCounterexample
	res.Pairs = len(pairs)
	if p.maxPairs == 0 {
		res.Exhaustive = 1
	}
	var rescueS, oneS wStat
	seenKind := map[string]bool{}
	var boundary [3]*wCounterexample // the longest one-stage rescue, the longest joint and the most dead runs: the real ring is checked on these shapes too
	note := func(kind string, stale, dead uint32, headAt, phase uint64) {
		if !seenKind[kind] {
			seenKind[kind] = true
			cex = append(cex, wCounterexample{kind: kind, stale: stale, dead: dead, headAt: uint32(headAt), phase: phase})
		}
	}
	per := max(1, p.budget/len(pairs))
	for _, pr := range pairs {
		dead, x := pr[0], pr[1]
		stale, live := full&^x, full&^dead
		period := lcm(n*RecoverySpacing, lcm(uint64(len(c.table(t, stale))), uint64(len(c.table(t, live)))))
		stride := (period + uint64(per) - 1) / uint64(per)
		if stride > 1 {
			res.Exhaustive = 0
		}
		for phase := uint64(0); phase < period; phase += stride {
			headAt := c.start + c.lag + 2 + phase
			res.Shapes++
			one := c.modelOne(t, stale, dead, headAt, limit)
			if one.noCommit {
				res.NoCommit1++
				note("one-stage no commit within the horizon", stale, dead, headAt, phase)
			} else {
				oneS.add(one.rounds)
				res.MaxOneStage = max(res.MaxOneStage, one.rounds)
				res.MaxOneDead = max(res.MaxOneDead, one.deadRuns)
				if one.rescue == 0 {
					res.NoWindow++
				} else {
					res.Window++
					rescueS.add(one.rescue)
					if one.rescue > res.MaxRescue {
						boundary[0] = &wCounterexample{kind: "longest rescue", stale: stale, dead: dead, phase: phase}
					}
					res.MaxRescue = max(res.MaxRescue, one.rescue)
				}
				if one.rounds > stageAllowance(c.lag, one.deadRuns) {
					res.OneStageOver++
					note("one-stage over the stage allowance", stale, dead, headAt, phase)
				}
			}
			w := c.modelWalk(t, stale, live, headAt, 1, limit)
			switch {
			case w.noLivePair:
				res.NoLivePair++
			case w.noCommit:
				res.NoCommit2++
				note("two-stage no commit within the horizon", stale, dead, headAt, phase)
			default:
				res.MaxStage1, res.MaxStage2 = max(res.MaxStage1, w.stage1), max(res.MaxStage2, w.stage2)
				if w.stage1+w.stage2 > res.MaxJoint {
					boundary[1] = &wCounterexample{kind: "longest joint", stale: stale, dead: dead, phase: phase}
				}
				if w.dead1+w.dead2 > res.MaxTwoDead {
					boundary[2] = &wCounterexample{kind: "most dead runs", stale: stale, dead: dead, phase: phase}
				}
				res.MaxJoint = max(res.MaxJoint, w.stage1+w.stage2)
				res.MaxTwoDead = max(res.MaxTwoDead, w.dead1+w.dead2)
				if w.stage1 > stageAllowance(c.lag, w.dead1) {
					res.Stage1Over++
					note("stage one over its allowance", stale, dead, headAt, phase)
				}
				if w.stage2 > stageAllowance(c.lag, w.dead2) {
					res.Stage2Over++
					note("stage two over its allowance", stale, dead, headAt, phase)
				}
				if w.stage1+w.stage2 > jointAllowance(c.lag, b) {
					res.JointOver++
					note("joint over its allowance", stale, dead, headAt, phase)
				}
				if w.dead1+w.dead2 > b {
					res.DeadRunsOver++
					note("d1+d2 over b", stale, dead, headAt, phase)
				}
				end := headAt + w.stage1 + 1 + w.stage2 // fresh = first+1+resubmit(1); the window ends at fresh+stage2
				owners := map[int]int{}
				for r := headAt + 1; r <= end; r++ {
					if (r-c.start-c.lag)%RecoverySpacing == RecoverySpacing-RecoveryRun {
						o, _ := c.runOwner(r)
						owners[o]++
					}
				}
				for _, k := range owners {
					if k > 1 {
						res.OwnerRepeat++
						note("an identity owns two run starts in the window", stale, dead, headAt, phase)
						break
					}
				}
			}
		}
	}
	// The real selector and ring on a deterministic sample and on every counterexample shape (within a replay budget of head positions).
	checked, skipped := 0, 0
	var cex2 []wCounterexample
	check := func(stale, dead uint32, headAt uint64) {
		if headAt-c.start > 400000 {
			skipped++
			return
		}
		live := full &^ dead
		require.Equal(t, c.realWalk(t, stale, live, headAt, 1, limit), c.modelWalk(t, stale, live, headAt, 1, limit), "%s: real ring vs model, stale %b dead %b head %d", p.name, stale, dead, headAt)
		require.Equal(t, c.realOne(t, stale, dead, headAt, limit), c.modelOne(t, stale, dead, headAt, limit), "%s: real ring vs model (one stage), stale %b dead %b head %d", p.name, stale, dead, headAt)
		checked++
	}
	for _, e := range cex {
		check(e.stale, e.dead, c.start+c.lag+2+e.phase)
	}
	for _, e := range boundary {
		if e != nil {
			check(e.stale, e.dead, c.start+c.lag+2+e.phase)
			cex2 = append(cex2, *e)
		}
	}
	rng := wRng(uint64(idx)*104729 + 5)
	for range 12 {
		pr := pairs[rng.next()%uint64(len(pairs))]
		check(full&^pr[1], pr[0], c.start+c.lag+2+rng.next()%(2*n*RecoverySpacing))
	}
	t.Logf("PIN %q: %#v", p.name, res)
	t.Logf("%-26s n=%d W=%d q=%d b=%d lag=%d n*S=%d b+2 vs n: %s | pairs %d shapes %d exhaustive-over-lcm=%v | real ring agrees on %d shapes (%d beyond the replay cap, not checked)",
		p.name, n, total, q, b, c.lag, n*RecoverySpacing, cmpWord(b+2, int(n)), res.Pairs, res.Shapes, res.Exhaustive == 1, checked, skipped)
	t.Logf("%-26s one-stage: %d no-window (a live triple inside the covered rounds), %d leave it; rounds max %d median %d; rescue rounds past the covered stretch max %d median %d; most dead runs met %d (4 timer rounds each); no-commit %d; over allowance %d",
		"", res.NoWindow, res.Window, oneS.max(), oneS.median(), rescueS.max(), rescueS.median(), res.MaxOneDead, res.NoCommit1, res.OneStageOver)
	t.Logf("%-26s two-stage: no live pair (helper could not build the repeat) %d; no-commit %d; stage1 max %d stage2 max %d joint max %d of %d; over: stage1 %d stage2 %d joint %d d1+d2>b %d; most dead runs in both stages %d; an identity owns two runs: %d",
		"", res.NoLivePair, res.NoCommit2, res.MaxStage1, res.MaxStage2, res.MaxJoint, jointAllowance(c.lag, b), res.Stage1Over, res.Stage2Over, res.JointOver, res.DeadRunsOver, res.MaxTwoDead, res.OwnerRepeat)
	for _, e := range append(cex, cex2...) {
		t.Logf("%-26s shape: %s: stale %0*b dead %0*b phase %d", "", e.kind, n, e.stale, n, e.dead, e.phase)
	}
	return res, cex
}

func cmpWord(a, b int) string {
	switch {
	case a < b:
		return "b+2 < n"
	case a == b:
		return "b+2 == n"
	}
	return "b+2 > n"
}

func TestWeightedWindows(t *testing.T) {
	for i, p := range wProfiles() {
		t.Run(p.name, func(t *testing.T) {
			res, cex := runProfile(t, i, p)
			if p.control {
				require.Zero(t, res.OneStageOver+res.Stage1Over+res.Stage2Over+res.JointOver+res.DeadRunsOver+res.NoCommit1+res.NoCommit2+res.OwnerRepeat, "a supported claim of the design: %v", cex)
			}
			if want, ok := wExpect[p.name]; ok {
				require.Equal(t, want, res, "pinned counts of the unsupported profile")
			}
		})
	}
}

// The quorum is the trust base's for every weight vector, and a set without quorum weight is refused by the selector's own table, so no stale bitmap below quorum is a sample.
func TestWeightedWindowsQuorumAndBelowQuorumSamples(t *testing.T) {
	for _, p := range wProfiles() {
		_, q, _ := quorumOf(t, p.weights)
		c := newWeightedStaleCommittee(t, p.weights, q, 1)
		full := uint32(1<<c.n - 1)
		for _, s := range []uint32{1, 3, full &^ 1} {
			if weightOf(p.weights, s) < q {
				_, err := c.e.table(c.bitmap(s))
				require.ErrorIs(t, err, ErrInvalidSample, "%s: set %b weighs %d of quorum %d", p.name, s, weightOf(p.weights, s), q)
			}
		}
	}
	var _ = types.NodeInfo{}
}

var wExpect = map[string]wResult{
	"4 equal (control)":        {Pairs: 12, Shapes: 36864, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 2376, Window: 34488, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x200, MaxRescue: 0x1ec, MaxStage1: 0x213, MaxStage2: 0x1ff, MaxJoint: 0x312, MaxOneDead: 1, MaxTwoDead: 1},
	"5 equal (control)":        {Pairs: 20, Shapes: 25600, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 25600, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0xd, MaxRescue: 0x0, MaxStage1: 0x217, MaxStage2: 0x5, MaxJoint: 0x21c, MaxOneDead: 1, MaxTwoDead: 1},
	"7 equal (control)":        {Pairs: 62, Shapes: 136192, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 115842, Window: 20350, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x1ff, MaxRescue: 0x1df, MaxStage1: 0x31f, MaxStage2: 0x1ff, MaxJoint: 0x41e, MaxOneDead: 1, MaxTwoDead: 2},
	"10 equal (control)":       {Pairs: 62, Shapes: 133824, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 108526, Window: 25298, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x2fb, MaxRescue: 0x2cf, MaxStage1: 0x42b, MaxStage2: 0x2ff, MaxJoint: 0x430, MaxOneDead: 2, MaxTwoDead: 3},
	"5 (3,2,2,2,2) (control)":  {Pairs: 20, Shapes: 230400, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 230400, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0xf, MaxRescue: 0x0, MaxStage1: 0x217, MaxStage2: 0x6, MaxJoint: 0x21d, MaxOneDead: 1, MaxTwoDead: 1},
	"4 heavy 6 at 0":           {Pairs: 12, Shapes: 49152, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 49152, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x10, MaxRescue: 0x0, MaxStage1: 0x313, MaxStage2: 0x5, MaxJoint: 0x318, MaxOneDead: 1, MaxTwoDead: 2},
	"4 heavy 6 at 1":           {Pairs: 12, Shapes: 49152, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 49152, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x10, MaxRescue: 0x0, MaxStage1: 0x313, MaxStage2: 0x5, MaxJoint: 0x318, MaxOneDead: 1, MaxTwoDead: 2},
	"4 heavy 6 at 3":           {Pairs: 12, Shapes: 49152, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 49152, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x10, MaxRescue: 0x0, MaxStage1: 0x313, MaxStage2: 0x5, MaxJoint: 0x318, MaxOneDead: 1, MaxTwoDead: 2},
	"4 heavy 7 at 0":           {Pairs: 12, Shapes: 110592, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 110592, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x11, MaxRescue: 0x0, MaxStage1: 0x313, MaxStage2: 0x8, MaxJoint: 0x31b, MaxOneDead: 1, MaxTwoDead: 2},
	"4 heavy 7 at 3":           {Pairs: 12, Shapes: 110592, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 110592, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x11, MaxRescue: 0x0, MaxStage1: 0x313, MaxStage2: 0x8, MaxJoint: 0x31b, MaxOneDead: 1, MaxTwoDead: 2},
	"5 (3,2,2,2,2) heavy at 1": {Pairs: 20, Shapes: 230400, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 230400, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0xf, MaxRescue: 0x0, MaxStage1: 0x217, MaxStage2: 0x6, MaxJoint: 0x21d, MaxOneDead: 1, MaxTwoDead: 1},
	"5 (3,2,2,2,2) heavy at 4": {Pairs: 20, Shapes: 230400, Exhaustive: 1, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 230400, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0xf, MaxRescue: 0x0, MaxStage1: 0x217, MaxStage2: 0x6, MaxJoint: 0x21d, MaxOneDead: 1, MaxTwoDead: 1},
	"6 heavy 2 at 0":           {Pairs: 402, Shapes: 143942, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 120049, Window: 23893, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x1ff, MaxRescue: 0x1e3, MaxStage1: 0x31b, MaxStage2: 0x1ff, MaxJoint: 0x41a, MaxOneDead: 1, MaxTwoDead: 2},
	"6 heavy 2 at 2":           {Pairs: 402, Shapes: 143362, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 125813, Window: 17549, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x2fd, MaxRescue: 0x2e1, MaxStage1: 0x31b, MaxStage2: 0x2ff, MaxJoint: 0x417, MaxOneDead: 2, MaxTwoDead: 2},
	"6 heavy 2 at 5":           {Pairs: 402, Shapes: 143420, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 123858, Window: 19562, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x1ff, MaxRescue: 0x1e3, MaxStage1: 0x31b, MaxStage2: 0x1ff, MaxJoint: 0x419, MaxOneDead: 1, MaxTwoDead: 2},
	"6 heavy 5 at 0":           {Pairs: 402, Shapes: 141741, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 141741, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x12, MaxRescue: 0x0, MaxStage1: 0x41b, MaxStage2: 0xa, MaxJoint: 0x422, MaxOneDead: 1, MaxTwoDead: 3},
	"6 heavy 5 at 2":           {Pairs: 402, Shapes: 141850, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 136255, Window: 5595, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x400, MaxRescue: 0x3e4, MaxStage1: 0x41b, MaxStage2: 0x1a, MaxJoint: 0x424, MaxOneDead: 3, MaxTwoDead: 3},
	"6 heavy 5 at 5":           {Pairs: 402, Shapes: 141680, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 141680, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x12, MaxRescue: 0x0, MaxStage1: 0x41b, MaxStage2: 0xa, MaxJoint: 0x422, MaxOneDead: 1, MaxTwoDead: 3},
	"6 (3,3,1,1,1,1)":          {Pairs: 402, Shapes: 145851, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 114112, Window: 31739, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x2ff, MaxRescue: 0x2e3, MaxStage1: 0x41b, MaxStage2: 0x1ff, MaxJoint: 0x41d, MaxOneDead: 2, MaxTwoDead: 3},
	"6 (4,3,2,2,1,1)":          {Pairs: 402, Shapes: 147397, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 123177, Window: 24220, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x1ff, MaxRescue: 0x1e3, MaxStage1: 0x419, MaxStage2: 0x1ff, MaxJoint: 0x421, MaxOneDead: 1, MaxTwoDead: 3},
	"6 equal":                  {Pairs: 402, Shapes: 147132, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 147132, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0xa, MaxRescue: 0x0, MaxStage1: 0x21b, MaxStage2: 0x5, MaxJoint: 0x21f, MaxOneDead: 1, MaxTwoDead: 1},
	"16 equal":                 {Pairs: 302, Shapes: 149649, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 140362, Window: 9287, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x3fa, MaxRescue: 0x3b6, MaxStage1: 0x641, MaxStage2: 0x3ff, MaxJoint: 0x643, MaxOneDead: 3, MaxTwoDead: 5},
	"16 (15,1x15)":             {Pairs: 302, Shapes: 149696, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 149696, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x21, MaxRescue: 0x0, MaxStage1: 0xa43, MaxStage2: 0x17, MaxJoint: 0xa45, MaxOneDead: 1, MaxTwoDead: 9},
	"16 (30,1x15)":             {Pairs: 302, Shapes: 149694, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 149694, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x1c, MaxRescue: 0x0, MaxStage1: 0xefb, MaxStage2: 0x29, MaxJoint: 0xefd, MaxOneDead: 1, MaxTwoDead: 14},
	"16 (31,1x15)":             {Pairs: 300, Shapes: 149976, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 149976, Window: 0, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x1b, MaxRescue: 0x0, MaxStage1: 0x93e, MaxStage2: 0x11, MaxJoint: 0x940, MaxOneDead: 1, MaxTwoDead: 8},
	"16 (1..16)":               {Pairs: 302, Shapes: 149773, Exhaustive: 0, NoLivePair: 0, NoCommit1: 0, NoCommit2: 0, NoWindow: 149741, Window: 32, OneStageOver: 0, Stage1Over: 0, Stage2Over: 0, JointOver: 0, DeadRunsOver: 0, OwnerRepeat: 0, MaxOneStage: 0x38b, MaxRescue: 0x347, MaxStage1: 0xa2f, MaxStage2: 0x1ff, MaxJoint: 0xa31, MaxOneDead: 3, MaxTwoDead: 9},
}
