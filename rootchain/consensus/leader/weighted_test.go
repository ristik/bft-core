package leader

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	test "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

// committee returns the members sorted by node ID string with the given weights assigned in that order.
func committee(t *testing.T, weights ...uint64) []*types.NodeInfo {
	t.Helper()
	ids := test.GeneratePeerIDs(t, len(weights))
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = id.String()
	}
	sort.Strings(names)
	nodes := make([]*types.NodeInfo, len(weights))
	for i := range weights {
		nodes[i] = &types.NodeInfo{NodeID: names[i], Stake: weights[i]}
	}
	return nodes
}

// withHeavy returns a copy of the committee whose weights are: heavy at position pos, light elsewhere, ids unchanged.
func reweighted(nodes []*types.NodeInfo, weights ...uint64) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(nodes))
	for i, n := range nodes {
		out[i] = &types.NodeInfo{NodeID: n.NodeID, Stake: weights[i]}
	}
	return out
}

// referenceSchedule is an independent implementation of the recurrence: it keys the priorities by node ID, picks the maximum with a
// sort rather than a scan, and uses math/big throughout. It returns the index (in canonical order) of the leader of each round
// from start through start+rounds-1.
func referenceSchedule(nodes []*types.NodeInfo, rounds int) []int {
	order := make([]int, len(nodes))
	for i := range order {
		order[i] = i
	}
	prio := map[string]*big.Int{}
	total := new(big.Int)
	for _, n := range nodes {
		prio[n.NodeID] = new(big.Int)
		total.Add(total, new(big.Int).SetUint64(n.Stake))
	}
	leaders := make([]int, 0, rounds)
	for r := 0; r < rounds; r++ {
		for _, n := range nodes {
			prio[n.NodeID].Add(prio[n.NodeID], new(big.Int).SetUint64(n.Stake))
		}
		sort.SliceStable(order, func(a, b int) bool {
			if c := prio[nodes[order[a]].NodeID].Cmp(prio[nodes[order[b]].NodeID]); c != 0 {
				return c > 0
			}
			return nodes[order[a]].NodeID < nodes[order[b]].NodeID
		})
		win := order[0]
		prio[nodes[win].NodeID].Sub(prio[nodes[win].NodeID], total)
		leaders = append(leaders, win)
	}
	return leaders
}

func indexOf(t *testing.T, nodes []*types.NodeInfo, id peer.ID) int {
	t.Helper()
	for i, n := range nodes {
		if n.NodeID == id.String() {
			return i
		}
	}
	t.Fatalf("leader %s is not a member", id)
	return -1
}

func schedule(t *testing.T, w *Weighted, nodes []*types.NodeInfo, from uint64, rounds int) []int {
	t.Helper()
	out := make([]int, rounds)
	for i := range out {
		id, err := w.GetLeaderForRound(from + uint64(i))
		require.NoError(t, err)
		out[i] = indexOf(t, nodes, id)
	}
	return out
}

// The unit-weight schedule is the canonical-order rotation of a handoff epoch, member (round-start) mod n, exactly.
func TestWeightedUnitWeightsGoldenSequence(t *testing.T) {
	nodes := committee(t, 1, 1, 1, 1)
	w, err := NewWeighted(7, nodes)
	require.NoError(t, err)
	require.Equal(t, []int{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1}, schedule(t, w, nodes, 7, 14), "golden: members 0,1,2,3 repeating from the start round")
	for _, n := range []int{1, 2, 3, 5, 7} {
		nodes := committee(t, slicesOf(n, 1)...)
		w, err := NewWeighted(3, nodes)
		require.NoError(t, err)
		for r := 0; r < 3*n+2; r++ {
			id, err := w.GetLeaderForRound(3 + uint64(r))
			require.NoError(t, err)
			require.Equal(t, nodes[r%n].NodeID, id.String(), "n=%d offset %d", n, r)
		}
	}
	// equal weights equal to each other but not one: the schedule is the same rotation
	nodes = committee(t, 5, 5, 5)
	w, err = NewWeighted(1, nodes)
	require.NoError(t, err)
	require.Equal(t, []int{0, 1, 2, 0, 1, 2}, schedule(t, w, nodes, 1, 6))
}

func slicesOf(n int, v uint64) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

const hhahbchh = "HHaHbHcHH"

func label(i, heavy int, lights *int) byte {
	return 0
}

// 6,1,1,1: the schedule and the priorities after each slot are the design's table, wherever the heavy member sits in the
// canonical order; the priorities are zero again after nine slots and the pattern repeats.
func TestWeightedHeavyPlusThreeLightSchedule(t *testing.T) {
	// design table: priorities after selection, in the order H, a, b, c
	table := [9][4]int64{{-3, 1, 1, 1}, {-6, 2, 2, 2}, {0, -6, 3, 3}, {-3, -5, 4, 4}, {3, -4, -4, 5}, {0, -3, -3, 6}, {6, -2, -2, -2}, {3, -1, -1, -1}, {0, 0, 0, 0}}
	for heavyPos := 0; heavyPos < 4; heavyPos++ {
		weights := slicesOf(4, 1)
		weights[heavyPos] = 6
		nodes := committee(t, weights...)
		w, err := NewWeighted(100, nodes)
		require.NoError(t, err)
		// the lights in canonical order are a, b, c
		var order []int // member index of H, a, b, c
		order = append(order, heavyPos)
		for i := range nodes {
			if i != heavyPos {
				order = append(order, i)
			}
		}
		var got strings.Builder
		for r := uint64(100); r < 100+27; r++ {
			id, err := w.GetLeaderForRound(r)
			require.NoError(t, err)
			got.WriteByte("Habc"[slot(order, indexOf(t, nodes, id))])
			k := int(r-100) % 9
			w.mu.Lock()
			for j, member := range order {
				require.EqualValues(t, table[k][j], w.prio[member].Int64(), "heavy at %d, round %d, member %d", heavyPos, r, j)
			}
			w.mu.Unlock()
		}
		require.Equal(t, strings.Repeat(hhahbchh, 3), strings.ReplaceAll(got.String(), "H", "H"), "heavy at position %d", heavyPos)
	}
}

func slot(order []int, member int) int {
	for j, m := range order {
		if m == member {
			return j
		}
	}
	return -1
}

// Which slots of the nine-slot period start three consecutive leaders from the responsive set, and the longest gap between them.
func TestWeightedResponsiveTriplesAndOfflineGap(t *testing.T) {
	period := []byte(hhahbchh)
	triples := func(online string) (starts []int, maxGap int) {
		in := func(k int) bool { return strings.IndexByte(online, period[(k-1)%9]) >= 0 }
		for k := 1; k <= 9; k++ {
			if in(k) && in(k+1) && in(k+2) {
				starts = append(starts, k)
			}
		}
		for i, s := range starts {
			next := starts[(i+1)%len(starts)]
			gap := (next - s + 9) % 9
			if gap == 0 {
				gap = 9
			}
			maxGap = max(maxGap, gap)
		}
		return
	}
	for online, want := range map[string]struct {
		starts []int
		gap    int
	}{"Ha": {[]int{1, 2, 8, 9}, 6}, "Hb": {[]int{4, 8, 9}, 4}, "Hc": {[]int{6, 7, 8, 9}, 6}} {
		starts, gap := triples(online)
		require.Equal(t, want.starts, starts, online)
		require.Equal(t, want.gap, gap, online)
	}

	// the heavy member's longest run of consecutive slots, and the spacing of the light slots, over the cyclic schedule
	nodes := committee(t, 6, 1, 1, 1)
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	s := schedule(t, w, nodes, 1, 18)
	run, longest := 0, 0
	var lightSlots []int
	for i, m := range s {
		if m == 0 {
			run++
			longest = max(longest, run)
		} else {
			run = 0
			lightSlots = append(lightSlots, i+1)
		}
	}
	require.Equal(t, 4, longest, "slots 8-11 are four consecutive heavy leaders")
	require.Equal(t, []int{3, 5, 7, 12, 14, 16}, lightSlots, "light slots 3,5,7,12,... have spacings 2,2,5")

	// 3,2,2,2,2 with the heavy member first: with it offline the longest gap between responsive leaders is two slots
	nodes = committee(t, 3, 2, 2, 2, 2)
	w, err = NewWeighted(1, nodes)
	require.NoError(t, err)
	s = schedule(t, w, nodes, 1, 44)
	require.Equal(t, []int{0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0}, s[:11], "H a b c d H a b c d H")
	require.Equal(t, s[:22], s[22:], "the period is 22 rounds")
	run, longest = 0, 0
	for _, m := range s {
		if m == 0 {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	require.Equal(t, 2, longest, "the heavy member leads at most two consecutive slots")
}

// After each selection the priorities sum to zero and stay within [-W, (n-1)W]; over any window the selections satisfy
// W*N_i = L*w_i + p_i(start) - p_i(end); and the schedule equals the independent reference.
func TestWeightedInvariantsAndReference(t *testing.T) {
	rng := rand.New(rand.NewSource(399))
	for trial := 0; trial < 300; trial++ {
		n := 1 + rng.Intn(5)
		weights := make([]uint64, n)
		var total int64
		for i := range weights {
			weights[i] = uint64(1 + rng.Intn(6))
			total += int64(weights[i])
		}
		nodes := committee(t, weights...)
		w, err := NewWeighted(1+uint64(rng.Intn(50)), nodes)
		require.NoError(t, err)
		rounds := int(2*total) + 5
		want := referenceSchedule(nodes, rounds)
		counts := make([]int64, n)
		for r := 0; r < rounds; r++ {
			id, err := w.GetLeaderForRound(w.start + uint64(r))
			require.NoError(t, err)
			m := indexOf(t, nodes, id)
			require.Equal(t, want[r], m, "trial %d round %d weights %v", trial, r, weights)
			counts[m]++
			sum := new(big.Int)
			w.mu.Lock()
			for i, p := range w.prio {
				sum.Add(sum, p)
				require.True(t, p.Cmp(big.NewInt(-total)) >= 0, "priority below -W")
				require.True(t, p.Cmp(big.NewInt(int64(n-1)*total)) <= 0, "priority above (n-1)W")
				require.Equal(t, int64(r+1)*int64(weights[i]), total*counts[i]+p.Int64(), "W*N_i = L*w_i - p_i(end) from zero")
			}
			w.mu.Unlock()
			require.Zero(t, sum.Sign(), "priorities sum to zero")
		}
	}
}

// Queries answered from the cache, the ring, a jump or a scratch replay all equal an independent replay, and a selector rebuilt from
// the same inputs (a restarted node) agrees whatever was asked of the old one.
func TestWeightedQueryOrderDoesNotChangeTheSchedule(t *testing.T) {
	nodes := committee(t, 6, 1, 1, 1, 2)
	const start, span = 11, 200
	want := referenceSchedule(nodes, span)
	at := func(r uint64) int { return want[r-start] }

	fresh := func() *Weighted {
		w, err := NewWeighted(start, nodes)
		require.NoError(t, err)
		return w
	}
	check := func(w *Weighted, r uint64) {
		id, err := w.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, at(r), indexOf(t, nodes, id), "round %d", r)
	}
	w := fresh()
	for _, r := range []uint64{start, start, start + 1, start + 1, start + 40, start + 39, start, start + 41, start + 120, start + 3, start + 119, start + 199, start + 7, start + 199, start + 190} {
		check(w, r)
	}
	// the cache was not rewound by the older queries
	require.EqualValues(t, start+199, w.last)

	rng := rand.New(rand.NewSource(7))
	w = fresh()
	for i := 0; i < 2000; i++ {
		check(w, start+uint64(rng.Intn(span)))
	}
	// a rebuilt selector, queried in any order, agrees with the first
	rebuilt := fresh()
	for r := uint64(start + span - 1); r >= start && r < start+span; r-- {
		check(rebuilt, r)
	}
	for r := uint64(start); r < start+span; r++ {
		a, _ := w.GetLeaderForRound(r)
		b, _ := rebuilt.GetLeaderForRound(r)
		require.Equal(t, a, b)
	}
}

func TestWeightedConcurrentQueries(t *testing.T) {
	nodes := committee(t, 3, 2, 2, 2, 2)
	const start, span = 5, 300
	want := referenceSchedule(nodes, span)
	w, err := NewWeighted(start, nodes)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 500; i++ {
				r := start + uint64(rng.Intn(span))
				id, err := w.GetLeaderForRound(r)
				if err != nil || nodes[want[r-start]].NodeID != id.String() {
					t.Errorf("round %d: %v %s", r, err, id)
					return
				}
			}
		}(int64(g))
	}
	wg.Wait()
}

func TestWeightedInputsAreCopiedAndOrderIndependent(t *testing.T) {
	nodes := committee(t, 6, 1, 1, 1)
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	want := schedule(t, w, nodes, 1, 30)

	// mutating the caller's slice and structs afterwards changes nothing
	other, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	for _, n := range nodes {
		n.Stake = 1
	}
	nodes[0], nodes[3] = nodes[3], nodes[0]
	require.Equal(t, want, schedule(t, other, committee0(t, want, other), 1, 30))

	// any permutation of the input gives the same schedule
	base := committee(t, 6, 1, 1, 1)
	for seed := int64(0); seed < 10; seed++ {
		shuffled := append([]*types.NodeInfo(nil), base...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		s, err := NewWeighted(1, shuffled)
		require.NoError(t, err)
		w, err := NewWeighted(1, base)
		require.NoError(t, err)
		for r := uint64(1); r < 40; r++ {
			a, _ := s.GetLeaderForRound(r)
			b, _ := w.GetLeaderForRound(r)
			require.Equal(t, a, b)
		}
	}
}

// committee0 rebuilds the canonical node list of a selector, to translate its leaders back to indices.
func committee0(t *testing.T, _ []int, w *Weighted) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(w.members))
	for i, m := range w.members {
		out[i] = &types.NodeInfo{NodeID: m.String()}
	}
	return out
}

func TestWeightedRejectsInvalidInputs(t *testing.T) {
	good := committee(t, 2, 1, 1)
	clone := func() []*types.NodeInfo { return reweighted(good, 2, 1, 1) }

	_, err := NewWeighted(0, good)
	require.ErrorIs(t, err, ErrInvalidStart)

	_, err = NewWeighted(1, nil)
	require.ErrorIs(t, err, ErrNoMembers)
	_, err = NewWeighted(1, []*types.NodeInfo{})
	require.ErrorIs(t, err, ErrNoMembers)

	withNil := clone()
	withNil[1] = nil
	_, err = NewWeighted(1, withNil)
	require.ErrorIs(t, err, ErrInvalidMember)

	badID := clone()
	badID[2].NodeID = "not a peer id"
	_, err = NewWeighted(1, badID)
	require.ErrorIs(t, err, ErrInvalidMember)

	dup := clone()
	dup[2].NodeID = dup[1].NodeID
	_, err = NewWeighted(1, dup)
	require.ErrorIs(t, err, ErrDuplicateMember)

	zero := clone()
	zero[1].Stake = 0
	_, err = NewWeighted(1, zero)
	require.ErrorIs(t, err, ErrInvalidWeight)
	require.NotErrorIs(t, err, ErrInvalidMember, "the weight, and only the weight, is what is wrong")

	w, err := NewWeighted(10, good)
	require.NoError(t, err)
	_, err = w.GetLeaderForRound(9)
	require.ErrorIs(t, err, ErrBeforeStart)
	_, err = w.GetLeaderForRound(0)
	require.ErrorIs(t, err, ErrBeforeStart)
	_, err = w.GetLeaderForRound(10)
	require.NoError(t, err)
}

func TestWeightedSingleMemberAndMaximumWeights(t *testing.T) {
	one := committee(t, 7)
	w, err := NewWeighted(1, one)
	require.NoError(t, err)
	for r := uint64(1); r < 20; r++ {
		id, err := w.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, one[0].NodeID, id.String())
	}

	// the largest weights a uint64 holds: the total overflows 64 bits, the arithmetic is exact
	huge := committee(t, math.MaxUint64, math.MaxUint64, 1<<40, 1)
	w, err = NewWeighted(1, huge)
	require.NoError(t, err)
	require.Equal(t, referenceSchedule(huge, 64), schedule(t, w, huge, 1, 64))
	q3 := committee(t, 1<<40, 1<<40, 1<<40, 1<<40)
	w, err = NewWeighted(1, q3)
	require.NoError(t, err)
	require.Equal(t, []int{0, 1, 2, 3, 0, 1, 2, 3}, schedule(t, w, q3, 1, 8))
}

// The round counter does not wrap: a schedule that runs to the top of the round space keeps advancing.
func TestWeightedRoundCounterDoesNotOverflow(t *testing.T) {
	nodes := committee(t, 2, 1, 1)
	start := uint64(math.MaxUint64 - 5)
	w, err := NewWeighted(start, nodes)
	require.NoError(t, err)
	want := referenceSchedule(nodes, 6)
	require.Equal(t, want, schedule(t, w, nodes, start, 6), "rounds up to MaxUint64")
	require.EqualValues(t, uint64(math.MaxUint64), w.last)
	_, err = w.GetLeaderForRound(start - 1)
	require.ErrorIs(t, err, ErrBeforeStart)
	// replay of an old round after the cache reached the top
	for r := uint64(0); r < 6; r++ {
		id, err := w.GetLeaderForRound(start + r)
		require.NoError(t, err)
		require.Equal(t, nodes[want[r]].NodeID, id.String())
	}
}

// QC, recovery and trust base callbacks are no-ops: they cannot move an epoch's schedule.
func TestWeightedCallbacksDoNotChangeTheSchedule(t *testing.T) {
	nodes := committee(t, 6, 1, 1, 1)
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	want := referenceSchedule(nodes, 40)
	for r := uint64(1); r <= 40; r++ {
		require.NoError(t, w.Update(nil, r, nil))
		require.NoError(t, w.UpdateWithTrustBase(nil, r))
		id, err := w.GetLeaderForRound(r)
		require.NoError(t, err)
		require.Equal(t, nodes[want[r-1]].NodeID, id.String())
	}
	_ = fmt.Sprint
}
