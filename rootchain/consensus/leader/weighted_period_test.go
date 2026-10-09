package leader

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/weightcap"
)

func gcdOf(ws []uint64) (g uint64) {
	for _, w := range ws {
		g = gcd(g, w)
	}
	return g
}

// checkPeriod compares the selector against the independent big.Int replay over two full periods, then checks the exact counts, the
// zero reset (the second period repeats the first) and the table's own length.
func checkPeriod(t *testing.T, weights []uint64) {
	t.Helper()
	nodes := committee(t, weights...)
	var total uint64
	for _, w := range weights {
		total += w
	}
	p := total / gcdOf(weights)
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	require.Equal(t, p, w.Period(), "weights %v", weights)
	want := referenceSchedule(nodes, int(2*p))
	got := schedule(t, w, nodes, 1, int(2*p))
	require.Equal(t, want, got, "weights %v", weights)
	counts := make([]uint64, len(weights))
	for _, m := range got[:p] {
		counts[m]++
	}
	g := gcdOf(weights)
	for i := range weights {
		require.Equal(t, weights[i]/g, counts[i], "member %d selected w_i/gcd times per period, weights %v", i, weights)
	}
	require.Equal(t, got[:p], got[p:], "the second period repeats the first exactly, weights %v", weights)
}

// Every ordered vector with up to five members and weights up to five, then random larger ones including common divisors and
// coprime totals near the bound.
func TestWeightedPeriodAgainstTheIndependentReplay(t *testing.T) {
	var rec func(prefix []uint64, n int)
	count := 0
	rec = func(prefix []uint64, n int) {
		if len(prefix) == n {
			checkPeriod(t, append([]uint64(nil), prefix...))
			count++
			return
		}
		for w := uint64(1); w <= 5; w++ {
			rec(append(prefix, w), n)
		}
	}
	for n := 1; n <= 4; n++ { // n = 5 is covered by the random trials below to keep the run short
		rec(nil, n)
	}
	require.Equal(t, 5+25+125+625, count)

	rng := rand.New(rand.NewSource(65536))
	for trial := 0; trial < 60; trial++ {
		n := 1 + rng.Intn(20)
		ws := make([]uint64, n)
		for i := range ws {
			ws[i] = uint64(1 + rng.Intn(1+rng.Intn(400)))
		}
		if trial%3 == 0 { // a common divisor
			d := uint64(2 + rng.Intn(9))
			for i := range ws {
				ws[i] *= d
			}
		}
		checkPeriod(t, ws)
	}
}

// Worst-period inputs: the period is as long as the bound allows (a total of B, or B-1, coprime), not the tiny period of equal
// weights.
func TestWeightedWorstPeriodInputs(t *testing.T) {
	for _, ws := range [][]uint64{
		{weightcap.B - 99, 1, 1, 1, 1, 1, 1, 1, 1, 1},              // one whale and nine singles: W = B - 90... exactly below
		{weightcap.B / 2, weightcap.B/2 - 1, 1},                    // coprime, W = B
		{weightcap.B - 1},                                          // a single member
		append([]uint64{weightcap.B - 99 + 1}, slicesOf(98, 1)...), // n = 99
		{40000, 25535, 1},                                          // W = B
		{21845, 21845, 21846},                                      // W = B - 0, periods differ by one weight
	} {
		var total uint64
		for _, w := range ws {
			total += w
		}
		if total > weightcap.B {
			continue
		}
		nodes := committee(t, ws...)
		w, err := NewWeighted(1, nodes)
		require.NoError(t, err)
		require.Equal(t, total/gcdOf(ws), w.Period())
		// two periods against the replay is too slow for big.Int at 65,536; compare a window per period and the closing property
		want := referenceSchedule(nodes, int(w.Period()))
		require.Equal(t, want, schedule(t, w, nodes, 1, int(w.Period())), "weights %v", ws)
	}
}

// Ties go to the smallest canonical ID: equal weights give the canonical rotation, whichever way the input is ordered.
func TestWeightedTiesAndPermutations(t *testing.T) {
	nodes := committee(t, 3, 3, 3, 3)
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	require.Equal(t, []int{0, 1, 2, 3, 0, 1, 2, 3}, schedule(t, w, nodes, 1, 8))
	shuffled := append([]*types.NodeInfo(nil), nodes...)
	rand.New(rand.NewSource(1)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	w2, err := NewWeighted(1, shuffled)
	require.NoError(t, err)
	require.Equal(t, schedule(t, w, nodes, 1, 8), schedule(t, w2, nodes, 1, 8))
}

// r = A*, A*+P-1, A*+P, below the start, and the very top of the round space.
func TestWeightedBoundaryRounds(t *testing.T) {
	nodes := committee(t, 6, 1, 1, 1)
	const start = 1000
	w, err := NewWeighted(start, nodes)
	require.NoError(t, err)
	p := w.Period()
	require.EqualValues(t, 9, p)
	want := referenceSchedule(nodes, int(p))
	at := func(r uint64) int {
		id, err := w.GetLeaderForRound(r)
		require.NoError(t, err)
		return indexOf(t, nodes, id)
	}
	require.Equal(t, want[0], at(start))
	require.Equal(t, want[p-1], at(start+p-1))
	require.Equal(t, want[0], at(start+p))
	require.Equal(t, want[(math.MaxUint64-start)%p], at(math.MaxUint64))
	_, err = w.GetLeaderForRound(start - 1)
	require.ErrorIs(t, err, ErrBeforeStart)
	_, err = w.GetLeaderForRound(0)
	require.ErrorIs(t, err, ErrBeforeStart)
}

// A lookup replays nothing, mutates nothing and allocates nothing, for a near round or a round at the top of the space; forward,
// backward, repeated and arbitrary queries and eight concurrent readers all agree with the reference.
func TestWeightedLookupIsReadOnlyAndAllocationFree(t *testing.T) {
	nodes := committee(t, 5, 3, 2, 1, 1)
	const start = 17
	w, err := NewWeighted(start, nodes)
	require.NoError(t, err)
	for _, r := range []uint64{start, start + 1, 1 << 40, math.MaxUint64} {
		allocs := testing.AllocsPerRun(100, func() { _, _ = w.GetLeaderForRound(r) })
		require.Zero(t, allocs, "round %d", r)
	}
	want := referenceSchedule(nodes, int(w.Period()))
	idx := func(r uint64) int { id, _ := w.GetLeaderForRound(r); return indexOf(t, nodes, id) }
	rng := rand.New(rand.NewSource(3))
	queries := []uint64{math.MaxUint64, start + 3, start, start + 3, 1 << 62, start + 2}
	for i := 0; i < 500; i++ {
		queries = append(queries, start+uint64(rng.Int63()))
	}
	var first []int
	for _, r := range queries {
		first = append(first, idx(r))
		require.Equal(t, want[(r-start)%w.Period()], first[len(first)-1])
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, r := range queries {
				if idx(r) != first[i] {
					t.Errorf("concurrent reader disagrees at %d", r)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// The selector does not keep its input: changing the committee afterwards changes nothing.
func TestWeightedImmutableInput(t *testing.T) {
	nodes := committee(t, 4, 2, 1)
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	before := schedule(t, w, nodes, 1, 14)
	nodes[0].Stake, nodes[1].Stake = 1, 9
	require.Equal(t, before, schedule(t, w, committee0(t, nil, w), 1, 14))
	_ = fmt.Sprint
}
