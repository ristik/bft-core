package leader

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	p2ptest "github.com/libp2p/go-libp2p/core/test"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/weightcap"
)

// Q4 #51 (C) / #399: the query-cost gate (design v2 section 4, second bullet) over the bounded lookup. The selector now holds one
// immutable period table, built once at construction from verified context in at most n*B steps; a lookup is O(1) and independent of
// the distance to the round, of any cache and of the epoch's age. The envelope is therefore the profile bound itself and the whole
// round space, not a distance limit:
//
//	supported membership   n <= 100 (weightcap.MaxMembers), total committed weight <= B = 65,536
//	supported distance     every round from the epoch start to math.MaxUint64
//	latency budget         2 s for constructor plus lookup (a cold restart or a first catch-up jump), and for any caller waiting behind it
//	allocation budget      at most 512 KiB and 2,048 allocations for constructor plus lookup; a lookup alone allocates nothing
//
// The budgets are the ones frozen before the change (2026-10-08) and are not widened to pass. BASELINE BEFORE THE CHANGE, kept as a record
// and not re-run: the replaying selector took 2.0 s (n=100, d=10^6, this host) to 4.0 s (#489 host) for one cold lookup, grew with d,
// and blocked every concurrent caller for the same time; its test weights (2^40+i) exceeded the committed-weight cap that now applies,
// so that row is not an unchanged-row comparison but a different input class (large raw stake is quantized to <= B before it commits).
const (
	q4MaxMembers       = weightcap.MaxMembers
	q4LatencyBudget    = 2 * time.Second
	q4AllocBytesBudget = 512 << 10
	q4AllocCountBudget = 2048
)

// q4CostRow is one measurement.
type q4CostRow struct {
	Kind       string  `json:"kind"` // cold-restart, old-query, concurrent-cold, cache-rebuild
	Members    int     `json:"members"`
	Distance   uint64  `json:"distance"`
	Weights    string  `json:"weights"`
	Period     uint64  `json:"period"`
	Ms         float64 `json:"ms"`
	BudgetMs   float64 `json:"budgetMs"`
	AllocBytes uint64  `json:"allocBytes,omitempty"`
	Allocs     uint64  `json:"allocs,omitempty"`
	Callers    int     `json:"callers,omitempty"`
	MaxWaitMs  float64 `json:"maxWaitMs,omitempty"`
	Supported  bool    `json:"supported"`
	Within     bool    `json:"within"`
}

type q4CostReport struct {
	Frozen struct {
		Members    int     `json:"members"`
		TotalB     uint64  `json:"totalWeightBound"`
		BudgetMs   float64 `json:"latencyBudgetMs"`
		AllocBytes uint64  `json:"allocBytes"`
		Allocs     uint64  `json:"allocs"`
	} `json:"frozen"`
	Profile string      `json:"profile"`
	Host    string      `json:"host"`
	Rows    []q4CostRow `json:"rows"`
}

// q4Input is one committee shape. worst-period inputs have gcd 1 and a total at the bound, so the period is as long as it can be.
type q4Input struct {
	name    string
	weights []uint64
}

func q4Inputs() []q4Input {
	n100 := make([]uint64, 100)
	for i := range n100 { // 100 unequal, coprime-ish weights summing to exactly B
		n100[i] = 655
	}
	n100[0] += weightcap.B - 65500 // 655*100 = 65500 -> the first member takes the rest, total B
	n100[1]++
	n100[2]--
	return []q4Input{
		{"n=100 worst period (total B, gcd 1)", n100},
		{"n=100 equal weights (period 100)", func() []uint64 {
			w := make([]uint64, 100)
			for i := range w {
				w[i] = 600
			}
			return w
		}()},
		{"n=4 6,1,1,1 (period 9)", []uint64{6, 1, 1, 1}},
		{"n=3 worst period (B/2, B/2-1, 1)", []uint64{weightcap.B / 2, weightcap.B/2 - 1, 1}},
	}
}

func q4Members(t testing.TB, ws []uint64) []*types.NodeInfo {
	t.Helper()
	names := make([]string, len(ws))
	for i := range names {
		id, err := p2ptest.RandPeerID()
		require.NoError(t, err)
		names[i] = id.String()
	}
	sort.Strings(names)
	nodes := make([]*types.NodeInfo, len(ws))
	for i := range nodes {
		nodes[i] = &types.NodeInfo{NodeID: names[i], Stake: ws[i]}
	}
	return nodes
}

func q4Row(kind string, in q4Input, d uint64) q4CostRow {
	return q4CostRow{Kind: kind, Members: len(in.weights), Distance: d, Weights: in.name, BudgetMs: float64(q4LatencyBudget) / 1e6, Supported: len(in.weights) <= q4MaxMembers}
}

func q4Mem(f func()) (bytes, allocs uint64, elapsed time.Duration) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	f()
	elapsed = time.Since(start)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs, elapsed
}

func q4Within(r q4CostRow, elapsed time.Duration) bool {
	return r.Supported && elapsed <= q4LatencyBudget && r.AllocBytes <= q4AllocBytesBudget && r.Allocs <= q4AllocCountBudget
}

// q4Distances are the mandatory query distances past the epoch start: the old Q4 rows, d~6e5, d=1e6 and the top of the round space.
func q4Distances(start uint64) []uint64 {
	return []uint64{1_000, 10_000, 100_000, 600_000, 1_000_000, math.MaxUint64 - start}
}

// TestQ4QueryCostGate runs every mandatory row: n=100 at d=10^6 (cold restart, old query, eight synchronized concurrent callers),
// d~6*10^5, the top of the round space and the worst-period inputs. A row outside its budget fails the test; nothing is measured
// only. Q4_COST_OUT=<file> keeps the measurements as JSON for the acceptance report.
func TestQ4QueryCostGate(t *testing.T) {
	if raceEnabled {
		t.Skip("wall-clock budgets are not meaningful under the race detector; they run in the Q4 deterministic gates job and the normal test shards")
	}
	rep := q4CostReport{Profile: "bounded period table (mandatory rows)", Host: fmt.Sprintf("%s/%s %d cpu %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())}
	rep.Frozen.Members, rep.Frozen.TotalB = q4MaxMembers, weightcap.B
	rep.Frozen.BudgetMs, rep.Frozen.AllocBytes, rep.Frozen.Allocs = float64(q4LatencyBudget)/1e6, q4AllocBytesBudget, q4AllocCountBudget
	const start = 1
	for _, in := range q4Inputs() {
		nodes := q4Members(t, in.weights)
		for _, d := range q4Distances(start) {
			// cold restart: constructor plus the first lookup, timed together
			row := q4Row("cold-restart", in, d)
			var w *Weighted
			var elapsed time.Duration
			row.AllocBytes, row.Allocs, elapsed = q4Mem(func() {
				var err error
				w, err = NewWeighted(start, nodes)
				require.NoError(t, err)
				_, err = w.GetLeaderForRound(start + d)
				require.NoError(t, err)
			})
			row.Period, row.Ms, row.Within = w.Period(), float64(elapsed)/1e6, q4Within(row, elapsed)
			rep.Rows = append(rep.Rows, row)

			// old query: a lookup on an existing selector; there is no cache to be ahead of, so it is the same constant work
			row = q4Row("old-query", in, d)
			row.AllocBytes, row.Allocs, elapsed = q4Mem(func() {
				_, err := w.GetLeaderForRound(start + d)
				require.NoError(t, err)
			})
			row.Period, row.Ms, row.Within = w.Period(), float64(elapsed)/1e6, q4Within(row, elapsed)
			rep.Rows = append(rep.Rows, row)

			// eight synchronized concurrent cold callers, each building and asking for the same far round
			row = q4Row("concurrent-cold", in, d)
			row.Callers = 8
			waits := make([]time.Duration, row.Callers)
			var wg sync.WaitGroup
			gate := make(chan struct{})
			row.AllocBytes, row.Allocs, elapsed = q4Mem(func() {
				for i := 0; i < row.Callers; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-gate
						at := time.Now()
						sel, err := NewWeighted(start, nodes)
						if err == nil {
							_, err = sel.GetLeaderForRound(start + d)
						}
						if err != nil {
							t.Error(err)
						}
						waits[i] = time.Since(at)
					}()
				}
				close(gate)
				wg.Wait()
			})
			var maxWait time.Duration
			for _, wt := range waits {
				maxWait = max(maxWait, wt)
			}
			row.Period, row.Ms, row.MaxWaitMs = w.Period(), float64(elapsed)/1e6, float64(maxWait)/1e6
			// the allocation budget is per caller: eight callers each allocate their own table
			row.AllocBytes, row.Allocs = row.AllocBytes/uint64(row.Callers), row.Allocs/uint64(row.Callers)
			row.Within = q4Within(row, maxWait)
			rep.Rows = append(rep.Rows, row)
		}
		// rebuild after eviction from a bounded cache: a construction, counted
		row := q4Row("cache-rebuild", in, 1_000_000)
		cache, err := NewTableCache(1)
		require.NoError(t, err)
		k1, k2 := TableKey{Epoch: 2, Start: start}, TableKey{Epoch: 3, Start: start}
		_, err = cache.Get(k1, nodes)
		require.NoError(t, err)
		_, err = cache.Get(k2, nodes) // evicts k1
		require.NoError(t, err)
		var sel *Weighted
		var elapsed time.Duration
		row.AllocBytes, row.Allocs, elapsed = q4Mem(func() {
			sel, err = cache.Get(k1, nodes)
			require.NoError(t, err)
			_, err = sel.GetLeaderForRound(start + row.Distance)
			require.NoError(t, err)
		})
		row.Period, row.Ms, row.Within = sel.Period(), float64(elapsed)/1e6, q4Within(row, elapsed)
		rep.Rows = append(rep.Rows, row)
	}
	for _, r := range rep.Rows {
		t.Logf("%-16s %-38s d=%-20d P=%-6d %8.2f ms (budget %.0f) alloc %7d B %5d allocs wait %.2f ms within=%v",
			r.Kind, r.Weights, r.Distance, r.Period, r.Ms, r.BudgetMs, r.AllocBytes, r.Allocs, r.MaxWaitMs, r.Within)
		require.True(t, r.Within, "%s %s d=%d is inside the frozen envelope and over its budget; the budget is not widened", r.Kind, r.Weights, r.Distance)
	}
	if out := os.Getenv("Q4_COST_OUT"); out != "" {
		raw, err := json.MarshalIndent(rep, "", " ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(out, append(raw, '\n'), 0o644))
	}
}

// TestQ4LookupCostIsConstant replaces the old "cost grows with the distance" assertion with the deterministic bounded-construction and
// constant-lookup ones: the table length is exactly W/gcd (so construction is at most n*B steps and 64 KiB), and a lookup allocates
// nothing for a near round, a far round and the top of the round space alike.
func TestQ4LookupCostIsConstant(t *testing.T) {
	for _, in := range q4Inputs() {
		nodes := q4Members(t, in.weights)
		w, err := NewWeighted(7, nodes)
		require.NoError(t, err)
		var total, g uint64
		for _, x := range in.weights {
			total += x
			g = gcd(g, x)
		}
		require.Equal(t, total/g, w.Period(), in.name)
		require.LessOrEqual(t, w.Period(), weightcap.B, "the table is at most B entries (64 KiB)")
		for _, r := range []uint64{7, 8, 1 << 20, 1 << 40, math.MaxUint64} {
			require.Zero(t, testing.AllocsPerRun(50, func() { _, _ = w.GetLeaderForRound(r) }), "%s round %d", in.name, r)
		}
	}
}
