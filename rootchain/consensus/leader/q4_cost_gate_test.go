package leader

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	p2ptest "github.com/libp2p/go-libp2p/core/test"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Q4 #51 (C): the #399 query-cost gate (design v2 section 4, second bullet) with the supported envelope and the budgets FROZEN here,
// before acceptance, and never widened after a failure. The selector replays each intervening round under one mutex, O(n*d), so a
// cold restart or a catch-up jump blocks every other caller for the duration of the replay.
//
// Frozen on 2026-10-08, from the #489 measurements (i7-8850H: n=100, d=10^5 took 620 ms, d=10^6 took 3.99 s):
//
//	supported membership   n <= 100, weights up to 2^40 per member (large and unequal)
//	supported distance     d <= 100,000 rounds past the epoch start or the cache (about 28 hours of epoch at 1 s rounds)
//	lookup budget          2 s for one cold or old-uncached lookup at the supported envelope (the consensus loop is blocked for it)
//	blocked-caller budget  no caller waits longer than the lookup budget behind a cold lookup
//	allocation budget      at most 512 KiB and 2,048 allocations per lookup (the scratch priorities are O(n), never O(d))
//
// A distance beyond 100,000 rounds is NOT supported: d=10^6 at n=100 takes seconds and needs a checkpoint or an accelerated lookup,
// which is separate prerequisite work (#489 says so). The full profile below measures it and reports that verdict; schedule density
// does not waive it.
const (
	q4SupportedMembers  = 100
	q4SupportedDistance = 100_000
	q4LookupBudget      = 2 * time.Second
	q4AllocBytesBudget  = 512 << 10
	q4AllocCountBudget  = 2048
)

// q4CostRow is one measurement.
type q4CostRow struct {
	Kind       string  `json:"kind"` // cold-restart, old-uncached, blocked-callers
	Members    int     `json:"members"`
	Distance   uint64  `json:"distance"`
	Ms         float64 `json:"ms"`
	BudgetMs   float64 `json:"budgetMs"`
	AllocBytes uint64  `json:"allocBytes,omitempty"`
	Allocs     uint64  `json:"allocs,omitempty"`
	Callers    int     `json:"callers,omitempty"`
	Blocked    int     `json:"blockedCallers,omitempty"`
	MaxWaitMs  float64 `json:"maxWaitMs,omitempty"`
	// Supported is true inside the frozen envelope; Within is the verdict against the (scaled) budget and is never true outside it:
	// a distance beyond the envelope is measured and reported, not passed.
	Supported bool `json:"supported"`
	Within    bool `json:"within"`
}

type q4CostReport struct {
	Frozen struct {
		Members    int     `json:"members"`
		Distance   uint64  `json:"distance"`
		BudgetMs   float64 `json:"lookupBudgetMs"`
		AllocBytes uint64  `json:"allocBytes"`
		Allocs     uint64  `json:"allocs"`
	} `json:"frozen"`
	Profile string      `json:"profile"`
	Host    string      `json:"host"`
	Rows    []q4CostRow `json:"rows"`
}

func q4Members(t testing.TB, n int) []*types.NodeInfo {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		id, err := p2ptest.RandPeerID()
		require.NoError(t, err)
		names[i] = id.String()
	}
	sort.Strings(names)
	nodes := make([]*types.NodeInfo, n)
	for i := range nodes {
		nodes[i] = &types.NodeInfo{NodeID: names[i], Stake: 1<<40 + uint64(i)}
	}
	return nodes
}

// q4Scaled is the lookup budget for a distance: linear in d (the replay is O(n*d)), capped at the frozen budget, which is the
// budget at the supported distance. A smaller profile therefore keeps the same per-round budget (20 us per round), and a distance
// beyond the envelope is judged against the frozen budget itself, never a scaled-up one.
func q4Scaled(d uint64) time.Duration {
	return min(q4LookupBudget, time.Duration(float64(q4LookupBudget)*float64(d)/float64(q4SupportedDistance)))
}

func q4Measure(t testing.TB, nodes []*types.NodeInfo, kind string, d uint64) q4CostRow {
	t.Helper()
	row := q4CostRow{Kind: kind, Members: len(nodes), Distance: d, BudgetMs: float64(q4Scaled(d)) / 1e6,
		Supported: len(nodes) <= q4SupportedMembers && d <= q4SupportedDistance}
	var w *Weighted
	var err error
	switch kind {
	case "cold-restart":
	case "old-uncached":
		w, err = NewWeighted(1, nodes)
		require.NoError(t, err)
		_, err = w.GetLeaderForRound(1 + d + 2*recentRounds) // the cache is ahead: round 1+d left the ring
		require.NoError(t, err)
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	if kind == "cold-restart" {
		w, err = NewWeighted(1, nodes)
		require.NoError(t, err)
	}
	_, err = w.GetLeaderForRound(1 + d)
	elapsed := time.Since(start)
	require.NoError(t, err)
	runtime.ReadMemStats(&after)
	row.Ms = float64(elapsed) / 1e6
	row.AllocBytes, row.Allocs = after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs
	row.Within = row.Supported && elapsed <= q4Scaled(d) && row.AllocBytes <= q4AllocBytesBudget && row.Allocs <= q4AllocCountBudget
	return row
}

// q4MeasureBlocked starts one cold lookup of distance d on a selector and, while it holds the mutex, calls the selector from
// callers goroutines for a round the cache cannot answer instantly; it records how long each waited.
func q4MeasureBlocked(t testing.TB, nodes []*types.NodeInfo, d uint64, callers int) q4CostRow {
	t.Helper()
	w, err := NewWeighted(1, nodes)
	require.NoError(t, err)
	row := q4CostRow{Kind: "blocked-callers", Members: len(nodes), Distance: d, BudgetMs: float64(q4Scaled(d)) / 1e6, Callers: callers,
		Supported: len(nodes) <= q4SupportedMembers && d <= q4SupportedDistance}
	var wg sync.WaitGroup
	waits := make([]time.Duration, callers)
	started := make(chan struct{})
	wg.Add(1)
	begin := time.Now()
	go func() {
		defer wg.Done()
		close(started)
		if _, err := w.GetLeaderForRound(1 + d); err != nil {
			t.Error(err)
		}
	}()
	<-started
	time.Sleep(time.Millisecond) // the cold lookup holds the mutex; the callers queue behind it
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			at := time.Now()
			if _, err := w.GetLeaderForRound(1); err != nil { // the first round: replayed or cached, trivial work, so any wait is the mutex
				t.Error(err)
			}
			waits[i] = time.Since(at)
		}()
	}
	wg.Wait()
	row.Ms = float64(time.Since(begin)) / 1e6
	var maxWait time.Duration
	for _, wt := range waits {
		maxWait = max(maxWait, wt)
		if wt > 10*time.Millisecond {
			row.Blocked++
		}
	}
	row.MaxWaitMs = float64(maxWait) / 1e6
	row.Within = row.Supported && maxWait <= q4Scaled(d)
	return row
}

// TestQ4QueryCostGate runs the CI profile (n=100, d=10^4, the same per-round budget as the frozen envelope: cheap and bounded) and,
// with Q4_COST_FULL=1, the acceptance profile over the whole envelope plus the measured-only d=10^6 row. Q4_COST_OUT=<file> keeps the
// measurements as JSON for the acceptance report.
func TestQ4QueryCostGate(t *testing.T) {
	full := os.Getenv("Q4_COST_FULL") == "1"
	rep := q4CostReport{Profile: "ci (n=100, d=10^4)", Host: fmt.Sprintf("%s/%s %d cpu %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())}
	rep.Frozen.Members, rep.Frozen.Distance = q4SupportedMembers, q4SupportedDistance
	rep.Frozen.BudgetMs, rep.Frozen.AllocBytes, rep.Frozen.Allocs = float64(q4LookupBudget)/1e6, q4AllocBytesBudget, q4AllocCountBudget

	type cell struct {
		n int
		d uint64
	}
	cells := []cell{{100, 10_000}}
	if full {
		rep.Profile = "full (frozen envelope plus the measured-only distance)"
		cells = []cell{{10, 10_000}, {100, 10_000}, {10, 100_000}, {100, 100_000}, {100, 1_000_000}}
	}
	for _, c := range cells {
		nodes := q4Members(t, c.n)
		rows := []q4CostRow{q4Measure(t, nodes, "cold-restart", c.d), q4Measure(t, nodes, "old-uncached", c.d), q4MeasureBlocked(t, nodes, c.d, 8)}
		for _, r := range rows {
			t.Logf("%-16s n=%-3d d=%-8d %9.1f ms (budget %8.1f ms) alloc %7d B %5d allocs, blocked %d/%d max wait %.1f ms, supported=%v within=%v",
				r.Kind, r.Members, r.Distance, r.Ms, r.BudgetMs, r.AllocBytes, r.Allocs, r.Blocked, r.Callers, r.MaxWaitMs, r.Supported, r.Within)
			if r.Supported {
				require.True(t, r.Within, "%s n=%d d=%d is inside the frozen envelope and over its budget: separate prerequisite work must bound or accelerate the lookup; the budget is not widened", r.Kind, r.Members, r.Distance)
			}
		}
		rep.Rows = append(rep.Rows, rows...)
	}
	if out := os.Getenv("Q4_COST_OUT"); out != "" {
		raw, err := json.MarshalIndent(rep, "", " ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(out, append(raw, '\n'), 0o644))
	}
}

// TestQ4QueryCostScalesWithDistanceNotMembersAlone pins the model the budgets rest on: the replay does n steps per round, so a
// lookup at ten times the distance costs several times as much (a regression to a constant-time lookup would silently make the
// budgets meaningless, and a quadratic one would break them).
func TestQ4QueryCostScalesWithDistanceNotMembersAlone(t *testing.T) {
	nodes := q4Members(t, 20)
	small := q4Measure(t, nodes, "cold-restart", 20_000)
	big := q4Measure(t, nodes, "cold-restart", 200_000)
	require.Greater(t, big.Ms, 3*small.Ms, "ten times the distance costs much more: the lookup replays every intervening round")
	require.Less(t, big.Ms, 40*small.Ms+50, "and not quadratically more")
}
