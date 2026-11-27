package consensus

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func TestLargerCommitteeRescueTiming(t *testing.T) {
	if os.Getenv("BFT_973_LARGER") == "" {
		t.Skip("set BFT_973_LARGER=1 to measure the rolling-change windows")
	}
	members := traceEnvInt(t, "BFT_973_MEMBERS", 7)
	require.Contains(t, []int{7, 16, 32}, members)
	gate9RescueTrace(t, members)
}

// TestWeightedTwoStageTiming reuses the gate 7 stale-proof scenario at two
// weighted placements. The libp2p row uses real root-to-root traffic. The
// scripted shard submits directly to a manager on both paths, as in gate 7.
func TestWeightedTwoStageTiming(t *testing.T) {
	if os.Getenv("BFT_973_WEIGHTED") == "" {
		t.Skip("set BFT_973_WEIGHTED=1 to measure the gate 7 weighted placements")
	}
	deadAt := traceEnvInt(t, "BFT_TRACE_DEAD", 0)
	require.Contains(t, []int{0, 1}, deadAt)
	const members = 5
	options := q3fixture.Options{
		Weights:         []uint64{3, 2, 2, 2, 2},
		WeightsByNodeID: true,
	}
	var transport *liveTransport
	var setup func(*q4bLive)
	if os.Getenv("BFT_TRACE_TRANSPORT") == "libp2p" {
		transport = newLiveTransport(t)
		setup = transport.install
	}
	timeout := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 10)) * time.Second
	c := newEqualLiveRate(t, timeout, 900*time.Millisecond, options, setup, rootTimingNames(members)...)
	ordered := c.all()
	slices.SortFunc(ordered, func(a, b string) int {
		return strings.Compare(c.id(a).String(), c.id(b).String())
	})
	for i, name := range ordered {
		require.Equal(t, options.Weights[i], c.nodes[c.idx(name)].weight)
	}
	d, x := ordered[deadAt], ordered[deadAt+1]
	requireTimingQuorum(t, c, c.except(x))
	requireTimingQuorum(t, c, c.except(d))
	t.Logf("NodeID order %v, weights %v; stop %s at index %d, return %s at index %d", ordered, options.Weights, d, deadAt, x, deadAt+1)
	reportRecoveryCycle(t, c.nodes[c.idx(d)].r.manager, c, ordered)
	lag, err := rctypes.LeaderLag(members)
	require.NoError(t, err)
	twoStageRun(t, c, x, d, lag+2, 1, transport)
}

func reportTwoStageClock(t *testing.T, rounds []clockRound) {
	t.Helper()
	reportTimingUnknown(t, rounds)
	var rho, tau []time.Duration
	for _, r := range rounds {
		switch {
		case r.skipped:
		case !r.known:
			tau = append(tau, r.d())
		case r.certified:
			rho = append(rho, r.d())
		}
	}
	t.Logf("rho (known, certified): %s; tau (unknown): %s", durations(rho, time.Second), durations(tau, 50*time.Millisecond))
}

func rootTimingNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("root-%02d", i)
	}
	return names
}

func requireTimingQuorum(t *testing.T, c *q4bLive, up []string) {
	t.Helper()
	var total, online uint64
	for _, n := range c.nodes {
		total += n.weight
	}
	for _, name := range up {
		online += c.nodes[c.idx(name)].weight
	}
	quorum := c.nodes[0].r.f.Body.RootThreshold
	require.Equal(t, 2*total/3+1, quorum)
	require.GreaterOrEqual(t, online, quorum, "responsive stake in %v", up)
	t.Logf("responsive stake %d of %d, quorum %d; nodes %v", online, total, quorum, up)
}

// Verify the full recovery ownership cycle by looking up its runs, without
// waiting for the cluster to execute that many rounds.
func reportRecoveryCycle(t *testing.T, m *ConsensusManager, c *q4bLive, ordered []string) {
	t.Helper()
	selector, ok := m.leaderSelector.(*leader.EpochReputation)
	require.True(t, ok)
	start := m.epochAnchor.Slot + 1
	for !selector.RecoveryRunStart(start) {
		start++
	}
	cycle := uint64(len(ordered) * leader.RecoverySpacing)
	for i := range ordered {
		round := start + uint64(i*leader.RecoverySpacing)
		require.True(t, selector.RecoveryRunStart(round))
		id, err := selector.GetLeaderForRound(round)
		require.NoError(t, err)
		require.Equal(t, c.id(ordered[i]), id, "recovery owner at round %d", round)
		if i == 0 {
			repeat, err := selector.GetLeaderForRound(round + cycle)
			require.NoError(t, err)
			require.Equal(t, id, repeat)
		}
	}
	t.Logf("recovery cycle: %d rounds (%d members × %d); first recovery run at %d", cycle, len(ordered), leader.RecoverySpacing, start)
}

func reportTimingUnknown(t *testing.T, rounds []clockRound) {
	t.Helper()
	skipped := 0
	for i := 0; i < len(rounds); {
		if rounds[i].skipped {
			skipped++
		}
		if rounds[i].known || rounds[i].skipped {
			i++
			continue
		}
		from := i
		for i < len(rounds) && !rounds[i].known && !rounds[i].skipped {
			i++
		}
		t.Logf("unknown interval [%d,%d): %d rounds, %s", rounds[from].round, rounds[i-1].round+1, i-from,
			rounds[i-1].end.Sub(rounds[from].start).Round(time.Millisecond))
	}
	t.Logf("round clock: %d completed rounds, %d skipped by poll", len(rounds), skipped)
}
