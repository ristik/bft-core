package consensus

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The design's gate 6 targets for established five-root operation with one member down: request to certificate p95 <= 6 s outside adaptation and
// recovery runs, and <= 60 s across a single dead recovery run.
const (
	gate6NormalP95 = 6 * time.Second
	gate6DeadRun   = 60 * time.Second
)

// #886 gate 6: five real managers on a real epoch 2, one never started. By default one placement; BFT_GATE6_ALL=1 runs every placement,
// which takes minutes each. BFT_GATE6_REQUESTS sets the number of shard requests (8 by default), BFT_GATE6_DEADRUN=1 adds one request across
// the dead member's own recovery run (up to five periods away: minutes), and BFT_TRACE_T sets T in seconds (2 by default; 10 is production).
// At T = 2 s wall times do not stand in for the 60 s target, which charges production timers: rounds do, and every sample is logged by phase.
// The wall-clock targets are asserted only with BFT_GATE6_TIMING=1, on a machine the run has to itself (the host run): on a shared laptop the
// rounds themselves slow down and the seconds measure the machine.
func TestFiveManagerOutage(t *testing.T) {
	names := []string{"H", "a", "b", "c", "d"}
	placements := names[len(names)-1:]
	if os.Getenv("BFT_GATE6_ALL") != "" {
		placements = names
	}
	for _, dead := range placements {
		t.Run("dead "+dead, func(t *testing.T) {
			t.Parallel()
			q4Slot(t)
			fiveManagerOutage(t, dead, names)
		})
	}
}

// fiveSample is one shard request: the root rounds and seconds from its first acceptance to its certificate, and the phase it spanned.
type fiveSample struct {
	rounds  uint64
	elapsed time.Duration
	sends   int
	phase   string // "normal", "live run" (a recovery run of a live member in the span) or "dead run" (the dead member's)
}

// fivePhase labels the rounds from..to: a recovery run of the dead member in them makes it "dead run", of another member "live run".
func fivePhase(selector *leader.EpochReputation, dead peer.ID, from, to uint64) string {
	phase := "normal"
	for r := from; r <= to; r++ {
		if !inRecoveryRun(selector, r) {
			continue
		}
		start := r
		for !selector.RecoveryRunStart(start) {
			start--
		}
		if owner, err := selector.GetLeaderForRound(start); err == nil && owner == dead {
			return "dead run"
		}
		phase = "live run"
	}
	return phase
}

// fiveRequest submits one shard request as a shard does (to the first live root that accepts it, and again when a new certificate of the shard,
// a T2 repeat, has made the proof it holds stale) and waits for its certificate.
func fiveRequest(t *testing.T, c *q4bLive, live []string, hash []byte, deadline time.Duration) fiveSample {
	t.Helper()
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	lastUC := func(name string) uint64 {
		si := m(name).blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		if si == nil || si.LastCR == nil {
			return 0
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
	}
	var ingress string
	var first, sentUnder uint64
	var at time.Time
	sends := 0
	refusals := map[string]int{}
	certified := func() bool {
		if ingress != "" && c.certifiedHash(ingress, hash) {
			return true
		}
		if ingress != "" && lastUC(ingress) == sentUnder {
			return false
		}
		for _, name := range live {
			proof := phaseLockProof(t, c, c.nodes[c.idx(name)].r, hash)
			if proof == nil {
				refusals["no view"]++
				continue
			}
			if err := m(name).RequestCertification(context.Background(), *proof); err != nil {
				refusals[err.Error()]++
				continue
			}
			if ingress == "" {
				first, at = c.state(name).Round, time.Now()
			}
			ingress, sentUnder = name, lastUC(name)
			sends++
			break
		}
		return false
	}
	// a plain loop, not Eventually: its condition may still be running when the failure message reads what the condition writes
	end := time.Now().Add(deadline)
	for !certified() {
		require.Truef(t, time.Now().Before(end), "the request is accepted and certified: ingress %q, %d sends, refusals %v", ingress, sends, refusals)
		time.Sleep(10 * time.Millisecond)
	}
	return fiveSample{rounds: c.state(ingress).Round - first, elapsed: time.Since(at), sends: sends}
}

// reportFive logs the samples by phase and unconditionally, and returns the normal ones' durations.
func reportFive(t *testing.T, label string, samples []fiveSample) (normal []time.Duration) {
	t.Helper()
	byPhase := map[string][]time.Duration{}
	var all []time.Duration
	var rows []string
	for _, s := range samples {
		byPhase[s.phase] = append(byPhase[s.phase], s.elapsed)
		all = append(all, s.elapsed)
		rows = append(rows, fmt.Sprintf("%s:%d/%s/%d", s.phase, s.rounds, s.elapsed.Round(time.Millisecond), s.sends))
	}
	t.Logf("%s: samples (phase:rounds/seconds/sends) %s", label, strings.Join(rows, " "))
	for _, phase := range []string{"normal", "live run", "dead run"} {
		t.Logf("%s, %s: %s", label, phase, durations(byPhase[phase], gate6NormalP95))
	}
	t.Logf("%s, unconditional: %s", label, durations(all, gate6NormalP95))
	return byPhase["normal"]
}

// gate6Timing says whether the wall-clock targets are asserted (BFT_GATE6_TIMING=1).
func gate6Timing() bool { return os.Getenv("BFT_GATE6_TIMING") != "" }

// p95 is the nearest-rank 95th percentile.
func p95(ds []time.Duration) time.Duration {
	ds = slices.Clone(ds)
	slices.Sort(ds)
	return ds[min(len(ds)-1, (len(ds)*95+99)/100-1)]
}

func fiveManagerOutage(t *testing.T, dead string, names []string) {
	const (
		minCommits   = 50
		requestLimit = 16 // root rounds from acceptance to the certificate, outside a recovery run: the T2 repeat of a dead shard slot is 12
	)
	requests := traceEnvInt(t, "BFT_GATE6_REQUESTS", 8)
	T := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 2)) * time.Second
	c := newEqualLive(t, T, names...)
	live := c.except(dead)
	c.start(live...)
	lag, err := rctypes.LeaderLag(uint64(len(names)))
	require.NoError(t, err)
	// past the bootstrap, and then one lag more, which every cutoff needs to have the samples without the dead member
	// (about ten visits of the dead member at two timeouts each, on top of the rounds: more than q4bDeadline when three clusters share a machine)
	slot := c.nodes[0].r.manager.epochAnchor.Slot
	require.Eventually(t, func() bool {
		for _, name := range live {
			if c.committedRound(name) < slot+2*lag+uint64(len(names)) {
				return false
			}
		}
		return true
	}, 3*q4bDeadline*max(1, T/(2*time.Second)), 50*time.Millisecond, "the survivors commit past the bootstrap and the aging")

	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	selector, ok := m(live[0]).leaderSelector.(*leader.EpochReputation)
	require.True(t, ok, "the epoch runs the reputation schedule")

	mark := c.mark()
	round := c.state(live[0]).Round
	for r := round + 1; r <= c.state(live[0]).Committed+lag; r++ {
		if inRecoveryRun(selector, r) {
			continue
		}
		got, err := selector.GetLeaderForRound(r)
		require.NoError(t, err, r)
		require.NotEqual(t, c.id(dead), got, "the absent member is selected outside its recovery run: round %d", r)
	}

	var samples []fiveSample
	for i := range requests {
		from := c.state(live[0]).Round
		s := fiveRequest(t, c, live, bytes.Repeat([]byte{0x90 + byte(i)}, 32), q4bDeadline)
		s.phase = fivePhase(selector, c.id(dead), from, c.state(live[0]).Round)
		if s.phase == "normal" {
			require.LessOrEqual(t, s.rounds, uint64(requestLimit), "request %d to certificate in root rounds", i)
		}
		samples = append(samples, s)
	}
	normal := reportFive(t, "dead "+dead, samples)
	if len(normal) > 0 && gate6Timing() {
		require.LessOrEqual(t, p95(normal), gate6NormalP95, "request to certificate p95 outside adaptation and recovery runs")
	}

	if os.Getenv("BFT_GATE6_DEADRUN") != "" {
		// the dead member's next recovery run: submit two rounds before it, so the request is pending across the run's four slots
		var runAt uint64
		for r := c.state(live[0]).Round + 3; runAt == 0; r++ {
			if selector.RecoveryRunStart(r) {
				if owner, err := selector.GetLeaderForRound(r); err == nil && owner == c.id(dead) {
					runAt = r
				}
			}
			require.Less(t, r, c.state(live[0]).Round+uint64(len(names)+1)*leader.RecoverySpacing, "the dead member owns a run within the coverage period")
		}
		t.Logf("dead run at round %d, now %d", runAt, c.state(live[0]).Round)
		require.Eventually(t, func() bool { return c.state(live[0]).Round+2 >= runAt }, time.Duration(runAt-c.state(live[0]).Round)*(T+2*time.Second), 20*time.Millisecond, "the rounds reach the dead run")
		from := c.state(live[0]).Round
		s := fiveRequest(t, c, live, bytes.Repeat([]byte{0xa0}, 32), q4bDeadline+8*T)
		s.phase = fivePhase(selector, c.id(dead), from, c.state(live[0]).Round)
		t.Logf("across the dead run of round %d: accepted at round %d, %d rounds and %s to the certificate, %d sends; T=%s", runAt, from, s.rounds, s.elapsed.Round(time.Millisecond), s.sends, T)
		require.Equal(t, "dead run", s.phase, "the request spanned the dead member's run")
		if gate6Timing() {
			require.LessOrEqual(t, s.elapsed, gate6DeadRun, "certified within 60 s across a single dead recovery run")
		}
		samples = append(samples, s)
		reportFive(t, "dead "+dead+", with the dead run", samples)
	}

	require.Eventually(t, func() bool { return len(c.commitsSince(c.idx(live[0]), mark)) >= minCommits }, q4bDeadline, 50*time.Millisecond, "ordinary commits go on")
	c.requireChainsAgree(live...)

	fiveReturnLeads(t, c, selector, dead, live, names)
	c.stopAll()
}

// fiveReturnLeads restarts the member, which votes, is selected again once a committed sample at the cutoff names it, and leads a committed block.
func fiveReturnLeads(t *testing.T, c *q4bLive, selector *leader.EpochReputation, member string, live, names []string) {
	t.Helper()
	returned := c.mark()
	returnedAt := c.state(live[0]).Round
	c.start(member)
	require.Eventually(t, func() bool {
		r := c.state(live[0]).Round
		for next := r + 1; next <= r+uint64(len(names)); next++ {
			if inRecoveryRun(selector, next) {
				continue
			}
			if got, err := selector.GetLeaderForRound(next); err == nil && got == c.id(member) {
				return true
			}
		}
		return false
	}, q4bDeadline, 50*time.Millisecond, "the returned member re-enters the schedule")
	// and leads a block the others commit: a normal-schedule round after its return whose committed block it authored
	led := func() uint64 {
		c.mu.Lock()
		rounds := make([]uint64, 0, len(c.chains[c.idx(live[0])]))
		for r := range c.chains[c.idx(live[0])] {
			if r > returnedAt {
				rounds = append(rounds, r)
			}
		}
		c.mu.Unlock()
		slices.Sort(rounds)
		for _, r := range rounds {
			b, err := c.nodes[c.idx(live[0])].r.manager.blockStore.Block(r)
			if err == nil && b.BlockData != nil && b.BlockData.Author == c.id(member).String() && !inRecoveryRun(selector, r) {
				return r
			}
		}
		return 0
	}
	var at uint64
	require.Eventually(t, func() bool { at = led(); return at != 0 }, q4bDeadline, 50*time.Millisecond, "the returned member leads a committed block outside a recovery run")
	t.Logf("%s returned at round %d and led the committed block of round %d", member, returnedAt, at)
	require.Eventually(t, func() bool {
		if len(c.commitsSince(c.idx(member), returned)) == 0 {
			return false
		}
		at := c.committedRound(member)
		for _, name := range live {
			if c.committedRound(name) < at {
				return false
			}
		}
		return true
	}, q4bDeadline, 50*time.Millisecond, "the returned member commits, and the others reach its round")
	c.requireChainsAgree(names...)
}

// #886 gate 6, a late failure: five members run and every sample names all five; one fails while it collects the votes of the current proposal (the
// next leader), so that round and its own fail. The active set changes once the cutoffs pass the failure: from then on the failed member leads only its
// recovery runs, shard requests certify within the normal-phase limits, and when it returns it leads a committed block again. BFT_GATE6_LATE_ALL=1
// fails each member in turn.
func TestFiveManagerLateCollectorFailure(t *testing.T) {
	names := []string{"H", "a", "b", "c", "d"}
	victims := []string{"b"}
	if os.Getenv("BFT_GATE6_LATE_ALL") != "" {
		victims = names
	}
	for _, victim := range victims {
		t.Run("fails "+victim, func(t *testing.T) {
			t.Parallel()
			q4Slot(t)
			fiveLateCollectorFailure(t, victim, names)
		})
	}
}

func fiveLateCollectorFailure(t *testing.T, victim string, names []string) {
	const requestLimit = 16
	T := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 2)) * time.Second
	c := newEqualLive(t, T, names...)
	c.start(names...)
	lag, err := rctypes.LeaderLag(uint64(len(names)))
	require.NoError(t, err)
	slot := c.nodes[0].r.manager.epochAnchor.Slot
	live := c.except(victim)
	watch := live[0]
	m := c.nodes[c.idx(watch)].r.manager
	selector, ok := m.leaderSelector.(*leader.EpochReputation)
	require.True(t, ok)
	require.Eventually(t, func() bool { return c.committedRound(watch) > slot+2*lag }, 2*q4bDeadline, 50*time.Millisecond, "all five commit past the bootstrap")

	// the failure: when the victim leads the next round of the watched node, it is the collector of the votes on the current proposal
	var failedAt uint64
	require.Eventually(t, func() bool {
		r := c.state(watch).Round
		if inRecoveryRun(selector, r) || inRecoveryRun(selector, r+1) {
			return false
		}
		cur, err1 := selector.GetLeaderForRound(r)
		next, err2 := selector.GetLeaderForRound(r + 1)
		if err1 != nil || err2 != nil || next != c.id(victim) || cur == c.id(victim) {
			return false
		}
		failedAt = r
		return true
	}, q4bDeadline, time.Millisecond, "the victim is the next leader")
	stoppedAt := time.Now()
	c.stop(victim)
	commits := c.mark()
	require.Eventually(t, func() bool { return len(c.commitsSince(c.idx(watch), commits)) > 0 && c.committedRound(watch) > failedAt }, q4bDeadline, 10*time.Millisecond, "the others commit again")
	t.Logf("%s failed as collector in round %d; next commit by round %d, %s later", victim, failedAt, c.committedRound(watch), time.Since(stoppedAt).Round(time.Millisecond))

	// the active set change: once the committed head is a lag past the failure, every cutoff of the normal schedule is a sample without the victim
	adapting := time.Now()
	require.Eventually(t, func() bool { return c.committedRound(watch) > failedAt+lag+1 }, q4bDeadline*max(1, T/(2*time.Second)), 50*time.Millisecond, "commits go past the lag")
	t.Logf("adaptation: from the failure to a committed head a lag past it, %s", time.Since(adapting).Round(time.Millisecond))
	round := c.state(watch).Round
	for r := round + 1; r <= c.committedRound(watch)+lag; r++ {
		if inRecoveryRun(selector, r) {
			continue
		}
		got, err := selector.GetLeaderForRound(r)
		require.NoError(t, err, r)
		require.NotEqual(t, c.id(victim), got, "the failed member is selected outside its recovery run after the active set changed: round %d", r)
	}
	var samples []fiveSample
	for i := range traceEnvInt(t, "BFT_GATE6_REQUESTS", 8) {
		from := c.state(watch).Round
		s := fiveRequest(t, c, live, bytes.Repeat([]byte{0xb0 + byte(i)}, 32), q4bDeadline)
		s.phase = fivePhase(selector, c.id(victim), from, c.state(watch).Round)
		if s.phase == "normal" {
			require.LessOrEqual(t, s.rounds, uint64(requestLimit), "request %d to certificate in root rounds", i)
		}
		samples = append(samples, s)
	}
	if normal := reportFive(t, "after "+victim+" failed", samples); len(normal) > 0 && gate6Timing() {
		require.LessOrEqual(t, p95(normal), gate6NormalP95)
	}
	c.requireChainsAgree(live...)
	fiveReturnLeads(t, c, selector, victim, live, names)
	c.stopAll()
}

func inRecoveryRun(s *leader.EpochReputation, round uint64) bool {
	for back := uint64(0); back < leader.RecoveryRun && back < round; back++ {
		if s.RecoveryRunStart(round - back) {
			return true
		}
	}
	return false
}
