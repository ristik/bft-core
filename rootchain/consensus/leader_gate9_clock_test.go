package consensus

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
)

// roundClock records, from one manager's view, when each round began and ended, its leader as the manager's selector named it then (an old
// round's lookup is later refused as below the coverage), and whether it ended with its own QC. It polls every
// 250 µs, so a duration is good to about half a millisecond. A round the manager passed between two polls shares the poll's interval
// with the rounds before it and is marked skipped.
type roundClock struct {
	mu     sync.Mutex
	rounds []clockRound
	stop   chan struct{}
	done   chan struct{}
}

type clockRound struct {
	round      uint64
	start, end time.Time
	certified  bool // the round was left with a QC for it: the manager's high QC had reached it
	skipped    bool
	leader     peer.ID
	known      bool // the selector named a leader when the round was seen
}

func (r clockRound) d() time.Duration { return r.end.Sub(r.start) }

func startRoundClock(m *ConsensusManager) *roundClock {
	c := &roundClock{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		lookup := func(round uint64) (peer.ID, bool) {
			id, err := m.leaderSelector.GetLeaderForRound(round)
			return id, err == nil
		}
		last, lastAt := m.pacemaker.GetCurrentRound(), time.Now()
		leaders := map[uint64]clockRound{}
		note := func(round uint64) {
			if _, ok := leaders[round]; !ok {
				id, known := lookup(round)
				leaders[round] = clockRound{leader: id, known: known}
			}
		}
		note(last)
		for {
			select {
			case <-c.stop:
				return
			case <-time.After(250 * time.Microsecond):
			}
			now := time.Now()
			round := m.pacemaker.GetCurrentRound()
			if round == last {
				continue
			}
			qc := m.blockStore.GetHighQc().GetRound()
			note(round)
			c.mu.Lock()
			for r := last; r < round; r++ {
				note(r) // a skipped round is looked up late, and may read as unknown
				l := leaders[r]
				delete(leaders, r)
				c.rounds = append(c.rounds, clockRound{round: r, start: lastAt, end: now, certified: qc >= r, skipped: round-last > 1, leader: l.leader, known: l.known})
			}
			c.mu.Unlock()
			last, lastAt = round, now
		}
	}()
	return c
}

// halt stops the clock and returns the rounds it saw end.
func (c *roundClock) halt() []clockRound {
	close(c.stop)
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.rounds)
}

// durations summarises a set of round durations: count, median, p95, p99, max, and how many reached over.
func durations(ds []time.Duration, over time.Duration) string {
	if len(ds) == 0 {
		return "none"
	}
	ds = slices.Clone(ds)
	slices.Sort(ds)
	n := 0
	for _, d := range ds {
		if d > over {
			n++
		}
	}
	q := func(p int) time.Duration { return ds[min(len(ds)-1, len(ds)*p/100)].Round(10 * time.Microsecond) }
	return fmt.Sprintf("%d rounds, median %s, p95 %s, p99 %s, max %s, %d over %s", len(ds), q(50), q(95), q(99), ds[len(ds)-1].Round(10*time.Microsecond), n, over)
}

// clockClass names a round's class as reportRho counts it.
func clockClass(r clockRound, dead peer.ID) string {
	switch {
	case r.skipped:
		return "skipped"
	case !r.known:
		return "unknown"
	case r.leader == dead:
		return "dead-led"
	case !r.certified:
		return "uncertified"
	}
	return "rho"
}

// reportRhoTail lists every rho sample over the limit with its neighbours, so a slow round can be placed: after a timeout, in or next to a
// recovery run, or among ordinary rounds (a stall on the round's own path).
func reportRhoTail(t *testing.T, rounds []clockRound, inRun map[uint64]bool, dead peer.ID, over time.Duration) {
	t.Helper()
	if len(rounds) == 0 {
		return
	}
	t0 := rounds[0].start
	for i, r := range rounds {
		if clockClass(r, dead) != "rho" || r.d() <= over {
			continue
		}
		near := ""
		for j := max(0, i-2); j <= min(len(rounds)-1, i+2); j++ {
			if j != i {
				n := rounds[j]
				near += fmt.Sprintf(" %d:%s:%s", n.round, clockClass(n, dead), n.d().Round(time.Millisecond))
			}
		}
		t.Logf("rho over %s: round %d, %s, at +%s, leader %s, in a recovery run %v; around:%s", over, r.round, r.d().Round(time.Millisecond),
			r.start.Sub(t0).Round(time.Millisecond), r.leader.ShortString(), inRun[r.round], near)
	}
}

// reportRho classifies the rounds a clock saw by their leader and outcome. rho in the design bounds a successful known-leader round, forwarding
// included: those are the rounds certified under a known live leader, recovery runs included. Rounds the dead member leads, rounds with an
// unknown leader and rounds a poll skipped are reported apart and are not rho samples.
func reportRho(t *testing.T, rounds []clockRound, runStart func(uint64) bool, dead peer.ID) {
	t.Helper()
	var rho, runs, deadLed, unknown, uncertified []time.Duration
	skipped := 0
	inRun := map[uint64]bool{}
	for _, r := range rounds {
		if runStart(r.round) {
			for i := uint64(0); i < leader.RecoveryRun; i++ {
				inRun[r.round+i] = true
			}
		}
	}
	for _, r := range rounds {
		switch {
		case r.skipped:
			skipped++
		case !r.known:
			unknown = append(unknown, r.d())
		case r.leader == dead:
			deadLed = append(deadLed, r.d())
		case !r.certified:
			uncertified = append(uncertified, r.d())
		default:
			rho = append(rho, r.d())
			if inRun[r.round] {
				runs = append(runs, r.d())
			}
		}
	}
	if len(rounds) > 0 {
		t.Logf("rho window: rounds %d to %d, %s", rounds[0].round, rounds[len(rounds)-1].round, rounds[len(rounds)-1].end.Sub(rounds[0].start).Round(time.Millisecond))
	}
	t.Logf("rho samples, certified under a known live leader: %s", durations(rho, time.Second))
	t.Logf("of those, in recovery runs: %s", durations(runs, time.Second))
	t.Logf("led by the dead member (timers, not rho): %s", durations(deadLed, time.Second))
	t.Logf("known live leader, not certified (not rho): %s", durations(uncertified, time.Second))
	t.Logf("unknown leader (not rho): %s; skipped by the poll: %d", durations(unknown, time.Second), skipped)
	reportRhoTail(t, rounds, inRun, dead, time.Second)
	// The tax of the dead member: the window's time in rounds that did not certify, against its whole time. Over a window of whole
	// cycles (a multiple of members*S rounds) it holds the same number of the dead member's runs wherever it starts.
	// The rounds a poll skipped share one interval: it counts once, and as lost if any of its rounds did not certify.
	rounds = slices.Clone(rounds)
	var lost, all time.Duration
	deadRuns := 0
	for i, r := range rounds {
		if i+1 < len(rounds) && r.skipped && rounds[i+1].skipped && rounds[i+1].start.Equal(r.start) {
			if !r.certified {
				rounds[i+1].certified = false // the interval's verdict travels to its last round, which counts it
			}
			continue
		}
		all += r.d()
		if !r.certified {
			lost += r.d()
		}
		if r.known && r.leader == dead && runStart(r.round) {
			deadRuns++
		}
	}
	if all > 0 {
		t.Logf("tax: %s of %s in rounds with no QC, %.2f%%; %d of the dead member's runs in the window", lost.Round(time.Millisecond), all.Round(time.Millisecond), 100*lost.Seconds()/all.Seconds(), deadRuns)
	}
}
