package consensus

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #886's last check before closure (arch, 2026-11-08): five roots on the production path (liveTransport: libp2p over same-host TCP, the root
// node's ingress, durable stores), T = 10 s, production's 900 ms block rate, the F8 topology with its default-batch proof load. For each dead
// placement, two complete windows of one whole cycle of the schedule (members × S rounds) each:
//  1. one member absent from the start, so the cycle holds every live member's recovery run and the absent member's own;
//  2. a rolling restart: the absent member returns as the next one by id order stops (the gate 9 rescue shape, at five roots).
//
// Through both windows every shard keeps a request of its own going over its shard network: the EVM shard sends its next as soon as its
// validators receive the last certificate, a batch shard (1,000 leaves inserted into its certified tree, about 212 KB) BFT_GATE9_FIVE_BATCH_S
// after it, and a request goes again, rebuilt, when the roots certify a T2 repeat of the shard first. A window stops making requests at its last
// round and waits for those in flight, so it is complete.
//
// It reports root progress (rounds, commits, rho, an unknown-leader window and its first commit) apart from fresh certification (each request from
// its first send to the first validator of the shard receiving its certificate), labelled by the root rounds it spans (normal, live run, dead run,
// restart: begun before the adaptation after the stop is over) and unconditionally. BFT_GATE6_TIMING=1 asserts the design's targets: normal p95 <= 6 s,
// <= 60 s across a dead run, the unknown-leader window to its commit <= 75 s, every shard's first fresh certificate after the stop <= 360 s.
//
// BFT_GATE9_FIVE=1; BFT_GATE9_FIVE_ALL=1 runs each placement in turn, otherwise BFT_TRACE_DEAD (an index by id order); BFT_TRACE_T seconds (10),
// BFT_TRACE_BLOCK_RATE_MS (900), BFT_TRACE_TOPOLOGY (f8batch; tns and single also run), BFT_GATE9_FIVE_BATCH_S (20), BFT_GATE9_FIVE_ROUNDS (a whole cycle; less for a smoke run). About 28 minutes a placement (8,354 s for all five on the 8 Nov host).
// The roots, the shard validators and the request generator share one process on one machine: single-host evidence, not separate hosts or a WAN.
func TestGate9FiveRootsOnLibp2p(t *testing.T) {
	if os.Getenv("BFT_GATE9_FIVE") == "" {
		t.Skip("set BFT_GATE9_FIVE=1: a measurement of about 28 minutes a placement")
	}
	names := []string{"H", "a", "b", "c", "d"}
	placements := []int{traceEnvInt(t, "BFT_TRACE_DEAD", 0)}
	if os.Getenv("BFT_GATE9_FIVE_ALL") != "" {
		placements = []int{0, 1, 2, 3, 4}
	}
	for _, at := range placements {
		t.Run(fmt.Sprintf("dead %d", at), func(t *testing.T) { fiveOnLibp2p(t, names, at) })
	}
}

// fiveFlow is one shard's run of requests.
type fiveFlow struct {
	s       liveShard
	seen    int               // the shard's receipts read so far
	pending bool              // a request is out
	sent    map[string]uint64 // the pending request's hashes, each with its reference time: a rebuilt request has another
	hash    []byte            // the latest of them
	under   uint64            // the root round of the certificate the latest was built on
	firstAt time.Time
	from    uint64 // the watched root's round at the first send
	sends   int
	certAt  time.Time // when its last certificate was received
	n       int       // the EVM shard's requests, for their hashes
	logged  bool
}

type flowSample struct {
	fiveSample
	shard    string
	from, to uint64
}

func fiveOnLibp2p(t *testing.T, names []string, deadAt int) {
	T := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 10)) * time.Second
	blockRate := time.Duration(traceEnvInt(t, "BFT_TRACE_BLOCK_RATE_MS", 900)) * time.Millisecond
	batchEvery := time.Duration(traceEnvInt(t, "BFT_GATE9_FIVE_BATCH_S", 20)) * time.Second
	topology := cmp.Or(os.Getenv("BFT_TRACE_TOPOLOGY"), "f8batch")
	options := traceTopology(t, topology)
	options.PeerEVM = true
	transport := newLiveTransport(t)
	c := newEqualLiveRate(t, T, blockRate, options, transport.install, names...)
	transport.addShards(c.nodes[0].r.f)
	ids := c.all()
	slices.SortFunc(ids, func(a, b string) int { return strings.Compare(c.id(a).String(), c.id(b).String()) })
	x, d := ids[deadAt%len(ids)], ids[(deadAt+1)%len(ids)]
	first := c.except(x)
	transport.up(c, first...)
	c.start(first...)
	lag, err := rctypes.LeaderLag(uint64(len(names)))
	require.NoError(t, err)
	slot := c.nodes[0].r.manager.epochAnchor.Slot
	require.Eventually(t, func() bool {
		for _, name := range first {
			if c.committedRound(name) < slot+2*lag+uint64(len(names)) {
				return false
			}
		}
		return true
	}, 30*time.Minute, 50*time.Millisecond, "the four commit past the bootstrap and the aging")
	shards := liveShards(c, topology == "f8batch")
	for _, s := range shards {
		require.False(t, s.rsmt && s.batch == nil, "an RSMT shard without a batch has no chain of transitions: use f8batch")
	}
	establish(t, c, first[0], shards, transport.submit)
	watch := c.except(x, d)[0]
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	selector, ok := m(watch).leaderSelector.(*leader.EpochReputation)
	require.True(t, ok, "the epoch runs the reputation schedule")
	cycle := uint64(traceEnvInt(t, "BFT_GATE9_FIVE_ROUNDS", len(names)*leader.RecoverySpacing)) // shorter only for a smoke run: then the windows are not whole cycles
	t.Logf("T=%s, block rate %s, topology %s, shards %v, batch every %s; absent %s, then %s stops as it returns; watched %s; cycle %d rounds",
		T, blockRate, topology, shards, batchEvery, x, d, watch, cycle)

	flows := make([]*fiveFlow, len(shards))
	for i, s := range shards {
		flows[i] = &fiveFlow{s: s, seen: len(transport.receipts(s, 0))}
	}
	lastCR := func(f *fiveFlow) (uint64, []byte) {
		si := m(watch).blockStore.ShardInfo(f.s.partition, f.s.shard)
		if si == nil || si.LastCR == nil {
			return 0, nil
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber, si.LastCR.UC.InputRecord.Hash
	}
	// send builds the shard's request under the watched root's view and sends it to every root up; fresh is a new transition, otherwise the
	// pending one rebuilt under a newer certificate. It reports whether it sent: the view may not have reached the shard's last certificate yet.
	send := func(f *fiveFlow, up []string, fresh bool) bool {
		r := c.nodes[c.idx(watch)].r
		view, enabled, err := r.manager.RequestView(f.s.partition, f.s.shard)
		if err != nil || !enabled {
			return false
		}
		prev, err := view.PreviousUC()
		require.NoError(t, err)
		reference := prev.UnicitySeal.Timestamp
		var hash, proof []byte
		if f.s.batch != nil {
			if pre := f.s.batch.PreRoot(); !bytes.Equal(view.PreviousStateHash(), pre[:]) {
				return false
			}
			at := time.Now()
			env, next, stats, err := f.s.batch.Envelope(reference)
			require.NoError(t, err)
			if !f.logged {
				f.logged = true
				t.Logf("shard %s: batch %+v, built in %s", f.s, stats, time.Since(at).Round(10*time.Microsecond))
			}
			hash, proof = next[:], env
		} else {
			if _, last := lastCR(f); fresh && f.hash != nil && !bytes.Equal(last, f.hash) {
				return false // the watched root has not yet stored the certificate the shard received
			}
			if fresh {
				f.n++
			}
			h := sha256.Sum256(fmt.Appendf(nil, "%s %d", f.s, f.n))
			hash = h[:]
		}
		req := signedShardRequest(t, r, f.s, view, hash, proof, reference)
		for _, name := range up {
			_ = transport.submit(name, req) // asynchronous: delivery is read at the shard's validators
		}
		if fresh {
			f.sent = map[string]uint64{}
			f.firstAt, f.from, f.sends, f.pending = time.Now(), c.state(watch).Round, 0, true
		}
		f.sent[string(hash)], f.hash, f.under = reference, hash, prev.UnicitySeal.RootChainRoundNumber
		f.sends++
		return true
	}

	// window runs one complete window from now: requests until the watched root reaches its last round, then the ones in flight
	window := func(label, dead string, up []string, stopRound uint64, returned string) uint64 {
		t.Helper()
		start := time.Now()
		mark := c.mark()
		from := c.state(watch).Round
		last := from + cycle
		clock := startRoundClock(m(watch))
		known := func(round uint64) bool {
			_, err := m(watch).leaderSelector.GetLeaderForRound(round)
			return err == nil
		}
		var samples []flowSample
		firstCert := map[string]time.Duration{}
		var unknownAt, commitAt time.Time
		var unknownRound, commitRound, committedAtUnknown uint64
		var settledRound uint64 // the restart's adaptation ends here: the commit after an unknown-leader window, or with none, 3 lags after the stop
		if stopRound == 0 {
			settledRound = from // a window with no stop has no restart phase
		}
		deadline := start.Add(steadyDeadline(T, cycle))
		var led uint64 // the first committed block the returned member authored outside a recovery run: read while the store still holds it
		var ledLook time.Time
		for {
			now := time.Now()
			require.True(t, now.Before(deadline), "%s: the window did not complete", label)
			st := c.state(watch)
			if !known(st.Round) && unknownAt.IsZero() {
				unknownAt, unknownRound, committedAtUnknown = now, st.Round, st.Committed
				t.Logf("%s: first unknown-leader round %d at %s", label, unknownRound, now.Sub(start).Round(time.Millisecond))
			}
			if !unknownAt.IsZero() && commitAt.IsZero() && st.Committed != committedAtUnknown {
				commitAt, commitRound = now, st.Round
				t.Logf("%s: first commit after it at round %d: unknown-to-commit %s over %d rounds", label, commitRound, now.Sub(unknownAt).Round(time.Millisecond), commitRound-unknownRound)
			}
			if settledRound == 0 && (!commitAt.IsZero() || unknownAt.IsZero() && st.Round > stopRound+3*lag) {
				settledRound = st.Round
				t.Logf("%s: adaptation over at round %d, %s after the stop", label, st.Round, now.Sub(start).Round(time.Millisecond))
			}
			if returned != "" && led == 0 && now.Sub(ledLook) > time.Second {
				ledLook, led = now, ledCommit(c, selector, returned, watch, stopRound)
				if led != 0 {
					t.Logf("%s: %s returned at round %d and led the committed block of round %d", label, returned, stopRound, led)
				}
			}
			open := false
			for _, f := range flows {
				for _, rc := range transport.receipts(f.s, f.seen) {
					f.seen++
					reference, ours := f.sent[string(rc.hash)]
					// Only the first receipt of a pending request is a sample. A later T2 repeat of a certificate already ours also matches f.sent,
					// but by then the request is no longer pending, so it is skipped here.
					if !f.pending || !ours {
						continue
					}
					s := flowSample{shard: f.s.String(), from: f.from, to: rc.seal}
					s.elapsed, s.rounds, s.sends = rc.at.Sub(f.firstAt), rc.seal-min(rc.seal, f.from), f.sends
					s.phase = fivePhase(selector, c.id(dead), f.from, rc.seal)
					if settledRound == 0 || f.from < settledRound {
						s.phase = "restart"
					}
					samples = append(samples, s)
					if _, ok := firstCert[f.s.String()]; !ok {
						firstCert[f.s.String()] = rc.at.Sub(start)
					}
					f.pending, f.certAt = false, rc.at
					if f.s.batch != nil {
						f.s.batch = f.s.batch.Next(reference)
					}
				}
				switch {
				case f.pending:
					open = true
					require.Less(t, time.Since(f.firstAt), 10*time.Minute, "%s: shard %s request from round %d, %d sends, not certified", label, f.s, f.from, f.sends)
					if seal, hash := lastCR(f); seal > f.under {
						if _, ours := f.sent[string(hash)]; !ours {
							send(f, up, false) // a T2 repeat certified first: the shard rebuilds its request under it
						}
					}
				case st.Round < last && (f.s.batch == nil || time.Since(f.certAt) >= batchEvery):
					send(f, up, true)
				}
			}
			if st.Round >= last && !open {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		rounds := clock.halt()
		end := c.state(watch)
		t.Logf("%s: rounds %d to %d (%d) in %s; %d commits at %s, committed head %d; samples %d", label, from, end.Round, end.Round-from,
			time.Since(start).Round(time.Millisecond), len(c.commitsSince(c.idx(watch), mark)), watch, end.Committed, len(samples))
		reportRho(t, rounds, selector.RecoveryRunStart, c.id(dead))
		var plain []fiveSample
		for _, s := range samples {
			plain = append(plain, s.fiveSample)
		}
		reportFive(t, label, plain)
		for _, f := range flows {
			var mine []fiveSample
			for _, s := range samples {
				if s.shard == f.s.String() {
					mine = append(mine, s.fiveSample)
				}
			}
			t.Logf("%s, shard %s: %d requests, first certificate received %s into the window; unconditional %s", label, f.s, len(mine),
				firstCert[f.s.String()].Round(time.Millisecond), durations(durationsOf(mine), gate6NormalP95))
		}
		if gate6Timing() {
			var normal []time.Duration
			for _, s := range samples {
				switch s.phase {
				case "normal":
					normal = append(normal, s.elapsed)
				case "dead run":
					require.LessOrEqual(t, s.elapsed, gate6DeadRun, "%s: shard %s from round %d certified within 60 s across a dead run", label, s.shard, s.from)
				case "restart":
					// a request begun before the adaptation after the stop is over spans the stopped member's timed-out rounds: the dead-run bound
					require.LessOrEqual(t, s.elapsed, gate6DeadRun, "%s: shard %s from round %d certified within 60 s across the rolling restart", label, s.shard, s.from)
				}
			}
			require.NotEmpty(t, normal, label)
			require.LessOrEqual(t, p95(normal), gate6NormalP95, "%s: request to certificate p95 outside adaptation and recovery runs", label)
			if stopRound != 0 {
				if !unknownAt.IsZero() {
					require.False(t, commitAt.IsZero(), "%s: a commit after the unknown-leader window", label)
					require.LessOrEqual(t, commitAt.Sub(unknownAt), 75*time.Second, "%s: unknown-leader window to its commit", label)
				}
				for _, f := range flows {
					require.LessOrEqual(t, firstCert[f.s.String()], 360*time.Second, "%s: shard %s's first fresh certificate after the stop", label, f.s)
				}
			}
		}
		return led
	}

	window(fmt.Sprintf("absent %s", x), x, first, 0, "")
	stopRound := c.state(watch).Round
	c.stop(d)
	transport.down(c, d)
	transport.up(c, x)
	c.start(x)
	t.Logf("rolling restart at round %d: %s stopped, %s started", stopRound, d, x)
	at := window(fmt.Sprintf("restart, %s back, %s down", x, d), d, c.except(d), stopRound, x)
	require.NotZero(t, at, "the returned member %s led a committed block outside a recovery run within the window", x)
	c.requireChainsAgree(c.except(d)...)
	c.stopAll()
}

func durationsOf(samples []fiveSample) []time.Duration {
	out := make([]time.Duration, len(samples))
	for i, s := range samples {
		out[i] = s.elapsed
	}
	return out
}
