package consensus

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/rsmtbatch"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
)

// liveShard is one shard of the fixture and what its validators sign.
type liveShard struct {
	partition types.PartitionID
	shard     types.ShardID
	rsmt      bool
	batch     *rsmtbatch.Batch // an RSMT shard's populated pre-state and fresh leaves; nil is one leaf inserted next to one stored
}

func (s liveShard) String() string { return fmt.Sprintf("%d/%s", s.partition, s.shard) }

var rsmtShardParams = map[string]string{"proof_type": "aggregator_rsmt_v1"}

// traceTopology is the fixture's shards for a deployment row of the design (gate 9): the packaged TN-S's two shards and proof types, or the F8 mixed topology with its
// one-validator aggregator shards, its T2 periods and enabled RSMT proofs. The EVM shard keeps the fixture's partition number; every other shard has the deployment's.
// T2 sets the repeat phase: the EVM shard has the fixture's 2.5 s in every row, and tns's aggregator takes the same, against the package's 5 s for both.
func traceTopology(t *testing.T, name string) q3fixture.Options {
	exec := map[string]string{"proof_type": "exec"}
	left, right := types.ShardID{}.Split()
	switch name {
	case "single":
		return q3fixture.Options{}
	case "tns":
		return q3fixture.Options{Params: exec, ExtraShards: []q3fixture.ExtraShard{{Partition: 7, Validators: 1}}}
	case "f8", "f8batch":
		return q3fixture.Options{Params: exec, ExtraShards: []q3fixture.ExtraShard{
			{Partition: 9, Shard: left, Validators: 1, T2Timeout: 2500 * time.Millisecond, Params: rsmtShardParams},
			{Partition: 9, Shard: right, Validators: 1, T2Timeout: 5000 * time.Millisecond, Params: rsmtShardParams},
			{Partition: 10, Validators: 1, T2Timeout: 7500 * time.Millisecond, Params: rsmtShardParams},
		}}
	}
	require.Fail(t, "unknown topology", name)
	return q3fixture.Options{}
}

// The default-batch load row of the design: each RSMT shard holds 10,000 certified leaves and inserts 1,000 fresh ones.
const (
	defaultBatchPreLeaves = 10_000
	defaultBatchInserted  = 1_000
)

func liveShards(c *q4bLive, defaultBatch bool) []liveShard {
	out := []liveShard{{partition: q3fixture.PartitionID}}
	left, right := types.ShardID{}.Split()
	for _, conf := range c.nodes[0].r.f.ExtraConfs {
		s := liveShard{partition: conf.PartitionID, shard: conf.ShardID, rsmt: conf.PartitionParams["proof_type"] == "aggregator_rsmt_v1"}
		if s.rsmt && defaultBatch {
			keyBit := -1 // the partition's one shard has the whole key space
			switch {
			case conf.ShardID.Equal(left):
				keyBit = 0
			case conf.ShardID.Equal(right):
				keyBit = 1
			}
			s.batch = rsmtbatch.New(s.String(), keyBit, defaultBatchPreLeaves, defaultBatchInserted)
		}
		out = append(out, s)
	}
	return out
}

// shardRequest is the same pending request of a shard under the view its ingress root collects under, signed by its own validators. first is the shard's first state
// from no previous root. Otherwise an RSMT shard inserts its batch, or without one a leaf next to its stored one, with a valid envelope under the request's reference
// time, and tamper breaks it. Generating a batch's envelope here takes tens of milliseconds per shard, in the process the roots share: on that row, R is not quite
// the 0 of an immediate resubmission.
func shardRequest(t *testing.T, r *q3Replica, s liveShard, first, tamper bool) *IRChangeRequest {
	t.Helper()
	view, enabled, err := r.manager.RequestView(s.partition, s.shard)
	if err != nil || !enabled {
		return nil
	}
	tr := view.ExpectedTR()
	prev, err := view.PreviousUC()
	require.NoError(t, err)
	reference := prev.UnicitySeal.Timestamp
	hash := bytes.Repeat([]byte{0x83}, 32)
	if first {
		hash = bytes.Repeat([]byte{0x81}, 32)
	}
	var proof []byte
	if s.rsmt {
		var prev, next [32]byte
		if s.batch != nil {
			prev = s.batch.PreRoot()
			proof, next, _, err = s.batch.Envelope(reference)
			require.NoError(t, err)
		} else {
			insert := newProofTransition(t, reference)
			prev, next, proof = insert.prev, insert.next, insert.envelope
		}
		hash = next[:]
		if first {
			hash, proof = prev[:], nil
		} else if tamper {
			proof = []byte{1, 2, 3}
		}
	}
	out := &IRChangeRequest{Partition: s.partition, Shard: s.shard, Reason: Quorum}
	for _, id := range view.Context().NodeIDs() {
		signer := r.f.EVMSigners[id]
		if s.partition != q3fixture.PartitionID {
			signer = r.f.ExtraSigners[id]
		}
		bcr := &certification.BlockCertificationRequest{PartitionID: s.partition, ShardID: s.shard, NodeID: id, ZkProof: proof, InputRecord: &types.InputRecord{
			Version: 1, Epoch: tr.Epoch, RoundNumber: tr.Round, PreviousHash: view.PreviousStateHash(), Hash: hash, BlockHash: bytes.Repeat([]byte{0x82}, 32),
			SummaryValue: []byte{1}, Timestamp: reference}}
		require.NoError(t, bcr.Sign(signer))
		out.Requests = append(out.Requests, bcr)
	}
	return out
}

func shardHash(m *ConsensusManager, s liveShard) []byte {
	si := m.blockStore.ShardInfo(s.partition, s.shard)
	if si == nil || si.LastCR == nil {
		return nil
	}
	return si.LastCR.UC.InputRecord.Hash
}

// establish certifies every shard's first state, so that an RSMT shard's next request is a proved transition from a certified root and not the first-state exception.
func establish(t *testing.T, c *q4bLive, name string, shards []liveShard, submit func(name string, req *IRChangeRequest) error) {
	t.Helper()
	n := c.nodes[c.idx(name)]
	for _, s := range shards {
		before := shardHash(n.r.manager, s)
		require.Eventually(t, func() bool {
			if !bytes.Equal(shardHash(n.r.manager, s), before) {
				return true
			}
			if proof := shardRequest(t, n.r, s, true, false); proof != nil {
				_ = submit(name, proof)
			}
			return false
		}, 3*time.Minute, 200*time.Millisecond, "shard %s", s)
	}
}

// The fixture's extra shards are real, on the F8 topology of a live epoch: each takes its own validators' first state and gets its own certificate; then each RSMT shard's
// insertion with a valid envelope is judged by the enabled verifier and certified, and a broken envelope is refused for its proof.
func TestExtraShardsAreCertifiedOnALiveEpoch(t *testing.T) {
	c := newEqualLiveOptions(t, 2*time.Second, traceTopology(t, "f8"), "H", "a", "b", "c")
	c.start(c.all()...)
	c.warm(3, c.all()...)
	shards := liveShards(c, false)
	require.Len(t, shards, 4)
	establish(t, c, "H", shards, func(name string, req *IRChangeRequest) error {
		return c.nodes[c.idx(name)].r.manager.RequestCertification(context.Background(), *req)
	})
	n := c.nodes[c.idx("H")]
	for _, s := range shards {
		if !s.rsmt {
			continue
		}
		view, enabled, err := n.r.manager.RequestView(s.partition, s.shard)
		require.NoError(t, err)
		require.True(t, enabled)
		pdr, err := view.PDR() // what VerifyIRChangeReqView judges under
		require.NoError(t, err)
		verifier, err := zkverifier.NewRegistry().GetVerifier(s.partition, s.shard, view.ExpectedTR().Epoch, pdr.GetPartitionParams())
		require.NoError(t, err)
		require.Equal(t, zkverifier.ProofTypeAggregatorRSMTv1, verifier.ProofType(), s)
		require.True(t, verifier.IsEnabled(), s)
		established := shardHash(n.r.manager, s)
		tampered := false
		require.Eventually(t, func() bool {
			if !bytes.Equal(shardHash(n.r.manager, s), established) {
				return true
			}
			if broken := shardRequest(t, n.r, s, false, true); broken != nil && !tampered {
				verdict, err := n.r.manager.judgeRetained(&drctypes.IRChangeReq{Partition: s.partition, Shard: s.shard, CertReason: drctypes.Quorum, Requests: broken.Requests})
				tampered = verdict == retainedRefused && errors.Is(err, ErrProofInvalid) && errors.Is(err, zkverifier.ErrInvalidProofFormat)
			}
			if proof := shardRequest(t, n.r, s, false, false); proof != nil {
				_ = n.r.manager.RequestCertification(context.Background(), *proof)
			}
			return false
		}, 3*time.Minute, 200*time.Millisecond, "shard %s", s)
		require.True(t, tampered, "a broken envelope was refused for its proof: %s", s)
	}
}

// traceCounters, when a measurement patch sets it, reports the judging and proof-verification work so far.
var traceCounters func() string

func traceEnvInt(t *testing.T, name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	require.NoError(t, err, name)
	return n
}

// #886 gate 9, a real multi-shard rescue: one rolling restart with every survivor holding one real request per shard of a deployment topology (traceTopology), signed by
// the shard's own validators, each from an established certified state. It reports what happened, window by window, not a per-round mean multiplied up: the unknown-leader window's total and its stalls, the
// first known and recovery rounds after it, the first commit, the deferred work behind it, and each shard's fresh request and certificate. Measurement only: it asserts
// no number. Four roots share one machine. Set TMPDIR to the disk being measured. BFT_GATE9_TRACE=1; BFT_TRACE_TOPOLOGY single, tns, f8 or f8batch, f8 with the default batch (single); BFT_TRACE_DEAD member index by
// id order (0: the first recovery run is the dead member's); BFT_TRACE_T seconds (10). BFT_TRACE_TRANSPORT=libp2p runs it on the production network: see liveTransport.
func TestGate9RescueTraceWithRealShards(t *testing.T) {
	if os.Getenv("BFT_GATE9_TRACE") == "" {
		t.Skip("set BFT_GATE9_TRACE=1: a measurement, not a regression test")
	}
	T := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 10)) * time.Second
	topology := cmp.Or(os.Getenv("BFT_TRACE_TOPOLOGY"), "single")
	deadAt := traceEnvInt(t, "BFT_TRACE_DEAD", 0)
	options := traceTopology(t, topology)
	var transport *liveTransport
	var setup func(*q4bLive)
	if os.Getenv("BFT_TRACE_TRANSPORT") == "libp2p" {
		options.PeerEVM = true
		transport = newLiveTransport(t)
		setup = transport.install
	}
	c := newEqualLiveOn(t, T, options, setup, "H", "a", "b", "c")
	submit := func(name string, req *IRChangeRequest) error {
		return c.nodes[c.idx(name)].r.manager.RequestCertification(context.Background(), *req)
	}
	if transport != nil {
		transport.addShards(c.nodes[0].r.f)
		submit = transport.submit
	}
	shards := liveShards(c, topology == "f8batch")
	lag := 4*uint64(len(c.nodes)) + 4
	names := c.all()
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(c.id(a).String(), c.id(b).String()) })
	d, x := names[deadAt%4], names[(deadAt+1)%4]
	// every forward of a retained request, by the round the watched node is in: the delivery premise of a recovery run is that a request reaches its leader before the run
	var forwardsMu sync.Mutex
	forwards := map[string][]uint64{}
	var currentRound func() uint64
	tapForward := func(msg any) {
		if m, ok := msg.(*abdrc.IrChangeReqMsg); ok {
			forwardsMu.Lock()
			if currentRound != nil {
				key := liveShard{partition: m.IrChangeReq.Partition, shard: m.IrChangeReq.Shard}.String()
				forwards[key] = append(forwards[key], currentRound())
			}
			forwardsMu.Unlock()
		}
	}
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		tapForward(msg)
		return base(from, to, msg)
	}
	first := c.except(x)
	if transport != nil {
		transport.tap = tapForward
		transport.up(c, first...)
	}
	c.start(first...)
	anchor := c.nodes[0].r.manager.epochAnchor.Slot
	require.Eventually(t, func() bool { // at T = 10 s the down member costs about two timers a cycle
		for _, name := range first {
			if c.committedRound(name) < anchor+lag+2 {
				return false
			}
		}
		return true
	}, 15*time.Minute, 50*time.Millisecond, "the cluster commits live in the activated epoch")
	establish(t, c, first[0], shards, submit)
	survivors := c.except(x, d)
	watch := survivors[0]
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	known := func(round uint64) bool {
		_, err := m(watch).leaderSelector.GetLeaderForRound(round)
		return err == nil
	}
	seal := func(p liveShard) uint64 {
		si := m(watch).blockStore.ShardInfo(p.partition, p.shard)
		if si == nil || si.LastCR == nil {
			return 0
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
	}
	require.Eventually(t, func() bool { // what the node watched reads as established is what establish saw, or a shard would later read as certified with no request sent
		for _, s := range shards {
			if !bytes.Equal(shardHash(m(watch), s), shardHash(m(first[0]), s)) {
				return false
			}
		}
		return true
	}, 2*time.Minute, 5*time.Millisecond, "the watched node holds the established states")
	c.stop(d)
	if transport != nil {
		transport.down(c, d)
		transport.up(c, x)
	}
	c.start(x)
	t0 := time.Now()
	since := func() time.Duration { return time.Since(t0).Round(time.Millisecond) }
	forwardsMu.Lock()
	currentRound = func() uint64 { return m(watch).pacemaker.GetCurrentRound() }
	forwardsMu.Unlock()
	counters := func(label string) {
		if traceCounters != nil {
			t.Logf("counters at %s: %s", label, traceCounters())
		}
	}
	for _, s := range shards {
		proof := shardRequest(t, c.nodes[c.idx(watch)].r, s, false, false)
		require.NotNil(t, proof, s)
		t.Logf("shard %s: rsmt %v, %d signers, proof %d bytes", s, s.rsmt, len(proof.Requests), len(proof.Requests[0].ZkProof))
		if s.batch != nil {
			reference := proof.Requests[0].InputRecord.Timestamp
			_, _, stats, err := s.batch.Envelope(reference)
			require.NoError(t, err)
			verifier := &zkverifier.AggregatorRSMTVerifier{}
			at := time.Now()
			require.NoError(t, verifier.VerifyProofAt(proof.Requests[0].ZkProof, proof.Requests[0].InputRecord.PreviousHash, proof.Requests[0].InputRecord.Hash, nil, reference))
			t.Logf("shard %s: batch %+v; one verification alone %s", s, stats, time.Since(at).Round(10*time.Microsecond))
		}
	}
	established := map[string][]byte{}
	for _, s := range shards {
		established[s.String()] = shardHash(m(watch), s)
	}
	startRound, startCommit := c.state(watch).Round, c.committedRound(watch)
	t.Logf("T=%s, topology %s, %s, dead index %d, start round %d, committed %d, stopped %s", T, topology, shards, deadAt, startRound, startCommit, d)

	type sample struct {
		round uint64
		d     time.Duration
		known bool
	}
	var samples []sample
	lastRound, roundAt, lastKnown := startRound, t0, known(startRound)
	var unknownFrom, firstKnownAfter, commitAt time.Time
	var lastEdge uint64
	var unknownRound, firstKnownRound, commitRound, commitAtUnknown uint64
	sentUnder := map[string]uint64{}
	sendRounds := map[string][]uint64{}
	certAt := map[string]time.Duration{}
	send := func(p liveShard, round uint64) {
		accepted := false
		for _, name := range survivors {
			if proof := shardRequest(t, c.nodes[c.idx(name)].r, p, false, false); proof != nil && submit(name, proof) == nil {
				accepted = true
			}
		}
		if accepted {
			sentUnder[p.String()] = seal(p)
			sendRounds[p.String()] = append(sendRounds[p.String()], round)
		}
	}
	deadline := t0.Add(40 * time.Minute)
	progressAt := t0
	for len(certAt) < len(shards) {
		require.True(t, time.Now().Before(deadline), "%d of %d certified in 40 minutes", len(certAt), len(shards))
		now := time.Now()
		st := c.state(watch)
		if st.Round != lastRound {
			gap := now.Sub(roundAt) / time.Duration(st.Round-lastRound)
			for r := lastRound; r < st.Round; r++ {
				samples = append(samples, sample{r, gap, lastKnown})
			}
			lastRound, roundAt, lastKnown = st.Round, now, known(st.Round)
		}
		if !lastKnown && st.Round != lastEdge && known(st.Round+1) && !unknownFrom.IsZero() {
			lastEdge = st.Round
			t.Logf("round %d at %s: its leader unknown, the next known", st.Round, since())
			counters("that round's start")
		}
		if !lastKnown && unknownFrom.IsZero() {
			unknownFrom, unknownRound, commitAtUnknown = now, st.Round, c.committedRound(watch)
			t.Logf("first unknown round %d at %s, %d rounds after the stop", unknownRound, since(), unknownRound-startRound)
			counters("the first unknown round")
		}
		if lastKnown && !unknownFrom.IsZero() && firstKnownAfter.IsZero() {
			firstKnownAfter, firstKnownRound = now, st.Round
			t.Logf("first known round after that %d at %s: unknown window total %s over %d rounds", firstKnownRound, since(), now.Sub(unknownFrom).Round(time.Millisecond), firstKnownRound-unknownRound)
			counters("the first known round")
		}
		if !unknownFrom.IsZero() && commitAt.IsZero() && c.committedRound(watch) != commitAtUnknown {
			commitAt, commitRound = now, st.Round
			t.Logf("first commit after that at round %d, %s: unknown-to-commit %s over %d rounds", commitRound, since(), now.Sub(unknownFrom).Round(time.Millisecond), commitRound-unknownRound)
			counters("the first commit")
		}
		for _, p := range shards {
			if _, done := certAt[p.String()]; done {
				continue
			}
			if !bytes.Equal(shardHash(m(watch), p), established[p.String()]) {
				certAt[p.String()] = time.Since(t0)
				continue
			}
			if !unknownFrom.IsZero() && (len(sendRounds[p.String()]) == 0 || seal(p) != sentUnder[p.String()]) {
				send(p, st.Round)
			}
		}
		if !commitAt.IsZero() && time.Since(progressAt) > 30*time.Second {
			progressAt = time.Now()
			for _, p := range shards {
				_, done := certAt[p.String()]
				t.Logf("progress %s at round %d: %s certified %v, seal %d, sent under %d, sends at rounds %v", since(), st.Round, p, done, seal(p), sentUnder[p.String()], sendRounds[p.String()])
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	end := time.Now()
	counters("the last certificate")
	if transport != nil {
		transport.reportDelivery(t0, shards, func(s liveShard) []byte { return shardHash(m(watch), s) })
	}
	require.False(t, unknownFrom.IsZero(), "no unknown round")
	require.False(t, commitAt.IsZero(), "no commit")

	// Window totals, then what they are made of. Rounds taking more than T/2 ran a timer; other rounds over stallAt are stalls.
	const stallAt = 200 * time.Millisecond
	var fast []time.Duration
	var stalls []sample
	var timers, unknownTimers, knownFast int
	var timerSum, unknownSum, stallSum time.Duration
	for _, s := range samples {
		switch {
		case s.d > T/2:
			timers++
			timerSum += s.d
			if !s.known {
				unknownTimers++
			}
		case s.known:
			knownFast++
		default:
			fast = append(fast, s.d)
			unknownSum += s.d
			if s.d > stallAt {
				stalls = append(stalls, s)
				stallSum += s.d
			}
		}
	}
	slices.Sort(fast)
	t.Logf("all %d rounds: %d timers %s (%d in unknown rounds), %d known fast; %d unknown fast %s, median %s, p95 %s, p99 %s, max %s", len(samples), timers, timerSum.Round(time.Millisecond), unknownTimers, knownFast,
		len(fast), unknownSum.Round(time.Millisecond), fast[len(fast)/2].Round(10*time.Microsecond), fast[len(fast)*95/100].Round(10*time.Microsecond), fast[len(fast)*99/100].Round(10*time.Microsecond), fast[len(fast)-1].Round(10*time.Microsecond))
	slices.SortFunc(stalls, func(a, b sample) int { return cmp.Compare(b.d, a.d) })
	var worst []string
	for _, s := range stalls[:min(len(stalls), 5)] {
		worst = append(worst, fmt.Sprintf("%d:%s", s.round, s.d.Round(time.Millisecond)))
	}
	t.Logf("stalls over %s among unknown fast rounds: %d, %s in all, worst round:duration %s", stallAt, len(stalls), stallSum.Round(time.Millisecond), strings.Join(worst, " "))
	var after []string
	for _, s := range samples {
		if s.round+3 >= firstKnownRound && s.round < firstKnownRound+8 || s.round+3 >= commitRound && s.round < commitRound+8 {
			after = append(after, fmt.Sprintf("%d:%v:%s", s.round, s.known, s.d.Round(time.Millisecond)))
		}
	}
	t.Logf("rounds from the first known (%d) and the first commit (%d), round:known:duration: %s", firstKnownRound, commitRound, strings.Join(after, " "))
	var resend []uint64
	sends := 0
	var certs []time.Duration
	for _, p := range shards {
		forwardsMu.Lock()
		sent := slices.DeleteFunc(slices.Clone(forwards[p.String()]), func(r uint64) bool { return r+3 < firstKnownRound || (r > firstKnownRound+8 && r+3 < commitRound) })
		forwardsMu.Unlock()
		t.Logf("shard %s: sends at rounds %v, certified %s after the stop; forwards around the first known round and the first commit at rounds %v", p, sendRounds[p.String()], certAt[p.String()].Round(time.Millisecond), sent)
		sends += len(sendRounds[p.String()])
		if n := len(sendRounds[p.String()]); n > 1 {
			resend = append(resend, max(sendRounds[p.String()][n-1], commitRound)-commitRound) // the poll can see a new seal before the new commit
		}
		certs = append(certs, certAt[p.String()])
	}
	slices.Sort(resend)
	slices.Sort(certs)
	if len(resend) > 0 {
		t.Logf("R as this harness resubmits, on seeing a new seal, so not a real shard's reaction; rounds from the first commit to a shard's fresh request: %d of %d shards resubmitted, min %d, median %d, max %d", len(resend), len(shards), resend[0], resend[len(resend)/2], resend[len(resend)-1])
	}
	t.Logf("certified: first shard %s, median %s, last %s after the stop; from the first commit to the last certificate %s over %d rounds; stop to last certificate %d rounds, %d sends", certs[0].Round(time.Millisecond), certs[len(certs)/2].Round(time.Millisecond),
		certs[len(certs)-1].Round(time.Millisecond), end.Sub(commitAt).Round(time.Millisecond), c.state(watch).Round-commitRound, c.state(watch).Round-startRound, sends)
}
