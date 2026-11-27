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
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/rsmtbatch"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
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
	return signedShardRequest(t, r, s, view, hash, proof, reference)
}

// signedShardRequest is the request of every validator of the shard for the transition to hash under the view, each signed with its own key.
func signedShardRequest(t *testing.T, r *q3Replica, s liveShard, view *storage.RequestRoundView, hash, proof []byte, reference uint64) *IRChangeRequest {
	t.Helper()
	tr := view.ExpectedTR()
	out := &IRChangeRequest{RootEpoch: r.manager.InstalledRootEpoch(), Partition: s.partition, Shard: s.shard, Reason: Quorum}
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
	hash, _ := watchedShardCertificate(m, s)
	return hash
}

func watchedShardCertificate(m *ConsensusManager, s liveShard) (hash []byte, round uint64) {
	si := m.blockStore().ShardInfo(s.partition, s.shard)
	if si == nil || si.LastCR == nil {
		return nil, 0
	}
	if seal := si.LastCR.UC.UnicitySeal; seal != nil {
		round = seal.RootChainRoundNumber
	}
	return si.LastCR.UC.InputRecord.Hash, round
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
// id order (0: the first recovery run is the dead member's); BFT_TRACE_T seconds (10); BFT_TRACE_BLOCK_RATE_MS (454; production's default is 900). BFT_TRACE_TRANSPORT=libp2p runs it on the
// production network: see liveTransport. BFT_TRACE_STEADY rounds after the last certificate measure rho.
func TestGate9RescueTraceWithRealShards(t *testing.T) {
	if os.Getenv("BFT_GATE9_TRACE") == "" {
		t.Skip("set BFT_GATE9_TRACE=1: a measurement, not a regression test")
	}
	gate9RescueTrace(t, 4)
}

func gate9RescueTrace(t *testing.T, members int) {
	t.Helper()
	T := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 10)) * time.Second
	larger := members > 4
	defaultTopology, defaultBlockRate := "single", phaseLockBlockRate
	if larger {
		defaultTopology, defaultBlockRate = "f8batch", 900*time.Millisecond
	}
	topology := cmp.Or(os.Getenv("BFT_TRACE_TOPOLOGY"), defaultTopology)
	deadAt := traceEnvInt(t, "BFT_TRACE_DEAD", 0)
	options := traceTopology(t, topology)
	var transport *liveTransport
	var setup func(*q4bLive)
	if os.Getenv("BFT_TRACE_TRANSPORT") == "libp2p" {
		options.PeerEVM = true
		transport = newLiveTransport(t)
		setup = transport.install
	}
	blockRate := time.Duration(traceEnvInt(t, "BFT_TRACE_BLOCK_RATE_MS", int(defaultBlockRate/time.Millisecond))) * time.Millisecond
	labels := []string{"H", "a", "b", "c"}
	if larger {
		labels = rootTimingNames(members)
		options.SameCommitteeGenesis = true
	}
	c := newEqualLiveRate(t, T, blockRate, options, setup, labels...)
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
	d, x := names[deadAt%members], names[(deadAt+1)%members]
	dead, returning := []string{d}, []string{x}
	exactQuorum := larger && os.Getenv("BFT_973_EXACT_QUORUM") == "1"
	if larger {
		b := (members - 1) / 3
		oldVoters := 3 * b
		if exactQuorum {
			// Every old QC must carry this whole set, so a collector
			// cannot select a different quorum subset with a live triple.
			oldVoters = int(c.nodes[0].r.f.Body.RootThreshold)
		}
		returning = names[oldVoters:]
		dead = nil
		// Spread the b stops so the complete old voter table has at
		// most two consecutive survivors, including across its wrap.
		for i := 0; i < b; i++ {
			dead = append(dead, names[i*oldVoters/b])
		}
		d = dead[0]
		requireTimingQuorum(t, c, c.except(returning...))
		requireTimingQuorum(t, c, c.except(dead...))
		t.Logf("NodeID order %v, unit weights, exact old quorum %v", names, exactQuorum)
	}
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
	first := c.except(returning...)
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
	survivors := c.except(append(slices.Clone(returning), dead...)...)
	watch := survivors[0]
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	known := func(round uint64) bool {
		_, err := m(watch).leaderSelector.GetLeaderForRound(round)
		return err == nil
	}
	seal := func(p liveShard) uint64 {
		_, round := watchedShardCertificate(m(watch), p)
		return round
	}
	require.Eventually(t, func() bool { // what the node watched reads as established is what establish saw, or a shard would later read as certified with no request sent
		for _, s := range shards {
			if !bytes.Equal(shardHash(m(watch), s), shardHash(m(first[0]), s)) {
				return false
			}
		}
		return true
	}, 2*time.Minute, 5*time.Millisecond, "the watched node holds the established states")
	if larger {
		reportRecoveryCycle(t, m(watch), c, names)
	}
	var t0 time.Time
	since := func() time.Duration { return time.Since(t0).Round(time.Millisecond) }
	counters := func(label string) {
		if traceCounters != nil {
			t.Logf("counters at %s: %s", label, traceCounters())
		}
	}
	type sample struct {
		round uint64
		d     time.Duration
		known bool
	}
	var samples []sample
	var startRound, lastRound uint64
	var roundAt time.Time
	var lastKnown bool
	var unknownFrom, firstKnownAfter, commitAt time.Time
	var lastEdge uint64
	var unknownRound, firstKnownRound, commitRound, commitAtUnknown uint64
	var rescueMiss bool
	var rescueWindow rescueTimingWindow
	var end time.Time
	var committedAfterUnknown atomic.Bool
	committed := func() uint64 { return c.committedRound(watch) }
	if larger {
		committed = func() uint64 { return m(watch).blockStore().CommittedRound() }
	}
	beginObservation := func() {
		startRound = m(watch).pacemaker.GetCurrentRound()
		lastRound, roundAt, lastKnown = startRound, t0, known(startRound)
		t.Logf("T=%s, block rate %s, topology %s, shards %v, start round %d, committed %d, stopped %v, returned %v", T, blockRate, topology, shards, startRound, committed(), dead, returning)
	}
	recordCommit := func(at time.Time, round uint64) {
		commitAt, commitRound = at, round
		committedAfterUnknown.Store(true)
		elapsed := commitAt.Sub(unknownFrom)
		t.Logf("first commit after that at round %d, %s: unknown-to-commit %s over %d rounds", commitRound, commitAt.Sub(t0).Round(time.Millisecond), elapsed.Round(time.Millisecond), commitRound-unknownRound)
		counters("the first commit")
		if larger && !rescueMiss && elapsed > 75*time.Second {
			rescueMiss = true
			t.Logf("75 s rescue target missed: first commit after unknown round %d observed after %s", unknownRound, elapsed)
		}
	}
	observe := func(now time.Time, round uint64) {
		roundKnown := lastKnown
		if round != lastRound {
			roundKnown = known(round)
		}
		beforeKnown := !roundKnown && round != lastEdge && !unknownFrom.IsZero() && known(round+1)
		if larger {
			now = rescueWindow.sampleTime()
			if now.IsZero() {
				return
			}
		}
		at := now.Sub(t0).Round(time.Millisecond)
		if round != lastRound {
			gap := now.Sub(roundAt) / time.Duration(round-lastRound)
			for r := lastRound; r < round; r++ {
				samples = append(samples, sample{r, gap, lastKnown})
			}
			lastRound, roundAt, lastKnown = round, now, roundKnown
		}
		if beforeKnown {
			lastEdge = round
			t.Logf("round %d at %s: its leader unknown, the next known", round, at)
			counters("that round's start")
		}
		if !lastKnown && unknownFrom.IsZero() {
			unknownFrom, unknownRound, commitAtUnknown = now, round, committed()
			t.Logf("first unknown round %d at %s, %d rounds after the stop", unknownRound, at, unknownRound-startRound)
			counters("the first unknown round")
		}
		if lastKnown && !unknownFrom.IsZero() && firstKnownAfter.IsZero() {
			firstKnownAfter, firstKnownRound = now, round
			t.Logf("first known round after that %d at %s: unknown window total %s over %d rounds", firstKnownRound, at, now.Sub(unknownFrom).Round(time.Millisecond), firstKnownRound-unknownRound)
			counters("the first known round")
		}
		if unknownFrom.IsZero() || !now.After(unknownFrom) || !commitAt.IsZero() {
			return
		}
		var head uint64
		commitObservedAt := now
		if larger {
			head, commitObservedAt = rescueWindow.readCommit(committed)
			if commitObservedAt.IsZero() {
				return
			}
		} else {
			head = committed()
		}
		if head != commitAtUnknown {
			recordCommit(commitObservedAt, round)
		} else if larger && !rescueMiss && commitObservedAt.Sub(unknownFrom) >= 75*time.Second {
			rescueMiss = true
			t.Logf("75 s elapsed since the first unknown leader at round %d; no commit by round %d", unknownRound, round)
		}
	}
	stopObserving := func() {}
	if larger {
		// Sample the round and committed head while shard proofs are being built.
		// The submission loop only reads the atomic progress flag until the observer joins.
		t0 = time.Now()
		beginObservation()
		clock := startRoundClock(m(watch))
		stop, done, ready := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			close(ready)
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					observe(time.Time{}, m(watch).pacemaker.GetCurrentRound())
				}
			}
		}()
		<-ready
		stopObserving = sync.OnceFunc(func() {
			close(stop)
			rounds := clock.halt()
			<-done
			if !end.IsZero() {
				rounds = slices.DeleteFunc(rounds, func(r clockRound) bool { return r.end.After(end) })
			}
			reportTimingUnknown(t, rounds)
		})
		defer stopObserving()
	}
	for _, name := range dead {
		c.stop(name)
		if transport != nil {
			transport.down(c, name)
		}
	}
	if transport != nil {
		transport.up(c, returning...)
	}
	c.start(returning...)
	if !larger {
		t0 = time.Now() // keep the original four-root trace's time origin
	}
	forwardsMu.Lock()
	currentRound = m(watch).pacemaker.GetCurrentRound
	forwardsMu.Unlock()
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
	if !larger {
		beginObservation()
	}
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
	var certificateMiss bool
certify:
	for len(certAt) < len(shards) {
		require.True(t, time.Now().Before(deadline), "%d of %d certified in 40 minutes", len(certAt), len(shards))
		now := time.Now()
		round := m(watch).pacemaker.GetCurrentRound()
		if !larger {
			observe(now, round)
		}
		for _, p := range shards {
			if _, done := certAt[p.String()]; done {
				continue
			}
			hash, sealRound := watchedShardCertificate(m(watch), p)
			if !bytes.Equal(hash, established[p.String()]) {
				if larger && len(certAt)+1 == len(shards) {
					end = rescueWindow.finish()
					certAt[p.String()] = end.Sub(t0)
					certificateRound := m(watch).pacemaker.GetCurrentRound()
					stopObserving()
					// The certificate and its seal came from one read of the durable
					// root. It can witness progress at the cutoff when a separate
					// head read did not return in time.
					if commitAt.IsZero() && !unknownFrom.IsZero() && sealRound > commitAtUnknown {
						t.Logf("last watched-root certificate witnesses commit of round %d at the rescue cutoff", sealRound)
						recordCommit(end, certificateRound)
					}
					break certify
				}
				certAt[p.String()] = time.Since(t0)
				continue
			}
			if (larger || !unknownFrom.IsZero()) && (len(sendRounds[p.String()]) == 0 || seal(p) != sentUnder[p.String()]) {
				send(p, round)
			}
		}
		if larger && !certificateMiss && now.Sub(t0) >= 360*time.Second && len(certAt) < len(shards) {
			certificateMiss = true
			t.Logf("360 s elapsed at round %d; fresh certificates recorded for %d/%d shards at the watched root", round, len(certAt), len(shards))
		}
		if committedAfterUnknown.Load() && time.Since(progressAt) > 30*time.Second {
			progressAt = time.Now()
			for _, p := range shards {
				_, done := certAt[p.String()]
				t.Logf("progress %s at round %d: %s certified %v, seal %d, sent under %d, sends at rounds %v", since(), round, p, done, seal(p), sentUnder[p.String()], sendRounds[p.String()])
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if end.IsZero() {
		end = time.Now()
	}
	counters("the last certificate")
	if transport != nil {
		transport.reportDelivery(t0, "the stop", shards, func(s liveShard) []byte { return shardHash(m(watch), s) })
	}
	if unknownFrom.IsZero() {
		require.True(t, larger && !exactQuorum, "no unknown round")
		t.Log("no unknown-leader window before the fresh certificates")
	} else {
		require.False(t, commitAt.IsZero(), "no commit")
	}

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
	t.Logf("all %d rounds: %d timers %s (%d in unknown rounds), %d known fast; unknown fast total %s, %s", len(samples), timers, timerSum.Round(time.Millisecond), unknownTimers, knownFast,
		unknownSum.Round(time.Millisecond), durations(fast, stallAt))
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
		if n := len(sendRounds[p.String()]); n > 1 && !commitAt.IsZero() {
			resend = append(resend, max(sendRounds[p.String()][n-1], commitRound)-commitRound) // the poll can see a new seal before the new commit
		}
		certs = append(certs, certAt[p.String()])
	}
	slices.Sort(resend)
	slices.Sort(certs)
	if len(resend) > 0 {
		t.Logf("R as this harness resubmits, on seeing a new seal, so not a real shard's reaction; rounds from the first commit to a shard's fresh request: %d of %d shards resubmitted, min %d, median %d, max %d", len(resend), len(shards), resend[0], resend[len(resend)/2], resend[len(resend)-1])
	}
	t.Logf("certified: first shard %s, median %s, last %s after the stop; stop to last certificate %d rounds, %d sends",
		certs[0].Round(time.Millisecond), certs[len(certs)/2].Round(time.Millisecond), certs[len(certs)-1].Round(time.Millisecond), c.state(watch).Round-startRound, sends)
	if !commitAt.IsZero() {
		t.Logf("from the first commit after the unknown window to the last certificate: %s over %d rounds",
			end.Sub(commitAt).Round(time.Millisecond), c.state(watch).Round-commitRound)
	}

	// rho: BFT_TRACE_STEADY more rounds with the dead member still down and the returned one up, every shard sending a fresh request as soon as
	// it reads its new certificate. The test generates and signs those requests, so how soon a shard sends again is this harness's, not a real shard's R.
	if steady := uint64(traceEnvInt(t, "BFT_TRACE_STEADY", 0)); steady > 0 {
		selector, ok := m(watch).leaderSelector.(*leader.EpochReputation)
		require.True(t, ok)
		clock := startRoundClock(m(watch))
		from := c.state(watch).Round
		certs := map[string]int{}
		for c.state(watch).Round < from+steady {
			require.True(t, time.Now().Before(t0.Add(steadyDeadline(T, steady))), "the steady phase did not reach %d rounds", steady)
			st := c.state(watch)
			for _, p := range shards {
				if seal(p) != sentUnder[p.String()] {
					certs[p.String()]++
					send(p, st.Round)
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		rounds := clock.halt()
		t.Logf("steady phase: %d rounds from %d with %s down, certificates per shard %v", steady, from, d, certs)
		reportRho(t, rounds, selector.RecoveryRunStart, c.id(d))
	}
}

// rescueTimingWindow associates each sample with the time its read completed.
// The cutoff and the sample check share a lock so a sample racing with the final
// certificate can be included only if its read completed within the window.
type rescueTimingWindow struct {
	mu  sync.Mutex
	end time.Time
}

func (w *rescueTimingWindow) finish() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.end = time.Now()
	return w.end
}

func (w *rescueTimingWindow) sampleTime() time.Time {
	at := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.end.IsZero() && at.After(w.end) {
		return time.Time{}
	}
	return at
}

func (w *rescueTimingWindow) readCommit(read func() uint64) (uint64, time.Time) {
	head := read()
	return head, w.sampleTime()
}

// steadyDeadline allows every steady round a timer and a second.
func steadyDeadline(T time.Duration, rounds uint64) time.Duration {
	return 40*time.Minute + time.Duration(rounds)*(T+time.Second)
}

// #886 gate 9, the size the five libp2p rescue traces did not reach: the three default-batch RSMT envelopes (about 212 KB each) in one proposal of
// about 635 KB, on the production transport at its unchanged limits (liveTransport), with every root up. A batch shard makes its one transition
// (rsmtbatch has one pre-state), so each run is one packing: it builds the three shards' requests, waits for a round to begin and sends them to
// every root at once, so the next leader holds all three when it proposes. A T2 repeat landing between building and sending makes a request
// stale (the fixture's batch shards have T2 periods of 2.5, 5 and 7.5 s): seeing that repeat, it builds and sends again. It requires a proposal carrying all
// three and all three certified under one seal, and skips a run whose requests were split: it did not reach the size. The trace patch records
// wire sizes and receipt and handling times. Repeat the run for more samples.
// BFT_GATE9_PACKED=1; BFT_TRACE_T and BFT_TRACE_BLOCK_RATE_MS as in the rescue trace.
func TestGate9ThreeEnvelopesInOneProposal(t *testing.T) {
	if os.Getenv("BFT_GATE9_PACKED") == "" {
		t.Skip("set BFT_GATE9_PACKED=1: a measurement on the production transport, not a regression test")
	}
	T := time.Duration(traceEnvInt(t, "BFT_TRACE_T", 10)) * time.Second
	blockRate := time.Duration(traceEnvInt(t, "BFT_TRACE_BLOCK_RATE_MS", int(phaseLockBlockRate/time.Millisecond))) * time.Millisecond
	options := traceTopology(t, "f8batch")
	options.PeerEVM = true
	transport := newLiveTransport(t)
	c := newEqualLiveRate(t, T, blockRate, options, transport.install, "H", "a", "b", "c")
	transport.addShards(c.nodes[0].r.f)
	var batch []liveShard
	for _, s := range liveShards(c, true) {
		if s.batch != nil {
			batch = append(batch, s)
		}
	}
	require.Len(t, batch, 3)
	// every proposal a leader sends, by round: which of the three shards it carries
	var mu sync.Mutex
	carried := map[uint64][]string{}
	transport.tap = func(msg any) {
		p, ok := msg.(*abdrc.ProposalMsg)
		if !ok || p.Block.Payload == nil {
			return
		}
		var in []string
		for _, req := range p.Block.Payload.Requests {
			key := liveShard{partition: req.Partition, shard: req.Shard}.String()
			if slices.ContainsFunc(batch, func(s liveShard) bool { return s.String() == key }) {
				in = append(in, key)
			}
		}
		if len(in) > 0 {
			mu.Lock()
			carried[p.Block.Round] = in
			mu.Unlock()
		}
	}
	all := c.all()
	transport.up(c, all...)
	c.start(all...)
	lag := 4*uint64(len(c.nodes)) + 4
	c.warm(lag+2, all...)
	establish(t, c, all[0], liveShards(c, true), transport.submit)
	watch := all[0]
	m := c.nodes[c.idx(watch)].r.manager
	seal := func(p liveShard) uint64 {
		si := m.blockStore().ShardInfo(p.partition, p.shard)
		if si == nil || si.LastCR == nil {
			return 0
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
	}
	t.Logf("T=%s, block rate %s, shards %v", T, blockRate, batch)
	before := map[string][]byte{}
	for _, s := range batch {
		before[s.String()] = shardHash(m, s)
	}
	certified := func() bool {
		for _, s := range batch {
			if bytes.Equal(shardHash(m, s), before[s.String()]) {
				return false
			}
		}
		return true
	}
	var sends []uint64
	var firstSent time.Time
	deadline := time.Now().Add(3 * time.Minute)
	for !certified() {
		require.True(t, time.Now().Before(deadline), "the three shards certified within 3 minutes, sends at rounds %v", sends)
		var proofs []*IRChangeRequest
		for _, s := range batch {
			proof := shardRequest(t, c.nodes[c.idx(watch)].r, s, false, false)
			require.NotNil(t, proof, s)
			proofs = append(proofs, proof)
		}
		from := c.state(watch).Round
		require.Eventually(t, func() bool { return c.state(watch).Round > from }, 2*T, time.Millisecond, "a round begins")
		sends = append(sends, c.state(watch).Round)
		if firstSent.IsZero() {
			firstSent = time.Now()
		}
		for _, name := range all {
			for _, proof := range proofs {
				require.NoError(t, transport.submit(name, proof))
			}
		}
		// sent again only when one of them is seen to be stale: a new certificate of a shard still waiting is a T2 repeat, under which its
		// proof can no longer certify
		under := map[string]uint64{}
		for _, s := range batch {
			under[s.String()] = seal(s)
		}
		stale := func() bool {
			for _, s := range batch {
				if bytes.Equal(shardHash(m, s), before[s.String()]) && seal(s) != under[s.String()] {
					return true
				}
			}
			return false
		}
		for !certified() && !stale() {
			require.True(t, time.Now().Before(deadline), "the three shards certified within 3 minutes, sends at rounds %v", sends)
			time.Sleep(5 * time.Millisecond)
		}
	}
	certifiedAfter := time.Since(firstSent)
	seals := map[uint64]int{}
	for _, s := range batch {
		seals[seal(s)]++
	}
	mu.Lock()
	var rounds []string
	packed := uint64(0)
	for r := sends[0]; r <= c.state(watch).Round; r++ {
		if in, ok := carried[r]; ok {
			rounds = append(rounds, fmt.Sprintf("%d:%v", r, in))
			if len(in) == 3 {
				packed = r
			}
		}
	}
	mu.Unlock()
	t.Logf("sends at rounds %v; all three certified %s after the first, seals %v; proposals carrying them %s; packed at round %d", sends, certifiedAfter.Round(time.Millisecond), seals, strings.Join(rounds, " "), packed)
	transport.reportDelivery(firstSent, "the first send", batch, func(s liveShard) []byte { return shardHash(m, s) })
	if packed == 0 {
		t.Skip("NOT PACKED: no proposal carried the three envelopes (a repeat split them), so this run did not reach the size; not a transport result")
	}
	require.Len(t, seals, 1, "the three were not certified under one seal")
}
