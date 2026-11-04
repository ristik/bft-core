package consensus

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #886's phase lock: on four equal members with one down, the request of the shard reaches the live ingress root in the last round
// before the dead slot, at every repeat UC, because T2 (12 root rounds) is a multiple of the four-round leader cycle.
const (
	phaseLockT2Rounds  = 12
	phaseLockRoundsMax = 8 // additional root rounds after live ingress acceptance
	phaseLockPeriods   = 4 // T2 periods a lost request is resubmitted for, at the same phase, before the run counts as locked
)

// phaseLockRotation replaces the selector with the plain rotation of the committee, the design's isolated retention regression: the phase
// lock needs a dead slot in every cycle, and the epoch's own selector leaves the full rotation after the bootstrap.
func phaseLockRotation(t *testing.T, c *q4bLive) {
	t.Helper()
	for _, n := range c.nodes {
		m := n.r.manager
		rotation, err := leader.NewWeighted(m.epochAnchor.Slot+1, m.trustBase.Load().RootNodes)
		require.NoError(t, err)
		m.leaderSelector = rotation
	}
}

// shardProof is the same pending request of the shard under the view its ingress root collects under: every member signs the same input
// record, as a shard's quorum does.
func phaseLockProof(t *testing.T, c *q4bLive, r *q3Replica, hash []byte) *IRChangeRequest {
	t.Helper()
	view, enabled, err := r.manager.RequestView(q3fixture.PartitionID, types.ShardID{})
	if err != nil || !enabled {
		return nil
	}
	tr := view.ExpectedTR()
	prev, err := view.PreviousUC()
	require.NoError(t, err)
	out := &IRChangeRequest{Partition: q3fixture.PartitionID, Shard: types.ShardID{}, Reason: Quorum}
	for _, id := range view.Context().NodeIDs() {
		bcr := &certification.BlockCertificationRequest{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}, NodeID: id, InputRecord: &types.InputRecord{
			Version: 1, Epoch: tr.Epoch, RoundNumber: tr.Round, PreviousHash: view.PreviousStateHash(), Hash: hash, BlockHash: bytes.Repeat([]byte{0x82}, 32),
			SummaryValue: []byte{1}, Timestamp: prev.UnicitySeal.Timestamp}}
		require.NoError(t, bcr.Sign(c.nodes[0].r.f.EVMSigners[id]))
		out.Requests = append(out.Requests, bcr)
	}
	return out
}

func (c *q4bLive) certifiedHash(name string, hash []byte) bool {
	si := c.nodes[c.idx(name)].r.manager.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	return si != nil && si.LastCR != nil && bytes.Equal(si.LastCR.UC.InputRecord.Hash, hash)
}

// lockedPhase is the logged failure: the ingress root's next leader is the last live one before the dead slot, so that leader's
// proposal has its votes sent to the dead member.
func lockedPhase(next, afterNext, dead peer.ID) bool { return next != dead && afterNext == dead }

// healthyPhase is the control: the next leader starts the run of three live leaders that commits its proposal.
func healthyPhase(next, afterNext, dead peer.ID, leaderBefore peer.ID) bool {
	return next != dead && afterNext != dead && leaderBefore == dead
}

// phaseLockRun submits at the given phase. A request not certified is submitted again at the same phase each
// T2 period, as the shard's resubmission on a repeat UC does. It returns the rounds from the first acceptance to the certificate, or
// false if the run locked.
func phaseLockRun(t *testing.T, c *q4bLive, dead string, phase func(round uint64, leaderOf func(uint64) peer.ID, dead peer.ID) bool) (uint64, bool) {
	t.Helper()
	live := c.except(dead)
	c.start(live...)
	c.warm(3, live...)
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	leaderOf := func(round uint64) peer.ID {
		l, err := m(live[0]).leaderSelector.GetLeaderForRound(round)
		require.NoError(t, err)
		return l
	}
	hash := bytes.Repeat([]byte{0x81}, 32)
	var ingress string
	first, lastSent := uint64(0), uint64(0)
	deadline := time.Now().Add(q4bDeadline * 3)
	for time.Now().Before(deadline) {
		if ingress != "" && c.certifiedHash(ingress, hash) {
			return c.state(ingress).Round - first, true
		}
		if first != 0 && c.state(live[0]).Round > first+phaseLockT2Rounds*phaseLockPeriods {
			return 0, false
		}
		for _, name := range live {
			round := c.state(name).Round
			next := leaderOf(round + 1)
			if next == c.id(name) || !phase(round, leaderOf, c.id(dead)) {
				continue
			}
			if first != 0 && round < lastSent+phaseLockT2Rounds {
				continue
			}
			proof := phaseLockProof(t, c, c.nodes[c.idx(name)].r, hash)
			if proof == nil {
				continue
			}
			if err := m(name).RequestCertification(context.Background(), *proof); err != nil {
				continue
			}
			if first == 0 {
				first, ingress = round, name
			}
			lastSent = round
			t.Logf("request accepted by %s at round %d, next leader %s, dead %s", name, round, next.ShortString(), c.id(dead).ShortString())
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Fail(t, "the phase of the request never came")
	return 0, false
}

func TestPhaseLockedRequestCertifies(t *testing.T) {
	// neither correctness nor the round bound may depend on the timer's relation to the phase: every dead placement at T = 2 s, as in the
	// failing experiment, and production T once
	for _, row := range []struct {
		dead    string
		timeout time.Duration
	}{{"H", 2 * time.Second}, {"a", 2 * time.Second}, {"b", 2 * time.Second}, {"c", 2 * time.Second}, {"c", 10 * time.Second}} {
		t.Run(fmt.Sprintf("dead %s, T=%s", row.dead, row.timeout), func(t *testing.T) {
			t.Parallel()
			q4Slot(t)
			c := newPhaseLockLive(t, row.timeout)
			phaseLockRotation(t, c)
			rounds, certified := phaseLockRun(t, c, row.dead, func(round uint64, leaderOf func(uint64) peer.ID, dead peer.ID) bool {
				return lockedPhase(leaderOf(round+1), leaderOf(round+2), dead)
			})
			require.True(t, certified, "the request locked to the phase before the dead slot: not certified in %d T2 periods of %d root rounds", phaseLockPeriods, phaseLockT2Rounds)
			require.LessOrEqual(t, rounds, uint64(phaseLockRoundsMax), fmt.Sprintf("certified %d rounds after acceptance", rounds))
			t.Logf("certified %d rounds after acceptance", rounds)
		})
	}
}

// The control of the test above: the same request and the same dead member, at the phase where the next leader starts the live run. It
// certifies without any retention, so the request is valid and the locked run fails by its phase alone.
func TestPhaseLockControlHealthyPhaseCertifies(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	phaseLockRotation(t, c)
	rounds, certified := phaseLockRun(t, c, "c", func(round uint64, leaderOf func(uint64) peer.ID, dead peer.ID) bool {
		return healthyPhase(leaderOf(round+1), leaderOf(round+2), dead, leaderOf(round))
	})
	require.True(t, certified)
	require.LessOrEqual(t, rounds, uint64(phaseLockRoundsMax))
	t.Logf("certified %d rounds after acceptance", rounds)
}

// rollingRestartRounds is the design's first-new-commit bound in rounds for n members with one unavailable recovery identity: every
// still-covered round, then the traversal to a live run past one dead run, then the live run itself: (D+1) + (b+1)*S + 4b + 4.
func rollingRestartRounds(n uint64) uint64 {
	const s, b = 256, 1
	d := 4*n + 4
	return d + 1 + (b+1)*s + 4*b + 4
}

// #886's rolling restart: four members commit with a, b, D while X is down, so every committed participation sample names a, b, D. X comes
// back and D stops before any commit carries X's vote: the live a, b, X hold a quorum and the stale schedule has no three live leaders in a
// row. The shard's request, resubmitted on each T2 period, must still certify within the fault-transition bound, and only X's own rejoin
// may enter state recovery. The bound is stated in rounds at T = 2 s, as in dev3's experiment (a T below a durable round's time only times every round out); the wall-clock ceiling at production T is measured separately.
func TestRollingRestartCertifiesRetainedRequest(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	x, d := "c", "b"
	first := c.except(x)
	c.start(first...)
	n := uint64(len(c.nodes))
	c.warm(4*n+4+2, first...) // the samples at every cutoff name H, a, b only
	survivors := c.except(x, d)

	c.stop(d)
	c.start(x)
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	leaderOf := func(round uint64) peer.ID {
		l, err := m(survivors[0]).leaderSelector.GetLeaderForRound(round)
		if err != nil {
			return ""
		}
		return l
	}
	hash := bytes.Repeat([]byte{0x81}, 32)
	start := c.state(survivors[0]).Round
	limit := start + rollingRestartRounds(n)
	lastSent, sentUnder := uint64(0), uint64(0)
	deadline := time.Now().Add(25 * time.Minute)
	for time.Now().Before(deadline) {
		round := c.state(survivors[0]).Round
		if c.certifiedHash(survivors[0], hash) {
			t.Logf("certified %d rounds after D stopped, limit %d; last submitted at round %d", round-start, limit-start, lastSent)
			return
		}
		require.LessOrEqual(t, round, limit, "the request did not certify within the bound of %d rounds", limit-start)
		for _, name := range survivors {
			require.False(t, m(name).recovery.InRecovery() && round > start+1 && c.state(name).Round >= round, "%s entered state recovery with no missing certified state", name)
		}
		// As a shard does: first at the locked phase or while no leader is known, then again whenever a new certificate of the shard makes
		// the proof it holds stale. A repeat UC that was waiting in the high QC's branch certifies when the first live run commits it.
		next, after := leaderOf(round+1), leaderOf(round+2)
		locked := next != "" && lockedPhase(next, after, c.id(d))
		judge := survivors[0]
		for _, name := range survivors {
			if next == c.id(name) {
				judge = name
			}
		}
		lastUC := func() uint64 {
			si := m(judge).blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
			if si == nil || si.LastCR == nil {
				return 0
			}
			return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
		}()
		first := lastSent == 0 && (locked || next == "")
		if first || (lastSent != 0 && lastUC != sentUnder) {
			if proof := phaseLockProof(t, c, c.nodes[c.idx(judge)].r, hash); proof != nil {
				if err := m(survivors[0]).RequestCertification(context.Background(), *proof); err == nil {
					lastSent, sentUnder = round, lastUC
					t.Logf("request accepted at round %d under the certificate of round %d", round, lastUC)
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Fail(t, "no verdict within 25 minutes")
}

// #886 gate 7, the design's two-stage exception, in part: a T2 repeat is in the certified branch when the shard's request reaches the ingress, the
// first live run commits the repeat, the held proof is stale, and the shard's fresh request certifies after a delay R of its own.
// This shape has no second covered stretch, at any R: between the stop and the first live run the stale schedule still has two live leaders in a
// row, so it keeps certifying blocks with X voting, the run commits them, and their records name the live set. Cutoffs right after the commit
// already select it (rev's probe, #919). So this does not reach the design's "about 480 s" accounting: that needs exactly one certified block
// after the stop. The limit of stage two below is that accounting's, and here it is far from binding.
func TestRollingRestartRepeatConsumesTheFirstLiveRun(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	const hold = 8 // R, in root rounds after the commit: explicit, not an instant resubmission
	c := newPhaseLockLive(t, 2*time.Second)
	var armed atomic.Bool
	var repeatMu sync.Mutex
	repeats := map[uint64]bool{} // every round the filter saw a T2 repeat proposed in
	base := c.net.filter
	c.net.filter = func(from, to peer.ID, msg any) bool {
		if p, ok := msg.(*abdrc.ProposalMsg); ok && armed.Load() && p.Block.Payload != nil {
			for _, req := range p.Block.Payload.Requests {
				if req.CertReason == drctypes.T2Timeout {
					repeatMu.Lock()
					repeats[p.Block.Round] = true
					repeatMu.Unlock()
				}
			}
		}
		return base(from, to, msg)
	}
	x, d := "c", "b"
	first := c.except(x)
	c.start(first...)
	n := uint64(len(c.nodes))
	d0 := 4*n + 4
	c.warm(d0+2, first...)
	survivors := c.except(x, d)
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	lastUC := func(name string) uint64 {
		si := m(name).blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		if si == nil || si.LastCR == nil {
			return 0
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
	}
	c.stop(d)
	c.start(x)
	armed.Store(true)
	ingress := survivors[0]
	start, startUC := c.state(ingress).Round, lastUC(ingress)
	hash := bytes.Repeat([]byte{0x81}, 32)

	// the shape: a repeat, uncommitted, and the QC on that very block. Only then does the request arrive, so no retained request can have gone first.
	isRepeat := func(round uint64) bool {
		repeatMu.Lock()
		defer repeatMu.Unlock()
		return repeats[round]
	}
	require.Eventually(t, func() bool { return isRepeat(c.state(ingress).HighQC) && lastUC(ingress) == startUC }, q4bDeadline, 5*time.Millisecond, "a T2 repeat certified, not yet committed")
	highQC := c.state(ingress).HighQC
	held := phaseLockProof(t, c, c.nodes[c.idx(ingress)].r, hash)
	require.NotNil(t, held)
	require.NoError(t, m(ingress).RequestCertification(context.Background(), *held))
	accepted := c.state(ingress).Round
	t.Logf("high QC %d when the request was held from round %d, %d rounds after the stop", highQC, accepted, accepted-start)

	// stage one: the first live run commits the repeat, and the same request cannot certify
	stage1 := start + rollingRestartRounds(n)
	for lastUC(ingress) == startUC { // plain loops: a failure inside Eventually's goroutine would not stop the test
		require.LessOrEqual(t, c.state(ingress).Round, stage1, "stage one: no commit of the repeat within the bound")
		time.Sleep(5 * time.Millisecond)
	}
	committed := c.state(ingress).Round
	require.False(t, c.certifiedHash(ingress, hash), "the first certificate is the repeat, not the held request")
	// the repeat that consumed the run was in the branch before the request came: a QC at or above a round says nothing about another branch
	inChain := func() (uint64, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		repeatMu.Lock()
		defer repeatMu.Unlock()
		for round := range c.chains[c.idx(ingress)] {
			if repeats[round] && round <= highQC && round > start {
				return round, true
			}
		}
		return 0, false
	}
	require.Eventually(t, func() bool { _, ok := inChain(); return ok }, 10*time.Second, 5*time.Millisecond, "a recorded T2 repeat at or below the high QC %d is in the committed chain", highQC)
	repeat, _ := inChain()
	t.Logf("repeat of round %d in the committed chain", repeat)
	view, enabled, err := m(ingress).RequestView(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.True(t, enabled)
	require.NotEqual(t, held.Requests[0].InputRecord.RoundNumber, view.ExpectedTR().Round, "the repeat moved the expected shard round: the held proof is stale")
	t.Logf("repeat committed by round %d, %d rounds after the stop, limit %d", committed, committed-start, stage1-start)

	// stage two: only the shard can certify it, so nothing does until it answers after R, and again if a further repeat made that proof stale too
	committedAt := time.Now()
	for c.state(ingress).Round < committed+hold {
		require.False(t, c.certifiedHash(ingress, hash), "certified with no fresh request: the held proof was not stale")
		require.LessOrEqual(t, c.state(ingress).Round, committed+rollingRestartRounds(n), "stage two: the rounds stopped")
		time.Sleep(5 * time.Millisecond)
	}
	resubmitDelay := time.Since(committedAt)
	freshDeadline := committed + hold + rollingRestartRounds(n)
	sends, sentUnder, freshAt := 0, uint64(0), uint64(0)
	stage2 := uint64(0)
	for !c.certifiedHash(ingress, hash) {
		if under := lastUC(ingress); sends == 0 || under != sentUnder {
			proof := phaseLockProof(t, c, c.nodes[c.idx(ingress)].r, hash)
			if proof != nil && m(ingress).RequestCertification(context.Background(), *proof) == nil {
				if sends == 0 {
					freshAt = c.state(ingress).Round
					stage2 = freshAt + d0 + 1 + leader.RecoveryRun // the design's accounting
				}
				sends++
				sentUnder = under
			}
		}
		if stage2 != 0 {
			require.LessOrEqual(t, c.state(ingress).Round, stage2, "stage two: not certified within the design's covered stretch and a live run")
		}
		require.LessOrEqual(t, c.state(ingress).Round, freshDeadline, "stage two: the fresh request was never accepted")
		time.Sleep(5 * time.Millisecond)
	}
	end := c.state(ingress).Round
	t.Logf("fresh request accepted at round %d after R=%s (%d rounds), certified by round %d: %d rounds and %s, limit %d, %d sends; %d rounds after the stop in all", freshAt, resubmitDelay.Round(time.Millisecond), hold, end, end-freshAt, (time.Since(committedAt) - resubmitDelay).Round(time.Millisecond), stage2-freshAt, sends, end-start)
	for _, name := range survivors {
		require.False(t, m(name).recovery.InRecovery(), "%s entered state recovery with no missing certified state", name)
	}
}

// On the production branch, the view-aware verifier: a request it refuses is neither sent nor held, and a valid one afterwards takes the slot.
func TestRetentionRefusesWhatTheViewAwareVerifierRefuses(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	c.start(c.all()...)
	c.warm(4, c.all()...)
	c.stopAll()
	r := c.nodes[0].r
	m := r.manager
	hash := bytes.Repeat([]byte{0x81}, 32)
	key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
	proof := func() *IRChangeRequest {
		p := phaseLockProof(t, c, r, hash)
		require.NotNil(t, p)
		return p
	}
	for name, tc := range map[string]struct {
		mutate func(*IRChangeRequest)
		want   error
	}{
		"below the quorum": {func(p *IRChangeRequest) { p.Requests = p.Requests[:1] }, quorumweight.ErrQuorumNotReached},
		"bad signature":    {func(p *IRChangeRequest) { p.Requests[0].Signature[0] ^= 1 }, quorumweight.ErrInvalidSignature},
	} {
		bad := proof()
		tc.mutate(bad)
		require.ErrorIs(t, m.onPartitionIRChangeReq(context.Background(), bad), tc.want, name)
		require.NotContains(t, m.retained, key, "%s holds no slot", name)
	}
	require.NoError(t, m.onPartitionIRChangeReq(context.Background(), proof()), "the valid one is accepted afterwards")
	require.Contains(t, m.retained, key)
}

// Rev's reproduction: a below-quorum request first does not delay the valid one.
func TestARefusedRequestDoesNotDelayTheValidOne(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newPhaseLockLive(t, 2*time.Second)
	c.start(c.all()...)
	c.warm(4, c.all()...)
	hash := bytes.Repeat([]byte{0x81}, 32)
	r := c.nodes[0].r
	var accepted uint64
	require.Eventually(t, func() bool {
		bad, good := phaseLockProof(t, c, r, hash), phaseLockProof(t, c, r, hash)
		if bad == nil || good == nil {
			return false
		}
		bad.Requests = bad.Requests[:1]
		if r.manager.RequestCertification(context.Background(), *bad) != nil || r.manager.RequestCertification(context.Background(), *good) != nil {
			return false
		}
		accepted = c.state("H").Round
		return true
	}, time.Minute, 50*time.Millisecond)
	require.Eventually(t, func() bool { return c.certifiedHash("H", hash) }, 2*time.Minute, 10*time.Millisecond, "the valid request certifies")
	require.LessOrEqual(t, c.state("H").Round-accepted, uint64(phaseLockRoundsMax))
}
