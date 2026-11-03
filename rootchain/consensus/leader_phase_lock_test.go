package consensus

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
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
