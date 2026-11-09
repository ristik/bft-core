package consensus

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
)

// #976: what the ROOTS do when no root holds the shard's request. Root side only, on four equal live managers over the in-process network (no libp2p, no
// real shard driver: the replacement request is made by the test, so these tests say nothing about the shard's reaction time R or about the shard
// applying the result). The premises are the ones the design answer states: a responsive root quorum, a live leader schedule, and a shard that
// builds a fresh request when the roots certify a repeat. The figures are root rounds counted from the shard's last certificate u.

// ingressLossBudget is the premise-based allowance, in root rounds, after the event a recovery step waits for (eligibility of the repeat, the
// submission of a fresh request): at most one leader cycle to reach a leader slot that includes it, then the three rounds of the commit rule.
// It is a test budget under these premises (responsive quorum, live schedule), not a bound on any real deployment; observed values are logged.
func ingressLossBudget(c *q4bLive) uint64 { return uint64(len(c.nodes)) + 3 }

type shardCert struct {
	seal uint64
	ir   *types.InputRecord
}

func shardCertOf(m *ConsensusManager) *shardCert {
	si := m.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	if si == nil || si.LastCR == nil {
		return nil
	}
	return &shardCert{seal: si.LastCR.UC.UnicitySeal.RootChainRoundNumber, ir: si.LastCR.UC.InputRecord}
}

// establishShardCertificate gives the shard a first certificate of a known hash and returns it.
func establishShardCertificate(t *testing.T, c *q4bLive, hash []byte) *shardCert {
	t.Helper()
	h := c.nodes[c.idx("H")].r.manager
	require.Eventually(t, func() bool {
		if c.certifiedHash("H", hash) {
			return true
		}
		if p := phaseLockProof(t, c, c.nodes[0].r, hash); p != nil {
			_ = h.RequestCertification(context.Background(), *p)
		}
		return false
	}, 2*time.Minute, 200*time.Millisecond)
	return shardCertOf(h)
}

// t2Rounds is the number of root rounds after which the shard's last certificate is eligible for a T2 repeat, as the proposal rule counts them.
func t2Rounds(m *ConsensusManager) uint64 {
	si := m.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	return t2TimeoutToRootRounds(si.T2Timeout, m.params.BlockRate/2)
}

// Nothing is submitted at all: the request is lost at every root by construction. The roots' own T2 timer, which does not depend on a request,
// certifies a repeat of the shard's last input record no earlier than its eligibility and within the premise budget after it; a fresh request
// then certifies as a non-repeat.
func TestIngressLossIsRecoveredByTheRootsT2Repeat(t *testing.T) {
	c := newPhaseLockLive(t, 2*time.Second)
	c.start(c.all()...)
	c.warm(8, c.all()...)
	h := c.nodes[c.idx("H")].r.manager
	hash0 := bytes.Repeat([]byte{0x90}, 32)
	last := establishShardCertificate(t, c, hash0)
	eligible := last.seal + t2Rounds(h)
	t0 := time.Now()
	t.Logf("last certificate at root round u=%d; T2 is %d root rounds, so a repeat is eligible from round %d; nothing is submitted", last.seal, t2Rounds(h), eligible)

	require.Eventually(t, func() bool { s := shardCertOf(h); return s != nil && s.seal > last.seal }, 5*time.Minute, 100*time.Millisecond)
	repeat := shardCertOf(h)
	t.Logf("the roots certified a new certificate for the shard at root round %d after %s", repeat.seal, time.Since(t0).Round(100*time.Millisecond))
	same, err := types.EqualIR(last.ir, repeat.ir)
	require.NoError(t, err)
	require.True(t, same, "it is a repeat: the same input record as the last certificate")
	require.GreaterOrEqual(t, repeat.seal, eligible, "never before the eligibility round")
	require.LessOrEqual(t, repeat.seal, eligible+ingressLossBudget(c), "within the premise budget after it")

	hash1 := bytes.Repeat([]byte{0x91}, 32)
	require.Eventually(t, func() bool {
		if c.certifiedHash("H", hash1) {
			return true
		}
		if p := phaseLockProof(t, c, c.nodes[0].r, hash1); p != nil {
			_ = h.RequestCertification(context.Background(), *p)
		}
		return false
	}, 2*time.Minute, 100*time.Millisecond)
	fresh := shardCertOf(h)
	require.NotEqual(t, repeat.seal, fresh.seal)
	same, err = types.EqualIR(repeat.ir, fresh.ir)
	require.NoError(t, err)
	require.False(t, same, "the fresh request certified as new work, not another repeat")
	require.LessOrEqual(t, fresh.seal, repeat.seal+ingressLossBudget(c), "the fresh request certifies within the premise budget of the repeat (the test submits at once; R is not measured)")
	t.Logf("fresh request certified at root round %d, %d rounds after the repeat", fresh.seal, fresh.seal-repeat.seal)
}

// The request is accepted by H alone (a, b, c are down: the fault-injection variant with ONE holder instead of the production pair, and a quorum
// outage induced on purpose, so this says nothing about uninterrupted one-fault availability). With H kept, the retained copy is forwarded
// when the others return and the request itself certifies. With H restarted (an in-process reopen of its stores, not an OS process restart) every
// copy is gone: the first new certificate is a T2 repeat, not the request.
//
// The loss boundary is asserted before the others return: no block of H's branch carries a change for the shard, so the request is in no
// persisted proposal that could still commit (an uncommitted block is persisted too, so "not committed" would not establish it).
func TestIngressLossAfterTheSoleHolderRestarts(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "holder kept (control)"
		if restart {
			name = "holder restarted"
		}
		t.Run(name, func(t *testing.T) {
			c := newPhaseLockLive(t, 2*time.Second)
			c.start(c.all()...)
			c.warm(8, c.all()...)
			h := c.nodes[c.idx("H")].r.manager
			hash0 := bytes.Repeat([]byte{0x90}, 32)
			last := establishShardCertificate(t, c, hash0)

			c.stop("a")
			c.stop("b")
			c.stop("c")
			hash1 := bytes.Repeat([]byte{0x91}, 32)
			p := phaseLockProof(t, c, c.nodes[0].r, hash1)
			require.NotNil(t, p)
			require.NoError(t, h.RequestCertification(context.Background(), *p))
			t.Logf("holders that received the request: H only (a, b, c down); H restarted: %v", restart)
			if restart {
				c.restart("H")
				h = c.nodes[c.idx("H")].r.manager
			}
			// the loss boundary, read on H's own block tree: no branch ending at its latest block carries a change for the shard
			tip := c.state("H").Round
			require.Nil(t, h.blockStore.IsChangeInProgress(tip, q3fixture.PartitionID, types.ShardID{}), "the request is in no proposal of H's tree")

			u := shardCertOf(h)
			require.Equal(t, last.seal, u.seal)
			t0 := time.Now()
			ready := c.state("H").Round
			c.start("a", "b", "c")
			if !restart {
				// the boundary check can see a request in a proposal: once the quorum is back, the retained request enters one before it certifies
				seen := false
				require.Eventually(t, func() bool {
					for _, name := range c.all() {
						m := c.nodes[c.idx(name)].r.manager
						if m.blockStore.IsChangeInProgress(c.state(name).Round, q3fixture.PartitionID, types.ShardID{}) != nil {
							seen = true
						}
					}
					return c.certifiedHash("H", hash1)
				}, 5*time.Minute, 20*time.Millisecond)
				require.True(t, seen, "the loss-boundary probe (IsChangeInProgress on the tree tip) does see the request while it is in a proposal")
				got := shardCertOf(h)
				t.Logf("the retained request certified at root round %d, %d rounds after the others were started (%s)", got.seal, c.state("H").Round-ready, time.Since(t0).Round(100*time.Millisecond))
				require.LessOrEqual(t, c.state("H").Round-ready, ingressLossBudget(c), "the control certifies quickly once the quorum returns")
				return
			}
			require.Eventually(t, func() bool { s := shardCertOf(h); return s != nil && s.seal > last.seal }, 5*time.Minute, 100*time.Millisecond)
			repeat := shardCertOf(h)
			t.Logf("first new certificate for the shard at root round %d, %s after the others were started (time from restored readiness; the outage itself is not counted)", repeat.seal, time.Since(t0).Round(100*time.Millisecond))
			require.False(t, c.certifiedHash("H", hash1), "the lost request did not certify")
			same, err := types.EqualIR(last.ir, repeat.ir)
			require.NoError(t, err)
			require.True(t, same, "the first new certificate is a T2 repeat of the last input record")
			require.GreaterOrEqual(t, repeat.seal, last.seal+t2Rounds(h))
		})
	}
}
