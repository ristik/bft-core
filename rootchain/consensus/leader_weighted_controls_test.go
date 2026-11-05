package consensus

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #886 gate 7, the design's weighted and insufficient-quorum controls on real managers of a real epoch 2. Rounds and outcomes count here; T is 2 s, so
// the wall times stand for nothing. The stall controls first show the cluster committing and afterwards show it committing again once quorum is back:
// without both, a dead harness would pass as a safe stall.

// insufficientQuorumStalls stops down, requires the rest to form no QC and commit nothing, and then restarts back and requires commits to resume.
func insufficientQuorumStalls(t *testing.T, weights []uint64, names, down []string, back string) {
	t.Helper()
	c := newEqualLiveOptions(t, 2*time.Second, q3fixture.Options{Weights: weights}, names...)
	c.start(c.all()...)
	c.warm(3, c.all()...)
	for _, name := range down {
		c.stop(name)
	}
	rest := c.except(down...)
	c.requireStalled(rest...)
	round := c.state(rest[0]).Round
	time.Sleep(q4bStall)
	// a TC needs the same quorum: the round cannot run away at certificate speed
	require.LessOrEqual(t, c.state(rest[0]).Round, round+1, "no quorum, no new round")
	committed := c.state(rest[0]).Committed
	t.Logf("stalled at committed %d, round %d, with %v down", committed, round, down)

	c.restart(back)
	require.Eventually(t, func() bool { return c.committedRound(rest[0]) > committed }, 3*q4bDeadline, 50*time.Millisecond, "commits resume with %s back", back)
	t.Logf("with %s back, committed %d at round %d", back, c.committedRound(rest[0]), c.state(rest[0]).Round)
	c.finish() // the replay checker judges the stall window and the whole trace
}

func TestFiveEqualTwoDownStallsSafely(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	insufficientQuorumStalls(t, []uint64{1, 1, 1, 1, 1}, []string{"H", "a", "b", "c", "d"}, []string{"c", "d"}, "d")
}

func TestHeavyMemberDownStallsSafely(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	insufficientQuorumStalls(t, []uint64{6, 1, 1, 1}, []string{"H", "a", "b", "c"}, []string{"H"}, "H")
}

// (3,2,2,2,2) with weight 3 down leaves weight 8, exactly the quorum of 11. The rolling shape: the heavy member is in every sample and a member no sample holds comes back, so
// the live voters are not the stale ones. TestWeightedStaleSets shows every such stale table still has a live triple within the covered rounds, so this commits without a rescue:
// the stall the design names for equal committees does not arise for this shape. It reports rounds; no latency is claimed for a weighted committee.
func TestWeightedRollingRestartCertifies(t *testing.T) {
	t.Parallel()
	q4Slot(t)
	c := newEqualLiveOptions(t, 2*time.Second, q3fixture.Options{Weights: []uint64{3, 2, 2, 2, 2}}, "H", "a", "b", "c", "d")
	first := c.except("d")
	c.start(first...)
	c.warm(4*uint64(len(c.nodes))+4+2, first...)
	c.stop("H")
	c.start("d")
	weightedRequestCertifies(t, c, c.except("H"))
}

// weightedRequestCertifies submits to two live ingress roots, and again when a new certificate has made the proof stale, until the shard is certified.
func weightedRequestCertifies(t *testing.T, c *q4bLive, live []string) {
	t.Helper()
	m := func(name string) *ConsensusManager { return c.nodes[c.idx(name)].r.manager }
	from, committed := c.state(live[0]).Round, c.committedRound(live[0])
	hash := bytes.Repeat([]byte{0x9e}, 32)
	sent := map[string]uint64{}
	var acceptedAt uint64
	unknown, lastRound := 0, from
	require.Eventually(t, func() bool {
		if round := c.state(live[0]).Round; round != lastRound {
			lastRound = round
			if _, err := m(live[0]).leaderSelector.GetLeaderForRound(round); errors.Is(err, drctypes.ErrHistoryUnavailable) {
				unknown++
			}
		}
		if c.certifiedHash(live[0], hash) {
			return true
		}
		for _, name := range live[:2] { // the default two ingress roots
			si := m(name).blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
			under := uint64(0)
			if si != nil && si.LastCR != nil {
				under = si.LastCR.UC.UnicitySeal.RootChainRoundNumber
			}
			if prev, ok := sent[name]; ok && prev == under {
				continue
			}
			if proof := phaseLockProof(t, c, c.nodes[c.idx(name)].r, hash); proof != nil && m(name).RequestCertification(context.Background(), *proof) == nil {
				sent[name] = under
				if acceptedAt == 0 {
					acceptedAt = c.state(name).Round
				}
			}
		}
		return false
	}, 30*time.Minute, 20*time.Millisecond, "the request certifies with weight 8 of 11")
	now := c.state(live[0])
	require.Greater(t, now.Committed, committed)
	t.Logf("heavy member stopped at round %d, committed %d; request accepted at round %d, certified by round %d, %d rounds after the stop, of them about %d seen with an unknown leader; committed %d", from, committed, acceptedAt, now.Round, now.Round-from, unknown, now.Committed)
}
