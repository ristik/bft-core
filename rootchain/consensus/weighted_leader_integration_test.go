package consensus

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

const tbstoreWeighted = tbstore.LeaderPolicyWeightedV1

func testnetworkMock() RootNet { return testnetwork.NewRootMockNetwork() }

func testobservabilityDefault(t *testing.T) Observability { return testobservability.Default(t) }

// Live in-process clusters, the real manager constructor and run loops, over the #401 skewed harness, with the root-wrr-v1 leader
// policy activated for the genesis epoch in each node's trust base store. The policy is inactive in production: nothing installs
// an activation outside these tests.

func weightedSpec(heavy, light uint64, n, heavyPos int) clusterSpec {
	return clusterSpec{heavy: heavy, light: light, n: n, heavyPos: heavyPos, weightedLeader: true}
}

// requireWeightedSelector is the premise that the cluster runs the dispatched selector rather than the reputation election.
func requireWeightedSelector(t *testing.T, c *skewedCluster, i int) {
	t.Helper()
	require.IsType(t, &leader.Weighted{}, c.manager(i).leaderSelector, "the epoch's activated policy built the weighted selector")
}

func (c *skewedCluster) leaders(i int, from, to uint64) []peer.ID {
	out := make([]peer.ID, 0, to-from+1)
	for r := from; r <= to; r++ {
		id, err := c.manager(i).leaderSelector.GetLeaderForRound(r)
		require.NoError(c.t, err)
		out = append(out, id)
	}
	return out
}

// Heavy plus ONE light node is weight 7 of 9, exactly the threshold. Under the old round-robin this depended on where the two sat
// in the committee (TestSkewedWeightHeavyPlusOneLightDependsOnThePlaceInTheSchedule: QCs without commit, or TCs only). With the
// weighted schedule H H a H b H c H H the heavy node leads three or four consecutive rounds every nine, so ordinary commits
// recur for every light node and every placement of the heavy node. Commit needs the QC of the next two rounds, and the signers
// of the latest QC are the heavy node and the light node: actual signed weight 7.
func TestWeightedLeaderHeavyPlusOneLightCommits(t *testing.T) {
	for name, tc := range map[string]struct{ heavyPos, lightOffset int }{
		"heavy first, the light after it":                 {0, 1},
		"heavy first, the second light":                   {0, 2},
		"heavy first, the third light":                    {0, 3},
		"heavy third, the light after it":                 {2, 1},
		"heavy last, the light that wraps around":         {3, 1},
		"heavy second, the light that is not a neighbour": {1, 2},
	} {
		t.Run(name, func(t *testing.T) {
			c := newClusterOf(t, weightedSpec(6, 1, 4, tc.heavyPos))
			light := c.lightAt(tc.lightOffset)
			c.start(0, light)
			requireWeightedSelector(t, c, 0)
			require.Eventually(t, func() bool { return c.highQCRound(0) >= 12 && c.committedRound(0) >= 10 }, 90*time.Second, 100*time.Millisecond,
				"QCs and commits with the heavy node and one light node (weight 7 of 9)")
			qc := c.manager(0).blockStore.GetHighQc()
			require.Len(t, qc.Signatures, 2, "the QC is signed by exactly the two online members")
			require.EqualValues(t, skewedThreshold, c.signedStake(func(yield func(string)) {
				for id := range qc.Signatures {
					yield(id)
				}
			}), "actual signer weight 7")
			require.NoError(t, qc.Verify(c.trust))
			c.requireNoDoubleSign()
		})
	}
}

// With the heavy node offline in 6,1,1,1 the three lights weigh 3 < 7: no QC, no TC, the round never advances (an unavailable
// quorum, not a bounded timeout recovery). The heavy node alone weighs 6 < 7: the same.
func TestWeightedLeaderBelowThresholdMakesNoProgress(t *testing.T) {
	for name, online := range map[string][]int{"heavy offline, three lights": {1, 2, 3}, "heavy node alone": {0}} {
		t.Run(name, func(t *testing.T) {
			c := newClusterOf(t, weightedSpec(6, 1, 4, 0))
			c.start(online...)
			requireWeightedSelector(t, c, online[0])
			time.Sleep(3500 * time.Millisecond)
			for _, i := range online {
				require.LessOrEqual(t, c.highQCRound(i), uint64(1), "no QC beyond the genesis QC")
				require.EqualValues(t, 2, c.manager(i).pacemaker.GetCurrentRound(), "the round never advances: no QC and no TC")
				tc, err := c.manager(i).blockStore.GetLastTC()
				require.NoError(t, err)
				require.Nil(t, tc)
				require.LessOrEqual(t, c.committedRound(i), uint64(1))
			}
			c.requireNoDoubleSign()
		})
	}
}

// The quorum-preserving control: in 3,2,2,2,2 (W=11, Q=8) the four lights weigh exactly 8, so with the heavy node offline timeouts
// form TCs and the schedule (the heavy node leads at most two consecutive rounds) gives responsive leaders in a bounded number of
// rounds: commits recur. The gap is measured in elapsed time between successive advances of the committed round after the first (at most 40 seconds, with at least six advances), not in rounds.
func TestWeightedLeaderHeavyOfflineWithQuorumLeftHasABoundedGap(t *testing.T) {
	c := newClusterOf(t, weightedSpec(3, 2, 5, 0))
	c.start(1, 2, 3, 4)
	requireWeightedSelector(t, c, 1)
	require.Eventually(t, func() bool { return c.committedRound(1) >= 6 }, 90*time.Second, 100*time.Millisecond, "commits with the heavy node offline")
	tc, err := c.manager(1).blockStore.GetLastTC()
	require.NoError(t, err)
	require.NotNil(t, tc, "the heavy node's rounds are left by a timeout certificate")
	require.NoError(t, tc.Verify(c.nodes[1].tbStore))
	require.GreaterOrEqual(t, c.signedStake(func(yield func(string)) {
		for id := range tc.Signatures {
			yield(id)
		}
	}), uint64(8))

	// the committed head keeps advancing: sample it; no sample window of 40 s without a commit advance
	last, lastAt := c.committedRound(1), time.Now()
	deadline := time.Now().Add(60 * time.Second)
	advances := 0
	for time.Now().Before(deadline) && advances < 6 {
		time.Sleep(100 * time.Millisecond)
		if now := c.committedRound(1); now > last {
			last, lastAt, advances = now, time.Now(), advances+1
		}
		require.Less(t, time.Since(lastAt), 40*time.Second, "the commit gap is bounded")
	}
	require.GreaterOrEqual(t, advances, 6, "commits recur")
	c.requireNoDoubleSign()
}

// A node that restarts over its durable stores builds the same schedule from the authenticated inputs (the epoch's policy, start and
// members), not from its restored round or the QCs it saw, and the cluster goes on committing with it.
func TestWeightedLeaderRestartKeepsTheScheduleAndCommits(t *testing.T) {
	const victim = 2
	c := newClusterOf(t, weightedSpec(6, 1, 4, 0), victim)
	c.start(0, 1, 2)
	requireWeightedSelector(t, c, victim)
	require.Eventually(t, func() bool { return c.committedRound(0) >= 5 && len(c.signedRounds(victim, "vote")) > 0 }, 60*time.Second, 50*time.Millisecond)
	before := c.leaders(victim, 1, 200)
	var voted uint64
	for _, r := range c.signedRounds(victim, "vote") {
		voted = max(voted, r)
	}

	c.reopen(victim)
	c.start(victim)
	requireWeightedSelector(t, c, victim)
	require.Equal(t, before, c.leaders(victim, 1, 200), "the restarted node has the same schedule")
	require.Equal(t, c.leaders(0, 1, 200), c.leaders(victim, 1, 200), "and so does every other node")

	target := c.committedRound(0) + 6
	require.Eventually(t, func() bool { return c.committedRound(0) >= target }, 60*time.Second, 100*time.Millisecond, "the cluster commits with the restarted node")
	require.Eventually(t, func() bool {
		for _, r := range c.signedRounds(victim, "vote") {
			if r > voted {
				return true
			}
		}
		return false
	}, 60*time.Second, 100*time.Millisecond, "the restarted node votes again")
	c.requireNoDoubleSign()
}

// The two construction sites of a successor epoch's selector, both through the policy dispatch: the live installation of the
// verified handoff and the restart over an installed anchor. Without an activation both build today's canonical-order rotation;
// with root-wrr-v1 recorded for the epoch, both build the weighted selector from the anchor's start round, and with the unit
// weights that a successor body can carry today it is the same schedule.
func TestWeightedLeaderSuccessorEpochDispatch(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	var all []*anchorReplica
	for _, r := range replicas {
		all = append(all, r)
	}
	live, restarted := all[0], all[1]
	for _, r := range all {
		require.IsType(t, &bootstrapLeader{}, r.manager.leaderSelector, "control: no activation, the handoff rotation")
	}
	start := anchor.Slot + 1
	legacySchedule := func(m *ConsensusManager) []peer.ID {
		out := make([]peer.ID, 0, 50)
		for r := start; r < start+50; r++ {
			id, err := m.leaderSelector.GetLeaderForRound(r)
			require.NoError(t, err)
			out = append(out, id)
		}
		return out
	}
	want := legacySchedule(live.manager)

	// live installation of the epoch, repeated after the policy was recorded for it
	require.NoError(t, live.store.ActivateLeaderPolicy(2, tbstoreWeighted))
	live.manager.pacemaker.Stop()
	live.manager.pacemaker.currentRound.Store(0) // the installation requires stopped consensus
	_, err := live.manager.InstallEpochGenesis(live.proof, live.oldHead, live.body)
	require.NoError(t, err)
	require.IsType(t, &leader.Weighted{}, live.manager.leaderSelector, "the live installation builds the activated policy's selector")
	require.Equal(t, want, legacySchedule(live.manager), "unit weights: the same schedule from the anchor's start")

	// restart over the installed anchor
	require.NoError(t, restarted.store.ActivateLeaderPolicy(2, tbstoreWeighted))
	restarted.manager.pacemaker.Stop()
	cm, err := NewConsensusManager(restarted.manager.id, restarted.store, restarted.manager.orchestration, testnetworkMock(),
		restarted.manager.safety.signer, restarted.db, testobservabilityDefault(t),
		WithConsensusParams(*restarted.manager.params), WithRecoveryProfile2(restarted.history))
	require.NoError(t, err)
	t.Cleanup(cm.pacemaker.Stop)
	require.IsType(t, &leader.Weighted{}, cm.leaderSelector, "the restart builds the activated policy's selector")
	require.Equal(t, want, legacySchedule(cm))
}
