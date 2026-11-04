package consensus

import (
	"bytes"
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #886 gate 6: five real managers on a real epoch 2, one never started. By default one placement; BFT_GATE6_ALL=1 runs every placement,
// which takes minutes each. The timeout is 2 s, not production's 10 s, so wall times here do not stand in for the targets: rounds do.
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

func fiveManagerOutage(t *testing.T, dead string, names []string) {
	const (
		minCommits   = 50
		requests     = 8
		requestLimit = 16 // root rounds from acceptance to the certificate, outside a recovery run: the T2 repeat of a dead shard slot is 12
	)
	c := newEqualLive(t, 2*time.Second, names...)
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
	}, 3*q4bDeadline, 50*time.Millisecond, "the survivors commit past the bootstrap and the aging")

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

	// shard certifications: each request goes to a live ingress root that does not lead next
	var rounds []uint64
	var seconds []float64
	lastUC := func(name string) uint64 {
		si := m(name).blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		if si == nil || si.LastCR == nil {
			return 0
		}
		return si.LastCR.UC.UnicitySeal.RootChainRoundNumber
	}
	for i := range requests {
		hash := bytes.Repeat([]byte{0x90 + byte(i)}, 32)
		var ingress string
		var first, sentUnder uint64
		var at time.Time
		sends := 0
		refusals := map[string]int{}
		ok := assert.Eventually(t, func() bool {
			if ingress != "" && c.certifiedHash(ingress, hash) {
				return true
			}
			// as a shard does: submit, and again when a new certificate of the shard (a T2 repeat) has made the proof it holds stale
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
		}, q4bDeadline, 10*time.Millisecond, "request %d is accepted and certified", i)
		require.True(t, ok, "request %d: ingress %q, %d sends, refusals %v", i, ingress, sends, refusals)
		rounds = append(rounds, c.state(ingress).Round-first)
		seconds = append(seconds, time.Since(at).Seconds())
	}
	t.Logf("dead %s: root rounds to the certificate %v, seconds %.2f", dead, rounds, seconds)
	require.LessOrEqual(t, slices.Max(rounds), uint64(requestLimit), "request to certificate in root rounds")

	require.Eventually(t, func() bool { return len(c.commitsSince(c.idx(live[0]), mark)) >= minCommits }, q4bDeadline, 50*time.Millisecond, "ordinary commits go on")
	c.requireChainsAgree(live...)

	// re-entry: the member returns, votes, and is selected again once a committed sample at the cutoff names it
	c.start(dead)
	require.Eventually(t, func() bool {
		r := c.state(live[0]).Round
		for next := r + 1; next <= r+uint64(len(names)); next++ {
			if inRecoveryRun(selector, next) {
				continue
			}
			if got, err := selector.GetLeaderForRound(next); err == nil && got == c.id(dead) {
				return true
			}
		}
		return false
	}, q4bDeadline, 50*time.Millisecond, "the returned member re-enters the schedule")
	c.requireChainsAgree(live...)
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
