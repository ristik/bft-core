package leader

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The two stages of #886's T2-repeat exception, on the real selector and ring with an abstract chain: a block is certified when its leader and the next one
// are live, and it commits when the leader after them is too, the three leaders of a commit. This is what a run of the managers cannot give: every id order
// and phase, with each recovery run's owner (over 12 periods: the owner repeats every 4 and the stale table's phase every 3). It takes no timing: `rounds` here is the design's round allowance, 281 for a stage with no dead run and 541 for
// one with it, and with one dead member in a cycle of four no two adjacent stages can both have one.
func TestTwoStageAllowanceOverEveryOrderAndPhase(t *testing.T) {
	const (
		n          = uint64(4)
		quorum     = uint64(3)
		start      = uint64(100)
		noDeadRun  = 281
		withDeadRn = 541
		joint      = 822
	)
	lag, err := rctypes.LeaderLag(n)
	require.NoError(t, err)
	nodes := erNodes(t, 1, 1, 1, 1)
	ids := sortedIDs(t, nodes)
	full := byte(1<<n - 1)
	shapes, skipped := 0, 0
	outcomes := map[string]int{}
	var longest uint64
	seen := map[uint64]int{}
	// One selector, and one ring per stale set advanced with the head: a table depends only on its voters and Next leaves its parent untouched, so every shape
	// starts from the ring at its head. Rebuilding that ring per shape took the race job past its timeout.
	var head LeaderHead
	e := erSelector(t, nodes, start, quorum, &head)
	for x := range ids {
		stale := full &^ (1 << x)
		prefix := erRing(t, n, start)
		for headAt := start + 1; headAt < start+lag+2+RecoverySpacing*12; headAt++ {
			prefix, err = prefix.Next(headAt, []byte{stale})
			require.NoError(t, err)
			if headAt < start+lag+2 {
				continue
			}
			for dead := range ids {
				if dead == x {
					continue
				}
				liveSet := full &^ (1 << dead)
				for _, resubmit := range []uint64{1, 8} {
					state := prefix
					head = LeaderHead{Round: headAt, State: prefix}
					commit := func(round uint64, voters byte) {
						state, err = state.Next(round, []byte{voters})
						require.NoError(t, err)
						head = LeaderHead{Round: round, State: state}
					}
					known := func(r uint64) (peer.ID, bool) {
						l, err := e.GetLeaderForRound(r)
						if err != nil {
							require.True(t, errors.Is(err, rctypes.ErrHistoryUnavailable), "round %d: %v", r, err)
							return "", false
						}
						return l, true
					}
					up := func(r uint64) bool { l, ok := known(r); return ok && l != ids[dead] }

					// the one certified block: the last pair of the two leaders that were up before X returned, within the covered rounds
					var only uint64
					for r := headAt + lag - 1; r > headAt && only == 0; r-- {
						a, oka := known(r)
						b, okb := known(r + 1)
						if oka && okb && a != ids[dead] && a != ids[x] && b != ids[dead] && b != ids[x] {
							only = r
						}
					}
					if only == 0 {
						skipped++
						continue
					}

					// stage one: the first three live leaders after it. The stale table cannot have them before the covered rounds end, or the shape is not this one.
					first := only + 1
					for !(up(first) && up(first+1) && up(first+2)) {
						first++
						require.Less(t, first, headAt+2*joint, "no live run")
					}
					deadRuns := func(from, to uint64) (count int) {
						for r := from; r <= to; r++ {
							if e.RecoveryRunStart(r) && e.members[((r-start-lag)/RecoverySpacing)%n] == ids[dead] {
								count++
							}
						}
						return count
					}
					stage1 := first + 1 - headAt
					dead1 := deadRuns(headAt+1, first+1)
					commit(only, stale) // it carried a QC from before the stop
					commit(first, liveSet)
					at := first + 1

					// stage two: the fresh request from `resubmit` rounds after the commit, in the next proposal, certified when that block or a later one commits
					fresh := at + resubmit
					r := at + 1
					for {
						if up(r-1) && up(r) && up(r+1) {
							commit(r-1, liveSet)
							if r-1 > fresh {
								break
							}
						}
						r++
						require.Less(t, r, fresh+2*joint, "dead %d x %d head %d: never certified", dead, x, headAt)
					}
					stage2 := r - fresh
					dead2 := deadRuns(fresh, r)

					shapes++
					if resubmit == 1 {
						seen[stage2]++
					}
					total := stage1 + stage2
					longest = max(longest, total)
					require.LessOrEqual(t, dead1+dead2, 1, "dead %d x %d head %d: a dead run in each stage", dead, x, headAt)
					if dead1 == 1 {
						require.LessOrEqual(t, stage1, uint64(withDeadRn), "dead %d x %d head %d", dead, x, headAt)
					} else {
						require.LessOrEqual(t, stage1, uint64(noDeadRun), "dead %d x %d head %d", dead, x, headAt)
					}
					if dead2 == 1 {
						require.LessOrEqual(t, stage2, uint64(withDeadRn), "dead %d x %d head %d", dead, x, headAt)
					} else {
						require.LessOrEqual(t, stage2, uint64(noDeadRun), "dead %d x %d head %d", dead, x, headAt)
					}
					require.LessOrEqual(t, total, uint64(joint), "dead %d x %d head %d", dead, x, headAt)
					outcomes[fmt.Sprintf("R=%d stage two %s, dead run in stage %d", resubmit, bucket(stage2), dead1*1+dead2*2)]++
				}
			}
		}
	}
	require.NotZero(t, shapes)
	t.Logf("stage two rounds at R=1: %v", seen)
	for _, k := range slices.Sorted(maps.Keys(outcomes)) {
		t.Logf("%6d  %s", outcomes[k], k)
	}
	t.Logf("%d shapes, %d without a live pair among the covered rounds, longest joint %d of %d", shapes, skipped, longest, joint)
}

func bucket(rounds uint64) string {
	switch {
	case rounds <= 10:
		return "up to 10"
	case rounds <= 25:
		return "11 to 25"
	case rounds <= 281:
		return "26 to 281"
	default:
		return "over 281"
	}
}
