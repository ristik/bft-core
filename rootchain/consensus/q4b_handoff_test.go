package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/q3format"
)

// Q4 #51 (B) handoff under weighted epochs: A (6,1,1,1) is the activated epoch 2; its committee (H and a, weight 7 of 9, the
// weighted scheme 2 quorum) commits the handoff to B (3,3,2,1) and epoch 3 is installed from that commit under the old epoch's own
// scheme, keys and threshold. One of four identities is replaced (c by d); the three carried identities hold 8 of 9 in both maps.
// The live rows below run B itself. The commit of the handoff is the Q3 fixture's, as in the Q3 tests (the handoff proposal flow of a
// running chain is the live lane's).

func TestQ4BHandoffArithmetic(t *testing.T) {
	c := newQ4BLiveB(t)
	r := c.nodes[0].r
	old, err := r.trust.GetByEpoch(2)
	require.NoError(t, err)
	next, err := r.trust.GetByEpoch(3)
	require.NoError(t, err)

	weights := func(nodes []*types.NodeInfo) (map[string]uint64, uint64) {
		out, total := map[string]uint64{}, uint64(0)
		for _, n := range nodes {
			out[n.NodeID] = n.Stake
			total += n.Stake
		}
		return out, total
	}
	ow, oTotal := weights(old.RootNodes)
	nw, nTotal := weights(next.RootNodes)
	require.EqualValues(t, 9, oTotal)
	require.EqualValues(t, 9, nTotal)
	quorum := func(total uint64) uint64 { return 2*total/3 + 1 }
	require.EqualValues(t, 7, quorum(oTotal))
	require.EqualValues(t, 7, quorum(nTotal))
	require.EqualValues(t, 7, old.QuorumThreshold)
	require.EqualValues(t, 7, next.QuorumThreshold)

	var carried, retainedOld, retainedNew uint64
	var replaced []string
	for id, w := range ow {
		if nwv, ok := nw[id]; ok {
			carried++
			retainedOld += w
			retainedNew += nwv
		} else {
			replaced = append(replaced, id)
		}
	}
	require.EqualValues(t, 3, carried)
	require.Len(t, replaced, 1, "one of four identities replaced")
	require.Less(t, uint64(len(replaced))*3, uint64(len(ow)), "strictly fewer than 1/3 of the identities change")
	require.GreaterOrEqual(t, retainedOld, quorum(oTotal), "the carried identities are a quorum of the old map")
	require.GreaterOrEqual(t, retainedNew, quorum(nTotal), "and of the new map")
	require.EqualValues(t, 8, retainedOld)
	require.EqualValues(t, 8, retainedNew)
	require.NotEqual(t, ow, nw, "reweighting is explicit")
	d := c.id("d").String()
	require.EqualValues(t, 1, nw[d])
	_, wasOld := ow[d]
	require.False(t, wasOld, "d is a new identity")

	t.Run("every replica installed epoch 3 from the verified history and runs root-wrr-v1 from A* with its own policy per epoch", func(t *testing.T) {
		for _, n := range c.nodes {
			start := n.r.manager.epochAnchor.Slot + 1
			requireWeightedEpoch(t, n.r, 3, start)
			for epoch, want := range map[uint64]string{2: q3format.LeaderPolicyWeightedV1, 3: q3format.LeaderPolicyWeightedV1} {
				got, err := n.r.trust.LeaderPolicy(epoch)
				require.NoError(t, err)
				require.Equal(t, want, got, "%s epoch %d", n.name, epoch)
			}
			require.NoError(t, n.r.rt.Admit(3))
		}
	})
}
