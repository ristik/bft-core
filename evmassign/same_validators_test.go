package evmassign

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestSameValidatorsIsAboutTheSetNotTheOrder(t *testing.T) {
	node := func(id string, stake uint64, key byte) *types.NodeInfo {
		return &types.NodeInfo{NodeID: id, Stake: stake, SigKey: []byte{key}}
	}
	// the installed genesis configuration keeps its generation order; a successor is sorted by node id
	installed := []*types.NodeInfo{node("b", 1, 2), node("d", 1, 4), node("a", 1, 1), node("c", 1, 3)}
	sorted := []*types.NodeInfo{node("a", 1, 1), node("b", 1, 2), node("c", 1, 3), node("d", 1, 4)}

	require.True(t, sameValidators(sorted, installed), "the same four, differently ordered")
	require.True(t, sameValidators(installed, sorted))
	require.True(t, sameValidators(sorted, sorted))
	require.True(t, sameValidators(nil, nil))

	changed := func(f func(v []*types.NodeInfo)) []*types.NodeInfo {
		v := []*types.NodeInfo{node("a", 1, 1), node("b", 1, 2), node("c", 1, 3), node("d", 1, 4)}
		f(v)
		return v
	}
	for name, other := range map[string][]*types.NodeInfo{
		"a stake changed":   changed(func(v []*types.NodeInfo) { v[2].Stake = 2 }),
		"a key changed":     changed(func(v []*types.NodeInfo) { v[1].SigKey = []byte{9} }),
		"a member replaced": changed(func(v []*types.NodeInfo) { v[3] = node("e", 1, 4) }),
		"a member missing":  changed(func(v []*types.NodeInfo) {})[:3],
		"a nil member":      changed(func(v []*types.NodeInfo) { v[0] = nil }),
	} {
		require.False(t, sameValidators(other, installed), name)
		require.False(t, sameValidators(installed, other), name)
	}
}
