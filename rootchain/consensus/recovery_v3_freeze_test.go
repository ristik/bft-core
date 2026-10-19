package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A root that state-imports in the genesis epoch must keep the V3 freeze rules the started root has: the replacement store gets the same
// authority setup as startup (bft-core#648). Without it the root refuses the V3 handoff block ("V3 freeze rules are not enabled").
func TestGenesisEpochStateImportKeepsTheV3FreezeRules(t *testing.T) {
	f := newPlanFixtureOpts(t, true)
	cm := f.cm
	require.True(t, cm.blockStore.V3FreezeEnabled(), "control: the started root has the rules")
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	before := cm.blockStore
	require.NoError(t, recoverTo(t, cm, state))
	require.NotSame(t, before, cm.blockStore, "premise: recovery replaced the block store")
	require.True(t, cm.blockStore.V3FreezeEnabled(), "the replacement store keeps the V3 freeze rules")
}

// Without a Q3 history there are no V3 rules to keep, and the recovered root has none either.
func TestGenesisEpochStateImportWithoutQ3HasNoV3Rules(t *testing.T) {
	f := newPlanFixtureOpts(t, false)
	state, err := f.cm.blockStore.GetState()
	require.NoError(t, err)
	require.NoError(t, recoverTo(t, f.cm, state))
	require.False(t, f.cm.blockStore.V3FreezeEnabled())
}
