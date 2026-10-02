package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// setInstaller is the node surface backed by the real configuration set, recording the order of installs.
type setInstaller struct {
	set   *shardnode.ShardConfSet
	calls []uint64
}

func (s *setInstaller) InstallShardConf(epoch uint64, hash []byte) error {
	s.calls = append(s.calls, epoch)
	return s.set.Install(epoch, hash)
}

// A verified assignment step is the only production source of the node's per-epoch shard configuration set: both its old and its new
// (epoch, hash) are installed, old first, and a contradiction with what is installed stops the handoff from activating.
func TestVerifiedAssignmentStepsAreInstalledIntoTheShardConfigurationSet(t *testing.T) {
	h := func(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }
	genesis := h(1)
	set, err := shardnode.NewShardConfSet(genesis[:])
	require.NoError(t, err)
	node := &setInstaller{set: set}

	t.Run("an assignment step installs the successor epoch's configuration, old before new", func(t *testing.T) {
		step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 0, NewShardEpoch: 1, OldActiveConfHash: genesis, NewActiveConfHash: h(2)}
		require.NoError(t, installAssignmentStepConfs(node, step))
		require.Equal(t, []uint64{0, 1}, node.calls)
		got, err := set.ForEpoch(1)
		require.NoError(t, err)
		want := h(2)
		require.Equal(t, want[:], got)
	})
	t.Run("replaying the step is harmless (restore, then catch-up)", func(t *testing.T) {
		step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 0, NewShardEpoch: 1, OldActiveConfHash: genesis, NewActiveConfHash: h(2)}
		require.NoError(t, installAssignmentStepConfs(node, step))
	})
	t.Run("a root-only step keeps the installed configuration", func(t *testing.T) {
		step := handoff.AssignmentStep{OldShardEpoch: 1, NewShardEpoch: 1, OldActiveConfHash: h(2), NewActiveConfHash: h(2)}
		require.NoError(t, installAssignmentStepConfs(node, step))
	})
	t.Run("a step that contradicts the installed configuration is refused", func(t *testing.T) {
		bad := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 1, NewShardEpoch: 2, OldActiveConfHash: h(9), NewActiveConfHash: h(3)}
		require.ErrorIs(t, installAssignmentStepConfs(node, bad), shardnode.ErrShardConfConflict, "the old side names another hash for epoch 1")
		_, err := set.ForEpoch(2)
		require.ErrorIs(t, err, shardnode.ErrShardConfEpochUnknown, "nothing of a refused step is installed")
		conflictNew := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 1, NewShardEpoch: 1, OldActiveConfHash: h(2), NewActiveConfHash: h(7)}
		require.ErrorIs(t, installAssignmentStepConfs(node, conflictNew), shardnode.ErrShardConfConflict, "the new side names another hash for the installed epoch")
	})
}
