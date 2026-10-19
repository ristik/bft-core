package shardnode

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// A shard that was idle across several scheduled epochs is certified directly under the newest one (old input record, new technical
// record, new configuration hash). The client accepts exactly that: the epoch of the technical record names the configuration, an
// installed later epoch is acceptable for an input record of an earlier one, the skipped epochs have nothing installed (and so name
// nothing), and an epoch whose configuration is not installed yet is retryable - never validated under another epoch's hash.
func TestShardConfSetAfterAJumpOverSkippedEpochs(t *testing.T) {
	h := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	set, err := NewShardConfSet(h(0))
	require.NoError(t, err)
	require.NoError(t, set.Install(3, h(3)))

	got, err := set.ForEpoch(3)
	require.NoError(t, err)
	require.Equal(t, h(3), got, "the technical record's epoch names the configuration")
	for _, skipped := range []uint64{1, 2} {
		_, err = set.ForEpoch(skipped)
		require.ErrorIs(t, err, ErrShardConfEpochUnknown, "epoch %d was never applied: nothing is invented for it", skipped)
	}
	require.Equal(t, [][]byte{h(0), h(3)}, set.ForIREpoch(0), "an input record still of epoch 0 may sit under the newly applied epoch 3")
	require.Equal(t, [][]byte{h(3)}, set.ForIREpoch(1))
	_, err = set.ForEpoch(4)
	require.ErrorIs(t, err, ErrShardConfEpochUnknown, "a configuration not installed yet is retryable")
	require.NoError(t, set.Install(4, h(4)))
	got, err = set.ForEpoch(4)
	require.NoError(t, err)
	require.Equal(t, h(4), got)
	require.ErrorIs(t, set.Install(3, h(9)), ErrShardConfConflict, "a different hash for an installed epoch is refused")
}
