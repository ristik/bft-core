package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoff"
)

func TestLoadEngineEpochTransition(t *testing.T) {
	transition := handoff.EVMTransition{OldRootEpoch: 6, NewRootEpoch: 7, OldActiveConfHash: [32]byte{9}, NewActiveConfHash: [32]byte{9}, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
		Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4}, FrozenParent: [32]byte{5},
			SuccessorParent: [32]byte{5}, SuccessorTR: [32]byte{6}, EVMRound: 7}}
	encoded, err := transition.Encode()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "epoch-transition.cbor")
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	loaded, err := loadEngineEpochTransition(path, 6)
	require.NoError(t, err)
	require.Equal(t, encoded, loaded)

	_, err = loadEngineEpochTransition(path, 5)
	require.ErrorContains(t, err, "configured root trust base is epoch 5")
	require.NoError(t, os.WriteFile(path, []byte{0x80}, 0o600))
	_, err = loadEngineEpochTransition(path, 6)
	require.ErrorContains(t, err, "decoding --engine-epoch-transition")
	_, err = loadEngineEpochTransition(filepath.Join(t.TempDir(), "missing.cbor"), 6)
	require.ErrorContains(t, err, "reading --engine-epoch-transition")
	empty, err := loadEngineEpochTransition("", 6)
	require.NoError(t, err)
	require.Empty(t, empty)
}
