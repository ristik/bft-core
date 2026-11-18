package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// --vr-evm-keys names the EVM shard node's keys.json: its key and node id become the member's, the member file is in the home, and a wrong
// file name, a missing file or no flag are told apart.
func TestVRMemberConfigReadsTheEVMKeys(t *testing.T) {
	home := t.TempDir()
	evm := t.TempDir()
	kc, err := generateKeys()
	require.NoError(t, err)
	raw, err := json.Marshal(kc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(evm, keyConfFileName), raw, 0o600))
	want, err := kc.NodeID()
	require.NoError(t, err)

	m, err := vrMemberConfig(home, filepath.Join(evm, keyConfFileName))
	require.NoError(t, err)
	require.Equal(t, want.String(), m.EVMNodeID)
	require.NotNil(t, m.EVMSigner)
	require.Equal(t, filepath.Join(home, vrMemberFileName), m.Path)
	require.Nil(t, m.Hold, "the development hold hook is off unless asked for")

	m, err = vrMemberConfig(home, "")
	require.NoError(t, err)
	require.Nil(t, m.EVMSigner, "without the flag the node signs readiness but sends no possession proof")

	_, err = vrMemberConfig(home, filepath.Join(evm, "other.json"))
	require.ErrorIs(t, err, ErrVRHandoffCmd)
	_, err = vrMemberConfig(home, filepath.Join(t.TempDir(), keyConfFileName))
	require.ErrorIs(t, err, ErrVRHandoffCmd)

	t.Setenv("UBFT_VR_MEMBER_HOLD", "1")
	m, err = vrMemberConfig(home, "")
	require.NoError(t, err)
	require.False(t, m.Hold())
	require.NoError(t, os.WriteFile(filepath.Join(home, "vr-member.hold"), nil, 0o600))
	require.True(t, m.Hold())
}
