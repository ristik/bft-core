package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
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
}

// The authority-held EVM key: both holders and a half-given authority are refused, a working configuration yields the authority provider.
func TestVRMemberConfigWithAnAuthority(t *testing.T) {
	home := t.TempDir()
	cred, err := service.NewCredential()
	require.NoError(t, err)
	credFile := filepath.Join(t.TempDir(), "pop.cred")
	require.NoError(t, writeCredentialFile(credFile, cred, false))
	sock := filepath.Join(t.TempDir(), "pop.sock")

	_, err = vrMemberConfig(home, filepath.Join(t.TempDir(), keyConfFileName), vrEVMAuthority{Socket: sock, Credential: credFile})
	require.ErrorIs(t, err, ErrVRHandoffCmd, "two holders of the EVM key")
	_, err = vrMemberConfig(home, "", vrEVMAuthority{Socket: sock})
	require.ErrorIs(t, err, ErrVRHandoffCmd, "a socket without a credential")
	_, err = vrMemberConfig(home, "", vrEVMAuthority{Credential: credFile})
	require.ErrorIs(t, err, ErrVRHandoffCmd, "a credential without a socket")
	_, err = vrMemberConfig(home, "", vrEVMAuthority{Socket: sock, Credential: filepath.Join(t.TempDir(), "missing")})
	require.ErrorIs(t, err, ErrVRHandoffCmd, "an unreadable credential")

	m, err := vrMemberConfig(home, "", vrEVMAuthority{Socket: sock, Credential: credFile})
	require.NoError(t, err)
	require.IsType(t, vrschedule.AuthorityPoP{}, m.EVMPoP)
	require.Nil(t, m.EVMSigner, "no EVM key in the root process")

	m, err = vrMemberConfig(home, "")
	require.NoError(t, err)
	require.Nil(t, m.EVMPoP)
}
