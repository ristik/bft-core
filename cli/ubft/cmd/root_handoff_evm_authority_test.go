package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type authorityTrust struct{ tb *types.RootTrustBaseV1 }

func (a authorityTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return a.tb, nil
}

// An authority-backed validator's possession proof comes from its signing authority's operator channel (its key never leaves it)
// and verifies in the handoff exactly like a locally signed one.
func TestEVMPoPFromASigningAuthority(t *testing.T) {
	dir := authoritySocketDir(t)
	rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)
	installed := installedPDR(t)
	enrollHash, err := installed.Hash(crypto.SHA256)
	require.NoError(t, err)
	authority, err := signingauthority.New(signingauthority.Enrollment{AuthorityID: "a1", NodeID: "ev-auth", NetworkID: installed.NetworkID,
		PartitionID: installed.PartitionID, ShardID: installed.ShardID, ShardEpoch: installed.Epoch, RootEpoch: signingauthority.PinRootEpoch(1),
		ShardConfHash: enrollHash, Profile: signingauthority.ProfileLegacyBCRv1}, authorityTrust{tb: tb})
	require.NoError(t, err)
	t.Cleanup(authority.Close)
	operatorCredential, err := service.NewCredential()
	require.NoError(t, err)
	server, err := service.NewServer(authority, service.Config{OperatorCredential: operatorCredential})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	operatorListener, err := service.ListenUnix(filepath.Join(dir, "operator.sock"))
	require.NoError(t, err)
	clientListener, err := service.ListenUnix(filepath.Join(dir, "client.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = operatorListener.Close(); _ = clientListener.Close() })
	go func() { _ = server.Serve(operatorListener, service.OperatorEndpoint) }()
	go func() { _ = server.Serve(clientListener, service.ClientEndpoint) }()
	credentialPath := filepath.Join(dir, "operator.cred")
	require.NoError(t, writeCredentialFile(credentialPath, operatorCredential, false))

	key, err := authority.SigningPublicKey()
	require.NoError(t, err)
	infos := []*types.NodeInfo{{NodeID: "ev-auth", SigKey: key, Stake: 1}}
	ctx := consensus.EVMAssignmentContext{Network: uint64(installed.NetworkID), Predecessor: bytes.Repeat([]byte{1}, 32), Attempt: 1,
		FrozenParent: bytes.Repeat([]byte{2}, 32), Installed: installed}
	contextFile := writeJSON(t, dir, "context.json", ctx)
	validatorsFile := writeJSON(t, dir, "validators.json", infos)

	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetArgs(append([]string{"handoff", "evm-pop"}, args...))
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := run("--context", contextFile, "--validators", validatorsFile, "--node-id", "ev-auth",
		"--authority-socket", filepath.Join(dir, "operator.sock"), "--authority-credential", credentialPath)
	require.NoError(t, err)
	var pop evmassign.PoP
	require.NoError(t, json.Unmarshal([]byte(out), &pop))
	_, popContext, err := readContextFile(contextFile)
	require.NoError(t, err)
	succ, err := evmassign.NewSuccessor(installed, infos)
	require.NoError(t, err)
	require.NoError(t, evmassign.VerifyPoPs(popContext, succ, []evmassign.PoP{pop}), "the authority's proof verifies in the handoff")

	t.Run("the shard node's client socket is not the operator channel", func(t *testing.T) {
		_, err := run("--context", contextFile, "--validators", validatorsFile, "--node-id", "ev-auth",
			"--authority-socket", filepath.Join(dir, "client.sock"), "--authority-credential", credentialPath)
		require.Error(t, err, "the client endpoint does not serve a possession proof")
	})
	t.Run("a node that is not the authority's is refused", func(t *testing.T) {
		other := []*types.NodeInfo{{NodeID: "someone-else", SigKey: key, Stake: 1}}
		_, err := run("--context", contextFile, "--validators", writeJSON(t, dir, "other.json", other), "--node-id", "someone-else",
			"--authority-socket", filepath.Join(dir, "operator.sock"), "--authority-credential", credentialPath)
		require.ErrorIs(t, err, signingauthority.ErrContextMismatch)
	})
}
