package cmd

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

// authoritySocketDir is short on purpose: a Unix socket path is limited to about 100 bytes, and the
// default temporary directory on macOS is long enough to matter.
func authoritySocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ubft-sa-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestSigningAuthorityCredentialFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.cred")

	cmd := New(testobserve.NewFactory(t))
	cmd.baseCmd.SetArgs([]string{"signing-authority", "credential", "--out", path})
	require.NoError(t, cmd.Execute(ctx))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	credential, err := readCredentialFile(path)
	require.NoError(t, err)
	require.Len(t, credential, service.CredentialBytes)

	cmd = New(testobserve.NewFactory(t))
	cmd.baseCmd.SetArgs([]string{"signing-authority", "credential", "--out", path})
	require.Error(t, cmd.Execute(ctx), "an existing operator credential is not overwritten")
	unchanged, err := readCredentialFile(path)
	require.NoError(t, err)
	require.Equal(t, credential, unchanged)

	t.Run("replacing writes the new credential in place of the old one", func(t *testing.T) {
		next, err := service.NewCredential()
		require.NoError(t, err)
		replaced := filepath.Join(dir, "client.cred")
		require.NoError(t, writeCredentialFile(replaced, credential, false))
		require.NoError(t, writeCredentialFile(replaced, next, true))
		read, err := readCredentialFile(replaced)
		require.NoError(t, err)
		require.Equal(t, next, read)
	})

	t.Run("a credential other users can read is refused", func(t *testing.T) {
		exposed := filepath.Join(dir, "exposed.cred")
		require.NoError(t, writeCredentialFile(exposed, credential, false))
		require.NoError(t, os.Chmod(exposed, 0o640))
		_, err := readCredentialFile(exposed)
		require.ErrorContains(t, err, "accessible to other users")
	})

	t.Run("a credential of the wrong length is refused", func(t *testing.T) {
		short := filepath.Join(dir, "short.cred")
		require.NoError(t, os.WriteFile(short, []byte(hex.EncodeToString(credential[:16])), 0o600))
		_, err := readCredentialFile(short)
		require.ErrorContains(t, err, "expected 32")
	})
}

func TestShardNodeSigningSelection(t *testing.T) {
	home := t.TempDir()
	keyConf, err := (&keyConfFlags{KeyConfFile: filepath.Join(home, keyConfFileName)}).loadKeyConf(&baseFlags{}, true)
	require.NoError(t, err)
	nodeID, err := keyConf.NodeID()
	require.NoError(t, err)
	authoritySigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	authorityVerifier, err := authoritySigner.Verifier()
	require.NoError(t, err)
	authorityKey, err := authorityVerifier.MarshalPublicKey()
	require.NoError(t, err)
	localKey, ok := localSigningKey(keyConf)
	require.True(t, ok)

	confNaming := func(nodeID string, key []byte) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{
			Version: 1, NetworkID: 5, PartitionID: 7, PartitionTypeID: 1, TypeIDLen: 8, UnitIDLen: 256,
			T2Timeout: 2500 * time.Millisecond, Validators: []*types.NodeInfo{{NodeID: nodeID, SigKey: key, Stake: 1}},
		}
	}
	conf := confNaming(nodeID.String(), authorityKey)
	credentialPath := filepath.Join(home, "client.cred")
	credential, err := service.NewCredential()
	require.NoError(t, err)
	require.NoError(t, writeCredentialFile(credentialPath, credential, false))
	socket := filepath.Join(home, "client.sock")

	t.Run("without authority flags the local key signs, as before", func(t *testing.T) {
		signing, err := buildCertificationSigning(&shardNodeSigningFlags{}, keyConf, conf, false)
		require.NoError(t, err)
		require.NotNil(t, signing.local)
		require.Nil(t, signing.authority)
	})

	t.Run("with an authority no local signer is kept", func(t *testing.T) {
		signing, err := buildCertificationSigning(&shardNodeSigningFlags{
			SigningAuthoritySocket: socket, SigningAuthorityCredential: credentialPath,
		}, keyConf, conf, false)
		require.NoError(t, err)
		defer signing.close()
		require.Nil(t, signing.local, "the round has no local key to fall back to")
		require.NotNil(t, signing.authority)
	})

	refused := func(t *testing.T, flags *shardNodeSigningFlags, conf *types.PartitionDescriptionRecord, contains string) {
		t.Helper()
		signing, err := buildCertificationSigning(flags, keyConf, conf, false)
		require.ErrorContains(t, err, contains)
		require.Nil(t, signing)
	}

	t.Run("an authority flag without the socket does not fall back to the local key", func(t *testing.T) {
		refused(t, &shardNodeSigningFlags{SigningAuthorityCredential: credentialPath}, conf, "without --signing-authority-socket")
		refused(t, &shardNodeSigningFlags{SigningAuthorityTimeout: time.Second}, conf, "without --signing-authority-socket")
	})

	t.Run("the socket without a credential", func(t *testing.T) {
		refused(t, &shardNodeSigningFlags{SigningAuthoritySocket: socket}, conf, "requires --signing-authority-credential")
	})

	t.Run("a configuration that does not name this node", func(t *testing.T) {
		refused(t, &shardNodeSigningFlags{SigningAuthoritySocket: socket, SigningAuthorityCredential: credentialPath},
			confNaming("some-other-node", authorityKey), "does not name this node")
	})

	t.Run("a restoring joiner (a configuration that does not name it) gets a signer whose key is bound later", func(t *testing.T) {
		flags := &shardNodeSigningFlags{SigningAuthoritySocket: socket, SigningAuthorityCredential: credentialPath}
		signing, err := buildCertificationSigning(flags, keyConf, confNaming("some-other-node", authorityKey), true)
		require.NoError(t, err)
		defer signing.close()
		require.NotNil(t, signing.deferred)
		require.Nil(t, signing.local, "still no local signer to fall back to")
		require.Equal(t, nodeID.String(), signing.nodeID)
		// a node the genesis configuration does name keeps its fixed key, restoring or not
		named, err := buildCertificationSigning(flags, keyConf, conf, true)
		require.NoError(t, err)
		defer named.close()
		require.Nil(t, named.deferred)
		// and a plain run of a node the configuration does not name is still refused
		_, err = buildCertificationSigning(flags, keyConf, confNaming("some-other-node", authorityKey), false)
		require.ErrorContains(t, err, "does not name this node")
	})

	t.Run("a configuration naming the key configuration's own signing key", func(t *testing.T) {
		refused(t, &shardNodeSigningFlags{SigningAuthoritySocket: socket, SigningAuthorityCredential: credentialPath},
			confNaming(nodeID.String(), localKey), "local signing key")
	})

	t.Run("a credential other users can read", func(t *testing.T) {
		exposed := filepath.Join(home, "exposed.cred")
		require.NoError(t, writeCredentialFile(exposed, credential, false))
		require.NoError(t, os.Chmod(exposed, 0o644))
		refused(t, &shardNodeSigningFlags{SigningAuthoritySocket: socket, SigningAuthorityCredential: exposed}, conf, "accessible to other users")
	})
}

/*
The deployment sequence end to end, with the commands an operator runs: an authority process that
starts pending, its node info feeding `shard-conf generate`, completion, a client credential, and a
shard node's signer built from its own configuration. What the shard side gets back verifies under
the key the shard configuration names, which is the key the root chain checks, and not under the
key configuration's own signing key.
*/
func TestSigningAuthorityDeploymentSequence(t *testing.T) {
	ctx := context.Background()
	logF := testobserve.NewFactory(t)
	sockets := authoritySocketDir(t)
	home := t.TempDir()
	clientSocket := filepath.Join(sockets, "client", "client.sock")
	operatorSocket := filepath.Join(sockets, "operator", "operator.sock")
	operatorCredential := filepath.Join(home, "operator.cred")

	run := func(args ...string) error {
		c := New(logF)
		c.baseCmd.SetOut(io.Discard)
		c.baseCmd.SetArgs(args)
		return c.Execute(ctx)
	}
	operatorArgs := func(args ...string) []string {
		return append(append([]string{"signing-authority"}, args...),
			"--operator-socket", operatorSocket, "--operator-credential", operatorCredential)
	}
	status := func() signingAuthorityStatus {
		t.Helper()
		var out bytes.Buffer
		c := New(logF)
		c.baseCmd.SetOut(&out)
		c.baseCmd.SetArgs(operatorArgs("status"))
		require.NoError(t, c.Execute(ctx))
		var s signingAuthorityStatus
		require.NoError(t, json.Unmarshal(out.Bytes(), &s))
		return s
	}

	// The shard node keeps its key configuration: its network identity stays with it.
	keyConf, err := (&keyConfFlags{KeyConfFile: filepath.Join(home, keyConfFileName)}).loadKeyConf(&baseFlags{}, true)
	require.NoError(t, err)
	nodeID, err := keyConf.NodeID()
	require.NoError(t, err)

	rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)
	trustBasePath := filepath.Join(home, "trust-base.json")
	require.NoError(t, util.WriteJsonFile(trustBasePath, tb))

	require.NoError(t, run("signing-authority", "credential", "--out", operatorCredential))

	authorityArgs := []string{
		"signing-authority", "run", "--home", home,
		"--client-socket", clientSocket, "--operator-socket", operatorSocket, "--operator-credential", operatorCredential,
		"--trust-base", trustBasePath, "--authority-id", "authority-1", "--node-id", nodeID.String(),
		"--network-id", "5", "--partition-id", "7", "--shard-epoch", "0", "--root-epoch", strconv.FormatUint(tb.GetEpoch(), 10),
	}
	authorityCtx, stopAuthority := context.WithCancel(ctx)
	stopped := make(chan error, 1)
	go func() {
		c := New(logF)
		c.baseCmd.SetArgs(authorityArgs)
		stopped <- c.Execute(authorityCtx)
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			stopAuthority()
			select {
			case err := <-stopped:
				require.NoError(t, err, "the authority stops cleanly when its context ends")
			case <-time.After(10 * time.Second):
				t.Error("the authority did not stop")
			}
		})
	}
	t.Cleanup(stop)
	require.Eventually(t, func() bool { return run(operatorArgs("status")...) == nil }, 20*time.Second, 50*time.Millisecond)

	pending := status()
	require.False(t, pending.EnrollmentComplete)
	require.Equal(t, nodeID.String(), pending.NodeID)
	require.Zero(t, pending.Generation)

	require.ErrorIs(t, run(authorityArgs...), service.ErrPathHeld, "a second authority is not started on a running one's socket")

	clientCredential := filepath.Join(home, "client.cred")
	require.ErrorIs(t, run(append(operatorArgs("replace-session"), "--out", clientCredential)...), signingauthority.ErrEnrollmentIncomplete)
	require.NoFileExists(t, clientCredential, "no client credential exists before the configuration is stated")

	nodeInfo := filepath.Join(home, "authority-node-info.json")
	require.NoError(t, run(append(operatorArgs("node-info"), "--out", nodeInfo)...))
	require.Error(t, run(append(operatorArgs("node-info"), "--out", nodeInfo)...), "existing node info is not overwritten")

	generate := func(nodeInfo string) (*types.PartitionDescriptionRecord, string) {
		t.Helper()
		confHome := t.TempDir()
		require.NoError(t, run("shard-conf", "generate", "--home", confHome, "--network-id", "5", "--partition-id", "7",
			"--partition-type-id", "1", "--epoch-start", "1", "--node-info", nodeInfo))
		path := filepath.Join(confHome, "shard-conf-7_0.json")
		conf, err := util.ReadJsonFile(path, &types.PartitionDescriptionRecord{})
		require.NoError(t, err)
		return conf, path
	}
	conf, confPath := generate(nodeInfo)

	// A configuration generated from the node info shard-node init writes names the key
	// configuration's own key. Both sides refuse it.
	localKey, ok := localSigningKey(keyConf)
	require.True(t, ok)
	localNodeInfo := filepath.Join(home, "local-node-info.json")
	require.NoError(t, util.WriteJsonFile(localNodeInfo, &types.NodeInfo{NodeID: nodeID.String(), SigKey: localKey, Stake: 1}))
	localConf, localConfPath := generate(localNodeInfo)
	require.ErrorIs(t, run(append(operatorArgs("complete-enrollment"), "--shard-conf", localConfPath)...), signingauthority.ErrContextMismatch)
	require.False(t, status().EnrollmentComplete)

	require.NoError(t, run(append(operatorArgs("complete-enrollment"), "--shard-conf", confPath)...))
	require.ErrorIs(t, run(append(operatorArgs("complete-enrollment"), "--shard-conf", confPath)...), signingauthority.ErrContextMismatch,
		"the enrollment is not reopened")
	require.NoError(t, run(append(operatorArgs("replace-session"), "--out", clientCredential)...))

	complete := status()
	require.True(t, complete.EnrollmentComplete)
	confHash, err := conf.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(confHash), complete.ShardConfHash)
	require.EqualValues(t, 1, complete.Generation)

	// The shard node's side, built from its own configuration.
	flags := &shardNodeSigningFlags{SigningAuthoritySocket: clientSocket, SigningAuthorityCredential: clientCredential}
	_, err = buildCertificationSigning(flags, keyConf, localConf, false)
	require.ErrorContains(t, err, "local signing key")
	signing, err := buildCertificationSigning(flags, keyConf, conf, false)
	require.NoError(t, err)
	t.Cleanup(signing.close)
	require.Nil(t, signing.local)

	uc, tr, proposed := certifiedWork(t, rootSigner, conf, nodeID.String())
	signed, err := signing.authority.Sign(ctx, uc, tr, proposed)
	require.NoError(t, err)
	named, err := conf.Validators[0].SigVerifier()
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(named), "the response verifies under the key the shard configuration names for this node")
	localSigner, err := keyConf.Signer()
	require.NoError(t, err)
	localVerifier, err := localSigner.Verifier()
	require.NoError(t, err)
	require.Error(t, signed.IsValid(localVerifier), "and was not made with the key configuration's signing key")
	require.EqualValues(t, 6, status().ReservedRound)

	// Replacing the session again fences the credential the shard node holds.
	require.NoError(t, run(append(operatorArgs("replace-session"), "--out", filepath.Join(home, "next-client.cred"))...))
	_, err = signing.authority.Sign(ctx, uc, tr, proposed)
	require.ErrorIs(t, err, signingauthority.ErrFenced)

	// Stopping the authority leaves the shard node's signer unavailable. Nothing signs in its place.
	stop()
	_, err = signing.authority.Sign(ctx, uc, tr, proposed)
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
}

// certifiedWork is a certificate under the given configuration, its technical record assigning round
// 6, and the request a shard node would propose for that round.
func certifiedWork(t *testing.T, rootSigner abcrypto.Signer, conf *types.PartitionDescriptionRecord, nodeID string) (*types.UnicityCertificate, *certification.TechnicalRecord, *certification.BlockCertificationRequest) {
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: 6, Epoch: 0, Leader: nodeID, StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	stateRoot := bytes.Repeat([]byte{0xa1}, 32)
	uc := testcertificates.CreateUnicityCertificate(t, rootSigner, &types.InputRecord{
		Version: 1, RoundNumber: 5, PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: stateRoot,
		BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: 1,
	}, conf, 41, zero, trHash)
	proposed := &certification.BlockCertificationRequest{
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, NodeID: nodeID,
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: 6, Epoch: 0, PreviousHash: stateRoot,
			Hash: bytes.Repeat([]byte{0xc1}, 32), BlockHash: bytes.Repeat([]byte{0xc2}, 32),
			SummaryValue: []byte{}, Timestamp: uc.UnicitySeal.Timestamp,
		},
	}
	return uc, tr, proposed
}
