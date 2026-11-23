package cmd

import (
	"bytes"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

type managedAuthorityFixture struct {
	managedWrites                       *atomic.Int32
	authority                           *signingauthority.Authority
	operatorSocket, clientSocket, proof string
	operatorCredential, managed         string
}

func newManagedAuthorityFixture(t *testing.T) managedAuthorityFixture {
	t.Helper()
	sockets := authoritySocketDir(t)
	dir := t.TempDir()
	fixture := managedAuthorityFixture{
		managedWrites:      new(atomic.Int32),
		operatorSocket:     filepath.Join(sockets, "operator.sock"),
		clientSocket:       filepath.Join(sockets, "client.sock"),
		operatorCredential: filepath.Join(dir, "operator.cred"),
		managed:            filepath.Join(dir, "managed", "client.cred"),
		proof:              filepath.Join(dir, "activation.cbor"),
	}
	require.NoError(t, os.Mkdir(filepath.Dir(fixture.managed), 0o700))
	root := q3fixture.New(t, q3fixture.Options{})
	conf := root.ShardConf
	hash, err := conf.Hash(crypto.SHA256)
	require.NoError(t, err)
	fixture.authority, err = signingauthority.New(signingauthority.Enrollment{
		AuthorityID: "a", NodeID: conf.Validators[0].NodeID, NetworkID: conf.NetworkID,
		PartitionID: conf.PartitionID, ShardID: conf.ShardID, ShardEpoch: conf.Epoch,
		RootEpoch: signingauthority.PinRootEpoch(1), ShardConfHash: hash, Profile: signingauthority.ProfileLegacyBCRv1,
	}, authorityTrust{tb: root.Old}, signingauthority.WithLineage(root.Old, root.UTB))
	require.NoError(t, err)
	t.Cleanup(fixture.authority.Close)
	proof, err := q3active.EncodeBundle(q3active.Bundle{Envelope: root.EnvelopeBytes, Snapshot: root.Snapshot, Candidate: root.Candidate})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture.proof, proof, 0o600))
	credential, err := service.NewCredential()
	require.NoError(t, err)
	require.NoError(t, writeCredentialFile(fixture.operatorCredential, credential, false))
	operator, err := service.ListenUnix(fixture.operatorSocket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = operator.Close() })
	client, err := service.ListenUnix(fixture.clientSocket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	destination, target, err := sessionPublicationTarget(fixture.operatorSocket, fixture.managed)
	require.NoError(t, err)
	server, err := service.NewServer(fixture.authority, service.Config{
		OperatorCredential: credential,
		ManagedSession: service.ManagedSession{
			Target: target,
			Publish: func(credential []byte) error {
				fixture.managedWrites.Add(1)
				return writeCredentialFile(destination, credential, true)
			},
			Matches: func(credential []byte) (bool, error) {
				current, err := readCredentialFile(destination)
				return bytes.Equal(current, credential), err
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	go func() { _ = server.Serve(operator, service.OperatorEndpoint) }()
	go func() { _ = server.Serve(client, service.ClientEndpoint) }()
	return fixture
}

func (f managedAuthorityFixture) run(t *testing.T, command, destination string) (advanceWithProofReport, error) {
	t.Helper()
	var cmd *cobra.Command
	args := []string{"--operator-socket", f.operatorSocket, "--operator-credential", f.operatorCredential, "--out", destination}
	if command == "advance-with-proof" {
		cmd = signingAuthorityAdvanceWithProofCmd(&baseFlags{})
		args = append(args, "--proof", f.proof, "--client-socket", f.clientSocket)
	} else {
		cmd = signingAuthorityReplaceSessionCmd(&baseFlags{})
	}
	var stdout, stderr bytes.Buffer
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	var report advanceWithProofReport
	err := cmd.ExecuteContext(t.Context())
	if err == nil && command == "advance-with-proof" {
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
	}
	return report, err
}

func TestOperatorCredentialCommandsResolveSymlinkParentInFilesystemOrder(t *testing.T) {
	for _, command := range []string{"advance-with-proof", "replace-session"} {
		t.Run(command, func(t *testing.T) {
			for _, physicallyManaged := range []bool{true, false} {
				name := "physically alternate"
				if physicallyManaged {
					name = "physically managed"
				}
				t.Run(name, func(t *testing.T) {
					f := newManagedAuthorityFixture(t)
					_, err := f.run(t, "replace-session", f.managed)
					require.NoError(t, err)
					old, err := os.ReadFile(f.managed)
					require.NoError(t, err)
					managedDir := filepath.Dir(f.managed)
					alternateDir := filepath.Join(filepath.Dir(managedDir), "alternate")
					alternate := filepath.Join(alternateDir, "client.cred")
					require.NoError(t, os.Mkdir(alternateDir, 0o700))

					from, to, destination := managedDir, alternateDir, alternate
					if physicallyManaged {
						from, to, destination = alternateDir, managedDir, f.managed
					}
					require.NoError(t, os.Mkdir(filepath.Join(to, "nested"), 0o700))
					require.NoError(t, os.Symlink(filepath.Join(to, "nested"), filepath.Join(from, "link")))
					redirected := from + "/link/../client.cred" // deliberately preserve the traversal
					_, err = f.run(t, command, redirected)
					require.NoError(t, err)
					require.NoError(t, checkClientCredential(t.Context(), f.clientSocket, destination, time.Second))
					if physicallyManaged {
						require.EqualValues(t, 2, f.managedWrites.Load(), "the server published both managed credentials")
						require.NoFileExists(t, alternate)
					} else {
						require.EqualValues(t, 1, f.managedWrites.Load(), "the alternate write stays outside the managed file")
						managed, err := os.ReadFile(f.managed)
						require.NoError(t, err)
						require.Equal(t, old, managed)
						require.ErrorIs(t, checkClientCredential(t.Context(), f.clientSocket, f.managed, time.Second), signingauthority.ErrFenced)
					}
				})
			}
			t.Run("unresolvable parent", func(t *testing.T) {
				f := newManagedAuthorityFixture(t)
				before := f.authority.Status()
				_, err := f.run(t, command, filepath.Dir(f.managed)+"/missing/../client.cred")
				require.ErrorContains(t, err, "resolving parent of credential")
				require.Equal(t, before, f.authority.Status())
			})
		})
	}
}

func TestAdvanceWithProofReplayPreservesAlternateUntilForcedRotation(t *testing.T) {
	f := newManagedAuthorityFixture(t)
	report, err := f.run(t, "advance-with-proof", f.managed)
	require.NoError(t, err)
	require.True(t, report.Advanced && report.SessionIssued)
	managedBefore, err := os.ReadFile(f.managed)
	require.NoError(t, err)
	alternate := filepath.Join(filepath.Dir(f.managed), "offline.cred")
	_, err = f.run(t, "replace-session", alternate)
	require.NoError(t, err)
	before := f.authority.Status()

	report, err = f.run(t, "advance-with-proof", f.managed)
	require.NoError(t, err)
	require.Len(t, report.Steps, 1)
	require.True(t, report.Steps[0].Replay)
	require.False(t, report.SessionIssued)
	_, target, err := sessionPublicationTarget(f.operatorSocket, alternate)
	require.NoError(t, err)
	require.Equal(t, target, report.ActiveAlternate)
	require.Equal(t, before, f.authority.Status())
	managedAfter, err := os.ReadFile(f.managed)
	require.NoError(t, err)
	require.Equal(t, managedBefore, managedAfter)
	require.NoError(t, checkClientCredential(t.Context(), f.clientSocket, alternate, time.Second))
	require.ErrorIs(t, checkClientCredential(t.Context(), f.clientSocket, f.managed, time.Second), signingauthority.ErrFenced)

	_, err = f.run(t, "replace-session", f.managed)
	require.NoError(t, err)
	require.NoError(t, checkClientCredential(t.Context(), f.clientSocket, f.managed, time.Second))
	require.ErrorIs(t, checkClientCredential(t.Context(), f.clientSocket, alternate, time.Second), signingauthority.ErrFenced)
	report, err = f.run(t, "advance-with-proof", f.managed)
	require.NoError(t, err)
	require.Empty(t, report.ActiveAlternate)
	require.False(t, report.SessionIssued)
}
