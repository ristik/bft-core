package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

func TestManagedOperatorAndFollowerPublishInIssueOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.cred")
	firstWrite, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Uint32
	f := newConfiguredFixture(t, nil, nil, ManagedSession{
		Target: "client.cred",
		Publish: func(credential []byte) error {
			if writes.Add(1) == 2 {
				close(firstWrite)
				<-release
			}
			return os.WriteFile(path, credential, 0o600)
		},
		Matches: func(credential []byte) (bool, error) {
			onDisk, err := os.ReadFile(path)
			return bytes.Equal(onDisk, credential), err
		},
	})
	ctx := t.Context()
	require.NoError(t, f.server.FollowSession())
	require.Zero(t, writes.Load(), "automatic following cannot bootstrap the client")
	publication, err := f.operator.PublishSession(ctx, "client.cred", true)
	require.NoError(t, err)
	require.True(t, publication.Managed && publication.Issued && f.server.SessionProvisioned())
	baseline, err := os.ReadFile(path)
	require.NoError(t, err)

	// Model a verified scope publication fencing the old generation and leaving
	// the already-provisioned incumbent without an admitted session.
	f.server.advance = func(context.Context, []byte) (signingauthority.AdvanceResult, error) {
		session, err := f.authority.ReplaceSession()
		return signingauthority.AdvanceResult{Advanced: true, Generation: session.Generation()}, err
	}
	_, err = f.operator.AdvanceWithProof(ctx, []byte("successor"))
	require.NoError(t, err)

	followDone := make(chan error, 1)
	go func() { followDone <- f.server.FollowSession() }()
	select {
	case <-firstWrite:
	case err := <-followDone:
		t.Fatalf("follower did not start publication: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the follower to publish")
	}
	operatorDone := make(chan error, 1)
	operatorStarted := make(chan struct{})
	go func() {
		close(operatorStarted)
		publication, err := f.operator.PublishSession(ctx, "client.cred", true)
		if err == nil && !(publication.Managed && publication.Issued) {
			err = errors.New("operator did not replace the managed session")
		}
		operatorDone <- err
	}()
	<-operatorStarted
	select {
	case err := <-operatorDone:
		close(release)
		<-followDone
		t.Fatalf("operator completed while follower owned publication: %v", err)
	case <-time.After(50 * time.Millisecond):
		close(release)
	}
	require.NoError(t, <-followDone)
	require.NoError(t, <-operatorDone)
	require.EqualValues(t, 3, writes.Load())
	final, err := os.ReadFile(path)
	require.NoError(t, err)
	require.False(t, bytes.Equal(baseline, final))

	check := func(credential []byte) error {
		c, err := NewClient(ClientConfig{Credential: credential, Dial: f.clientDir, Timeout: time.Second})
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.RestoreStatus(ctx)
		return err
	}
	require.NoError(t, check(final), "the final file authenticates after both writers finish")
	require.ErrorIs(t, check(baseline), signingauthority.ErrFenced)
	_, err = f.operator.ReplaceSession(ctx)
	require.ErrorIs(t, err, ErrManagedSession, "legacy callers cannot issue a credential they could write out of order")
	_, err = f.operator.ReplaceSessionFor(ctx, "client.cred")
	require.ErrorIs(t, err, ErrManagedSession)

	alternate, err := f.operator.ReplaceSessionFor(ctx, "offline.cred")
	require.NoError(t, err)
	require.NoError(t, f.server.FollowSession())
	require.EqualValues(t, 3, writes.Load(), "the follower does not undo a deliberate fence in the same scope")
	require.ErrorIs(t, check(final), signingauthority.ErrFenced)
	require.NoError(t, check(alternate))
}

func TestManagedSessionRecoversAfterOperatorDisconnectsAndPublicationFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.cred")
	var unwritable atomic.Bool
	f := newConfiguredFixture(t, nil, nil, ManagedSession{
		Target: "client.cred",
		Publish: func(credential []byte) error {
			if unwritable.Load() {
				return os.ErrPermission
			}
			return os.WriteFile(path, credential, 0o600)
		},
		Matches: func(credential []byte) (bool, error) {
			onDisk, err := os.ReadFile(path)
			return bytes.Equal(onDisk, credential), err
		},
	})
	ctx := t.Context()
	_, err := f.operator.PublishSession(ctx, "client.cred", true)
	require.NoError(t, err)
	initial, err := os.ReadFile(path)
	require.NoError(t, err)

	published := make(chan struct{})
	f.server.advance = func(context.Context, []byte) (signingauthority.AdvanceResult, error) {
		defer close(published)
		session, err := f.authority.ReplaceSession()
		return signingauthority.AdvanceResult{Advanced: true, Generation: session.Generation()}, err
	}
	conn, err := f.operatorDial(ctx)
	require.NoError(t, err)
	require.NoError(t, writeFrame(conn, wireRequest{
		Version: protocolVersion, Op: uint64(opAdvanceWithProof), Credential: f.operatorCredential, Payload: []byte("successor"),
	}))
	require.NoError(t, conn.Close(), "the operator never reads the advance reply")
	select {
	case <-published:
	case <-time.After(5 * time.Second):
		t.Fatal("the disconnected operator's proof was not applied")
	}
	require.True(t, f.server.SessionProvisioned())
	unwritable.Store(true)
	require.ErrorIs(t, f.server.FollowSession(), ErrCredentialPublication)
	old, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, initial, old)
	unwritable.Store(false)
	require.NoError(t, f.server.FollowSession())
	repaired, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEqual(t, initial, repaired)
	c, err := NewClient(ClientConfig{Credential: repaired, Dial: f.clientDir, Timeout: time.Second})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.RestoreStatus(ctx)
	require.NoError(t, err, "the repaired file holds the admitted credential")
}
