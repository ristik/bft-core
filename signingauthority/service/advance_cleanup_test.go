package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
)

// The server's credential cleanup after a proof advance (astra on #1087): the advance's publication fences every session up to its
// generation; a session replacement that lands between that publication and the server's cleanup is newer and must survive, and the
// credential the publication fenced must be dropped. The advance is replaced by its fencing effect on the real authority (a generation
// step), so the interleaving is deterministic; the cleanup and the credential checks are the server's own.
func TestAReplacementBetweenPublicationAndCleanupSurvivesIt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	fenced := f.admit(t) // the shard node's client of the scope the advance leaves
	var replaced []byte
	f.server.advance = func(context.Context, []byte) (signingauthority.AdvanceResult, error) {
		// the publication: the authority's generation steps past the admitted session, which is fenced from here on
		if _, err := f.authority.ReplaceSession(); err != nil {
			return signingauthority.AdvanceResult{}, err
		}
		published := f.authority.Status().Generation
		// an operator's replacement lands now, before the server's cleanup
		credential, err := f.server.replaceSession()
		require.NoError(t, err)
		replaced = credential
		return signingauthority.AdvanceResult{Epoch: 2, Advanced: true, Generation: published}, nil
	}
	_, err := f.operator.AdvanceWithProof(ctx, []byte("a proof"))
	require.NoError(t, err)

	_, err = fenced.RestoreStatus(ctx)
	require.ErrorIs(t, err, signingauthority.ErrFenced, "the credential the publication fenced is dropped")
	fresh, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: replaced, Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer func() { _ = fresh.Close() }()
	_, err = fresh.RestoreStatus(ctx)
	require.NoError(t, err, "the newer credential survives the cleanup")
}

// The other order: a replacement before the publication is fenced by it, and the server drops that credential too.
func TestAReplacementBeforePublicationIsDroppedByTheCleanup(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	_ = f.admit(t)
	var early []byte
	f.server.advance = func(context.Context, []byte) (signingauthority.AdvanceResult, error) {
		credential, err := f.server.replaceSession()
		require.NoError(t, err)
		early = credential
		if _, err := f.authority.ReplaceSession(); err != nil { // the publication, after the replacement
			return signingauthority.AdvanceResult{}, err
		}
		return signingauthority.AdvanceResult{Epoch: 2, Advanced: true, Generation: f.authority.Status().Generation}, nil
	}
	_, err := f.operator.AdvanceWithProof(ctx, []byte("a proof"))
	require.NoError(t, err)
	client, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: early, Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	_, err = client.RestoreStatus(ctx)
	require.ErrorIs(t, err, signingauthority.ErrFenced, "a credential the publication fenced is not admitted")
	f.server.mu.Lock()
	require.False(t, f.server.hasSession, "and the server holds none until the operator issues the next")
	f.server.mu.Unlock()
}
