package shardnode

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

var _ recordKeepingSigner = (*DeferredAuthoritySigner)(nil)

// A joiner's authority signer signs nothing until its expected key is bound from a verified source; then it is the ordinary signer.
func TestADeferredAuthoritySignerFailsClosedUntilItsKeyIsBound(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, health := f.round(t)
	authority, session := f.authorityFor(t)
	deferred, err := NewDeferredAuthoritySigner(signingauthority.NewLocalClient(authority, session))
	require.NoError(t, err)
	r.SetCertificationSigner(deferred)

	_, err = deferred.Sign(ctx, f.uc, f.tr, nil)
	require.ErrorIs(t, err, ErrAuthorityKeyUnbound)
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.Empty(t, sub.sent, "nothing is signed before the key is bound")
	require.False(t, health.Snapshot().Voting)
	require.False(t, authority.Status().HasReservation, "the authority was not even asked")

	require.NoError(t, deferred.BindKey(f.authorityKey(t, authority)))
	r2, sub2, health2 := f.round(t)
	r2.SetCertificationSigner(deferred)
	require.NoError(t, r2.HandleCertificate(ctx, f.uc, f.tr))
	require.Len(t, sub2.reqs, 1)
	require.True(t, health2.Snapshot().Voting)
	pub, err := authority.SigningPublicKey()
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(pub)
	require.NoError(t, err)
	require.NoError(t, sub2.reqs[0].IsValid(verifier))
}

func TestADeferredAuthoritySignerBindsOneKeyForGood(t *testing.T) {
	f := newWiringFixture(t)
	authority, session := f.authorityFor(t)
	deferred, err := NewDeferredAuthoritySigner(signingauthority.NewLocalClient(authority, session))
	require.NoError(t, err)
	key := f.authorityKey(t, authority)
	require.NoError(t, deferred.BindKey(key))
	require.NoError(t, deferred.BindKey(key), "the same key again is a no-op")
	require.ErrorIs(t, deferred.BindKey(f.localVerifier(t)), ErrAuthorityKeyConflict, "another key is an inconsistency, not a rotation")
	require.Error(t, deferred.BindKey(nil))
	_, err = NewDeferredAuthoritySigner(nil)
	require.Error(t, err)
}

// probeClient is a client with the restore-status probe the process client has.
type probeClient struct {
	SigningAuthorityClient
	status signingauthority.Status
}

func (p probeClient) RestoreStatus(context.Context) (signingauthority.Status, error) {
	return p.status, nil
}

// The restore readiness probes need the client only, so a joiner can run them before any key is known.
func TestADeferredAuthoritySignerAnswersTheRestoreProbesBeforeItsKeyIsBound(t *testing.T) {
	f := newWiringFixture(t)
	authority, session := f.authorityFor(t)
	client := probeClient{SigningAuthorityClient: signingauthority.NewLocalClient(authority, session), status: signingauthority.Status{Generation: 1}}
	deferred, err := NewDeferredAuthoritySigner(client)
	require.NoError(t, err)
	status, err := deferred.RestoreStatus(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, status.Generation)
	require.NoError(t, deferred.RestoreReadiness(context.Background(), 0))
}

// A staging-only joiner is built without a session (the authority issues none before its enrollment names its key); the session is
// provisioned when a request needs it after the key is bound, and not before.
func TestALazyDeferredAuthoritySignerProvisionsItsSessionOnlyAfterTheKeyIsBound(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	authority, session := f.authorityFor(t)
	calls, issued := 0, false
	deferred, err := NewLazyDeferredAuthoritySigner(func() (SigningAuthorityClient, error) {
		calls++
		if !issued {
			return nil, errors.New("no credential yet")
		}
		return probeClient{SigningAuthorityClient: signingauthority.NewLocalClient(authority, session), status: signingauthority.Status{Generation: 1}}, nil
	})
	require.NoError(t, err)
	_, err = NewLazyDeferredAuthoritySigner(nil)
	require.Error(t, err)

	_, err = deferred.Sign(ctx, f.uc, f.tr, nil)
	require.ErrorIs(t, err, ErrAuthorityKeyUnbound)
	require.NoError(t, deferred.RestoreReadiness(ctx, 0), "a staging-only joiner signs nothing: nothing to be ready for")
	_, err = deferred.RestoreStatus(ctx)
	require.ErrorIs(t, err, ErrAuthoritySessionUnavailable)

	callsBefore := calls
	require.NoError(t, deferred.BindKey(f.authorityKey(t, authority)))
	require.Equal(t, callsBefore, calls, "binding the key does not itself ask for a session")
	_, err = deferred.Sign(ctx, f.uc, f.tr, nil)
	require.ErrorIs(t, err, ErrAuthoritySessionUnavailable, "bound, session not issued yet")
	require.ErrorIs(t, deferred.RestoreReadiness(ctx, 0), ErrAuthoritySessionUnavailable, "a bound signer needs its session")

	issued = true
	r, sub, health := f.round(t)
	r.SetCertificationSigner(deferred)
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.Len(t, sub.reqs, 1, "promoted: signs through the acquired session")
	require.True(t, health.Snapshot().Voting)
	require.NoError(t, deferred.RestoreReadiness(ctx, 0))
}
