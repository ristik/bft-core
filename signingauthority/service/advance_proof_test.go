package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/signingauthority"
)

// A proof verification holds no lock the shard node needs (astra on #1087): while one is in progress the client goes on reserving,
// signing, retaining and releasing, and a second proof is refused at once (ErrAdvanceBusy) instead of queueing behind the first.
func TestAProofVerificationBlocksNeitherTheClientNorTheBusyRefusal(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	first := true
	f := newFixtureWith(t, nil, func(tb *types.RootTrustBaseV1) []signingauthority.Option {
		return []signingauthority.Option{signingauthority.WithLineage(tb, false), signingauthority.WithAdvanceHook(func() {
			if first { // only the first verification pauses; the busy refusal comes before the hook
				first = false
				close(entered)
				<-release
			}
		})}
	})
	client := f.admit(t)
	ctx := context.Background()

	firstDone := make(chan error, 1)
	go func() {
		_, err := f.operator.AdvanceWithProof(ctx, []byte("not a bundle"))
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first verification did not start")
	}

	progressed := make(chan error, 1)
	go func() {
		auth, err := client.Reserve(ctx, f.request())
		if err == nil {
			err = client.Sign(ctx)
		}
		if err == nil {
			err = client.RetainResponse(ctx)
		}
		if err == nil {
			_, err = client.Release(ctx, auth.AssignedRound, auth.UnsignedDigest)
		}
		progressed <- err
	}()
	select {
	case err := <-progressed:
		require.NoError(t, err, "the client's whole exchange completes during the verification")
	case <-time.After(5 * time.Second):
		t.Fatal("the client is blocked by a proof verification")
	}

	second, err := NewOperatorClient(ClientConfig{Dial: f.operatorDial, Credential: f.operatorCredential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer func() { _ = second.Close() }()
	started := time.Now()
	_, err = second.AdvanceWithProof(ctx, []byte("not a bundle either"))
	require.ErrorIs(t, err, signingauthority.ErrAdvanceBusy)
	require.Less(t, time.Since(started), 2*time.Second, "refused at once, not queued")

	close(release)
	require.ErrorIs(t, <-firstDone, signingauthority.ErrLineageUnverified)
	_, err = client.RestoreStatus(ctx)
	require.NoError(t, err, "a refused proof changes nothing: the client's credential is still the admitted one")
}
