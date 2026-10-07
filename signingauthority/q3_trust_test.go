package signingauthority

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

// The authority's own trust, provisioned from the verified Q3 history: a request is authenticated against the weights of the
// activated epoch only once the install journal has completed, with the quorum those weights define, and never before.
func TestAuthenticationOverTheGuardedLookupFollowsTheInstalledActivation(t *testing.T) {
	ctx := context.Background()
	q := q3fixture.New(t, q3fixture.Options{}) // member 0 weighs 6, the others 1: W=9, quorum 7
	p := q3process.New(t, q)
	rt := p.Start()
	require.NoError(t, rt.Recover(ctx))

	f := newFixture(t, 1)
	f.enroll.RootEpoch = PinRootEpoch(2)
	authority, err := New(f.enroll, rt.Trust(nil))
	require.NoError(t, err)

	// the request's certificate is of root epoch 2, sealed by the chosen members of the activated committee
	request := func(members ...int) Request {
		f.uc.UnicitySeal.Epoch = 2
		f.uc.UnicitySeal.Signatures = nil
		for _, i := range members {
			n := q.NewNodes[i]
			require.NoError(t, f.uc.UnicitySeal.Sign(n.PeerConf.ID.String(), n.Signer))
		}
		return f.request()
	}

	_, err = authority.Authenticate(ctx, request(0, 1))
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.ErrorIs(t, err, q3format.ErrUnknownEpoch, "the history does not hold the epoch yet")

	p.Root.OnInstall = func(q3format.Entry) {
		_, err := authority.Authenticate(ctx, request(0, 1))
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.ErrorIs(t, err, q3active.ErrNotActive, "the history holds the epoch, the installation is not complete")
	}
	require.NoError(t, rt.Activate(ctx, p.Bundle()))

	t.Run("the heavy member and one light member are a quorum", func(t *testing.T) {
		auth, err := authority.Authenticate(ctx, request(0, 1))
		require.NoError(t, err)
		require.EqualValues(t, assignedRound, auth.AssignedRound)
	})
	t.Run("three light members are not, nor is the heavy member alone", func(t *testing.T) {
		_, err := authority.Authenticate(ctx, request(1, 2, 3))
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
		_, err = authority.Authenticate(ctx, request(0))
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
	})
	t.Run("a restart does not admit the epoch before recovery", func(t *testing.T) {
		restarted := p.Start()
		again, err := New(f.enroll, restarted.Trust(nil))
		require.NoError(t, err)
		_, err = again.Authenticate(ctx, request(0, 1))
		require.ErrorIs(t, err, q3active.ErrNotActive)
		require.NoError(t, restarted.Recover(ctx))
		_, err = again.Authenticate(ctx, request(0, 1))
		require.NoError(t, err)
	})
}
