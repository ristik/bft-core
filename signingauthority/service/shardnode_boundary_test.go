package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// The shard node's side of the boundary is this client and nothing else: it satisfies the interface
// a round is given, without a session and without a key.
var _ shardnode.SigningAuthorityClient = (*Client)(nil)

func TestARoundsSignerDrivesTheAuthorityProcess(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	authority, _ := f.provision(t)
	client := authority.admit(t)

	// The expected key is provisioned the way a deployment would provision it: from the authority,
	// through the operator endpoint, before any signing happens.
	_, key, err := authority.operator.Enrollment(ctx)
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(key)
	require.NoError(t, err)

	signer, err := shardnode.NewAuthoritySigner(client, verifier)
	require.NoError(t, err)

	signed, err := signer.Sign(ctx, f.uc, f.tr, f.proposed)
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(verifier))

	unsigned, err := signed.Bytes()
	require.NoError(t, err)
	proposed, err := f.proposed.Bytes()
	require.NoError(t, err)
	require.Equal(t, proposed, unsigned, "what comes back is this round's own proposal, signed elsewhere")

	// A re-delivery of the same round replays the retained response rather than signing again.
	again, err := signer.Sign(ctx, f.uc, f.tr, f.proposed)
	require.NoError(t, err)
	require.Equal(t, signed.Signature, again.Signature)

	// And when the authority process is gone, the round's signer reports unavailability, which is
	// what makes the node non-voting rather than locally signing.
	authority.kill(t)
	_, err = signer.Sign(ctx, f.uc, f.tr, f.proposed)
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
}
