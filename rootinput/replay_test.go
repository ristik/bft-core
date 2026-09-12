package rootinput

/*
Acceptance for the replay predicate (#10 / f2c §2). Every certificate is real and every refusal
establishes its own premise: each negative first shows the same inputs accepted with only the field
under test corrected, so an unrelated failure cannot satisfy the case.
*/

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAcceptBlock_AcceptsTheBlockItsAuthorizationDescribes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)
	c := f.context()

	derived, err := Derive(ctx, c, uc, tr)
	require.NoError(t, err)
	b := BlockBinding{ParentHash: bytes.Clone(c.ParentHash), ExtraData: derived.Commitment[:]}

	res, err := AcceptBlock(ctx, c, uc, tr, b)
	require.NoError(t, err)
	require.Equal(t, derived.Encoded, res.Encoded, "acceptance returns the authenticated derivation")
	require.Equal(t, derived.Commitment, res.Commitment)
	require.NotNil(t, res.Certificate)
}

func TestAcceptBlock_IsMemoryless(t *testing.T) {
	// A genuine block replays every time it is offered. That is the point of the split: acceptance
	// here says the block is the one the certificate authorizes, never that answering the round
	// again is permitted. Freshness belongs to the caller's applied state and, for signing, to the
	// signing record (#105 step 2).
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)
	c := f.context()
	derived, err := Derive(ctx, c, uc, tr)
	require.NoError(t, err)
	b := BlockBinding{ParentHash: bytes.Clone(c.ParentHash), ExtraData: derived.Commitment[:]}

	for i := 0; i < 3; i++ {
		_, err := AcceptBlock(ctx, c, uc, tr, b)
		require.NoErrorf(t, err, "replay %d", i)
	}
}

func TestAcceptBlock_RefusesABlockThatIsNotTheOneAuthorized(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)
	c := f.context()
	derived, err := Derive(ctx, c, uc, tr)
	require.NoError(t, err)
	good := BlockBinding{ParentHash: bytes.Clone(c.ParentHash), ExtraData: derived.Commitment[:]}

	// Premise: unmodified, it is accepted.
	_, err = AcceptBlock(ctx, c, uc, tr, good)
	require.NoError(t, err)

	t.Run("a commitment for another authorization", func(t *testing.T) {
		// A repeat of the same work at a higher root round: genuine, and a different authorization,
		// so the block that commits to it is not the block this one authorizes.
		repeat, repeatTR := f.cert(t, 4, 5, 60,
			bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb1}, 32), 1, 2)
		other, err := Derive(ctx, c, repeat, repeatTR)
		require.NoError(t, err, "the other authorization is itself valid")
		require.NotEqual(t, derived.Commitment, other.Commitment)

		_, err = AcceptBlock(ctx, c, uc, tr, BlockBinding{ParentHash: bytes.Clone(c.ParentHash), ExtraData: other.Commitment[:]})
		require.ErrorIs(t, err, ErrBindingMismatch)
	})

	t.Run("a parent that is not the certified one", func(t *testing.T) {
		b := good
		b.ParentHash = bytes.Repeat([]byte{0x5e}, 32)
		_, err := AcceptBlock(ctx, c, uc, tr, b)
		require.ErrorIs(t, err, ErrBindingMismatch)
		require.ErrorContains(t, err, "certified parent",
			"a wrong parent is reported as a wrong parent, not as a commitment mismatch")
	})

	t.Run("extraData that is not a 32-byte commitment", func(t *testing.T) {
		for _, ed := range [][]byte{nil, {}, bytes.Repeat([]byte{0x01}, 31), bytes.Repeat([]byte{0x01}, 33)} {
			b := good
			b.ExtraData = ed
			_, err := AcceptBlock(ctx, c, uc, tr, b)
			require.ErrorIs(t, err, ErrBindingMismatch, "extraData of %d bytes", len(ed))
		}
	})

	t.Run("a parent that is not 32 bytes", func(t *testing.T) {
		b := good
		b.ParentHash = bytes.Repeat([]byte{0xa9}, 31)
		_, err := AcceptBlock(ctx, c, uc, tr, b)
		require.ErrorIs(t, err, ErrBindingMismatch)
	})
}

func TestAcceptBlock_AuthorizationFailuresAreNotBindingFailures(t *testing.T) {
	// The two situations must stay distinguishable: "this authorization is not mine to act on" is an
	// operator's misconfiguration or an attack, while "this block does not match a good
	// authorization" is a divergent or forged block.
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)
	c := f.context()
	derived, err := Derive(ctx, c, uc, tr)
	require.NoError(t, err)
	b := BlockBinding{ParentHash: bytes.Clone(c.ParentHash), ExtraData: derived.Commitment[:]}

	t.Run("an unauthenticated certificate never reaches the binding check", func(t *testing.T) {
		subQuorum, subTR := f.cert(t, 4, 5, 50,
			bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb1}, 32), 1)
		_, err := AcceptBlock(ctx, c, subQuorum, subTR, b)
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.NotErrorIs(t, err, ErrBindingMismatch)
	})

	t.Run("a wrong pinned round is a derivation refusal", func(t *testing.T) {
		wrong := c
		wrong.Round = 9
		_, err := AcceptBlock(ctx, wrong, uc, tr, b)
		require.ErrorIs(t, err, ErrNotPinned)
		require.NotErrorIs(t, err, ErrBindingMismatch)
	})
}

func TestAcceptBlock_TheCursorIsAsOfTheReplayedRound(t *testing.T) {
	// The replay-specific sourcing rule. A block written when the committed cursor was 40 is valid
	// history; replaying it against the node's CURRENT cursor, which has since moved past the
	// authorization's root round, rejects history that was correct when it was written.
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t) // authorization at root round 50

	asOfThatRound := f.context()
	asOfThatRound.LastAppliedRootRound = 40
	derived, err := Derive(ctx, asOfThatRound, uc, tr)
	require.NoError(t, err)
	b := BlockBinding{ParentHash: bytes.Clone(asOfThatRound.ParentHash), ExtraData: derived.Commitment[:]}

	_, err = AcceptBlock(ctx, asOfThatRound, uc, tr, b)
	require.NoError(t, err, "against the cursor committed as of that round the block replays")

	current := f.context()
	current.LastAppliedRootRound = 70
	_, err = AcceptBlock(ctx, current, uc, tr, b)
	require.ErrorIs(t, err, ErrNotPinned,
		"the node's current cursor rejects valid history, which is why the caller must source it as of the round")
}

func TestAcceptBlock_OwnsWhatItReturns(t *testing.T) {
	// The caller's header slices are its own; mutating them after acceptance cannot change what was
	// accepted or what the result says.
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)
	c := f.context()
	derived, err := Derive(ctx, c, uc, tr)
	require.NoError(t, err)

	parent := bytes.Clone(c.ParentHash)
	extra := bytes.Clone(derived.Commitment[:])
	res, err := AcceptBlock(ctx, c, uc, tr, BlockBinding{ParentHash: parent, ExtraData: extra})
	require.NoError(t, err)

	for i := range parent {
		parent[i] ^= 0xff
	}
	for i := range extra {
		extra[i] ^= 0xff
	}
	require.Equal(t, derived.Encoded, res.Encoded)
	require.Equal(t, derived.Commitment, res.Commitment)
	require.NotEqual(t, parent, res.Input.ParentHash, "the caller's slice really was mutated")
}
