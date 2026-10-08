package q3format_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
)

// An exact recovery K needs no readiness receipts, selected by its verified candidate preimage and never by an empty receipt list.
func TestAnExactRecoveryNeedsNoReceiptsAndNothingElseDoes(t *testing.T) {
	primary := q3fixture.New(t, q3fixture.Options{Assignment: true})
	recovery := q3fixture.New(t, q3fixture.Options{After: primary, Assignment: true, Recovery: true, Installed: primary.Successor})
	require.Empty(t, recovery.Link.Receipts, "premise: the recovery fixture carries none")
	require.NotEmpty(t, recovery.Link.Preimage)

	base := func(t *testing.T) *q3format.History {
		h, err := q3format.NewHistory(primary.Old)
		require.NoError(t, err)
		h, err = h.VerifyEnvelope(primary.Envelope)
		require.NoError(t, err)
		return h
	}
	t.Run("the receipt-free recovery link extends the history and the whole envelope verifies from genesis", func(t *testing.T) {
		next, err := base(t).WithV3(recovery.Link)
		require.NoError(t, err)
		require.EqualValues(t, 3, next.Tip().Epoch())
		h, err := q3format.NewHistory(primary.Old)
		require.NoError(t, err)
		_, err = h.VerifyEnvelope(recovery.Envelope)
		require.NoError(t, err)
		// it round-trips through the canonical envelope
		raw, err := recovery.Envelope.Encode()
		require.NoError(t, err)
		back, err := q3format.DecodeEnvelope(raw)
		require.NoError(t, err)
		require.Equal(t, recovery.Link.Preimage, back.Links[len(back.Links)-1].Preimage)
	})
	t.Run("a recovery that carries receipts anyway is refused: the exemption carries none", func(t *testing.T) {
		l := recovery.Link
		l.Receipts = primary.Link.Receipts
		_, err := base(t).WithV3(l)
		require.ErrorIs(t, err, q3format.ErrRecoveryExemption)
	})
	t.Run("empty receipts never select the exemption: without the preimage the full set is required", func(t *testing.T) {
		l := recovery.Link
		l.Preimage = nil
		_, err := base(t).WithV3(l)
		require.ErrorIs(t, err, q3format.ErrReceiptMissing)
	})
	t.Run("a preimage that is not the committed candidate is refused", func(t *testing.T) {
		l := recovery.Link
		l.Preimage = bytes.Clone(l.Preimage)
		l.Preimage[len(l.Preimage)/2] ^= 1
		_, err := base(t).WithV3(l)
		require.ErrorIs(t, err, q3format.ErrBinding)
	})
	t.Run("a primary never gets the exemption: its receipts are required, by the history and by a retained reference", func(t *testing.T) {
		l := primary.Link
		l.Receipts = nil
		h, err := q3format.NewHistory(primary.Old)
		require.NoError(t, err)
		_, err = h.WithV3(l)
		require.ErrorIs(t, err, q3format.ErrReceiptMissing)
		// a retained reference to the verified primary entry that drops its receipts is a conflict
		e := primary.Envelope
		e.Links = append([]q3format.Link(nil), e.Links...)
		e.Links[0].Receipts = nil
		full, err := q3format.NewHistory(primary.Old)
		require.NoError(t, err)
		full, err = full.VerifyEnvelope(primary.Envelope)
		require.NoError(t, err)
		_, err = full.VerifyEnvelope(e)
		require.ErrorIs(t, err, q3format.ErrConflict)
	})
	t.Run("a retained reference must repeat the committed preimage", func(t *testing.T) {
		full, err := q3format.NewHistory(primary.Old)
		require.NoError(t, err)
		full, err = full.VerifyEnvelope(recovery.Envelope)
		require.NoError(t, err)
		e := recovery.Envelope
		e.Links = append([]q3format.Link(nil), e.Links...)
		e.Links[len(e.Links)-1].Preimage = nil
		_, err = full.VerifyEnvelope(e)
		require.ErrorIs(t, err, q3format.ErrConflict)
	})
	// forged K and broken lineage: each of these is a recovery whose candidate is edited BEFORE its digest is committed, so the digest chain is
	// consistent and only the exemption's own rules can refuse it
	forged := func(t *testing.T, mutate func(*evmassign.Candidate)) q3format.Link {
		t.Helper()
		r := q3fixture.New(t, q3fixture.Options{After: primary, Assignment: true, Recovery: true, Installed: primary.Successor, MutateCandidate: mutate})
		return r.Link
	}
	for name, tc := range map[string]struct {
		mutate func(*evmassign.Candidate)
		want   error
	}{
		"replaces another assignment":     {func(c *evmassign.Candidate) { c.ReplacedAssignment[0] ^= 1 }, evmassign.ErrRecoveryLineage},
		"carries another authorization":   {func(c *evmassign.Candidate) { c.Authorization.ResultID[0] ^= 1 }, evmassign.ErrAuthorization},
		"K changed in a payee (forged K)": {func(c *evmassign.Candidate) { c.Identities[0].OperatorPayee[0] ^= 1 }, evmassign.ErrAuthorization},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := base(t).WithV3(forged(t, tc.mutate))
			require.ErrorIs(t, err, q3format.ErrRecoveryExemption)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("a recovery must replace a committed primary: the preceding link committed no preimage", func(t *testing.T) {
		e := primary.Envelope
		e.Links = append([]q3format.Link(nil), e.Links...)
		e.Links[len(e.Links)-1].Preimage = nil // the primary still carries its full receipts, so it verifies without one
		h, err := q3format.NewHistory(primary.Old)
		require.NoError(t, err)
		h, err = h.VerifyEnvelope(e)
		require.NoError(t, err)
		_, err = h.WithV3(recovery.Link)
		require.ErrorIs(t, err, q3format.ErrRecoveryExemption)
		require.ErrorIs(t, err, evmassign.ErrRecoveryLineage)
	})
}
