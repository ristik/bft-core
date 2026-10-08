package storage

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// v3FreezeFor is a V3 freeze whose candidate is the given preimage: the body names exactly the candidate's root members, the predecessor is
// the one the candidate was built for, and the receipt gate is the real one in effect (it refuses whatever it is asked about, as the real
// rules do for an incomplete set), so a freeze passes it only by not being asked.
func v3FreezeFor(t *testing.T, predecessor, preimage []byte) (*v3Freeze, evmassign.Candidate) {
	t.Helper()
	c, err := evmassign.DecodeCandidate(preimage)
	require.NoError(t, err)
	f := newV3Freeze(t)
	digest := sha256.Sum256(preimage)
	f.predec, f.candidate = predecessor, digest[:]
	f.auth.predecessor = predecessor
	f.rules.receiptsErr = errors.New("incomplete receipt set")
	f.body.Members = c.RootMembers
	f.body.ChangeRecordHash = evmroot.D4CandidateContextHash(5, predecessor, c.Attempt, digest[:], 7)
	link, err := f.rules.Prior(5, 1, 1, predecessor)
	require.NoError(t, err)
	f.body.PredecessorHash = link
	f.rules.bodies[string(f.rawBody)] = f.body
	return f, c
}

func (f *v3Freeze) companionWith(t *testing.T, r evmroot.OrderedHandoffRecord, preimage, receipts []byte) []byte {
	t.Helper()
	message, err := EndorsementBytes(r)
	require.NoError(t, err)
	sigs := map[string]hex.Bytes{}
	for _, name := range []string{"old-a", "old-b", "old-c"} {
		sig, err := f.signers[name].SignBytes(message)
		require.NoError(t, err)
		sigs[name] = sig
	}
	raw, err := (FreezeV3Authorization{Version: freezeV3Version, Body: f.rawBody, Parent: f.parent, Candidate: f.candidate, Preimage: preimage, Receipts: receipts, Signatures: sigs}).Bytes()
	require.NoError(t, err)
	return raw
}

// An exact recovery K is admitted at Freeze with no readiness receipts, selected by its verified candidate preimage; a primary, a recovery that
// carries receipts anyway, a forged K and a companion with neither receipts nor preimage are each refused for their own reason.
func TestV3FreezeOfAnExactRecoveryNeedsNoReceiptsAndNothingElseDoesNot(t *testing.T) {
	p := installPendingAssignment(t)
	recovery := p.supersede(t, nil).preimage
	primary := p.first.built.preimage

	t.Run("exact recovery K, no receipts: admitted, and the receipt gate is never asked", func(t *testing.T) {
		f, c := v3FreezeFor(t, p.body1, recovery)
		require.EqualValues(t, evmassign.KindRecovery, c.Kind)
		r := f.record()
		parent, err := f.verify(t, r, f.companionWith(t, r, recovery, nil))
		require.NoError(t, err)
		require.Equal(t, f.parent, parent)
		require.Empty(t, f.rules.asked, "no readiness receipts were collected or asked for")
	})
	t.Run("a recovery that carries receipts is refused: the exemption carries none", func(t *testing.T) {
		f, _ := v3FreezeFor(t, p.body1, recovery)
		r := f.record()
		_, err := f.verify(t, r, f.companionWith(t, r, recovery, []byte("receipts")))
		require.ErrorIs(t, err, ErrFreezeV3Receipts)
	})
	t.Run("a primary without receipts is refused: empty receipts never select the exemption", func(t *testing.T) {
		f, c := v3FreezeFor(t, p.first.candidate.Predecessor, primary)
		require.EqualValues(t, evmassign.KindPrimary, c.Kind)
		r := f.record()
		_, err := f.verify(t, r, f.companionWith(t, r, primary, nil))
		require.ErrorIs(t, err, ErrFreezeV3Receipts)
		require.Len(t, f.rules.asked, 1, "the full receipt set was demanded")
	})
	t.Run("a forged K (a changed payee) is refused by the candidate binding before any exemption", func(t *testing.T) {
		c, err := evmassign.DecodeCandidate(recovery)
		require.NoError(t, err)
		c.Identities = append([]evmassign.Identity(nil), c.Identities...)
		c.Identities[0].OperatorPayee = append([]byte(nil), c.Identities[0].OperatorPayee...)
		c.Identities[0].OperatorPayee[0] ^= 1
		forged, err := c.Encode()
		require.NoError(t, err)
		f, _ := v3FreezeFor(t, p.body1, forged)
		r := f.record()
		_, err = f.verify(t, r, f.companionWith(t, r, forged, nil))
		require.ErrorIs(t, err, ErrFreezeV3Binding)
		require.ErrorIs(t, err, evmassign.ErrNotIncumbent)
	})
	t.Run("a companion with neither receipts nor a preimage is not a V3 companion", func(t *testing.T) {
		f, _ := v3FreezeFor(t, p.body1, recovery)
		r := f.record()
		_, err := ParseFreezeCompanion(f.companionWith(t, r, nil, nil))
		require.ErrorIs(t, err, ErrHandoffRecord)
		parsed, err := ParseFreezeCompanion(f.companionWith(t, r, recovery, nil))
		require.NoError(t, err, "a preimage without receipts parses: verifyFreezeV3 decides by the decoded kind")
		require.Empty(t, parsed.Receipts)
	})
}
