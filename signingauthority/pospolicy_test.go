package signingauthority

import (
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
)

func posPin() PosPolicy {
	return PosPolicy{Network: [32]byte{1}, ChainID: [32]byte{31: 7}, Election: [20]byte{0xE1}, IDs: []uint64{5}}
}

func posRequest() PosPoPRequest {
	return PosPoPRequest{ResultID: [32]byte{1}, AssignmentID: [32]byte{2}, Snapshot: [32]byte{3}, Attempt: 2, ID: 5, Generation: 1}
}

func newPosAuthority(t *testing.T, pin *PosPolicy) *Authority {
	t.Helper()
	f := newFixture(t, 1)
	opts := []Option{WithLatePosPolicy()}
	if pin != nil {
		opts = append(opts, WithPosPolicy(*pin))
	}
	a, err := New(f.enroll, trustStub{tb: f.tb}, opts...)
	require.NoError(t, err)
	return a
}

// The proof is the digest of the contracts' Election.popDigest (evmassign.PoPDigest) for the pinned election, signed by the authority's key.
func TestPosPoPIsThePinnedElectionsDigest(t *testing.T) {
	pin := posPin()
	a := newPosAuthority(t, &pin)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	r := posRequest()
	pop, err := a.SignPosPoP(r)
	require.NoError(t, err)
	require.Equal(t, uint64(5), pop.ID)
	require.Equal(t, pub, pop.EVMKey)
	var d evmassign.ElectionDeployment
	d.NetworkWord, d.ChainID, d.Election = pin.Network, pin.ChainID, pin.Election
	want := evmassign.PoPDigest(d, r.ResultID, r.AssignmentID, r.Snapshot, r.Attempt, r.ID, r.Generation, pub)
	sig := append([]byte(nil), pop.Signature...)
	sig[64] -= 27
	got, err := ethSigToPub(want, sig)
	require.NoError(t, err)
	require.Equal(t, pub, got)
	require.False(t, a.Status().HasReservation, "no certification round is touched")
}

func TestPosPoPScope(t *testing.T) {
	t.Run("no pin refuses", func(t *testing.T) {
		_, err := newPosAuthority(t, nil).SignPosPoP(posRequest())
		require.ErrorIs(t, err, ErrPosPolicy)
	})
	pin := posPin()
	a := newPosAuthority(t, &pin)
	t.Run("another identity", func(t *testing.T) {
		r := posRequest()
		r.ID = 4
		_, err := a.SignPosPoP(r)
		require.ErrorIs(t, err, ErrPosPolicy)
	})
	t.Run("empty fields", func(t *testing.T) {
		r := posRequest()
		r.Snapshot = [32]byte{}
		_, err := a.SignPosPoP(r)
		require.ErrorIs(t, err, ErrContextMismatch)
	})
	t.Run("an incomplete pin is refused at start", func(t *testing.T) {
		f := newFixture(t, 1)
		bad := posPin()
		bad.IDs = nil
		_, err := New(f.enroll, trustStub{tb: f.tb}, WithPosPolicy(bad))
		require.ErrorIs(t, err, ErrPosPolicy)
	})
}

// A pin set on a running authority is final: the same pin again is a no-op, another election is refused, and a delegation outside it too.
func TestPosPolicyIsPinnedOnce(t *testing.T) {
	a := newPosAuthority(t, nil)
	pin := posPin()
	require.NoError(t, a.SetPosPolicy(pin))
	require.NoError(t, a.SetPosPolicy(pin))
	other := posPin()
	other.Election = [20]byte{0xE2}
	require.ErrorIs(t, a.SetPosPolicy(other), ErrPosPolicyConflict)
	other = posPin()
	other.IDs = []uint64{5, 6}
	require.ErrorIs(t, a.SetPosPolicy(other), ErrPosPolicyConflict)
	_, err := a.SignPosPoP(posRequest())
	require.NoError(t, err)

	req := DelegationPossessionRequest{Network: pin.Network, Chain: pin.ChainID, Election: [20]byte{0xE2}}
	req.Request.Id = 5
	_, err = a.SignDelegationPossession(req)
	require.ErrorIs(t, err, ErrPosPolicy, "a pinned authority signs delegations for its election only")
}

func ethSigToPub(digest [32]byte, sig []byte) ([]byte, error) {
	pub, err := ethcrypto.SigToPub(digest[:], sig)
	if err != nil {
		return nil, err
	}
	return ethcrypto.CompressPubkey(pub), nil
}

// The pin binds the older election possession (SignElectionPoP) as well: the same PoPDigest must not be obtainable outside it.
func TestPosPolicyBindsTheElectionPoPToo(t *testing.T) {
	a, req, _ := electionPoFixtureForPin(t)
	_, id, err := evmassign.ElectionPoPDigest(req.Candidate, req.Deployment, req.Attempt, mustPub(t, a), testNodeID)
	require.NoError(t, err)
	d := req.Deployment
	pin := PosPolicy{Network: d.NetworkWord, ChainID: d.ChainID, Election: d.Election, IDs: []uint64{id}}
	require.NoError(t, a.SetPosPolicy(pin))
	_, err = a.SignElectionPoP(req)
	require.NoError(t, err, "inside the pin")

	other := req
	other.Deployment.Election = [20]byte{0xEE}
	_, err = a.SignElectionPoP(other)
	require.ErrorIs(t, err, ErrPosPolicy, "another election")
	other = req
	other.Deployment.ChainID = [32]byte{31: 9}
	_, err = a.SignElectionPoP(other)
	require.ErrorIs(t, err, ErrPosPolicy, "another chain")
}

func TestRequirePosPolicyRefusesAllThreeUntilPinned(t *testing.T) {
	f := newFixture(t, 1)
	a, err := New(f.enroll, trustStub{tb: f.tb}, WithRequirePosPolicy(), WithLatePosPolicy())
	require.NoError(t, err)
	_, err = a.SignPosPoP(posRequest())
	require.ErrorIs(t, err, ErrPosPolicy)
	_, err = a.SignDelegationPossession(DelegationPossessionRequest{})
	require.ErrorIs(t, err, ErrPosPolicy)
	// a valid candidate: the refusal is the pin's, not the candidate validation's
	ea, ereq, _ := electionPoPFixture(t)
	ea.requirePos = true
	_, err = ea.SignElectionPoP(ereq)
	require.ErrorIs(t, err, ErrPosPolicy)
	require.NoError(t, a.SetPosPolicy(posPin()))
	_, err = a.SignPosPoP(posRequest())
	require.NoError(t, err)
}

func electionPoFixtureForPin(t *testing.T) (*Authority, ElectionPoPRequest, []byte) {
	a, req, pub := electionPoPFixture(t)
	a.latePos = true
	return a, req, pub
}

func mustPub(t *testing.T, a *Authority) []byte {
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	return pub
}

// Without the development opt-in the operator channel cannot install the pin: it comes from startup.
func TestPosPolicyNotInstallableAtRunTimeInProduction(t *testing.T) {
	f := newFixture(t, 1)
	a, err := New(f.enroll, trustStub{tb: f.tb}, WithRequirePosPolicy())
	require.NoError(t, err)
	require.ErrorIs(t, a.SetPosPolicy(posPin()), ErrPosPolicy)
	b, err := New(f.enroll, trustStub{tb: f.tb}, WithPosPolicy(posPin()))
	require.NoError(t, err)
	require.NoError(t, b.SetPosPolicy(posPin()), "the same pin as at startup is a no-op")
	other := posPin()
	other.Election = [20]byte{0xEE}
	require.ErrorIs(t, b.SetPosPolicy(other), ErrPosPolicyConflict)
}

// Startup installation: two different pins conflict, and a reused option does not share state between authorities.
func TestStartupPosPolicyConflictAndReuse(t *testing.T) {
	f := newFixture(t, 1)
	other := posPin()
	other.Election = [20]byte{0xEE}
	_, err := New(f.enroll, trustStub{tb: f.tb}, WithPosPolicy(posPin()), WithPosPolicy(other))
	require.ErrorIs(t, err, ErrPosPolicyConflict)

	pin := posPin()
	opt := WithPosPolicy(pin)
	a, err := New(f.enroll, trustStub{tb: f.tb}, opt)
	require.NoError(t, err)
	b, err := New(f.enroll, trustStub{tb: f.tb}, opt)
	require.NoError(t, err)
	pin.IDs[0] = 9 // the caller's slice is not the authority's
	_, err = a.SignPosPoP(posRequest())
	require.NoError(t, err)
	require.NotSame(t, a.pos, b.pos)
	require.NotSame(t, &a.pos.IDs[0], &b.pos.IDs[0])
}
