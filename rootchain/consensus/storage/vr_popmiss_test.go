package storage_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// #1319 (astra option (a)): the predecessor roots commit a PoP request for the intent (control op 6) with a cutoff POP_WINDOW in root
// progress after it; an Expired RejectResult v2 past the cutoff may carry per-member miss certificates signed by a quorum by weight of the
// entire predecessor committee; the executor commits the certified members in record kind 9 between the OutputRejected and the
// SessionClosed. The fixture's committee is r1..r4 at unit weight (quorum 3); the roster is the successors 1, 2, 3, 5.

const missRejectRound = 4_200 // root progress 4,199, past the request's cutoff 10 + POP_WINDOW = 4,106

// withRequest makes the fixture's intent carry its PoP request (attempt 0, the rejection's).
func (f *vxFixture) withRequest() {
	f.intents.in.Request = vrschema.PoPRequest{Epoch: 1, Network: vxNetwork, Predecessor: bytes.Clone(f.body[:]), ResultID: bytes.Clone(f.r[:]), Attempt: 0,
		Roster: []uint64{1, 2, 3, 5}, Intent: bytes.Clone(f.intent[:])}
}

func (f *vxFixture) popRequest(round uint64) rctypes.PosControl {
	return rctypes.PosControl{Registry: true, Network: f.dep.RootNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: round,
		Op: rctypes.OpPoPRequest, Request: &rctypes.RequestContext{IntentDigest: f.intent}}
}

// missCert is the certificate of stakingID by the incumbents at the given positions (1..4 are r1..r4; 5 is the joiner, no incumbent), each
// signing msgOf(request digest, stakingID).
func (f *vxFixture) missCert(t *testing.T, r vrschema.PoPRequest, stakingID uint64, msgOf func([32]byte, uint64) []byte, signers ...uint64) rctypes.MissCertificate {
	d, err := r.Digest()
	require.NoError(t, err)
	c := rctypes.MissCertificate{StakingID: stakingID}
	for _, i := range signers {
		sig, err := f.members[i].rk.signer.SignBytes(msgOf(d, stakingID))
		require.NoError(t, err)
		c.Sigs = append(c.Sigs, rctypes.MissSig{NodeID: f.members[i].root, Sig: sig})
	}
	return c
}

func statement(t *testing.T) func([32]byte, uint64) []byte {
	return func(d [32]byte, id uint64) []byte {
		b, err := vrschema.MissStatementBytes(d, id)
		require.NoError(t, err)
		return b
	}
}

// missWorld is a fixture whose result is due at the rejection, a committed PoP request, and the honest rejection without certificates.
func missWorld(t *testing.T) (*vxFixture, *storage.ExecutedBlock, vrschema.PoPRequest, rctypes.PosControl) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime
	f.attempt = 1
	f.build()
	f.withRequest()
	g := f.genesis()
	req := f.must(g, f.block(g, 11, 1_005, nil, f.popRequest(11)))
	stored := rootState(t, req).Request
	require.NotNil(t, stored, "the request is committed")
	require.EqualValues(t, 10+vrschema.PoPWindow, stored.Deadline, "the cutoff is POP_WINDOW past the block's root progress")
	require.EqualValues(t, 1, stored.Epoch)
	c, ok := f.built(t, f.rejectBuilder(t, 0b0111), f.rejectionContext(0), missRejectRound)
	require.True(t, ok)
	return f, req, *stored, c
}

func withMisses(c rctypes.PosControl, ms ...rctypes.MissCertificate) rctypes.PosControl {
	r := *c.Reject
	r.Misses = ms
	c.Reject = &r
	return c
}

// The request is committed once per intent, only for the derivable intent; a state without it keeps its version 2 encoding.
func TestThePoPRequestIsCommittedOncePerDerivableIntent(t *testing.T) {
	f, req, stored, _ := missWorld(t)
	require.Equal(t, []uint64{1, 2, 3, 5}, stored.Roster)
	require.Equal(t, f.intent[:], stored.Intent)
	_, err := f.exec(req, f.block(req, 12, 1_006, nil, f.popRequest(12)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "once per intent")

	g := f.genesis()
	other := f.popRequest(11)
	other.Request = &rctypes.RequestContext{IntentDigest: [32]byte{7}}
	_, err = f.exec(g, f.block(g, 11, 1_005, nil, other))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "an intent that is not the derivable one")
	f.intents.ok = false
	_, err = f.exec(g, f.block(g, 11, 1_005, nil, f.popRequest(11)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "no derivable intent")

	require.Nil(t, rootState(t, g).Request)
	raw := g.ShardState.Control.VR
	require.Equal(t, byte(2), raw[len("UNICITY_VR_ROOT_STATE")+2], "no request: the version 2 encoding")
}

// A valid certificate is committed: record kind 9 names the certified roster member between the OutputRejected and the SessionClosed at
// one anchor, the request is consumed, and the result is resolved as by any rejection.
func TestACertifiedMissIsCommittedInItsOwnRecord(t *testing.T) {
	f, req, stored, c := missWorld(t)
	cert := f.missCert(t, stored, 5, statement(t), 1, 2, 3)
	rej := f.must(req, f.block(req, missRejectRound, 1_900, nil, withMisses(c, cert)))
	recs := rej.ShardState.Records
	require.Len(t, recs, 3)
	require.Equal(t, []rootrecords.Kind{rootrecords.KindOutputRejected, rootrecords.KindPoPMissed, rootrecords.KindSessionClosed},
		[]rootrecords.Kind{recs[0].Kind, recs[1].Kind, recs[2].Kind})
	m, err := vrschema.DecodePoPMissed(recs[1].Data)
	require.NoError(t, err)
	require.Equal(t, vrschema.PoPMissed{ResultID: f.r, Deadline: stored.Deadline, MissedBitmap: 0b1000}, m, "bit 3: the fourth roster member, id 5")
	require.Equal(t, recs[0].Progress, recs[1].Progress)
	require.True(t, posState(t, rej).IsResolved(f.r))
	require.Nil(t, rootState(t, rej).Request, "the rejection consumes the request")

	// an incumbent: two members, each on its own certificate
	two := f.must(req, f.block(req, missRejectRound, 1_900, nil, withMisses(c, f.missCert(t, stored, 2, statement(t), 1, 3, 4), cert)))
	m, err = vrschema.DecodePoPMissed(two.ShardState.Records[1].Data)
	require.NoError(t, err)
	require.EqualValues(t, 0b1010, m.MissedBitmap)

	// ordinary expiry still closes without certificates, and consumes the request too
	plain := f.must(req, f.block(req, missRejectRound, 1_900, nil, c))
	require.Len(t, plain.ShardState.Records, 2)
	require.Nil(t, rootState(t, plain).Request)
}

// Every certificate that does not stand is refused, and with it the whole control: a sub-quorum, a statement under another domain, of
// another roster (another request), a member outside the roster, a signer outside the committee, a duplicate signer, before the cutoff,
// without a committed request, or with a cutoff past the result's expiry.
func TestABadMissCertificateIsRefused(t *testing.T) {
	f, req, stored, c := missWorld(t)
	exec := func(parent *storage.ExecutedBlock, round uint64, ctl rctypes.PosControl) error {
		ctl.OrderingRound = round
		_, err := f.exec(parent, f.block(parent, round, 1_900, nil, ctl))
		return err
	}
	ok := f.missCert(t, stored, 5, statement(t), 1, 2, 3)
	require.NoError(t, exec(req, missRejectRound, withMisses(c, ok)))

	otherRoster := stored
	otherRoster.Roster = []uint64{1, 2, 3, 4, 5}
	wrongDomain := func(d [32]byte, id uint64) []byte {
		b, err := vrschema.MissStatementBytes(d, id)
		require.NoError(t, err)
		return append([]byte("not a miss: "), b...)
	}
	outside := ok
	outside.Sigs = append(append([]rctypes.MissSig(nil), ok.Sigs...), rctypes.MissSig{NodeID: f.members[5].root, Sig: ok.Sigs[0].Sig})
	for name, cert := range map[string]rctypes.MissCertificate{
		"sub-quorum":            f.missCert(t, stored, 5, statement(t), 1, 2),
		"wrong domain":          f.missCert(t, stored, 5, wrongDomain, 1, 2, 3),
		"wrong roster":          f.missCert(t, otherRoster, 5, statement(t), 1, 2, 3),
		"outside the roster":    f.missCert(t, stored, 4, statement(t), 1, 2, 3),
		"outside the committee": outside,
	} {
		require.ErrorIs(t, exec(req, missRejectRound, withMisses(c, cert)), storage.ErrVRControlRefused, name)
		require.ErrorIs(t, exec(req, missRejectRound, withMisses(c, cert)), vrschema.ErrPoPMiss, name)
	}
	// one bad certificate refuses the control even beside a good one: the leader leaves the bad one out (it judges each alone)
	require.ErrorIs(t, exec(req, missRejectRound, withMisses(c, f.missCert(t, stored, 2, statement(t), 1, 2), ok)), vrschema.ErrPoPMiss)

	// before the cutoff
	early := 4_000
	ec, okEarly := f.built(t, f.rejectBuilder(t, 0b0111), f.rejectionContext(0), uint64(early))
	require.True(t, okEarly)
	require.ErrorIs(t, exec(req, uint64(early), withMisses(ec, ok)), storage.ErrVRControlRefused, "before the cutoff")
	require.NoError(t, exec(req, uint64(early), ec), "the ordinary expiry is not held back")

	// without a committed request
	g := f.genesis()
	require.ErrorIs(t, exec(g, missRejectRound, withMisses(c, ok)), storage.ErrVRControlRefused, "no committed request")

	// a cutoff past the result's expiry: the window did not fit the lifetime
	late := newVXFixture(t)
	late.progress = 100 + vrschema.Lifetime
	late.attempt = 1
	late.build()
	late.withRequest()
	lg := late.genesis()
	lateRound := uint64(100 + vrschema.Lifetime - vrschema.PoPWindow + 10)
	lreq := late.must(lg, late.block(lg, lateRound, 1_005, nil, late.popRequest(lateRound)))
	lstored := *rootState(t, lreq).Request
	require.Greater(t, lstored.Deadline, uint64(100+vrschema.Lifetime))
	lc, okLate := late.built(t, late.rejectBuilder(t, 0b0111), late.rejectionContext(0), lstored.Deadline+5)
	require.True(t, okLate)
	lc.OrderingRound = lstored.Deadline + 5
	_, err := late.exec(lreq, late.block(lreq, lc.OrderingRound, 1_900, nil, withMisses(lc, late.missCert(t, lstored, 5, statement(t), 1, 2, 3))))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "a window past the lifetime")
	_, err = late.exec(lreq, late.block(lreq, lc.OrderingRound, 1_900, nil, lc))
	require.NoError(t, err, "its ordinary expiry still closes")
}

// The certificates of different members are independent: roots that disagree about one member (its statements short of the quorum) do not
// keep another member from being certified, nor the expiry from closing.
func TestMissCertificatesArePerMember(t *testing.T) {
	f, req, stored, c := missWorld(t)
	committee := []vrschema.CommitteeMember{}
	for i := uint64(1); i <= 4; i++ {
		committee = append(committee, vrschema.CommitteeMember{NodeID: f.members[i].root, Key: f.members[i].rk.pub, Weight: 1})
	}
	certs := []rctypes.MissCertificate{f.missCert(t, stored, 2, statement(t), 4), f.missCert(t, stored, 5, statement(t), 2, 3, 4)}
	// the leader keeps each certificate that alone reaches the quorum
	var kept []rctypes.MissCertificate
	for _, x := range certs {
		if _, err := vrschema.VerifyMissCertificates(stored, storage.MissCertificatesOf([]rctypes.MissCertificate{x}), committee, 3); err == nil {
			kept = append(kept, x)
		}
	}
	require.Len(t, kept, 1)
	rej := f.must(req, f.block(req, missRejectRound, 1_900, nil, withMisses(c, kept...)))
	m, err := vrschema.DecodePoPMissed(rej.ShardState.Records[1].Data)
	require.NoError(t, err)
	require.EqualValues(t, 0b1000, m.MissedBitmap, "member 5 only")
}

// #1319 review P3-7: a committed request of another attempt or result than the rejection's carries no certificate. (A request of another
// epoch cannot be held: the executor stamps the block's epoch, and the block end drops the request once the epoch changes, which
// vradmit's TestRootStateCarriesThePoPRequestOnlyWhileHeld covers; the executor's epoch check is the backstop.)
func TestACertificateOfAnotherRequestIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*vrschema.PoPRequest){
		"another attempt": func(r *vrschema.PoPRequest) { r.Attempt = 1 },
		"another result":  func(r *vrschema.PoPRequest) { r.ResultID = bytes.Repeat([]byte{0x5a}, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newVXFixture(t)
			f.progress = 100 + vrschema.Lifetime
			f.attempt = 1
			f.build()
			f.withRequest()
			edit(&f.intents.in.Request)
			g := f.genesis()
			req := f.must(g, f.block(g, 11, 1_005, nil, f.popRequest(11)))
			stored := *rootState(t, req).Request
			c, ok := f.built(t, f.rejectBuilder(t, 0b0111), f.rejectionContext(0), missRejectRound)
			require.True(t, ok)
			_, err := f.exec(req, f.block(req, missRejectRound, 1_900, nil, withMisses(c, f.missCert(t, stored, 5, statement(t), 1, 2, 3))))
			require.ErrorIs(t, err, storage.ErrVRControlRefused)
			_, err = f.exec(req, f.block(req, missRejectRound, 1_900, nil, c))
			require.NoError(t, err, "the ordinary expiry still closes")
		})
	}
}

// #1319 review P3-7 and P3-1: the quorum is of the whole committee, never of the live part, and never below the trust base's own threshold.
// Here r1..r4 sign for a committee that also names the joiner's root (five unit weights, quorum 4): three signers are refused, four certify.
// With the four-root committee and a trust-base threshold of 4, three signers are refused too.
func TestTheMissQuorumIsOfTheWholeCommittee(t *testing.T) {
	f, req, stored, c := missWorld(t)
	exec := func(ms ...rctypes.MissCertificate) error {
		_, err := f.exec(req, f.block(req, missRejectRound, 1_900, nil, withMisses(c, ms...)))
		return err
	}
	require.NoError(t, exec(f.missCert(t, stored, 5, statement(t), 1, 2, 3)), "4 unit roots: quorum 3")
	f.auth.Quorum = 4
	require.ErrorIs(t, exec(f.missCert(t, stored, 5, statement(t), 1, 2, 3)), vrschema.ErrPoPMiss, "the trust base's threshold 4 binds")
	require.NoError(t, exec(f.missCert(t, stored, 5, statement(t), 1, 2, 3, 4)))
	f.auth.Quorum = 0
	f.auth.Root = append(append([]evmassign.RootMember(nil), f.kRoot...), evmassign.RootMember{NodeID: f.members[5].root, Key: f.members[5].rk.pub, Weight: 1})
	require.ErrorIs(t, exec(f.missCert(t, stored, 5, statement(t), 1, 2, 3)), vrschema.ErrPoPMiss, "five unit roots: quorum 4")
	require.NoError(t, exec(f.missCert(t, stored, 5, statement(t), 1, 2, 3, 4)))
}

// #1319 review P3-7: one member's statements cannot certify another member: the statement binds the staking id.
func TestStatementsOfOneMemberCannotCertifyAnother(t *testing.T) {
	f, req, stored, c := missWorld(t)
	of3 := f.missCert(t, stored, 3, statement(t), 1, 2, 3)
	as5 := rctypes.MissCertificate{StakingID: 5, Sigs: of3.Sigs}
	_, err := f.exec(req, f.block(req, missRejectRound, 1_900, nil, withMisses(c, as5)))
	require.ErrorIs(t, err, vrschema.ErrPoPMiss)
}
