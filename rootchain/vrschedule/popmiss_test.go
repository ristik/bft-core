package vrschedule

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// #1319: the root side of the certified handoff-PoP miss (the PoP relay, the statements at the cutoff, their collection).

// testDeadline is the cutoff of a request committed at root progress 10.
const testDeadline = 10 + vrschema.PoPWindow

func (w *world) request(deadline uint64) *vrschema.PoPRequest {
	r, err := PoPRequestOf(w.in, w.d, w.RC.RootEpoch)
	require.NoError(w.T, err)
	r.Deadline = deadline
	return &r
}

func (w *world) committedAt(r *vrschema.PoPRequest, progress uint64) Committed {
	c := w.committed(0)
	c.Request, c.Progress, c.ProgressOK = r, progress, true
	return c
}

// The intent's request names its roster in VR's member order: the successors by ascending staking id.
func TestThePoPRequestOfAnIntentIsItsRosterInMemberOrder(t *testing.T) {
	w := newWorld(t)
	r := w.request(9)
	require.Equal(t, []uint64{1, 2, 3, 5}, r.Roster)
	require.Equal(t, w.d[:], r.Intent)
	require.Equal(t, w.R[:], r.ResultID)
	require.NoError(t, r.Check())
}

// A proof a member sent to this root is relayed to its peers once; a duplicate, and this root's own proof, are not.
func TestARetainedProofIsRelayedOnce(t *testing.T) {
	w := newWorld(t)
	var relayed []Message
	s := NewService(ServiceConfig{Self: "root-1", Send: func(m Message) {
		if m.PoP != nil {
			relayed = append(relayed, m)
		}
	}})
	s.Update(w.committed(0))
	pops := w.PoPs(w.in)
	o, _, err := s.Offer("root-5", Message{PoP: &pops[3]})
	require.NoError(t, err)
	require.Equal(t, Retained, o)
	require.Len(t, relayed, 1)
	require.Equal(t, pops[3].EVMNodeID, relayed[0].PoP.EVMNodeID)
	o, _, _ = s.Offer("root-2", Message{PoP: &pops[3]})
	require.Equal(t, Duplicate, o)
	require.Len(t, relayed, 1, "a duplicate is not relayed")
	o, _, _ = s.Offer("root-1", Message{PoP: &pops[0]})
	require.Equal(t, Retained, o)
	require.Len(t, relayed, 1, "this root's own proof is the member's to send")
}

// At the first committed update at or past the cutoff a root states, once, the roster members whose proof it lacks, signed by its root key
// over the request's domain-separated statement; nothing before the cutoff. Its statements are re-sent while the request is committed.
func TestMissesAreStatedAtTheCutoffForTheMissingMembersOnly(t *testing.T) {
	w := newWorld(t)
	var sent [][]MissMessage
	m := w.Members[1]
	s := NewService(ServiceConfig{Self: m.Root, Signer: m.RK.Signer, SendMiss: func(ms []MissMessage) { sent = append(sent, ms) }})
	r := w.request(testDeadline)
	s.Update(w.committedAt(r, 10))
	pops := w.PoPs(w.in)
	for i := range pops[:3] { // members 1, 2, 3 prove; 5 does not
		_, _, err := s.Offer("root-2", Message{PoP: &pops[i]})
		require.NoError(t, err)
	}
	s.Update(w.committedAt(r, testDeadline-1))
	require.Empty(t, sent, "nothing before the cutoff")
	s.Update(w.committedAt(r, testDeadline))
	require.Len(t, sent, 1)
	require.Len(t, sent[0], 1)
	digest, err := r.Digest()
	require.NoError(t, err)
	st := sent[0][0]
	require.Equal(t, digest, st.Request)
	require.EqualValues(t, 5, st.StakingID)
	msg, err := vrschema.MissStatementBytes(digest, 5)
	require.NoError(t, err)
	require.NoError(t, vrschema.Verify(m.RK.Pub, st.Sig, msg))
	// decided once: a late proof changes nothing, and only the periodic re-send repeats the same statement
	_, _, err = s.Offer("root-2", Message{PoP: &pops[3]})
	require.NoError(t, err)
	for i := 0; i < MissResendEvery; i++ {
		s.Update(w.committedAt(r, testDeadline+1+uint64(i)))
	}
	require.Len(t, sent, 2)
	require.Equal(t, sent[0], sent[1])
	certs := s.MissCertificates(*r)
	require.Len(t, certs, 1)
	require.EqualValues(t, 5, certs[0].StakingID)
	require.Equal(t, m.Root, certs[0].Sigs[0].NodeID)
}

// A root that learned the request's intent only at or after the cutoff (a restart) states no miss: it never had the chance to receive the
// proofs.
func TestNoMissIsStatedForAnIntentLearnedAfterTheCutoff(t *testing.T) {
	w := newWorld(t)
	var sent [][]MissMessage
	m := w.Members[1]
	s := NewService(ServiceConfig{Self: m.Root, Signer: m.RK.Signer, SendMiss: func(ms []MissMessage) { sent = append(sent, ms) }})
	r := w.request(testDeadline)
	s.Update(w.committedAt(r, testDeadline))
	s.Update(w.committedAt(r, testDeadline+1))
	require.Empty(t, sent)
	require.Empty(t, s.MissCertificates(*r))
}

// Statements of the other incumbents are kept when they verify by the signer's root key; a non-incumbent's, a forged one and a repeat are
// not. The certificates are one per member, signatures ascending by node id, each member on its own.
func TestPeerMissStatementsAreVerifiedAndCertificatesArePerMember(t *testing.T) {
	w := newWorld(t)
	s := NewService(ServiceConfig{Self: "root-1"})
	r := w.request(testDeadline)
	s.Update(w.committedAt(r, 10))
	digest, err := r.Digest()
	require.NoError(t, err)
	state := func(i uint64, id uint64) MissMessage {
		msg, err := vrschema.MissStatementBytes(digest, id)
		require.NoError(t, err)
		sig, err := w.Members[i].RK.Signer.SignBytes(msg)
		require.NoError(t, err)
		return MissMessage{Request: digest, StakingID: id, Sig: sig}
	}
	for _, i := range []uint64{4, 2, 3} {
		o, err := s.OfferMiss(w.Members[i].Root, state(i, 3))
		require.NoError(t, err)
		require.Equal(t, Retained, o)
	}
	o, _ := s.OfferMiss(w.Members[2].Root, state(2, 3))
	require.Equal(t, Duplicate, o)
	o, _ = s.OfferMiss(w.Members[2].Root, state(2, 5))
	require.Equal(t, Retained, o)
	o, err = s.OfferMiss(w.Members[5].Root, state(5, 3))
	require.Equal(t, Dropped, o, "member 5 is a successor, not an incumbent")
	require.Error(t, err)
	forged := state(3, 5)
	forged.Sig[10] ^= 1
	o, err = s.OfferMiss(w.Members[3].Root, forged)
	require.Equal(t, Refused, o)
	require.Error(t, err)
	another := state(4, 5)
	o, err = s.OfferMiss(w.Members[3].Root, another)
	require.Equal(t, Refused, o, "a statement of another signer under this one's name")
	require.Error(t, err)

	certs := s.MissCertificates(*r)
	require.Len(t, certs, 2)
	require.EqualValues(t, 3, certs[0].StakingID)
	require.Equal(t, []string{"root-2", "root-3", "root-4"}, []string{certs[0].Sigs[0].NodeID, certs[0].Sigs[1].NodeID, certs[0].Sigs[2].NodeID})
	require.EqualValues(t, 5, certs[1].StakingID)
	require.Len(t, certs[1].Sigs, 1)
	// the committee of four unit weights has quorum 3: member 3's certificate stands, member 5's does not, and neither blocks the other
	var committee []vrschema.CommitteeMember
	for i := uint64(1); i <= 4; i++ {
		committee = append(committee, vrschema.CommitteeMember{NodeID: w.Members[i].Root, Key: w.Members[i].RK.Pub, Weight: 1})
	}
	bm, err := vrschema.VerifyMissCertificates(*r, certs[:1], committee, 3)
	require.NoError(t, err)
	require.EqualValues(t, 0b0100, bm, "bit 2: the third roster member, staking id 3")
	_, err = vrschema.VerifyMissCertificates(*r, certs[1:], committee, 3)
	require.ErrorIs(t, err, vrschema.ErrPoPMiss)
}

// A miss statement pushed over the peer protocol reaches the receiving root's service, signed by the stream's peer (#1319).
func TestAMissStatementOverRealHosts(t *testing.T) {
	w := newWorld(t)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	svc := w.service("x")
	r := w.request(testDeadline)
	c := w.committedAt(r, 10)
	c.Incumbents = map[string][]byte{sender.ID().String(): w.Members[1].RK.Pub}
	svc.Update(c)
	server := NewServer(svc, NewQueue(svc, 0), func(id peer.ID) bool { return id == sender.ID() })
	receiver.RegisterProtocolHandler(ProtocolID, server.Handler)
	t.Cleanup(func() { receiver.RemoveProtocolHandler(ProtocolID) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	digest, err := r.Digest()
	require.NoError(t, err)
	msg, err := vrschema.MissStatementBytes(digest, 5)
	require.NoError(t, err)
	sig, err := w.Members[1].RK.Signer.SignBytes(msg)
	require.NoError(t, err)
	require.NoError(t, PushMisses(ctx, FromLibp2p(sender), []peer.ID{receiver.ID()}, []MissMessage{{Request: digest, StakingID: 5, Sig: sig}}))
	require.Eventually(t, func() bool { return len(svc.MissCertificates(*r)) == 1 }, 20*time.Second, 50*time.Millisecond)
	got := svc.MissCertificates(*r)[0]
	require.EqualValues(t, 5, got.StakingID)
	require.Equal(t, sender.ID().String(), got.Sigs[0].NodeID)
}

// A root outside the predecessor committee (here the joining successor 5) states no miss: its statements would carry no weight.
func TestOnlyThePredecessorCommitteeStatesMisses(t *testing.T) {
	w := newWorld(t)
	var sent [][]MissMessage
	m := w.Members[5]
	s := NewService(ServiceConfig{Self: m.Root, Signer: m.RK.Signer, SendMiss: func(ms []MissMessage) { sent = append(sent, ms) }})
	r := w.request(testDeadline)
	s.Update(w.committedAt(r, 10))
	s.Update(w.committedAt(r, testDeadline))
	require.Empty(t, sent)
	require.Empty(t, s.MissCertificates(*r))
}

// #1319 review P2-1: a root that restarted after the members stopped re-sending (they stop once an assembly is held) but before the cutoff
// comes back without their proofs. It states nothing: it did not hold the intent from the request's block on.
func TestARootRestartedAfterTheRequestStatesNoMiss(t *testing.T) {
	w := newWorld(t)
	var sent [][]MissMessage
	m := w.Members[1]
	s := NewService(ServiceConfig{Self: m.Root, Signer: m.RK.Signer, SendMiss: func(ms []MissMessage) { sent = append(sent, ms) }})
	r := w.request(testDeadline)
	s.Update(w.committedAt(r, 11)) // (re)staged one block after the request's block (progress 10)
	s.Update(w.committedAt(r, testDeadline))
	require.Empty(t, sent, "no statement: the root cannot know what the members sent before it restarted")
}

// #1319 review P2-1: a root that held a verified assembly of the intent knows every member proved (the candidate carries a verified proof
// per successor), even when it never received a member's PoP directly; it states no miss.
func TestARootHoldingTheAssemblyStatesNoMiss(t *testing.T) {
	w := newWorld(t)
	var sent [][]MissMessage
	who := w.assembler(0)
	var s *Service
	for i := uint64(1); i <= 4 && s == nil; i++ { // an incumbent that is not view 0's assembler
		if m := w.Members[i]; m.Root != who {
			s = NewService(ServiceConfig{Self: m.Root, Signer: m.RK.Signer, SendMiss: func(ms []MissMessage) { sent = append(sent, ms) }})
		}
	}
	require.NotNil(t, s)
	r := w.request(testDeadline)
	s.Update(w.committedAt(r, 10))
	pops := w.PoPs(w.in)
	a := w.Assembly(w.in, w.d, 0, pops)
	o, _, err := s.Offer(who, Message{Assembly: &a})
	require.NoError(t, err)
	require.Equal(t, Retained, o, "the assembly is verified in full")
	s.Update(w.committedAt(r, testDeadline))
	require.Empty(t, sent, "the assembly proves every member: no miss")
	require.Empty(t, s.MissCertificates(*r))
}

// #1319 review P2-1: when a quorum of the roots restarted after the request (say a rolling upgrade inside the window), only the roots that
// held the intent throughout state misses, which is below the quorum: no member is certified.
func TestRestartedRootsCannotFormAQuorumOfMisses(t *testing.T) {
	w := newWorld(t)
	r := w.request(testDeadline)
	digest, err := r.Digest()
	require.NoError(t, err)
	var all []MissMessage
	var by []string
	var committee []vrschema.CommitteeMember
	for i := uint64(1); i <= 4; i++ {
		m := w.Members[i]
		committee = append(committee, vrschema.CommitteeMember{NodeID: m.Root, Key: m.RK.Pub, Weight: 1})
		var mine []MissMessage
		s := NewService(ServiceConfig{Self: m.Root, Signer: m.RK.Signer, SendMiss: func(ms []MissMessage) { mine = append(mine, ms...) }})
		since := uint64(10)
		if i > 1 {
			since = 200 // roots 2, 3, 4 restarted after the request; nobody proved to anyone
		}
		s.Update(w.committedAt(r, since))
		s.Update(w.committedAt(r, testDeadline))
		for _, x := range mine {
			all = append(all, x)
			by = append(by, m.Root)
		}
	}
	require.NotEmpty(t, all, "the root that held the intent throughout states the misses")
	collector := NewService(ServiceConfig{Self: w.Members[1].Root})
	collector.Update(w.committedAt(r, 10))
	for i, x := range all {
		_, _ = collector.OfferMiss(by[i], x)
	}
	for _, c := range collector.MissCertificates(*r) {
		_, err := vrschema.VerifyMissCertificates(*r, []vrschema.MissCertificate{c}, committee, 3)
		require.ErrorIs(t, err, vrschema.ErrPoPMiss, "member %d is not certified by one root", c.StakingID)
	}
	_ = digest
}

// #1319 review P3-3: statements of any other request digest than the committed one are dropped before verification.
func TestStatementsOfAnotherRequestAreDropped(t *testing.T) {
	w := newWorld(t)
	s := NewService(ServiceConfig{Self: "root-1"})
	r := w.request(testDeadline)
	other := *r
	other.Attempt++
	od, err := other.Digest()
	require.NoError(t, err)
	msg, err := vrschema.MissStatementBytes(od, 5)
	require.NoError(t, err)
	sig, err := w.Members[2].RK.Signer.SignBytes(msg)
	require.NoError(t, err)
	o, _ := s.OfferMiss(w.Members[2].Root, MissMessage{Request: od, StakingID: 5, Sig: sig})
	require.Equal(t, Dropped, o, "no committed request yet")
	s.Update(w.committedAt(r, 10))
	o, _ = s.OfferMiss(w.Members[2].Root, MissMessage{Request: od, StakingID: 5, Sig: sig})
	require.Equal(t, Dropped, o, "another request than the committed one")
}
