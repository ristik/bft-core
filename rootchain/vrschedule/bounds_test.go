package vrschedule

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// The regressions of review #1188's message-handling findings (B1 to B7, B11).

func (w *world) signerOf(root string) abcrypto.Signer {
	for _, m := range w.Members {
		if m.Root == root {
			return m.RK.Signer
		}
	}
	w.T.Fatalf("no member %s", root)
	return nil
}

// held is a service at view 0 holding every proof and view 0's assembly.
func (w *world) held(c Committed) (*Service, vrhandoff.Assembly) {
	s := w.service("x")
	s.Update(c)
	pops := w.PoPs(w.in)
	a := w.Assembly(w.in, w.d, 0, pops)
	for i := range pops {
		_, _, _ = s.Offer("peer", Message{PoP: &pops[i]})
	}
	o, _, err := s.Offer(w.assembler(0), Message{Assembly: &a})
	require.NoError(w.T, err)
	require.Equal(w.T, Retained, o)
	return s, a
}

func (w *world) trustBase() []byte {
	_, tb, err := vrhandoff.TrustBase(w.in, w.RC.RootEpoch)
	require.NoError(w.T, err)
	return tb
}

// B1: a successor member re-signing its readiness (50 distinct, valid copies) yields one evidence record; only the first conflict is
// verified, every later copy is dropped unverified.
func TestReadinessEquivocationIsOneRecord(t *testing.T) {
	w := newWorld(t)
	s, a := w.held(w.committed(0))
	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256.Sum256(a.Candidate), w.BC)
	require.NoError(t, err)
	tb := w.trustBase()
	m := w.J[0]
	signer := w.ByStaking(m.StakingID).RK.Signer
	r0, err := vrhandoff.SignReadiness(w.in, a, body, m.RootNodeID, tb, nil, signer)
	require.NoError(t, err)
	o, _, err := s.Offer("byz", Message{Readiness: &r0})
	require.NoError(t, err)
	require.Equal(t, Retained, o)
	outcomes := map[Outcome]int{}
	for i := 0; i < 50; i++ {
		var rule vrschema.Word
		rule[0], rule[1] = byte(i), 0xAA
		c, err := vrhandoff.SignCommitment(w.in.Network, m, rule, rule, signer)
		require.NoError(t, err)
		r, err := vrhandoff.SignReadiness(w.in, a, body, m.RootNodeID, tb, []vrhandoff.SupportCommitment{c}, signer)
		require.NoError(t, err)
		j := s.Prepare("byz", Message{Readiness: &r})
		if i > 0 {
			require.Nil(t, j.Verify, "copy %d is not verified: the member already equivocated in the view", i)
		}
		o, _, _ := s.Offer("byz", Message{Readiness: &r})
		outcomes[o]++
	}
	require.Equal(t, map[Outcome]int{Equivocated: 1, Dropped: 49}, outcomes)
	ev := s.Evidence()
	require.Len(t, ev, 1)
	require.Equal(t, m.RootNodeID, ev[0].Signer)
	o, _, _ = s.Offer("peer", Message{Readiness: &r0})
	require.Equal(t, Duplicate, o, "the retained readiness stays")

	// the evidence goes with its view's retention window
	s.Update(w.committed(RetainedViews))
	require.Empty(t, s.Evidence())
}

// B1: an assembler signing a second assembly of its view yields one evidence record; later ones are dropped unverified.
func TestAssemblyEquivocationIsOneRecord(t *testing.T) {
	w := newWorld(t)
	s, a := w.held(w.committed(0))
	signer := w.signerOf(w.assembler(0))
	outcomes := map[Outcome]int{}
	for i := 0; i < 20; i++ {
		other := a
		other.Candidate = append(append([]byte(nil), a.Candidate...), byte(i))
		msg, err := other.SignedBytes()
		require.NoError(t, err)
		other.Sig, err = signer.SignBytes(msg)
		require.NoError(t, err)
		o, _, _ := s.Offer("relay", Message{Assembly: &other})
		outcomes[o]++
	}
	require.Equal(t, map[Outcome]int{Equivocated: 1, Dropped: 19}, outcomes)
	ev := s.Evidence()
	require.Len(t, ev, 1)
	require.Equal(t, w.assembler(0), ev[0].Signer)
	require.False(t, s.lastSeats()["relay"], "a relay of a valid conflict is not penalised")
}

// B1: a readiness with more commitments than the support table can hold is dropped before anything is verified or buffered.
func TestAnOversizedReadinessIsNeverVerified(t *testing.T) {
	w := newWorld(t)
	s, a := w.held(w.committed(0))
	r := w.readiness(a)[w.J[0].RootNodeID]
	r.Commitments = make([]vrschema.SupportCommitment, vrschema.SupportRules+1)
	j := s.Prepare("byz", Message{Readiness: &r})
	require.Nil(t, j.Verify)
	require.Equal(t, Dropped, j.Outcome)
}

// B2: a bogus or dead digest holds no slot: messages for a not-yet-derived intent from other senders are buffered within their own quota,
// a bogus digest's messages expire, and a dead intent's late messages are dropped outright.
func TestNoDigestHoldsTheBuffer(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	pops := w.PoPs(w.in)
	bogus := pops[0]
	bogus.IntentDigest = make([]byte, 32)
	bogus.IntentDigest[0] = 0xEE
	o, _, _ := s.Offer("byz", Message{PoP: &bogus})
	require.Equal(t, Buffered, o)
	next := pops[1]
	next.IntentDigest = make([]byte, 32)
	next.IntentDigest[0] = 0x11
	o, _, _ = s.Offer("honest", Message{PoP: &next})
	require.Equal(t, Buffered, o, "a message for the next intent is buffered, not dropped")
	for i := 0; i <= PendingExpiry; i++ {
		s.Update(w.committed(0))
	}
	s.mu.Lock()
	require.Empty(t, s.buffered, "both expired")
	s.mu.Unlock()

	// the current intent dies: its late messages are dropped, not buffered
	dead := w.committed(0)
	dead.Derivable = false
	s.Update(dead)
	o, _, _ = s.Offer("late", Message{PoP: &pops[2]})
	require.Equal(t, Dropped, o, "a dead intent's message")
	s.Update(w.committed(0))
	o, _, _ = s.Offer("late", Message{PoP: &pops[2]})
	require.Equal(t, Retained, o, "the same intent derived again is current")
}

// B3: before an intent is derived the bound is the largest committee's; at the bound a sender with fewer queued messages displaces the
// longest queue's newest, so two flooding senders cannot starve an honest one.
func TestQueueAdmissionIsFair(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	q := NewQueue(s, 0)
	pops := w.PoPs(w.in)
	admitted := 0
	for i := 0; i < 16; i++ {
		p := pops[i%len(pops)]
		if q.Submit(fmt.Sprintf("s%02d", i), Message{PoP: &p}) {
			admitted++
		}
	}
	require.Equal(t, 16, admitted, "no intent: n_s is MAX_COMMITTEE")
	require.Equal(t, QueueBound(vrschema.MaxCommittee), q.bound())

	s.Update(w.committed(0))
	q = NewQueue(s, 0)
	bound := q.bound()
	p := pops[0]
	for i := 0; i < MaxQueuedPerPeer; i++ {
		q.Submit("byz1", Message{PoP: &p})
		q.Submit("byz2", Message{PoP: &p})
	}
	require.Equal(t, bound, q.Len())
	for i := 0; i < 3; i++ {
		require.True(t, q.Submit(fmt.Sprintf("honest%d", i), Message{PoP: &p}), "an honest sender is admitted at the bound")
	}
	require.Equal(t, bound, q.Len())
	q.mu.Lock()
	require.LessOrEqual(t, len(q.per["byz1"])-len(q.per["byz2"]), 1)
	q.mu.Unlock()
	require.False(t, q.Submit("byz1", Message{PoP: &p}), "a flooding sender displaces nobody")
}

// B3: an invalid proof is verified at most 1 + MaxReplacements times per sender and successor.
func TestInvalidProofsHaveAnAllowance(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	p := w.PoPs(w.in)[0]
	p.PoP.Signature = append([]byte(nil), p.PoP.Signature...)
	p.PoP.Signature[3] ^= 1
	var got []Outcome
	for i := 0; i < 5; i++ {
		o, _, _ := s.Offer("byz", Message{PoP: &p})
		got = append(got, o)
	}
	require.Equal(t, []Outcome{Refused, Refused, Dropped, Dropped, Dropped}, got)
	good := w.PoPs(w.in)[0]
	o, _, _ := s.Offer("honest", Message{PoP: &good})
	require.Equal(t, Retained, o, "another sender's valid proof")
}

// B5: with a verification queue, buffered messages that become judgeable go back through the queue (verified there, off the service's
// lock), not inline.
func TestBufferedMessagesAreRequeued(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	q := NewQueue(s, 0)
	ms := w.messages(1)
	for _, m := range ms {
		_, _, _ = s.Offer("peer", m)
	}
	require.Zero(t, q.Len())
	s.Update(w.committed(1))
	require.NotZero(t, q.Len(), "view 1's assembly went to the queue")
	for q.Step() {
	}
	_, ok := s.Plan()
	require.True(t, ok, "the queue re-judged the buffered view, its readiness after its assembly")
}

// B6: a readiness naming another assembly of the view is dropped without charging its sender or moving its seat.
func TestAReadinessOfAnotherAssemblyIsNotCharged(t *testing.T) {
	w := newWorld(t)
	s, a := w.held(w.committed(0))
	other := a
	other.Candidate = append(append([]byte(nil), a.Candidate...), 1)
	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256.Sum256(other.Candidate), w.BC)
	require.NoError(t, err)
	tb := w.trustBase()
	m := w.J[0]
	r, err := vrhandoff.SignReadiness(w.in, other, body, m.RootNodeID, tb, nil, w.ByStaking(m.StakingID).RK.Signer)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		o, _, _ := s.Offer("honest", Message{Readiness: &r})
		require.Equal(t, Dropped, o)
	}
	require.False(t, s.lastSeats()["honest"])
	good := w.readiness(a)[m.RootNodeID]
	o, _, _ := s.Offer("honest", Message{Readiness: &good})
	require.Equal(t, Retained, o, "the sender's allowance is intact")
}

// B7: a readiness lacking the support an effective rule requires is refused (its sender keeps its seat) and a covering replacement is
// retained; no complete set without that support ever enters I-RET.
func TestAReadinessMustCarryTheRequiredSupport(t *testing.T) {
	w := newWorld(t)
	rule, release := vrschema.Word{0x51}, vrschema.Word{0x52}
	c := w.committed(0)
	c.Schedule = []vrschema.Activation{{RuleID: rule, ReleaseDigest: release, RootEpoch: w.RC.RootEpoch, State: vrschema.ActActive, ChangeID: 1}}
	s, a := w.held(c)
	rs := w.readiness(a) // no commitments
	m := w.J[0]
	bare := rs[m.RootNodeID]
	o, _, err := s.Offer("member", Message{Readiness: &bare})
	require.Equal(t, Refused, o)
	require.ErrorIs(t, err, vradmit.ErrSupportWait)
	require.False(t, s.lastSeats()["member"], "an unsupported readiness keeps its sender's seat")

	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256.Sum256(a.Candidate), w.BC)
	require.NoError(t, err)
	tb := w.trustBase()
	signer := w.ByStaking(m.StakingID).RK.Signer
	cm, err := vrhandoff.SignCommitment(w.in.Network, m, rule, release, signer)
	require.NoError(t, err)
	covered, err := vrhandoff.SignReadiness(w.in, a, body, m.RootNodeID, tb, []vrhandoff.SupportCommitment{cm}, signer)
	require.NoError(t, err)
	o, _, err = s.Offer("member", Message{Readiness: &covered})
	require.NoError(t, err)
	require.Equal(t, Retained, o, "the covering replacement")
	for id, r := range rs {
		if id != m.RootNodeID {
			r := r
			_, _, _ = s.Offer(id, Message{Readiness: &r})
		}
	}
	_, _, complete, _ := s.Current()
	require.False(t, complete, "the other members' bare readiness were refused: the view is not complete")
}

// The certificate stage re-checks the support (I-RET admission): a complete set of readiness each retained under the basis of its own
// time, which lacks the support required now, never enters I-RET. The committed schedule cannot change under a live intent (an Update
// that changes it restarts the intent's state, below), so the test sets it inside the service.
func TestTheCertificateStageRechecksTheSupport(t *testing.T) {
	w := newWorld(t)
	s, a := w.held(w.committed(0))
	rs := w.readiness(a)
	last := w.J[len(w.J)-1]
	for _, m := range w.J[:len(w.J)-1] {
		r := rs[m.RootNodeID]
		o, _, err := s.Offer(m.RootNodeID, Message{Readiness: &r})
		require.NoError(t, err)
		require.Equal(t, Retained, o)
	}
	rule, release := vrschema.Word{0x51}, vrschema.Word{0x52}
	s.mu.Lock()
	s.sch = []vrschema.Activation{{RuleID: rule, ReleaseDigest: release, RootEpoch: w.RC.RootEpoch, State: vrschema.ActActive, ChangeID: 1}}
	s.mu.Unlock()
	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256.Sum256(a.Candidate), w.BC)
	require.NoError(t, err)
	signer := w.ByStaking(last.StakingID).RK.Signer
	cm, err := vrhandoff.SignCommitment(w.in.Network, last, rule, release, signer)
	require.NoError(t, err)
	covered, err := vrhandoff.SignReadiness(w.in, a, body, last.RootNodeID, w.trustBase(), []vrhandoff.SupportCommitment{cm}, signer)
	require.NoError(t, err)
	o, _, err := s.Offer(last.RootNodeID, Message{Readiness: &covered})
	require.NoError(t, err)
	require.Equal(t, Retained, o, "the last member's readiness carries the support")
	_, _, complete, _ := s.Current()
	require.False(t, complete, "the complete set lacks the support required now: not held in I-RET")
	_, ok := s.Plan()
	require.False(t, ok)
}

// astra's op-4 reproduction (review of #1188, P1): an ordinary RuleSupport control, support for a scheduled future rule by a K member, changes
// the committed support table under a live intent. The intent, its view and everything verified for it stay at every root: the proofs, the
// assembly, the readiness, I-RET and the plan; a replacement commitment changes the table again, with the same result.
func TestASupportUpdateKeepsTheLiveIntent(t *testing.T) {
	w := newWorld(t)
	rule, release := vrschema.Word{0x51}, vrschema.Word{0x52}
	sch := []vrschema.Activation{{RuleID: rule, ReleaseDigest: release, RootEpoch: 100, State: vrschema.ActActive, ChangeID: 1}}
	w.RC.Fold.Schedule = sch
	w.in, w.d = w.Intent()
	c := w.committed(0)
	c.Schedule = sch
	roots := []*Service{w.service("x"), w.service("y")}
	for _, s := range roots {
		s.Update(c)
		offerAll(t, s, w.messages(0))
		_, ok := s.Plan()
		require.True(t, ok)
	}
	member := w.K[0]
	signer := w.ByStaking(member.StakingID).RK.Signer
	for _, rel := range []vrschema.Word{release, {0x53}} {
		cm, err := vrhandoff.SignCommitment(w.in.Network, member, rule, rel, signer)
		require.NoError(t, err)
		before := supportBasis(sch, c.Table)
		c.Table, err = vradmit.ApplyRuleSupport(c.Table, w.in.Network, []vrschema.SupportCommitment{cm}, w.K, sch)
		require.NoError(t, err, "a valid op-4 support update for a future rule")
		require.NotEqual(t, before, supportBasis(sch, c.Table))
		for _, s := range roots {
			s.Update(c)
			digest, view, complete, ok := s.Current()
			require.True(t, ok)
			require.Equal(t, w.d, digest)
			require.Zero(t, view)
			require.True(t, complete, "I-RET is kept")
			stage, ok := s.Stage(w.d, 0)
			require.True(t, ok)
			require.Len(t, stage.PoPs, len(w.J))
			require.Len(t, stage.Assemblies, 1)
			require.Len(t, stage.Readiness, len(w.J))
			_, ok = s.Plan()
			require.True(t, ok, "the plan holds over the new table")
		}
	}
}

// A changed basis under which the held certificate no longer meets gate (a) releases it, and only it: the intent's proofs, assembly and
// readiness stay, and a later complete set that meets the new basis may be held.
func TestABasisTheHeldCertificateFailsReleasesOnlyIt(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	offerAll(t, s, w.messages(0))
	_, _, complete, _ := s.Current()
	require.True(t, complete)
	c := w.committed(0)
	c.Schedule = []vrschema.Activation{{RuleID: vrschema.Word{0x51}, ReleaseDigest: vrschema.Word{0x52}, RootEpoch: w.RC.RootEpoch, State: vrschema.ActActive, ChangeID: 1}}
	s.Update(c)
	intent, _, complete, ok := s.Current()
	require.True(t, ok)
	require.Equal(t, w.d, intent, "the same live intent")
	require.False(t, complete, "the certificate lacks the support now required")
	set, _ := s.Stage(w.d, 0)
	require.Len(t, set.PoPs, len(w.J), "its proofs stay")
	require.Len(t, set.Assemblies, 1)
	require.Len(t, set.Readiness, len(w.J))
	o, _, _ := s.Offer("peer", w.messages(0)[0])
	require.Equal(t, Duplicate, o, "a sticky proof stays sticky")
}

// astra's starvation reproduction (review of #1188, P2): a seated-last sender's valid replacement is served within one round while another
// sender keeps its queue replenished with duplicates.
func TestASeatedLastReplacementIsServedWithinARound(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	p := w.PoPs(w.in)[0]
	bad := p
	bad.PoP.Signature = append([]byte(nil), p.PoP.Signature...)
	bad.PoP.Signature[3] ^= 1
	o, _, _ := s.Offer("recovering-peer", Message{PoP: &bad})
	require.Equal(t, Refused, o)
	q := NewQueue(s, 0)
	require.True(t, q.Submit("recovering-peer", Message{PoP: &p}))
	other := w.PoPs(w.in)[1]
	o, _, _ = s.Offer("other-peer", Message{PoP: &other})
	require.Equal(t, Retained, o)
	held := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, ok := s.cur.pops[p.EVMNodeID]
		return ok
	}
	steps := 0
	for ; steps < 1000 && !held(); steps++ {
		require.True(t, q.Submit("other-peer", Message{PoP: &other}))
		require.True(t, q.Step())
	}
	require.True(t, held(), "the replacement is retained")
	require.LessOrEqual(t, steps, 2, "within one round of two senders")
}

// Continuously replenished arrivals: with S senders each keeping its queue full, a message that arrives as its sender's j-th queued message
// is served within (j + 1) * S services (QMax's bound), seated-last senders included.
func TestServiceRoundsBoundTheWaitUnderReplenishedArrivals(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	s.mu.Lock()
	s.lastSeat["late-1"], s.lastSeat["late-2"] = true, true
	s.mu.Unlock()
	q := NewQueue(s, 0)
	q.bound = func() int { return 1 << 20 }
	senders := []string{"a", "b", "c", "d", "late-1", "late-2"}
	const depth = 3
	type tagged struct {
		sender string
		at     int
	}
	var pending []tagged
	p := w.PoPs(w.in)[0]
	submit := func(sender string, now int) {
		require.True(t, q.Submit(sender, Message{PoP: &p}))
		pending = append(pending, tagged{sender, now})
	}
	for _, x := range senders {
		for i := 0; i < depth; i++ {
			submit(x, 0)
		}
	}
	served := map[string]int{}
	worst := 0
	for step := 1; step <= 600; step++ {
		m, ok := q.pop()
		require.True(t, ok)
		// the sender's oldest outstanding message is the one served (FIFO per sender)
		for i, tg := range pending {
			if tg.sender == m.sender {
				worst = max(worst, step-tg.at)
				pending = append(pending[:i], pending[i+1:]...)
				break
			}
		}
		served[m.sender]++
		submit(m.sender, step) // every sender keeps its queue at depth
	}
	bound := (depth + 1) * len(senders)
	require.LessOrEqual(t, worst, bound, "no message waits longer than (j + 1) * S services")
	for _, x := range senders {
		require.InDelta(t, 100, served[x], 1, "every sender, seated last or not, is served once per round")
	}
}

// B11: when the served sender's queue empties, the next sender is served next, not skipped.
func TestRoundRobinSkipsNoSender(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	q := NewQueue(s, 0)
	p := w.PoPs(w.in)[0]
	q.Submit("a", Message{PoP: &p})
	q.Submit("b", Message{PoP: &p})
	q.Submit("b", Message{PoP: &p})
	q.Submit("c", Message{PoP: &p})
	var order []string
	for q.Len() > 0 {
		m, _ := q.pop()
		order = append(order, m.sender)
	}
	require.Equal(t, []string{"a", "b", "c", "b"}, order)
}

// The on-demand output read (review #1188 test gaps): Derive reads VR's output at an uncached certified EVM state through Fetch and caches
// it; DeriveCached, the leader's check, never fetches and reports the state unavailable.
func TestDeriveFetchesOnDemandAndDeriveCachedNever(t *testing.T) {
	st := vradmit.GenesisRootState(1, 4)
	raw, err := st.Encode()
	require.NoError(t, err)
	sources, err := NewSources("")
	require.NoError(t, err)
	root := [32]byte{7}
	fetches := 0
	p := &Intents{Config: func() (q3format.ProtocolConfig, error) { return q3format.ProtocolConfig{}, nil }, Sources: sources, Outputs: NewOutputs(),
		Fetch: func(_, r [32]byte) (*vrhandoff.Output, error) {
			fetches++
			require.Equal(t, root, r)
			return nil, nil // no open Published output there
		}}
	q := storage.VRIntentQuery{Control: &evmroot.ControlState{VR: raw}, Backoff: st.Backoff, Epoch: st.Backoff.Epoch, LatestEVMRoot: root,
		LatestEVMBlock: make([]byte, 32), LatestEVMOK: true, Root: func() (storage.VRRootFacts, error) { return storage.VRRootFacts{}, nil }}
	_, ok, err := p.DeriveCached(q)
	require.ErrorIs(t, err, ErrUnavailable)
	require.False(t, ok)
	require.Zero(t, fetches, "the leader's check never reads the execution client")
	_, ok, err = p.Derive(q)
	require.NoError(t, err)
	require.False(t, ok, "fetched: no open output there")
	require.Equal(t, 1, fetches)
	_, _, err = p.DeriveCached(q)
	require.NoError(t, err, "now cached")
	_, _, _ = p.Derive(q)
	require.Equal(t, 1, fetches, "cached: not fetched again")
}

// At the bound, among equally long queues the sender the service seated last is displaced first.
func TestDisplacementPrefersASenderSeatedLast(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	bad := w.PoPs(w.in)[0]
	bad.PoP.Signature = append([]byte(nil), bad.PoP.Signature...)
	bad.PoP.Signature[3] ^= 1
	o, _, _ := s.Offer("zz-byz", Message{PoP: &bad})
	require.Equal(t, Refused, o)
	require.True(t, s.lastSeats()["zz-byz"])
	q := NewQueue(s, 0)
	q.bound = func() int { return 4 }
	p := w.PoPs(w.in)[1]
	for i := 0; i < 2; i++ {
		require.True(t, q.Submit("aa-honest", Message{PoP: &p}))
		require.True(t, q.Submit("zz-byz", Message{PoP: &p}))
	}
	require.True(t, q.Submit("mm-new", Message{PoP: &p}))
	q.mu.Lock()
	defer q.mu.Unlock()
	require.Len(t, q.per["aa-honest"], 2, "the honest sender keeps its messages")
	require.Len(t, q.per["zz-byz"], 1)
}
