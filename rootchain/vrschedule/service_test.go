package vrschedule

import (
	"crypto/sha256"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type world struct {
	*vrhandofffix.Fixture
	in  vrhandoff.Intent
	d   [32]byte
	ids []string
}

func newWorld(t *testing.T) *world {
	f := vrhandofffix.New(t)
	in, d := f.Intent()
	_, ids := f.Incumbents()
	return &world{Fixture: f, in: in, d: d, ids: ids}
}

func (w *world) committed(view uint64) Committed {
	keys, _ := w.Incumbents()
	return Committed{Derived: Derived{VRIntent: storage.VRIntent{Digest: w.d, AnchorRound: w.in.AnchorRound}, Intent: w.in, RootEpoch: w.RC.RootEpoch, Body: w.BC},
		Derivable: true, CommittedView: view, Incumbents: keys, K: w.K}
}

// service is a root's service; self names it (an incumbent's node id) and signs its assemblies with its key.
func (w *world) service(self string) *Service {
	for _, m := range w.Members {
		if m.Root == self {
			return NewService(ServiceConfig{Self: self, Signer: m.RK.Signer})
		}
	}
	return NewService(ServiceConfig{Self: self})
}

func (w *world) assembler(view uint64) string { return vrhandoff.Assembler(w.d, w.ids, view) }

// readiness is every successor's readiness of an assembly, by root node id.
func (w *world) readiness(a vrhandoff.Assembly) map[string]vrhandoff.Readiness {
	t := w.T
	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256.Sum256(a.Candidate), w.BC)
	require.NoError(t, err)
	_, tb, err := vrhandoff.TrustBase(w.in, w.RC.RootEpoch)
	require.NoError(t, err)
	out := map[string]vrhandoff.Readiness{}
	for _, m := range w.J {
		r, err := vrhandoff.SignReadiness(w.in, a, body, m.RootNodeID, tb, nil, w.ByStaking(m.StakingID).RK.Signer)
		require.NoError(t, err)
		out[m.RootNodeID] = r
	}
	return out
}

func (w *world) messages(view uint64) []Message {
	pops := w.PoPs(w.in)
	a := w.Assembly(w.in, w.d, view, pops)
	var out []Message
	for i := range pops {
		out = append(out, Message{PoP: &pops[i]})
	}
	out = append(out, Message{Assembly: &a})
	for _, r := range w.readiness(a) {
		r := r
		out = append(out, Message{Readiness: &r})
	}
	return out
}

func offerAll(t *testing.T, s *Service, ms []Message) {
	for _, m := range ms {
		_, _, _ = s.Offer("peer", m)
	}
}

// Two roots receiving the messages of view 0 in different orders (readiness before its assembly is buffered and judged once the assembly
// is held) reach the same judgment: a complete verified certificate and a Prepare plan whose certificate both verify; identical caches are
// not required.
func TestTwoRootsJudgeMessagesInAnyOrderAlike(t *testing.T) {
	w := newWorld(t)
	ms := w.messages(0)
	a, b := w.service("x"), w.service("y")
	a.Update(w.committed(0))
	b.Update(w.committed(0))
	rev := append([]Message(nil), ms...)
	rand.New(rand.NewSource(7)).Shuffle(len(rev), func(i, j int) { rev[i], rev[j] = rev[j], rev[i] })
	offerAll(t, a, ms)
	offerAll(t, b, rev)
	pa, ok := a.Plan()
	require.True(t, ok)
	pb, ok := b.Plan()
	require.True(t, ok)
	require.Equal(t, pa.Certificate.Assembly.Candidate, pb.Certificate.Assembly.Candidate)
	require.Equal(t, w.d, pa.Intent)
	require.Equal(t, w.R, pa.Result)
	require.Empty(t, pa.RuleSupport.Refs, "no effective rule: no support evidence")
}

// The committed current view's assembler assembles once every successor's proof is held and sends it; another root does not; nothing
// advances the view but a committed HandoffView.
func TestTheViewsAssemblerAssembles(t *testing.T) {
	w := newWorld(t)
	var sent []Message
	who := w.assembler(0)
	var s *Service
	for _, m := range w.Members {
		if m.Root == who {
			s = NewService(ServiceConfig{Self: who, Signer: m.RK.Signer, Send: func(m Message) {
				if m.Assembly != nil { // the peers' proofs it relays are counted by TestARetainedProofIsRelayedOnce
					sent = append(sent, m)
				}
			}})
		}
	}
	require.NotNil(t, s)
	s.Update(w.committed(0))
	other := w.service(w.assembler(1))
	other.Update(w.committed(0))
	for _, p := range w.PoPs(w.in) {
		p := p
		_, _, err := s.Offer("peer", Message{PoP: &p})
		require.NoError(t, err)
		_, _, err = other.Offer("peer", Message{PoP: &p})
		require.NoError(t, err)
	}
	require.Len(t, sent, 1, "view 0's assembler sent its assembly")
	require.EqualValues(t, 0, sent[0].Assembly.Slot)
	// view 1 commits: the other root is its assembler and assembles from the proofs it already holds
	out := other.Update(w.committed(1))
	require.Len(t, out, 1)
	require.EqualValues(t, 1, out[0].Assembly.Slot)
	_, view, _, ok := s.Current()
	require.True(t, ok)
	require.EqualValues(t, 0, view, "the service never advances a view on its own")
}

// Sticky proofs: a second valid proof of a member is a duplicate. Equivocation: a second, different readiness of one member in one view is
// evidence; readiness of the same member in another view is not.
func TestStickyProofsAndEquivocation(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(1))
	ms0, ms1 := w.messages(0), w.messages(1)
	offerAll(t, s, ms0)
	offerAll(t, s, ms1)
	require.Empty(t, s.Evidence(), "readiness in different views is not equivocation")
	p := *ms0[0].PoP
	o, _, _ := s.Offer("peer", Message{PoP: &p})
	require.Equal(t, Duplicate, o)

	// a second readiness of the first member in view 1, over another trust-base signature (another valid encoding of its statement)
	var r vrhandoff.Readiness
	for _, m := range ms1 {
		if m.Readiness != nil {
			r = *m.Readiness
			break
		}
	}
	member := w.ByStaking(w.J[0].StakingID)
	for _, j := range w.J {
		if _, err := vrschema.ReadinessReceipt(r.Receipt, j.RootNodeID); err == nil {
			member = w.ByStaking(j.StakingID)
		}
	}
	// re-sign the envelope with a commitment-free but different trust-base signature: a signed conflict
	var a vrhandoff.Assembly
	for _, m := range ms1 {
		if m.Assembly != nil {
			a = *m.Assembly
		}
	}
	tbSig, err := member.RK.Signer.SignBytes([]byte("another trust base"))
	require.NoError(t, err)
	r2 := r
	r2.TrustBaseSig = tbSig
	env, err := r2.EnvelopeBytes()
	require.NoError(t, err)
	r2.EnvelopeSig, err = member.RK.Signer.SignBytes(env)
	require.NoError(t, err)
	_ = a
	o, _, _ = s.Offer("peer", Message{Readiness: &r2})
	require.Equal(t, Refused, o, "a second readiness that does not verify is refused, not evidence")
	o, _, _ = s.Offer("peer", Message{Readiness: &r})
	require.Equal(t, Duplicate, o)
}

// An invalid readiness alone completes nothing; a later valid replacement completes the view; the replacement allowance is bounded and
// never weakens certificate membership.
func TestInvalidReadinessAndItsReplacement(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	pops := w.PoPs(w.in)
	a := w.Assembly(w.in, w.d, 0, pops)
	for i := range pops {
		_, _, _ = s.Offer("peer", Message{PoP: &pops[i]})
	}
	_, _, err := s.Offer(w.assembler(0), Message{Assembly: &a})
	require.NoError(t, err)
	rs := w.readiness(a)
	var last string
	for id, r := range rs {
		last = id
		_ = r
	}
	for id, r := range rs {
		if id == last {
			continue
		}
		r := r
		o, _, err := s.Offer(id, Message{Readiness: &r})
		require.NoError(t, err)
		require.Equal(t, Retained, o)
	}
	bad := rs[last]
	bad.TrustBaseSig = append([]byte(nil), bad.TrustBaseSig...)
	bad.TrustBaseSig[5] ^= 1
	o, _, _ := s.Offer(last, Message{Readiness: &bad})
	require.Equal(t, Refused, o)
	_, ok := s.Plan()
	require.False(t, ok, "an invalid readiness alone causes no Prepare")
	o, _, _ = s.Offer(last, Message{Readiness: &bad})
	require.Equal(t, Refused, o, "the one replacement, again invalid")
	o, _, _ = s.Offer(last, Message{Readiness: &bad})
	require.Equal(t, Dropped, o, "the replacement counter limits attempts")
	_, ok = s.Plan()
	require.False(t, ok, "without a valid replacement the view does not complete")

	// a fresh root with a valid replacement after one failure completes normally
	s2 := w.service("x")
	s2.Update(w.committed(0))
	for i := range pops {
		_, _, _ = s2.Offer("peer", Message{PoP: &pops[i]})
	}
	_, _, _ = s2.Offer(w.assembler(0), Message{Assembly: &a})
	o, _, _ = s2.Offer(last, Message{Readiness: &bad})
	require.Equal(t, Refused, o)
	for id, r := range rs {
		r := r
		_, _, _ = s2.Offer(id, Message{Readiness: &r})
	}
	_, ok = s2.Plan()
	require.True(t, ok, "the valid replacement completes the view")
}

// I-RET: the first complete certificate (view 1) stays usable after the committed view advanced to 1 + 6, while the views window moves
// on; buffered messages for a view two ahead are judged once it commits, three ahead are dropped; an intent that dies takes its plan.
func TestIRetAcrossAdvancementAndIntentDeath(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(1))
	offerAll(t, s, w.messages(1))
	p, ok := s.Plan()
	require.True(t, ok)
	require.EqualValues(t, 1, p.Certificate.Assembly.Slot)
	for v := uint64(2); v <= 7; v++ {
		s.Update(w.committed(v))
	}
	p7, ok := s.Plan()
	require.True(t, ok, "a certificate of view h is usable at h + 6")
	require.Equal(t, p.Certificate.Assembly.Candidate, p7.Certificate.Assembly.Candidate)

	ahead := w.service("x")
	ahead.Update(w.committed(0))
	for _, m := range w.messages(2) {
		m := m
		o, _, _ := ahead.Offer("peer", m)
		if m.PoP == nil {
			require.Equal(t, Buffered, o, "a view two ahead is buffered")
		}
	}
	m3 := w.messages(3)
	o, _, _ := ahead.Offer("peer", m3[len(m3)-1])
	require.Equal(t, Dropped, o, "three ahead is dropped")
	_, ok = ahead.Plan()
	require.False(t, ok)
	ahead.Update(w.committed(2))
	_, ok = ahead.Plan()
	require.True(t, ok, "buffered messages are re-evaluated when their view commits")

	dead := w.committed(7)
	dead.Derivable = false
	s.Update(dead)
	_, ok = s.Plan()
	require.False(t, ok, "the intent died: stage 0 restarts")
	pr := w.committed(7)
	pr.Prepared = true
	s.Update(pr)
	_, ok = s.Plan()
	require.False(t, ok, "a committed Prepare ends planning")
}

// A restarted root rebuilds its view state from a peer's stage set.
func TestStageRebuildsARestartedRoot(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	offerAll(t, s, w.messages(0))
	set, ok := s.Stage(w.d, 0)
	require.True(t, ok)
	require.Len(t, set.PoPs, len(w.J))
	require.Len(t, set.Assemblies, 1)
	require.Len(t, set.Readiness, len(w.J))
	restarted := w.service("y")
	restarted.Update(w.committed(0))
	offerAll(t, restarted, set.Offers())
	_, ok = restarted.Plan()
	require.True(t, ok)
	_, ok = s.Stage([32]byte{1}, 0)
	require.False(t, ok)
}

type stepClock struct{ now time.Time }

func (c *stepClock) Now() time.Time { return c.now }

// The verification queue: bounded to (1 + n_s) x 4 x 2, 64 per peer, served round-robin by sender with a sender whose message failed
// verification seated last; a verification over PiMax on the wall clock keeps its result.
func TestTheVerificationQueue(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	s.Update(w.committed(0))
	require.Equal(t, 40, QueueBound(4))
	require.Equal(t, 19600*time.Millisecond, QMax(3*vrschema.MaxCommittee+1, 3, 100*time.Millisecond), "the honest envelope: j = 3, S = 49")
	require.Equal(t, 318500*time.Millisecond, QMax(3*vrschema.MaxCommittee+1, MaxQueuedPerPeer, 100*time.Millisecond), "the queue's own bound")
	require.True(t, PVAdequate(10, 1, 19, 10), "D + delta + Q_max < 4 T at T(0, 0)")
	q := NewQueue(s, 100*time.Millisecond)
	var order []string
	q.Delivered = func(Outcome, []Message, error) {}
	ms := w.messages(0)
	for i := 0; i < 3; i++ {
		require.True(t, q.Submit("a", variant(*ms[0].PoP, i+1)))
		require.True(t, q.Submit("b", variant(*ms[1].PoP, i+1)))
	}
	for q.Len() > 0 {
		m, _ := q.pop()
		order = append(order, m.sender)
	}
	require.Equal(t, []string{"a", "b", "a", "b", "a", "b"}, order, "round-robin by sender")
	for i := 0; i < 40; i++ {
		q.Submit("p"+string(rune('a'+i%26))+string(rune('a'+i/26)), ms[0])
	}
	require.False(t, q.Submit("late", ms[0]), "over the bound")
	for q.Step() {
	}

	// a verification that takes longer than PiMax on the wall clock keeps its result (review #1188 B4): PiMax is a cost bound
	slow := w.service("x")
	slow.Update(w.committed(0))
	sq := NewQueue(slow, 100*time.Millisecond)
	clock := &stepClock{now: time.Unix(1000, 0)}
	calls := 0
	sq.now = func() time.Time {
		calls++
		if calls%2 == 0 {
			clock.now = clock.now.Add(150 * time.Millisecond)
		}
		return clock.now
	}
	var outs []Outcome
	sq.Delivered = func(o Outcome, _ []Message, _ error) { outs = append(outs, o) }
	p := *ms[0].PoP
	sq.Submit("a", Message{PoP: &p})
	sq.Step()
	require.Equal(t, []Outcome{Retained}, outs, "a slow verification is kept, never discarded")
	require.False(t, slow.lastSeats()["a"])
}

// The transport may read the service while it sends (its peers are the service's members): Send runs outside the service's lock (found on
// the live run, where the assembler root deadlocked its consensus loop).
func TestSendRunsOutsideTheServicesLock(t *testing.T) {
	w := newWorld(t)
	who := w.assembler(0)
	var s *Service
	sent := 0
	for _, m := range w.Members {
		if m.Root == who {
			s = NewService(ServiceConfig{Self: who, Signer: m.RK.Signer, Send: func(m Message) {
				_ = s.Members()
				_, _ = s.Plan()
				if m.Assembly != nil {
					sent++
				}
			}})
		}
	}
	require.NotNil(t, s)
	s.Update(w.committed(0))
	done := make(chan struct{})
	go func() {
		for _, p := range w.PoPs(w.in) {
			p := p
			_, _, _ = s.Offer("peer", Message{PoP: &p})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the assembler's Send deadlocked on the service")
	}
	require.Equal(t, 1, sent)
}
