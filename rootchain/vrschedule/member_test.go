package vrschedule

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// swarm is the fixture's roots (1..4 the incumbents, 5 the joiner) as services joined by an in-memory bus; the successors 1, 2, 3 and 5
// run a Member. No test message is made by hand: the members' proofs and readiness are theirs.
type swarm struct {
	w        *world
	svcs     map[string]*Service
	members  map[string]*Member
	paths    map[string]string
	bus      []busMsg
	sentKind map[string]int
	sch      []vrschema.Activation
}

type busMsg struct {
	from string
	m    Message
}

func (w *world) swarm(t *testing.T, sch []vrschema.Activation) *swarm {
	s := &swarm{w: w, svcs: map[string]*Service{}, members: map[string]*Member{}, paths: map[string]string{}, sentKind: map[string]int{}, sch: sch}
	dir := t.TempDir()
	for i := uint64(1); i <= 5; i++ {
		s.start(t, w.Members[i].Root, filepath.Join(dir, w.Members[i].Root+".json"), i != 4)
	}
	return s
}

func (s *swarm) start(t *testing.T, id, path string, member bool) {
	var m *Member
	for _, x := range s.w.Members {
		if x.Root != id {
			continue
		}
		svc := NewService(ServiceConfig{Self: id, Signer: x.RK.Signer, Send: func(msg Message) { s.record(id, msg) }})
		s.svcs[id] = svc
		if member {
			var err error
			m, err = NewMember(svc, MemberConfig{Self: id, RootSigner: x.RK.Signer, EVMSigner: x.EK.Signer, Path: path, Send: func(msg Message) { s.record(id, msg) }})
			require.NoError(t, err)
			s.members[id] = m
		}
		s.paths[id] = path
	}
}

func (s *swarm) record(from string, m Message) {
	switch {
	case m.PoP != nil:
		s.sentKind["pop"]++
	case m.Assembly != nil:
		s.sentKind["assembly"]++
	case m.Readiness != nil:
		s.sentKind["readiness"]++
	}
	s.bus = append(s.bus, busMsg{from, m})
}

func (s *swarm) update(view uint64) {
	c := s.w.committed(view)
	c.Schedule = s.sch
	for _, svc := range s.svcs {
		svc.Update(c)
	}
}

// run steps every member and delivers the bus until it is quiet.
func (s *swarm) run(t *testing.T) {
	for round := 0; round < 40; round++ {
		for _, m := range s.members {
			require.NoError(t, m.Step())
		}
		if len(s.bus) == 0 {
			return
		}
		bus := s.bus
		s.bus = nil
		for _, b := range bus {
			for id, svc := range s.svcs {
				if id != b.from {
					_, _, _ = svc.Offer(b.from, b.m)
				}
			}
		}
	}
}

func readFile(t *testing.T, path string) memberFile {
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var f memberFile
	require.NoError(t, json.Unmarshal(raw, &f))
	return f
}

// Admitted or elected, the members do every step themselves: from the committed intent alone their possession proofs, the view's assembler's
// assembly, their readiness with the support commitments of the effective rule and a complete verified certificate come about on every root.
func TestMembersCompleteTheViewWithoutAHarness(t *testing.T) {
	w := newWorld(t)
	rule := vrschema.Activation{RuleID: vrschema.RuleID("rule-a"), ReleaseDigest: vrschema.Word{0xaa}, RootEpoch: 2, State: vrschema.ActActive, ChangeID: 1}
	s := w.swarm(t, []vrschema.Activation{rule})
	s.update(0)
	s.run(t)
	for id, svc := range s.svcs {
		_, _, complete, ok := svc.Current()
		require.True(t, ok)
		require.True(t, complete, "%s holds a complete verified certificate (I-RET)", id)
		set, _ := svc.Stage(w.d, 0)
		require.Len(t, set.Readiness, 4)
		for _, r := range set.Readiness {
			require.Len(t, r.Commitments, 1, "the readiness carries the effective rule's support commitment")
			require.Equal(t, rule.RuleID[:], r.Commitments[0].RuleID)
		}
	}
	require.GreaterOrEqual(t, s.sentKind["pop"], 4, "every member sent its proof")
	require.Equal(t, 1, s.sentKind["assembly"])
}

// The possession proof is sticky: one per intent and member, persisted, the same bytes after a restart.
func TestAMembersPoPIsStickyAcrossARestart(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	joiner := w.Members[5].Root
	require.NoError(t, s.members[joiner].Step())
	f := readFile(t, s.paths[joiner])
	require.Len(t, f.Intents, 1)
	first := f.Intents[0].PoP
	require.NotEmpty(t, first)

	s.start(t, joiner, s.paths[joiner], true) // the node restarts: a fresh service and member over the same file
	s.svcs[joiner].Update(w.committed(0))
	require.NoError(t, s.members[joiner].Step())
	require.Equal(t, first, readFile(t, s.paths[joiner]).Intents[0].PoP)
	got, ok := s.svcs[joiner].Stage(w.d, 0)
	require.True(t, ok)
	require.Len(t, got.PoPs, 1, "the restarted member re-offered its persisted proof to its fresh service")
	raw, err := hex.DecodeString(first)
	require.NoError(t, err)
	var want vrhandoff.PoPOffer
	require.NoError(t, types.Cbor.Unmarshal(raw, &want))
	require.Equal(t, want, got.PoPs[0])
}

// A member signs at most one assembly per view, persists (intent, view, candidate digest) before releasing, and after a restart re-sends what
// it persisted and never re-signs the view.
func TestAMemberSignsAViewOnceAndRestartsWithoutResigning(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	joiner := w.Members[5].Root
	f := readFile(t, s.paths[joiner])
	require.Len(t, f.Intents[0].Views, 1)
	v := f.Intents[0].Views[0]
	require.EqualValues(t, 0, v.View)
	require.NotEmpty(t, v.Readiness)

	// restart mid-protocol: the node comes back with a fresh service, learns the assembly (its peers re-serve it) and re-sends its readiness
	s.start(t, joiner, s.paths[joiner], true)
	s.svcs[joiner].Update(w.committed(0))
	set, ok := s.svcs[w.Members[1].Root].Stage(w.d, 0)
	require.True(t, ok)
	for _, m := range set.Offers() {
		if m.Readiness != nil && m.Readiness.Slot == 0 {
			continue // its own readiness is not served back to it: it must come from its file
		}
		_, _, _ = s.svcs[joiner].Offer("peer", m)
	}
	s.bus = nil
	require.NoError(t, s.members[joiner].Step())
	require.Equal(t, f, readFile(t, s.paths[joiner]), "nothing was signed again")
	rs, ok := s.svcs[joiner].Stage(w.d, 0)
	require.True(t, ok)
	have := false
	for _, r := range rs.Readiness {
		enc, err := r.Encode()
		require.NoError(t, err)
		have = have || hex.EncodeToString(enc) == v.Readiness
	}
	require.True(t, have, "the persisted readiness is in the restarted service again")

	// a different assembly of an already signed view is not signed
	pf := readFile(t, s.paths[joiner])
	pf.Intents[0].Views[0].CandidateDigest = hex.EncodeToString(make([]byte, 32))
	raw, err := json.Marshal(pf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(s.paths[joiner], raw, 0o600))
	s.start(t, joiner, s.paths[joiner], true)
	s.svcs[joiner].Update(w.committed(0))
	for _, m := range set.Offers() {
		if m.Readiness == nil {
			_, _, _ = s.svcs[joiner].Offer("peer", m)
		}
	}
	s.bus = nil
	require.NoError(t, s.members[joiner].Step())
	require.Empty(t, s.bus, "a view signed for another candidate is never signed again")
}

// Messages for a view that is not committed are not signed: a member waits for the committed view, and signs the next view's assembly only
// when that view commits.
func TestAMemberSignsOnlyInTheCommittedView(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	joiner := w.Members[5].Root
	require.Len(t, readFile(t, s.paths[joiner]).Intents[0].Views, 1)
	s.update(1) // view 1 commits: a new assembler assembles; the members sign it, as a second view
	s.run(t)
	views := readFile(t, s.paths[joiner]).Intents[0].Views
	require.Len(t, views, 2)
	require.EqualValues(t, 1, views[1].View)
}

// A node that is no successor of the intent (an incumbent that leaves) sends and signs nothing.
func TestANonSuccessorDoesNothing(t *testing.T) {
	w := newWorld(t)
	svc := NewService(ServiceConfig{Self: w.Members[4].Root})
	m, err := NewMember(svc, MemberConfig{Self: w.Members[4].Root, RootSigner: w.Members[4].RK.Signer, EVMSigner: w.Members[4].EK.Signer, Send: func(Message) { t.Fatal("sent") }})
	require.NoError(t, err)
	svc.Update(w.committed(0))
	require.NoError(t, m.Step())
}

// A corrupt member file is an error, never an empty state: a member must not forget a signed view.
func TestACorruptMemberFileRefusesToStart(t *testing.T) {
	w := newWorld(t)
	path := filepath.Join(t.TempDir(), "m.json")
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	_, err := NewMember(NewService(ServiceConfig{}), MemberConfig{Self: "x", RootSigner: w.Members[1].RK.Signer, Path: path})
	require.ErrorIs(t, err, ErrMember)
}
