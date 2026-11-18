package vrschedule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
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
	supports func(vrschema.Activation) bool
	stages   map[string]int
}

type busMsg struct {
	from string
	m    Message
}

func (w *world) swarm(t *testing.T, sch []vrschema.Activation) *swarm {
	s := &swarm{w: w, svcs: map[string]*Service{}, members: map[string]*Member{}, paths: map[string]string{}, sentKind: map[string]int{}, sch: sch, stages: map[string]int{}, supports: func(vrschema.Activation) bool { return true }}
	dir := t.TempDir()
	for i := uint64(1); i <= 5; i++ {
		s.start(t, w.Members[i].Root, filepath.Join(dir, w.Members[i].Root+".json"), true)
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
			m, err = NewMember(svc, MemberConfig{Self: id, RootSigner: x.RK.Signer, EVMSigner: x.EK.Signer, Path: path, Send: func(msg Message) { s.record(id, msg) }, Supports: s.supports,
				Stage: func(Staged) error { s.stages[id]++; return nil }})
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
		require.Len(t, set.Readiness, 5, "four successors and the K member that leaves")
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
	s.start(t, joiner, s.paths[joiner], true)
	s.svcs[joiner].Update(w.committed(0))
	for _, m := range set.Offers() {
		if m.Readiness == nil {
			_, _, _ = s.svcs[joiner].Offer("peer", m)
		}
	}
	tamperAssembly(s.svcs[joiner], 0)
	s.bus = nil
	require.NoError(t, s.members[joiner].Step())
	for _, b := range s.bus {
		if b.m.Readiness != nil {
			enc, err := b.m.Readiness.Encode()
			require.NoError(t, err)
			require.Equal(t, v.Readiness, hex.EncodeToString(enc), "only the readiness it signed is re-sent, nothing new")
		}
	}
	require.Equal(t, f, readFile(t, s.paths[joiner]))
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

// A K member that is no successor (identity 4 leaves) sends readiness for rule support only, on its own: every root retains it beside the
// certificate, and the Prepare plan's rule-support evidence carries every K member's readiness (the J readiness of K members that stay, the
// support-only readiness of the one that leaves), ascending by stakingID, so the K-support gate of the activation rule holds over all of K.
func TestAKMemberThatLeavesSendsSupportReadinessAndThePlanCarriesIt(t *testing.T) {
	w := newWorld(t)
	rule := vrschema.Activation{RuleID: vrschema.RuleID("rule-a"), ReleaseDigest: vrschema.Word{0xaa}, RootEpoch: 2, State: vrschema.ActActive, ChangeID: 1}
	s := w.swarm(t, []vrschema.Activation{rule})
	s.update(0)
	s.run(t)
	leaver := w.Members[4].Root
	for id, svc := range s.svcs {
		p, ok := svc.Plan()
		require.True(t, ok, "%s: the K-support gate holds from this intent's K-member readiness", id)
		require.Len(t, p.RuleSupport.KReadiness, 4)
		var prev []byte
		have := false
		for _, r := range p.RuleSupport.KReadiness {
			sid := r.Commitments[0].StakingID
			require.Greater(t, string(sid), string(prev))
			prev = sid
			have = have || string(sid) == string(vrhandoffStaking(4))
		}
		require.True(t, have, "the leaving member's readiness is part of the evidence")
		_, ok = svc.Prepared()
		require.True(t, ok)
	}
	require.Len(t, readFile(t, s.paths[leaver]).Intents[0].Views, 1, "it signed its one view")
}

func vrhandoffStaking(id uint64) []byte { w := vrschema.U64(id); return w[:] }

// A K member's readiness is support only: without a commitment it is refused, and a readiness of a node that is neither a successor nor in
// K is dropped.
func TestAKMembersReadinessNeedsACommitmentAndOutsidersAreDropped(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil) // no rule: nothing for a K member to support
	s.update(0)
	s.run(t)
	leaver := w.Members[4].Root
	_, err := os.Stat(s.paths[leaver])
	require.True(t, os.IsNotExist(err), "no rule needs its support: it signed and sent nothing")
	svc := s.svcs[w.Members[1].Root]
	set, _ := svc.Stage(w.d, 0)
	require.Len(t, set.Readiness, 4)

	// a K member's readiness without a commitment (built by hand over the held assembly) is refused
	a := set.Assemblies[0]
	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256sum(a.Candidate), w.BC)
	require.NoError(t, err)
	_, tb, err := vrhandoff.TrustBase(w.in, w.RC.RootEpoch)
	require.NoError(t, err)
	r, err := vrhandoff.SignReadiness(w.in, a, body, leaver, tb, nil, w.Members[4].RK.Signer)
	require.NoError(t, err)
	o, _, _ := svc.Offer("peer", Message{Readiness: &r})
	require.Equal(t, Refused, o)
	// a node outside K and J
	r2, err := vrhandoff.SignReadiness(w.in, a, body, "outsider", tb, nil, w.Members[4].RK.Signer)
	require.NoError(t, err)
	o, _, _ = svc.Offer("peer", Message{Readiness: &r2})
	require.Equal(t, Dropped, o)
}

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

// Rule support is fail-closed: a node that does not implement a scheduled rule signs no readiness (it would burn its one signature of the view
// and claim a release it does not run), and logs UpgradeRequired; with the rule implemented it commits to it, in ascending rule order, for
// the rules the gate needs only (a latched rule is committed, a rule beyond the successor epoch's reach is not).
func TestAMemberSupportsOnlyWhatItImplements(t *testing.T) {
	w := newWorld(t)
	rule := vrschema.Activation{RuleID: vrschema.RuleID("rule-a"), ReleaseDigest: vrschema.Word{0xaa}, RootEpoch: 2, State: vrschema.ActActive, ChangeID: 1}
	latched := vrschema.Activation{RuleID: vrschema.RuleID("rule-b"), ReleaseDigest: vrschema.Word{0xbb}, RootEpoch: 1, State: vrschema.ActLatched, ChangeID: 2}
	far := vrschema.Activation{RuleID: vrschema.RuleID("rule-c"), ReleaseDigest: vrschema.Word{0xcc}, RootEpoch: 9, State: vrschema.ActActive, ChangeID: 3}
	sch := []vrschema.Activation{rule, latched, far}

	// the default: ImplementedRules (empty): nothing is supported, so nothing is signed and the view does not complete
	s := w.swarm(t, sch)
	s.supports = nil
	for id := range s.members {
		svc := s.svcs[id]
		m, err := NewMember(svc, MemberConfig{Self: id, RootSigner: w.byRoot(id).RK.Signer, EVMSigner: w.byRoot(id).EK.Signer, Send: func(msg Message) { s.record(id, msg) }})
		require.NoError(t, err)
		s.members[id] = m
	}
	s.update(0)
	s.run(t)
	require.Zero(t, s.sentKind["readiness"], "a node that implements none of the scheduled rules signs no readiness")
	for _, svc := range s.svcs {
		_, _, complete, _ := svc.Current()
		require.False(t, complete)
	}

	// implementing them: the commitments are the rules the gate needs (E <= epoch+1), ascending, the far rule excluded
	ImplementedRules[[2]vrschema.Word{rule.RuleID, rule.ReleaseDigest}] = true
	ImplementedRules[[2]vrschema.Word{latched.RuleID, latched.ReleaseDigest}] = true
	t.Cleanup(func() {
		delete(ImplementedRules, [2]vrschema.Word{rule.RuleID, rule.ReleaseDigest})
		delete(ImplementedRules, [2]vrschema.Word{latched.RuleID, latched.ReleaseDigest})
	})
	s.update(0)
	s.run(t)
	set, _ := s.svcs[w.Members[1].Root].Stage(w.d, 0)
	require.NotEmpty(t, set.Readiness)
	for _, r := range set.Readiness {
		require.Len(t, r.Commitments, 2)
		require.Less(t, string(r.Commitments[0].RuleID), string(r.Commitments[1].RuleID))
		for _, c := range r.Commitments {
			require.NotEqual(t, far.RuleID[:], c.RuleID, "a rule beyond the successor epoch's reach is not committed")
		}
	}
}

// The EVM key must be the member's: a key of another node is refused before anything is persisted; a persisted proof that does not verify is
// derived again, and only the proof, never a signed view.
func TestAWrongEVMKeyIsRefusedAndAnInvalidStoredPoPIsRecovered(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	path := filepath.Join(t.TempDir(), "m.json")
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	svc.Update(w.committed(0))

	wrong, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: w.Members[1].EK.Signer, EVMNodeID: w.Members[1].EVM, Path: path})
	require.NoError(t, err)
	err = wrong.Step()
	require.ErrorIs(t, err, ErrMember)
	require.Contains(t, err.Error(), "--vr-evm-keys")
	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "nothing was persisted")

	// the node id is not known to the caller, but the key is another node's: the proof does not verify and is not persisted either
	anon, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: w.Members[1].EK.Signer, Path: path})
	require.NoError(t, err)
	require.ErrorIs(t, anon.Step(), ErrMember)
	_, statErr = os.Stat(path)
	require.True(t, os.IsNotExist(statErr))

	// a stored proof that does not verify (written by an older run with the wrong key) is derived again: only the proof is replaced, a signed
	// view stays. The record is a genuine one (the joiner signed its view 0), its proof then replaced by one of another EVM key.
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	f := readFile(t, s.paths[self.Root])
	wrongPoP, err := vrhandoff.SignPoP(w.in, w.J[3], w.Members[1].EK.Signer) // member 5's identity, another node's EVM key
	require.NoError(t, err)
	rawPoP, err := types.Cbor.Marshal(wrongPoP)
	require.NoError(t, err)
	f.Intents[0].PoP = hex.EncodeToString(rawPoP)
	raw, err := json.Marshal(f)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(s.paths[self.Root], raw, 0o600))
	s.start(t, self.Root, s.paths[self.Root], true)
	s.svcs[self.Root].Update(w.committed(0))
	require.NoError(t, s.members[self.Root].Step())
	g := readFile(t, s.paths[self.Root])
	require.NotEqual(t, f.Intents[0].PoP, g.Intents[0].PoP, "the invalid stored proof was derived again")
	require.Equal(t, f.Intents[0].Views, g.Intents[0].Views, "the signed view was not wiped")
}

// The restart loader validates the persisted anti-equivocation record in full, not only its syntax: any inconsistency refuses to start the
// member (nothing is silently dropped, so a signed view is never forgotten and signing never resumes over an untrusted record).
func TestAnInconsistentMemberFileRefusesToStart(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	joiner := w.Members[5]
	good := readFile(t, s.paths[joiner.Root])
	require.Equal(t, 1, good.Version)

	load := func(mutate func(f *memberFile)) error {
		raw, err := json.Marshal(good)
		require.NoError(t, err)
		var f memberFile
		require.NoError(t, json.Unmarshal(raw, &f)) // a deep copy
		mutate(&f)
		out, err := json.Marshal(f)
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "m.json")
		require.NoError(t, os.WriteFile(path, out, 0o600))
		_, err = NewMember(NewService(ServiceConfig{}), MemberConfig{Self: joiner.Root, RootSigner: joiner.RK.Signer, Path: path})
		return err
	}
	require.NoError(t, load(func(*memberFile) {}), "the genuine record loads")
	for name, mut := range map[string]func(f *memberFile){
		"a version that is not this format's":     func(f *memberFile) { f.Version = 7 },
		"the outer view not the readiness's":      func(f *memberFile) { f.Intents[0].Views[0].View = 123 },
		"a candidate digest of another candidate": func(f *memberFile) { f.Intents[0].Views[0].CandidateDigest = hex.EncodeToString(make([]byte, 32)) },
		"a readiness that is not hex":             func(f *memberFile) { f.Intents[0].Views[0].Readiness = "zz" },
		"an empty readiness":                      func(f *memberFile) { f.Intents[0].Views[0].Readiness = "" },
		"a readiness of another intent": func(f *memberFile) {
			f.Intents[0].Intent = hex.EncodeToString(make([]byte, 32))
		},
		"a non-canonical intent id":       func(f *memberFile) { f.Intents[0].Intent = strings.ToUpper(f.Intents[0].Intent) },
		"a short intent id":               func(f *memberFile) { f.Intents[0].Intent = f.Intents[0].Intent[:10] },
		"a view recorded twice":           func(f *memberFile) { f.Intents[0].Views = append(f.Intents[0].Views, f.Intents[0].Views[0]) },
		"an intent recorded twice":        func(f *memberFile) { f.Intents = append(f.Intents, f.Intents[0]) },
		"a possession proof of no intent": func(f *memberFile) { f.Intents[0].PoP = "00" },
	} {
		require.ErrorIs(t, load(mut), ErrMember, name)
	}
	// a readiness signed by another root key is not this node's record
	other := readFile(t, s.paths[w.Members[1].Root])
	require.ErrorIs(t, load(func(f *memberFile) { f.Intents[0].Views[0].Readiness = other.Intents[0].Views[0].Readiness }), ErrMember, "another node's readiness")
}

// When the readiness cannot be persisted nothing is released: no message, nothing in the member's own service.
func TestAPersistFailureReleasesNothing(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	self := w.Members[5]
	var sent []Message
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: self.EK.Signer, Path: filepath.Join(dir, "m.json"),
		Send: func(msg Message) { sent = append(sent, msg) }, Supports: func(vrschema.Activation) bool { return true }})
	require.NoError(t, err)
	svc.Update(w.committed(0))
	pops := w.PoPs(w.in)
	for i := range pops {
		_, _, _ = svc.Offer("peer", Message{PoP: &pops[i]})
	}
	a := w.Assembly(w.in, w.d, 0, pops)
	_, _, _ = svc.Offer("peer", Message{Assembly: &a})
	require.NoError(t, os.Chmod(dir, 0o500)) // the state can no longer be written
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	require.Error(t, m.Step())
	for _, msg := range sent {
		require.Nil(t, msg.Readiness)
	}
	set, _ := svc.Stage(w.d, 0)
	require.Empty(t, set.Readiness, "not even the member's own service holds a readiness")
}

// A validly signed assembly of a view that is not committed yet is buffered and never signed; it is signed once its view commits.
func TestAMemberDoesNotSignAnUncommittedView(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	path := filepath.Join(t.TempDir(), "m.json")
	var sent []Message
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: self.EK.Signer, Path: path, Send: func(msg Message) { sent = append(sent, msg) }})
	require.NoError(t, err)
	svc.Update(w.committed(0))
	pops := w.PoPs(w.in)
	for i := range pops {
		_, _, _ = svc.Offer("peer", Message{PoP: &pops[i]})
	}
	a1 := w.Assembly(w.in, w.d, 1, pops)
	o, _, _ := svc.Offer("peer", Message{Assembly: &a1})
	require.Equal(t, Buffered, o)
	require.NoError(t, m.Step())
	for _, msg := range sent {
		require.Nil(t, msg.Readiness, "no readiness for an uncommitted view")
	}
	require.Empty(t, readFile(t, path).Intents[0].Views)
	svc.Update(w.committed(1))
	require.NoError(t, m.Step())
	views := readFile(t, path).Intents[0].Views
	require.Len(t, views, 1)
	require.EqualValues(t, 1, views[0].View)
}

// A node that learns the certificate's assembly only after the Prepare commits (it restarted, or joined late) still stages it, once.
func TestAMemberStagesAfterThePrepareCommits(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	joiner := w.Members[5].Root
	donor, _ := s.svcs[w.Members[1].Root].Stage(w.d, 0)

	var staged int
	x := w.Members[5]
	svc := NewService(ServiceConfig{Self: joiner, Signer: x.RK.Signer})
	m, err := NewMember(svc, MemberConfig{Self: joiner, RootSigner: x.RK.Signer, EVMSigner: x.EK.Signer, Path: s.paths[joiner],
		Stage: func(Staged) error { staged++; return nil }})
	require.NoError(t, err)
	svc.Update(w.committed(0))
	for _, msg := range donor.Offers() {
		_, _, _ = svc.Offer("peer", msg)
	}
	c := w.committed(0)
	c.Prepared = true
	svc.Update(c)
	require.NoError(t, m.Step())
	require.NoError(t, m.Step())
	require.Equal(t, 1, staged, "staged once, after the Prepare")
}

// A signed view whose assembly the service now holds differently is not signed again; its readiness is still sent to the peers, and it is
// logged. A view is never lost to the retention of other intents: only intents of an older (epoch, attempt) go.
func TestAMemberResendsItsSignedReadinessAndKeepsItsIntents(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	joiner := w.Members[5].Root
	f := readFile(t, s.paths[joiner])
	signed := f.Intents[0].Views[0].Readiness
	set, _ := s.svcs[w.Members[1].Root].Stage(w.d, 0)
	s.start(t, joiner, s.paths[joiner], true)
	s.svcs[joiner].Update(w.committed(0))
	for _, m := range set.Offers() {
		if m.Readiness == nil {
			_, _, _ = s.svcs[joiner].Offer("peer", m)
		}
	}
	tamperAssembly(s.svcs[joiner], 0)
	s.bus = nil
	require.NoError(t, s.members[joiner].Step())
	require.Empty(t, s.bus, "a different assembly is not signed, and nothing is sent for it")
	_ = signed
	require.Equal(t, f, readFile(t, s.paths[joiner]), "and nothing new is signed")

	m := s.members[joiner]
	m.mu.Lock()
	defer m.mu.Unlock()
	d1, d2, d3, d4 := [32]byte{1}, [32]byte{2}, [32]byte{3}, [32]byte{4}
	m.file = memberFile{}
	m.intent(d1, 1, 0)
	m.intent(d2, 1, 0) // the same attempt: both are kept
	require.Len(t, m.file.Intents, 2)
	m.intent(d3, 1, 1) // a later attempt: the older ones go
	require.Len(t, m.file.Intents, 1)
	m.intent(d4, 1, 1)
	m.intent(d1, 1, 0) // an intent of an older attempt that comes back: not kept beside the current ones, but the current stay
	require.GreaterOrEqual(t, len(m.file.Intents), 2)
}

func (w *world) byRoot(id string) vrhandofffix.Member {
	for _, m := range w.Members {
		if m.Root == id {
			return m
		}
	}
	w.T.Fatalf("no member %s", id)
	return vrhandofffix.Member{}
}

// tamperAssembly makes the service hold another assembly of a view (a different candidate), as if its assembler had equivocated: the held
// assembly's candidate bytes change, so its digest is no longer the one the member signed.
func tamperAssembly(svc *Service, view uint64) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	vs := svc.cur.views[view]
	a := *vs.assembly
	a.Candidate = append(append([]byte(nil), a.Candidate...), 0)
	vs.assembly = &a
}

// The sign/persist/send step is atomic against a committed-state update: when the committed view advances, the intent dies or a Prepare
// commits between the member's snapshot and its signature (here, inside its support policy, called while it builds the readiness), nothing
// is signed, persisted or sent over the old state.
func TestACommittedStateChangeDuringSigningReleasesNothing(t *testing.T) {
	for name, change := range map[string]func(w *world, svc *Service){
		"the view advances": func(w *world, svc *Service) { svc.Update(w.committed(1)) },
		"the intent dies":   func(w *world, svc *Service) { svc.Update(Committed{}) },
		"a Prepare commits": func(w *world, svc *Service) { c := w.committed(0); c.Prepared = true; svc.Update(c) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			self := w.Members[5]
			path := filepath.Join(t.TempDir(), "m.json")
			var sent []Message
			svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
			rule := vrschema.Activation{RuleID: vrschema.RuleID("rule-a"), ReleaseDigest: vrschema.Word{0xaa}, RootEpoch: 2, State: vrschema.ActActive, ChangeID: 1}
			fired := false
			m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: self.EK.Signer, Path: path,
				Send: func(msg Message) { sent = append(sent, msg) },
				Supports: func(vrschema.Activation) bool {
					if !fired { // called after the snapshot, before the signature
						fired = true
						change(w, svc)
					}
					return true
				}})
			require.NoError(t, err)
			c := w.committed(0)
			c.Schedule = []vrschema.Activation{rule}
			svc.Update(c)
			pops := w.PoPs(w.in)
			for i := range pops {
				_, _, _ = svc.Offer("peer", Message{PoP: &pops[i]})
			}
			a := w.Assembly(w.in, w.d, 0, pops)
			_, _, _ = svc.Offer("peer", Message{Assembly: &a})
			require.NoError(t, m.Step())
			require.True(t, fired)
			for _, msg := range sent {
				require.Nil(t, msg.Readiness, "no readiness over the state that moved on")
			}
			if f, err := os.ReadFile(path); err == nil {
				var mf memberFile
				require.NoError(t, json.Unmarshal(f, &mf))
				for _, mi := range mf.Intents {
					require.Empty(t, mi.Views, "no signed view was persisted")
				}
			}
			set, _ := svc.Stage(w.d, 0)
			require.Empty(t, set.Readiness)
		})
	}
}

// A message the member's own service did not admit is never sent: here the service refuses to take the node's proof (its allowance is spent).
func TestAMessageTheLocalServiceDroppedIsNotSent(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	var sent []Message
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: self.EK.Signer, Send: func(msg Message) { sent = append(sent, msg) }})
	require.NoError(t, err)
	svc.Update(w.committed(0))
	svc.mu.Lock()
	svc.cur.popRefused[popKey(self.Root, self.EVM)] = MaxReplacements + 1
	svc.mu.Unlock()
	err = m.Step()
	require.ErrorIs(t, err, ErrMember)
	require.Empty(t, sent, "a dropped offer is not sent")
}

// A K member that is no successor and signs its support only after the successors' certificate is complete still gets it to every root: the
// exchange stays open while the Prepare plan waits for the K weight (here the leaver carries 3 of 6 K weight, so the three staying members'
// 3 do not make more than 2/3).
func TestALateKMemberSupportReachesTheRootsAfterTheCertificate(t *testing.T) {
	w := newWorld(t)
	w.K[3].Weight, w.K[3].RawWeight = 3, 3 // the leaver (identity 4) carries 3 of 6
	rule := vrschema.Activation{RuleID: vrschema.RuleID("rule-a"), ReleaseDigest: vrschema.Word{0xaa}, RootEpoch: 2, State: vrschema.ActActive, ChangeID: 1}
	s := w.swarm(t, []vrschema.Activation{rule})
	leaver := w.Members[4].Root
	late := s.members[leaver]
	delete(s.members, leaver) // the leaver is slow: it does not step at first
	s.update(0)
	s.run(t)
	for id, svc := range s.svcs {
		_, _, complete, _ := svc.Current()
		require.True(t, complete, "%s: the successors' certificate is complete", id)
		_, ready := svc.Plan()
		require.False(t, ready, "%s: the plan still waits for K support", id)
	}
	s.members[leaver] = late
	s.bus = nil
	require.NoError(t, late.Step())
	t.Logf("leaver bus after one step: %d, kready held by leaver: %d", len(s.bus), len(func() []vrhandoff.Readiness { set, _ := s.svcs[leaver].Stage(w.d, 0); return set.Readiness }()))
	s.run(t)
	for id, svc := range s.svcs {
		_, ready := svc.Plan()
		require.True(t, ready, "%s: the late K support arrived although the certificate was complete", id)
	}
}

// A saved readiness is verified in full under the current committed state before it is admitted or sent: one signed under another support
// basis (a rule scheduled since) and one whose receipt bytes were altered (the envelope omits them) are neither admitted nor sent.
func TestASavedReadinessIsVerifiedUnderTheCurrentState(t *testing.T) {
	w := newWorld(t)
	s := w.swarm(t, nil)
	s.update(0)
	s.run(t)
	joiner := w.Members[5]
	donor, _ := s.svcs[w.Members[1].Root].Stage(w.d, 0)

	restart := func(t *testing.T, path string, sch []vrschema.Activation) (*Member, *Service, *[]Message) {
		var sent []Message
		svc := NewService(ServiceConfig{Self: joiner.Root, Signer: joiner.RK.Signer})
		m, err := NewMember(svc, MemberConfig{Self: joiner.Root, RootSigner: joiner.RK.Signer, EVMSigner: joiner.EK.Signer, EVMNodeID: joiner.EVM, Path: path,
			Send: func(msg Message) { sent = append(sent, msg) }, Supports: func(vrschema.Activation) bool { return true }})
		require.NoError(t, err)
		c := w.committed(0)
		c.Schedule = sch
		svc.Update(c)
		for _, msg := range donor.Offers() {
			if msg.Readiness == nil || msg.Readiness.Slot != 0 {
				_, _, _ = svc.Offer("peer", msg)
			} else if enc, _ := msg.Readiness.Encode(); enc != nil {
				// the donor's readiness of other members is offered; this node's own comes from its file
				if _, err := vrschema.ReadinessReceipt(msg.Readiness.Receipt, joiner.Root); err != nil {
					_, _, _ = svc.Offer("peer", msg)
				}
			}
		}
		return m, svc, &sent
	}
	copyFile := func(t *testing.T) string {
		raw, err := os.ReadFile(s.paths[joiner.Root])
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "m.json")
		require.NoError(t, os.WriteFile(path, raw, 0o600))
		return path
	}

	t.Run("a support basis that changed since it was signed", func(t *testing.T) {
		rule := vrschema.Activation{RuleID: vrschema.RuleID("rule-a"), ReleaseDigest: vrschema.Word{0xaa}, RootEpoch: 2, State: vrschema.ActActive, ChangeID: 1}
		m, svc, sent := restart(t, copyFile(t), []vrschema.Activation{rule})
		require.NoError(t, m.Step())
		for _, msg := range *sent {
			require.Nil(t, msg.Readiness, "a readiness that lacks the support the current schedule needs is not sent")
		}
		set, _ := svc.Stage(w.d, 0)
		for _, r := range set.Readiness {
			_, err := vrschema.ReadinessReceipt(r.Receipt, joiner.Root)
			require.Error(t, err, "nor admitted into the node's own service")
		}
	})
	t.Run("altered receipt bytes", func(t *testing.T) {
		path := copyFile(t)
		f := readFile(t, path)
		raw, err := hex.DecodeString(f.Intents[0].Views[0].Readiness)
		require.NoError(t, err)
		r, err := vrschema.DecodeReadiness(raw)
		require.NoError(t, err)
		r.Receipt = append([]byte(nil), r.Receipt...)
		r.Receipt[len(r.Receipt)-1] ^= 1 // the receipt's last byte (inside its signature)
		enc, err := r.Encode()
		require.NoError(t, err)
		f.Intents[0].Views[0].Readiness = hex.EncodeToString(enc)
		out, err := json.Marshal(f)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, out, 0o600))
		m, svc, sent := restart(t, path, nil) // the envelope omits the receipt: the file loads
		require.NoError(t, m.Step())
		for _, msg := range *sent {
			require.Nil(t, msg.Readiness)
		}
		set, _ := svc.Stage(w.d, 0)
		for _, rr := range set.Readiness {
			_, err := vrschema.ReadinessReceipt(rr.Receipt, joiner.Root)
			require.Error(t, err)
		}
	})
}

// A versionless empty object and a JSON null are not an empty signing history: an existing file must carry the format's version.
func TestAnEmptyOrNullMemberFileRefusesToStart(t *testing.T) {
	w := newWorld(t)
	for _, content := range []string{"{}", "null", `{"intents":[]}`} {
		path := filepath.Join(t.TempDir(), "m.json")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		_, err := NewMember(NewService(ServiceConfig{}), MemberConfig{Self: "x", RootSigner: w.Members[1].RK.Signer, Path: path})
		require.ErrorIs(t, err, ErrMember, content)
	}
	path := filepath.Join(t.TempDir(), "m.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"intents":[]}`), 0o600))
	_, err := NewMember(NewService(ServiceConfig{}), MemberConfig{Self: "x", RootSigner: w.Members[1].RK.Signer, Path: path})
	require.NoError(t, err)
}

// A record holding the bound of intents that may still revive takes no new intent, and the member signs nothing new (it never evicts one).
func TestAFullMemberFileSignsNothingNew(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMSigner: self.EK.Signer})
	require.NoError(t, err)
	m.mu.Lock()
	for i := 0; i < memberMaxIntents; i++ {
		m.file.Intents = append(m.file.Intents, memberIntent{Intent: hex.EncodeToString(bytesOf(byte(i + 1))), Epoch: 5, Attempt: 5})
	}
	m.mu.Unlock()
	svc.Update(w.committed(0))
	require.ErrorIs(t, m.Step(), ErrMember)
}

func bytesOf(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
