package vrschedule

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The root side of the staged handoff protocol (design sections 5.3.1 to 5.3.4): for the intent derived over the committed state it keeps
// the sticky possession proofs, the assembly and the successors' readiness of the committed current view and the three before it, assembles
// as its view's assembler, retains the first complete verified certificate (I-RET), and plans the Prepare. Messages for a view up to two
// ahead, or for an intent not derived here yet, are buffered per sender and re-judged when they become judgeable; nothing in the service
// ever advances a view (only committed HandoffViews do).
//
// Every signature check runs outside the service's lock: a message's own verification (Job.Verify), the re-judgment of buffered messages
// (handed back to the verification queue, or verified off the lock without one), this root's assembly and the I-RET certificate check. The
// lock guards only classification and admission, so the consensus loop's Plan and Prepared never wait on protocol work.
//
// Equivocation is bounded (design 5.3.4, review #1188 B1): per view, at most one assembly and one readiness per member are retained, and
// the first verified conflict of a signer is its one evidence record; every later message of that signer in that view is dropped unverified.
// Evidence lives with its view and goes with the retention window or the intent.

// Retention and buffering bounds (design 5.3.3, 5.3.4; schema constants).
const (
	RetainedViews   = 4 // the committed current view and the 3 previous ones
	BufferAhead     = 2 // views ahead of the committed current view that are buffered
	BufferPerPeer   = 64
	MaxReplacements = 1 // per sender and view (per sender and member for a proof), after a failed verification
	// PendingExpiry is how many committed root blocks a message for an intent not derived here is kept: long enough for a lagging root to
	// derive the next intent, short enough that a bogus or dead digest frees its sender's buffer.
	PendingExpiry = 64
	// DeadIntents is how many recently dead intents are remembered: their late messages are dropped outright.
	DeadIntents = 8
)

// Message is one protocol message (stages 2 to 4).
type Message struct {
	PoP       *vrhandoff.PoPOffer
	Assembly  *vrhandoff.Assembly
	Readiness *vrhandoff.Readiness
}

func (m Message) intentDigest() []byte {
	switch {
	case m.PoP != nil:
		return m.PoP.IntentDigest
	case m.Assembly != nil:
		return m.Assembly.IntentDigest
	case m.Readiness != nil:
		return m.Readiness.IntentDigest
	}
	return nil
}

func (m Message) view() (uint64, bool) {
	switch {
	case m.Assembly != nil:
		return m.Assembly.Slot, true
	case m.Readiness != nil:
		return m.Readiness.Slot, true
	}
	return 0, false
}

// formatBound is the cost bound a message is held to before anything is buffered or verified: a readiness carries at most one commitment
// per rule the support table can hold (SupportRules), which bounds its signature checks and its size (review #1188 B1, B4, B12).
func formatBound(m Message) error {
	if m.Readiness != nil && len(m.Readiness.Commitments) > vrschema.SupportRules {
		return fmt.Errorf("vrschedule: a readiness with %d commitments (at most %d)", len(m.Readiness.Commitments), vrschema.SupportRules)
	}
	return nil
}

// Committed is what the service learns from one committed root block: the intent derived over it (Derivable false when none is), the
// committed current view of that intent (0 until a HandoffView binds it), whether a Prepare of its attempt is committed, the incumbents
// (node id to root key), the acknowledged committee K, the committed support table and schedule.
type Committed struct {
	Derived       Derived
	Derivable     bool
	CommittedView uint64
	Prepared      bool
	Incumbents    map[string][]byte
	K             []evmassign.Identity
	Table         vradmit.SupportTable
	Schedule      []vrschema.Activation
	// FrozenParent and FrozenRoot are the frozen EVM parent a committed Prepare bound and its certified state root (zero otherwise): the
	// Freeze witness is fetched there in the background.
	FrozenParent, FrozenRoot [32]byte
}

// Outcome is how one offered message was judged.
type Outcome int

const (
	Retained    Outcome = iota // verified and kept
	Duplicate                  // the same message, or another valid proof of a member that already has one (sticky)
	Buffered                   // for a future view or an intent not derived here yet
	Dropped                    // stale, out of bounds, not this root's to judge, or admitted no further
	Refused                    // failed verification (format, signature, semantics): a replacement may follow
	Equivocated                // a signed conflict in one view: evidence, no replacement
)

func (o Outcome) String() string {
	return [...]string{"retained", "duplicate", "buffered", "dropped", "refused", "equivocated"}[o]
}

// Equivocation is the evidence of two conflicting signed messages of one signer in one view.
type Equivocation struct {
	Signer      string
	View        uint64
	First, Next []byte
}

// StageSet is what a root serves a restarted peer (GetStage): every retained message of the intent from a view on.
type StageSet struct {
	PoPs       []vrhandoff.PoPOffer
	Assemblies []vrhandoff.Assembly
	Readiness  []vrhandoff.Readiness
}

// ServiceConfig is one root's protocol participation.
type ServiceConfig struct {
	Self   string          // this root's node id
	Signer abcrypto.Signer // its root key: the assembly
	// Send hands an outbound message (this root's assembly) to the transport, never under the service's lock; nil sends nothing.
	Send func(Message)
	Log  *slog.Logger
}

type viewState struct {
	assembly   *vrhandoff.Assembly
	assemblyAt []byte // the assembly's encoding (conflict evidence)
	body       q3format.BodyV3
	candidate  [32]byte // the held assembly's candidate digest and body identity: what its readiness names
	bodyID     [32]byte
	readiness  map[string]vrhandoff.Readiness
	// kready is the readiness of K members that are not successors (design 5.3.1 stage 4: support only), by root node id; it never counts toward
	// completeness and carries the support commitments the K-support gate (7.3 b) reads from this intent's K-member readiness
	kready    map[string]vrhandoff.Readiness
	encodings map[string][]byte
	refused   map[string]int // replacements spent by sender
	// supportWait counts readiness refused by sender only for lacking the support the gate needs: bounded like refused, and reset when the
	// support basis changes (the same readiness may then be admitted)
	supportWait map[string]int
	evidence    map[string]Equivocation // the one conflict of each equivocating signer in this view
	tried       bool                    // the complete set was checked as a certificate
}

type intentState struct {
	d          Derived
	digest     [32]byte
	order      []string
	incumbents map[string][]byte
	successors []evmassign.Identity
	byRoot     map[string]evmassign.Identity
	byEVM      map[string]evmassign.Identity
	kOnly      map[string]evmassign.Identity // K members that are not successors, by root node id
	trustBase  []byte
	pops       map[string]vrhandoff.PoPOffer
	popRefused map[string]int // failed proofs by sender and successor
	view       uint64
	prepared   bool
	views      map[uint64]*viewState
	iret       *PreparePlan
	assembled  map[uint64]bool
	basis      [32]byte // the committed schedule and support table the intent's verdicts were judged under
}

type bufItem struct {
	m  Message
	at uint64 // the update it was buffered at
}

// Service is one root's protocol state (design 5.3.4).
type Service struct {
	cfg ServiceConfig
	mu  sync.Mutex
	cur *intentState
	k   []evmassign.Identity
	tab vradmit.SupportTable
	sch []vrschema.Activation
	// buffered messages by sender (at most BufferPerPeer each): for a future view of the current intent, or for an intent not derived
	// here yet (kept PendingExpiry updates)
	buffered map[string][]bufItem
	dead     [][32]byte
	updates  uint64
	lastSeat map[string]bool
	// requeue hands a buffered message that became judgeable back to the verification queue (set by NewQueue); false when the queue does not
	// admit it, and the message stays buffered
	requeue func(sender string, m Message) bool
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{cfg: cfg, buffered: map[string][]bufItem{}, lastSeat: map[string]bool{}}
}

func (s *Service) log() *slog.Logger {
	if s.cfg.Log != nil {
		return s.cfg.Log
	}
	return slog.New(slog.DiscardHandler)
}

// followUp is the work a state change makes judgeable, done after the lock is released: buffered messages to re-judge, this root's
// assembly to make, a complete set to check as a certificate.
type followUp struct {
	pend    []queued
	asm     *assemblyTask
	cert    *certTask
	requeue func(string, Message) bool
}

func (f *followUp) merge(g followUp) {
	f.pend = append(f.pend, g.pend...)
	if g.asm != nil {
		f.asm = g.asm
	}
	if g.cert != nil {
		f.cert = g.cert
	}
}

func (f followUp) empty() bool { return len(f.pend) == 0 && f.asm == nil && f.cert == nil }

// Update applies one committed root block. A changed or underivable intent kills the current one (stage 0 restarts); a newly committed
// view prunes the retention window and re-judges the buffered messages. It returns the messages this root sends (its assembly).
func (s *Service) Update(c Committed) []Message {
	s.mu.Lock()
	f := s.updateLocked(c)
	s.mu.Unlock()
	return s.finish(f)
}

// send hands this root's own messages to the transport, outside the service's lock (the transport reads the service's members).
func (s *Service) send(out []Message) {
	if s.cfg.Send == nil {
		return
	}
	for _, m := range out {
		s.cfg.Send(m)
	}
}

func (s *Service) markDead(d [32]byte) {
	s.log().Info("VR handoff: the intent died", "intent", fmt.Sprintf("%x", d[:8]))
	s.dead = append(s.dead, d)
	if len(s.dead) > DeadIntents {
		s.dead = s.dead[len(s.dead)-DeadIntents:]
	}
}

func (s *Service) isDead(d []byte) bool {
	for _, x := range s.dead {
		if bytes.Equal(x[:], d) {
			return true
		}
	}
	return false
}

func (s *Service) updateLocked(c Committed) followUp {
	s.updates++
	s.k, s.tab, s.sch = c.K, c.Table, c.Schedule
	defer s.pruneBuffered()
	if !c.Derivable {
		if s.cur != nil {
			s.markDead(s.cur.digest)
		}
		s.cur = nil
		return followUp{}
	}
	basis := supportBasis(c.Schedule, c.Table)
	if s.cur != nil && s.cur.digest == c.Derived.Digest && s.cur.basis != basis {
		s.rebaseLocked(s.cur, basis)
	}
	if s.cur == nil || s.cur.digest != c.Derived.Digest {
		if s.cur != nil {
			s.markDead(s.cur.digest)
		}
		st, err := newIntentState(c)
		if err != nil {
			s.log().Warn("VR handoff: the derived intent cannot be staged", "error", err)
			s.cur = nil
			return followUp{}
		}
		st.basis = basis
		s.cur = st
		s.lastSeat = map[string]bool{}
		for i, d := range s.dead {
			if d == st.digest {
				s.dead = append(s.dead[:i:i], s.dead[i+1:]...)
				break
			}
		}
		s.log().Info("VR handoff: intent", "intent", fmt.Sprintf("%x", st.digest[:8]), "attempt", st.d.Intent.Attempt, "anchorRound", st.d.Intent.AnchorRound,
			"assembler0", vrschema.Assembler(st.order, 0))
	}
	st := s.cur
	st.prepared = c.Prepared
	if c.CommittedView > st.view {
		st.view = c.CommittedView
	}
	for v := range st.views {
		if v+RetainedViews <= st.view {
			delete(st.views, v)
		}
	}
	return s.followLocked()
}

// pruneBuffered drops buffered messages of dead intents, and those for an intent not derived here that have waited PendingExpiry updates
// (review #1188 B2: no digest, bogus or dead, holds a sender's buffer for long).
func (s *Service) pruneBuffered() {
	for sender, q := range s.buffered {
		kept := q[:0]
		for _, it := range q {
			d := it.m.intentDigest()
			current := s.cur != nil && bytes.Equal(d, s.cur.digest[:])
			if current || (!s.isDead(d) && s.updates-it.at <= PendingExpiry) {
				kept = append(kept, it)
			}
		}
		if s.buffered[sender] = kept; len(kept) == 0 {
			delete(s.buffered, sender)
		}
	}
}

// rebaseLocked carries a live intent over a change of the committed support table or schedule (astra review of #1188, P1): a RuleSupport
// control adds or replaces table entries under a live intent, which stays the same intent. Everything intent-bound stays (the sticky proofs,
// the assemblies, every retained readiness, the evidence, the replacement accounting); only the verdicts that rest on the support basis are
// judged again: the held certificate is kept unless gate (a) of 7.3 no longer holds for one of its successors under the new basis, the
// complete sets of the retained views are checked again, and readiness refused only for missing support may be sent again. Gate (b) is
// Plan's, judged on every call.
func (s *Service) rebaseLocked(st *intentState, basis [32]byte) {
	st.basis = basis
	for _, vs := range st.views {
		vs.tried = false
		vs.supportWait = map[string]int{}
	}
	if st.iret == nil {
		return
	}
	for i, r := range st.iret.Certificate.Readiness {
		if i >= len(st.successors) {
			break
		}
		if err := vradmit.VerifySuccessorSupport(s.sch, st.d.RootEpoch+1, st.d.Intent.Network, s.tab, st.successors[i], r.Commitments); err != nil {
			s.log().Warn("VR handoff: the held certificate lacks support the changed basis requires; a later complete set may replace it",
				"intent", fmt.Sprintf("%x", st.digest[:8]), "error", err)
			st.iret = nil
			return
		}
	}
}

// supportBasis is the digest of the committed schedule and support table.
func supportBasis(sch []vrschema.Activation, tab vradmit.SupportTable) [32]byte {
	b, err := types.Cbor.Marshal([]any{sch, tab.Entries})
	if err != nil {
		return [32]byte{0xff} // the verdicts are judged again
	}
	return sha256.Sum256(b)
}

func newIntentState(c Committed) (*intentState, error) {
	cand, err := vrhandoff.CandidateOf(c.Derived.Intent)
	if err != nil {
		return nil, err
	}
	_, tb, err := vrhandoff.TrustBase(c.Derived.Intent, c.Derived.RootEpoch)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(c.Incumbents))
	for id := range c.Incumbents {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("no incumbents")
	}
	st := &intentState{d: c.Derived, digest: c.Derived.Digest, order: vrhandoff.AssemblerOrder(c.Derived.Digest, ids), incumbents: c.Incumbents,
		successors: cand.Identities, byRoot: map[string]evmassign.Identity{}, byEVM: map[string]evmassign.Identity{}, trustBase: tb,
		pops: map[string]vrhandoff.PoPOffer{}, popRefused: map[string]int{}, views: map[uint64]*viewState{}, assembled: map[uint64]bool{}}
	for _, m := range cand.Identities {
		st.byRoot[m.RootNodeID], st.byEVM[m.EVMNodeID] = m, m
	}
	st.kOnly = map[string]evmassign.Identity{}
	for _, m := range c.K {
		if _, succ := st.byRoot[m.RootNodeID]; !succ {
			st.kOnly[m.RootNodeID] = m
		}
	}
	return st, nil
}

// Offer judges one message from sender (a peer's node id, or this root's own): classification under the lock, verification off it, then
// admission. Admission (which peers may send at all) is the transport's; the verification queue (Queue) uses Prepare and Apply.
func (s *Service) Offer(sender string, m Message) (Outcome, []Message, error) {
	o, err, f := s.offer(sender, m)
	return o, s.finish(f), err
}

func (s *Service) offer(sender string, m Message) (Outcome, error, followUp) {
	j := s.Prepare(sender, m)
	if j.Verify == nil {
		return j.Outcome, j.Err, followUp{}
	}
	return s.apply(j, j.Verify())
}

// Job is one admitted message's verification, split so it runs without the service's lock (the verification service, design 5.3.4): Verify
// is pure over a snapshot of the state it was prepared against; Apply admits its result. A Job with a nil Verify is already judged.
type Job struct {
	Outcome Outcome
	Err     error
	Verify  func() error
	sender  string
	msg     Message
	st      *intentState     // the intent state it was prepared against: a revived intent of the same digest is another state
	body    *q3format.BodyV3 // an assembly's derived body
	// conflict: the job verifies a second, different message of a signer that already has one retained in the view (equivocation
	// evidence if it verifies)
	conflict bool
}

// Prepare classifies a message under the lock: stale, buffered, duplicate, out of bounds or already equivocated is judged here; anything
// else gets its pure verification over a snapshot.
func (s *Service) Prepare(sender string, m Message) Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prepareLocked(sender, m)
}

func (s *Service) prepareLocked(sender string, m Message) Job {
	d := m.intentDigest()
	st := s.cur
	j := Job{sender: sender, msg: m}
	if len(d) != 32 {
		j.Outcome, j.Err = Dropped, errors.New("vrschedule: a message without an intent")
		return j
	}
	if err := formatBound(m); err != nil {
		j.Outcome, j.Err = Dropped, err
		return j
	}
	if st == nil || !bytes.Equal(d, st.digest[:]) {
		// another intent: a dead one is dropped; one not derived here yet is buffered within the sender's own quota and expires
		if s.isDead(d) {
			j.Outcome = Dropped
			return j
		}
		j.Outcome = s.buffer(sender, m)
		return j
	}
	j.st = st
	if v, ok := m.view(); ok {
		if v > st.view+BufferAhead || v+RetainedViews <= st.view {
			j.Outcome = Dropped
			return j
		}
		if v > st.view {
			j.Outcome = s.buffer(sender, m)
			return j
		}
	}
	in := st.d.Intent
	switch {
	case m.PoP != nil:
		p := *m.PoP
		if _, ok := st.byEVM[p.EVMNodeID]; !ok {
			j.Outcome, j.Err = Dropped, fmt.Errorf("vrschedule: %s is not a successor validator", p.EVMNodeID)
			return j
		}
		if _, have := st.pops[p.EVMNodeID]; have {
			j.Outcome = Duplicate // sticky: the first verified proof is kept; another valid encoding is not a conflict
			return j
		}
		if st.popRefused[popKey(sender, p.EVMNodeID)] > MaxReplacements {
			j.Outcome = Dropped
			return j
		}
		j.Verify = func() error { return vrhandoff.VerifyPoP(in, p) }
	case m.Assembly != nil:
		a := *m.Assembly
		vs := st.viewOf(a.Slot)
		if vs.refused[sender] > MaxReplacements {
			j.Outcome = Dropped
			return j
		}
		incumbents := st.incumbents
		if vs.assembly != nil {
			enc, err := encodeAssembly(a)
			if err == nil && bytes.Equal(enc, vs.assemblyAt) {
				j.Outcome = Duplicate
				return j
			}
			if _, eq := vs.evidence[vrschema.Assembler(st.order, a.Slot)]; eq {
				j.Outcome = Dropped // the assembler equivocated in this view: nothing more of it is verified
				return j
			}
			// a conflict needs only its signature to be evidence
			j.conflict = true
			j.Verify = func() error { return vrhandoff.VerifyAssemblySig(a, incumbents) }
			return j
		}
		epoch, bc := st.d.RootEpoch, st.d.Body
		j.body = &q3format.BodyV3{}
		out := j.body
		j.Verify = func() error {
			if err := vrhandoff.VerifyAssemblySig(a, incumbents); err != nil {
				return err
			}
			if _, err := vrhandoff.VerifyAssembly(in, a); err != nil {
				return err
			}
			b, err := vrhandoff.DeriveBody(in, epoch, sha256.Sum256(a.Candidate), bc)
			*out = b
			return err
		}
	case m.Readiness != nil:
		r := *m.Readiness
		vs := st.viewOf(r.Slot)
		member, kOnly, ok := s.readinessBy(st, r)
		if !ok {
			j.Outcome, j.Err = Dropped, errors.New("vrschedule: readiness of no successor or K member")
			return j
		}
		enc, err := r.Encode()
		if err != nil {
			j.Outcome, j.Err = s.refuse(vs, sender, err)
			return j
		}
		prev, have := vs.encodings[member.RootNodeID]
		if have && bytes.Equal(prev, enc) {
			j.Outcome = Duplicate
			return j
		}
		if vs.assembly == nil {
			j.Outcome = s.buffer(sender, m) // verified once the view's assembly is held
			return j
		}
		if vs.refused[sender] > MaxReplacements || vs.supportWait[sender] > MaxReplacements {
			j.Outcome = Dropped
			return j
		}
		// a readiness for another assembly of the view is not this root's to judge (the assembler equivocated, or roots hold different
		// assemblies): dropped, and its sender keeps its seat and allowance (review #1188 B6)
		if !bytes.Equal(r.CandidateDigest, vs.candidate[:]) || !bytes.Equal(r.BodyID, vs.bodyID[:]) {
			j.Outcome, j.Err = Dropped, errors.New("vrschedule: a readiness of another assembly of the view")
			return j
		}
		a, body, tb := *vs.assembly, vs.body, st.trustBase
		if have {
			if _, eq := vs.evidence[member.RootNodeID]; eq {
				j.Outcome = Dropped // the member equivocated in this view: nothing more of it is verified
				return j
			}
			j.conflict = true
			j.Verify = func() error { return vrhandoff.VerifyReadiness(in, a, body, member, tb, r) }
			return j
		}
		sch, tab, epoch := s.sch, s.tab, st.d.RootEpoch
		if kOnly {
			// a K member that is no successor sends readiness for rule support only (design 5.3.1 stage 4, 7.3): the same verification of its
			// envelope, receipt and commitments, the commitments' scope, and at least one commitment (there is nothing else it could support)
			j.Verify = func() error {
				if len(r.Commitments) == 0 {
					return errors.New("vrschedule: a K member's readiness without a support commitment")
				}
				if err := vrhandoff.VerifyReadiness(in, a, body, member, tb, r); err != nil {
					return err
				}
				return vradmit.CommitmentsInScope(sch, in.Network, r.Commitments)
			}
			return j
		}
		j.Verify = func() error {
			if err := vrhandoff.VerifyReadiness(in, a, body, member, tb, r); err != nil {
				return err
			}
			// the support it must carry for the gate to hold for it (design 5.3.3; review #1188 B7): a refusal allows a covering replacement
			return vradmit.VerifySuccessorSupport(sch, epoch+1, in.Network, tab, member, r.Commitments)
		}
	default:
		j.Outcome, j.Err = Dropped, errors.New("vrschedule: an empty message")
	}
	return j
}

func popKey(sender, evm string) string { return sender + "\x00" + evm }

// Apply admits a verified job (verr is its verification's result) against the state as it is now: a message whose intent died meanwhile is
// dropped; a verified second assembly or readiness of one signer in one view is its equivocation evidence.
func (s *Service) Apply(j Job, verr error) (Outcome, []Message, error) {
	o, err, f := s.apply(j, verr)
	return o, s.finish(f), err
}

func (s *Service) apply(j Job, verr error) (Outcome, error, followUp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.applyLocked(j, verr)
	var f followUp
	if o == Retained {
		f = s.followLocked()
	}
	return o, err, f
}

func (s *Service) applyLocked(j Job, verr error) (Outcome, error) {
	st := s.cur
	if st == nil || st != j.st {
		return Dropped, nil
	}
	m := j.msg
	if v, ok := m.view(); ok && v+RetainedViews <= st.view {
		return Dropped, nil
	}
	switch {
	case m.PoP != nil:
		if verr != nil {
			st.popRefused[popKey(j.sender, m.PoP.EVMNodeID)]++
			s.lastSeat[j.sender] = true
			return Refused, verr
		}
		if _, have := st.pops[m.PoP.EVMNodeID]; have {
			return Duplicate, nil
		}
		st.pops[m.PoP.EVMNodeID] = *m.PoP
		return Retained, nil
	case m.Assembly != nil:
		a := *m.Assembly
		vs := st.viewOf(a.Slot)
		if verr != nil {
			return s.refuse(vs, j.sender, verr)
		}
		enc, err := encodeAssembly(a)
		if err != nil {
			return s.refuse(vs, j.sender, err)
		}
		if vs.assembly != nil {
			if bytes.Equal(enc, vs.assemblyAt) {
				return Duplicate, nil
			}
			return s.equivocated(vs, vrschema.Assembler(st.order, a.Slot), a.Slot, vs.assemblyAt, enc), nil
		}
		if j.conflict || j.body == nil {
			return Dropped, nil // judged as a conflict of an assembly no longer held
		}
		vs.assembly, vs.assemblyAt, vs.body = &a, enc, *j.body
		vs.candidate, vs.bodyID = sha256.Sum256(a.Candidate), j.body.Identity()
		return Retained, nil
	case m.Readiness != nil:
		r := *m.Readiness
		vs := st.viewOf(r.Slot)
		if verr != nil {
			return s.refuse(vs, j.sender, verr)
		}
		member, kOnly, _ := s.readinessBy(st, r)
		enc, err := r.Encode()
		if err != nil {
			return s.refuse(vs, j.sender, err)
		}
		if prev, have := vs.encodings[member.RootNodeID]; have {
			if bytes.Equal(prev, enc) {
				return Duplicate, nil
			}
			return s.equivocated(vs, member.RootNodeID, r.Slot, prev, enc), nil
		}
		if j.conflict {
			return Dropped, nil
		}
		if kOnly {
			vs.kready[member.RootNodeID], vs.encodings[member.RootNodeID] = r, enc
			return Retained, nil
		}
		vs.readiness[member.RootNodeID], vs.encodings[member.RootNodeID] = r, enc
		return Retained, nil
	}
	return Dropped, nil
}

// equivocated logs a signer's first verified conflict in a view as its one evidence record; later ones add nothing.
func (s *Service) equivocated(vs *viewState, signer string, view uint64, first, next []byte) Outcome {
	if _, have := vs.evidence[signer]; !have {
		vs.evidence[signer] = Equivocation{Signer: signer, View: view, First: first, Next: next}
		s.log().Warn("VR handoff: equivocation evidence", "signer", signer, "view", view)
	}
	return Equivocated
}

// buffer keeps a message for later judgment, at most BufferPerPeer per sender.
func (s *Service) buffer(sender string, m Message) Outcome {
	q := s.buffered[sender]
	if len(q) >= BufferPerPeer {
		return Dropped
	}
	s.buffered[sender] = append(q, bufItem{m: m, at: s.updates})
	return Buffered
}

func (st *intentState) viewOf(v uint64) *viewState {
	vs := st.views[v]
	if vs == nil {
		vs = &viewState{readiness: map[string]vrhandoff.Readiness{}, kready: map[string]vrhandoff.Readiness{}, encodings: map[string][]byte{}, refused: map[string]int{},
			supportWait: map[string]int{}, evidence: map[string]Equivocation{}}
		st.views[v] = vs
	}
	return vs
}

// refuse counts a failed message against its sender's replacement allowance for the view and seats the sender last for the intent; a
// readiness that only lacks the support the gate needs keeps its sender's seat (its member has not upgraded yet).
func (s *Service) refuse(vs *viewState, sender string, err error) (Outcome, error) {
	if errors.Is(err, vradmit.ErrSupportWait) {
		vs.supportWait[sender]++
		return Refused, err
	}
	vs.refused[sender]++
	s.lastSeat[sender] = true
	return Refused, err
}

// readinessMember is the successor a readiness is by: the singleton receipt names it.
func (s *Service) readinessMember(st *intentState, r vrhandoff.Readiness) (evmassign.Identity, bool) {
	m, _, ok := s.readinessBy(st, r)
	return m, ok
}

// readinessBy is the member a readiness is by and whether it is a K member that is not a successor (its readiness is support only).
func (s *Service) readinessBy(st *intentState, r vrhandoff.Readiness) (m evmassign.Identity, kOnly, ok bool) {
	for id, m := range st.byRoot {
		if _, err := vrschema.ReadinessReceipt(r.Receipt, id); err == nil {
			return m, false, true
		}
	}
	for id, m := range st.kOnly {
		if _, err := vrschema.ReadinessReceipt(r.Receipt, id); err == nil {
			return m, true, true
		}
	}
	return evmassign.Identity{}, false, false
}

// followLocked is the work the current state makes judgeable.
func (s *Service) followLocked() followUp {
	return followUp{pend: s.judgeableLocked(), asm: s.assembleLocked(), cert: s.completeLocked(), requeue: s.requeue}
}

// finish does a state change's follow-up work outside the lock, until none is left, and sends this root's messages it produced.
func (s *Service) finish(f followUp) []Message {
	var out []Message
	for !f.empty() {
		switch {
		case f.cert != nil:
			t := f.cert
			f.cert = nil
			s.runCertificate(t)
		case f.asm != nil:
			t := f.asm
			f.asm = nil
			m, more, ok := s.runAssembly(t)
			if ok {
				out = append(out, m)
			}
			f.merge(more)
		case f.requeue != nil:
			for _, p := range f.pend {
				if !f.requeue(p.sender, p.msg) {
					s.rebuffer(p.sender, p.msg) // re-judged at the next update
				}
			}
			f.pend = nil
		default:
			p := f.pend[0]
			f.pend = f.pend[1:]
			_, _, more := s.offer(p.sender, p.msg)
			f.merge(more)
		}
	}
	s.send(out)
	return out
}

func (s *Service) rebuffer(sender string, m Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffer(sender, m)
}

// judgeableLocked takes out of the buffer every message the current state may now judge (its intent derived, its view committed, its
// view's assembly held, or its view stale, to be dropped), senders in their seat order. Messages still not judgeable stay buffered.
func (s *Service) judgeableLocked() []queued {
	st := s.cur
	if st == nil || len(s.buffered) == 0 {
		return nil
	}
	senders := make([]string, 0, len(s.buffered))
	for k := range s.buffered {
		senders = append(senders, k)
	}
	sort.Slice(senders, func(i, j int) bool {
		if s.lastSeat[senders[i]] != s.lastSeat[senders[j]] {
			return !s.lastSeat[senders[i]]
		}
		return senders[i] < senders[j]
	})
	var out []queued
	for _, sender := range senders {
		q := s.buffered[sender]
		kept := q[:0]
		for _, it := range q {
			if st.judgeable(it.m) {
				out = append(out, queued{sender: sender, msg: it.m})
			} else {
				kept = append(kept, it)
			}
		}
		if s.buffered[sender] = kept; len(kept) == 0 {
			delete(s.buffered, sender)
		}
	}
	return out
}

func (st *intentState) judgeable(m Message) bool {
	if !bytes.Equal(m.intentDigest(), st.digest[:]) {
		return false
	}
	v, ok := m.view()
	if !ok {
		return true
	}
	if v+RetainedViews <= st.view {
		return true // stale: dropped when judged
	}
	if v > st.view {
		return false
	}
	if m.Readiness != nil {
		vs := st.views[v]
		return vs != nil && vs.assembly != nil
	}
	return true
}

type assemblyTask struct {
	intent vrhandoff.Intent
	view   uint64
	pops   []vrhandoff.PoPOffer
}

// assembleLocked is this root's assembly to make when it is the committed current view's assembler and every successor's proof is held.
func (s *Service) assembleLocked() *assemblyTask {
	st := s.cur
	if st == nil || st.prepared || s.cfg.Signer == nil || st.assembled[st.view] || vrschema.Assembler(st.order, st.view) != s.cfg.Self ||
		len(st.pops) != len(st.successors) {
		return nil
	}
	st.assembled[st.view] = true
	pops := make([]vrhandoff.PoPOffer, 0, len(st.pops))
	for _, p := range st.pops {
		pops = append(pops, p)
	}
	return &assemblyTask{intent: st.d.Intent, view: st.view, pops: pops}
}

// runAssembly assembles and signs outside the lock, then offers the assembly as this root's own message.
func (s *Service) runAssembly(t *assemblyTask) (Message, followUp, bool) {
	_, raw, _, err := vrhandoff.Assemble(t.intent, t.pops)
	if err != nil {
		s.log().Warn("VR handoff: cannot assemble", "view", t.view, "error", err)
		return Message{}, followUp{}, false
	}
	a, err := vrhandoff.SignAssembly(t.intent, t.view, raw, s.cfg.Signer)
	if err != nil {
		s.log().Warn("VR handoff: cannot sign the assembly", "view", t.view, "error", err)
		return Message{}, followUp{}, false
	}
	m := Message{Assembly: &a}
	o, err, f := s.offer(s.cfg.Self, m)
	if o != Retained {
		s.log().Warn("VR handoff: this root's own assembly is not retained", "outcome", o.String(), "error", err)
		return Message{}, f, false
	}
	s.log().Info("VR handoff: assembled", "intent", fmt.Sprintf("%x", a.IntentDigest[:8]), "view", t.view)
	return m, f, true
}

type certTask struct {
	st   *intentState
	view uint64
	in   vradmit.CertificateInput
	plan PreparePlan
}

// completeLocked is a complete set of a retained view to check as a certificate while no certificate is held: every successor's readiness
// for the view's assembly, each carrying the support the gate needs for it under the committed schedule.
func (s *Service) completeLocked() *certTask {
	st := s.cur
	if st == nil || st.iret != nil {
		return nil
	}
	views := make([]uint64, 0, len(st.views))
	for v := range st.views {
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i] < views[j] })
	for _, view := range views {
		vs := st.views[view]
		if vs.tried || vs.assembly == nil || len(vs.readiness) != len(st.successors) {
			continue
		}
		vs.tried = true
		rs := map[string]vrhandoff.Readiness{}
		supported := true
		for k, v := range vs.readiness {
			rs[k] = v
			if err := vradmit.VerifySuccessorSupport(s.sch, st.d.RootEpoch+1, st.d.Intent.Network, s.tab, st.byRoot[k], v.Commitments); err != nil {
				supported = false
			}
		}
		if !supported {
			s.log().Info("VR handoff: a complete set lacks the support the gate needs; a later view may complete", "view", view)
			continue
		}
		cert, err := vrhandoff.Certificate(*vs.assembly, st.successors, rs, vs.body.Identity())
		if err != nil {
			continue
		}
		cand, err := vrschema.DecodeCandidateV6(vs.assembly.Candidate)
		if err != nil {
			continue
		}
		return &certTask{st: st, view: view,
			in: vradmit.CertificateInput{Certificate: cert, IntentDigest: st.digest, CommittedView: st.view, Incumbents: st.incumbents,
				CandidateBytes: vs.assembly.Candidate, Successors: st.successors, Body: vs.body, Attempt: st.d.Intent.Attempt, TrustBaseBytes: st.trustBase},
			plan: PreparePlan{Intent: st.digest, Epoch: st.d.RootEpoch, Attempt: st.d.Intent.Attempt, Predecessor: bytes.Clone(st.d.Intent.PredecessorBodyID),
				Result: vrschema.Word(cand.SourceRef), Body: vs.body, Certificate: cert}}
	}
	return nil
}

// runCertificate verifies a complete set outside the lock as Freeze validity will judge it and retains it in I-RET when the intent still
// holds none: the first complete certificate of the intent is kept.
func (s *Service) runCertificate(t *certTask) {
	if err := vradmit.VerifyCertificate(t.in); err != nil {
		s.log().Warn("VR handoff: a complete set does not verify as a certificate", "view", t.view, "error", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil || st != t.st || st.iret != nil {
		return
	}
	plan := t.plan
	st.iret = &plan
	s.log().Info("VR handoff: a complete verified certificate is held (I-RET)", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", t.view)
}

type planInput struct {
	plan PreparePlan
	sch  []vrschema.Activation
	tab  vradmit.SupportTable
	k    []evmassign.Identity
	kr   []vrschema.Readiness // this intent's K-member readiness (support evidence)
	st   *intentState
}

func (s *Service) held(planning bool) (planInput, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil || st.iret == nil || (planning && st.prepared) {
		return planInput{}, false
	}
	return planInput{plan: *st.iret, sch: s.sch, tab: s.tab, k: s.k, kr: s.kReadinessLocked(st), st: st}, true
}

// Plan is the Prepare a leader may order (design 5.3.1 stage 5): the current intent's I-RET certificate with the rule-support evidence the
// gate (7.3) accepts over the committed table; false when no complete verified certificate is held, a Prepare is committed, or the gate
// does not hold yet. The gate is checked outside the lock.
func (s *Service) Plan() (PreparePlan, bool) {
	h, ok := s.held(true)
	if !ok {
		return PreparePlan{}, false
	}
	p := h.plan
	p.RuleSupport = supportEvidence(h.sch, h.tab, h.k)
	p.RuleSupport.KReadiness = h.kr
	st := h.st
	if err := vradmit.VerifyRuleSupport(vradmit.SupportInput{Network: st.d.Intent.Network, SuccessorEpoch: st.d.RootEpoch + 1, Schedule: h.sch, Table: h.tab,
		Evidence: p.RuleSupport, Readiness: p.Certificate.Readiness, IntentDigest: st.digest[:], J: st.successors, K: h.k}); err != nil {
		return PreparePlan{}, false
	}
	return p, true
}

// Prepared is the retained certificate of the current intent once its attempt is prepared: the Freeze v5 it carries, with the rule-support
// evidence over the committed table.
func (s *Service) Prepared() (PreparePlan, bool) {
	h, ok := s.held(false)
	if !ok {
		return PreparePlan{}, false
	}
	p := h.plan
	p.RuleSupport = supportEvidence(h.sch, h.tab, h.k)
	p.RuleSupport.KReadiness = h.kr
	return p, true
}

// supportEvidence references every committed table entry of a K member's exact binding for a rule of the committed schedule. Committed
// entries were verified when they were committed: they are matched by binding (staking id, generation, root key hash), not verified again
// on the consensus loop (review #1188 r2 N3); admission resolves and checks every reference.
func supportEvidence(sch []vrschema.Activation, tab vradmit.SupportTable, k []evmassign.Identity) vrschema.RuleSupportEvidence {
	ev := vrschema.RuleSupportEvidence{}
	rules := map[vrschema.Word]bool{}
	for _, a := range vrschema.Effective(sch) {
		rules[a.RuleID] = true
	}
	for _, c := range tab.Entries {
		if len(c.RuleID) != 32 || !rules[vrschema.Word(c.RuleID)] {
			continue
		}
		for _, m := range k {
			if bytes.Equal(m.StakingID, c.StakingID) && c.Generation == m.Generation && bytes.Equal(c.RootKeyHash, ethcrypto.Keccak256(m.RootKey)) {
				d, err := c.Digest()
				if err == nil {
					ev.Refs = append(ev.Refs, d[:])
				}
			}
		}
	}
	sort.Slice(ev.Refs, func(i, j int) bool { return bytes.Compare(ev.Refs[i], ev.Refs[j]) < 0 })
	return ev
}

// Stage is GetStage(I, fromView): every retained message of intent from fromView on, for a restarted peer.
func (s *Service) Stage(intent [32]byte, fromView uint64) (StageSet, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil || st.digest != intent {
		return StageSet{}, false
	}
	var out StageSet
	for _, p := range st.pops {
		out.PoPs = append(out.PoPs, p)
	}
	sort.Slice(out.PoPs, func(i, j int) bool { return out.PoPs[i].EVMNodeID < out.PoPs[j].EVMNodeID })
	views := make([]uint64, 0, len(st.views))
	for v := range st.views {
		if v >= fromView {
			views = append(views, v)
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i] < views[j] })
	for _, v := range views {
		vs := st.views[v]
		if vs.assembly != nil {
			out.Assemblies = append(out.Assemblies, *vs.assembly)
		}
		ids := make([]string, 0, len(vs.readiness))
		for id := range vs.readiness {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			out.Readiness = append(out.Readiness, vs.readiness[id])
		}
		kids := make([]string, 0, len(vs.kready))
		for id := range vs.kready {
			kids = append(kids, id)
		}
		sort.Strings(kids)
		for _, id := range kids {
			out.Readiness = append(out.Readiness, vs.kready[id])
		}
	}
	return out, true
}

// Evidence is the equivocation evidence of the current intent's retained views: one record per equivocating signer and view.
func (s *Service) Evidence() []Equivocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	var out []Equivocation
	for _, vs := range s.cur.views {
		for _, e := range vs.evidence {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].View != out[j].View {
			return out[i].View < out[j].View
		}
		return out[i].Signer < out[j].Signer
	})
	return out
}

// Current is the current intent's digest, its committed view and whether a complete certificate is held.
func (s *Service) Current() (intent [32]byte, view uint64, complete, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return intent, 0, false, false
	}
	return s.cur.digest, s.cur.view, s.cur.iret != nil, true
}

// Members are the node ids the peer protocol admits for the current intent: the incumbents, the successors' roots and K's roots.
func (s *Service) Members() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for _, m := range s.k {
		out[m.RootNodeID] = true
	}
	if s.cur != nil {
		for id := range s.cur.incumbents {
			out[id] = true
		}
		for id := range s.cur.byRoot {
			out[id] = true
		}
	}
	return out
}

func encodeAssembly(a vrhandoff.Assembly) ([]byte, error) {
	if _, err := a.SignedBytes(); err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(a)
}

// kReadinessLocked is this intent's K-member readiness, the evidence of K's rule support in a Freeze v5 (design 5.1, 7.3): for each K member
// at most one verified readiness that carries a commitment, ascending by its stakingID. A K member that is also a successor is represented
// by its readiness in the retained certificate (a J readiness is a K readiness of the same intent, signed by the same root key); a K member
// that is not is represented by the readiness it sent for support only, from the earliest retained view that holds one.
func (s *Service) kReadinessLocked(st *intentState) []vrschema.Readiness {
	byRoot := map[string]vrschema.Readiness{}
	if st.iret != nil {
		for _, r := range st.iret.Certificate.Readiness {
			if m, kOnly, ok := s.readinessBy(st, r); ok && !kOnly {
				byRoot[m.RootNodeID] = r
			}
		}
	}
	views := make([]uint64, 0, len(st.views))
	for v := range st.views {
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i] < views[j] })
	for _, v := range views {
		for id, r := range st.views[v].kready {
			if _, have := byRoot[id]; !have {
				byRoot[id] = r
			}
		}
	}
	inK := map[string]bool{}
	for _, m := range s.k {
		inK[m.RootNodeID] = true
	}
	var out []vrschema.Readiness
	for id, r := range byRoot {
		// a commitment of a rule the committed schedule no longer holds (the basis changed under the intent) would invalidate the Freeze
		if inK[id] && len(r.Commitments) > 0 && vradmit.CommitmentsInScope(s.sch, st.d.Intent.Network, r.Commitments) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].Commitments[0].StakingID, out[j].Commitments[0].StakingID) < 0
	})
	return out
}
