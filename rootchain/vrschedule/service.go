package vrschedule

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

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
// ahead are buffered and re-evaluated when the view commits; nothing in the service ever advances a view (only committed HandoffViews do).
// The service is synchronous; the verification queue (Queue) bounds and schedules what reaches it.

// Retention and buffering bounds (design 5.3.3, 5.3.4; schema constants).
const (
	RetainedViews   = 4 // the committed current view and the 3 previous ones
	BufferAhead     = 2 // views ahead of the committed current view that are buffered
	BufferPerPeer   = 64
	MaxReplacements = 1 // per sender and view, after a budget or format failure
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
	Dropped                    // stale, out of bounds, or admitted no further
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
	readiness  map[string]vrhandoff.Readiness
	encodings  map[string][]byte
	refused    map[string]int // replacements spent by sender
}

type intentState struct {
	d          Derived
	digest     [32]byte
	order      []string
	incumbents map[string][]byte
	successors []evmassign.Identity
	byRoot     map[string]evmassign.Identity
	byEVM      map[string]evmassign.Identity
	trustBase  []byte
	pops       map[string]vrhandoff.PoPOffer
	view       uint64
	prepared   bool
	views      map[uint64]*viewState
	iret       *PreparePlan
	assembled  map[uint64]bool
}

// Service is one root's protocol state (design 5.3.4): at most two intents (the current one and one not derived here yet, whose
// messages are buffered by digest).
type Service struct {
	cfg ServiceConfig
	mu  sync.Mutex
	cur *intentState
	k   []evmassign.Identity
	tab vradmit.SupportTable
	sch []vrschema.Activation
	// buffered messages, by sender, for future views or for the one intent not derived here yet
	buffered map[string][]Message
	pending  [32]byte // the digest of the intent buffered messages name besides the current one
	lastSeat map[string]bool
	evidence []Equivocation
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{cfg: cfg, buffered: map[string][]Message{}, lastSeat: map[string]bool{}}
}

func (s *Service) log() *slog.Logger {
	if s.cfg.Log != nil {
		return s.cfg.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Update applies one committed root block. A changed or underivable intent kills the current one (stage 0 restarts); a newly committed
// view prunes the retention window and re-evaluates the buffered messages. It returns the messages this root sends (its assembly).
func (s *Service) Update(c Committed) []Message {
	out := s.update(c)
	s.send(out)
	return out
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

func (s *Service) update(c Committed) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.k, s.tab, s.sch = c.K, c.Table, c.Schedule
	if !c.Derivable {
		if s.cur != nil {
			s.log().Info("VR handoff: the intent died", "intent", fmt.Sprintf("%x", s.cur.digest[:8]))
		}
		s.cur = nil
		return nil
	}
	if s.cur == nil || s.cur.digest != c.Derived.Digest {
		if s.cur != nil {
			s.log().Info("VR handoff: the intent died", "intent", fmt.Sprintf("%x", s.cur.digest[:8]))
		}
		st, err := newIntentState(c)
		if err != nil {
			s.log().Warn("VR handoff: the derived intent cannot be staged", "error", err)
			s.cur = nil
			return nil
		}
		s.cur = st
		s.lastSeat = map[string]bool{}
		for sender, q := range s.buffered {
			kept := q[:0]
			for _, m := range q {
				if d := m.intentDigest(); bytes.Equal(d, st.digest[:]) || bytes.Equal(d, s.pending[:]) {
					kept = append(kept, m)
				}
			}
			if s.buffered[sender] = kept; len(kept) == 0 {
				delete(s.buffered, sender)
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
	var out []Message
	out = append(out, s.reevaluate()...)
	out = append(out, s.assembleLocked()...)
	return out
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
		pops: map[string]vrhandoff.PoPOffer{}, views: map[uint64]*viewState{}, assembled: map[uint64]bool{}}
	for _, m := range cand.Identities {
		st.byRoot[m.RootNodeID], st.byEVM[m.EVMNodeID] = m, m
	}
	return st, nil
}

// Offer judges one message from sender (a peer's node id, or this root's own) inline: verification and admission in one call. Admission
// (which peers may send at all) is the transport's; the verification queue (Queue) uses Prepare and runs the verification off the lock.
func (s *Service) Offer(sender string, m Message) (Outcome, []Message, error) {
	j := s.Prepare(sender, m)
	if j.Verify == nil {
		return j.Outcome, nil, j.Err
	}
	err := j.Verify()
	return s.Apply(j, err)
}

// Job is one admitted message's verification, split so it runs without the service's lock (the verification service, design 5.3.4): Verify
// is pure over a snapshot of the state it was prepared against; Apply admits its result. A Job with a nil Verify is already judged.
type Job struct {
	Outcome Outcome
	Err     error
	Verify  func() error
	sender  string
	msg     Message
	digest  [32]byte
	body    *q3format.BodyV3 // an assembly's derived body
}

// Prepare classifies a message under the lock: stale, buffered, duplicate or out of bounds is judged here; anything else gets its pure
// verification over a snapshot.
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
	if st == nil || !bytes.Equal(d, st.digest[:]) {
		// another intent: buffered for the one intent this root may not have derived yet (at most two intents)
		if s.pending != ([32]byte{}) && !bytes.Equal(d, s.pending[:]) {
			j.Outcome = Dropped
			return j
		}
		s.pending = [32]byte(d)
		j.Outcome = s.buffer(sender, m)
		return j
	}
	j.digest = st.digest
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
		j.Verify = func() error { return vrhandoff.VerifyPoP(in, p) }
	case m.Assembly != nil:
		a := *m.Assembly
		vs := st.viewOf(a.Slot)
		if vs.assembly != nil {
			enc, err := encodeAssembly(a)
			if err == nil && bytes.Equal(enc, vs.assemblyAt) {
				j.Outcome = Duplicate
				return j
			}
		} else if vs.refused[sender] > MaxReplacements {
			j.Outcome = Dropped
			return j
		}
		incumbents, epoch, bc := st.incumbents, st.d.RootEpoch, st.d.Body
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
		member, ok := s.readinessMember(st, r)
		if !ok {
			j.Outcome, j.Err = Dropped, errors.New("vrschedule: readiness of no successor")
			return j
		}
		enc, err := r.Encode()
		if err != nil {
			j.Outcome, j.Err = s.refuse(vs, sender, err)
			return j
		}
		if prev, have := vs.encodings[member.RootNodeID]; have && bytes.Equal(prev, enc) {
			j.Outcome = Duplicate
			return j
		}
		if vs.assembly == nil {
			j.Outcome = s.buffer(sender, m) // verified once the view's assembly is held
			return j
		}
		if _, have := vs.encodings[member.RootNodeID]; !have && vs.refused[sender] > MaxReplacements {
			j.Outcome = Dropped
			return j
		}
		a, body, tb := *vs.assembly, vs.body, st.trustBase
		j.Verify = func() error { return vrhandoff.VerifyReadiness(in, a, body, member, tb, r) }
	default:
		j.Outcome, j.Err = Dropped, errors.New("vrschedule: an empty message")
	}
	return j
}

// Apply admits a verified job (verr is its verification's result) against the state as it is now: a message whose intent died meanwhile is
// dropped; a verified second assembly or readiness of one signer in one view is equivocation evidence.
func (s *Service) Apply(j Job, verr error) (Outcome, []Message, error) {
	s.mu.Lock()
	o, err := s.applyLocked(j, verr)
	var out []Message
	if o == Retained {
		out = append(out, s.reevaluate()...)
		out = append(out, s.assembleLocked()...)
	}
	s.mu.Unlock()
	s.send(out)
	return o, out, err
}

func (s *Service) applyLocked(j Job, verr error) (Outcome, error) {
	st := s.cur
	if st == nil || st.digest != j.digest {
		return Dropped, nil
	}
	m := j.msg
	switch {
	case m.PoP != nil:
		if verr != nil {
			if !errors.Is(verr, ErrBudget) {
				s.lastSeat[j.sender] = true
			}
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
			s.evidence = append(s.evidence, Equivocation{Signer: vrschema.Assembler(st.order, a.Slot), View: a.Slot, First: vs.assemblyAt, Next: enc})
			return Equivocated, nil
		}
		vs.assembly, vs.assemblyAt, vs.body = &a, enc, *j.body
		return Retained, nil
	case m.Readiness != nil:
		r := *m.Readiness
		vs := st.viewOf(r.Slot)
		if verr != nil {
			return s.refuse(vs, j.sender, verr)
		}
		member, _ := s.readinessMember(st, r)
		enc, err := r.Encode()
		if err != nil {
			return s.refuse(vs, j.sender, err)
		}
		if prev, have := vs.encodings[member.RootNodeID]; have {
			if bytes.Equal(prev, enc) {
				return Duplicate, nil
			}
			s.evidence = append(s.evidence, Equivocation{Signer: member.RootNodeID, View: r.Slot, First: prev, Next: enc})
			return Equivocated, nil
		}
		vs.readiness[member.RootNodeID], vs.encodings[member.RootNodeID] = r, enc
		s.complete(st, r.Slot, vs)
		return Retained, nil
	}
	return Dropped, nil
}

// buffer keeps a message for later judgment, at most BufferPerPeer per sender.
func (s *Service) buffer(sender string, m Message) Outcome {
	q := s.buffered[sender]
	if len(q) >= BufferPerPeer {
		return Dropped
	}
	s.buffered[sender] = append(q, m)
	return Buffered
}

func (st *intentState) viewOf(v uint64) *viewState {
	vs := st.views[v]
	if vs == nil {
		vs = &viewState{readiness: map[string]vrhandoff.Readiness{}, encodings: map[string][]byte{}, refused: map[string]int{}}
		st.views[v] = vs
	}
	return vs
}

// refuse counts a failed message against its sender's replacement allowance for the view and seats the sender last for the intent.
func (s *Service) refuse(vs *viewState, sender string, err error) (Outcome, error) {
	vs.refused[sender]++
	if !errors.Is(err, ErrBudget) { // a budget overrun is dropped without evidence and keeps the sender's seat
		s.lastSeat[sender] = true
	}
	return Refused, err
}

// readinessMember is the successor a readiness is by: the singleton receipt names it.
func (s *Service) readinessMember(st *intentState, r vrhandoff.Readiness) (evmassign.Identity, bool) {
	for id, m := range st.byRoot {
		if _, err := vrschema.ReadinessReceipt(r.Receipt, id); err == nil {
			return m, true
		}
	}
	return evmassign.Identity{}, false
}

// complete admits the view's complete set into I-RET once it verifies as Freeze validity will judge it; the first complete certificate of
// the intent is kept.
func (s *Service) complete(st *intentState, view uint64, vs *viewState) {
	if st.iret != nil || vs.assembly == nil || len(vs.readiness) != len(st.successors) {
		return
	}
	rs := map[string]vrhandoff.Readiness{}
	for k, v := range vs.readiness {
		rs[k] = v
	}
	cert, err := vrhandoff.Certificate(*vs.assembly, st.successors, rs, vs.body.Identity())
	if err != nil {
		return
	}
	if err := vradmit.VerifyCertificate(vradmit.CertificateInput{Certificate: cert, IntentDigest: st.digest, CommittedView: st.view, Incumbents: st.incumbents,
		CandidateBytes: vs.assembly.Candidate, Successors: st.successors, Body: vs.body, Attempt: st.d.Intent.Attempt, TrustBaseBytes: st.trustBase}); err != nil {
		s.log().Warn("VR handoff: a complete set does not verify as a certificate", "view", view, "error", err)
		return
	}
	cand, err := vrschema.DecodeCandidateV6(vs.assembly.Candidate)
	if err != nil {
		return
	}
	st.iret = &PreparePlan{Intent: st.digest, Epoch: st.d.RootEpoch, Attempt: st.d.Intent.Attempt, Predecessor: bytes.Clone(st.d.Intent.PredecessorBodyID),
		Result: vrschema.Word(cand.SourceRef), Body: vs.body, Certificate: cert}
	s.log().Info("VR handoff: a complete verified certificate is held (I-RET)", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", view)
}

// reevaluate offers again every buffered message that the current state may now judge (its view committed, its intent derived, its
// view's assembly held), senders in their seat order. Messages still not judgeable stay buffered.
func (s *Service) reevaluate() []Message {
	if s.cur == nil {
		return nil
	}
	if bytes.Equal(s.pending[:], s.cur.digest[:]) {
		s.pending = [32]byte{}
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
	for progress := true; progress; {
		progress = false
		for _, sender := range senders {
			q := s.buffered[sender]
			s.buffered[sender] = nil
			for _, m := range q {
				j := s.prepareLocked(sender, m)
				o := j.Outcome
				if j.Verify != nil {
					o, _ = s.applyLocked(j, j.Verify())
				}
				if o == Retained {
					progress = true
				}
			}
			if len(s.buffered[sender]) == 0 {
				delete(s.buffered, sender)
			}
		}
	}
	return nil
}

// assembleLocked makes this root's assembly when it is the committed current view's assembler and every successor's proof is held.
func (s *Service) assembleLocked() []Message {
	st := s.cur
	if st == nil || st.prepared || s.cfg.Signer == nil || st.assembled[st.view] || vrschema.Assembler(st.order, st.view) != s.cfg.Self ||
		len(st.pops) != len(st.successors) {
		return nil
	}
	pops := make([]vrhandoff.PoPOffer, 0, len(st.pops))
	for _, p := range st.pops {
		pops = append(pops, p)
	}
	_, raw, _, err := vrhandoff.Assemble(st.d.Intent, pops)
	if err != nil {
		s.log().Warn("VR handoff: cannot assemble", "view", st.view, "error", err)
		return nil
	}
	a, err := vrhandoff.SignAssembly(st.d.Intent, st.view, raw, s.cfg.Signer)
	if err != nil {
		s.log().Warn("VR handoff: cannot sign the assembly", "view", st.view, "error", err)
		return nil
	}
	st.assembled[st.view] = true
	j := s.prepareLocked(s.cfg.Self, Message{Assembly: &a})
	o, err := j.Outcome, j.Err
	if j.Verify != nil {
		o, err = s.applyLocked(j, j.Verify())
	}
	if o != Retained {
		s.log().Warn("VR handoff: this root's own assembly is not retained", "outcome", o.String(), "error", err)
		return nil
	}
	s.log().Info("VR handoff: assembled", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view)
	return []Message{{Assembly: &a}}
}

// Plan is the Prepare a leader may order (design 5.3.1 stage 5): the current intent's I-RET certificate with the rule-support evidence the
// gate (7.3) accepts over the committed table; false when no complete verified certificate is held, a Prepare is committed, or the gate
// does not hold yet.
func (s *Service) Plan() (PreparePlan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil || st.iret == nil || st.prepared {
		return PreparePlan{}, false
	}
	p := *st.iret
	p.RuleSupport = s.supportEvidence(st)
	if err := vradmit.VerifyRuleSupport(vradmit.SupportInput{Network: st.d.Intent.Network, SuccessorEpoch: st.d.RootEpoch + 1, Schedule: s.sch, Table: s.tab,
		Evidence: p.RuleSupport, Readiness: p.Certificate.Readiness, IntentDigest: st.digest[:], J: st.successors, K: s.k}); err != nil {
		return PreparePlan{}, false
	}
	return p, true
}

// Prepared is the retained certificate of the current intent once its attempt is prepared: the Freeze v5 it carries, with the rule-support
// evidence over the committed table.
func (s *Service) Prepared() (PreparePlan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil || st.iret == nil {
		return PreparePlan{}, false
	}
	p := *st.iret
	p.RuleSupport = s.supportEvidence(st)
	return p, true
}

// supportEvidence references every committed table entry of a K member's exact binding for a rule of the committed schedule.
func (s *Service) supportEvidence(st *intentState) vrschema.RuleSupportEvidence {
	ev := vrschema.RuleSupportEvidence{}
	rules := map[vrschema.Word]bool{}
	for _, a := range vrschema.Effective(s.sch) {
		rules[a.RuleID] = true
	}
	for _, c := range s.tab.Entries {
		if len(c.RuleID) != 32 || !rules[vrschema.Word(c.RuleID)] {
			continue
		}
		for _, m := range s.k {
			if bytes.Equal(m.StakingID, c.StakingID) && vradmit.VerifyCommitment(c, m) == nil {
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
	}
	return out, true
}

// Evidence is the equivocation evidence logged so far.
func (s *Service) Evidence() []Equivocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Equivocation(nil), s.evidence...)
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
