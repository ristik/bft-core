package vrschedule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The node side of the handoff protocol (VT-09, ristik/bft-core#1149; design sections 5.3.2, 5.3.3). A node that is a successor member of the
// derived intent (admitted or elected) does every member step itself, from the state its own service holds over the committed chain: its
// sticky possession proof (stage 2, one per intent and member, persisted and re-served), its readiness over a fully verified assembly of the
// committed current view (stage 4) with the support commitments of every rule the gate needs, and the staging of the candidate for the
// pre-connection to the successor committee and the in-process switch. No host-side drive and no harness plays the member.
//
// Member rules (5.3.3): readiness is signed only for an assembly the service verified in full (signature of the view's assembler, the
// candidate's semantics and every possession proof, the derived body) in the committed current view; (intent, view, candidate digest) is
// persisted durably before the readiness is released, and at most one assembly is signed per view; a restarted member resumes at the
// committed view (the service's) and never re-signs a persisted view: it re-sends what it persisted. Nothing here advances a view.

// ErrMember reports a member step this node refuses.
var ErrMember = errors.New("vrschedule: member")

// ResendEvery is how often a member re-sends its possession proof until the view's assembly is held, and its readiness until the
// intent's certificate is complete (a peer that was not reachable or that restarted learns it; peers also pull it with GetStage).
const ResendEvery = 5 * time.Second

// Intents the member's file remembers (the newest ones).
const memberKeptIntents = 2

// Staged is what the member hands to the staging hook once it holds a verified assembly: the successor body, its candidate digest, the
// attempt and the candidate's identities (the successor's EVM validators and roots).
type Staged struct {
	Body            q3format.BodyV3
	CandidateDigest [32]byte
	Attempt         uint64
	Identities      []evmassign.Identity
}

// MemberConfig is one node's member participation.
type MemberConfig struct {
	Self       string          // this node's root node id
	RootSigner abcrypto.Signer // its root key: the readiness and the support commitments
	EVMSigner  abcrypto.Signer // its EVM key: the possession proof; nil: the node holds no EVM key and sends none
	// Path is the member's persisted state (sticky proofs, signed views); empty keeps it in memory only (tests).
	Path string
	// Send hands an outbound message to the transport; nil sends nothing.
	Send func(Message)
	// Supports reports whether this node runs the release of an effective rule and supports it; nil supports every rule of the committed
	// schedule (the node's binary is the implementation the schedule's rules name).
	Supports func(vrschema.Activation) bool
	// Stage stages a verified candidate for the pre-connection and the in-process switch; its error is logged, never fatal.
	Stage func(Staged) error
	// Hold, when set and true, makes the member hold back its readiness (the possession proof goes out): a development test hook that lets a
	// lane restart a member between its proof and its readiness. Production nodes leave it nil.
	Hold func() bool
	Log  *slog.Logger
	Now  func() time.Time
}

// memberFile is the persisted member state.
type memberFile struct {
	Intents []memberIntent `json:"intents"`
}

type memberIntent struct {
	Intent string       `json:"intent"`
	PoP    string       `json:"pop,omitempty"`
	Views  []memberView `json:"views,omitempty"`
}

type memberView struct {
	View            uint64 `json:"view"`
	CandidateDigest string `json:"candidateDigest"`
	Readiness       string `json:"readiness,omitempty"`
}

// Member is the node-side protocol participant over a Service.
type Member struct {
	cfg MemberConfig
	svc *Service

	mu       sync.Mutex
	file     memberFile
	lastPoP  time.Time
	lastRd   time.Time
	staged   [32]byte
	noEVMKey bool
}

// NewMember loads the persisted state (a missing file is an empty state; a corrupt one is an error: a member must not forget a signed view).
func NewMember(svc *Service, cfg MemberConfig) (*Member, error) {
	if cfg.Self == "" || cfg.RootSigner == nil {
		return nil, fmt.Errorf("%w: a node id and a root key are required", ErrMember)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := &Member{cfg: cfg, svc: svc}
	if cfg.Path != "" {
		raw, err := os.ReadFile(cfg.Path) // #nosec G304 -- the node's own state file
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			if err := json.Unmarshal(raw, &m.file); err != nil {
				return nil, fmt.Errorf("%w: %s: %w", ErrMember, cfg.Path, err)
			}
		}
	}
	return m, nil
}

func (m *Member) log() *slog.Logger {
	if m.cfg.Log != nil {
		return m.cfg.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (m *Member) persist() error {
	if m.cfg.Path == "" {
		return nil
	}
	raw, err := json.Marshal(m.file)
	if err != nil {
		return err
	}
	return writeDurable(m.cfg.Path, raw)
}

func (m *Member) intent(d [32]byte) *memberIntent {
	h := hex.EncodeToString(d[:])
	for i := range m.file.Intents {
		if m.file.Intents[i].Intent == h {
			return &m.file.Intents[i]
		}
	}
	if len(m.file.Intents) >= memberKeptIntents {
		m.file.Intents = m.file.Intents[len(m.file.Intents)-memberKeptIntents+1:]
	}
	m.file.Intents = append(m.file.Intents, memberIntent{Intent: h})
	return &m.file.Intents[len(m.file.Intents)-1]
}

func (mi *memberIntent) view(v uint64) *memberView {
	for i := range mi.Views {
		if mi.Views[i].View == v {
			return &mi.Views[i]
		}
	}
	return nil
}

// memberState is what a successor member reads of its service: the derived intent, whether this node is one of its successors, what the
// service holds of its messages, and the committed current view's verified assembly.
type memberState struct {
	intent     vrhandoff.Intent
	digest     [32]byte
	rootEpoch  uint64
	self       evmassign.Identity
	successor  bool
	kOnly      bool // a K member that is no successor: it sends readiness for rule support only
	popHeld    bool
	view       uint64
	prepared   bool
	complete   bool
	assembly   *vrhandoff.Assembly
	body       q3format.BodyV3
	candidate  [32]byte
	trustBase  []byte
	readyHeld  bool
	schedule   []vrschema.Activation
	table      vradmit.SupportTable
	successors []evmassign.Identity
}

func (s *Service) memberState(self string) (memberState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil {
		return memberState{}, false
	}
	ms := memberState{intent: st.d.Intent, digest: st.digest, rootEpoch: st.d.RootEpoch, view: st.view, prepared: st.prepared, complete: st.iret != nil,
		trustBase: st.trustBase, schedule: s.sch, table: s.tab, successors: st.successors}
	ms.self, ms.successor = st.byRoot[self]
	if !ms.successor {
		if m, ok := st.kOnly[self]; ok {
			ms.self, ms.kOnly = m, true
			if vs := st.views[st.view]; vs != nil && vs.assembly != nil {
				a := *vs.assembly
				ms.assembly, ms.body, ms.candidate = &a, vs.body, vs.candidate
				_, ms.readyHeld = vs.kready[self]
			}
		}
		return ms, true
	}
	_, ms.popHeld = st.pops[ms.self.EVMNodeID]
	if vs := st.views[st.view]; vs != nil {
		if vs.assembly != nil {
			a := *vs.assembly
			ms.assembly, ms.body, ms.candidate = &a, vs.body, vs.candidate
		}
		_, ms.readyHeld = vs.readiness[self]
	}
	return ms, true
}

// Step does whatever the member owes in the state its service holds now; it is idempotent and cheap, called after every committed update,
// every retained message and on a timer. It returns the first error of its steps (logged by the caller; a later Step retries).
func (m *Member) Step() error {
	st, ok := m.svc.memberState(m.cfg.Self)
	if !ok || !(st.successor || st.kOnly) || st.prepared {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	if st.successor {
		if err := m.stepPoP(st); err != nil {
			errs = append(errs, err)
		}
	}
	if st.assembly != nil && (m.cfg.Hold == nil || !m.cfg.Hold()) {
		if err := m.stepReadiness(st); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Member) send(msg Message) {
	if m.cfg.Send != nil {
		m.cfg.Send(msg)
	}
}

// stepPoP: stage 2. One proof per (intent, member), signed once, persisted, kept in the service and re-sent until the view's assembly is
// held. A restarted member re-offers its persisted proof to its fresh service.
func (m *Member) stepPoP(st memberState) error {
	mi := m.intent(st.digest)
	var p vrhandoff.PoPOffer
	if mi.PoP == "" {
		if m.cfg.EVMSigner == nil {
			if !m.noEVMKey {
				m.noEVMKey = true
				m.log().Warn("VR handoff member: this node holds no EVM key, so it cannot send its possession proof", "intent", fmt.Sprintf("%x", st.digest[:8]))
			}
			return nil
		}
		var err error
		if p, err = vrhandoff.SignPoP(st.intent, st.self, m.cfg.EVMSigner); err != nil {
			return fmt.Errorf("%w: possession proof: %w", ErrMember, err)
		}
		raw, err := types.Cbor.Marshal(p)
		if err != nil {
			return err
		}
		mi.PoP = hex.EncodeToString(raw)
		if err := m.persist(); err != nil { // persisted before it is released
			mi.PoP = ""
			return fmt.Errorf("%w: persisting the possession proof: %w", ErrMember, err)
		}
		m.log().Info("VR handoff member: possession proof", "intent", fmt.Sprintf("%x", st.digest[:8]), "evm", st.self.EVMNodeID)
	} else {
		raw, err := hex.DecodeString(mi.PoP)
		if err == nil {
			err = types.Cbor.Unmarshal(raw, &p)
		}
		if err != nil {
			return fmt.Errorf("%w: persisted possession proof: %w", ErrMember, err)
		}
	}
	if !st.popHeld {
		// the service verifies it like any peer's; a held proof is sticky, so this is a no-op once it is retained
		if o, _, err := m.svc.Offer(m.cfg.Self, Message{PoP: &p}); o == Refused {
			return fmt.Errorf("%w: this node's own possession proof is refused: %w", ErrMember, err)
		}
	}
	if st.assembly == nil && m.cfg.Now().Sub(m.lastPoP) >= ResendEvery {
		m.lastPoP = m.cfg.Now()
		m.send(Message{PoP: &p})
	}
	return nil
}

// commitments are the support commitments of every effective or latched rule the gate needs for a successor of this root epoch (strictly
// ascending by rule id), by this node's root key, for the rules this node supports.
func (m *Member) commitments(st memberState) ([]vrhandoff.SupportCommitment, error) {
	var out []vrhandoff.SupportCommitment
	for _, a := range vradmit.RequiredRules(st.schedule, st.rootEpoch+1) {
		if m.cfg.Supports != nil && !m.cfg.Supports(a) {
			continue
		}
		c, err := vrhandoff.SignCommitment(st.intent.Network, st.self, a.RuleID, a.ReleaseDigest, m.cfg.RootSigner)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// stepReadiness: stage 4, over the verified assembly of the committed current view.
func (m *Member) stepReadiness(st memberState) error {
	mi := m.intent(st.digest)
	cd := sha256.Sum256(st.assembly.Candidate)
	if st.successor {
		if err := m.stage(st, cd); err != nil {
			m.log().Warn("VR handoff member: staging the candidate failed", "error", err)
		}
	}
	if pv := mi.view(st.view); pv != nil {
		// a persisted view is never signed again; its readiness is re-sent and re-offered
		if pv.CandidateDigest != hex.EncodeToString(cd[:]) {
			return nil // another assembly of a view this member already signed: not signed (at most one per view)
		}
		var r vrhandoff.Readiness
		raw, err := hex.DecodeString(pv.Readiness)
		if err == nil {
			r, err = vrschema.DecodeReadiness(raw)
		}
		if err != nil || pv.Readiness == "" {
			return fmt.Errorf("%w: persisted readiness of view %d: %v", ErrMember, st.view, err)
		}
		return m.release(st, r)
	}
	body := st.body
	cs, err := m.commitments(st)
	if err != nil {
		return fmt.Errorf("%w: support commitments: %w", ErrMember, err)
	}
	if st.kOnly && len(cs) == 0 {
		return nil // a K member that is no successor has nothing else to send: no rule needs its support
	}
	r, err := vrhandoff.SignReadiness(st.intent, *st.assembly, body, m.cfg.Self, st.trustBase, cs, m.cfg.RootSigner)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMember, err)
	}
	enc, err := r.Encode()
	if err != nil {
		return err
	}
	mi.Views = append(mi.Views, memberView{View: st.view, CandidateDigest: hex.EncodeToString(cd[:]), Readiness: hex.EncodeToString(enc)})
	if err := m.persist(); err != nil { // (intent, view, candidate digest) is durable before the readiness is released
		mi.Views = mi.Views[:len(mi.Views)-1]
		return fmt.Errorf("%w: persisting the signed view: %w", ErrMember, err)
	}
	m.log().Info("VR handoff member: readiness", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view, "commitments", len(cs))
	m.lastRd = time.Time{}
	return m.release(st, r)
}

// release offers a signed readiness to this node's own service and re-sends it until the intent's certificate is complete.
func (m *Member) release(st memberState, r vrhandoff.Readiness) error {
	if !st.readyHeld {
		if o, _, err := m.svc.Offer(m.cfg.Self, Message{Readiness: &r}); o == Refused {
			return fmt.Errorf("%w: this node's own readiness is refused: %w", ErrMember, err)
		}
	}
	if !st.complete && m.cfg.Now().Sub(m.lastRd) >= ResendEvery {
		m.lastRd = m.cfg.Now()
		m.send(Message{Readiness: &r})
	}
	return nil
}

// stage hands the verified candidate to the staging hook once per assembly.
func (m *Member) stage(st memberState, cd [32]byte) error {
	if m.cfg.Stage == nil || m.staged == cd {
		return nil
	}
	if err := m.cfg.Stage(Staged{Body: st.body, CandidateDigest: cd, Attempt: st.intent.Attempt, Identities: st.successors}); err != nil {
		return err
	}
	m.staged = cd
	m.log().Info("VR handoff member: candidate staged", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view, "body", fmt.Sprintf("%x", st.body.Identity()))
	return nil
}
