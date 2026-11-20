package vrschedule

import (
	"bytes"
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
	"github.com/unicitynetwork/bft-core/monitoring"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrrules"
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
//
// The member file (vr-member.json in the node's home) is a safety store like the root's safety store and the key store: it must be
// preserved across restarts, upgrades and backups. A node that loses it can sign a second assembly in a view it already signed, which is
// equivocation. A missing file is an empty state and is never an error, so deleting it is silent.
//
// Rule support (7.3): a member commits only to rules whose (ruleId, releaseDigest) this binary implements (ImplementedRules, empty for PoA
// today, or MemberConfig.Supports). It signs no readiness for a view while a rule the gate requires is not implemented here: it logs
// UpgradeRequired and waits, rather than counting as a supporter of a release it does not run.

// ImplementedRules are the rules (ruleId, releaseDigest) this binary implements, which its members may support (design 7.3, 7.4). It is empty
// today (the PoA generation has no activation rule); a release that implements a rule adds its pair here.
var ImplementedRules = map[[2]vrschema.Word]bool{}

// ErrMember reports a member step this node refuses.
var ErrMember = errors.New("vrschedule: member")

// ResendEvery is how often a member re-sends its possession proof until the view's assembly is held, and its readiness until the
// intent's certificate is complete (a peer that was not reachable or that restarted learns it; peers also pull it with GetStage).
const ResendEvery = 5 * time.Second

// Staged is what the member hands to the staging hook once it holds a verified assembly: the successor body, its candidate digest, the
// attempt and the candidate's identities (the successor's EVM validators and roots).
type Staged struct {
	Intent          [32]byte // the intent the candidate belongs to: a staging write is made only while it is the active one
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
	// EVMPoP is the typed possession-proof provider (VT-09, #1201): the local one (LocalPoP, the EVM key in this process) or the authority
	// one (AuthorityPoP: the key stays in its signing authority). It takes precedence over EVMSigner, which is shorthand for LocalPoP.
	EVMPoP PoPProvider
	// Path is the member's persisted state (sticky proofs, signed views); empty keeps it in memory only (tests).
	Path string
	// Send hands an outbound message to the transport; nil sends nothing.
	Send func(Message)
	// Supports reports whether this node implements an effective rule's release and supports it; nil: the compiled-in ImplementedRules
	// (a node supports nothing it does not run).
	Supports func(vrschema.Activation) bool
	// EVMNodeID is the node id of the EVM key (EVMSigner): the member refuses to sign a possession proof when it is not the EVM node id the
	// intent names for this node (a wrong --vr-evm-keys).
	EVMNodeID string
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
	Version int            `json:"version"`
	Intents []memberIntent `json:"intents"`
}

// memberFileVersion is the persisted format's version.
const memberFileVersion = 1

type memberIntent struct {
	Intent  string       `json:"intent"`
	Epoch   uint64       `json:"rootEpoch"`
	Attempt uint64       `json:"attempt"`
	PoP     string       `json:"pop,omitempty"`
	Views   []memberView `json:"views,omitempty"`
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
	warned   map[uint64]bool
	upgrade  map[vrschema.Word]bool
}

// NewMember loads the persisted state (a missing file is an empty state; a corrupt one is an error: a member must not forget a signed view).
func NewMember(svc *Service, cfg MemberConfig) (*Member, error) {
	if cfg.Self == "" || cfg.RootSigner == nil {
		return nil, fmt.Errorf("%w: a node id and a root key are required", ErrMember)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.EVMPoP == nil && cfg.EVMSigner != nil {
		cfg.EVMPoP = LocalPoP{Signer: cfg.EVMSigner}
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
			if err := m.validateFile(); err != nil {
				return nil, fmt.Errorf("%w: %s: %w", ErrMember, cfg.Path, err)
			}
		}
	}
	return m, nil
}

// validateFile checks the persisted anti-equivocation record in full before the member may sign anything (a node whose record is inconsistent
// refuses to start: it must not resume signing over a record it cannot trust, and a bad record is never silently dropped): the format
// version; canonical, unique intent ids; unique views; every saved readiness decodes canonically, names this node's receipt, agrees with the
// (intent, view, candidate digest) it is indexed under and carries a valid envelope signature of this node's own root key; every saved proof
// decodes and names its intent. (What needs the committed context, a proof's validity against the intent, is checked when the intent is
// current: an invalid proof is derived again then, never a readiness.)
func (m *Member) validateFile() error {
	if m.file.Version != memberFileVersion {
		return fmt.Errorf("member file version %d, want %d", m.file.Version, memberFileVersion)
	}
	ver, err := m.cfg.RootSigner.Verifier()
	if err != nil {
		return err
	}
	key, err := ver.MarshalPublicKey()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, mi := range m.file.Intents {
		d, err := hex.DecodeString(mi.Intent)
		if err != nil || len(d) != 32 || hex.EncodeToString(d) != mi.Intent {
			return fmt.Errorf("intent %d: not a canonical 32-byte hex digest", i)
		}
		if seen[mi.Intent] {
			return fmt.Errorf("intent %x appears twice", d[:8])
		}
		seen[mi.Intent] = true
		if mi.PoP != "" {
			raw, err := hex.DecodeString(mi.PoP)
			var p vrhandoff.PoPOffer
			if err == nil {
				err = types.Cbor.Unmarshal(raw, &p)
			}
			if err != nil {
				return fmt.Errorf("intent %x: the saved possession proof does not decode: %w", d[:8], err)
			}
			if !bytes.Equal(p.IntentDigest, d) {
				return fmt.Errorf("intent %x: the saved possession proof is of another intent", d[:8])
			}
		}
		views := map[uint64]bool{}
		for _, v := range mi.Views {
			if views[v.View] {
				return fmt.Errorf("intent %x: view %d is recorded twice", d[:8], v.View)
			}
			views[v.View] = true
			cd, err := hex.DecodeString(v.CandidateDigest)
			if err != nil || len(cd) != 32 {
				return fmt.Errorf("intent %x view %d: the candidate digest is not 32 bytes of hex", d[:8], v.View)
			}
			raw, err := hex.DecodeString(v.Readiness)
			if err != nil || len(raw) == 0 {
				return fmt.Errorf("intent %x view %d: the saved readiness is not hex", d[:8], v.View)
			}
			r, err := vrschema.DecodeReadiness(raw)
			if err != nil {
				return fmt.Errorf("intent %x view %d: the saved readiness does not decode: %w", d[:8], v.View, err)
			}
			if !bytes.Equal(r.IntentDigest, d) || r.Slot != v.View || !bytes.Equal(r.CandidateDigest, cd) {
				return fmt.Errorf("intent %x view %d: the saved readiness is of another intent, view or candidate than its record", d[:8], v.View)
			}
			if rs, err := vrschema.RuleSupportDigest(r.Commitments); err != nil || !bytes.Equal(rs[:], r.RuleSupportDigest) {
				return fmt.Errorf("intent %x view %d: the saved readiness' rule-support digest is not its commitments'", d[:8], v.View)
			}
			receipt, err := vrschema.ReadinessReceipt(r.Receipt, m.cfg.Self)
			if err != nil || len(receipt.Signature) == 0 {
				return fmt.Errorf("intent %x view %d: the saved readiness is not this node's receipt: %v", d[:8], v.View, err)
			}
			env, err := r.EnvelopeBytes()
			if err != nil {
				return fmt.Errorf("intent %x view %d: %w", d[:8], v.View, err)
			}
			if err := vrschema.Verify(key, r.EnvelopeSig, env); err != nil {
				return fmt.Errorf("intent %x view %d: the saved readiness is not signed by this node's root key: %w", d[:8], v.View, err)
			}
		}
	}
	return nil
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
	m.file.Version = memberFileVersion
	raw, err := json.Marshal(m.file)
	if err != nil {
		return err
	}
	return writeDurable(m.cfg.Path, raw)
}

// memberMaxIntents bounds the file: intents of the current or a later (root epoch, attempt) are never evicted (a revived intent's signed
// views must survive); only strictly older ones go, and when the bound is still reached no further intent is recorded and the member signs
// nothing new (it never evicts a record that may matter).
const memberMaxIntents = 16

func (m *Member) intent(d [32]byte, epoch, attempt uint64) *memberIntent {
	h := hex.EncodeToString(d[:])
	for i := range m.file.Intents {
		if m.file.Intents[i].Intent == h {
			return &m.file.Intents[i]
		}
	}
	kept := m.file.Intents[:0]
	for _, x := range m.file.Intents {
		if x.Epoch < epoch || (x.Epoch == epoch && x.Attempt < attempt) {
			continue // strictly older than the intent in hand
		}
		kept = append(kept, x)
	}
	m.file.Intents = kept
	if len(m.file.Intents) >= memberMaxIntents {
		return nil // the record is full of intents that may still revive: no new signing until an operator has dealt with the file
	}
	m.file.Intents = append(m.file.Intents, memberIntent{Intent: h, Epoch: epoch, Attempt: attempt})
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
	intent    vrhandoff.Intent
	digest    [32]byte
	rootEpoch uint64
	self      evmassign.Identity
	successor bool
	kOnly     bool // a K member that is no successor: it sends readiness for rule support only
	popHeld   bool
	view      uint64
	prepared  bool
	complete  bool
	assembly  *vrhandoff.Assembly
	body      q3format.BodyV3
	candidate [32]byte
	trustBase []byte
	readyHeld bool
	// the assembly and body of the retained certificate once a Prepare is committed (the staging of a node that learns of it only then)
	prepAssembly *vrhandoff.Assembly
	prepBody     q3format.BodyV3
	schedule     []vrschema.Activation
	table        vradmit.SupportTable
	successors   []evmassign.Identity
	// tok names the committed state this snapshot was taken over: a decision to sign or send is released only while it still holds
	tok stateToken
}

func (s *Service) memberState(self string) (memberState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if st == nil {
		return memberState{}, false
	}
	ms := memberState{intent: st.d.Intent, digest: st.digest, rootEpoch: st.d.RootEpoch, view: st.view, prepared: st.prepared, complete: st.iret != nil,
		trustBase: st.trustBase, schedule: s.sch, table: s.tab, successors: st.successors, tok: s.tokenLocked()}
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
	if st.prepared && st.iret != nil {
		a := st.iret.Certificate.Assembly
		ms.prepAssembly, ms.prepBody = &a, st.iret.Body
	}
	if vs := st.views[st.view]; vs != nil {
		if vs.assembly != nil {
			a := *vs.assembly
			ms.assembly, ms.body, ms.candidate = &a, vs.body, vs.candidate
		}
		_, ms.readyHeld = vs.readiness[self]
	}
	return ms, true
}

// stateToken names the committed state a member's decision was made over: the intent's state, its committed view and its support basis. A
// decision to sign or to send is released only while the service is still in exactly that state and no Prepare is committed.
type stateToken struct {
	st       *intentState
	view     uint64
	basisVer uint64
}

func (s *Service) tokenLocked() stateToken {
	return stateToken{st: s.cur, view: s.cur.view, basisVer: s.cur.basisVer}
}

func (s *Service) tokenValidLocked(t stateToken) bool {
	return t.st != nil && s.cur == t.st && t.st.view == t.view && !t.st.prepared && t.st.basisVer == t.basisVer
}

func (s *Service) tokenValid(t stateToken) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenValidLocked(t)
}

var errStaleState = errors.New("vrschedule: the committed state moved on")

// releaseOwn admits this node's own message into the service and reports whether it may be sent, atomically with the committed state it was
// decided over: under the service's lock it re-checks the token (the intent, its committed view, no Prepare, the support basis) and admits the
// message without verifying it again (the member verified what it signed). Only a retained or an already held message may be sent; a
// dropped, buffered or refused one never is. The follow-up work (this node's own assembly) runs after the lock is released. The transport
// send itself stays outside the lock (the transport reads the service's members): a commit that lands between this check and the send leaves a
// message in flight, as any sent message may be.
func (s *Service) releaseOwn(t stateToken, self string, m Message) (Outcome, error) {
	s.mu.Lock()
	if !s.tokenValidLocked(t) {
		s.mu.Unlock()
		return Dropped, errStaleState
	}
	j := s.prepareLocked(self, m)
	o, err := j.Outcome, j.Err
	var f followUp
	if j.Verify != nil {
		o, err = s.applyLocked(j, nil)
		if o == Retained {
			f = s.followLocked()
		}
	}
	s.mu.Unlock()
	s.finish(f)
	return o, err
}

// sendable is whether an outcome of releaseOwn lets the message go out.
func sendable(o Outcome) bool { return o == Retained || o == Duplicate }

// Step does whatever the member owes in the state its service holds now; it is idempotent and cheap, called after every committed update,
// every retained message and on a timer. It returns the first error of its steps (logged by the caller; a later Step retries).
func (m *Member) Step() error {
	st, ok := m.svc.memberState(m.cfg.Self)
	if !ok || !(st.successor || st.kOnly) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if st.prepared {
		// a Prepare is committed: nothing is signed any more, but a successor that learns the certificate's assembly only now (it restarted, or
		// joined late) still stages it, for the pre-connection and the in-process switch
		if st.successor && st.prepAssembly != nil {
			cd := sha256.Sum256(st.prepAssembly.Candidate)
			if err := m.stage(st, st.prepBody, cd); err != nil {
				m.log().Warn("VR handoff member: staging the prepared candidate failed", "error", err)
			}
		}
		return nil
	}
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

// stepPoP: stage 2. One proof per (intent, member), signed once, verified, persisted, kept in the service and re-sent until the view's
// assembly is held. A restarted member re-offers its persisted proof to its fresh service. A proof is never persisted before it verifies, and
// a persisted one that does not verify (an older wrong key) is derived again: only the proof is replaced, never a signed view.
func (m *Member) stepPoP(st memberState) error {
	mi := m.intent(st.digest, st.rootEpoch, st.intent.Attempt)
	if mi == nil {
		return fmt.Errorf("%w: the member file holds the bound of intents that may still revive: nothing new is recorded or signed", ErrMember)
	}
	var p vrhandoff.PoPOffer
	have := false
	if mi.PoP != "" {
		raw, err := hex.DecodeString(mi.PoP)
		if err == nil {
			err = types.Cbor.Unmarshal(raw, &p)
		}
		if err == nil {
			err = vrhandoff.VerifyPoP(st.intent, p)
		}
		if err == nil && p.EVMNodeID != st.self.EVMNodeID {
			err = fmt.Errorf("the saved proof is of EVM node %s, not this member's %s", p.EVMNodeID, st.self.EVMNodeID)
		}
		if err != nil {
			m.log().Warn("VR handoff member: the persisted possession proof does not verify; it is derived again", "error", err)
			mi.PoP = ""
		} else {
			have = true
		}
	}
	if !have {
		if m.cfg.EVMPoP == nil {
			if !m.noEVMKey {
				m.noEVMKey = true
				m.log().Warn("VR handoff member: this node holds no EVM key, so it cannot send its possession proof", "intent", fmt.Sprintf("%x", st.digest[:8]))
			}
			return nil
		}
		if m.cfg.EVMNodeID != "" && m.cfg.EVMNodeID != st.self.EVMNodeID {
			return fmt.Errorf("%w: the EVM key given (--vr-evm-keys) is node %s, the intent names %s as this node's EVM node", ErrMember, m.cfg.EVMNodeID, st.self.EVMNodeID)
		}
		var err error
		if p, err = m.offerPoP(st); err != nil {
			return fmt.Errorf("%w: possession proof: %w", ErrMember, err)
		}
		if err := vrhandoff.VerifyPoP(st.intent, p); err != nil {
			return fmt.Errorf("%w: the possession proof of the EVM key given does not verify against the intent: %w", ErrMember, err)
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
		m.log().Info("VR handoff member: possession proof", "intent", fmt.Sprintf("%x", st.digest[:8]), "evm", st.self.EVMNodeID, monitoring.Event(monitoring.EvVRMemberPossession))
	}
	// released only over the committed state this step started from, and sent only if the service admitted it (or already holds it)
	o, err := m.svc.releaseOwn(st.tok, m.cfg.Self, Message{PoP: &p})
	if errors.Is(err, errStaleState) {
		return nil // the committed state moved on: the next step starts from the new one (the proof is persisted, sticky)
	}
	if !sendable(o) {
		return fmt.Errorf("%w: this node's own possession proof is not admitted (%s): %v", ErrMember, o, err)
	}
	if st.assembly == nil && m.cfg.Now().Sub(m.lastPoP) >= ResendEvery {
		m.lastPoP = m.cfg.Now()
		m.send(Message{PoP: &p})
	}
	return nil
}

// supports reports whether this node implements and supports a rule's release: its own Supports, else the compiled-in ImplementedRules.
func (m *Member) supports(a vrschema.Activation) bool {
	if m.cfg.Supports != nil {
		return m.cfg.Supports(a)
	}
	// rule support decides; the release digest is advisory (design section 7.4): a rule of this binary's compiled-in set (vrrules) is supported
	// whatever release digest the schedule names
	return vrrules.Known().Has(a.RuleID) || ImplementedRules[[2]vrschema.Word{a.RuleID, a.ReleaseDigest}]
}

// commitments are the support commitments of every effective or latched rule the gate needs for a successor of this root epoch (strictly
// ascending by rule id), by this node's root key. A rule this node does not support is reported in missing: a successor signs no readiness
// while one is missing (it would burn its one signature of the view on a readiness the gate refuses, and claim a release it does not run).
func (m *Member) commitments(st memberState) (cs []vrhandoff.SupportCommitment, missing []vrschema.Activation, err error) {
	for _, a := range vradmit.RequiredRules(st.schedule, st.rootEpoch+1) {
		if !m.supports(a) {
			missing = append(missing, a)
			continue
		}
		c, err := vrhandoff.SignCommitment(st.intent.Network, st.self, a.RuleID, a.ReleaseDigest, m.cfg.RootSigner)
		if err != nil {
			return nil, nil, err
		}
		cs = append(cs, c)
	}
	return cs, missing, nil
}

// stepReadiness: stage 4, over the verified assembly of the committed current view.
func (m *Member) stepReadiness(st memberState) error {
	mi := m.intent(st.digest, st.rootEpoch, st.intent.Attempt)
	if mi == nil {
		return fmt.Errorf("%w: the member file holds the bound of intents that may still revive: nothing new is recorded or signed", ErrMember)
	}
	cd := sha256.Sum256(st.assembly.Candidate)
	if pv := mi.view(st.view); pv != nil {
		// a persisted view is never signed again; its readiness is re-sent and re-offered
		var r vrhandoff.Readiness
		raw, err := hex.DecodeString(pv.Readiness)
		if err == nil && pv.Readiness != "" {
			r, err = vrschema.DecodeReadiness(raw)
		} else if err == nil {
			err = errors.New("empty")
		}
		if err != nil {
			return fmt.Errorf("%w: persisted readiness of view %d: %w", ErrMember, st.view, err)
		}
		if pv.CandidateDigest != hex.EncodeToString(cd[:]) {
			// another assembly of a view this member already signed: not signed (at most one per view), and not staged; the readiness it
			// signed is still sent to the peers that hold that assembly. This is the evidence of an equivocating assembler, or of a revived state.
			if !m.warned[st.view] {
				if m.warned == nil {
					m.warned = map[uint64]bool{}
				}
				m.warned[st.view] = true
				m.log().Warn("VR handoff member: the service holds another assembly of a view this member signed; nothing new is signed and nothing is sent for it",
					"intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view, "signed", pv.CandidateDigest[:16], "held", hex.EncodeToString(cd[:8]))
			}
			return nil // nothing is admitted or sent for it: a readiness is sent only over the assembly this node's service holds
		}
		if err := m.release(st, r); err != nil {
			return err
		}
		if st.successor && m.svc.tokenValid(st.tok) {
			if err := m.stage(st, st.body, cd); err != nil {
				m.log().Warn("VR handoff member: staging the candidate failed", "error", err)
			}
		}
		return nil
	}
	body := st.body
	cs, missing, err := m.commitments(st)
	if err != nil {
		return fmt.Errorf("%w: support commitments: %w", ErrMember, err)
	}
	if len(missing) > 0 {
		if st.successor {
			for _, a := range missing {
				if !m.upgrade[a.RuleID] {
					if m.upgrade == nil {
						m.upgrade = map[vrschema.Word]bool{}
					}
					m.upgrade[a.RuleID] = true
					m.log().Warn("VR handoff member: UpgradeRequired: the committed schedule holds a rule this binary does not implement; this node signs no readiness (it does not support it)",
						"ruleId", fmt.Sprintf("%x", a.RuleID[:8]), "releaseDigest", fmt.Sprintf("%x", a.ReleaseDigest[:8]), "rootEpoch", a.RootEpoch, monitoring.Event(monitoring.EvVRUpgradeRequired))
				}
			}
			return nil
		}
		// a K member that is no successor sends what it supports: nothing else is asked of it
	}
	if st.kOnly && len(cs) == 0 {
		return nil // a K member that is no successor has nothing else to send: no rule needs its support
	}
	// The decision, the signature and the durable record are one step, serialized with the committed-state transition: the service's lock is
	// held from the state check to the end of the write, so no committed update (a view advancing, an intent dying, a Prepare, a support
	// basis change) lands between the check and the record, and no signing call of the old state happens after the update. The signing, the
	// verification and the write touch no service state, so holding the lock across them cannot deadlock; the committed update waits for them
	// (a signature and one fsync).
	var r vrhandoff.Readiness
	var cfgErr error
	valid, err := m.svc.underToken(st.tok, func() error {
		var err error
		if r, err = vrhandoff.SignReadiness(st.intent, *st.assembly, body, m.cfg.Self, st.trustBase, cs, m.cfg.RootSigner); err != nil {
			return fmt.Errorf("%w: %w", ErrMember, err)
		}
		// what is made durable verifies exactly as every root will judge it
		if err := vrhandoff.VerifyReadiness(st.intent, *st.assembly, body, st.self, st.trustBase, r); err != nil {
			cfgErr = fmt.Errorf("%w: this node's own readiness does not verify: %w", ErrMember, err)
			return cfgErr
		}
		if st.successor {
			if err := vradmit.VerifySuccessorSupport(st.schedule, st.rootEpoch+1, st.intent.Network, st.table, st.self, r.Commitments); err != nil {
				cfgErr = fmt.Errorf("%w: this node's own readiness lacks the support the gate needs: %w", ErrMember, err)
				return cfgErr
			}
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
		return nil
	})
	if !valid {
		return nil // the committed state moved on since this step's snapshot: nothing was signed over it
	}
	if err != nil {
		return err
	}
	m.log().Info("VR handoff member: readiness", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view, "commitments", len(cs), monitoring.Event(monitoring.EvVRMemberReady))
	m.lastRd = time.Time{}
	if err := m.release(st, r); err != nil {
		return err
	}
	if st.successor && m.svc.tokenValid(st.tok) {
		if err := m.stage(st, st.body, cd); err != nil {
			m.log().Warn("VR handoff member: staging the candidate failed", "error", err)
		}
	}
	return nil
}

// underToken runs fn while the service holds exactly the state tok names (the intent, its committed view, no Prepare, the support basis),
// serialized with every committed-state update: it reports false without running fn when the state moved on. fn must not call back into the
// service.
func (s *Service) underToken(t stateToken, fn func() error) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tokenValidLocked(t) {
		return false, nil
	}
	return true, fn()
}

// SuccessorState is the current intent, its committed view and whether self is one of its successors, read in one snapshot (an incumbent or a
// K member that is no successor is not one).
func (s *Service) SuccessorState(self string) (intent [32]byte, view uint64, successor, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return intent, 0, false, false
	}
	_, successor = s.cur.byRoot[self]
	return s.cur.digest, s.cur.view, successor, true
}

// ExchangeOpen is whether this root's readiness exchange is still open, so that it keeps pulling stage sets: while no certificate is held, or
// one is held but the Prepare plan still waits for K support. After a committed Prepare it is open only for a root that does not hold the
// certificate (it needs recovery), never for one that does.
func (s *Service) ExchangeOpen() bool {
	s.mu.Lock()
	st := s.cur
	if st == nil {
		s.mu.Unlock()
		return false
	}
	prepared, held := st.prepared, st.iret != nil
	s.mu.Unlock()
	if prepared {
		return !held
	}
	if !held {
		return true
	}
	_, ready := s.Plan()
	return !ready
}

// exchangePending is whether the readiness exchange is still open for this member. A K member that is no successor re-sends its support until
// a Prepare is committed or the intent changes: it cannot know whether the other roots hold it (its own plan becoming ready says nothing of
// theirs), and a Prepare ends every step. A successor stops once its own certificate is complete and its plan holds the K support (the stage
// pull recovers what others miss).
func (m *Member) exchangePending(st memberState) bool {
	if st.kOnly || !st.complete {
		return true
	}
	_, ready := m.svc.Plan()
	return !ready
}

// verifyOwn verifies a readiness as every root will judge it under the committed state of the snapshot: the envelope, receipt and
// commitments over the held assembly, body and trust base, and the support the gate needs of a successor.
func (m *Member) verifyOwn(st memberState, r vrhandoff.Readiness) error {
	if st.assembly == nil {
		return errors.New("no assembly is held")
	}
	if err := vrhandoff.VerifyReadiness(st.intent, *st.assembly, st.body, st.self, st.trustBase, r); err != nil {
		return err
	}
	if st.successor {
		return vradmit.VerifySuccessorSupport(st.schedule, st.rootEpoch+1, st.intent.Network, st.table, st.self, r.Commitments)
	}
	return vradmit.CommitmentsInScope(st.schedule, st.intent.Network, r.Commitments)
}

// release admits a signed readiness into this node's own service and sends it, atomically with the committed state it was decided over: a
// state that moved on suppresses the release (the durable record stays), and a message the local service did not admit is never sent. The
// readiness is verified in full under the current committed state first, a saved one included: a readiness the current state does not verify
// (altered bytes, a support basis that changed since it was signed) is never admitted or sent. It is re-sent until the exchange is settled:
// the successors' certificate is complete AND the Prepare plan holds the K support it waits for (a K member's support can come after the
// certificate), or a Prepare is committed.
func (m *Member) release(st memberState, r vrhandoff.Readiness) error {
	if err := m.verifyOwn(st, r); err != nil {
		m.log().Warn("VR handoff member: a readiness this node signed does not verify under the current committed state; it is not released",
			"intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view, "error", err)
		return nil
	}
	o, err := m.svc.releaseOwn(st.tok, m.cfg.Self, Message{Readiness: &r})
	if errors.Is(err, errStaleState) {
		m.log().Debug("VR handoff member: the committed state moved on; the signed readiness is kept, not released", "view", st.view)
		return nil
	}
	if !sendable(o) {
		return fmt.Errorf("%w: this node's own readiness is not admitted (%s): %v", ErrMember, o, err)
	}
	if m.exchangePending(st) && m.cfg.Now().Sub(m.lastRd) >= ResendEvery {
		m.lastRd = m.cfg.Now()
		m.log().Debug("VR handoff member: readiness sent", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view)
		m.send(Message{Readiness: &r})
	}
	return nil
}

// stage hands the verified candidate to the staging hook once per assembly.
func (m *Member) stage(st memberState, body q3format.BodyV3, cd [32]byte) error {
	if m.cfg.Stage == nil || m.staged == cd {
		return nil
	}
	if err := m.cfg.Stage(Staged{Intent: st.digest, Body: body, CandidateDigest: cd, Attempt: st.intent.Attempt, Identities: st.successors}); err != nil {
		return err
	}
	m.staged = cd
	m.log().Info("VR handoff member: candidate staged", "intent", fmt.Sprintf("%x", st.digest[:8]), "view", st.view, "body", fmt.Sprintf("%x", body.Identity()), monitoring.Event(monitoring.EvVRMemberStaged))
	return nil
}
