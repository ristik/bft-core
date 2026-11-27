package vrschema

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The handoff view protocol messages (design section 5.3.1a; Slot is the committed view number, as in design v3 section 6.3). Every message is
// CBOR toarray with 32-byte digests as byte strings. Every signature is a 65-byte abcrypto secp256k1 signature (SignBytes: SHA-256 of
// the signed bytes) by the sender's ROOT key, except a PoP, which the member's EVM key signs over evmassign.PoPMessage.

// ErrHandoff reports a malformed or unverifiable handoff message.
var ErrHandoff = errors.New("vrschema: invalid handoff message")

// IntentVersion is Intent.Version.
const IntentVersion = 1

// Source is stage 0.
type Source struct {
	_              struct{} `cbor:",toarray"`
	ResultID       []byte   `json:"resultId"`
	EVMBlockHash   []byte   `json:"evmBlockHash"`
	EVMBlockNumber uint64   `json:"evmBlockNumber"`
	CertRootRound  uint64   `json:"certRootRound"`
	OutputCommit   []byte   `json:"outputCommit"`
}

// Intent is stage 1. Candidate is the canonical encoding of the unsigned candidate v6 (PoPs empty, verdicts set).
type Intent struct {
	_                 struct{} `cbor:",toarray"`
	Version           uint64   `json:"version"`
	Network           uint64   `json:"network"`
	Genesis           []byte   `json:"genesis"`
	PredecessorBodyID []byte   `json:"predecessorBodyId"`
	Attempt           uint64   `json:"attempt"`
	AnchorRound       uint64   `json:"anchorRound"`
	Source            Source   `json:"source"`
	Candidate         []byte   `json:"candidate"`
}

func len32(bs ...[]byte) bool {
	for _, b := range bs {
		if len(b) != 32 {
			return false
		}
	}
	return true
}

// Encode is CBOR(["UNICITY_VR_HANDOFF_INTENT", intent]).
func (i Intent) Encode() ([]byte, error) {
	if i.Version != IntentVersion || !len32(i.Genesis, i.PredecessorBodyID, i.Source.ResultID, i.Source.EVMBlockHash, i.Source.OutputCommit) ||
		len(i.Candidate) == 0 || len(i.Candidate) > MaxCandidateBytes {
		return nil, fmt.Errorf("%w: intent shape", ErrHandoff)
	}
	return types.Cbor.Marshal([]any{IntentDomain, i})
}

// Digest is SHA-256 of Encode: the intentDigest every later message names.
func (i Intent) Digest() ([32]byte, error) {
	b, err := i.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// AnchorRound is max(source.certRootRound, attemptOpenRound).
func AnchorRound(certRootRound, attemptOpenRound uint64) uint64 {
	return max(certRootRound, attemptOpenRound)
}

// EarliestActivation is anchorRound + 16, an earliest bound only.
func EarliestActivation(anchorRound uint64) uint64 { return anchorRound + EarliestOffset }

// PoPOffer is stage 2: one sticky possession proof per (intent, member), signed by the member's EVM key over evmassign.PoPMessage.
type PoPOffer struct {
	_            struct{}      `cbor:",toarray"`
	IntentDigest []byte        `json:"intentDigest"`
	EVMNodeID    string        `json:"evmNodeId"`
	PoP          evmassign.PoP `json:"pop"`
}

// Assembly is stage 3, by assembler(order, Slot). Candidate is the canonical v6 encoding: the intent's unsigned candidate plus one PoP
// per successor member in EVM-node order.
type Assembly struct {
	_            struct{} `cbor:",toarray"`
	IntentDigest []byte   `json:"intentDigest"`
	Slot         uint64   `json:"slot"` // the committed view number
	Candidate    []byte   `json:"candidate"`
	Sig          []byte   `json:"sig"`
}

// SignedBytes is CBOR(["UNICITY_VR_HANDOFF_ASSEMBLY", 1, intentDigest, slot, sha256(candidate)]).
func (a Assembly) SignedBytes() ([]byte, error) {
	if !len32(a.IntentDigest) || len(a.Candidate) == 0 || len(a.Candidate) > MaxCandidateBytes {
		return nil, fmt.Errorf("%w: assembly shape", ErrHandoff)
	}
	cd := sha256.Sum256(a.Candidate)
	return types.Cbor.Marshal([]any{AssemblyDomain, uint64(1), a.IntentDigest, a.Slot, cd[:]})
}

// SupportCommitment is one rule-support commitment, signed by that binding's root key.
type SupportCommitment struct {
	_             struct{} `cbor:",toarray"`
	Network       uint64   `json:"network"`
	StakingID     []byte   `json:"stakingId"` // 32-byte big-endian VR id
	Generation    uint64   `json:"generation"`
	RootKeyHash   []byte   `json:"rootKeyHash"` // keccak256(rootKey), the member word
	BindingRef    []byte   `json:"bindingRef"`  // the registry binding ref of the signing member (root and EVM bindings and payee)
	RuleID        []byte   `json:"ruleId"`
	ReleaseDigest []byte   `json:"releaseDigest"`
	Sig           []byte   `json:"sig"`
}

// SignedBytes is CBOR(["UNICITY_VR_RULE_SUPPORT", 2, network, stakingID, generation, rootKeyHash, bindingRef, ruleId, releaseDigest]).
func (c SupportCommitment) SignedBytes() ([]byte, error) {
	if !len32(c.StakingID, c.RootKeyHash, c.BindingRef, c.RuleID, c.ReleaseDigest) {
		return nil, fmt.Errorf("%w: commitment shape", ErrHandoff)
	}
	return types.Cbor.Marshal([]any{RuleSupportDomain, uint64(2), c.Network, c.StakingID, c.Generation, c.RootKeyHash, c.BindingRef, c.RuleID, c.ReleaseDigest})
}

// Digest is SHA-256 of the commitment's full CBOR (signature included): the reference a Freeze carries for a committed table entry.
func (c SupportCommitment) Digest() ([32]byte, error) {
	b, err := types.Cbor.Marshal(c)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// RuleSupportDigest is SHA-256(CBOR(["UNICITY_VR_RULE_SUPPORT_SET", 1, commitments])) over one member's commitments in strictly
// ascending ruleId (an empty set is allowed when no rule is effective or latched).
func RuleSupportDigest(cs []SupportCommitment) ([32]byte, error) {
	for i := 1; i < len(cs); i++ {
		if bytes.Compare(cs[i-1].RuleID, cs[i].RuleID) >= 0 {
			return [32]byte{}, fmt.Errorf("%w: commitments not strictly ascending by ruleId", ErrHandoff)
		}
	}
	if cs == nil {
		cs = []SupportCommitment{}
	}
	b, err := types.Cbor.Marshal([]any{RuleSupportSetDomain, uint64(1), cs})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Readiness is stage 4, by one successor member (or, for rule support only, a K member).
type Readiness struct {
	_                 struct{}            `cbor:",toarray"`
	IntentDigest      []byte              `json:"intentDigest"`
	Slot              uint64              `json:"slot"` // the committed view number
	CandidateDigest   []byte              `json:"candidateDigest"`
	BodyID            []byte              `json:"bodyId"`
	RuleSupportDigest []byte              `json:"ruleSupportDigest"`
	Commitments       []SupportCommitment `json:"commitments"`
	Receipt           []byte              `json:"receipt"`      // q3format.EncodeReceipts of the singleton set {[nodeID, sig]} over ReceiptContext{..., CandidateDigest, BodyID, ...}
	TrustBaseSig      []byte              `json:"trustBaseSig"` // over the successor trust base derived from the intent
	EnvelopeSig       []byte              `json:"envelopeSig"`
}

// EnvelopeBytes is CBOR(["UNICITY_VR_READINESS", 1, intentDigest, slot, candidateDigest, bodyID, ruleSupportDigest, sha256(trustBaseSig)]).
func (r Readiness) EnvelopeBytes() ([]byte, error) {
	if !len32(r.IntentDigest, r.CandidateDigest, r.BodyID, r.RuleSupportDigest) || len(r.TrustBaseSig) == 0 {
		return nil, fmt.Errorf("%w: readiness shape", ErrHandoff)
	}
	tb := sha256.Sum256(r.TrustBaseSig)
	return types.Cbor.Marshal([]any{ReadinessDomain, uint64(1), r.IntentDigest, r.Slot, r.CandidateDigest, r.BodyID, r.RuleSupportDigest, tb[:]})
}

// ViewCertificate is what Freeze v5 carries: the assembly and exactly one readiness per successor member, in the order of the
// candidate's identities (ascending StakingID), every one naming the assembly's (intentDigest, slot, candidateDigest, bodyID).
type ViewCertificate struct {
	_         struct{}    `cbor:",toarray"`
	Assembly  Assembly    `json:"assembly"`
	Readiness []Readiness `json:"readiness"`
}

// CheckShape is the context and cardinality check of a certificate for the successor root node ids in identity order (ascending
// StakingID): exactly one readiness each, naming the assembly's context, with a consistent rule-support digest and a receipt that is the
// singleton set of that member's receipt. Signatures are verified by the caller against the intent's successor keys and trust base.
func (c ViewCertificate) CheckShape(successors []string, bodyID []byte) error {
	if len(c.Readiness) != len(successors) {
		return fmt.Errorf("%w: %d readiness for %d successors", ErrHandoff, len(c.Readiness), len(successors))
	}
	cd := sha256.Sum256(c.Assembly.Candidate)
	for i, r := range c.Readiness {
		if !bytes.Equal(r.IntentDigest, c.Assembly.IntentDigest) || r.Slot != c.Assembly.Slot || !bytes.Equal(r.CandidateDigest, cd[:]) ||
			!bytes.Equal(r.BodyID, bodyID) {
			return fmt.Errorf("%w: readiness %d does not match the assembly context", ErrHandoff, i)
		}
		rs, err := RuleSupportDigest(r.Commitments)
		if err != nil || !bytes.Equal(rs[:], r.RuleSupportDigest) {
			return fmt.Errorf("%w: readiness %d rule-support digest", ErrHandoff, i)
		}
		if _, err := ReadinessReceipt(r.Receipt, successors[i]); err != nil {
			return fmt.Errorf("readiness %d: %w", i, err)
		}
	}
	return nil
}

// RuleSupportEvidence is the Freeze v5 rule-support set: references to committed support-table entries (Digest of the committed
// commitment, strictly ascending), fresh commitments (strictly ascending by (stakingID, ruleId)), and this intent's K-member readiness,
// each naming one binding through its commitments, strictly ascending by that stakingID. Duplicates are refused by the strict order.
type RuleSupportEvidence struct {
	_          struct{}            `cbor:",toarray"`
	Refs       [][]byte            `json:"refs"`
	Fresh      []SupportCommitment `json:"fresh"`
	KReadiness []Readiness         `json:"kReadiness"`
}

// FreezeV5 is the Freeze companion v5. Witness is the retained witness over exactly one account (VR at the pinned address and code
// hash); the control carries its SHA-256.
type FreezeV5 struct {
	_           struct{}            `cbor:",toarray"`
	Candidate   []byte              `json:"candidate"` // canonical v6 bytes, equal to the certificate's Assembly.Candidate
	Certificate ViewCertificate     `json:"certificate"`
	RuleSupport RuleSupportEvidence `json:"ruleSupport"`
	Witness     []byte              `json:"witness"`
}

// FreezeVersion is the companion version.
const FreezeVersion = 5

// Encode is CBOR(["UNICITY_VR_FREEZE", 5, companion]).
func (f FreezeV5) Encode() ([]byte, error) {
	if !bytes.Equal(f.Candidate, f.Certificate.Assembly.Candidate) {
		return nil, fmt.Errorf("%w: freeze candidate is not the certified assembly's", ErrHandoff)
	}
	if err := f.RuleSupport.check(); err != nil {
		return nil, err
	}
	f = f.canonical()
	return types.Cbor.Marshal([]any{FreezeDomain, uint64(FreezeVersion), f})
}

// AssemblerOrder lists the incumbents ascending by SHA-256(intentDigest || utf8(nodeID)), ties (impossible for distinct ids) by nodeID.
func AssemblerOrder(intent [32]byte, incumbents []string) []string {
	type k struct {
		h  [32]byte
		id string
	}
	ks := make([]k, 0, len(incumbents))
	for _, id := range incumbents {
		ks = append(ks, k{sha256.Sum256(append(append([]byte{}, intent[:]...), id...)), id})
	}
	sort.Slice(ks, func(i, j int) bool {
		if c := bytes.Compare(ks[i].h[:], ks[j].h[:]); c != 0 {
			return c < 0
		}
		return ks[i].id < ks[j].id
	})
	out := make([]string, len(ks))
	for i, x := range ks {
		out[i] = x.id
	}
	return out
}

// Assembler is order[view mod n].
func Assembler(order []string, view uint64) string { return order[view%uint64(len(order))] }

// Sign signs bytes with a root (or EVM) key.
func Sign(s abcrypto.Signer, b []byte) ([]byte, error) { return s.SignBytes(b) }

// Verify checks a 65-byte abcrypto signature over bytes by a compressed key.
func Verify(key, sig, b []byte) error {
	v, err := abcrypto.NewVerifierSecp256k1(key)
	if err != nil {
		return err
	}
	return v.VerifyBytes(sig, b)
}

// HandoffViewReplay is everything the replay rule of control op 5 reads.
type HandoffViewReplay struct {
	IntentDerivable  bool   `json:"intentDerivable"` // the named intent is the derivable one and its source is still valid
	CommittedView    uint64 `json:"committedView"`
	BackoffAgrees    bool   `json:"backoffAgrees"`    // the backoff bookkeeping admits the view (ApplyBlock)
	PrepareCommitted bool   `json:"prepareCommitted"` // a Prepare is committed for the intent's attempt
	OpenUCTime       uint64 `json:"openUcTime"`       // openTime(view-1): committed UC timestamp of the block opening view-1 (view 0: the anchor)
	Level            uint8  `json:"level"`
	N                uint32 `json:"n"`
	InBlock          int    `json:"inBlock"` // HandoffView controls in the carrying block
}

// VerifyHandoffView is the replay rule: valid iff derivable, the next view, no committed Prepare, block UC time at least
// openTime(view-1) + T(level, view-1) (a never deadline is never met), and the only HandoffView of its block.
func VerifyHandoffView(r HandoffViewReplay, view uint64, blockUCTime uint64) error {
	switch {
	case !r.IntentDerivable:
		return errors.New("IntentNotDerivable")
	case r.CommittedView == ^uint64(0) || view != r.CommittedView+1 || !r.BackoffAgrees:
		return errors.New("NotNextView")
	case r.PrepareCommitted:
		return errors.New("PrepareCommitted")
	case r.InBlock != 1:
		return errors.New("NotSoleHandoffView")
	}
	at, never := Deadline(r.OpenUCTime, r.Level, view-1, r.N)
	if never || blockUCTime < at {
		return errors.New("BeforeReplayFloor")
	}
	return nil
}

// Bounds of the rule-support evidence: the support table is 16 members x 64 rules, K has at most 16 members.
const (
	MaxSupportRefs  = SupportMembers * SupportRules
	MaxSupportFresh = SupportMembers * SupportRules
	MaxKReadiness   = MaxCommittee
)

// KReadinessStakingID is the one stakingID every commitment of a K-member readiness names (a K readiness is evidence of exactly one
// binding, and carries at least one commitment).
func KReadinessStakingID(r Readiness) ([]byte, error) {
	if len(r.Commitments) == 0 {
		return nil, fmt.Errorf("%w: K readiness without commitments", ErrHandoff)
	}
	id := r.Commitments[0].StakingID
	for _, c := range r.Commitments[1:] {
		if !bytes.Equal(c.StakingID, id) {
			return nil, fmt.Errorf("%w: K readiness names two bindings", ErrHandoff)
		}
	}
	return id, nil
}

// check: refs are 32-byte digests strictly ascending (no duplicate), at most 1024; fresh commitments strictly ascending by
// (stakingID, ruleId), at most 1024; K readiness strictly ascending by the stakingID it names (one per K member), at most 16.
func (e RuleSupportEvidence) check() error {
	if len(e.Refs) > MaxSupportRefs || len(e.Fresh) > MaxSupportFresh || len(e.KReadiness) > MaxKReadiness {
		return fmt.Errorf("%w: rule-support evidence bounds", ErrOversize)
	}
	for i, r := range e.Refs {
		if len(r) != 32 {
			return fmt.Errorf("%w: rule-support reference %d", ErrHandoff, i)
		}
		if i > 0 && bytes.Compare(e.Refs[i-1], r) >= 0 {
			return fmt.Errorf("%w: rule-support references not strictly ascending", ErrHandoff)
		}
	}
	for i := 1; i < len(e.Fresh); i++ {
		a, b := e.Fresh[i-1], e.Fresh[i]
		if k := bytes.Compare(a.StakingID, b.StakingID); k > 0 || (k == 0 && bytes.Compare(a.RuleID, b.RuleID) >= 0) {
			return fmt.Errorf("%w: fresh commitments not strictly ascending", ErrHandoff)
		}
	}
	var prev []byte
	for i, r := range e.KReadiness {
		id, err := KReadinessStakingID(r)
		if err != nil {
			return err
		}
		if i > 0 && bytes.Compare(prev, id) >= 0 {
			return fmt.Errorf("%w: K readiness not strictly ascending by stakingID", ErrHandoff)
		}
		prev = id
	}
	return nil
}

func (r Readiness) canonical() Readiness {
	if r.Commitments == nil {
		r.Commitments = []SupportCommitment{}
	}
	return r
}

func (e RuleSupportEvidence) canonical() RuleSupportEvidence {
	if e.Refs == nil {
		e.Refs = [][]byte{}
	}
	if e.Fresh == nil {
		e.Fresh = []SupportCommitment{}
	}
	ks := make([]Readiness, len(e.KReadiness))
	for i, r := range e.KReadiness {
		ks[i] = r.canonical()
	}
	e.KReadiness = ks
	return e
}

func (c ViewCertificate) canonical() ViewCertificate {
	rs := make([]Readiness, len(c.Readiness))
	for i, r := range c.Readiness {
		rs[i] = r.canonical()
	}
	c.Readiness = rs
	return c
}

func (f FreezeV5) canonical() FreezeV5 {
	f.Certificate = f.Certificate.canonical()
	f.RuleSupport = f.RuleSupport.canonical()
	return f
}

// strict decodes raw into v, then requires the canonical re-encoding (every list an array, never null) to be exactly raw.
func strict(raw []byte, v any, again func() ([]byte, error)) error {
	if err := types.Cbor.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrCanonical, err)
	}
	b, err := again()
	if err != nil {
		return err
	}
	if !bytes.Equal(b, raw) {
		return ErrCanonical
	}
	return nil
}

// Encode is the canonical CBOR of a readiness message.
func (r Readiness) Encode() ([]byte, error) {
	if _, err := r.EnvelopeBytes(); err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(r.canonical())
}

// DecodeReadiness accepts exactly the canonical encoding.
func DecodeReadiness(raw []byte) (Readiness, error) {
	var r Readiness
	err := strict(raw, &r, func() ([]byte, error) { return r.Encode() })
	return r, err
}

// Encode is the canonical CBOR of a view certificate.
func (c ViewCertificate) Encode() ([]byte, error) {
	for _, r := range c.Readiness {
		if _, err := r.EnvelopeBytes(); err != nil {
			return nil, err
		}
	}
	return types.Cbor.Marshal(c.canonical())
}

// DecodeViewCertificate accepts exactly the canonical encoding.
func DecodeViewCertificate(raw []byte) (ViewCertificate, error) {
	var c ViewCertificate
	err := strict(raw, &c, func() ([]byte, error) { return c.Encode() })
	return c, err
}

// DecodeIntent accepts exactly the canonical encoding of CBOR(["UNICITY_VR_HANDOFF_INTENT", intent]).
func DecodeIntent(raw []byte) (Intent, error) {
	var w struct {
		_      struct{} `cbor:",toarray"`
		Domain string
		Body   Intent
	}
	err := strict(raw, &w, func() ([]byte, error) {
		if w.Domain != IntentDomain {
			return nil, ErrCanonical
		}
		return w.Body.Encode()
	})
	return w.Body, err
}

// DecodeFreezeV5 accepts exactly the canonical companion encoding.
func DecodeFreezeV5(raw []byte) (FreezeV5, error) {
	var w struct {
		_       struct{} `cbor:",toarray"`
		Domain  string
		Version uint64
		Body    FreezeV5
	}
	err := strict(raw, &w, func() ([]byte, error) {
		if w.Domain != FreezeDomain || w.Version != FreezeVersion {
			return nil, ErrCanonical
		}
		return w.Body.Encode()
	})
	return w.Body, err
}

// EncodeReadinessReceipt is Readiness.Receipt: the q3format receipt-set codec over the singleton set of this member's receipt, so the
// Freeze side can merge the certificate's receipts into the set q3format.VerifyReceipts takes.
func EncodeReadinessReceipt(r q3format.Receipt) ([]byte, error) {
	return q3format.EncodeReceipts([]q3format.Receipt{r})
}

// ReadinessReceipt decodes Readiness.Receipt and requires exactly one receipt, named for nodeID.
func ReadinessReceipt(raw []byte, nodeID string) (q3format.Receipt, error) {
	rs, err := q3format.DecodeReceipts(raw)
	if err != nil {
		return q3format.Receipt{}, err
	}
	if len(rs) != 1 || rs[0].NodeID != nodeID {
		return q3format.Receipt{}, fmt.Errorf("%w: readiness receipt is not the singleton of %q", ErrHandoff, nodeID)
	}
	return rs[0], nil
}
