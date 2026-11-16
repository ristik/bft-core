package vrschema

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
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
	RuleID        []byte   `json:"ruleId"`
	ReleaseDigest []byte   `json:"releaseDigest"`
	Sig           []byte   `json:"sig"`
}

// SignedBytes is CBOR(["UNICITY_VR_RULE_SUPPORT", 1, network, stakingID, generation, rootKeyHash, ruleId, releaseDigest]).
func (c SupportCommitment) SignedBytes() ([]byte, error) {
	if !len32(c.StakingID, c.RootKeyHash, c.RuleID, c.ReleaseDigest) {
		return nil, fmt.Errorf("%w: commitment shape", ErrHandoff)
	}
	return types.Cbor.Marshal([]any{RuleSupportDomain, uint64(1), c.Network, c.StakingID, c.Generation, c.RootKeyHash, c.RuleID, c.ReleaseDigest})
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
	Receipt           []byte              `json:"receipt"`      // q3format receipt over ReceiptContext{..., CandidateDigest, BodyID, ...}, unchanged format
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

// CheckShape is the context and cardinality check of a certificate for `successors` members (signatures and receipts are verified by
// the caller against the intent's successor keys and trust base).
func (c ViewCertificate) CheckShape(successors int, bodyID []byte) error {
	if len(c.Readiness) != successors {
		return fmt.Errorf("%w: %d readiness for %d successors", ErrHandoff, len(c.Readiness), successors)
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
	}
	return nil
}

// RuleSupportEvidence is the Freeze v5 rule-support set: references to committed support-table entries (Digest of the committed
// commitment, ascending), fresh commitments (ascending by (stakingID, ruleId)), and this intent's K-member readiness carrying
// commitments (ascending by envelope bytes).
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
	for i := 1; i < len(f.RuleSupport.Refs); i++ {
		if bytes.Compare(f.RuleSupport.Refs[i-1], f.RuleSupport.Refs[i]) >= 0 {
			return nil, fmt.Errorf("%w: rule-support references not strictly ascending", ErrHandoff)
		}
	}
	for i, r := range f.RuleSupport.Refs {
		if len(r) != 32 {
			return nil, fmt.Errorf("%w: rule-support reference %d", ErrHandoff, i)
		}
	}
	for i := 1; i < len(f.RuleSupport.Fresh); i++ {
		a, b := f.RuleSupport.Fresh[i-1], f.RuleSupport.Fresh[i]
		if k := bytes.Compare(a.StakingID, b.StakingID); k > 0 || (k == 0 && bytes.Compare(a.RuleID, b.RuleID) >= 0) {
			return nil, fmt.Errorf("%w: fresh commitments not strictly ascending", ErrHandoff)
		}
	}
	if f.RuleSupport.Refs == nil {
		f.RuleSupport.Refs = [][]byte{}
	}
	if f.RuleSupport.Fresh == nil {
		f.RuleSupport.Fresh = []SupportCommitment{}
	}
	if f.RuleSupport.KReadiness == nil {
		f.RuleSupport.KReadiness = []Readiness{}
	}
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
