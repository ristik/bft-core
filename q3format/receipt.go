package q3format

import (
	"bytes"
	"errors"
	"fmt"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

var (
	// ErrReceiptContext is returned when a receipt context is not the one of the body it is checked against.
	ErrReceiptContext = errors.New("q3format: readiness context does not match the body")
	// ErrReceiptMissing is returned when a successor member has no receipt.
	ErrReceiptMissing = errors.New("q3format: successor member without a readiness receipt")
	// ErrReceiptDuplicate is returned when a member has more than one receipt.
	ErrReceiptDuplicate = errors.New("q3format: duplicate readiness receipt")
	// ErrReceiptUnknown is returned for a receipt from a signer that is not a successor member.
	ErrReceiptUnknown = errors.New("q3format: readiness receipt from an unknown signer")
	// ErrReceiptSignature is returned for a receipt whose signature does not verify under the member's root key.
	ErrReceiptSignature = errors.New("q3format: invalid readiness receipt signature")
)

const (
	receiptDomain = "UNICITY_Q3_READINESS_V1"
	maxSignature  = 128
)

// ReceiptContext is what one readiness receipt is bound to: the chain (network and root genesis), the predecessor and
// attempt of the handoff, the candidate digest, the V3 body identity and the identity of the required protocol tuple. A
// receipt replayed for another candidate, attempt, body or tuple therefore does not verify. Receipts are witnesses outside
// the body identity.
type ReceiptContext struct {
	Network         uint64
	Genesis         [32]byte
	Predecessor     [32]byte
	Attempt         uint64
	CandidateDigest [32]byte
	BodyID          [32]byte
	Config          [32]byte
}

// ContextFor is the receipt context of body for a handoff attempt and candidate. The predecessor is the body's own.
func ContextFor(b BodyV3, attempt uint64, candidate [32]byte) ReceiptContext {
	c := ReceiptContext{Network: b.Network, Genesis: b.Config.Genesis, Attempt: attempt, CandidateDigest: candidate,
		BodyID: b.Identity(), Config: b.Config.Identity()}
	copy(c.Predecessor[:], b.PredecessorHash)
	return c
}

// Message is the exact bytes a successor member's root key signs, named for that member.
func (c ReceiptContext) Message(nodeID string) []byte {
	return enc(receiptDomain, uint64(1), c.Network, c.Genesis[:], c.Predecessor[:], c.Attempt, c.CandidateDigest[:], c.BodyID[:], c.Config[:], nodeID)
}

// Receipt is one successor member's signed readiness declaration. It is an accountable statement of co-hosted support, not an
// attestation.
type Receipt struct {
	NodeID    string
	Signature []byte
}

// SignReceipt signs the readiness of nodeID for c with its root key.
func SignReceipt(c ReceiptContext, nodeID string, signer abcrypto.Signer) (Receipt, error) {
	sig, err := signer.SignBytes(c.Message(nodeID))
	return Receipt{NodeID: nodeID, Signature: sig}, err
}

// VerifyReceipts requires c to be the context of b, then exactly one valid receipt from every successor member: a missing,
// duplicate or unknown signer, or a signature by another key, is refused.
func VerifyReceipts(b BodyV3, c ReceiptContext, receipts []Receipt) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if c != ContextFor(b, c.Attempt, c.CandidateDigest) {
		return ErrReceiptContext
	}
	members := make(map[string][]byte, len(b.Members))
	for _, m := range b.Members {
		members[m.NodeID] = m.ConsensusKey
	}
	seen := make(map[string]struct{}, len(receipts))
	for _, r := range receipts {
		key, ok := members[r.NodeID]
		if !ok {
			return fmt.Errorf("%w: %q", ErrReceiptUnknown, r.NodeID)
		}
		if _, dup := seen[r.NodeID]; dup {
			return fmt.Errorf("%w: %q", ErrReceiptDuplicate, r.NodeID)
		}
		seen[r.NodeID] = struct{}{}
		if !validSignature(key, c.Message(r.NodeID), r.Signature) {
			return fmt.Errorf("%w: %q", ErrReceiptSignature, r.NodeID)
		}
	}
	for _, m := range b.Members {
		if _, ok := seen[m.NodeID]; !ok {
			return fmt.Errorf("%w: %q", ErrReceiptMissing, m.NodeID)
		}
	}
	return nil
}

func validSignature(key, msg, sig []byte) bool {
	v, err := abcrypto.NewVerifierSecp256k1(key)
	return err == nil && v.VerifyBytes(sig, msg) == nil
}

func receiptItems(rs []Receipt) []any {
	out := make([]any, len(rs))
	for i, r := range rs {
		out[i] = []any{r.NodeID, r.Signature}
	}
	return out
}

// readReceipts reads receipts strictly ordered by node id, at most MaxMembers.
func readReceipts(r *reader) ([]Receipt, error) {
	a := r.array(MaxMembers)
	var out []Receipt
	for i := 0; i < a.len() && a.err == nil; i++ {
		e := a.sub(2)
		rc := Receipt{NodeID: e.text(maxText), Signature: e.bytes(-1, maxSignature)}
		if err := e.done(); err != nil {
			return nil, err
		}
		if i > 0 && bytes.Compare([]byte(out[i-1].NodeID), []byte(rc.NodeID)) >= 0 {
			return nil, fmt.Errorf("%w: receipts are not strictly ordered by node id", ErrFormat)
		}
		out = append(out, rc)
	}
	return out, a.err
}
