// Package quorumweight is the one checked implementation of root-quorum weight arithmetic (D3, ADR 0005): a quorum is a
// sum of the weights of unique authorised signers, accumulated with overflow refusal and compared with the threshold
// floor(2*W/3)+1. Every root quorum site decides through it instead of counting signatures or adding weights by hand.
package quorumweight

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	// ErrWeightOverflow is returned when a weight sum or threshold computation does not fit in uint64.
	ErrWeightOverflow = errors.New("quorum weight overflow")
	// ErrDuplicateSigner is returned when the same signer is counted twice.
	ErrDuplicateSigner = errors.New("duplicate quorum signer")
	// ErrUnknownSigner is returned for a signer that is not a member of the trust base.
	ErrUnknownSigner = errors.New("unknown quorum signer")
	// ErrInvalidSignature is returned when a signature in a certificate does not verify.
	ErrInvalidSignature = errors.New("invalid quorum signature")
	// ErrZeroWeight is returned for an empty member set or a zero total/threshold; a real quorum is at least 1.
	ErrZeroWeight = errors.New("zero quorum weight")
	// ErrQuorumNotReached is returned when the verified signer weight is below the threshold.
	ErrQuorumNotReached = errors.New("quorum not reached")
)

// notReached keeps the long-standing message of go-base's VerifyQuorumSignatures and matches ErrQuorumNotReached.
type notReached struct{ weight, threshold uint64 }

func (e notReached) Error() string {
	return fmt.Sprintf("quorum not reached, signed_votes=%d quorum_threshold=%d", e.weight, e.threshold)
}

func (e notReached) Is(target error) bool { return target == ErrQuorumNotReached }

// Add returns a+b, or ErrWeightOverflow.
func Add(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, ErrWeightOverflow
	}
	return a + b, nil
}

// Threshold is the root quorum threshold floor(2*total/3)+1 for a total weight of at least 1 (D3 section 3).
func Threshold(total uint64) (uint64, error) {
	if total == 0 {
		return 0, ErrZeroWeight
	}
	if total > math.MaxUint64/2 {
		return 0, ErrWeightOverflow
	}
	return 2*total/3 + 1, nil
}

// FaultyBound is the largest weight that may be Byzantine while a quorum is still safe: total - Threshold(total).
func FaultyBound(total uint64) (uint64, error) {
	t, err := Threshold(total)
	if err != nil {
		return 0, err
	}
	return total - t, nil // t <= total for every total >= 1
}

// TotalWeight sums the stake of the members with overflow refusal. Duplicate node ids and nil members are refused.
func TotalWeight(nodes []*types.NodeInfo) (uint64, error) {
	var tally Tally
	for _, n := range nodes {
		if n == nil {
			return 0, ErrUnknownSigner
		}
		if err := tally.Add(n.NodeID, n.Stake); err != nil {
			return 0, err
		}
	}
	if tally.Weight() == 0 {
		return 0, ErrZeroWeight
	}
	return tally.Weight(), nil
}

// Tally accumulates the weight of unique signers. The zero value is ready to use.
type Tally struct {
	seen   map[string]struct{}
	weight uint64
}

// Add counts signer once with the given weight. A repeat of the signer is ErrDuplicateSigner and an overflow is
// ErrWeightOverflow; in either case the tally is left unchanged.
func (t *Tally) Add(signer string, weight uint64) error {
	if _, dup := t.seen[signer]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateSigner, signer)
	}
	sum, err := Add(t.weight, weight)
	if err != nil {
		return err
	}
	if t.seen == nil {
		t.seen = make(map[string]struct{})
	}
	t.seen[signer] = struct{}{}
	t.weight = sum
	return nil
}

// Weight is the weight accumulated so far.
func (t *Tally) Weight() uint64 { return t.weight }

// Reached reports whether the accumulated weight meets a non-zero threshold.
func (t *Tally) Reached(threshold uint64) bool { return Reached(t.weight, threshold) }

// Reached reports whether weight meets a threshold. A zero threshold is never reached: a real threshold is at least 1.
func Reached(weight, threshold uint64) bool { return threshold != 0 && weight >= threshold }

// Verifier is the part of a root trust base that VerifySigned needs.
type Verifier interface {
	VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error)
	GetQuorumThreshold() uint64
}

type memberLister interface{ GetRootNodes() []*types.NodeInfo }

// VerifySigned is the D3 certificate check (docs/design/d3-weighted-consensus-trust-base.md section 3 and its v1
// compatibility rule): a signer that is not a member of the trust base rejects the certificate, no signer may repeat, the
// weights of the verified signatures are added with overflow refusal and the sum must reach the trust base threshold.
// As under v1, an invalid signature from a KNOWN member is skipped and carries no weight. It returns the verified
// signer weight.
func VerifySigned(tb Verifier, data []byte, signatures map[string]hex.Bytes) (uint64, error) {
	return verifySigned(tb, data, signatures, false)
}

// VerifySignedStrict is VerifySigned for the sites that always refused a certificate carrying any invalid signature
// (handoff proofs and authority, frontier replies): an invalid signature from a known member is ErrInvalidSignature.
func VerifySignedStrict(tb Verifier, data []byte, signatures map[string]hex.Bytes) (uint64, error) {
	return verifySigned(tb, data, signatures, true)
}

func verifySigned(tb Verifier, data []byte, signatures map[string]hex.Bytes, strict bool) (uint64, error) {
	threshold := tb.GetQuorumThreshold()
	if threshold == 0 {
		return 0, ErrZeroWeight
	}
	members := map[string]struct{}(nil)
	if l, ok := tb.(memberLister); ok {
		if nodes := l.GetRootNodes(); len(nodes) > 0 {
			members = make(map[string]struct{}, len(nodes))
			for _, n := range nodes {
				if n != nil {
					members[n.NodeID] = struct{}{}
				}
			}
		}
	}
	signers := make([]string, 0, len(signatures))
	for id := range signatures {
		signers = append(signers, id)
	}
	sort.Strings(signers) // deterministic error for a certificate with several bad signatures
	var tally Tally
	for _, id := range signers {
		stake, err := tb.VerifySignature(data, signatures[id], id)
		if err != nil {
			if members != nil {
				if _, ok := members[id]; !ok {
					return 0, fmt.Errorf("%w: %q", ErrUnknownSigner, id)
				}
			}
			if !strict {
				continue // v1 legacy acceptance: an invalid signature of a known member counts for nothing
			}
			return 0, fmt.Errorf("%w: signer %q: %w", ErrInvalidSignature, id, err)
		}
		if err := tally.Add(id, stake); err != nil {
			return 0, err
		}
	}
	if !tally.Reached(threshold) {
		return tally.Weight(), notReached{weight: tally.Weight(), threshold: threshold}
	}
	return tally.Weight(), nil
}

// Checked returns tb with VerifyQuorumSignatures replaced by VerifySigned, so that go-base verifiers that take a
// RootTrustBase (UnicityCertificate.Verify, UnicitySeal.Verify) decide through the checked arithmetic instead of
// go-base's unchecked sum. Only the production *RootTrustBaseV1 is wrapped; any other implementation (a test double)
// is returned unchanged.
func Checked(tb types.RootTrustBase) types.RootTrustBase {
	v1, ok := tb.(*types.RootTrustBaseV1)
	if !ok || v1 == nil {
		return tb
	}
	return checkedTrustBase{RootTrustBase: v1}
}

type checkedTrustBase struct{ types.RootTrustBase }

func (c checkedTrustBase) VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error {
	_, err := VerifySigned(c.RootTrustBase, data, signatures)
	return err
}

// VerifyTrustBase is RootTrustBaseV1.Verify with the signature quorum decided by VerifySigned: the structural link to
// prev (IsValid) and then the signatures of the previous epoch's validators (self-signed for the genesis epoch).
func VerifyTrustBase(r, prev *types.RootTrustBaseV1) error {
	if err := r.IsValid(prev); err != nil {
		return err
	}
	signer := prev // r.IsValid has refused a missing prev for every epoch above 1
	if r.Epoch == 1 {
		signer = r
	}
	sigBytes, err := r.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to get trust base sig bytes: %w", err)
	}
	if _, err := VerifySigned(signer, sigBytes, r.Signatures); err != nil {
		return fmt.Errorf("failed to verify signatures: %w", err)
	}
	return nil
}
