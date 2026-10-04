package types

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// ErrInvalidRequest is returned for a malformed certification request or proof: a nil request, a request of another
// shard, a proof whose reason does not match its requests.
var ErrInvalidRequest = errors.New("invalid certification request")

// RequestWeights is the vote weight view of one shard round (Q2 design section 2): who may vote, with what weight, and the
// threshold Q = floor(W/2)+1 over the total W of every member including absent signers. The production implementation is
// quorumweight.RequestContext; proof size limits count members, not weight.
type RequestWeights interface {
	MemberCount() int
	TotalWeight() uint64
	Threshold() uint64
	SignerWeight(id string) (uint64, error)
}

// withSentinels keeps err's text and additionally matches every sentinel with errors.Is.
type withSentinels struct {
	err       error
	sentinels []error
}

func (e withSentinels) Error() string   { return e.err.Error() }
func (e withSentinels) Unwrap() []error { return append([]error{e.err}, e.sentinels...) }

// RequestTally counts the certification requests of one shard round: every signer once across all groups, grouped by the
// size-inclusive request hash. It is the single implementation behind both buffer formation and proof verification, so
// the same vectors give the same decisions on both. Add is atomic: a refused request leaves the tally unchanged.
type RequestTally struct {
	w        RequestWeights
	signers  map[string]struct{}
	groups   map[[32]byte]uint64
	received uint64
	best     uint64
}

func NewRequestTally(w RequestWeights) *RequestTally {
	return &RequestTally{w: w, signers: make(map[string]struct{}), groups: make(map[[32]byte]uint64)}
}

// CloneWith is an independent copy counting with w from now on: a caller that has more to check after Add works on a clone
// and publishes it only when every check passed. The signers already counted are not reweighed.
func (t *RequestTally) CloneWith(w RequestWeights) *RequestTally {
	c := &RequestTally{w: w, signers: make(map[string]struct{}, len(t.signers)), groups: make(map[[32]byte]uint64, len(t.groups)), received: t.received, best: t.best}
	for k := range t.signers {
		c.signers[k] = struct{}{}
	}
	for k, v := range t.groups {
		c.groups[k] = v
	}
	return c
}

// Add counts signer once with its weight in group. An unknown signer is quorumweight.ErrUnknownSigner, a repeated one
// quorumweight.ErrDuplicateSigner and an overflow quorumweight.ErrWeightOverflow.
func (t *RequestTally) Add(signer string, group [32]byte) error {
	if _, dup := t.signers[signer]; dup {
		return fmt.Errorf("%w: %q", quorumweight.ErrDuplicateSigner, signer)
	}
	weight, err := t.w.SignerWeight(signer)
	if err != nil {
		return err
	}
	if weight == 0 {
		return fmt.Errorf("%w: signer %q", quorumweight.ErrZeroWeight, signer)
	}
	received, err := quorumweight.Add(t.received, weight)
	if err != nil {
		return err
	}
	matching, err := quorumweight.Add(t.groups[group], weight)
	if err != nil {
		return err
	}
	// everything is computed; only now is the tally changed
	t.signers[signer] = struct{}{}
	t.groups[group] = matching
	t.received = received
	t.best = max(t.best, matching)
	return nil
}

// GroupWeight is the weight of one request hash group.
func (t *RequestTally) GroupWeight(group [32]byte) uint64 { return t.groups[group] }

// Received is R, the weight of every counted signer.
func (t *RequestTally) Received() uint64 { return t.received }

// Matching is M, the weight of the heaviest single group (zero when empty).
func (t *RequestTally) Matching() uint64 { return t.best }

// Signers is the number of counted signers.
func (t *RequestTally) Signers() int { return len(t.signers) }

// Groups is the number of distinct request hashes.
func (t *RequestTally) Groups() int { return len(t.groups) }

// QuorumReached is M >= Q.
func (t *RequestTally) QuorumReached() bool { return quorumweight.Reached(t.best, t.w.Threshold()) }

// Validate refuses a context that cannot give a verdict: a threshold that is not the majority of a nonzero total, or a
// received weight above the total. It is checked before any verdict, quorum included, so that an inconsistent context
// never certifies.
func (t *RequestTally) Validate() error {
	q, total := t.w.Threshold(), t.w.TotalWeight()
	if total == 0 {
		return quorumweight.ErrZeroWeight
	}
	if q != total/2+1 {
		return fmt.Errorf("%w: threshold %d is not the majority of total weight %d", quorumweight.ErrInconsistentTally, q, total)
	}
	if t.received > total {
		return fmt.Errorf("%w: received weight %d above total %d", quorumweight.ErrInconsistentTally, t.received, total)
	}
	return nil
}

// QuorumImpossible is M + (W-R) < Q, strictly: M+U == Q is still possible. An inconsistent tally or total is an error,
// never evidence of impossibility.
func (t *RequestTally) QuorumImpossible() (bool, error) {
	if err := t.Validate(); err != nil {
		return false, err
	}
	return quorumweight.QuorumImpossible(t.w.TotalWeight(), t.received, t.best)
}
