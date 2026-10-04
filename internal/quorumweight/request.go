package quorumweight

// Shard request quorum (Q2, briefs/q2-design.md sections 1 and 2): the EVM shard's request threshold floor(W/2)+1, the
// strict no-quorum (impossibility) test M+U < Q, and the immutable context that fixes which weights those are computed from.
// Root quorums keep Threshold (floor(2W/3)+1); the two are never substitutes. Production contexts are unit-weighted: the
// weighted EVM context is constructible but no production site builds one until the Q3 activation.

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"slices"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
)

const (
	// MaxMemberWeight bounds one EVM member's weight, 2^40.
	MaxMemberWeight uint64 = 1 << 40
	// MaxTotalWeight bounds the total weight of an EVM request context, 2^48.
	MaxTotalWeight uint64 = 1 << 48
)

var (
	// ErrWeightCap is returned for a member weight outside [1, MaxMemberWeight] or a total above MaxTotalWeight.
	ErrWeightCap = errors.New("request weight outside the allowed bounds")
	// ErrDuplicateKey is returned when two members of a request context share a signing key.
	ErrDuplicateKey = errors.New("duplicate request signing key")
	// ErrRequestContext is returned when a configuration does not match the context it is being bound to: the committed
	// configuration hash, the partition type or the policy.
	ErrRequestContext = errors.New("request context mismatch")
	// ErrCouplingRequired is returned for a type-8 weighted context built without coupling evidence.
	ErrCouplingRequired = errors.New("weighted EVM request context requires coupling evidence")
	// ErrInconsistentTally is returned when received/matching weights contradict each other or the total.
	ErrInconsistentTally = errors.New("inconsistent request tally")
)

// MajorityThreshold is the shard request threshold floor(total/2)+1 for a total weight of at least 1.
func MajorityThreshold(total uint64) (uint64, error) {
	if total == 0 {
		return 0, ErrZeroWeight
	}
	return total/2 + 1, nil // cannot overflow: total/2 < MaxUint64
}

// QuorumImpossible reports whether no group can ever reach the threshold given what has been received: with total weight W,
// received weight R (every signer once, across all groups) and the heaviest single group M, the remaining weight is
// U = W-R and the quorum is impossible exactly when M+U < Q, strictly (M+U == Q is still possible). It refuses R > W, M > R,
// a zero total and overflow; those are errors, never evidence of impossibility.
func QuorumImpossible(total, received, matching uint64) (bool, error) {
	q, err := MajorityThreshold(total)
	if err != nil {
		return false, err
	}
	if received > total || matching > received {
		return false, fmt.Errorf("%w: total=%d received=%d matching=%d", ErrInconsistentTally, total, received, matching)
	}
	best, err := Add(matching, total-received)
	if err != nil {
		return false, err
	}
	return best < q, nil
}

// RequestPolicy says how a request context counts votes. It is selected from the authenticated partition type and
// certified activation, never by a request.
type RequestPolicy uint8

const (
	// PolicyUnit is one vote per configured key (every aggregator, and every production EVM shard before activation).
	PolicyUnit RequestPolicy = iota + 1
	// PolicyEVMWeighted counts the coupled root weights mirrored into the EVM assignment.
	PolicyEVMWeighted
)

// Coupling is the authenticated root side of a coupled EVM assignment: the root epoch and body identity that authorise it,
// the root committee with its weights and the root->EVM bindings.
type Coupling struct {
	RootEpoch  uint64
	RootBodyID []byte
	Root       []evmassign.RootMember
	Bindings   []evmassign.Binding
}

// RequestContext is the immutable set of authenticated members, weights, total and threshold under which the requests of
// one shard round are counted. Build it with NewUnitRequestContext or NewWeightedRequestContext and never mutate it:
// accessors return copies.
type RequestContext struct {
	policy     RequestPolicy
	typeID     types.PartitionTypeID
	network    types.NetworkID
	partition  types.PartitionID
	shard      string // ShardID key, copied at construction
	shardEpoch uint64
	confHash   []byte
	rootEpoch  uint64
	rootBody   []byte
	ids        []string // sorted
	weights    map[string]uint64
	verifiers  map[string]abcrypto.Verifier
	total      uint64
	threshold  uint64
}

// NewUnitRequestContext builds the unit-weight context of pdr: every validator has exactly one vote whatever its Stake says
// (a Stake other than 1 is refused, not normalised). committedHash is the configuration hash the context must be bound to;
// pdr must hash to it under hashAlg.
func NewUnitRequestContext(pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash, committedHash []byte) (*RequestContext, error) {
	c, err := newContext(pdr, hashAlg, committedHash, PolicyUnit)
	if err != nil {
		return nil, err
	}
	for _, v := range pdr.Validators {
		if v == nil {
			return nil, fmt.Errorf("%w: missing member", ErrUnknownSigner)
		}
		if v.Stake != 1 {
			return nil, fmt.Errorf("%w: unit policy requires stake 1, validator %q has %d", ErrWeightCap, v.NodeID, v.Stake)
		}
	}
	return c.finish(pdr, func(v *types.NodeInfo) uint64 { return 1 }, 0, nil)
}

// NewWeightedRequestContext builds the weighted context of an EVM (partition type 8) configuration from its coupled root
// assignment. Each EVM member's weight is its Stake, which must mirror its bound root member (evmassign.ValidateCoupling);
// weights are in [1, MaxMemberWeight] and the total is at most MaxTotalWeight. Missing coupling evidence is
// ErrCouplingRequired and a non-EVM type is ErrRequestContext: a request cannot pick its own policy.
func NewWeightedRequestContext(pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash, committedHash []byte, coupling *Coupling) (*RequestContext, error) {
	c, err := newContext(pdr, hashAlg, committedHash, PolicyEVMWeighted)
	if err != nil {
		return nil, err
	}
	if pdr.PartitionTypeID != evmassign.EVMPartitionTypeID {
		return nil, fmt.Errorf("%w: weighted policy is for partition type %d, not %d", ErrRequestContext, evmassign.EVMPartitionTypeID, pdr.PartitionTypeID)
	}
	if coupling == nil || len(coupling.RootBodyID) == 0 {
		return nil, ErrCouplingRequired
	}
	if len(pdr.Validators) > evmassign.MaxValidators {
		return nil, fmt.Errorf("%w: %d validators", ErrWeightCap, len(pdr.Validators))
	}
	// member structure first: ValidateCoupling dereferences every validator
	seen := make(map[string]struct{}, len(pdr.Validators))
	for _, v := range pdr.Validators {
		if v == nil || v.NodeID == "" {
			return nil, fmt.Errorf("%w: missing member identity", ErrUnknownSigner)
		}
		if _, dup := seen[v.NodeID]; dup {
			// a repeated identity is also not a bijection with the root members
			return nil, fmt.Errorf("%w: %q: %w", ErrDuplicateSigner, v.NodeID, evmassign.ErrCoupling)
		}
		seen[v.NodeID] = struct{}{}
	}
	if err := evmassign.ValidateCoupling(coupling.Root, pdr, coupling.Bindings); err != nil {
		return nil, fmt.Errorf("coupled root assignment: %w", err)
	}
	return c.finish(pdr, func(v *types.NodeInfo) uint64 { return v.Stake }, coupling.RootEpoch, coupling.RootBodyID)
}

func newContext(pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash, committedHash []byte, policy RequestPolicy) (*RequestContext, error) {
	if pdr == nil {
		return nil, fmt.Errorf("%w: missing configuration", ErrRequestContext)
	}
	h, err := pdr.Hash(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("hashing configuration: %w", err)
	}
	if len(committedHash) == 0 || !bytes.Equal(h, committedHash) {
		return nil, fmt.Errorf("%w: configuration hashes to %x, committed %x", ErrRequestContext, h, committedHash)
	}
	return &RequestContext{
		policy:     policy,
		typeID:     pdr.PartitionTypeID,
		network:    pdr.NetworkID,
		partition:  pdr.PartitionID,
		shard:      pdr.ShardID.String(),
		shardEpoch: pdr.Epoch,
		confHash:   bytes.Clone(h),
	}, nil
}

func (c *RequestContext) finish(pdr *types.PartitionDescriptionRecord, weight func(*types.NodeInfo) uint64, rootEpoch uint64, rootBody []byte) (*RequestContext, error) {
	// an empty member set totals zero and is refused by MajorityThreshold below
	c.weights = make(map[string]uint64, len(pdr.Validators))
	c.verifiers = make(map[string]abcrypto.Verifier, len(pdr.Validators))
	keys := make(map[string]struct{}, len(pdr.Validators))
	var total uint64
	for _, v := range pdr.Validators {
		if v == nil || v.NodeID == "" {
			return nil, fmt.Errorf("%w: missing member identity", ErrUnknownSigner)
		}
		if _, dup := c.weights[v.NodeID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateSigner, v.NodeID)
		}
		if _, dup := keys[string(v.SigKey)]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, v.NodeID)
		}
		w := weight(v)
		if w == 0 {
			return nil, fmt.Errorf("%w: member %q", ErrZeroWeight, v.NodeID)
		}
		if w > MaxMemberWeight && c.policy == PolicyEVMWeighted {
			return nil, fmt.Errorf("%w: member %q weight %d", ErrWeightCap, v.NodeID, w)
		}
		sum, err := Add(total, w)
		if err != nil {
			return nil, err
		}
		if sum > MaxTotalWeight && c.policy == PolicyEVMWeighted {
			return nil, fmt.Errorf("%w: total weight above %d", ErrWeightCap, MaxTotalWeight)
		}
		// Built from a private copy of the key, never through NodeInfo.SigVerifier: that caches the verifier on the caller's
		// NodeInfo, so a key changed after an earlier call would leave this context verifying with another key than the
		// one it hashed and checked for duplicates.
		ver, err := abcrypto.NewVerifierSecp256k1(bytes.Clone(v.SigKey))
		if err != nil {
			return nil, fmt.Errorf("creating verifier for validator %q: %w", v.NodeID, err)
		}
		keys[string(v.SigKey)] = struct{}{}
		c.weights[v.NodeID], c.verifiers[v.NodeID], total = w, ver, sum
		c.ids = append(c.ids, v.NodeID)
	}
	slices.Sort(c.ids)
	q, err := MajorityThreshold(total)
	if err != nil {
		return nil, err
	}
	c.total, c.threshold, c.rootEpoch, c.rootBody = total, q, rootEpoch, bytes.Clone(rootBody)
	return c, nil
}

// Policy is how the context counts votes.
func (c *RequestContext) Policy() RequestPolicy { return c.policy }

// PartitionTypeID is the authenticated partition type the policy was selected for.
func (c *RequestContext) PartitionTypeID() types.PartitionTypeID { return c.typeID }

// ConfHash is the committed configuration hash the context is bound to.
func (c *RequestContext) ConfHash() []byte { return bytes.Clone(c.confHash) }

// ShardEpoch is the shard configuration epoch.
func (c *RequestContext) ShardEpoch() uint64 { return c.shardEpoch }

// RootEpoch and RootBodyID identify the coupled root assignment; both are zero/nil for a unit context.
func (c *RequestContext) RootEpoch() uint64  { return c.rootEpoch }
func (c *RequestContext) RootBodyID() []byte { return bytes.Clone(c.rootBody) }

// Identity is the cache key of the context: network, partition, shard, shard epoch, root epoch and body, configuration
// hash and policy. Two contexts with equal identity must be equal.
func (c *RequestContext) Identity() string {
	return fmt.Sprintf("%d/%d/%s/%d/%d/%x/%x/%d", c.network, c.partition, c.shard, c.shardEpoch, c.rootEpoch, c.rootBody, c.confHash, c.policy)
}

// MemberCount is the number of members; proof size limits count members, not weight.
func (c *RequestContext) MemberCount() int { return len(c.ids) }

// TotalWeight is W, the weight of every member including absent signers.
func (c *RequestContext) TotalWeight() uint64 { return c.total }

// Threshold is Q = floor(W/2)+1.
func (c *RequestContext) Threshold() uint64 { return c.threshold }

// SignerWeight is the weight of a member, or ErrUnknownSigner.
func (c *RequestContext) SignerWeight(id string) (uint64, error) {
	w, ok := c.weights[id]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnknownSigner, id)
	}
	return w, nil
}

// NodeIDs returns the sorted member identities.
func (c *RequestContext) NodeIDs() []string { return slices.Clone(c.ids) }

// Verifier is the signature verifier of a member, or ErrUnknownSigner.
func (c *RequestContext) Verifier(id string) (abcrypto.Verifier, error) {
	v, ok := c.verifiers[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSigner, id)
	}
	return v, nil
}

// QuorumReached reports whether a matching group of weight matching meets Q.
func (c *RequestContext) QuorumReached(matching uint64) bool { return Reached(matching, c.threshold) }

// QuorumImpossible is QuorumImpossible for this context's total weight.
func (c *RequestContext) QuorumImpossible(received, matching uint64) (bool, error) {
	return QuorumImpossible(c.total, received, matching)
}
