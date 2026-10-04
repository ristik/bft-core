package partitions

import (
	"fmt"
	"maps"
	"slices"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

type (
	// TrustBase is the test adapter of a shard's members for request counting: it implements the weights interface the
	// request buffer and proof verification count with. NewPartitionTrustBase is unit-weighted like every production shard;
	// NewWeightedPartitionTrustBase gives the members explicit weights for the isolated weighted fixtures.
	TrustBase struct {
		partitionTrustBase map[string]abcrypto.Verifier
		weights            map[string]uint64
		identity           string
	}
)

func NewPartitionTrustBase(tb map[string]abcrypto.Verifier) *TrustBase {
	w := make(map[string]uint64, len(tb))
	for id := range tb {
		w[id] = 1
	}
	return &TrustBase{partitionTrustBase: tb, weights: w, identity: "unit"}
}

// NewWeightedPartitionTrustBase is a trust base whose member weights are the given ones; identity tags it like an
// assignment identity.
func NewWeightedPartitionTrustBase(identity string, weights map[string]uint64) *TrustBase {
	tb := make(map[string]abcrypto.Verifier, len(weights))
	for id := range weights {
		tb[id] = nil
	}
	return &TrustBase{partitionTrustBase: tb, weights: weights, identity: identity}
}

// MemberCount is the number of registered members.
func (v *TrustBase) MemberCount() int { return len(v.weights) }

// TotalWeight is the weight of every registered member.
func (v *TrustBase) TotalWeight() uint64 {
	var t uint64
	for _, w := range v.weights {
		t += w
	}
	return t
}

// Threshold is floor(W/2)+1.
func (v *TrustBase) Threshold() uint64 { return v.TotalWeight()/2 + 1 }

// SignerWeight is the weight of a member, ErrUnknownSigner for any other.
func (v *TrustBase) SignerWeight(id string) (uint64, error) {
	w, ok := v.weights[id]
	if !ok {
		return 0, fmt.Errorf("%w: %q", quorumweight.ErrUnknownSigner, id)
	}
	return w, nil
}

// Identity tags what the buffer counted under.
func (v *TrustBase) Identity() string { return v.identity }

// GetQuorum calculates and returns minimum number of nodes required for a quorum
func (v *TrustBase) GetQuorum() uint64 {
	// Partition quorum is currently set to 50%, meaning at least
	// +1 to round up and avoid using floats
	return (uint64(len(v.partitionTrustBase)) / 2) + 1
}

// GetTotalNodes returns total number of registered validator nodes
func (v *TrustBase) GetTotalNodes() uint64 {
	return uint64(len(v.partitionTrustBase))
}

func (v *TrustBase) NodeIDs() []string {
	return slices.Collect(maps.Keys(v.partitionTrustBase))
}

func (v *TrustBase) Verify(nodeId string, f func(v abcrypto.Verifier) error) error {
	ver, found := v.partitionTrustBase[nodeId]
	if !found {
		return fmt.Errorf("node %s is not part of partition trustbase", nodeId)
	}
	return f(ver)
}
