// Package weightvalidation is the version-aware validation of root members, root trust bases and partition descriptions
// for Q3 (briefs/q3-design-v2.md section 6, slice A). It wraps bft-go-base instead of changing it: go-base's NodeInfo.IsValid,
// PartitionDescriptionRecord.IsValid and evmassign.ValidateSet refuse any stake other than 1, and there is no fork of go-base
// to relax that.
//
// The caller names the context explicitly. ModeUnit is the legacy unit-weight world and delegates to go-base unchanged.
// ModeWeighted is the validated V3 world: root members and EVM validators may carry the bounded weights of D3 (1..2^40 each,
// 2^48 in total), and an exact root threshold. The aggregator role never gains weights in either mode. The zero Role and Mode
// are refused, so a caller cannot fall into a default.
//
// A weighted check reuses go-base's own structural rules by validating a copy whose stakes are normalised to 1, and then
// checks the weights itself; no go-base rule is re-implemented. Nothing in production calls this package yet.
package weightvalidation

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Role is the part a validator set plays. Aggregator sets are PDR validators of non-EVM shards.
type Role uint8

const (
	RoleRoot Role = iota + 1
	RoleEVM
	RoleAggregator
)

// Mode selects the validation rules. ModeUnit is the legacy rule set, ModeWeighted the Q3 V3 rule set.
type Mode uint8

const (
	ModeUnit Mode = iota + 1
	ModeWeighted
)

var (
	// ErrContext is returned for an unset or unknown role or mode, or a role that does not apply to the checked object.
	ErrContext = errors.New("weightvalidation: unknown or inapplicable validation context")
	// ErrNonUnitAggregator is returned for an aggregator validator whose weight is not 1, in either mode.
	ErrNonUnitAggregator = errors.New("weightvalidation: aggregator validators are unit weight")
	// ErrWeight is returned for a weighted member whose weight is outside [1, evmroot.MaxMemberWeight].
	ErrWeight = errors.New("weightvalidation: member weight out of range")
	// ErrTotalWeight is returned when the total weight exceeds evmroot.MaxTotalWeight or overflows.
	ErrTotalWeight = errors.New("weightvalidation: total weight out of range")
	// ErrThreshold is returned when a root trust base threshold is not the exact one for its members.
	ErrThreshold = errors.New("weightvalidation: root threshold is not the exact threshold of the members")
	// ErrMembers is returned for an empty, nil, duplicated or unordered member set.
	ErrMembers = errors.New("weightvalidation: invalid member set")
	// ErrMember is returned for a structurally invalid member record (nil, empty id, missing or invalid key) found by the
	// weighted rules or by Nodes and RootTrustBase. go-base's own error stays in the chain; ModeUnit Node and PDR return
	// go-base's error unchanged.
	ErrMember = errors.New("weightvalidation: invalid member record")
	// ErrPartition is returned when a weighted partition description fails go-base's structural rules. A nil record is
	// types.ErrSystemDescriptionIsNil, unchanged.
	ErrPartition = errors.New("weightvalidation: invalid partition description")
)

// asMember classifies a go-base structural refusal of a member as ErrMember, keeping it in the chain and leaving this
// package's own sentinels alone.
func asMember(err error) error {
	if err == nil || errors.Is(err, ErrMember) || errors.Is(err, ErrContext) || errors.Is(err, ErrNonUnitAggregator) || errors.Is(err, ErrWeight) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMember, err)
}

func checkContext(role Role, mode Mode) error {
	if role < RoleRoot || role > RoleAggregator || mode < ModeUnit || mode > ModeWeighted {
		return fmt.Errorf("%w: role %d mode %d", ErrContext, role, mode)
	}
	return nil
}

// unitCopy is n with its stake normalised to 1: it passes go-base's structural validation exactly when n does apart from the
// stake. It is a new value because NodeInfo carries a sync.Once and must not be copied.
func unitCopy(n *types.NodeInfo) *types.NodeInfo {
	if n == nil {
		return nil
	}
	return &types.NodeInfo{NodeID: n.NodeID, SigKey: append([]byte(nil), n.SigKey...), Stake: 1}
}

func weightInRange(n *types.NodeInfo) error {
	if n.Stake == 0 || n.Stake > evmroot.MaxMemberWeight {
		return fmt.Errorf("%w: %q has weight %d, allowed 1..%d", ErrWeight, n.NodeID, n.Stake, evmroot.MaxMemberWeight)
	}
	return nil
}

// Node validates one validator record. ModeUnit is NodeInfo.IsValid; ModeWeighted accepts any weight in range for the root and
// EVM roles. A non-unit aggregator is ErrNonUnitAggregator (joined with go-base's own refusal) in both modes.
func Node(n *types.NodeInfo, role Role, mode Mode) error {
	err := node(n, role, mode)
	if mode == ModeWeighted {
		return asMember(err)
	}
	return err
}

func node(n *types.NodeInfo, role Role, mode Mode) error {
	if err := checkContext(role, mode); err != nil {
		return err
	}
	if role == RoleAggregator && n != nil && n.Stake != 1 {
		return errors.Join(ErrNonUnitAggregator, n.IsValid())
	}
	if mode == ModeUnit || role == RoleAggregator || n == nil {
		return n.IsValid()
	}
	if err := unitCopy(n).IsValid(); err != nil {
		return err
	}
	return weightInRange(n)
}

// Nodes validates a member set and returns its total weight: every member through Node, unique node ids, and in ModeWeighted
// also unique signing keys and a total of at most evmroot.MaxTotalWeight, summed with overflow refusal.
func Nodes(nodes []*types.NodeInfo, role Role, mode Mode) (uint64, error) {
	if err := checkContext(role, mode); err != nil {
		return 0, err
	}
	if len(nodes) == 0 {
		return 0, fmt.Errorf("%w: empty", ErrMembers)
	}
	var total quorumweight.Tally
	keys := make(map[string]string, len(nodes))
	for i, n := range nodes {
		if err := Node(n, role, mode); err != nil {
			return 0, fmt.Errorf("member %d: %w", i, asMember(err))
		}
		if err := total.Add(n.NodeID, n.Stake); err != nil {
			return 0, fmt.Errorf("%w: duplicate node id %q: %w", ErrMembers, n.NodeID, err)
		}
		if mode == ModeWeighted {
			if owner, dup := keys[string(n.SigKey)]; dup {
				return 0, fmt.Errorf("%w: %q shares a signing key with %q", ErrMembers, n.NodeID, owner)
			}
			keys[string(n.SigKey)] = n.NodeID
		}
	}
	if mode == ModeWeighted && total.Weight() > evmroot.MaxTotalWeight {
		return 0, fmt.Errorf("%w: %d > %d", ErrTotalWeight, total.Weight(), evmroot.MaxTotalWeight)
	}
	return total.Weight(), nil
}

// RootTrustBase validates the members and threshold of a root trust base (not its epoch link or signatures, which are
// RootTrustBaseV1.Verify's). Members must be strictly ordered by node id, as go-base's lookup requires. ModeUnit requires unit
// weights and a threshold in [floor(2n/3)+1, n], as types.NewTrustBase does; ModeWeighted requires exactly floor(2W/3)+1.
func RootTrustBase(tb *types.RootTrustBaseV1, mode Mode) error {
	if err := checkContext(RoleRoot, mode); err != nil {
		return err
	}
	if tb == nil {
		return fmt.Errorf("%w: nil trust base", ErrMembers)
	}
	total, err := Nodes(tb.RootNodes, RoleRoot, mode)
	if err != nil {
		return err
	}
	for i := 1; i < len(tb.RootNodes); i++ {
		if tb.RootNodes[i-1].NodeID >= tb.RootNodes[i].NodeID {
			return fmt.Errorf("%w: members are not strictly ordered by node id", ErrMembers)
		}
	}
	want, err := quorumweight.Threshold(total)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrThreshold, err)
	}
	bad := tb.QuorumThreshold < want || tb.QuorumThreshold > total
	if mode == ModeWeighted {
		bad = tb.QuorumThreshold != want
	}
	if bad {
		return fmt.Errorf("%w: have %d, want %d of %d", ErrThreshold, tb.QuorumThreshold, want, total)
	}
	return nil
}

// PDR validates a partition description with the validator rules of role (RoleEVM or RoleAggregator). ModeUnit is
// PartitionDescriptionRecord.IsValid. ModeWeighted runs it on a copy with unit stakes, then checks the weights of an EVM set.
func PDR(pdr *types.PartitionDescriptionRecord, role Role, mode Mode) error {
	if err := checkContext(role, mode); err != nil {
		return err
	}
	if role == RoleRoot {
		return fmt.Errorf("%w: a partition description has no root role", ErrContext)
	}
	if pdr == nil {
		return pdr.IsValid()
	}
	if role == RoleAggregator {
		for _, v := range pdr.Validators {
			if v != nil && v.Stake != 1 {
				return errors.Join(ErrNonUnitAggregator, pdr.IsValid())
			}
		}
	}
	if mode == ModeUnit || role == RoleAggregator {
		return pdr.IsValid()
	}
	cp := *pdr
	cp.Validators = make([]*types.NodeInfo, len(pdr.Validators))
	for i, v := range pdr.Validators {
		cp.Validators[i] = unitCopy(v)
	}
	if err := cp.IsValid(); err != nil {
		return fmt.Errorf("%w: %w", ErrPartition, err)
	}
	_, err := Nodes(pdr.Validators, RoleEVM, ModeWeighted)
	return err
}

// EVMSet validates a successor EVM validator set: ModeUnit is evmassign.ValidateSet; ModeWeighted runs it on unit-stake copies
// (size bound, strict order, valid unique keys) and then checks the weights and total.
func EVMSet(validators []*types.NodeInfo, mode Mode) error {
	if err := checkContext(RoleEVM, mode); err != nil {
		return err
	}
	if mode == ModeUnit {
		return evmassign.ValidateSet(validators)
	}
	copies := make([]*types.NodeInfo, len(validators))
	for i, v := range validators {
		copies[i] = unitCopy(v)
	}
	if err := evmassign.ValidateSet(copies); err != nil {
		return err
	}
	_, err := Nodes(validators, RoleEVM, ModeWeighted)
	return err
}

type evmRules struct{ mode Mode }

func (r evmRules) PDR(p *types.PartitionDescriptionRecord) error { return PDR(p, RoleEVM, r.mode) }
func (r evmRules) Set(v []*types.NodeInfo) error                 { return EVMSet(v, r.mode) }

// EVMRules is the successor EVM assignment rule set of a mode, for evmassign's *With functions: ModeUnit is evmassign.UnitRules
// behaviour, ModeWeighted the bounded weights of a verified Q3 activation.
func EVMRules(mode Mode) evmassign.Rules { return evmRules{mode} }
