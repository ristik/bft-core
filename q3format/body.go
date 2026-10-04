package q3format

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrBody is returned for a V3 body that fails its own checks.
var ErrBody = errors.New("q3format: invalid V3 trust-base body")

// ErrPrior is returned for a prior trust-base reference that cannot be a predecessor.
var ErrPrior = errors.New("q3format: invalid predecessor")

const (
	// BodyVersion is the version of TrustBaseBodyV3.
	BodyVersion = 3
	bodyDomain  = "UNICITY_TRUSTBASE_V3"
	toV3Domain  = "UNICITY_TRUSTBASE_TO_V3"
	// MaxMembers bounds a body's member list at the existing assignment limit, so a coupled root/EVM set always fits.
	MaxMembers = evmassign.MaxValidators
	maxBodyLen = 64 << 10
	maxText    = 64
	maxField   = 64
)

// BodyV3 is the distinct canonical V3 body: every V2 semantic field plus the protocol tuple. It carries no signature,
// endorsement or readiness witness, so its identity is stable across all of them. The actual activation A* is not in it.
type BodyV3 struct {
	Network, Epoch     uint64
	EarliestActivation uint64 // A_min, a lower bound
	Members            evmroot.WeightSet
	RootThreshold      uint64
	StateSummary       []byte
	ChangeRecordHash   []byte
	PredecessorHash    []byte
	Config             ProtocolConfig
}

func (b BodyV3) fields() []any {
	members := append(evmroot.WeightSet(nil), b.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	mem := make([]any, len(members))
	for i, m := range members {
		mem[i] = []any{m.StakingID, m.NodeID, m.ConsensusKey, m.Weight}
	}
	opt := func(v []byte) any {
		if len(v) == 0 {
			return nil
		}
		return v
	}
	return []any{uint64(BodyVersion), b.Network, b.Epoch, b.EarliestActivation, mem, b.RootThreshold,
		opt(b.StateSummary), opt(b.ChangeRecordHash), opt(b.PredecessorHash), b.Config.fields()}
}

// Encode is the canonical body, ["UNICITY_TRUSTBASE_V3", fields]: the V2 field array with Version 3 and the ordered
// ProtocolConfig array appended as its final field, members sorted by node id as in V2.
func (b BodyV3) Encode() []byte { return enc(bodyDomain, b.fields()) }

// Identity is SHA-256 of Encode.
func (b BodyV3) Identity() [32]byte { return sha256.Sum256(b.Encode()) }

// Validate checks the tuple (which requires a network), that its network is the body's, the bounded weights and member identities (through
// weightvalidation, root role, weighted mode), and that the recorded threshold is exactly the weighted one.
func (b BodyV3) Validate() error {
	if b.Epoch < 2 || b.EarliestActivation == 0 || len(b.PredecessorHash) != 32 {
		return fmt.Errorf("%w: network, epoch, earliest activation and a 32-byte predecessor are required", ErrBody)
	}
	if err := b.Config.Validate(); err != nil {
		return err
	}
	if b.Config.Network != b.Network {
		return fmt.Errorf("%w: tuple network %d is not the body's %d", ErrBody, b.Config.Network, b.Network)
	}
	if len(b.Members) > MaxMembers {
		return fmt.Errorf("%w: %d members, limit %d", ErrTooLarge, len(b.Members), MaxMembers)
	}
	if err := b.Members.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrBody, err)
	}
	nodes := make([]*types.NodeInfo, len(b.Members))
	for i, m := range b.Members {
		nodes[i] = &types.NodeInfo{NodeID: m.NodeID, SigKey: m.ConsensusKey, Stake: m.Weight}
	}
	total, err := weightvalidation.Nodes(nodes, weightvalidation.RoleRoot, weightvalidation.ModeWeighted)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBody, err)
	}
	if want, err := quorumweight.Threshold(total); err != nil || b.RootThreshold != want {
		return fmt.Errorf("%w: threshold %d, want %d of %d", ErrBody, b.RootThreshold, want, total)
	}
	return nil
}

// DecodeBody parses a canonical V3 body and validates it. Another version is ErrVersion, a noncanonical or oversize encoding
// ErrFormat or ErrTooLarge.
func DecodeBody(raw []byte) (BodyV3, error) {
	if v, err := Version(raw); err != nil {
		return BodyV3{}, err
	} else if v != BodyVersion {
		return BodyV3{}, fmt.Errorf("%w: body version %d", ErrVersion, v)
	}
	r, err := parse(raw, maxBodyLen)
	if err != nil {
		return BodyV3{}, err
	}
	r.expect(bodyDomain)
	f := r.sub(10)
	if err := r.done(); err != nil {
		return BodyV3{}, err
	}
	var b BodyV3
	if v := f.uint(); f.err == nil && v != BodyVersion {
		return BodyV3{}, fmt.Errorf("%w: body version %d", ErrVersion, v)
	}
	b.Network, b.Epoch, b.EarliestActivation = f.uint(), f.uint(), f.uint()
	mem := f.array(MaxMembers)
	for i := 0; i < mem.len() && mem.err == nil; i++ {
		m := mem.sub(4)
		member := evmroot.Member{StakingID: m.text(maxText), NodeID: m.text(maxText), ConsensusKey: m.bytes(evmroot.ConsensusKeyLen, 0), Weight: m.uint()}
		if err := m.done(); err != nil {
			return BodyV3{}, err
		}
		b.Members = append(b.Members, member)
	}
	if mem.err != nil {
		return BodyV3{}, mem.err
	}
	b.RootThreshold = f.uint()
	b.StateSummary, b.ChangeRecordHash, b.PredecessorHash = f.optBytes(maxField), f.optBytes(maxField), f.optBytes(maxField)
	if f.err == nil {
		b.Config, f.err = readConfig(f)
	}
	if err := f.done(); err != nil {
		return BodyV3{}, err
	}
	// members are sorted by Encode, so an unordered or noncanonical encoding differs here
	if !bytes.Equal(b.Encode(), raw) {
		return BodyV3{}, fmt.Errorf("%w: not the canonical encoding", ErrFormat)
	}
	return b, b.Validate()
}

// Version reports the body version of a canonical encoding: 3 for the V3 domain array, 2 for the V2 field array (whose first
// field is its version). V1 is the go-base tagged trust base and is not a body. Anything else is ErrVersion.
func Version(raw []byte) (uint64, error) {
	r, err := parse(raw, maxBodyLen)
	if err != nil {
		return 0, err
	}
	switch first := r.take().(type) {
	case string:
		if first == bodyDomain {
			return 3, nil
		}
	case uint64:
		if first == evmroot.TrustBaseVersion && r.len() == 9 {
			return 2, nil
		}
	}
	return 0, fmt.Errorf("%w: not a V2 or V3 body", ErrVersion)
}

// Prior names the trust base a V3 body succeeds. BodyVersion 1 is the V1 trust base and Identity its hash including
// signatures; 2 and 3 are body identities.
type Prior struct {
	Network, Epoch, BodyVersion uint64
	Identity                    []byte
}

// Hash is the PredecessorHash a V3 body must carry: the identity of a V3 prior directly, and for the first V3 body
// SHA-256(CBOR(["UNICITY_TRUSTBASE_TO_V3", N, priorEpoch, priorBodyVersion, priorIdentity])), so that no V1 or V2 bytes are
// reinterpreted as V3.
func (p Prior) Hash() ([]byte, error) {
	if p.Network == 0 || p.Epoch == 0 || len(p.Identity) != 32 || p.BodyVersion < 1 || p.BodyVersion > BodyVersion {
		return nil, fmt.Errorf("%w: network, epoch, version 1..3 and a 32-byte identity are required", ErrPrior)
	}
	if p.BodyVersion == BodyVersion {
		return bytes.Clone(p.Identity), nil
	}
	h := sha256.Sum256(enc(toV3Domain, p.Network, p.Epoch, p.BodyVersion, p.Identity))
	return h[:], nil
}
