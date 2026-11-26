package evmassign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
)

// CandidateVersion is the only encoding of an assignment-bearing candidate.
// The legacy root-only operator candidate (version 1) is unchanged.
const CandidateVersion uint64 = 5

// MaxCandidateBytes bounds the retained preimage: it is carried once in the
// freeze companion and the handoff bundle, never in the root-input D[] payload.
const MaxCandidateBytes = 256 * 1024

const candidateDomain = "UNICITY_H3_EVM_ASSIGNMENT_CANDIDATE"

// RootMember is one successor root-chain member, bound so a candidate names both halves of the one coupled operation.
type RootMember struct {
	_      struct{} `cbor:",toarray"`
	NodeID string
	Key    []byte
	Weight uint64
}

// Binding couples one successor root entity to its delegated EVM participant. The two keys are distinct credentials; the
// weights are equal (the EVM set mirrors the root's).
type Binding struct {
	_          struct{} `cbor:",toarray"`
	RootNodeID string   `json:"rootNodeId"`
	EVMNodeID  string   `json:"evmNodeId"`
}

// Supersession binds a replacement of an installed, still unacknowledged
// assignment on the same frozen parent. The base is the registry assignment
// authenticated from P; the chain commits the already committed steps from
// the base up to and including SupersededH.
type Supersession struct {
	_               struct{} `cbor:",toarray"`
	SupersededH     []byte   // record ID of the latest committed H being replaced
	BaseRootEpoch   uint64   // registry assignment.rootEpoch at P
	BaseShardEpoch  uint64   // registry assignment.epoch at P
	BaseActiveHash  []byte   // registry assignment.activeConfHash at P
	ChainLen        uint64   // committed steps from the base through SupersededH
	ChainCommitment []byte   // ChainCommit over those steps
}

// Candidate is the one byte sequence fixed before root endorsements are
// collected. Its digest is the existing 32-byte candidate hash that D4's
// candidate context, and so TrustBaseBodyV2.ChangeRecordHash, binds.
type Candidate struct {
	_             struct{} `cbor:",toarray"`
	Version       uint64
	Kind          uint64 // KindPrimary or KindRecovery
	Network       uint64
	Predecessor   []byte // predecessor root BodyID
	Attempt       uint64
	RootMembers   []RootMember
	OldShardEpoch uint64
	OldActiveHash []byte // full hash of the installed configuration being replaced
	Assignment    []byte // canonical CBOR of the successor PDR, EpochStart zero
	PoPs          []PoP
	Supersedes    *Supersession
	Bindings      []Binding // one per successor root member, sorted by RootNodeID
	// Identities are the frozen identity records, sorted by StakingID: the one authenticated description of the coupled set that
	// RootMembers, Bindings and the successor validators must agree with, operator payees included.
	Identities []Identity
	// Authorization is the recovery authorization (K) both kinds carry; ReplacedAssignment is set by a recovery only.
	Authorization      *Authorization
	ReplacedAssignment []byte
	Changes            []Change // aggregator validator replacements, at most one per shard (kind 1 only)
	SourceRef          []byte   // reserved: must be empty
}

// Lifecycle is the candidate's kind-defining part.
func (c Candidate) Lifecycle() Lifecycle {
	return Lifecycle{Kind: c.Kind, Identities: c.Identities, Authorization: c.Authorization, ReplacedAssignment: c.ReplacedAssignment}
}

// PoPContext is the context every possession proof of this candidate signs.
func (c Candidate) PoPContext() (PoPContext, error) {
	pop := PoPContext{Network: c.Network, Attempt: c.Attempt}
	if len(c.Predecessor) != 32 {
		return pop, ErrCandidate
	}
	copy(pop.Predecessor[:], c.Predecessor)
	digest, err := IdentitiesDigest(c.Identities)
	if err != nil {
		return pop, err
	}
	pop.Identities = digest
	return pop, nil
}

// VerifyCandidatePoPs verifies the possession proofs of a primary candidate under the context it carries. A recovery carries none.
func VerifyCandidatePoPs(c Candidate, succ *types.PartitionDescriptionRecord) error {
	pop, err := c.PoPContext()
	if err != nil {
		return err
	}
	return VerifyPoPs(pop, succ, c.PoPs)
}

func (c Candidate) Encode() ([]byte, error) {
	if c.Version != CandidateVersion {
		return nil, ErrCandidate
	}
	if err := c.Lifecycle().validShape(len(c.PoPs)); err != nil {
		return nil, errors.Join(ErrCandidate, err)
	}
	b, err := types.Cbor.Marshal([]any{candidateDomain, c})
	if err != nil || len(b) > MaxCandidateBytes {
		return nil, ErrCandidate
	}
	return b, nil
}

// Digest is the candidate hash carried in the approval, the freeze companion
// and the D3 body's change-record context.
func (c Candidate) Digest() ([32]byte, error) {
	b, err := c.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DecodeCandidate accepts exactly one canonical encoding.
func DecodeCandidate(data []byte) (Candidate, error) {
	var c Candidate
	if len(data) == 0 || len(data) > MaxCandidateBytes {
		return c, ErrCandidate
	}
	var wrapper struct {
		_      struct{} `cbor:",toarray"`
		Domain string
		Body   Candidate
	}
	if err := types.Cbor.Unmarshal(data, &wrapper); err != nil || wrapper.Domain != candidateDomain {
		return c, ErrCandidate
	}
	canonical, err := wrapper.Body.Encode()
	if err != nil || !bytes.Equal(canonical, data) {
		return c, ErrCandidate
	}
	return wrapper.Body, nil
}

// Successor decodes and canonically checks the carried successor PDR.
func (c Candidate) Successor() (*types.PartitionDescriptionRecord, error) {
	var pdr types.PartitionDescriptionRecord
	if len(c.Assignment) == 0 || types.Cbor.Unmarshal(c.Assignment, &pdr) != nil {
		return nil, ErrAssignment
	}
	again, err := types.Cbor.Marshal(&pdr)
	if err != nil || !bytes.Equal(again, c.Assignment) {
		return nil, ErrAssignment
	}
	return &pdr, nil
}

// NewCandidate assembles the candidate. PoPs must already be collected: every
// successor key signs PoPMessage for this context before propose.
func NewCandidate(c PoPContext, root []RootMember, current, succ *types.PartitionDescriptionRecord,
	pops []PoP, supersedes *Supersession, bindings []Binding, lc Lifecycle, changes []Change) (Candidate, error) {
	return NewCandidateWith(UnitRules, c, root, current, succ, pops, supersedes, bindings, lc, changes)
}

// NewCandidateWith is NewCandidate with the successor's validator set checked under the rules r.
func NewCandidateWith(r Rules, c PoPContext, root []RootMember, current, succ *types.PartitionDescriptionRecord,
	pops []PoP, supersedes *Supersession, bindings []Binding, lc Lifecycle, changes []Change) (Candidate, error) {
	if err := ValidateSuccessorWith(r, current, succ); err != nil {
		return Candidate{}, err
	}
	if err := ValidateCoupling(root, succ, bindings); err != nil {
		return Candidate{}, err
	}
	if err := ValidateIdentities(lc.Identities, root, succ, bindings); err != nil {
		return Candidate{}, err
	}
	digest, err := IdentitiesDigest(lc.Identities)
	if err != nil {
		return Candidate{}, err
	}
	c.Identities = digest
	if lc.Kind == KindPrimary {
		if err := VerifyPoPs(c, succ, pops); err != nil {
			return Candidate{}, err
		}
	}
	old, err := PDRHash(current)
	if err != nil {
		return Candidate{}, err
	}
	raw, err := types.Cbor.Marshal(succ)
	if err != nil {
		return Candidate{}, err
	}
	out := Candidate{Version: CandidateVersion, Kind: lc.Kind, Network: c.Network, Predecessor: bytes.Clone(c.Predecessor[:]),
		Attempt: c.Attempt, RootMembers: root, OldShardEpoch: current.Epoch,
		OldActiveHash: old[:], Assignment: raw, PoPs: pops, Supersedes: supersedes, Bindings: bindings,
		Identities: lc.Identities, Authorization: lc.Authorization, ReplacedAssignment: lc.ReplacedAssignment, Changes: changes}
	if _, err := out.Encode(); err != nil {
		return Candidate{}, err
	}
	return out, nil
}

// BindingContext is what a verifier knows independently of the candidate and
// of the installed EVM configuration.
type BindingContext struct {
	PoPContext
	// SuccessorRoot is the member list of the successor trust-base body.
	SuccessorRoot []RootMember
	// Digest is the candidate hash the approval, companion and D3 context carry.
	Digest []byte
	// ControlPartition is the reserved control partition id, which no change may target.
	ControlPartition types.PartitionID
	// Rules are the validator weight rules of the successor assignment; nil is UnitRules. Only a verified Q3 activation sets them.
	Rules Rules
}

func (b BindingContext) rules() Rules {
	if b.Rules == nil {
		return UnitRules
	}
	return b.Rules
}

// VerifyContext adds the authenticated installed EVM configuration.
type VerifyContext struct {
	BindingContext
	// Current is the authenticated installed EVM configuration.
	Current *types.PartitionDescriptionRecord
	// CurrentRoot is the old root committee; nil skips the EVM-only refusal (see VerifyInstalled).
	CurrentRoot []RootMember
}

// sameValidators compares the two validator sets, not their order: a successor assignment is sorted by node id (NewSuccessor), while the installed
// configuration keeps the order it was generated in (the genesis lists its validators in the order of the trust base's root nodes, which the genesis
// plan pairs by index), so a committee that did not change would otherwise always read as an EVM-only change.
func sameValidators(a, b []*types.NodeInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] == nil || b[i] == nil {
			return false
		}
	}
	byID := func(nodes []*types.NodeInfo) []*types.NodeInfo {
		sorted := slices.Clone(nodes)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].NodeID < sorted[j].NodeID })
		return sorted
	}
	a, b = byID(a), byID(b)
	for i := range a {
		if a[i] == nil || b[i] == nil || a[i].NodeID != b[i].NodeID || a[i].Stake != b[i].Stake || !bytes.Equal(a[i].SigKey, b[i].SigKey) {
			return false
		}
	}
	return true
}

// ValidateCoupling checks that the successor root members and the successor EVM validators are one coupled set: the
// bindings are a bijection between them (sorted, unique, no unknown or missing id), each pair has equal weight, and a
// signing key is shared across roles: no root key is any entity's EVM key (global distinctness, co-hosted processes must not
// share private keys).
func ValidateCoupling(root []RootMember, succ *types.PartitionDescriptionRecord, bindings []Binding) error {
	if succ == nil || len(root) == 0 || len(bindings) != len(root) || len(succ.Validators) != len(root) {
		return fmt.Errorf("%w: %d root members, %d EVM validators, %d bindings", ErrCoupling, len(root), lenValidators(succ), len(bindings))
	}
	byRoot := make(map[string]RootMember, len(root))
	for _, m := range root {
		byRoot[m.NodeID] = m
	}
	byEVM := make(map[string]*types.NodeInfo, len(succ.Validators))
	for _, v := range succ.Validators {
		byEVM[v.NodeID] = v
	}
	seenRoot, seenEVM := map[string]bool{}, map[string]bool{}
	for i, b := range bindings {
		if i > 0 && bindings[i-1].RootNodeID >= b.RootNodeID {
			return fmt.Errorf("%w: bindings are not sorted by unique root node id", ErrCoupling)
		}
		m, okR := byRoot[b.RootNodeID]
		v, okE := byEVM[b.EVMNodeID]
		if !okR || !okE || seenRoot[b.RootNodeID] || seenEVM[b.EVMNodeID] {
			return fmt.Errorf("%w: binding %q -> %q is not a one-to-one pair of a root member and an EVM validator", ErrCoupling, b.RootNodeID, b.EVMNodeID)
		}
		seenRoot[b.RootNodeID], seenEVM[b.EVMNodeID] = true, true
		if m.Weight != v.Stake {
			return fmt.Errorf("%w: %q has root weight %d but EVM weight %d", ErrCoupling, b.RootNodeID, m.Weight, v.Stake)
		}
	}
	// Keys are distinct across roles, not only within a bound pair: no root key is any entity's EVM key (a root key signing
	// as another entity's EVM participant would defeat the delegation), and no EVM key is a root key.
	rootKeys := make(map[string]string, len(root))
	for _, m := range root {
		rootKeys[string(m.Key)] = m.NodeID
	}
	for _, v := range succ.Validators {
		if owner, shared := rootKeys[string(v.SigKey)]; shared {
			return fmt.Errorf("%w: EVM validator %q uses the signing key of root entity %q", ErrCoupling, v.NodeID, owner)
		}
	}
	return nil
}

// sameCommittee compares two root committees as sets: the order a candidate lists its members in is not part of who they are. The
// EVM-only refusal must not depend on it (a reordered, unchanged committee would otherwise pass as a change). sameRoot, the exact
// comparison of the listed order, stays for the binding to the preimage.
func sameCommittee(a, b []RootMember) bool {
	if len(a) != len(b) {
		return false
	}
	byID := func(members []RootMember) []RootMember {
		sorted := slices.Clone(members)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].NodeID != sorted[j].NodeID {
				return sorted[i].NodeID < sorted[j].NodeID
			}
			return bytes.Compare(sorted[i].Key, sorted[j].Key) < 0
		})
		return sorted
	}
	return sameRoot(byID(a), byID(b))
}

func sameRoot(a, b []RootMember) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].NodeID != b[i].NodeID || a[i].Weight != b[i].Weight || !bytes.Equal(a[i].Key, b[i].Key) {
			return false
		}
	}
	return true
}

// VerifyBinding decodes the preimage and checks every binding that needs no
// EVM state: digest, root/attempt/parent context, no combined change, the
// successor assignment and a possession proof for every successor key.
func VerifyBinding(data []byte, v BindingContext) (Candidate, *types.PartitionDescriptionRecord, error) {
	c, err := DecodeCandidate(data)
	if err != nil {
		return Candidate{}, nil, err
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(digest[:], v.Digest) {
		return Candidate{}, nil, fmt.Errorf("%w: candidate digest", ErrContext)
	}
	for _, check := range []struct {
		ok   bool
		what string
	}{
		{c.Network == v.Network, "network"},
		{bytes.Equal(c.Predecessor, v.Predecessor[:]), "predecessor"},
		{c.Attempt == v.Attempt, "attempt"},
	} {
		if !check.ok {
			return Candidate{}, nil, fmt.Errorf("%w: %s", ErrContext, check.what)
		}
	}
	if !sameRoot(c.RootMembers, v.SuccessorRoot) {
		return Candidate{}, nil, fmt.Errorf("%w: successor root members", ErrContext)
	}
	succ, err := c.Successor()
	if err != nil {
		return Candidate{}, nil, err
	}
	if err := ValidateAssignmentWith(v.rules(), succ); err != nil {
		return Candidate{}, nil, err
	}
	if err := ValidateCoupling(c.RootMembers, succ, c.Bindings); err != nil {
		return Candidate{}, nil, err
	}
	if err := VerifyKind(c, succ); err != nil {
		return Candidate{}, nil, err
	}
	if _, err := ValidateChanges(c.Changes, c.SourceRef, v.PoPContext, v.ControlPartition); err != nil {
		return Candidate{}, nil, err
	}
	if s := c.Supersedes; s != nil {
		if len(s.SupersededH) != 32 || len(s.BaseActiveHash) != 32 || len(s.ChainCommitment) != 32 ||
			s.ChainLen == 0 || s.BaseRootEpoch == 0 || s.BaseShardEpoch >= succ.Epoch-1 {
			return Candidate{}, nil, fmt.Errorf("%w: supersession shape", ErrContext)
		}
	}
	return c, succ, nil
}

// RebindingOnly reports whether the successor EVM set differs from the installed one only by binding replacements of retained root
// members (#1286, astra: an EVM-key recovery is a new EVM node identity for an unchanged root entity). Each binding is checked against
// that root entity's own authorized binding in the frozen incumbent K (the candidate's Authorization, bound here to the installed
// configuration by its assignment hash): either kept exactly (node id, key, weight) or replaced by a node id and key the installed set
// does not hold, at the same weight. K's root entities are the candidate's (node id, key, weight; order-independent), the successor is
// coupled one to one (ValidateCoupling) and at least one binding is replaced. A swap of delegates between entities, an EVM validator
// added or removed without its root entity, a weight or count change and a key change under a kept node id are refused. Possession
// proofs of every successor key are VerifyBinding's; endorsement, root epoch advance and continuity are the handoff's as for any other.
func RebindingOnly(c Candidate, succ, current *types.PartitionDescriptionRecord) bool {
	replaced, ok := checkRebinding(c, succ, current)
	return ok && replaced > 0
}

// checkRebinding is RebindingOnly's per-entity check; it returns the number of replaced bindings.
func checkRebinding(c Candidate, succ, current *types.PartitionDescriptionRecord) (int, bool) {
	a := c.Authorization
	if a == nil || succ == nil || current == nil || len(a.K) != len(c.RootMembers) || len(succ.Validators) != len(current.Validators) ||
		len(current.Validators) != len(a.K) || ValidateCoupling(c.RootMembers, succ, c.Bindings) != nil {
		return 0, false
	}
	kd, err := IdentitiesDigest(a.K)
	if err != nil {
		return 0, false
	}
	if h, err := AssignmentHash(current, kd); err != nil || !bytes.Equal(h[:], a.BaseAssignmentHash) {
		return 0, false
	}
	kRoot := make([]RootMember, len(a.K))
	byRoot := make(map[string]Identity, len(a.K))
	for i, k := range a.K {
		kRoot[i] = RootMember{NodeID: k.RootNodeID, Key: k.RootKey, Weight: k.Weight}
		byRoot[k.RootNodeID] = k
	}
	if !sameCommittee(kRoot, c.RootMembers) {
		return 0, false
	}
	installed := make(map[string]*types.NodeInfo, len(current.Validators))
	keys := make(map[string]bool, len(current.Validators))
	for _, v := range current.Validators {
		if v == nil {
			return 0, false
		}
		installed[v.NodeID] = v
		keys[string(v.SigKey)] = true
	}
	next := make(map[string]*types.NodeInfo, len(succ.Validators))
	for _, v := range succ.Validators {
		if v == nil {
			return 0, false
		}
		next[v.NodeID] = v
	}
	replaced := 0
	for _, b := range c.Bindings {
		k, ok := byRoot[b.RootNodeID]
		v := next[b.EVMNodeID]
		old := installed[k.EVMNodeID]
		if !ok || v == nil || old == nil || !bytes.Equal(old.SigKey, k.EVMKey) {
			return 0, false
		}
		if v.NodeID == k.EVMNodeID {
			if !bytes.Equal(v.SigKey, old.SigKey) || v.Stake != old.Stake {
				return 0, false // a key or weight change under the entity's kept node id
			}
			continue
		}
		if installed[v.NodeID] != nil || keys[string(v.SigKey)] || v.Stake != old.Stake {
			return 0, false // another entity's delegate (a swap), a reused key, or a weight change
		}
		replaced++
	}
	return replaced, true
}

// VerifyInstalled checks a bound candidate against the authenticated installed
// configuration it replaces. currentRoot is the old root committee: an EVM validator change while it is unchanged is
// refused (ErrEVMOnly) unless it is only binding replacements of retained root members (RebindingOnly). A caller that has only the installed configuration (re-derivation at activation, after the
// freeze already enforced this) passes nil.
func VerifyInstalled(c Candidate, succ, current *types.PartitionDescriptionRecord, currentRoot []RootMember) error {
	return VerifyInstalledWith(UnitRules, c, succ, current, currentRoot)
}

// swapsAuthorizedBindings reports whether the candidate's root entities are K's and some binding names another EVM node than the
// entity's authorized one in K (an unchanged EVM set whose delegates moved between entities).
func swapsAuthorizedBindings(c Candidate) bool {
	a := c.Authorization
	kRoot := make([]RootMember, len(a.K))
	byRoot := make(map[string]string, len(a.K))
	for i, k := range a.K {
		kRoot[i] = RootMember{NodeID: k.RootNodeID, Key: k.RootKey, Weight: k.Weight}
		byRoot[k.RootNodeID] = k.EVMNodeID
	}
	if !sameCommittee(kRoot, c.RootMembers) {
		return false
	}
	for _, b := range c.Bindings {
		if byRoot[b.RootNodeID] != b.EVMNodeID {
			return true
		}
	}
	return false
}

// VerifyInstalledWith is VerifyInstalled under the rules r.
func VerifyInstalledWith(r Rules, c Candidate, succ, current *types.PartitionDescriptionRecord, currentRoot []RootMember) error {
	if err := ValidateSuccessorWith(r, current, succ); err != nil {
		return err
	}
	if currentRoot != nil && sameCommittee(c.RootMembers, currentRoot) {
		if !sameValidators(succ.Validators, current.Validators) {
			if !RebindingOnly(c, succ, current) {
				return ErrEVMOnly
			}
		} else if c.Authorization != nil && swapsAuthorizedBindings(c) {
			return ErrEVMOnly // the same EVM set with delegates swapped between the authorized root entities
		}
	}
	old, err := PDRHash(current)
	if err != nil {
		return err
	}
	if c.OldShardEpoch != current.Epoch {
		return fmt.Errorf("%w: installed assignment epoch", ErrContext)
	}
	if !bytes.Equal(c.OldActiveHash, old[:]) {
		return fmt.Errorf("%w: installed assignment hash", ErrContext)
	}
	return nil
}

// Verify is VerifyBinding followed by VerifyInstalled.
func Verify(data []byte, v VerifyContext) (Candidate, *types.PartitionDescriptionRecord, error) {
	c, succ, err := VerifyBinding(data, v.BindingContext)
	if err != nil {
		return Candidate{}, nil, err
	}
	if err := VerifyInstalledWith(v.rules(), c, succ, v.Current, v.CurrentRoot); err != nil {
		return Candidate{}, nil, err
	}
	return c, succ, nil
}

// ChainCommit folds the committed handoff record IDs of a supersession chain,
// base first, into one commitment. BFT verifies every step from retained
// history before it issues the folded acknowledgement.
func ChainCommit(baseRootEpoch, baseShardEpoch uint64, baseActive []byte, steps [][]byte) ([32]byte, error) {
	if len(baseActive) != 32 || len(steps) == 0 {
		return [32]byte{}, ErrContext
	}
	acc, err := hashCBOR("UNICITY_H3_SUPERSESSION_CHAIN", uint64(1), baseRootEpoch, baseShardEpoch, baseActive)
	if err != nil {
		return acc, err
	}
	for _, id := range steps {
		if len(id) != 32 {
			return [32]byte{}, ErrContext
		}
		if acc, err = hashCBOR("UNICITY_H3_SUPERSESSION_STEP", acc[:], id); err != nil {
			return acc, err
		}
	}
	return acc, nil
}

// Provenance is what the orchestration records beside a derived configuration:
// the committed record that activated it and the candidate it came from. It is
// an index entry, never an authority; supersession verification re-reads it only
// to name the committed chain a replacement is built on.
type Provenance struct {
	_               struct{} `cbor:",toarray"`
	RecordID        []byte   // committed H record id
	CandidateDigest []byte
	RootEpoch       uint64 // successor root epoch H activates
	Kind            uint64 // KindPrimary or KindRecovery of the committed candidate
	// Preimage is the committed candidate. It is an index copy re-verified against CandidateDigest and Kind on every decode, so the
	// lifecycle rules (incumbent, head, spent recovery allowance) are read from retained committed data, never from a local flag.
	Preimage []byte
}

func (p Provenance) Bytes() ([]byte, error) {
	if len(p.RecordID) != 32 || len(p.CandidateDigest) != 32 || p.RootEpoch < 2 {
		return nil, ErrContext
	}
	digest := sha256.Sum256(p.Preimage)
	c, err := DecodeCandidate(p.Preimage)
	if err != nil || !bytes.Equal(digest[:], p.CandidateDigest) || c.Kind != p.Kind {
		return nil, fmt.Errorf("%w: provenance candidate", ErrContext)
	}
	return types.Cbor.Marshal(p)
}

func DecodeProvenance(raw []byte) (Provenance, error) {
	var p Provenance
	if err := types.Cbor.Unmarshal(raw, &p); err != nil {
		return p, ErrContext
	}
	if canonical, err := p.Bytes(); err != nil || !bytes.Equal(canonical, raw) {
		return Provenance{}, ErrContext
	}
	return p, nil
}

// Chain describes the committed, still unacknowledged assignment steps of one
// shard, oldest first, and the acknowledged base they extend.
type Chain struct {
	BaseRootEpoch  uint64
	BaseShardEpoch uint64
	BaseActiveHash []byte
	Steps          []ChainStep
}

// ChainStep is one committed handoff in a Chain.
type ChainStep struct {
	ShardEpoch      uint64
	ConfHash        []byte
	RecordID        []byte
	CandidateDigest []byte
	RootEpoch       uint64
	Kind            uint64
	Preimage        []byte
}

// Commitment is ChainCommit over the steps' record identifiers.
func (c Chain) Commitment() ([32]byte, error) {
	ids := make([][]byte, 0, len(c.Steps))
	for _, s := range c.Steps {
		ids = append(ids, s.RecordID)
	}
	return ChainCommit(c.BaseRootEpoch, c.BaseShardEpoch, c.BaseActiveHash, ids)
}

// Supersession returns the candidate field binding this chain: the latest
// committed H it replaces and the acknowledged base it extends.
func (c Chain) Supersession() (*Supersession, error) {
	if len(c.Steps) == 0 {
		return nil, ErrContext
	}
	commit, err := c.Commitment()
	if err != nil {
		return nil, err
	}
	return &Supersession{SupersededH: bytes.Clone(c.Steps[len(c.Steps)-1].RecordID), BaseRootEpoch: c.BaseRootEpoch,
		BaseShardEpoch: c.BaseShardEpoch, BaseActiveHash: bytes.Clone(c.BaseActiveHash), ChainLen: uint64(len(c.Steps)),
		ChainCommitment: commit[:]}, nil
}

// VerifyChain checks a candidate's supersession binding against the chain read
// from the verifier's own committed history.
func VerifyChain(s *Supersession, c Chain) error {
	want, err := c.Supersession()
	if err != nil {
		return err
	}
	if s == nil || !bytes.Equal(s.SupersededH, want.SupersededH) || s.BaseRootEpoch != want.BaseRootEpoch ||
		s.BaseShardEpoch != want.BaseShardEpoch || !bytes.Equal(s.BaseActiveHash, want.BaseActiveHash) ||
		s.ChainLen != want.ChainLen || !bytes.Equal(s.ChainCommitment, want.ChainCommitment) {
		return fmt.Errorf("%w: supersession differs from the committed chain", ErrContext)
	}
	return nil
}

// ActivatedFromPreimage decodes a candidate preimage and applies the committed
// activation round: the configuration the shard runs from that round, whose
// Hash is the shard configuration hash the root certifies afterwards. It is
// the one derivation shared by the root and by shard nodes following handoffs.
func ActivatedFromPreimage(preimage []byte, activation uint64) (Candidate, *types.PartitionDescriptionRecord, error) {
	c, err := DecodeCommittedCandidate(preimage)
	if err != nil {
		return c, nil, err
	}
	succ, err := c.Successor()
	if err != nil {
		return c, nil, err
	}
	pdr, err := Activate(succ, activation)
	if err != nil {
		return c, nil, err
	}
	return c, pdr, nil
}
