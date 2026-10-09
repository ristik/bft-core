package evmassign

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/internal/weightcap"
	"sort"

	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Candidate kinds. One candidate format serves both: a primary candidate (J) is built from an election result and needs a fresh
// possession proof from every successor key; a recovery candidate re-installs exactly the last acknowledged incumbent committee (K)
// after a committed but unacknowledged primary, and carries no fresh proofs (docs/design/pos-architecture.md sections 5 and 6).
const (
	KindPrimary  uint64 = 1
	KindRecovery uint64 = 2
)

const (
	StakingIDLen = 32
	PayeeLen     = 20
	DigestLen    = 32

	identitiesDomain    = "UNICITY_P85_IDENTITIES"
	exposureDomain      = "UNICITY_P85_EXPOSURE_COMMIT"
	authorizationDomain = "UNICITY_P85_RECOVERY_AUTHORIZATION"
	// MaxRecoveryCommitted is the number of committed recovery candidates one frozen parent admits, restarts and aborts included.
	MaxRecoveryCommitted = 1
)

var (
	// ErrIdentity reports a malformed, unordered or inconsistent identity record set.
	ErrIdentity = errors.New("evmassign: invalid identity records")
	// ErrKind reports a candidate whose kind does not match the fields it carries.
	ErrKind = errors.New("evmassign: candidate kind does not match its contents")
	// ErrAuthorization reports a recovery authorization that is malformed or that the committed primary does not commit to.
	ErrAuthorization = errors.New("evmassign: invalid recovery authorization")
	// ErrNotIncumbent reports a recovery committee that is not exactly the last acknowledged incumbent committee.
	ErrNotIncumbent = errors.New("evmassign: recovery committee is not the exact incumbent")
	// ErrRecoveryUsed reports a second committed recovery on one frozen parent.
	ErrRecoveryUsed = errors.New("evmassign: the committed recovery allowance of this frozen parent is spent")
	// ErrRecoveryLineage reports a recovery that does not extend the committed, unacknowledged primary it is derived from.
	ErrRecoveryLineage = errors.New("evmassign: recovery does not extend the committed primary")
	// ErrContinuity wraps a failed committee continuity predicate; the continuity sentinels stay in the chain.
	ErrContinuity = errors.New("evmassign: committee continuity")
)

// Identity is one frozen election identity record: the validator entity, both of its signing bindings, its committed weight, the
// reward destination fixed for this assignment and the digest of its exposure references. Every field is committed by the
// assignment hash, so a possession proof and the candidate digest authenticate the payee. The payee is never read from a mutable
// current nomination.
type Identity struct {
	_              struct{} `cbor:",toarray"`
	StakingID      []byte   `json:"stakingId"`
	Generation     uint64   `json:"generation"`
	RootNodeID     string   `json:"rootNodeId"`
	RootKey        []byte   `json:"rootKey"`
	EVMNodeID      string   `json:"evmNodeId"`
	EVMKey         []byte   `json:"evmKey"`
	Weight         uint64   `json:"weight"`    // the committed (quantized) weight q: voting, leader, reward, threshold and continuity
	RawWeight      uint64   `json:"rawWeight"` // the raw bonded weight x >= q the collateral must cover; q = quant(x over the set, B)
	OperatorPayee  []byte   `json:"operatorPayee"`
	ExposureDigest []byte   `json:"exposureDigest"`
}

func (i Identity) valid() error {
	switch {
	case len(i.StakingID) != StakingIDLen, len(i.OperatorPayee) != PayeeLen, len(i.ExposureDigest) != DigestLen,
		i.RootNodeID == "", i.EVMNodeID == "", len(i.RootKey) != KeyLen, len(i.EVMKey) != KeyLen, i.Weight == 0,
		i.RawWeight < i.Weight:
		return fmt.Errorf("%w: malformed record %x", ErrIdentity, i.StakingID)
	case isZero(i.OperatorPayee), isZero(i.ExposureDigest):
		return fmt.Errorf("%w: zero operator payee or exposure digest for %x", ErrIdentity, i.StakingID)
	}
	return nil
}

func isZero(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func (i Identity) fields() []any {
	return []any{i.StakingID, i.Generation, i.RootNodeID, i.RootKey, i.EVMNodeID, i.EVMKey, i.Weight, i.RawWeight, i.OperatorPayee, i.ExposureDigest}
}

// IdentitiesDigest commits to the ordered identity records, operator payees included. It is carried in PoPContext, so it enters
// the assignment hash every possession proof signs.
func IdentitiesDigest(ids []Identity) ([32]byte, error) {
	list := make([]any, 0, len(ids))
	for _, i := range ids {
		list = append(list, i.fields())
	}
	return hashCBOR(identitiesDomain, uint64(1), list)
}

// ExposureCommit is the authenticated commitment to the exposure records the identities carry, each bound to the payee, generation
// and identity of its assignment. A recovery reads it from the incumbent assignment, never from a current staged nomination.
func ExposureCommit(ids []Identity) ([32]byte, error) {
	list := make([]any, 0, len(ids))
	for _, i := range ids {
		list = append(list, []any{i.StakingID, i.Generation, i.OperatorPayee, i.ExposureDigest})
	}
	return hashCBOR(exposureDomain, uint64(1), list)
}

// Members is the continuity view of identity records.
func Members(ids []Identity) []continuity.Member {
	out := make([]continuity.Member, 0, len(ids))
	for _, i := range ids {
		m := continuity.Member{RootNodeID: i.RootNodeID, RootKey: i.RootKey, EVMNodeID: i.EVMNodeID, EVMKey: i.EVMKey, Weight: i.Weight}
		copy(m.ID[:], i.StakingID)
		out = append(out, m)
	}
	return out
}

// ValidateIdentities checks that the identity records are the one authenticated description of the coupled set: strictly ordered by
// staking id, well formed, and in exact correspondence with the root members, the EVM validators and the bindings. The three
// arrays are in different orders (root members and bindings by root node id, EVM validators by EVM node id), so correspondence is
// established by identifier lookup, never positionally.
func ValidateIdentities(ids []Identity, root []RootMember, succ *types.PartitionDescriptionRecord, bindings []Binding) error {
	if succ == nil || len(ids) == 0 || len(ids) != len(root) || len(ids) != len(bindings) || len(ids) != len(succ.Validators) {
		return fmt.Errorf("%w: %d identities, %d root members, %d EVM validators, %d bindings", ErrIdentity, len(ids), len(root), lenValidators(succ), len(bindings))
	}
	byRoot := make(map[string]RootMember, len(root))
	for _, m := range root {
		byRoot[m.NodeID] = m
	}
	byEVM := make(map[string]*types.NodeInfo, len(succ.Validators))
	for _, v := range succ.Validators {
		byEVM[v.NodeID] = v
	}
	bound := make(map[[2]string]bool, len(bindings))
	for _, b := range bindings {
		bound[[2]string{b.RootNodeID, b.EVMNodeID}] = true
	}
	seenRoot, seenEVM := map[string]bool{}, map[string]bool{}
	for n, i := range ids {
		if err := i.valid(); err != nil {
			return err
		}
		if n > 0 && bytes.Compare(ids[n-1].StakingID, i.StakingID) >= 0 {
			return fmt.Errorf("%w: records are not strictly ordered by staking id", ErrIdentity)
		}
		m, okR := byRoot[i.RootNodeID]
		v, okE := byEVM[i.EVMNodeID]
		if !okR || !okE || seenRoot[i.RootNodeID] || seenEVM[i.EVMNodeID] {
			return fmt.Errorf("%w: %x names a root or EVM node that is unknown or shared", ErrIdentity, i.StakingID)
		}
		seenRoot[i.RootNodeID], seenEVM[i.EVMNodeID] = true, true
		if !bytes.Equal(m.Key, i.RootKey) || !bytes.Equal(v.SigKey, i.EVMKey) || m.Weight != i.Weight || v.Stake != i.Weight {
			return fmt.Errorf("%w: %x differs from its root member or EVM validator in key or weight", ErrIdentity, i.StakingID)
		}
		if !bound[[2]string{i.RootNodeID, i.EVMNodeID}] {
			return fmt.Errorf("%w: %x has no binding between its root and EVM node", ErrIdentity, i.StakingID)
		}
	}
	return CheckQuantized(ids)
}

// CheckQuantized requires the committed weights of a committee to be the quantization of its raw weights under the profile cap B:
// q = quant(x over the set). The root, ureth and the contracts evaluate the same pure function, so a record whose q was not derived from
// the x it commits is a projection mismatch and is refused.
func CheckQuantized(ids []Identity) error {
	raw := make([]uint64, len(ids))
	for n, i := range ids {
		raw[n] = i.RawWeight
	}
	q, _, err := Quantize(raw, weightcap.B)
	if err != nil {
		return fmt.Errorf("%w: raw weights cannot be quantized: %v", ErrIdentity, err)
	}
	for n, i := range ids {
		if i.Weight != q[n] {
			return fmt.Errorf("%w: %x commits weight %d, the quantization of its raw weight %d is %d", ErrIdentity, i.StakingID, i.Weight, i.RawWeight, q[n])
		}
	}
	return nil
}

// Authorization is the recovery authorization of one election result, committed by the primary J that publishes it and re-presented
// in full by the recovery candidate. K is exactly the last acknowledged incumbent committee.
type Authorization struct {
	_                  struct{}   `cbor:",toarray"`
	Network            uint64     `json:"network"`
	Chain              uint64     `json:"chain"`
	Contracts          []byte     `json:"contracts"` // digest of the contract addresses and code hashes
	ResultID           []byte     `json:"resultId"`
	SnapshotDigest     []byte     `json:"snapshotDigest"`
	BaseRootBodyID     []byte     `json:"baseRootBodyId"`     // the root body of the last acknowledged committee
	BaseAssignmentHash []byte     `json:"baseAssignmentHash"` // its assignment hash
	K                  []Identity `json:"k"`
	ExposureDigest     []byte     `json:"exposureDigest"` // ExposureCommit(K)
	Policies           []byte     `json:"policies"`       // digest of the captured penalty/protection policies
}

// Digest is the commitment a primary candidate carries and a recovery candidate must reproduce.
func (a Authorization) Digest() ([32]byte, error) {
	for _, f := range [][]byte{a.Contracts, a.ResultID, a.SnapshotDigest, a.BaseRootBodyID, a.BaseAssignmentHash, a.ExposureDigest, a.Policies} {
		if len(f) != DigestLen || isZero(f) {
			return [32]byte{}, fmt.Errorf("%w: field width or zero", ErrAuthorization)
		}
	}
	if len(a.K) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty K", ErrAuthorization)
	}
	for n, i := range a.K {
		if err := i.valid(); err != nil {
			return [32]byte{}, errors.Join(ErrAuthorization, err)
		}
		if n > 0 && bytes.Compare(a.K[n-1].StakingID, i.StakingID) >= 0 {
			return [32]byte{}, fmt.Errorf("%w: K is not strictly ordered by staking id", ErrAuthorization)
		}
	}
	want, err := ExposureCommit(a.K)
	if err != nil || !bytes.Equal(want[:], a.ExposureDigest) {
		return [32]byte{}, fmt.Errorf("%w: exposure commitment is not the one K carries", ErrAuthorization)
	}
	list := make([]any, 0, len(a.K))
	for _, i := range a.K {
		list = append(list, i.fields())
	}
	return hashCBOR(authorizationDomain, uint64(1), a.Network, a.Chain, a.Contracts, a.ResultID, a.SnapshotDigest, a.BaseRootBodyID,
		a.BaseAssignmentHash, list, a.ExposureDigest, a.Policies)
}

// Lifecycle is the part of a candidate that makes it primary or recovery. Both kinds publish the full recovery Authorization, so a
// primary whose K is not the exact incumbent is refused when it is admitted, not when it is needed. Exactly one of two shapes is valid:
//
//   - primary: a possession proof for every successor key, no replaced assignment;
//   - recovery: no fresh proofs, and ReplacedAssignment is the assignment hash of the committed primary it replaces.
type Lifecycle struct {
	Kind               uint64
	Identities         []Identity
	Authorization      *Authorization
	ReplacedAssignment []byte
}

func (l Lifecycle) validShape(pops int) error {
	if l.Authorization == nil {
		return fmt.Errorf("%w: the recovery authorization is mandatory", ErrKind)
	}
	switch l.Kind {
	case KindPrimary:
		if len(l.ReplacedAssignment) != 0 || pops == 0 {
			return fmt.Errorf("%w: a primary carries every proof and no replaced assignment", ErrKind)
		}
	case KindRecovery:
		if len(l.ReplacedAssignment) != DigestLen || pops != 0 {
			return fmt.Errorf("%w: a recovery carries the replaced assignment and no fresh proofs", ErrKind)
		}
	default:
		return fmt.Errorf("%w: kind %d", ErrKind, l.Kind)
	}
	return nil
}

// VerifyAuthorization is the static half of the kind rules: the carried authorization is well formed and bound to the candidate's
// network, and a recovery re-installs exactly the K the authorization names.
func VerifyAuthorization(c Candidate) error {
	a := c.Authorization
	if a == nil {
		return fmt.Errorf("%w: missing", ErrAuthorization)
	}
	if _, err := a.Digest(); err != nil {
		return err
	}
	if a.Network != c.Network {
		return fmt.Errorf("%w: another network", ErrAuthorization)
	}
	if c.Kind != KindRecovery {
		return nil
	}
	kd, err := IdentitiesDigest(a.K)
	if err != nil {
		return err
	}
	cd, err := IdentitiesDigest(c.Identities)
	if err != nil {
		return err
	}
	if kd != cd {
		return fmt.Errorf("%w: the recovery committee differs from K in a member, key, weight, payee or exposure", ErrNotIncumbent)
	}
	return nil
}

// Head is the committed, still unacknowledged primary a recovery extends: its decoded candidate and its successor assignment.
type Head struct {
	Candidate Candidate
	Successor *types.PartitionDescriptionRecord
}

// LifecycleContext is the authenticated state the kind rules need: the last acknowledged committee, the continuity policy and the
// committed lineage of the frozen parent.
type LifecycleContext struct {
	// Incumbent is the identity set of the last acknowledged assignment (the genesis manifest's, before any rotation) and
	// IncumbentAssignment its assignment hash.
	Incumbent           []Identity
	IncumbentAssignment [32]byte
	Policy              continuity.Policy
	// Head is the latest committed unacknowledged primary; nil when none is pending.
	Head *Head
	// CommittedRecoveries counts the committed recovery candidates of the pending chain (one frozen parent).
	CommittedRecoveries int
	// Pending is the number of committed, unacknowledged steps of that chain.
	Pending int
}

// MaxProfileSpan is the longest unacknowledged chain this profile admits: an ordinary transition acknowledges one step, J followed by
// a recovery K folds two. There is no third transition.
const MaxProfileSpan = 2

// ErrPendingPrimary reports a primary candidate admitted over a committed, unacknowledged one.
var ErrPendingPrimary = errors.New("evmassign: a primary cannot supersede a pending primary")

// ErrSpan reports a candidate that would make the unacknowledged chain longer than MaxProfileSpan.
var ErrSpan = errors.New("evmassign: the unacknowledged chain would exceed the two-step profile")

// VerifyLifecycle is the state-dependent half of the kind rules, run wherever a candidate is admitted next to VerifyInstalled: exact
// incumbent K, the continuity predicates of the candidate's own boundary, and for a recovery the lineage and the spent allowance.
func VerifyLifecycle(c Candidate, ctx LifecycleContext) error {
	a := c.Authorization
	if a == nil {
		return fmt.Errorf("%w: missing", ErrAuthorization)
	}
	if ctx.CommittedRecoveries >= MaxRecoveryCommitted {
		return ErrRecoveryUsed
	}
	if ctx.Pending+1 > MaxProfileSpan {
		return fmt.Errorf("%w: %d pending", ErrSpan, ctx.Pending)
	}
	if (c.Supersedes != nil) != (ctx.Pending > 0) {
		return fmt.Errorf("%w: a supersession is exactly a candidate over a pending chain", ErrRecoveryLineage)
	}
	inc, err := IdentitiesDigest(ctx.Incumbent)
	if err != nil {
		return err
	}
	k, err := IdentitiesDigest(a.K)
	if err != nil {
		return err
	}
	if inc != k || !bytes.Equal(a.BaseAssignmentHash, ctx.IncumbentAssignment[:]) {
		return fmt.Errorf("%w: K is not the last acknowledged committee", ErrNotIncumbent)
	}
	switch c.Kind {
	case KindPrimary:
		if ctx.Pending != 0 {
			return fmt.Errorf("%w: only the recovery may replace a committed, unacknowledged primary", ErrPendingPrimary)
		}
		if !bytes.Equal(a.BaseRootBodyID, c.Predecessor) {
			return fmt.Errorf("%w: K is based on another root body", ErrAuthorization)
		}
		return continuityError(ctx.Incumbent, c.Identities, ctx.Policy)
	case KindRecovery:
		h := ctx.Head
		if h == nil || h.Successor == nil || h.Candidate.Kind != KindPrimary || h.Candidate.Authorization == nil {
			return fmt.Errorf("%w: no committed unacknowledged primary", ErrRecoveryLineage)
		}
		want, err := h.Candidate.Authorization.Digest()
		got, err2 := a.Digest()
		if err != nil || err2 != nil || want != got {
			return fmt.Errorf("%w: the authorization is not the one the committed primary published", ErrAuthorization)
		}
		if !bytes.Equal(a.BaseRootBodyID, h.Candidate.Predecessor) {
			return fmt.Errorf("%w: K is based on another root body", ErrAuthorization)
		}
		hd, err := IdentitiesDigest(h.Candidate.Identities)
		if err != nil {
			return err
		}
		replaced, err := AssignmentHash(h.Successor, hd)
		if err != nil || !bytes.Equal(replaced[:], c.ReplacedAssignment) {
			return fmt.Errorf("%w: replaced assignment is not the committed primary's", ErrRecoveryLineage)
		}
		return continuityError(h.Candidate.Identities, c.Identities, ctx.Policy)
	}
	return ErrKind
}

func continuityError(o, s []Identity, p continuity.Policy) error {
	if _, err := continuity.Check(Members(o), Members(s), p); err != nil {
		return errors.Join(ErrContinuity, err)
	}
	return nil
}

// VerifyKind is everything about a candidate's kind that needs no installed state: the shape, the identity records against the root
// members, validators and bindings, the authorization and, for a primary, the fresh possession proof of every successor key.
func VerifyKind(c Candidate, succ *types.PartitionDescriptionRecord) error {
	if err := c.Lifecycle().validShape(len(c.PoPs)); err != nil {
		return err
	}
	if err := ValidateIdentities(c.Identities, c.RootMembers, succ, c.Bindings); err != nil {
		return err
	}
	if err := VerifyAuthorization(c); err != nil {
		return err
	}
	if c.Kind == KindPrimary {
		return VerifyCandidatePoPs(c, succ)
	}
	return nil
}

// DeriveRecovery derives the recovery candidate's content from the committed unacknowledged primary alone: exactly K, fresh successor
// epoch, the primary's non-membership configuration, sorted root members, bindings and EVM validators, and no fresh proofs. Every
// relayer and every verifier computes the same result; nothing is chosen. installed is the installed (primary) configuration the
// recovery replaces.
func DeriveRecovery(head Head, installed *types.PartitionDescriptionRecord) (Lifecycle, *types.PartitionDescriptionRecord, []RootMember, []Binding, error) {
	a := head.Candidate.Authorization
	if a == nil || head.Successor == nil || installed == nil {
		return Lifecycle{}, nil, nil, nil, ErrRecoveryLineage
	}
	root := make([]RootMember, 0, len(a.K))
	bindings := make([]Binding, 0, len(a.K))
	validators := make([]*types.NodeInfo, 0, len(a.K))
	for _, i := range a.K {
		root = append(root, RootMember{NodeID: i.RootNodeID, Key: bytes.Clone(i.RootKey), Weight: i.Weight})
		bindings = append(bindings, Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
		validators = append(validators, &types.NodeInfo{NodeID: i.EVMNodeID, SigKey: bytes.Clone(i.EVMKey), Stake: i.Weight})
	}
	sort.Slice(root, func(x, y int) bool { return root[x].NodeID < root[y].NodeID })
	sort.Slice(bindings, func(x, y int) bool { return bindings[x].RootNodeID < bindings[y].RootNodeID })
	succ, err := NewSuccessor(installed, validators)
	if err != nil {
		return Lifecycle{}, nil, nil, nil, err
	}
	hd, err := IdentitiesDigest(head.Candidate.Identities)
	if err != nil {
		return Lifecycle{}, nil, nil, nil, err
	}
	replaced, err := AssignmentHash(head.Successor, hd)
	if err != nil {
		return Lifecycle{}, nil, nil, nil, err
	}
	return Lifecycle{Kind: KindRecovery, Identities: a.K, Authorization: a, ReplacedAssignment: replaced[:]}, succ, root, bindings, nil
}

// AssignmentID is the assignment hash of the candidate's successor assignment under its frozen identity records: the identifier a
// recovery names for the committee it re-installs and the one custody keys the assignment by.
func (c Candidate) AssignmentID() ([32]byte, error) {
	succ, err := c.Successor()
	if err != nil {
		return [32]byte{}, err
	}
	digest, err := IdentitiesDigest(c.Identities)
	if err != nil {
		return [32]byte{}, err
	}
	return AssignmentHash(succ, digest)
}

// ResultID is the election result the candidate's authorization names.
func (c Candidate) ResultID() (id [32]byte) {
	if c.Authorization != nil {
		copy(id[:], c.Authorization.ResultID)
	}
	return id
}
