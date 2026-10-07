package storage

// Authenticated request round view (Q2-C1, briefs/q2-design-v2.md section 3). One resolver selects, from committed activation
// history and a verified parent shard state, the immutable view under which the requests of one shard round are admitted,
// verified and executed: the assignment (members, weights, thresholds), the authorised configuration, the expected technical
// record and the previous certified state and UC. Nothing here reads the last committed ShardInfo of a live state and nothing
// a request carries selects its own authority. Production still installs unit contexts and legacy dispatch; weighted contexts
// are built only by isolated fixtures until the Q3 activation.

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// requestSentinel is a sentinel that also matches its parent, so a refusal is both specific and a request context mismatch.
type requestSentinel struct {
	msg    string
	parent error
}

func (e *requestSentinel) Error() string { return e.msg }
func (e *requestSentinel) Unwrap() error { return e.parent }

var (
	// ErrRequestNotActive refuses certification, execution or timeout under an assignment that is committed but whose
	// activation round has not been reached. It is also a quorumweight.ErrRequestContext.
	ErrRequestNotActive error = &requestSentinel{"request context is not active yet", quorumweight.ErrRequestContext}
	// ErrStaleRequestContext refuses a request or proof for another shard epoch, round, state or UC than the view's. It is
	// also a quorumweight.ErrRequestContext.
	ErrStaleRequestContext error = &requestSentinel{"request belongs to another request context", quorumweight.ErrRequestContext}
)

// RequestPurpose says what a resolved view is used for; the same target may resolve differently by purpose.
type RequestPurpose uint8

const (
	// PurposeCollect admits requests; it may resolve an assignment that is committed but not yet active (collection only).
	PurposeCollect RequestPurpose = iota + 1
	// PurposeCertify, PurposeExecute and PurposeTimeout need the assignment to be active at the target root round.
	PurposeCertify
	PurposeExecute
	PurposeTimeout
	// PurposeReplay targets a verified historical block: the assignment in force at that round, never today's.
	PurposeReplay
)

func (p RequestPurpose) valid() bool { return p >= PurposeCollect && p <= PurposeReplay }

// RequestActivation is one verified committed assignment of the shard with its authorising root identity. It owns private
// copies of everything it holds. NewRequestAnchor and ActivationFromHandoff are the only exported ways to make one.
type RequestActivation struct {
	pdr       *types.PartitionDescriptionRecord
	confHash  []byte
	ctx       *quorumweight.RequestContext
	rootEpoch uint64
	rootBody  []byte
	start     uint64 // A*: first root round the assignment is in force; zero for the anchor
	trHash    []byte // committed successor technical record digest; nil for the anchor
	version   uint64 // certified protocol version
}

func clonePDR(pdr *types.PartitionDescriptionRecord) (*types.PartitionDescriptionRecord, error) {
	raw, err := types.Cbor.Marshal(pdr)
	if err != nil {
		return nil, err
	}
	out := &types.PartitionDescriptionRecord{}
	return out, types.Cbor.Unmarshal(raw, out)
}

// newRequestActivation builds the activation under policy (unit, or weighted with coupling). The context is bound to the
// configuration hash the activation computes itself, never to one supplied beside it.
func newRequestActivation(pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash, policy quorumweight.RequestPolicy, coupling *quorumweight.Coupling,
	rootEpoch uint64, rootBody []byte, start uint64, trHash []byte, version uint64) (*RequestActivation, error) {
	if pdr == nil || version == 0 || len(rootBody) == 0 {
		return nil, fmt.Errorf("%w: incomplete activation", quorumweight.ErrRequestContext)
	}
	own, err := clonePDR(pdr)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	hash, err := own.Hash(hashAlg)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	var ctx *quorumweight.RequestContext
	switch policy {
	case quorumweight.PolicyUnit:
		ctx, err = quorumweight.NewUnitRequestContext(own, hashAlg, hash)
	case quorumweight.PolicyEVMWeighted:
		ctx, err = quorumweight.NewWeightedRequestContext(own, hashAlg, hash, coupling)
	default:
		err = fmt.Errorf("%w: unknown policy %d", quorumweight.ErrRequestContext, policy)
	}
	if err != nil {
		return nil, err
	}
	return &RequestActivation{pdr: own, confHash: hash, ctx: ctx, rootEpoch: rootEpoch, rootBody: bytes.Clone(rootBody),
		start: start, trHash: bytes.Clone(trHash), version: version}, nil
}

// NewIsolatedWeightedRequestAnchor is the mirrored-weight activation of a coupled EVM assignment installed from a trusted
// checkpoint, for isolated fixtures and the Q3 integration that will install weighted configurations. Weighted configurations
// are not installed in production before Q3 (genesis and historical configurations stay unit-only), and nothing in production
// calls this: it exists so that a collector, a leader or a follower can be exercised end to end with weights, through the same
// activation type the committed history produces. The weighted request context validates the coupling's consistency under the
// supplied trusted anchor, and the authorizing root epoch and body must be the coupling's own: a disagreement is refused.
func NewIsolatedWeightedRequestAnchor(pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash, coupling *quorumweight.Coupling,
	rootEpoch uint64, rootBody []byte, version uint64) (*RequestActivation, error) {
	if coupling == nil {
		return nil, quorumweight.ErrCouplingRequired
	}
	if rootEpoch != coupling.RootEpoch || !bytes.Equal(rootBody, coupling.RootBodyID) {
		return nil, fmt.Errorf("%w: authorizing root %d/%x is not the coupling's %d/%x", quorumweight.ErrRequestContext,
			rootEpoch, rootBody, coupling.RootEpoch, coupling.RootBodyID)
	}
	return newRequestActivation(pdr, hashAlg, quorumweight.PolicyEVMWeighted, coupling, rootEpoch, rootBody, 0, nil, version)
}

// NewRequestAnchor is the unit-weight activation of a trusted genesis or checkpoint configuration, in force from the start.
func NewRequestAnchor(pdr *types.PartitionDescriptionRecord, hashAlg crypto.Hash, rootEpoch uint64, rootBody []byte, version uint64) (*RequestActivation, error) {
	return newRequestActivation(pdr, hashAlg, quorumweight.PolicyUnit, nil, rootEpoch, rootBody, 0, nil, version)
}

// shardParent is the owned copy of the verified parent shard state a view is resolved against.
type shardParent struct {
	tr       certification.TechnicalRecord // the executing state's technical record
	lastTR   certification.TechnicalRecord // the last certified technical record
	uc       *types.UnicityCertificate     // the last certified UC
	ucDigest []byte
	rootHash []byte // last certified state hash
	confHash []byte
	pending  *types.InputRecord // change already in the pipeline for the shard
}

// RequestSnapshot is the opaque handle the resolver reads: the verified anchor and committed activation chain of one shard
// plus its verified parent execution state. It is not a map a caller can fill with assertions.
type RequestSnapshot struct {
	network   uint64
	partition types.PartitionID
	shard     types.ShardID
	chain     []*RequestActivation
	parent    shardParent
	frozen    *ShardInfo // private copy of the parent state, the base of the derived successor technical record
	parentID  []byte
	hashAlg   crypto.Hash
}

// NewRequestSnapshot checks that chain[0] is the anchor and that the rest follow it (consecutive shard epochs, rising
// activation rounds, rising root epochs), that the parent state belongs to that chain and that its installed configuration
// hash is the chain's for its epoch. Missing or unlinked history is ErrAssignmentHistory; a hash that differs is a request
// context mismatch. Everything is copied on entry.
func NewRequestSnapshot(network uint64, hashAlg crypto.Hash, parent *ShardInfo, parentID []byte, pending *types.InputRecord, chain ...*RequestActivation) (*RequestSnapshot, error) {
	if parent == nil || parent.LastCR == nil || len(chain) == 0 || len(parentID) == 0 {
		return nil, fmt.Errorf("%w: no verified parent state or activation history", ErrAssignmentHistory)
	}
	first := chain[0]
	if first == nil || first.start != 0 {
		return nil, fmt.Errorf("%w: history does not begin at a trusted anchor", ErrAssignmentHistory)
	}
	for i, a := range chain {
		if a == nil || a.pdr.PartitionID != parent.PartitionID || !a.pdr.ShardID.Equal(parent.ShardID) {
			return nil, fmt.Errorf("%w: activation %d is not of shard %s-%s", ErrAssignmentHistory, i, parent.PartitionID, parent.ShardID)
		}
		if i == 0 {
			continue
		}
		p := chain[i-1]
		if a.pdr.Epoch != p.pdr.Epoch+1 || a.start <= p.start || a.rootEpoch <= p.rootEpoch || a.pdr.NetworkID != p.pdr.NetworkID {
			return nil, fmt.Errorf("%w: activation %d does not follow activation %d", ErrAssignmentHistory, i, i-1)
		}
	}
	// the network is authenticated by the history and the previous UC, never asserted beside them
	for i, a := range chain {
		if uint64(a.pdr.NetworkID) != network {
			return nil, fmt.Errorf("%w: snapshot network %d, activation %d is of network %d", quorumweight.ErrRequestContext, network, i, a.pdr.NetworkID)
		}
	}
	if seal := parent.LastCR.UC.UnicitySeal; seal == nil || uint64(seal.NetworkID) != network {
		return nil, fmt.Errorf("%w: snapshot network %d, previous UC is of another network or unsealed", quorumweight.ErrRequestContext, network)
	}
	idx := slices.IndexFunc(chain, func(a *RequestActivation) bool { return a.pdr.Epoch == parent.TR.Epoch })
	if idx < 0 {
		return nil, fmt.Errorf("%w: no activation for shard epoch %d", ErrAssignmentHistory, parent.TR.Epoch)
	}
	if !bytes.Equal(chain[idx].confHash, parent.ShardConfHash) {
		return nil, fmt.Errorf("%w: parent state is under configuration %x, history has %x", quorumweight.ErrRequestContext, parent.ShardConfHash, chain[idx].confHash)
	}
	ucDigest, err := parent.LastCR.UC.Hash(hashAlg)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	uc, err := cloneCBOR(&parent.LastCR.UC)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	var pend *types.InputRecord
	if pending != nil {
		if pend, err = cloneCBOR(pending); err != nil {
			return nil, errors.Join(ErrAssignmentHistory, err)
		}
	}
	frozen := *parent
	frozen.Fees, frozen.Stat = maps.Clone(parent.Fees), parent.Stat
	frozen.PrevEpochFees, frozen.PrevEpochStat = bytes.Clone(parent.PrevEpochFees), bytes.Clone(parent.PrevEpochStat)
	frozen.RootHash, frozen.IR, frozen.LastCR = bytes.Clone(parent.RootHash), nil, nil
	frozen.TR, frozen.ShardConfHash = cloneTR(parent.TR), bytes.Clone(parent.ShardConfHash)
	frozen.PartitionParams = maps.Clone(parent.PartitionParams)
	s := &RequestSnapshot{frozen: &frozen, network: network, partition: parent.PartitionID, shard: parent.ShardID, parentID: bytes.Clone(parentID), hashAlg: hashAlg,
		chain: slices.Clone(chain), parent: shardParent{tr: cloneTR(parent.TR), lastTR: cloneTR(parent.LastCR.Technical), uc: uc, ucDigest: ucDigest,
			rootHash: bytes.Clone(parent.RootHash), confHash: bytes.Clone(parent.ShardConfHash), pending: pend}}
	return s, nil
}

// cloneTR is a technical record owning its hash bytes.
func cloneTR(tr certification.TechnicalRecord) certification.TechnicalRecord {
	tr.StatHash, tr.FeeHash = bytes.Clone(tr.StatHash), bytes.Clone(tr.FeeHash)
	return tr
}

func cloneCBOR[T any](v *T) (*T, error) {
	raw, err := types.Cbor.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := new(T)
	return out, types.Cbor.Unmarshal(raw, out)
}

// RequestQuery is what a caller asks for. Every field is compared with what the snapshot resolves; none of them selects the
// authority, policy, version or anchor.
type RequestQuery struct {
	Network      uint64
	Partition    types.PartitionID
	Shard        types.ShardID
	RootEpoch    uint64 // the root epoch whose assignment authorises the shard round
	RootRound    uint64 // the target root round
	RootBodyID   []byte
	Version      uint64
	ParentID     []byte // the verified parent block the view is resolved against
	PrevUCDigest []byte // digest of the shard's previous certified UC
	Purpose      RequestPurpose
}

// RequestRoundView is the immutable result of the resolver. Its getters return copies.
type RequestRoundView struct {
	ctx        *quorumweight.RequestContext
	pdr        *types.PartitionDescriptionRecord
	expectedTR certification.TechnicalRecord
	prevHash   []byte
	prevUC     *types.UnicityCertificate
	ucDigest   []byte
	pending    *types.InputRecord
	target     RequestQuery
	version    uint64
	start      uint64
	trDigest   []byte
	t2         time.Duration
	collection bool // resolved before its activation round, collection only
	assignKey  []byte
	viewKey    []byte
}

func lp(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	h.Write(n[:])
	h.Write(b)
}

func lpu(h interface{ Write([]byte) (int, error) }, v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	lp(h, n[:])
}

// AssignmentKey identifies the assignment alone: the context identity, hash algorithm, certified version and authorising root
// identity. It is true for unit contexts as well. Shard epoch alone, or a root epoch assumed equal to it, never identifies one.
func assignmentKey(a *RequestActivation, hashAlg crypto.Hash) []byte {
	h := sha256.New()
	lp(h, []byte("UNICITY_Q2_ASSIGNMENT_KEY"))
	lp(h, []byte(a.ctx.Identity()))
	lpu(h, uint64(hashAlg))
	lpu(h, a.version)
	lpu(h, a.rootEpoch)
	lp(h, a.rootBody)
	return h.Sum(nil)
}

// AssignmentKey and ViewKey are the cache identities of the assignment and of the whole view. The ViewKey additionally binds
// the target root epoch/round/body, the parent identity, the expected technical record, the previous UC and state hash, the
// activation, the purpose and the pending-change snapshot.
func (v *RequestRoundView) AssignmentKey() []byte { return bytes.Clone(v.assignKey) }
func (v *RequestRoundView) ViewKey() []byte       { return bytes.Clone(v.viewKey) }

// Identity is the assignment identity the buffer tags tallies with: the AssignmentKey, never the shard epoch alone.
func (v *RequestRoundView) Identity() string { return hex.EncodeToString(v.assignKey) }

// RoundTag is the shard round and anchor the requests of the view build on.
func (v *RequestRoundView) RoundTag() string {
	return roundTag(v.expectedTR.Round, v.expectedTR.Epoch, v.prevHash, v.prevUC.UnicitySeal.Timestamp)
}

// roundTag is the canonical tag of the shard round and anchor (expected round, epoch, previous state hash and timestamp).
func roundTag(round, epoch uint64, prevHash []byte, timestamp uint64) string {
	h := sha256.New()
	lp(h, []byte("UNICITY_Q2_ROUND_TAG"))
	lpu(h, round)
	lpu(h, epoch)
	lp(h, prevHash)
	lpu(h, timestamp)
	return hex.EncodeToString(h.Sum(nil))
}

func (v *RequestRoundView) bindViewKey(hashAlg crypto.Hash) {
	h := sha256.New()
	lp(h, []byte("UNICITY_Q2_VIEW_KEY"))
	lp(h, v.assignKey)
	lpu(h, v.target.Network)
	lpu(h, uint64(v.target.Partition))
	lp(h, []byte(v.target.Shard.String()))
	lpu(h, v.target.RootEpoch)
	lpu(h, v.target.RootRound)
	lp(h, v.target.RootBodyID)
	lp(h, v.target.ParentID)
	lpu(h, uint64(v.target.Purpose))
	lpu(h, v.expectedTR.Round)
	lpu(h, v.expectedTR.Epoch)
	lp(h, []byte(v.expectedTR.Leader))
	lp(h, v.expectedTR.StatHash)
	lp(h, v.expectedTR.FeeHash)
	lp(h, v.ucDigest)
	lp(h, v.prevHash)
	lpu(h, v.start)
	lp(h, v.trDigest)
	if v.pending != nil {
		raw, _ := v.pending.Bytes()
		lp(h, raw)
	} else {
		lp(h, nil)
	}
	v.viewKey = h.Sum(nil)
}

// Context is a deep copy-free read of the immutable assignment component (the type's accessors return copies).
func (v *RequestRoundView) Context() *quorumweight.RequestContext { return v.ctx }

// PDR returns a copy of the configuration that authorises the shard round.
func (v *RequestRoundView) PDR() (*types.PartitionDescriptionRecord, error) { return clonePDR(v.pdr) }

// ExpectedTR is the technical record every request of the round must carry the round and epoch of.
func (v *RequestRoundView) ExpectedTR() certification.TechnicalRecord {
	return cloneTR(v.expectedTR)
}

// PreviousUC returns a copy of the shard's previous certified UC.
func (v *RequestRoundView) PreviousUC() (*types.UnicityCertificate, error) {
	return cloneCBOR(v.prevUC)
}

// PreviousStateHash is the last certified state hash requests must build on.
func (v *RequestRoundView) PreviousStateHash() []byte { return bytes.Clone(v.prevHash) }

// HasPendingChange reports whether the snapshot froze a change of the shard in the uncommitted pipeline.
func (v *RequestRoundView) HasPendingChange() bool { return v.pending != nil }

// T2Timeout is the configured timeout of the authorised configuration; only elapsed root rounds ever use it.
func (v *RequestRoundView) T2Timeout() time.Duration { return v.t2 }

// CollectionOnly is true when the view was resolved before its activation round: requests may be collected under it, but
// nothing is certified, executed or timed out under it.
func (v *RequestRoundView) CollectionOnly() bool { return v.collection }

// ResolveRequestContext selects the view for query from the snapshot. It never falls back to the latest local state: missing
// history is ErrAssignmentHistory; every supplied identity that differs from the resolved one is a quorumweight.ErrRequestContext;
// a certification purpose before the activation round is ErrRequestNotActive.
func ResolveRequestContext(q RequestQuery, snap *RequestSnapshot) (*RequestRoundView, error) {
	if snap == nil {
		return nil, fmt.Errorf("%w: no authenticated snapshot", ErrAssignmentHistory)
	}
	if q.Version == 0 || q.RootRound == 0 || len(q.RootBodyID) == 0 || len(q.ParentID) == 0 || len(q.PrevUCDigest) == 0 || !q.Purpose.valid() {
		return nil, fmt.Errorf("%w: incomplete query", quorumweight.ErrRequestContext)
	}
	if q.Network != snap.network || q.Partition != snap.partition || !q.Shard.Equal(snap.shard) {
		return nil, fmt.Errorf("%w: query is for network %d shard %s-%s, snapshot is %d %s-%s", quorumweight.ErrRequestContext,
			q.Network, q.Partition, q.Shard, snap.network, snap.partition, snap.shard)
	}
	if !bytes.Equal(q.ParentID, snap.parentID) {
		return nil, fmt.Errorf("%w: parent %x, snapshot parent %x", quorumweight.ErrRequestContext, q.ParentID, snap.parentID)
	}
	// the assignment in force at the target round: the latest activation starting at or before it
	idx := -1
	for i, a := range snap.chain {
		if a.start <= q.RootRound {
			idx = i
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("%w: no assignment in force at root round %d", ErrAssignmentHistory, q.RootRound)
	}
	collection := false
	if next := idx + 1; next < len(snap.chain) {
		// A committed successor is not in force yet. Collection may resolve it when the caller names it; a caller that names its root identity for any
		// other purpose is told it is not active, never answered with the old assignment under the new name.
		named := snap.chain[next].rootEpoch == q.RootEpoch && bytes.Equal(snap.chain[next].rootBody, q.RootBodyID)
		switch {
		case q.Purpose == PurposeCollect && named:
			idx, collection = next, true
		case named && q.Purpose != PurposeReplay:
			return nil, fmt.Errorf("%w: activation round %d, target round %d", ErrRequestNotActive, snap.chain[next].start, q.RootRound)
		}
	}
	act := snap.chain[idx]
	if act.version != q.Version {
		return nil, fmt.Errorf("%w: certified version %d, query %d", quorumweight.ErrRequestContext, act.version, q.Version)
	}
	if act.rootEpoch != q.RootEpoch || !bytes.Equal(act.rootBody, q.RootBodyID) {
		return nil, fmt.Errorf("%w: root assignment %d/%x, query %d/%x", quorumweight.ErrRequestContext, act.rootEpoch, act.rootBody, q.RootEpoch, q.RootBodyID)
	}
	if !bytes.Equal(snap.parent.ucDigest, q.PrevUCDigest) {
		return nil, fmt.Errorf("%w: previous UC %x, query %x", quorumweight.ErrRequestContext, snap.parent.ucDigest, q.PrevUCDigest)
	}
	tr, err := expectedTR(snap, idx)
	if err != nil {
		return nil, err
	}
	var pending *types.InputRecord
	if snap.parent.pending != nil {
		if pending, err = cloneCBOR(snap.parent.pending); err != nil {
			return nil, errors.Join(ErrAssignmentHistory, err)
		}
	}
	prevUC, err := cloneCBOR(snap.parent.uc)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	pdr, err := clonePDR(act.pdr)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	v := &RequestRoundView{ctx: act.ctx, pdr: pdr, expectedTR: tr, prevHash: bytes.Clone(snap.parent.rootHash), prevUC: prevUC,
		ucDigest: bytes.Clone(snap.parent.ucDigest), pending: pending, target: q, version: act.version, start: act.start,
		trDigest: bytes.Clone(act.trHash), t2: act.pdr.T2Timeout, collection: collection, assignKey: assignmentKey(act, snap.hashAlg)}
	v.target.RootBodyID, v.target.ParentID, v.target.PrevUCDigest = bytes.Clone(q.RootBodyID), bytes.Clone(q.ParentID), bytes.Clone(q.PrevUCDigest)
	v.bindViewKey(snap.hashAlg)
	return v, nil
}

// expectedTR is the technical record the round's requests build on. While the shard still runs the epoch before the active
// assignment (the committed state lags the activation) the successor record is derived from the frozen parent state, or taken
// from the parent when it has already installed the assignment, and its digest must be the committed one. Otherwise it is the
// last certified record, whose epoch must be the assignment's.
func expectedTR(snap *RequestSnapshot, idx int) (certification.TechnicalRecord, error) {
	act, p := snap.chain[idx], snap.parent
	switch {
	case idx > 0 && p.lastTR.Epoch+1 == act.pdr.Epoch:
		tr := cloneTR(p.tr)
		if tr.Epoch+1 == act.pdr.Epoch {
			derived, err := successorTechnicalRecordWith(snap.frozen, act.pdr, snap.hashAlg, resetMembers)
			if err != nil {
				return tr, errors.Join(ErrAssignmentHistory, err)
			}
			tr = derived
		}
		digest, err := tr.Hash()
		if err != nil || !bytes.Equal(digest, act.trHash) {
			return tr, fmt.Errorf("%w: successor technical record %x, committed %x", quorumweight.ErrRequestContext, digest, act.trHash)
		}
		return tr, nil
	case p.lastTR.Epoch == act.pdr.Epoch:
		return cloneTR(p.lastTR), nil
	}
	return certification.TechnicalRecord{}, fmt.Errorf("%w: shard epoch %d is not that of the assignment in force (%d)", ErrStaleRequestContext, p.lastTR.Epoch, act.pdr.Epoch)
}

// ValidRequest is the admission check of one block certification request under the view: membership and signature under the
// context's own key for that node, the shard, and the expected round, epoch, state hash and timestamp. It is the same check at
// collection, in a follower's proof verification and at execution.
//
// A signer that is not a member and a bad signature keep their own identities; every other refusal (a nil or malformed request,
// another shard, stale continuity) also matches rctypes.ErrInvalidRequest, preserving the underlying error and its continuity
// identity (ErrStaleRequestContext).
func (v *RequestRoundView) ValidRequest(req *certification.BlockCertificationRequest) error {
	err := v.validRequest(req)
	if err == nil || errors.Is(err, ErrNodeNotInTrustBase) || errors.Is(err, quorumweight.ErrInvalidSignature) {
		return err
	}
	return malformedRequest{err}
}

func (v *RequestRoundView) validRequest(req *certification.BlockCertificationRequest) error {
	if req == nil {
		return fmt.Errorf("invalid certification request: %w", certification.ErrBlockCertificationRequestIsNil)
	}
	ver, err := v.ctx.Verifier(req.NodeID)
	if err != nil {
		return fmt.Errorf("invalid certification request: node %q is %w", req.NodeID, ErrNodeNotInTrustBase)
	}
	if err := req.IsValid(signatureVerifier{ver}); err != nil {
		return fmt.Errorf("invalid certification request: %w", err)
	}
	if req.PartitionID != v.target.Partition || !req.ShardID.Equal(v.target.Shard) {
		return fmt.Errorf("request of shard %s-%s but view of %s-%s: %w", req.PartitionID, req.ShardID, v.target.Partition, v.target.Shard, rctypes.ErrInvalidRequest)
	}
	if req.IRRound() != v.expectedTR.Round {
		return fmt.Errorf("%w: expected round %d, got %d", ErrStaleRequestContext, v.expectedTR.Round, req.IRRound())
	}
	if req.InputRecord.Epoch != v.expectedTR.Epoch {
		return fmt.Errorf("%w: expected epoch %d, got %d", ErrStaleRequestContext, v.expectedTR.Epoch, req.InputRecord.Epoch)
	}
	if !bytes.Equal(req.IRPreviousHash(), v.prevHash) {
		return fmt.Errorf("%w: request has different root hash for last certified state", ErrStaleRequestContext)
	}
	if req.InputRecord.Timestamp != v.prevUC.UnicitySeal.Timestamp {
		return fmt.Errorf("%w: IR timestamp %d doesn't match UnicitySeal timestamp %d", ErrStaleRequestContext, req.InputRecord.Timestamp, v.prevUC.UnicitySeal.Timestamp)
	}
	return nil
}

// view as the weights and admission of rctypes.IRChangeReq.Verify
func (v *RequestRoundView) MemberCount() int                       { return v.ctx.MemberCount() }
func (v *RequestRoundView) TotalWeight() uint64                    { return v.ctx.TotalWeight() }
func (v *RequestRoundView) Threshold() uint64                      { return v.ctx.Threshold() }
func (v *RequestRoundView) SignerWeight(id string) (uint64, error) { return v.ctx.SignerWeight(id) }

// VerifiedRequest binds the derived IR to the view that judged the proof and to the exact proof bytes.
type VerifiedRequest struct {
	IR          *types.InputRecord
	ViewKey     []byte
	ProofDigest []byte
}

var _ rctypes.RequestVerifier = (*RequestRoundView)(nil)

// VerifyIRChangeReq verifies a whole proof under the view: every member request independently, the weighted quorum or
// impossibility, T2 by elapsed root rounds, then the pending-change and LUC-age checks against the same snapshot. A collection
// view never certifies. Errors return no result.
func (v *RequestRoundView) VerifyIRChangeReq(req *rctypes.IRChangeReq, t2Rounds uint64) (*VerifiedRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("IR change request is nil: %w", rctypes.ErrInvalidRequest)
	}
	if v.collection {
		return nil, fmt.Errorf("%w: collection-only view", ErrRequestNotActive)
	}
	if req.Partition != v.target.Partition || !req.Shard.Equal(v.target.Shard) {
		return nil, fmt.Errorf("change request of shard %s-%s but view of %s-%s: %w", req.Partition, req.Shard, v.target.Partition, v.target.Shard, rctypes.ErrInvalidRequest)
	}
	round := v.target.RootRound
	ir, err := req.Verify(v, v.prevUC, round, t2Rounds)
	if err != nil {
		return nil, fmt.Errorf("certification request verification failed: %w", err)
	}
	if v.pending != nil {
		if b, err := types.EqualIR(ir, v.pending); b || err != nil {
			if err != nil {
				return nil, fmt.Errorf("comparing input records: %w", err)
			}
			return nil, ErrDuplicateChangeReq
		}
		return nil, fmt.Errorf("shard %s-%s has pending changes in pipeline", v.target.Partition, v.target.Shard)
	}
	if round < v.prevUC.UnicitySeal.RootChainRoundNumber {
		return nil, fmt.Errorf("current round %v is in the past, LUC round %v: %w", round, v.prevUC.UnicitySeal.RootChainRoundNumber, ErrStaleRequestContext)
	}
	raw, err := types.Cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding proof: %w", err)
	}
	digest := sha256.Sum256(raw)
	return &VerifiedRequest{IR: ir, ViewKey: v.ViewKey(), ProofDigest: digest[:]}, nil
}

// ErrDuplicateChangeReq is the refusal of a request whose result is the one already in the pipeline. The consensus package
// re-exports it, so both verifiers refuse with one identity.
var ErrDuplicateChangeReq = errors.New("duplicate ir change request")

// RequestHistory is the committed, verified source of the activation chain a block's executor resolves views from. It is
// provided by the verifier; without one, execution keeps its legacy dispatch.
type RequestHistory interface {
	// Chain is the verified activation chain of the shard, anchor first.
	Chain(partition types.PartitionID, shard types.ShardID) ([]*RequestActivation, error)
	// Network and Version are the certified network and protocol version.
	Network() uint64
	Version() uint64
	// RootIdentity is the root epoch and body identity of the assignment authorising the given root round.
	RootIdentity(round uint64) (uint64, []byte, error)
}

// RequestViewVerifier is the view-aware branch of IRChangeReqVerifier. A verifier that implements it with a non-nil history
// is dispatched here; every other verifier keeps the round-only legacy dispatch.
type RequestViewVerifier interface {
	IRChangeReqVerifier
	RequestHistory() RequestHistory
	// PendingChange is the change of the shard in the uncommitted pipeline, frozen into the view's snapshot.
	PendingChange(partition types.PartitionID, shard types.ShardID) *types.InputRecord
	VerifyIRChangeReqView(view *RequestRoundView, irChReq *rctypes.IRChangeReq) (*VerifiedRequest, error)
}

// viewDispatch returns the view-aware verifier when the verifier has a history, else nil (legacy dispatch).
func viewDispatch(v IRChangeReqVerifier) RequestViewVerifier {
	if vv, ok := v.(RequestViewVerifier); ok && vv.RequestHistory() != nil {
		return vv
	}
	return nil
}

// resolveExecutionView resolves the view a block executes the shard's requests under, from the verified state the block is
// being executed on (parent) and the committed history, never from the last committed ShardInfo.
func resolveExecutionView(vv RequestViewVerifier, parent *ShardInfo, parentID []byte, round uint64, hashAlg crypto.Hash) (*RequestRoundView, error) {
	return ResolveParentView(vv.RequestHistory(), vv.PendingChange(parent.PartitionID, parent.ShardID), parent, parentID, round, hashAlg, PurposeExecute, nil)
}

// ResolveParentView resolves the view of the shard's requests for the target root round and purpose from the committed
// history and the verified parent state (with the change still in its pipeline). It is the one resolution shared by execution,
// the leader's admission and proposal, and timeout generation; a failure returns no view and is never answered from the last
// committed state.
func ResolveParentView(h RequestHistory, pending *types.InputRecord, parent *ShardInfo, parentID []byte, round uint64, hashAlg crypto.Hash, purpose RequestPurpose, cache *RequestViewCache) (*RequestRoundView, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: no committed request history", ErrAssignmentHistory)
	}
	if parent == nil {
		return nil, fmt.Errorf("%w: no verified parent state", ErrAssignmentHistory)
	}
	chain, err := h.Chain(parent.PartitionID, parent.ShardID)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	snap, err := NewRequestSnapshot(h.Network(), hashAlg, parent, parentID, pending, chain...)
	if err != nil {
		return nil, err
	}
	rootEpoch, rootBody, err := h.RootIdentity(round)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	q := RequestQuery{Network: h.Network(), Partition: parent.PartitionID, Shard: parent.ShardID, RootEpoch: rootEpoch,
		RootRound: round, RootBodyID: rootBody, Version: h.Version(), ParentID: parentID, PrevUCDigest: snap.parent.ucDigest, Purpose: purpose}
	if cache != nil {
		return cache.Resolve(q, snap)
	}
	return ResolveRequestContext(q, snap)
}

// ineligibleAtExecution reports whether a request is outside the view for a reason that makes it ineligible rather than the
// block invalid: a signer that is not a member, or a request for another shard round, epoch or state. Like a request for a
// removed shard it is ignored, identically on every root; it changes no state and counts toward nothing.
func ineligibleAtExecution(view *RequestRoundView, irChReq *rctypes.IRChangeReq) (bool, error) {
	for _, req := range irChReq.Requests {
		if err := view.ValidRequest(req); err != nil && (errors.Is(err, ErrNodeNotInTrustBase) || errors.Is(err, ErrStaleRequestContext)) {
			return true, err
		}
	}
	return false, nil
}

// resetMembers installs the members of pdr and no request context. A view derives the successor technical record from the
// configuration the assignment committed, whatever its weights: leader and commitments depend on the members alone.
func resetMembers(si *ShardInfo, pdr *types.PartitionDescriptionRecord, _ crypto.Hash, _ []byte) error {
	si.nodeIDs = make([]string, 0, len(pdr.Validators))
	for _, v := range pdr.Validators {
		si.nodeIDs = append(si.nodeIDs, v.NodeID)
	}
	slices.Sort(si.nodeIDs)
	if n := len(si.Fees); n != len(si.nodeIDs) {
		return fmt.Errorf("shard has %d nodes but fee list contains %d nodes", len(si.nodeIDs), n)
	}
	return nil
}
