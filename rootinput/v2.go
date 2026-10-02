package rootinput

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ObservationProfileBindingV2 identifies an owned fixed observation context
// and root trust base. It is process-local comparison metadata and grants no
// authority by itself.
func ObservationProfileBindingV2(c ObservationContextV2, tb *types.RootTrustBaseV1) ([32]byte, error) {
	if tb == nil || c.NetworkID == 0 || c.PartitionID == 0 || c.ShardID.Length() > 4096 || len(c.ShardConfHash) != 32 || c.RootEpoch == 0 || len(tb.RootNodes) == 0 || len(tb.RootNodes) > 64 {
		return [32]byte{}, ErrV2Context
	}
	for _, n := range tb.RootNodes {
		if n == nil || len(n.NodeID) == 0 || len(n.NodeID) > 256 || len(n.SigKey) == 0 || len(n.SigKey) > 256 {
			return [32]byte{}, ErrV2Context
		}
	}
	if len(tb.Signatures) > 64 {
		return [32]byte{}, ErrV2Context
	}
	total := len(tb.StateHash) + len(tb.ChangeRecordHash) + len(tb.PreviousEntryHash)
	for _, n := range tb.RootNodes {
		total += len(n.NodeID) + len(n.SigKey)
	}
	for author, sig := range tb.Signatures {
		if len(author) == 0 || len(author) > 256 || len(sig) > 256 {
			return [32]byte{}, ErrV2Context
		}
		total += len(author) + len(sig)
	}
	if total > 1<<20 {
		return [32]byte{}, ErrV2Context
	}
	raw, err := types.Cbor.Marshal(tb)
	if err != nil {
		return [32]byte{}, err
	}
	var owned types.RootTrustBaseV1
	if err = types.Cbor.Unmarshal(raw, &owned); err != nil {
		return [32]byte{}, err
	}
	sort.Slice(owned.RootNodes, func(i, j int) bool { return owned.RootNodes[i].NodeID < owned.RootNodes[j].NodeID })
	trust, err := types.Cbor.Marshal(&owned)
	if err != nil {
		return [32]byte{}, err
	}
	tuple := struct {
		_         struct{} `cbor:",toarray"`
		Domain    string
		Version   uint64
		Network   types.NetworkID
		Partition types.PartitionID
		Shard     []byte
		Conf      []byte
		Epoch     uint64
		Trust     []byte
	}{Domain: "configured-progress/observation-profile", Version: 1, Network: c.NetworkID, Partition: c.PartitionID, Shard: c.ShardID.Bytes(), Conf: bytes.Clone(c.ShardConfHash), Epoch: c.RootEpoch, Trust: trust}
	b, err := types.Cbor.Marshal(tuple)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// AdmissionProfileBindingV2 additionally binds the configured genesis-origin
// identity used by an admission coordinator.
func AdmissionProfileBindingV2(c ObservationContextV2, tb *types.RootTrustBaseV1, originIdentity []byte) ([32]byte, error) {
	if len(originIdentity) != sha256.Size {
		return [32]byte{}, ErrV2Context
	}
	observation, err := ObservationProfileBindingV2(c, tb)
	if err != nil {
		return [32]byte{}, err
	}
	tuple := struct {
		_           struct{} `cbor:",toarray"`
		Domain      string
		Version     uint64
		Observation []byte
		Origin      []byte
	}{Domain: "configured-progress/admission-profile", Version: 1, Observation: observation[:], Origin: bytes.Clone(originIdentity)}
	b, err := types.Cbor.Marshal(tuple)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

var (
	ErrV2Context  = errors.New("rootinput: v2 configured context mismatch")
	ErrV2Shape    = errors.New("rootinput: v2 authenticated origin shape invalid")
	ErrV2Ancestry = errors.New("rootinput: v2 execution ancestry mismatch")
)

// unsupportedObservationV2 reports that a correctly authenticated statement is outside
// the configured v2 profile. It grants no observation, freshness, or readiness authority.
// The classifier deliberately recognizes only the direct error returned by this package;
// trust-provider errors which happen to wrap the same sentinels are not authenticated evidence.
type unsupportedObservationV2 struct{ cause error }

func (e *unsupportedObservationV2) Error() string { return e.cause.Error() }
func (e *unsupportedObservationV2) Unwrap() error { return e.cause }

func unsupportedV2(cause error) error { return &unsupportedObservationV2{cause: cause} }

// IsUnsupportedObservationV2 classifies only a direct post-authentication profile refusal.
func IsUnsupportedObservationV2(err error) bool {
	_, ok := err.(*unsupportedObservationV2)
	return ok
}

// ErrConfEpochUnknown refuses an observation whose shard epoch has no installed configuration yet.
var ErrConfEpochUnknown = errors.New("rootinput: no installed shard configuration for the certificate's shard epoch")

// ObservationContextV2 contains only locally configured trust and identity pins.
type ObservationContextV2 struct {
	NetworkID     types.NetworkID
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte
	// ConfForEpoch, when set, supersedes ShardConfHash: the certificate must commit to exactly the
	// configuration hash installed for the shard epoch its technical record names (which the unicity certificate binds). A shard epoch
	// with no installed configuration is ErrConfEpochUnknown (retryable once its assignment is installed), never a fallback to
	// another epoch's hash. The pinned ShardConfHash stays the deployment's genesis identity.
	ConfForEpoch func(shardEpoch uint64) ([]byte, bool)
	RootEpoch    uint64
	TrustBases   TrustBases
	// EpochAuthority is set only for profile 2. It reports the epoch whose
	// handoff has been installed; nil preserves the fixed genesis profile.
	EpochAuthority RootEpochAuthority
}

// RootEpochAuthority is backed by locally verified handoff state. A trust
// history lookup alone does not grant current-epoch authority.
type RootEpochAuthority interface {
	CurrentRootEpoch() (uint64, bool)
}

// VerifiedObservationV2 is authenticated signed evidence, but makes no execution ancestry/readiness claim.
type VerifiedObservationV2 struct {
	network   types.NetworkID
	partition types.PartitionID
	shard     []byte
	conf      []byte
	rootEpoch uint64
	origin    evmroot.RootOriginV2
	class     evmroot.OriginClassV2
	uc        *types.UnicityCertificate
	tr        *certification.TechnicalRecord
}

func (o VerifiedObservationV2) Valid() bool {
	return o.uc != nil && o.tr != nil && o.class != evmroot.OriginInvalidV2
}
func (o VerifiedObservationV2) Class() evmroot.OriginClassV2   { return o.class }
func (o VerifiedObservationV2) OriginIdentity() evmroot.Hash32 { return o.origin.Identity() }
func (o VerifiedObservationV2) Origin() evmroot.RootOriginV2   { return cloneOriginV2(o.origin) }
func (o VerifiedObservationV2) Certificate() *types.UnicityCertificate {
	if o.uc == nil {
		return nil
	}
	u, _, _ := own(o.uc, o.tr)
	return u
}
func (o VerifiedObservationV2) TechnicalRecord() *certification.TechnicalRecord {
	if o.tr == nil {
		return nil
	}
	_, t, _ := own(o.uc, o.tr)
	return t
}

// AuthenticateObservationV2 authenticates current signed evidence without an
// EVM witness. Historical callers use AuthenticateHistoricalObservationV2 and
// must never turn that result into current consumer authority.
func AuthenticateObservationV2(ctx context.Context, c ObservationContextV2, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (VerifiedObservationV2, error) {
	return authenticateObservationV2(ctx, c, uc, tr, false)
}

// AuthenticateHistoricalObservationV2 verifies a previously admitted record
// under its signer epoch, including after the local current epoch advances.
func AuthenticateHistoricalObservationV2(ctx context.Context, c ObservationContextV2, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (VerifiedObservationV2, error) {
	return authenticateObservationV2(ctx, c, uc, tr, true)
}

func authenticateObservationV2(ctx context.Context, c ObservationContextV2, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, historical bool) (VerifiedObservationV2, error) {
	if c.TrustBases == nil || len(c.ShardConfHash) != 32 || uc == nil || tr == nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: incomplete observation context/evidence", ErrContextIncomplete)
	}
	u, t, err := own(uc, tr)
	if err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: %v", ErrContextIncomplete, err)
	}
	conf := bytes.Clone(c.ShardConfHash)
	shard := bytes.Clone(c.ShardID.Bytes())
	if err = t.IsValid(); err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: technical record: %w", ErrUnauthenticated, err)
	}
	if err = t.HashMatches(u.TRHash); err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: technical record binding: %w", ErrUnauthenticated, err)
	}
	tb, err := c.TrustBases.GetByEpoch(ctx, u.GetRootEpoch())
	if err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: local trust base epoch %d: %w", ErrUnauthenticated, u.GetRootEpoch(), err)
	}
	if tb == nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: no local trust base for epoch %d", ErrUnauthenticated, u.GetRootEpoch())
	}
	if c.ConfForEpoch != nil {
		installed, ok := c.ConfForEpoch(t.Epoch)
		if !ok || len(installed) != 32 {
			return VerifiedObservationV2{}, fmt.Errorf("%w: shard epoch %d", ErrConfEpochUnknown, t.Epoch)
		}
		conf = bytes.Clone(installed)
		if err = u.Verify(tb, crypto.SHA256, c.PartitionID, c.ShardID, conf); err != nil {
			return VerifiedObservationV2{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
		}
	} else if err = u.Verify(tb, crypto.SHA256, c.PartitionID, c.ShardID, conf); err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if u.UnicitySeal == nil || uint64(u.UnicitySeal.NetworkID) != uint64(c.NetworkID) {
		return VerifiedObservationV2{}, fmt.Errorf("%w: network", ErrWrongContext)
	}
	current := c.RootEpoch
	if c.EpochAuthority != nil {
		var ready bool
		current, ready = c.EpochAuthority.CurrentRootEpoch()
		if !ready || current < c.RootEpoch {
			return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: current root epoch is unavailable", ErrV2Context))
		}
	}
	if !historical && u.GetRootEpoch() != current {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: certificate root epoch %d, current %d", ErrV2Context, u.GetRootEpoch(), current))
	}
	if historical && (u.GetRootEpoch() > current || (c.EpochAuthority == nil && u.GetRootEpoch() != current)) {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: historical root epoch %d exceeds installed %d", ErrV2Context, u.GetRootEpoch(), current))
	}
	if u.InputRecord == nil {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: missing input record", ErrV2Shape))
	}
	ir := u.InputRecord
	o := evmroot.RootOriginV2{NetworkID: uint64(u.UnicitySeal.NetworkID), RootRound: u.UnicitySeal.RootChainRoundNumber, RootEpoch: u.UnicitySeal.Epoch, ReferenceTime: u.UnicitySeal.Timestamp, UnicityTreeRoot: bytes.Clone(u.UnicitySeal.Hash), InputVersion: uint64(ir.Version), IR: evmroot.ShardInputRecord{Round: ir.RoundNumber, Epoch: ir.Epoch, PreviousHash: bytes.Clone(ir.PreviousHash), Hash: bytes.Clone(ir.Hash), Timestamp: ir.Timestamp, BlockHash: bytes.Clone(ir.BlockHash)}, TRHash: bytes.Clone(u.TRHash), ShardConfHash: bytes.Clone(u.ShardConfHash)}
	class, err := o.Class()
	if err != nil {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: %v", ErrV2Shape, err))
	}
	if class == evmroot.OriginBootstrapV2 && (ir.SumOfEarnedFees != 0 || ir.SummaryValue != nil || ir.ETHash != nil) {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: bootstrap requires the exact initial input record", ErrV2Shape))
	}
	// Shard epochs are authenticated by the certificate. The authorized (technical record) epoch
	// is never behind the certified one; DeriveV2 binds both to the registry's assignment.
	if t.Epoch < ir.Epoch {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: authorized shard epoch %d is behind certified epoch %d", ErrV2Context, t.Epoch, ir.Epoch))
	}
	if t.Round == 0 || t.Round <= ir.RoundNumber {
		return VerifiedObservationV2{}, unsupportedV2(fmt.Errorf("%w: authorized round %d must strictly advance certified round %d", ErrV2Shape, t.Round, ir.RoundNumber))
	}
	return VerifiedObservationV2{network: c.NetworkID, partition: c.PartitionID, shard: shard, conf: conf, rootEpoch: u.GetRootEpoch(), origin: o, class: class, uc: u, tr: t}, nil
}

// ContextV2 binds an authenticated observation to trusted genesis and one exact verified parent witness.
// ParentHash is a caller-owned authenticated continuity premise, as in v1; Snapshot alone does not certify it.
type ContextV2 struct {
	Genesis            registrygenesis.GenesisOrigin
	Parent             registryproof.Snapshot
	Round              uint64
	ParentHash         []byte
	TransitionsPending bool
	// Transition is supplied by the verified, installed root handoff anchor.
	// It is included exactly once, while the parent registry is still in the old epoch.
	Transition []byte
}

type ResultV2 struct {
	Input       evmroot.RootInputV2
	Encoded     []byte
	Commitment  evmroot.Hash32
	Observation VerifiedObservationV2
}

func DeriveV2(c ContextV2, o VerifiedObservationV2) (ResultV2, error) {
	if !o.Valid() || !c.Genesis.Valid() || !c.Parent.Valid() {
		return ResultV2{}, fmt.Errorf("%w: observation, genesis origin, and snapshot are required", ErrV2Context)
	}
	var transition handoff.EVMTransition
	if c.TransitionsPending {
		var err error
		transition, err = handoff.DecodeEVMTransition(c.Transition)
		if err != nil {
			return ResultV2{}, fmt.Errorf("%w: missing or invalid installed transition", ErrUnsupported)
		}
	} else if len(c.Transition) != 0 {
		return ResultV2{}, fmt.Errorf("%w: transition without pending handoff", ErrUnsupported)
	}
	parent := bytes.Clone(c.ParentHash)
	if len(parent) != 32 || !bytes.Equal(parent, c.Parent.ParentHash().Bytes()) {
		return ResultV2{}, fmt.Errorf("%w: chosen snapshot subject is not the pinned parent", ErrV2Ancestry)
	}
	r := c.Genesis.Record()
	if uint64(o.network) != r.NetworkID || uint64(o.partition) != r.PartitionID || !bytes.Equal(o.shard, r.ShardID) {
		return ResultV2{}, fmt.Errorf("%w: observation and genesis origin name different deployment contexts", ErrV2Context)
	}
	f := c.Parent.Fields()
	layout2 := f.Layout == registryproof.LayoutVersion2
	genesisConf := c.Genesis.FullShardConfHash().Bytes()
	activeConf := genesisConf
	var activeShardEpoch uint64
	if layout2 {
		activeConf, activeShardEpoch = f.ActiveConfHash.Bytes(), f.ShardEpoch
	}
	if c.TransitionsPending {
		expectedOldConf := genesisConf
		if layout2 {
			expectedOldConf = f.ActiveConfHash.Bytes()
		}
		if transition.OldRootEpoch != f.RootEpoch || transition.NewRootEpoch != o.rootEpoch ||
			transition.OldShardEpoch != activeShardEpoch || !bytes.Equal(transition.OldActiveConfHash[:], expectedOldConf) ||
			!bytes.Equal(transition.Ack.FrozenParent[:], parent) {
			return ResultV2{}, fmt.Errorf("%w: transition epoch, registry assignment or frozen parent mismatch", ErrV2Context)
		}
		// The acknowledgement names the certified shard epoch of the parent and the latest
		// installed assignment: the origin's IR epoch and the authenticated technical record.
		if transition.OldShardEpoch != o.origin.IR.Epoch || transition.NewShardEpoch != o.tr.Epoch ||
			!bytes.Equal(transition.NewActiveConfHash[:], o.conf) {
			return ResultV2{}, fmt.Errorf("%w: transition does not match the certified origin and authorized assignment", ErrV2Context)
		}
		if !layout2 && (transition.NewShardEpoch != 0 || transition.SupersessionSpan != 0) {
			return ResultV2{}, fmt.Errorf("%w: registry layout 1 cannot acknowledge an assignment change", ErrV2Context)
		}
	} else {
		if o.rootEpoch != f.RootEpoch {
			return ResultV2{}, fmt.Errorf("%w: root epoch change requires installed transition", ErrV2Context)
		}
		// Ordinary execution: certified epoch = authorized epoch = registry assignment, and the
		// certificate carries that assignment's configuration.
		if o.origin.IR.Epoch != activeShardEpoch || o.tr.Epoch != activeShardEpoch || !bytes.Equal(o.conf, activeConf) {
			return ResultV2{}, fmt.Errorf("%w: certified/authorized shard epoch or configuration differs from the registry assignment", ErrV2Context)
		}
	}
	pc := c.Genesis.ProofContext()
	verified := c.Parent.VerifiedContext()
	verified.Active = registryproof.Assignment{} // the authenticated assignment narrows a read; it is not deployment identity
	if verified != pc {
		return ResultV2{}, fmt.Errorf("%w: snapshot and genesis origin use different proof contexts", ErrV2Context)
	}
	if c.Round != o.tr.Round {
		return ResultV2{}, fmt.Errorf("%w: pinned round %d, authenticated assignment %d", ErrNotPinned, c.Round, o.tr.Round)
	}
	var boundTransition []byte
	if c.TransitionsPending {
		// The committed successor TR names the first assignment, but T2 may
		// advance it before the acknowledgement block is built. Bind the Ack
		// to the authenticated assignment used by this exact block.
		transition.Ack.EVMRound = c.Round
		var err error
		boundTransition, err = transition.Encode()
		if err != nil {
			return ResultV2{}, fmt.Errorf("%w: bound acknowledgement: %v", ErrV2Context, err)
		}
	}
	if !c.TransitionsPending && o.origin.RootRound < c.Parent.LastAppliedRootRound() {
		return ResultV2{}, fmt.Errorf("%w: root round %d behind committed cursor %d", ErrNotPinned, o.origin.RootRound, c.Parent.LastAppliedRootRound())
	}
	b0, s0 := c.Genesis.BlockHash(), c.Genesis.StateRoot()
	switch o.class {
	case evmroot.OriginBootstrapV2:
		if !c.Parent.Genesis() || c.Parent.Number() != 0 || c.Parent.ParentHash() != b0 || c.Parent.StateRoot() != s0 || c.Parent.HeaderParentHash() != (common.Hash{}) || f.OutcomesRound != 0 {
			return ResultV2{}, fmt.Errorf("%w: bootstrap requires exact unexecuted B0 witness", ErrV2Ancestry)
		}
	case evmroot.OriginFirstCertifiedV2:
		if c.Parent.Genesis() || c.Parent.Number() != 1 || c.Parent.ParentHash() != common.BytesToHash(o.origin.IR.BlockHash) || c.Parent.StateRoot() != common.BytesToHash(o.origin.IR.Hash) || c.Parent.HeaderParentHash() != b0 || f.OutcomesRound != o.origin.IR.Round {
			return ResultV2{}, fmt.Errorf("%w: first-certified witness is not B1/S1 at executed round with predecessor B0", ErrV2Ancestry)
		}
	case evmroot.OriginOrdinaryV2:
		if c.Parent.Genesis() {
			return ResultV2{}, fmt.Errorf("%w: authenticated non-bootstrap history cannot use B0", ErrV2Ancestry)
		}
		if !bytes.Equal(o.origin.IR.PreviousHash, o.origin.IR.Hash) {
			if c.Parent.ParentHash() != common.BytesToHash(o.origin.IR.BlockHash) || c.Parent.StateRoot() != common.BytesToHash(o.origin.IR.Hash) || f.OutcomesRound != o.origin.IR.Round {
				return ResultV2{}, fmt.Errorf("%w: ordinary state-changing witness does not match certified block/state/round", ErrV2Ancestry)
			}
		} else if c.Parent.StateRoot() != common.BytesToHash(o.origin.IR.Hash) || f.OutcomesRound > o.origin.IR.Round {
			return ResultV2{}, fmt.Errorf("%w: quiet parent state/cursor contradicts authenticated history", ErrV2Ancestry)
		}
	default:
		return ResultV2{}, fmt.Errorf("%w: invalid class", ErrV2Shape)
	}
	ri := evmroot.RootInputV2{Version: evmroot.ProfileVersionV2, NetworkID: uint64(o.network), PartitionID: uint64(o.partition), ShardID: bytes.Clone(o.shard), Round: c.Round, CertifiedEpoch: o.origin.IR.Epoch, AuthorizedEpoch: o.tr.Epoch, ParentHash: parent, Origin: cloneOriginV2(o.origin), TE: evmroot.TechnicalRecord{Round: o.tr.Round, Epoch: o.tr.Epoch, Leader: o.tr.Leader, StatHash: bytes.Clone(o.tr.StatHash), FeeHash: bytes.Clone(o.tr.FeeHash)}}
	if c.TransitionsPending {
		ri.Transitions = [][]byte{boundTransition}
	}
	if err := ri.Validate(); err != nil {
		return ResultV2{}, fmt.Errorf("%w: %v", ErrV2Shape, err)
	}
	return ResultV2{Input: ri, Encoded: ri.Encode(), Commitment: ri.ExtraData(), Observation: o.clone()}, nil
}

func (o VerifiedObservationV2) clone() VerifiedObservationV2 {
	u, t, _ := own(o.uc, o.tr)
	o.uc, o.tr = u, t
	o.conf = bytes.Clone(o.conf)
	o.shard = bytes.Clone(o.shard)
	o.origin = cloneOriginV2(o.origin)
	return o
}
func cloneOriginV2(o evmroot.RootOriginV2) evmroot.RootOriginV2 {
	o.UnicityTreeRoot = bytes.Clone(o.UnicityTreeRoot)
	o.TRHash = bytes.Clone(o.TRHash)
	o.ShardConfHash = bytes.Clone(o.ShardConfHash)
	o.IR.PreviousHash = bytes.Clone(o.IR.PreviousHash)
	o.IR.Hash = bytes.Clone(o.IR.Hash)
	o.IR.BlockHash = bytes.Clone(o.IR.BlockHash)
	return o
}
