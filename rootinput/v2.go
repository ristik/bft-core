package rootinput

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrV2Context  = errors.New("rootinput: v2 configured context mismatch")
	ErrV2Shape    = errors.New("rootinput: v2 authenticated origin shape invalid")
	ErrV2Ancestry = errors.New("rootinput: v2 execution ancestry mismatch")
)

// ObservationContextV2 contains only locally configured trust and identity pins.
type ObservationContextV2 struct {
	NetworkID     types.NetworkID
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte
	RootEpoch     uint64
	TrustBases    TrustBases
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

// AuthenticateObservationV2 authenticates and classifies signed evidence without requiring an EVM witness.
func AuthenticateObservationV2(ctx context.Context, c ObservationContextV2, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (VerifiedObservationV2, error) {
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
	if err = u.Verify(tb, crypto.SHA256, c.PartitionID, c.ShardID, conf); err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if u.UnicitySeal == nil || uint64(u.UnicitySeal.NetworkID) != uint64(c.NetworkID) {
		return VerifiedObservationV2{}, fmt.Errorf("%w: network", ErrWrongContext)
	}
	if u.GetRootEpoch() != c.RootEpoch {
		return VerifiedObservationV2{}, fmt.Errorf("%w: certificate root epoch %d, configured %d", ErrV2Context, u.GetRootEpoch(), c.RootEpoch)
	}
	if u.InputRecord == nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: missing input record", ErrV2Shape)
	}
	ir := u.InputRecord
	o := evmroot.RootOriginV2{NetworkID: uint64(u.UnicitySeal.NetworkID), RootRound: u.UnicitySeal.RootChainRoundNumber, RootEpoch: u.UnicitySeal.Epoch, ReferenceTime: u.UnicitySeal.Timestamp, UnicityTreeRoot: bytes.Clone(u.UnicitySeal.Hash), InputVersion: uint64(ir.Version), IR: evmroot.ShardInputRecord{Round: ir.RoundNumber, Epoch: ir.Epoch, PreviousHash: bytes.Clone(ir.PreviousHash), Hash: bytes.Clone(ir.Hash), Timestamp: ir.Timestamp, BlockHash: bytes.Clone(ir.BlockHash)}, TRHash: bytes.Clone(u.TRHash), ShardConfHash: bytes.Clone(u.ShardConfHash)}
	class, err := o.Class()
	if err != nil {
		return VerifiedObservationV2{}, fmt.Errorf("%w: %v", ErrV2Shape, err)
	}
	if class == evmroot.OriginBootstrapV2 && (ir.SumOfEarnedFees != 0 || ir.SummaryValue != nil || ir.ETHash != nil) {
		return VerifiedObservationV2{}, fmt.Errorf("%w: bootstrap requires the exact initial input record", ErrV2Shape)
	}
	if ir.Epoch != 0 || t.Epoch != 0 {
		return VerifiedObservationV2{}, fmt.Errorf("%w: only shard epoch zero is supported", ErrV2Context)
	}
	if t.Round == 0 || t.Round <= ir.RoundNumber {
		return VerifiedObservationV2{}, fmt.Errorf("%w: authorized round %d must strictly advance certified round %d", ErrV2Shape, t.Round, ir.RoundNumber)
	}
	return VerifiedObservationV2{network: c.NetworkID, partition: c.PartitionID, shard: shard, conf: conf, rootEpoch: c.RootEpoch, origin: o, class: class, uc: u, tr: t}, nil
}

// ContextV2 binds an authenticated observation to trusted genesis and one exact verified parent witness.
// ParentHash is a caller-owned authenticated continuity premise, as in v1; Snapshot alone does not certify it.
type ContextV2 struct {
	Genesis            registrygenesis.GenesisOrigin
	Parent             registryproof.Snapshot
	Round              uint64
	ParentHash         []byte
	TransitionsPending bool
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
	if c.TransitionsPending {
		return ResultV2{}, fmt.Errorf("%w: transitions pending", ErrUnsupported)
	}
	parent := bytes.Clone(c.ParentHash)
	if len(parent) != 32 || !bytes.Equal(parent, c.Parent.ParentHash().Bytes()) {
		return ResultV2{}, fmt.Errorf("%w: chosen snapshot subject is not the pinned parent", ErrV2Ancestry)
	}
	r := c.Genesis.Record()
	if uint64(o.network) != r.NetworkID || uint64(o.partition) != r.PartitionID || !bytes.Equal(o.shard, r.ShardID) || !bytes.Equal(o.conf, c.Genesis.FullShardConfHash().Bytes()) || o.rootEpoch != r.RootEpoch {
		return ResultV2{}, fmt.Errorf("%w: observation and genesis origin name different deployment contexts", ErrV2Context)
	}
	f := c.Parent.Fields()
	pc := c.Genesis.ProofContext()
	if c.Parent.VerifiedContext() != pc {
		return ResultV2{}, fmt.Errorf("%w: snapshot and genesis origin use different proof contexts", ErrV2Context)
	}
	if c.Round != o.tr.Round {
		return ResultV2{}, fmt.Errorf("%w: pinned round %d, authenticated assignment %d", ErrNotPinned, c.Round, o.tr.Round)
	}
	if o.origin.RootRound < c.Parent.LastAppliedRootRound() {
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
