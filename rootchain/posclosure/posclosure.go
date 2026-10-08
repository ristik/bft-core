// Package posclosure connects the root's P85 CloseLiability executor to the history it must be judged against: the closed epoch's own
// trust base, and the EVM assignment the orchestration installed when H was ordered. It owns no rule; storage decides.
package posclosure

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrHistory reports history the closure cannot be judged against.
var ErrHistory = errors.New("posclosure: closure history unavailable")

// TrustBases is the root's trust base store.
type TrustBases interface {
	GetByEpoch(epoch uint64) (*types.RootTrustBaseV1, error)
	SigningConfig(epoch uint64) (votesig.Config, error)
}

// Orchestration is the shard configuration history with the retained identity records.
type Orchestration interface {
	ShardConfig(partition types.PartitionID, shard types.ShardID, rootRound uint64) (*types.PartitionDescriptionRecord, error)
	AcknowledgedIdentities(partition types.PartitionID, shard types.ShardID, epoch uint64) ([]evmassign.Identity, [32]byte, error)
}

// History implements handoffdelivery.ClosureHistory over the root's stores for the EVM shard.
type History struct {
	Partition     types.PartitionID
	Shard         types.ShardID
	TrustBases    TrustBases
	Orchestration Orchestration
}

func (h History) TrustBase(epoch uint64) (*types.RootTrustBaseV1, votesig.Config, error) {
	tb, err := h.TrustBases.GetByEpoch(epoch)
	if err != nil || tb == nil {
		return nil, votesig.Config{}, errors.Join(ErrHistory, fmt.Errorf("trust base of epoch %d", epoch), err)
	}
	cfg, err := h.TrustBases.SigningConfig(epoch)
	if err != nil {
		return nil, votesig.Config{}, errors.Join(ErrHistory, fmt.Errorf("signing configuration of epoch %d", epoch), err)
	}
	return tb, cfg, nil
}

// Assignment is the configuration installed at the root round H was ordered, and its identity records: the EVM assignment the handoff
// terminates (acknowledged or still pending, whichever the root's committee of that epoch was installed with).
func (h History) Assignment(orderRound uint64) ([]byte, []evmassign.Identity, [32]byte, error) {
	var none [32]byte
	conf, err := h.Orchestration.ShardConfig(h.Partition, h.Shard, orderRound)
	if err != nil || conf == nil {
		return nil, nil, none, errors.Join(ErrHistory, fmt.Errorf("shard configuration at round %d", orderRound), err)
	}
	confHash, err := conf.Hash(crypto.SHA256)
	if err != nil {
		return nil, nil, none, errors.Join(ErrHistory, err)
	}
	ids, assignment, err := h.Orchestration.AcknowledgedIdentities(h.Partition, h.Shard, conf.Epoch)
	if err != nil {
		return nil, nil, none, errors.Join(ErrHistory, err)
	}
	return confHash, ids, assignment, nil
}

// Authority is the storage.ClosureAuthority over a verifier.
type Authority struct {
	Verifier handoffdelivery.ClosureVerifier
}

// New builds the authority of the EVM shard.
func New(history History) Authority {
	return Authority{Verifier: handoffdelivery.ClosureVerifier{Partition: history.Partition, Shard: history.Shard, History: history}}
}

func (a Authority) VerifyClosure(witness []byte, closedEpoch uint64) (storage.ClosureFacts, error) {
	ev, err := a.Verifier.Verify(witness, closedEpoch)
	if err != nil {
		return storage.ClosureFacts{}, err
	}
	return storage.ClosureFacts{ClosedEpoch: ev.ClosedEpoch, BundleID: ev.BundleID, HRecordID: ev.HRecordID, HRound: ev.HRound,
		TerminalRoot: ev.TerminalRoot, AssignmentID: ev.AssignmentID, Closed: ev.Closed}, nil
}

var _ storage.ClosureAuthority = Authority{}
var _ handoffdelivery.ClosureHistory = History{}

// BundleSource serves the finalized terminal bundle of a handoff: the bundle that opens epoch (so closes epoch-1). The consensus manager
// is one.
type BundleSource interface {
	HandoffBundle(ctx context.Context, epoch uint64) (*handoffdelivery.Bundle, error)
}

// Proposer builds the mandatory CloseLiability control a leader includes, from the root's own retained bundle. The witness is the exact
// canonical bundle bytes; the control commits to their SHA-256 and to the closure the verifier establishes from them, and the digests
// are derived from the frozen identity records, never read from the bundle's submitter.
type Proposer struct {
	Source     BundleSource
	Authority  Authority
	Deployment storage.PosDeployment
}

func (p Proposer) Closure(closedEpoch, orderingEpoch, orderingRound uint64) (rctypes.PosControl, []byte, error) {
	bundle, err := p.Source.HandoffBundle(context.Background(), closedEpoch+1)
	if err != nil || bundle == nil {
		return rctypes.PosControl{}, nil, errors.Join(ErrHistory, fmt.Errorf("terminal bundle of epoch %d", closedEpoch), err)
	}
	raw, err := handoffdelivery.EncodeBundle(*bundle)
	if err != nil {
		return rctypes.PosControl{}, nil, err
	}
	ev, err := p.Authority.Verifier.Verify(raw, closedEpoch)
	if err != nil {
		return rctypes.PosControl{}, nil, err
	}
	exposure, err := evmassign.AssignmentExposureDigest(p.Deployment.Deployment, ev.AssignmentID, ev.Closed)
	if err != nil {
		return rctypes.PosControl{}, nil, err
	}
	keys, err := evmassign.KeyHistoryDigest(ev.Closed)
	if err != nil {
		return rctypes.PosControl{}, nil, err
	}
	data := storage.ClosureData{AssignmentID: ev.AssignmentID, HRound: ev.HRound, HRecordID: ev.HRecordID, TerminalRoot: ev.TerminalRoot,
		ExposureDigest: exposure, KeyHistoryDigest: keys}
	return rctypes.PosControl{Network: p.Deployment.RootNetwork, ChainID: p.Deployment.ChainID, Custody: p.Deployment.Custody,
		OrderingEpoch: orderingEpoch, OrderingRound: orderingRound, Op: rctypes.OpCloseLiability,
		Close: &rctypes.CloseContext{ClosedEpoch: closedEpoch, BundleSemanticID: ev.BundleID}, Data: data.Encode(),
		WitnessHash: sha256.Sum256(raw)}, raw, nil
}

var _ storage.ClosureProposer = Proposer{}
