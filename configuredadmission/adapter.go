// Package configuredadmission bridges the configured-progress v2 coordinator to the generic
// BFTClient admission boundary. The shard-node CLI explicitly activates this path; importing the
// package elsewhere does not register it.
package configuredadmission

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

type Factory struct {
	Store      *configuredprogress.Store
	Origin     registrygenesis.GenesisOrigin
	Invalidate func()
}

type admission struct {
	coordinator *configuredprogress.AdmissionCoordinator
	rootEpoch   uint64
}

func (a *admission) Submit(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	_, err := a.coordinator.Submit(ctx, uc, tr)
	return err
}

func (a *admission) Close() error      { return a.coordinator.Close() }
func (a *admission) RootEpoch() uint64 { return a.rootEpoch }

type finalityGate struct{ boundary shardnode.FinalityBoundary }

func (g finalityGate) WithinFinality(ctx context.Context, f func() error) error {
	release, err := g.boundary.Hold(ctx, "configured-admission")
	if err != nil {
		return err
	}
	defer release()
	if err = ctx.Err(); err != nil {
		return err
	}
	return f()
}

func (f Factory) Start(ctx context.Context, id shardnode.AdmissionIdentity, gate shardnode.FinalityBoundary, callbacks shardnode.AdmissionCallbacks) (shardnode.CertificateAdmission, error) {
	if f.Store == nil || !f.Origin.Valid() || f.Invalidate == nil || gate == nil || callbacks.AuthenticatedFeed == nil || callbacks.DeliverDurable == nil || id.TrustBases == nil {
		return nil, fmt.Errorf("configuredadmission: incomplete factory configuration")
	}
	r := f.Origin.Record()
	if uint64(id.PartitionID) != r.PartitionID || !bytes.Equal(id.ShardID.Bytes(), r.ShardID) || !bytes.Equal(id.FullShardConfHash, f.Origin.FullShardConfHash().Bytes()) {
		return nil, fmt.Errorf("configuredadmission: client identity does not match trusted genesis origin")
	}
	obs := rootinput.ObservationContextV2{NetworkID: types.NetworkID(r.NetworkID), PartitionID: id.PartitionID, ShardID: id.ShardID, ShardConfHash: bytes.Clone(id.FullShardConfHash), ConfForEpoch: id.ConfForEpoch, RootEpoch: r.RootEpoch, TrustBases: id.TrustBases}
	record := certifiedstore.Context{NetworkID: types.NetworkID(r.NetworkID), PartitionID: id.PartitionID, ShardID: id.ShardID, FullShardConfHash: bytes.Clone(id.FullShardConfHash), Registry: f.Origin.ProofContext(), TrustBases: id.TrustBases}
	coordinator, err := configuredprogress.NewAdmissionCoordinator(ctx, configuredprogress.AdmissionConfig{
		Store: f.Store, Context: configuredprogress.Context{Origin: f.Origin, Observation: obs, Record: record}, Gate: finalityGate{boundary: gate}, Invalidate: f.Invalidate,
		OnAuthenticated: func(o rootinput.VerifiedObservationV2) {
			callbacks.AuthenticatedFeed(o.Certificate(), o.TechnicalRecord())
		},
		Deliver: func(deliveryCtx context.Context, o rootinput.VerifiedObservationV2) error {
			return callbacks.DeliverDurable(deliveryCtx, o.Certificate(), o.TechnicalRecord())
		},
	})
	if err != nil {
		return nil, err
	}
	return &admission{coordinator: coordinator, rootEpoch: r.RootEpoch}, nil
}
