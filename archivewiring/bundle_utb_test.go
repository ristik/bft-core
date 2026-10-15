package archivewiring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

type profileHistory struct {
	old *types.RootTrustBaseV1
	utb bool
}

func (h profileHistory) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return h.old, nil
}

func (h profileHistory) BundleSigning(old *types.RootTrustBaseV1) votesig.Config {
	return votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(old.NetworkID), UTB: h.utb}
}

// The archive's bundle admission verifies a bundle by the profile of the history that holds its old epoch: a UTB history accepts a UTB bundle, a plain one refuses the
// version 3 certificate, and a history that names no configuration is the legacy rule.
func TestBundleAdmissionFollowsTheProfileOfTheHistory(t *testing.T) {
	f := handoffbundle.New(t)
	handoffbundle.WithUTB(t, f)
	raw, err := handoffdelivery.EncodeBundle(handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot})
	require.NoError(t, err)
	q := archive.BundleRequest{Context: transportBundleContext(), Epoch: 2}
	q.Context.PartitionID, q.Context.ShardID = f.Partition, f.Shard
	copy(q.Context.FullShardConfHash[:], f.ConfHash)

	require.NoError(t, VerifyBundle(context.Background(), q, raw, profileHistory{old: f.Old, utb: true}, nil))
	err = VerifyBundle(context.Background(), q, raw, profileHistory{old: f.Old}, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "envelope")
	err = VerifyBundle(context.Background(), q, raw, &legacyHistory{f.Old}, nil)
	require.ErrorContains(t, err, "envelope")
}

type legacyHistory struct{ old *types.RootTrustBaseV1 }

func (h *legacyHistory) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return h.old, nil
}
