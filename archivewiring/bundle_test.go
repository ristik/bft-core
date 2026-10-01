package archivewiring

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-go-base/types"
)

type recordingBundleHistory struct{ requested []uint64 }

func (h *recordingBundleHistory) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	h.requested = append(h.requested, epoch)
	return nil, errors.New("unavailable predecessor")
}

func TestBundleVerificationSelectsPredecessorTrustEpoch(t *testing.T) {
	history := &recordingBundleHistory{}
	q := archive.BundleRequest{Context: transportBundleContext(), Epoch: 2}
	bundle := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}}, Body: evmroot.TrustBaseBodyV2{Epoch: 2}}
	raw, err := handoffdelivery.EncodeBundle(bundle)
	require.NoError(t, err)
	require.ErrorContains(t, VerifyBundle(context.Background(), q, raw, history), "unavailable predecessor")
	require.Equal(t, []uint64{1}, history.requested)
	q.Epoch = 3
	require.ErrorIs(t, VerifyBundle(context.Background(), q, raw, history), archive.ErrInvalid)
	require.Equal(t, []uint64{1}, history.requested, "wrong successor epoch never selects a trust base")
	bundle.Proof.Record.Epoch, bundle.Body.Epoch = 2, 3
	raw, err = handoffdelivery.EncodeBundle(bundle)
	require.NoError(t, err)
	require.ErrorContains(t, VerifyBundle(context.Background(), q, raw, history), "unavailable predecessor")
	require.Equal(t, []uint64{1, 2}, history.requested)
}

func transportBundleContext() archive.Context {
	q, _ := transportFixture()
	return q.Context
}
