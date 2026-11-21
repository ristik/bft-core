package shardnode

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The fence decides from the authenticated schedule of the checkpoint the bundle carries (empty in the fixture), at the epoch installed.
func TestHandoffInstallFence(t *testing.T) {
	ctx := context.Background()
	fx := handoffbundle.New(t)
	bundle := handoffdelivery.Bundle{Proof: fx.Proof, Body: fx.Body, Snapshot: fx.Snapshot}
	var seen []uint64
	install := func(f func(uint64, []vrschema.Activation) error) (*HistoricalTrustBaseStore, error) {
		s, err := NewHistoricalTrustBaseStore(ctx, memorydb.New(), fx.Old, [32]byte{2}, true, WithFence(f))
		require.NoError(t, err)
		_, err = s.InstallHandoff(ctx, bundle, fx.Partition, fx.Shard, fx.ConfHash)
		return s, err
	}
	epoch := bundle.Body.Epoch

	_, err := install(func(e uint64, sched []vrschema.Activation) error {
		seen = append(seen, e)
		require.Empty(t, sched)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []uint64{epoch}, seen)
	_, err = install(nil)
	require.NoError(t, err, "no fence")

	// the real gate over that (empty) checkpoint schedule passes without an endpoint
	gate := vrrules.NewGate(vrrules.StaticSource{Err: errors.New("no endpoint is needed")}, vrrules.Set{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err = install(gate.CheckCheckpoint)
	require.NoError(t, err)

	refuse := &vrrules.UpgradeRequired{RootEpoch: epoch}
	s, err := install(func(uint64, []vrschema.Activation) error { return refuse })
	require.ErrorIs(t, err, vrrules.ErrUpgradeRequired)
	_, getErr := s.GetByEpoch(ctx, epoch)
	require.Error(t, getErr, "nothing of the epoch was appended")
}
