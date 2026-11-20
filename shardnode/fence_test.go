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

func TestHandoffInstallFence(t *testing.T) {
	ctx := context.Background()
	rule := vrschema.RuleID("future-rule")
	sched := func(e uint64, state uint8) vrrules.StaticSource {
		return vrrules.StaticSource{Entries: []vrschema.Activation{{RuleID: rule, ReleaseDigest: vrschema.Word{7}, RootEpoch: e, State: state, ChangeID: 1}}}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fx := handoffbundle.New(t)
	bundle := handoffdelivery.Bundle{Proof: fx.Proof, Body: fx.Body, Snapshot: fx.Snapshot}
	install := func(g *vrrules.Gate) (*HistoricalTrustBaseStore, error) {
		s, err := NewHistoricalTrustBaseStore(ctx, memorydb.New(), fx.Old, [32]byte{2}, true, WithFence(g))
		require.NoError(t, err)
		_, err = s.InstallHandoff(ctx, bundle, fx.Partition, fx.Shard, fx.ConfHash)
		return s, err
	}
	epoch := bundle.Body.Epoch

	_, err := install(vrrules.NewGate(sched(epoch+1, vrschema.ActActive), vrrules.Set{}, log))
	require.NoError(t, err, "allowed before E")
	_, err = install(vrrules.NewGate(sched(epoch, vrschema.ActSuperseded), vrrules.Set{}, log))
	require.NoError(t, err, "superseded entry ignored")
	_, err = install(vrrules.NewGate(sched(epoch, vrschema.ActActive), vrrules.Set{rule: "future-rule"}, log))
	require.NoError(t, err, "known rule passes")
	_, err = install(nil)
	require.NoError(t, err, "no source")

	for _, e := range []uint64{epoch, epoch - 1} {
		s, err := install(vrrules.NewGate(sched(e, vrschema.ActActive), vrrules.Set{}, log))
		require.ErrorIs(t, err, vrrules.ErrUpgradeRequired, "refused at and after E=%d", e)
		_, getErr := s.GetByEpoch(ctx, epoch)
		require.Error(t, getErr, "nothing of the epoch was appended")
	}

	_, err = install(vrrules.NewGate(vrrules.StaticSource{Err: errors.New("rpc down")}, vrrules.Set{}, log))
	require.Error(t, err, "source error fails closed")
	require.NotErrorIs(t, err, vrrules.ErrUpgradeRequired)
}
