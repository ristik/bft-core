package consensus

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A Q3 activation judges the candidate with the same state-dependent rules as freeze admission: exact incumbent K, continuity,
// primary/recovery lineage and the committed history. Each case changes one thing and asserts the sentinel.

func TestQ3ActivationRefusesAForeignIncumbent(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	r := newQ3Replica(t, f, f.NewNodes[0])
	foreign := append([]evmassign.Identity(nil), f.Incumbent...)
	foreign[0].OperatorPayee = bytes.Repeat([]byte{0xEE}, evmassign.PayeeLen) // the recorded incumbent differs from K in the payee only
	r.incumbent = foreign
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(context.Background()))
	err := r.rt.Activate(context.Background(), r.bundle())
	require.ErrorIs(t, err, evmassign.ErrNotIncumbent)
	_, err = r.trust.GetByEpoch(2)
	require.Error(t, err)
}

func TestQ3ActivationEnforcesTheContinuityBudget(t *testing.T) {
	// the fixture's primary replaces one of four members (M = 2); a committed budget of one refuses it
	f := q3fixture.New(t, q3fixture.Options{Assignment: true, Params: map[string]string{storage.ParamContinuityMaxM: "1"}})
	r := newQ3Replica(t, f, f.NewNodes[0])
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(context.Background()))
	err := r.rt.Activate(context.Background(), r.bundle())
	require.ErrorIs(t, err, evmassign.ErrContinuity)
	require.ErrorIs(t, err, continuity.ErrMembership)
}

// pendingPrimary activates the fixture's primary and returns the replica with the authenticated pending state and installed primary.
func pendingPrimary(t *testing.T) (*q3Replica, *q3fixture.Fixture, types.PartitionShardID, *types.PartitionDescriptionRecord, *storage.ShardInfo, *evmassign.Supersession) {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	r := newQ3Replica(t, f, f.NewNodes[0])
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(context.Background()))
	require.NoError(t, r.rt.Activate(context.Background(), r.bundle()))
	_, err := r.manager.blockStore.Add(&rctypes.BlockData{Version: 2, Round: 7, Epoch: 2, Payload: &rctypes.Payload{Version: 2}, Anchor: r.manager.epochAnchor}, nil)
	require.NoError(t, err)
	first, err := r.manager.blockStore.Block(7)
	require.NoError(t, err)
	key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
	configs, err := r.orchestration.ShardConfigs(7)
	require.NoError(t, err)
	chain, err := storage.CommittedChain(r.orchestration, key.PartitionID, types.ShardID{}, 0)
	require.NoError(t, err)
	binding, err := chain.Supersession()
	require.NoError(t, err)
	return r, f, key, configs[key], first.ShardState.States[key], binding
}

func TestQ3ActivationRefusesAPrimaryOverAPendingPrimary(t *testing.T) {
	r, f, _, installed, pending, binding := pendingPrimary(t)
	second := q3fixture.New(t, q3fixture.Options{After: f, Assignment: true, Installed: installed, ShardState: pending,
		MutateCandidate: func(c *evmassign.Candidate) { c.Supersedes = binding }})
	err := r.rt.Activate(context.Background(), q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot, Candidate: second.Candidate})
	require.ErrorIs(t, err, evmassign.ErrPendingPrimary)
	_, err = r.trust.GetByEpoch(3)
	require.Error(t, err)
}

func TestQ3ActivationRefusesARecoveryThatDoesNotExtendThePrimary(t *testing.T) {
	cases := map[string]struct {
		mutate func(*evmassign.Candidate)
		want   error
	}{
		"replaces another assignment":   {func(c *evmassign.Candidate) { c.ReplacedAssignment[0] ^= 1 }, evmassign.ErrRecoveryLineage},
		"carries another authorization": {func(c *evmassign.Candidate) { c.Authorization.ResultID[0] ^= 1 }, evmassign.ErrAuthorization},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, f, _, installed, pending, binding := pendingPrimary(t)
			second := q3fixture.New(t, q3fixture.Options{After: f, Assignment: true, Recovery: true, Installed: installed, ShardState: pending,
				MutateCandidate: func(c *evmassign.Candidate) { c.Supersedes = binding; tc.mutate(c) }})
			err := r.rt.Activate(context.Background(), q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot, Candidate: second.Candidate})
			require.ErrorIs(t, err, tc.want)
			_, err = r.trust.GetByEpoch(3)
			require.Error(t, err)
		})
	}
}
