package q3active_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// volatileSink is a root sink whose installed state is lost on restart, as a shard node's is.
type volatileSink struct {
	held      map[uint64]bool
	installs  int
	restores  int
	restoring bool
}

func (s *volatileSink) InstallVerifiedEpoch(e q3format.Entry, _ handoff.OldCommitProof, head *abdrc.CommittedBlock, _ []byte) (*rctypes.EpochAnchor, error) {
	if head == nil {
		return nil, errors.New("no checkpoint")
	}
	s.installs++
	s.held[e.Epoch()] = true
	return &rctypes.EpochAnchor{}, nil
}
func (s *volatileSink) HoldsVerifiedEpoch(e q3format.Entry) error {
	if !s.held[e.Epoch()] {
		return errors.New("not installed")
	}
	return nil
}

type restoringSink struct{ volatileSink }

func (s *restoringSink) RestoreVerifiedEpoch(e q3format.Entry, _ handoff.OldCommitProof, head *abdrc.CommittedBlock, _ []byte) error {
	if head == nil {
		return errors.New("no checkpoint")
	}
	s.restores++
	s.held[e.Epoch()] = true
	return nil
}

// A volatile root sink is rebuilt by the journal's restore on every start; a sink that cannot be restored fails the check, so a restart
// never reports an activation installed that this process does not hold.
func TestAVolatileRootSinkIsRestoredBeforeTheJournalChecksIt(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)

	start := func(root q3active.RootSink) *q3active.Runtime {
		rt, err := q3active.New(q3active.Config{DB: p.DB, Genesis: f.Old})
		require.NoError(t, err)
		p.Safety.Bind(rt)
		p.Shard.Bind(rt)
		p.Authority.Bind(rt)
		require.NoError(t, rt.Attach(q3active.Participants{Root: root, Safety: p.Safety, Shard: p.Shard, Authority: p.Authority}))
		return rt
	}

	first := &restoringSink{volatileSink{held: map[uint64]bool{}}}
	rt := start(first)
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.Bundle()))
	require.Equal(t, 1, first.installs)
	require.Zero(t, first.restores)
	require.EqualValues(t, f.Claim.Epoch, rt.ActiveEpoch())

	// the process restarts: a new runtime over the durable journal, and a sink that holds nothing
	second := &restoringSink{volatileSink{held: map[uint64]bool{}}}
	rt = start(second)
	require.Zero(t, rt.ActiveEpoch(), "nothing is active before recovery")
	require.NoError(t, rt.Recover(ctx))
	require.Equal(t, 1, second.restores, "the finished activation was restored into the sink")
	require.Zero(t, second.installs, "and not installed again")
	require.NoError(t, rt.Admit(f.Claim.Epoch))
	require.EqualValues(t, f.Claim.Epoch, rt.ActiveEpoch())

	// a sink that holds nothing and cannot be restored fails the journal's check
	third := &volatileSink{held: map[uint64]bool{}}
	rt = start(third)
	require.Error(t, rt.Recover(ctx), "the restart does not report an activation installed that this process does not hold")
	require.Error(t, rt.Admit(f.Claim.Epoch))
	require.Zero(t, rt.ActiveEpoch())
}
