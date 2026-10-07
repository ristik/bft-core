package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// TestExactlyTheHeavyMemberAndOneLightMemberFormTheQuorum is the manager-level exact case: the QC is collected from the heavy member
// (6) and one light member (1) and no one else, its signers weigh exactly 7 of 9, and the certificate verifies independently under
// the epoch's own trust base and signing configuration.
func TestExactlyTheHeavyMemberAndOneLightMemberFormTheQuorum(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	ctx := context.Background()
	collector := c.firstProposal(anchor.Slot)
	before := collector.manager.pacemaker.GetCurrentRound()
	light := c.lights()[0]

	require.NoError(t, collector.manager.onVoteMsg(ctx, c.voteOf(light)))
	require.Equal(t, before, collector.manager.pacemaker.GetCurrentRound(), "light 1 of 9: no QC")
	require.NoError(t, collector.manager.onVoteMsg(ctx, c.voteOf(c.heavy())))
	require.Greater(t, collector.manager.pacemaker.GetCurrentRound(), before, "heavy 6 + light 1 = 7: the round moves on")

	qc := collector.net.WaitRootProposal(t).Block.Qc
	require.NotNil(t, qc)
	tb := collector.manager.trustBase.Load()
	var weight uint64
	for _, n := range tb.RootNodes {
		if _, signed := qc.Signatures[n.NodeID]; signed {
			weight += n.Stake
		}
	}
	require.Len(t, qc.Signatures, 2, "no other member signed")
	require.Contains(t, qc.Signatures, c.heavy().id().String())
	require.Contains(t, qc.Signatures, light.id().String())
	require.EqualValues(t, 7, weight, "the signers weigh exactly the threshold")
	cfg, err := collector.trust.SigningConfig(2)
	require.NoError(t, err)
	require.NoError(t, qc.VerifyScheme(tb, cfg), "the certificate verifies independently of the manager that built it")
	require.Equal(t, votesig.SchemeDomainBound, qc.Scheme)
}

// TestAnIncompleteLeaderSignsAndBroadcastsNoProposal drives the leader side of the activation gate: the root step has installed the
// epoch and its pacemaker runs, but the authority step failed, so Admit(2) is ErrNotActive and the leader makes no proposal.
func TestAnIncompleteLeaderSignsAndBroadcastsNoProposal(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	ctx := context.Background()

	// install the root step on one replica to learn the leader of the first successor round, then make that replica the stuck one
	probe := c.replicas[0]
	probe.authority.off.Store(true)
	require.NoError(t, probe.rt.Recover(ctx))
	require.ErrorIs(t, probe.rt.Activate(ctx, probe.bundle()), q3active.ErrNotBound)
	anchor := probe.manager.epochAnchor
	first, err := probe.manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	leader := c.byID(first)
	if leader != probe {
		probe.authority.off.Store(false)
		require.NoError(t, probe.rt.Recover(ctx))
		require.NoError(t, probe.rt.Admit(2))
		leader.authority.off.Store(true)
		require.NoError(t, leader.rt.Recover(ctx))
		require.ErrorIs(t, leader.rt.Activate(ctx, leader.bundle()), q3active.ErrNotBound)
	}
	require.ErrorIs(t, leader.rt.Admit(2), q3active.ErrNotActive)
	require.NotNil(t, leader.manager.epochAnchor, "the root step finished: the manager holds the epoch")
	leader.startConsensus()

	leader.manager.processNewRoundEvent(ctx)
	require.Empty(t, leader.net.SentMessages(network.ProtocolRootProposal), "the leader of an incompletely installed epoch broadcasts no proposal")

	// the same leader, once wired, recovered and admitted, proposes
	leader.authority.off.Store(false)
	require.NoError(t, leader.rt.Recover(ctx))
	require.NoError(t, leader.rt.Admit(2))
	leader.manager.processNewRoundEvent(ctx)
	require.EqualValues(t, anchor.Slot+1, leader.net.WaitRootProposal(t).Block.Round)
}

// TestACoupledHandoffIsNotInstalledAsRootOnly: the committed candidate of an assignment handoff is not the recomputable root-only
// operator candidate, so omitting its preimage must not make the install succeed, at the manager or through the runtime.
func TestACoupledHandoffIsNotInstalledAsRootOnly(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	rootOnly := q3fixture.New(t, q3fixture.Options{Chain: f})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	coupled, err := h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	plain, err := h.VerifyEnvelope(rootOnly.Envelope)
	require.NoError(t, err)
	require.False(t, coupled.Tip().RootOnly(), "the committed candidate is an EVM assignment")
	require.True(t, plain.Tip().RootOnly(), "the committed candidate is the operator candidate of the members")

	t.Run("the manager refuses the omitted candidate of an assignment", func(t *testing.T) {
		r := newQ3Replica(t, f, f.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		require.NoError(t, r.trust.BindSigningAuthority(coupled))
		_, err := r.manager.InstallVerifiedEpoch(coupled.Tip(), f.Proof, f.Snapshot, nil)
		require.ErrorIs(t, err, ErrQ3Candidate)
		require.ErrorContains(t, err, "not the root-only operator candidate")
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound, "nothing was installed")
		require.Nil(t, r.manager.epochAnchor)
	})
	t.Run("the manager refuses the supplied candidate of an assignment", func(t *testing.T) {
		r := newQ3Replica(t, f, f.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		require.NoError(t, r.trust.BindSigningAuthority(coupled))
		_, err := r.manager.InstallVerifiedEpoch(coupled.Tip(), f.Proof, f.Snapshot, f.Candidate)
		require.ErrorIs(t, err, ErrQ3Candidate)
		require.NotContains(t, err.Error(), "operator candidate")
	})
	t.Run("the runtime does not admit an epoch whose candidate was omitted", func(t *testing.T) {
		r := newQ3Replica(t, f, f.NewNodes[0])
		r.mustOpen(true)
		t.Cleanup(r.close)
		require.NoError(t, r.rt.Recover(context.Background()))
		err := r.rt.Activate(context.Background(), r.bundle())
		require.ErrorIs(t, err, ErrQ3Candidate)
		require.ErrorIs(t, r.rt.Admit(2), q3active.ErrNotActive)
	})
	t.Run("a root-only handoff installs without a candidate", func(t *testing.T) {
		r := newQ3Replica(t, rootOnly, rootOnly.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		require.NoError(t, r.trust.BindSigningAuthority(plain))
		a, err := r.manager.InstallVerifiedEpoch(plain.Tip(), rootOnly.Proof, rootOnly.Snapshot, nil)
		require.NoError(t, err)
		require.EqualValues(t, 2, a.Epoch)
	})
}
