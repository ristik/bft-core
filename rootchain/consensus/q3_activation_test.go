package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Slice D2 of Q3 #50: a real in-process activation at a committed boundary, through the verified history and the durable install
// journal, into real root managers with real stores. The committee after the boundary weighs 6,1,1,1 (W=9, quorum 7). The skewed
// multi-node harness of #401 and the weighted leader selector of #403 are not merged, so the rounds below are driven through the
// manager handlers over the mock network, with the leader schedule the manager has today (uniform).

func (c *q3Cluster) heavy() *q3Replica { return c.replicas[0] }

func (c *q3Cluster) lights() []*q3Replica { return c.replicas[1:] }

// firstProposal has the leader of the first successor round propose and every replica handle the proposal, which each answers with
// its scheme 2 vote. It returns the replica that collects the votes.
func (c *q3Cluster) firstProposal(anchorSlot uint64) *q3Replica {
	c.t.Helper()
	ctx := context.Background()
	first, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(anchorSlot + 1)
	require.NoError(c.t, err)
	c.byID(first).manager.processNewRoundEvent(ctx)
	proposal := c.byID(first).net.WaitRootProposal(c.t)
	c.proposal = proposal
	for _, r := range c.replicas {
		require.NoError(c.t, r.manager.onProposalMsg(ctx, proposal))
	}
	next, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(anchorSlot + 2)
	require.NoError(c.t, err)
	collector := c.byID(next)
	collector.manager.pacemaker.setState(ctx, pmsRoundMatured)
	return collector
}

func (c *q3Cluster) voteOf(r *q3Replica) *abdrc.VoteMsg {
	c.t.Helper()
	votes := r.net.SentMessages(network.ProtocolRootVote)
	require.Len(c.t, votes, 1, "replica %s voted once", r.id())
	return votes[0].Message.(*abdrc.VoteMsg)
}

func TestActivationAtABoundaryWithWeights6111(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	ctx := context.Background()

	t.Run("every store holds the weighted epoch under the committed scheme", func(t *testing.T) {
		require.EqualValues(t, 6, anchor.Slot, "the successor is anchored at (E, A*-1)")
		for _, r := range c.replicas {
			tb := r.manager.trustBase.Load()
			require.EqualValues(t, 2, tb.Epoch)
			require.EqualValues(t, 7, tb.EpochStart)
			require.EqualValues(t, 7, tb.QuorumThreshold, "W=9, Q=7")
			var total uint64
			weights := map[string]uint64{}
			for _, n := range tb.RootNodes {
				total += n.Stake
				weights[n.NodeID] = n.Stake
			}
			require.EqualValues(t, 9, total)
			require.EqualValues(t, 6, weights[c.heavy().id().String()])
			for _, l := range c.lights() {
				require.EqualValues(t, 1, weights[l.id().String()])
			}
			old, err := r.trust.SigningConfig(1)
			require.NoError(t, err)
			require.EqualValues(t, votesig.SchemeLegacy, old.Scheme)
			cfg, err := r.trust.SigningConfig(2)
			require.NoError(t, err)
			require.EqualValues(t, votesig.SchemeDomainBound, cfg.Scheme)
			require.Equal(t, c.f.Genesis, cfg.Genesis)
			require.NoError(t, r.rt.Admit(2))
			require.NoError(t, r.rt.Gate(ctx, c.f.Claim))
			s := r.rt.Snapshot()
			require.EqualValues(t, 2, s.Epoch())
			require.EqualValues(t, 9, s.Total())
			require.EqualValues(t, 7, s.Threshold())
			// the shard-side and authority-side lookups serve the same verified weights
			for _, view := range []q3active.TrustLookup{r.shard, r.authority.inner.(*q3active.Guarded)} {
				got, err := view.GetByEpoch(ctx, 2)
				require.NoError(t, err)
				require.EqualValues(t, 7, got.QuorumThreshold)
			}
		}
	})

	t.Run("weight 3 of three light members is no quorum, the heavy member with one light one is", func(t *testing.T) {
		collector := c.firstProposal(anchor.Slot)
		before := collector.manager.pacemaker.GetCurrentRound()
		require.EqualValues(t, anchor.Slot+1, before)
		var heavyVote *abdrc.VoteMsg
		var lightVotes []*abdrc.VoteMsg
		for _, r := range c.replicas {
			v := c.voteOf(r)
			require.EqualValues(t, votesig.SchemeDomainBound, v.Scheme, "the successor signs scheme 2")
			if r == c.heavy() {
				heavyVote = v
			} else {
				lightVotes = append(lightVotes, v)
			}
		}
		for _, v := range lightVotes {
			require.NoError(t, collector.manager.onVoteMsg(ctx, v))
		}
		require.Equal(t, before, collector.manager.pacemaker.GetCurrentRound(),
			"three light members weigh 3 against 7: no QC, whatever their number")
		require.NoError(t, collector.manager.onVoteMsg(ctx, heavyVote))
		require.Greater(t, collector.manager.pacemaker.GetCurrentRound(), before, "heavy 6 + light 1 reaches 7: the QC forms and the round moves on")
		proposal := collector.net.WaitRootProposal(t)
		require.EqualValues(t, anchor.Slot+2, proposal.Block.Round)
		require.NotNil(t, proposal.Block.Qc)
		require.Equal(t, votesig.SchemeDomainBound, proposal.Block.Qc.Scheme, "the QC is paired")
	})
}

func TestTheHeavyMemberAloneIsNotAQuorum(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	collector := c.firstProposal(anchor.Slot)
	before := collector.manager.pacemaker.GetCurrentRound()
	require.NoError(t, collector.manager.onVoteMsg(context.Background(), c.voteOf(c.heavy())))
	require.Equal(t, before, collector.manager.pacemaker.GetCurrentRound(), "6 of 9 is below 7")
}

func TestOldFormMessagesOfTheActivatedEpochAreRefused(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	ctx := context.Background()
	collector := c.firstProposal(anchor.Slot)
	vote := c.voteOf(c.heavy())

	t.Run("a legacy-form vote of the heavy member", func(t *testing.T) {
		legacy := *vote
		legacy.Scheme, legacy.SealSignature = 0, nil
		require.ErrorIs(t, collector.manager.onVoteMsg(ctx, &legacy), votesig.ErrScheme)
	})
	t.Run("a vote with a swapped signature", func(t *testing.T) {
		forged := *vote
		forged.Signature = c.voteOf(c.lights()[0]).Signature
		require.Error(t, collector.manager.onVoteMsg(ctx, &forged))
	})
	t.Run("nothing was counted", func(t *testing.T) {
		require.EqualValues(t, anchor.Slot+1, collector.manager.pacemaker.GetCurrentRound())
		require.NoError(t, collector.manager.onVoteMsg(ctx, vote), "the authentic one still counts")
	})
}

func TestNoSignatureIsMadeBeforeTheJournalIsComplete(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	ctx := context.Background()
	// the leader of the first successor round must be able to propose, so it is never the replica that cannot complete: replica 0
	// installs first and tells who leads, and the stuck one is the last of the others
	c.replicas[0].activate()
	anchor := c.replicas[0].manager.epochAnchor
	first, err := c.replicas[0].manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	leader := c.byID(first)
	stuck := c.replicas[3]
	if leader == stuck {
		stuck = c.replicas[2]
	}
	// the stuck replica's authority was not given the guarded lookup
	stuck.authority.off.Store(true)
	for _, r := range c.replicas[1:] {
		if r != stuck {
			r.activate()
		}
	}
	require.NoError(t, stuck.rt.Recover(ctx))
	err = stuck.rt.Activate(ctx, stuck.bundle())
	require.ErrorIs(t, err, q3active.ErrNotBound)
	require.ErrorIs(t, stuck.rt.Admit(2), q3active.ErrNotActive)
	require.NotNil(t, stuck.manager.epochAnchor, "the root step finished: the manager holds the epoch")
	stuck.startConsensus()

	// the leader proposes; the stuck replica receives the proposal and signs nothing
	leader.manager.processNewRoundEvent(ctx)
	proposal := leader.net.WaitRootProposal(t)
	before := stuck.db.GetHighestVotedRound()
	err = stuck.manager.onProposalMsg(ctx, proposal)
	require.ErrorIs(t, err, q3active.ErrNotActive)
	require.Empty(t, stuck.net.SentMessages(network.ProtocolRootVote), "no vote left the node")
	require.Equal(t, before, stuck.db.GetHighestVotedRound(), "no voting state moved")
	_, err = stuck.manager.safety.RecordedTimeout(2, anchor.Slot+1)
	require.ErrorIs(t, err, q3active.ErrNotActive, "nor is an earlier timeout sent again")

	// wired, recovered and admitted: the same replica signs
	stuck.authority.off.Store(false)
	require.NoError(t, stuck.rt.Recover(ctx))
	require.NoError(t, stuck.rt.Admit(2))
	require.NoError(t, stuck.manager.onProposalMsg(ctx, proposal))
	require.Len(t, stuck.net.SentMessages(network.ProtocolRootVote), 1)
}

func TestRestartAcrossTheBoundary(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	anchor := c.activateAll()
	ctx := context.Background()
	collector := c.firstProposal(anchor.Slot)
	voter := c.heavy()
	if voter == collector {
		voter = c.replicas[1]
	}
	vote := c.voteOf(voter)
	require.EqualValues(t, anchor.Slot+1, voter.db.GetHighestVotedRound())

	t.Run("a binary that does not know the history cannot take the activated epoch", func(t *testing.T) {
		voter.close()
		err := voter.open(false)
		require.Error(t, err, "the anchor's lineage is a V3 body the V1/V2 recovery history does not hold")
		require.Nil(t, voter.manager)
	})

	t.Run("the process restarts with the verified history rebuilt from the journal", func(t *testing.T) {
		voter.mustOpen(true)
		require.Equal(t, anchor, voter.manager.epochAnchor, "the durable anchor is recovered")
		e, ok := voter.rt.Activated(2)
		require.True(t, ok, "the history is rebuilt from the retained proof bytes")
		require.Equal(t, c.f.Claim, e.Claim())
		require.ErrorIs(t, voter.rt.Admit(2), q3active.ErrNotActive, "nothing is admitted before recovery")
		require.NoError(t, voter.rt.Recover(ctx))
		require.NoError(t, voter.rt.Admit(2))
		require.EqualValues(t, 7, voter.manager.trustBase.Load().QuorumThreshold)
		require.EqualValues(t, anchor.Slot+1, voter.db.GetHighestVotedRound(), "the vote lock survived")
		cfg, err := voter.trust.SigningConfig(2)
		require.NoError(t, err)
		require.EqualValues(t, votesig.SchemeDomainBound, cfg.Scheme)
	})

	t.Run("it reproduces its recorded vote and never signs a second statement for the round", func(t *testing.T) {
		block, err := voter.manager.blockStore.Block(anchor.Slot + 1)
		require.NoError(t, err)
		again, err := voter.manager.safety.MakeVote(c.proposal.Block, block.RootHash, nil, nil)
		require.NoError(t, err)
		require.Equal(t, vote.VoteInfo, again.VoteInfo, "the retry of the same statement is the recorded one")
		require.Equal(t, vote.LedgerCommitInfo, again.LedgerCommitInfo)
		other := append([]byte(nil), block.RootHash...)
		other[0] ^= 0xFF
		_, err = voter.manager.safety.MakeVote(c.proposal.Block, other, nil, nil)
		require.ErrorIs(t, err, storage.ErrDecisionConflict)
	})
}

func TestRestartInTheMiddleOfTheInstallationCompletesTheExactActivation(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	ctx := context.Background()
	r := c.replicas[1]
	r.authority.off.Store(true)
	require.NoError(t, r.rt.Recover(ctx))
	require.ErrorIs(t, r.rt.Activate(ctx, r.bundle()), q3active.ErrNotBound)
	require.ErrorIs(t, r.rt.Admit(2), q3active.ErrNotActive)
	anchor := r.manager.epochAnchor
	require.NotNil(t, anchor)

	// the crash: the root has installed, the journal has staged and finished the first steps
	r.close()
	r.mustOpen(true)
	require.Equal(t, anchor, r.manager.epochAnchor)
	require.ErrorIs(t, r.rt.Admit(2), q3active.ErrNotActive, "a restart does not open the gate")
	require.NoError(t, r.rt.Recover(ctx))
	require.NoError(t, r.rt.Admit(2))
	require.NoError(t, r.rt.Gate(ctx, c.f.Claim))
	require.EqualValues(t, 7, r.manager.trustBase.Load().QuorumThreshold)
	r.startConsensus()

	// a second restart after completion changes nothing and re-installs nothing
	r.close()
	r.mustOpen(true)
	require.NoError(t, r.rt.Recover(ctx))
	require.NoError(t, r.rt.Admit(2))
	require.Equal(t, anchor, r.manager.epochAnchor)
}

func TestInstallVerifiedEpochRefusals(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	env, err := q3format.DecodeEnvelope(f.EnvelopeBytes)
	require.NoError(t, err)
	verified, err := h.VerifyEnvelope(env)
	require.NoError(t, err)
	activated, genesis := verified.Tip(), h.Tip()
	_ = ctx

	// a manager whose trust store is bound to the verified history, installing directly: the manager's own checks
	fresh := func(t *testing.T) *q3Replica {
		r := newQ3Replica(t, f, f.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		require.NoError(t, r.trust.BindSigningAuthority(verified))
		return r
	}
	t.Run("a zero entry", func(t *testing.T) {
		r := fresh(t)
		_, err := r.manager.InstallVerifiedEpoch(q3format.Entry{}, f.Proof, f.Snapshot, nil)
		require.ErrorIs(t, err, ErrNotVerifiedEpoch)
	})
	t.Run("a legacy entry", func(t *testing.T) {
		r := fresh(t)
		_, err := r.manager.InstallVerifiedEpoch(genesis, f.Proof, f.Snapshot, nil)
		require.ErrorIs(t, err, ErrNotVerifiedEpoch)
	})
	t.Run("a candidate the V3 install does not carry", func(t *testing.T) {
		r := fresh(t)
		_, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, f.Snapshot, []byte{1})
		require.ErrorIs(t, err, ErrQ3Candidate)
	})
	t.Run("running consensus", func(t *testing.T) {
		r := fresh(t)
		r.manager.pacemaker.Reset(ctx, 3, nil, nil)
		_, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, f.Snapshot, nil)
		require.ErrorContains(t, err, "stopped profile-2 consensus")
	})
	t.Run("a proof of another record than the one that activated the epoch", func(t *testing.T) {
		other := q3fixture.New(t, q3fixture.Options{})
		r := fresh(t)
		_, err := r.manager.InstallVerifiedEpoch(activated, other.Proof, f.Snapshot, nil)
		require.Error(t, err)
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound)
	})
	t.Run("a snapshot that is not the committed checkpoint", func(t *testing.T) {
		r := fresh(t)
		tampered := *f.Snapshot
		tampered.ShardInfo = append([]abdrc.ShardInfo(nil), f.Snapshot.ShardInfo...)
		tampered.ShardInfo[0].IRTR.Round++
		_, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, &tampered, nil)
		require.Error(t, err)
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound, "nothing was installed")
	})
	t.Run("no snapshot", func(t *testing.T) {
		r := fresh(t)
		_, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, nil, nil)
		require.Error(t, err)
	})
	t.Run("a trust store that is not bound to the history", func(t *testing.T) {
		r := newQ3Replica(t, f, f.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		_, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, f.Snapshot, nil)
		require.ErrorIs(t, err, tbstore.ErrSigningHistory)
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound)
	})
	t.Run("acceptance control, then idempotence", func(t *testing.T) {
		r := fresh(t)
		anchor, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, f.Snapshot, nil)
		require.NoError(t, err)
		require.EqualValues(t, 6, anchor.Slot)
		require.NoError(t, r.manager.HoldsVerifiedEpoch(activated))
		again, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, f.Snapshot, nil)
		require.NoError(t, err)
		require.Equal(t, anchor, again)
	})
	t.Run("holding is checked, not assumed", func(t *testing.T) {
		r := fresh(t)
		require.Error(t, r.manager.HoldsVerifiedEpoch(activated), "before the install the store lacks the epoch")
		require.ErrorIs(t, r.manager.HoldsVerifiedEpoch(q3format.Entry{}), ErrNotVerifiedEpoch)
		_, err := r.manager.InstallVerifiedEpoch(activated, f.Proof, f.Snapshot, nil)
		require.NoError(t, err)
		require.NoError(t, r.manager.HoldsVerifiedEpoch(activated))
	})
}
