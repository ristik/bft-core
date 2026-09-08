package shardnode_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// failingSubmitter records every request handed to it and never sends one.
type failingSubmitter struct {
	got []*certification.BlockCertificationRequest
}

func (s *failingSubmitter) Submit(_ context.Context, r *certification.BlockCertificationRequest) error {
	s.got = append(s.got, r)
	return errors.New("transport failure")
}

/*
TestRound_CommitsOnlyWhatTheCertificateCertifies is the boundary between a PROPOSAL and a
CERTIFIED BLOCK, and a plain transport failure was enough to cross it.

r.pending is the block this node built or verified for the round it last submitted. Committing is a
different act — for the Engine adapter it sets head, safe and FINALIZED — and may only ever apply to
a block the root chain has certified. The two were conflated: Submit returning an error ended
HandleCertificate with the next round's proposal installed as pending, BFTClient recorded the
certificate as unapplied, the retransmission re-entered the round, and commitPrevious finalised that
uncertified proposal. Nothing undoes a finalisation.
*/
func TestRound_CommitsOnlyWhatTheCertificateCertifies(t *testing.T) {
	t.Run("a replayed certificate does not commit the proposal it never certified", func(t *testing.T) {
		ctx := context.Background()
		fake := executortest.New()
		fake.AddEntries([]byte("uncertified transaction"))
		exec := &recordingExecutor{Executor: fake}
		sub := &failingSubmitter{}
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		round := shardnode.NewRound("node", types.PartitionID(8), types.ShardID{}, exec,
			shardnode.NewLoopbackDisseminator(), signer, sub, nil)

		// The genesis certificate: the node builds round 1 on a state-changing entry and the send
		// fails. The round-1 block is now a proposal nothing has certified.
		uc, technical := genesisUC(1000), tr(1, 0, "node")
		err = round.HandleCertificate(ctx, uc, technical)
		require.ErrorIs(t, err, shardnode.ErrSubmissionFailed)
		require.Empty(t, exec.commitTargets(), "nothing is certified yet, so nothing may be committed")
		require.NotEmpty(t, sub.got[0].InputRecord.BlockHash)

		// The same certificate arrives again — a retransmission, which is routine.
		_ = round.HandleCertificate(ctx, uc, technical)
		for _, target := range exec.commitTargets() {
			require.NotEqual(t, []byte(sub.got[0].InputRecord.BlockHash), []byte(target),
				"the round-1 proposal must never be committed on the strength of the round-0 certificate")
		}
		require.Empty(t, exec.commitTargets(),
			"the genesis certificate certifies no block, so this delivery commits nothing at all")
	})

	t.Run("the certified block is committed, not the proposed one", func(t *testing.T) {
		// Following the root chain's decision means committing ITS block. The previous revision
		// logged that it was doing so and committed this node's own block anyway — and decided
		// whether to log by comparing the certified STATE root against a BLOCK hash, so the line
		// fired on every ordinary non-quiet round against a real executor.
		ctx := context.Background()
		fake := executortest.New()
		exec := &recordingExecutor{Executor: fake}
		sub := &recordingSubmitter{}
		round, nodeID := newTestRound(t, exec, sub)

		require.NoError(t, round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
		fake.AddEntries([]byte("a real block"))
		require.NoError(t, round.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, nodeID)))
		req := sub.last(t)
		require.NotEmpty(t, req.InputRecord.BlockHash)

		before := len(exec.commitTargets())
		require.NoError(t, round.HandleCertificate(ctx, certifyFrom(req, 3, 1000), tr(3, 0, nodeID)))
		targets := exec.commitTargets()
		require.Greater(t, len(targets), before)
		require.Equal(t, []byte(req.InputRecord.BlockHash), []byte(targets[len(targets)-1]),
			"the commit target is the certificate's block hash")
	})

	t.Run("a certificate for another round commits nothing", func(t *testing.T) {
		// A repeat of an earlier round is an ordinary thing for the root chain to send. It says
		// nothing about the round this node proposed for, so it must not move the executor.
		ctx := context.Background()
		fake := executortest.New()
		exec := &recordingExecutor{Executor: fake}
		sub := &recordingSubmitter{}
		round, nodeID := newTestRound(t, exec, sub)

		require.NoError(t, round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
		fake.AddEntries([]byte("a real block"))
		require.NoError(t, round.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, nodeID)))

		before := len(exec.commitTargets())
		// The root chain re-issues the PREVIOUS round instead of certifying the one just proposed.
		repeat := certifyFrom(sub.got[0], 3, 1000)
		_ = round.HandleCertificate(ctx, repeat, tr(3, 0, nodeID))
		require.Equal(t, before, len(exec.commitTargets()),
			"a certificate for round 1 certifies nothing about the round-2 proposal")
	})
}

// TestRound_SendFailureIsNotApplicationFailure pins the distinction the delivery layer needs.
//
// Everything before the send is application; the send belongs to the NEXT round's proposal. A
// transport error must be reported as such, so a retransmission is not treated as "this
// certificate was never applied" and re-entered.
func TestRound_SendFailureIsNotApplicationFailure(t *testing.T) {
	ctx := context.Background()
	fake := executortest.New()
	sub := &failingSubmitter{}
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	round := shardnode.NewRound("node", types.PartitionID(8), types.ShardID{}, fake,
		shardnode.NewLoopbackDisseminator(), signer, sub, nil)

	err = round.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, "node"))
	require.ErrorIs(t, err, shardnode.ErrSubmissionFailed)

	require.Len(t, sub.got, 3, "an uncertain send is retried, bounded")
	first := sub.got[0]
	for _, again := range sub.got[1:] {
		require.Equal(t, first.Signature, again.Signature,
			"a retry re-sends the identical signed request; it must never sign different bytes for one round")
		require.Same(t, first.InputRecord, again.InputRecord)
	}
}
