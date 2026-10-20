package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// lastCRs is the CBOR of the latest response (the UC and the technical record as one pair) of each of the shards in a block.
func lastCRs(t *testing.T, b *ExecutedBlock) map[types.PartitionID][]byte {
	t.Helper()
	out := map[types.PartitionID][]byte{}
	for key, si := range b.ShardState.States {
		if si.LastCR == nil {
			continue
		}
		raw, err := types.Cbor.Marshal(si.LastCR)
		require.NoError(t, err)
		out[key.PartitionID] = raw
	}
	return out
}

func lastCR(t *testing.T, s *BlockStore, round uint64, p types.PartitionID) *certification.CertificationResponse {
	t.Helper()
	b := mustBlock(t, s, round)
	return b.ShardState.States[types.PartitionShardID{PartitionID: p, ShardID: types.ShardID{}.Key()}].LastCR
}

// Independent follower recovery (#475 item 2): a follower recovers through a verified state message (the committed head and the pending
// blocks) and replays the QCs and the pending blocks in order. It reconstructs the historical LastCR frontier, as the store it recovered
// from has it: every pending block holds the pair of the committed head it was executed on until its own ancestor commits, a commit that
// the replay performs replaces the pair in the descendants only, and the follower ends in the state of the uninterrupted store: the same
// pairs, state roots and state message. The window holds a state-changing certification of one shard and a repeat UC (T2 timeout) of
// the other, both committed after the head, so the pair of each shard moves while the replay runs.
func TestFollowerRecoveryReplaysTheHistoricalLastCRFrontier(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	for range 14 { // both shards are certified, and the second one has been idle for longer than the timeout rounds
		c.next()
	}
	c.next(1)

	// the window: block A repeats shard 2 (T2 timeout), block B changes shard 1. The QC of B has not formed, so A and B are pending
	// and the head is the round before A.
	qa := c.propose(nil, []types.PartitionID{2})
	headRound := c.round - 1
	rA := c.round
	c.process(qa)
	qb := c.propose([]types.PartitionID{1}, nil)
	rB := c.round
	source := c.store
	require.EqualValues(t, headRound, source.blockTree.root.data.GetRound(), "premise: the window is pending; pending=%d", len(source.blockTree.allUncommittedNodes()))
	headBefore := lastCRs(t, mustBlock(t, source, headRound))
	require.Len(t, headBefore, 2)

	sm := received(t, c.state())
	require.Len(t, sm.Pending, 2)
	follower, _, err := c.recoverInto(sm)
	require.NoError(t, err)
	// the replay, in order, as the consensus manager does it: the QC of the block first, then the block
	for i, b := range sm.Pending {
		_, err := follower.ProcessQc(b.Qc)
		require.True(t, err == nil || (i == 0 && errorsIsCommitFailed(err)), "%v", err)
		_, err = follower.Add(b, chainVerifier{follower})
		require.NoError(t, err)
	}

	// the historical frontier: before the QC of B, no pending block has any pair but the head's, in the follower as in the source
	for _, round := range []uint64{rA, rB} {
		require.Equal(t, headBefore, lastCRs(t, mustBlock(t, follower, round)), "round %d: the follower's pending block holds the head's pairs", round)
		require.Equal(t, lastCRs(t, mustBlock(t, source, round)), lastCRs(t, mustBlock(t, follower, round)), "round %d: as the source's", round)
	}
	require.Equal(t, lastCRs(t, mustBlock(t, source, headRound)), lastCRs(t, mustBlock(t, follower, headRound)))

	// the QC of B arrives at both: A commits and generates the repeat UC of shard 2 (A holds the timeout), which both stores propagate
	c.process(qb)
	_, err = follower.ProcessQc(qb)
	require.NoError(t, err)
	repeated := lastCR(t, source, rA, 2)
	require.NotEqual(t, headBefore[2], lastCRs(t, mustBlock(t, source, rA))[2], "premise: the commit replaced the pair of shard 2")
	require.EqualValues(t, rA, repeated.UC.UnicitySeal.RootChainRoundNumber)
	for _, s := range []*BlockStore{source, follower} {
		require.Equal(t, headBefore[1], lastCRs(t, mustBlock(t, s, rA))[1], "shard 1 is not certified by A: its pair stays")
		for _, round := range []uint64{rA, rB} {
			require.Equal(t, lastCRs(t, mustBlock(t, source, rA)), lastCRs(t, mustBlock(t, s, round)), "round %d carries the committed root's pairs", round)
		}
	}
	require.Equal(t, lastCRs(t, mustBlock(t, source, rA)), lastCRs(t, mustBlock(t, follower, rA)))

	// the continuation is the same: shard 1 (changed in B) commits with the next QC and both stores produce the same pairs, roots and state
	qc := c.propose(nil, nil)
	rC := c.round
	bd := mustBlock(t, source, rC).BlockData
	got, err := follower.Add(bd, chainVerifier{follower})
	require.NoError(t, err)
	require.Equal(t, mustBlock(t, source, rC).RootHash, mustBlock(t, follower, rC).RootHash)
	require.Equal(t, got, []byte(mustBlock(t, follower, rC).RootHash))
	c.process(qc)
	_, err = follower.ProcessQc(qc)
	require.NoError(t, err)
	require.Equal(t, lastCRs(t, mustBlock(t, source, rB)), lastCRs(t, mustBlock(t, follower, rB)))
	require.EqualValues(t, rB, lastCR(t, follower, rC, 1).UC.UnicitySeal.RootChainRoundNumber, "shard 1 is certified by the commit of B")
	want, err := types.Cbor.Marshal(c.state())
	require.NoError(t, err)
	have, err := follower.GetState()
	require.NoError(t, err)
	haveRaw, err := types.Cbor.Marshal(have)
	require.NoError(t, err)
	require.Equal(t, want, haveRaw, "the follower serves the state message of the uninterrupted store")

	// and the persisted follower reopens into the same pairs
	reopened, err := New(follower.hash, follower.storage, c.orch, c.log)
	require.NoError(t, err)
	require.Equal(t, lastCRs(t, mustBlock(t, follower, rC)), lastCRs(t, mustBlock(t, reopened, rC)))
}
