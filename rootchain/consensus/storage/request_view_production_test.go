package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The pending-acknowledgement state that block execution itself produces (InstallEpochAnchor + nextBlock, including its fee/stat recompute
// under a Control record), not a helper's imitation of it: the view resolves to the parent's record at installation and across real
// timeout transitions, a one-byte change of either commitment is refused, and a reopened store reproduces the same view with an empty
// cache.
func TestProductionInstalledParentResolvesAcrossTimeoutsAndReopen(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchorEpoch, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchorEpoch)
	for round := uint64(8); round <= 10; round++ {
		f.addSuccessorBlock(t, s, round, nil)
	}

	genesisAnchor, err := NewRequestAnchor(f.current, crypto.SHA256, 1, f.predecessor, fxVersion)
	require.NoError(t, err)
	body := bytes.Clone(h.commit.NextBodyID)
	activation, err := newRequestActivation(h.activated, crypto.SHA256, quorumweight.PolicyUnit, nil, h.genesis.Epoch, body, h.genesis.Start, h.successorT, fxVersion)
	require.NoError(t, err)
	parentID := bytes.Repeat([]byte{0x9D}, 32)
	resolve := func(si *ShardInfo, cache *RequestViewCache) (*RequestRoundView, error) {
		if si.LastCR == nil {
			// the fixture's shard has never certified: its last certified record is the predecessor epoch's, one round before the installed one
			tr := certification.TechnicalRecord{Round: si.TR.Round - 1, Epoch: si.TR.Epoch - 1, Leader: si.TR.Leader}
			ir := &types.InputRecord{Version: 1, RoundNumber: tr.Round, Epoch: tr.Epoch, PreviousHash: []byte{1}, Hash: si.RootHash, BlockHash: []byte{2}, Timestamp: fxTimestamp}
			cp := *si
			cp.LastCR = &certification.CertificationResponse{Partition: si.PartitionID, Shard: si.ShardID, Technical: tr, UC: types.UnicityCertificate{Version: 1, InputRecord: ir,
				UnicitySeal: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: h.genesis.Start - 1, Timestamp: fxTimestamp, Hash: []byte{4}}}}
			si = &cp
		}
		snap, err := NewRequestSnapshot(5, crypto.SHA256, si, parentID, nil, genesisAnchor, activation)
		require.NoError(t, err)
		return cache.Resolve(RequestQuery{Network: 5, Partition: f.shard.PartitionID, Shard: si.ShardID, RootEpoch: h.genesis.Epoch, RootRound: h.genesis.Start + 3,
			RootBodyID: body, Version: fxVersion, ParentID: parentID, PrevUCDigest: snap.parent.ucDigest, Purpose: PurposeExecute}, snap)
	}

	installed := mustBlock(t, s, 10).ShardState.States[f.shard]
	require.NotEqual(t, installed.TR.Epoch, installed.IR.Epoch, "installed, acknowledgement pending")
	var keys [][]byte
	for repeats := 0; repeats <= 4; repeats++ {
		si := *installed
		si.Fees = cloneFees(installed.Fees)
		for i := 0; i < repeats; i++ {
			require.NoError(t, si.nextRoundWith(nil, h.activated, crypto.SHA256, (*ShardInfo).resetTrustBase))
		}
		v, err := resolve(&si, NewRequestViewCache())
		require.NoError(t, err, "repeats %d", repeats)
		require.Equal(t, si.TR, v.ExpectedTR(), "the production-installed parent's own record")
		keys = append(keys, v.ViewKey())

		// a one-byte change of either commitment is refused, with no view
		for name, mutate := range map[string]func(*ShardInfo){
			"fee hash":  func(x *ShardInfo) { x.TR.FeeHash = append([]byte{x.TR.FeeHash[0] ^ 1}, x.TR.FeeHash[1:]...) },
			"stat hash": func(x *ShardInfo) { x.TR.StatHash = append([]byte{x.TR.StatHash[0] ^ 1}, x.TR.StatHash[1:]...) },
		} {
			bad := si
			mutate(&bad)
			cache := NewRequestViewCache()
			view, err := resolve(&bad, cache)
			require.ErrorIs(t, err, quorumweight.ErrRequestContext, "%s, repeats %d", name, repeats)
			require.Nil(t, view)
			require.Zero(t, cache.Len())
		}
	}
	for i := 1; i < len(keys); i++ {
		require.NotEqual(t, keys[i-1], keys[i], "every timeout is another view")
	}

	// reopen: the persisted state of the same block, an empty cache, the same view
	before, err := resolve(installed, NewRequestViewCache())
	require.NoError(t, err)
	reopened, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	again, err := resolve(mustBlock(t, reopened, 10).ShardState.States[f.shard], NewRequestViewCache())
	require.NoError(t, err)
	require.Equal(t, before.ViewKey(), again.ViewKey())
	require.Equal(t, before.ExpectedTR(), again.ExpectedTR())
}

func cloneFees(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
