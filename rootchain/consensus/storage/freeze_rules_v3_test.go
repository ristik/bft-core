package storage_test

import (
	"crypto"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// The Freeze companion's version selects the validator weight rules its successor assignment is judged under, at the block execution of
// the Freeze record itself: the same weighted (6,1,1,1) successor of a unit shard passes the weight rules under a V3 companion and is
// refused under a V2 one. The V3 case is then stopped, by a later stage (no incumbent baseline in this orchestration), which proves the
// weight rules were not what refused it.
func TestFreezeExecutionJudgesAV3CompanionsAssignmentUnderTheBoundedWeights(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	candidate, err := evmassign.DecodeCandidate(f.Candidate)
	require.NoError(t, err)
	succ, err := candidate.Successor()
	require.NoError(t, err)
	var heavy uint64
	for _, v := range succ.Validators {
		heavy = max(heavy, v.Stake)
	}
	require.EqualValues(t, 6, heavy, "premise: the successor is weighted")

	state, err := storage.NewShardInfo(f.ShardConf, crypto.SHA256)
	require.NoError(t, err)
	var current []evmassign.RootMember
	for _, n := range f.Old.RootNodes {
		current = append(current, evmassign.RootMember{NodeID: n.NodeID, Key: n.SigKey, Weight: n.Stake})
	}
	sort.Slice(current, func(i, j int) bool { return current[i].NodeID < current[j].NodeID })
	sigs := map[string]hex.Bytes{"old": {1}}
	digest := make([]byte, 32)
	v2, err := storage.FreezeAssignmentAuthorization{Version: 2, Body: []byte("body"), Parent: digest, Candidate: digest, Preimage: f.Candidate, Signatures: sigs}.Bytes()
	require.NoError(t, err)
	v3, err := storage.FreezeV3Authorization{Version: 3, Body: []byte("body"), Parent: digest, Candidate: digest, Preimage: f.Candidate, Receipts: []byte("receipts"), Signatures: sigs}.Bytes()
	require.NoError(t, err)

	run := func(companion []byte) error {
		return storage.VerifyFreezeAssignmentForTest(companion, state, f.ShardConf, nil, current,
			map[types.PartitionShardID]*storage.ShardInfo{}, map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil, nil)
	}
	err = run(v2)
	require.ErrorIs(t, err, storage.ErrHandoffRecord)
	require.ErrorIs(t, err, evmassign.ErrAssignment, "a V2 companion keeps the unit rules: the stake refuses it")

	err = run(v3)
	require.ErrorIs(t, err, storage.ErrHandoffRecord)
	require.NotErrorIs(t, err, evmassign.ErrAssignment, "a V3 companion admits the weighted successor under the bounded weights")
	require.ErrorIs(t, err, storage.ErrLifecycle, "and is stopped by the lifecycle stage this orchestration cannot serve")
}
