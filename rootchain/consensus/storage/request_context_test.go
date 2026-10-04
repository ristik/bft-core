package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

func orchestrationOf(pdr *types.PartitionDescriptionRecord) mockOrchestration {
	key := types.PartitionShardID{PartitionID: pdr.PartitionID, ShardID: pdr.ShardID.Key()}
	return mockOrchestration{
		shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
			return map[types.PartitionShardID]*types.PartitionDescriptionRecord{key: pdr}, nil
		},
	}
}

func requireUnitContext(t *testing.T, si *ShardInfo, pdr *types.PartitionDescriptionRecord) {
	t.Helper()
	ctx := si.RequestContext()
	require.NotNil(t, ctx)
	require.Equal(t, quorumweight.PolicyUnit, ctx.Policy())
	require.Equal(t, si.ShardConfHash, ctx.ConfHash())
	require.Equal(t, pdr.Epoch, ctx.ShardEpoch())
	require.Equal(t, len(pdr.Validators), ctx.MemberCount())
	require.EqualValues(t, len(pdr.Validators), ctx.TotalWeight())
	require.EqualValues(t, len(pdr.Validators)/2+1, ctx.Threshold())
	require.Equal(t, si.nodeIDs, ctx.NodeIDs())
}

// Site 1 (sharding.go NewShardInfo): genesis builds the unit context, and a non-unit configuration is refused.
func TestNewShardInfoBuildsUnitRequestContext(t *testing.T) {
	_, infos := testutils.CreateTestNodes(t, 4)
	pdr := newShardConf(t)
	pdr.Validators = infos
	si, err := NewShardInfo(pdr, crypto.SHA256)
	require.NoError(t, err)
	requireUnitContext(t, si, pdr)
	require.EqualValues(t, 3, si.RequestContext().Threshold())

	heavy := newShardConf(t)
	heavy.Validators = infos
	heavy.Validators[0].Stake = 2
	_, err = NewShardInfo(heavy, crypto.SHA256)
	require.ErrorIs(t, err, quorumweight.ErrWeightCap)
	heavy.Validators[0].Stake = 0
	_, err = NewShardInfo(heavy, crypto.SHA256)
	require.ErrorIs(t, err, quorumweight.ErrWeightCap)
}

// Site 2 (sharding.go nextEpoch): the successor epoch gets its own context bound to its own configuration hash, and the
// predecessor's context is untouched.
func TestNextEpochRebuildsRequestContext(t *testing.T) {
	_, infos := testutils.CreateTestNodes(t, 3)
	pdr := newShardConf(t)
	pdr.Validators = infos[:2]
	si, err := NewShardInfo(pdr, crypto.SHA256)
	require.NoError(t, err)
	before := si.RequestContext()

	next := *pdr
	next.Epoch = 1
	next.Validators = infos
	si.TR.Epoch++ // nextRound advances the technical record epoch before it derives the successor
	nsi, err := si.nextEpoch(&next, crypto.SHA256)
	require.NoError(t, err)
	requireUnitContext(t, nsi, &next)
	require.NotEqual(t, before.Identity(), nsi.RequestContext().Identity())
	require.Same(t, before, si.RequestContext())
	require.EqualValues(t, 2, before.Threshold())

	heavy := next
	heavy.Validators = []*types.NodeInfo{{NodeID: infos[0].NodeID, SigKey: infos[0].SigKey, Stake: 3}, infos[1]}
	_, err = si.nextEpoch(&heavy, crypto.SHA256)
	require.ErrorIs(t, err, quorumweight.ErrWeightCap, "a weight-changing successor is not admitted before activation")
}

// Site 3 (block_tree.go initBlock): a block restored from the database re-derives the context. Under the handoff profile a
// configuration that differs from the stored ShardConfHash is refused (ErrAssignmentHistory, before any context exists);
// outside it the stored hash is still not compared (existing profiles keep their verification rules, design section 4), so
// the context binds to the loaded configuration. Weight is refused in both.
func TestInitBlockRequestContext(t *testing.T) {
	pdr := newShardConf(t)
	block := genesisBlockWithShard(t, pdr)
	key := types.PartitionShardID{PartitionID: pdr.PartitionID, ShardID: pdr.ShardID.Key()}
	si := block.ShardState.States[key]
	si.requestCtx = nil
	require.NoError(t, initBlock(block, orchestrationOf(pdr)))
	requireUnitContext(t, si, pdr)

	altered := *pdr
	altered.T2Timeout++
	alteredHash, err := altered.Hash(crypto.SHA256)
	require.NoError(t, err)

	si.requestCtx = nil
	require.NoError(t, initBlock(block, orchestrationOf(&altered)), "legacy profile: no new refusal")
	require.Equal(t, alteredHash, si.RequestContext().ConfHash(), "the context binds to the configuration that was loaded")

	si.requestCtx = nil
	block.ShardState.Control = &evmroot.ControlState{}
	err = initBlock(block, orchestrationOf(&altered))
	require.ErrorIs(t, err, ErrAssignmentHistory)
	require.Nil(t, si.requestCtx, "a refused restore leaves no context")
	block.ShardState.Control = nil

	heavy := *pdr
	heavy.Validators = []*types.NodeInfo{{NodeID: pdr.Validators[0].NodeID, SigKey: pdr.Validators[0].SigKey, Stake: 4}}
	err = initBlock(block, orchestrationOf(&heavy))
	require.ErrorIs(t, err, quorumweight.ErrWeightCap)
}

// Site 4 (block_executor.go NewRootBlock): a checkpoint restore re-derives the context from the orchestration's
// configuration and refuses an altered one.
func TestNewRootBlockRestoreRefusesAlteredConfiguration(t *testing.T) {
	pdr := newShardConf(t)
	block := genesisBlockWithShard(t, pdr)
	shards, err := toRecoveryShardInfo(block)
	require.NoError(t, err)
	head := &abdrc.CommittedBlock{Block: block.BlockData, ShardInfo: shards, Qc: block.Qc, CommitQc: block.CommitQc}

	restored, err := NewRootBlock(head, crypto.SHA256, orchestrationOf(pdr), ProfileLegacy)
	require.NoError(t, err)
	key := types.PartitionShardID{PartitionID: pdr.PartitionID, ShardID: pdr.ShardID.Key()}
	requireUnitContext(t, restored.ShardState.States[key], pdr)

	altered := *pdr
	altered.Validators = append(append([]*types.NodeInfo{}, pdr.Validators...), testutils.NewTestNode(t).NodeInfo(t))
	_, err = NewRootBlock(head, crypto.SHA256, orchestrationOf(&altered), ProfileLegacy)
	require.ErrorContains(t, err, "shard conf hash doesn't match")

	heavy := *pdr
	heavy.Validators = []*types.NodeInfo{{NodeID: pdr.Validators[0].NodeID, SigKey: pdr.Validators[0].SigKey, Stake: 5}}
	hh, err := heavy.Hash(crypto.SHA256)
	require.NoError(t, err)
	headHeavy := *head
	headHeavy.ShardInfo = append([]abdrc.ShardInfo{}, shards...)
	headHeavy.ShardInfo[0].ShardConfHash = hh // the stored hash matches, the weight is still refused
	_, err = NewRootBlock(&headHeavy, crypto.SHA256, orchestrationOf(&heavy), ProfileLegacy)
	require.ErrorIs(t, err, quorumweight.ErrWeightCap)
}
