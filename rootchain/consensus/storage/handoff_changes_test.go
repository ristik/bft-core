package storage

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// aggregatorShard is an existing aggregator shard (partition 9) of the fixture's chain, certified under its own key.
type aggregatorShard struct {
	conf    *types.PartitionDescriptionRecord
	key     types.PartitionShardID
	oldKey  evmKey
	nextKey evmKey
}

// addAggregator installs an aggregator shard next to the EVM shard (real orchestration and committed state) and returns it.
func (f *assignmentFixture) addAggregator(t *testing.T) aggregatorShard {
	t.Helper()
	a := aggregatorShard{oldKey: newEVMKey(t, "agg-old"), nextKey: newEVMKey(t, "agg-new")}
	a.conf = &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1,
		PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}, Validators: []*types.NodeInfo{a.oldKey.info}}
	require.NoError(t, f.orch.AddShardConfig(a.conf))
	evmShard := f.shard
	f.installShard(t, a.conf, func(*ShardInfo) {})
	a.key = f.shard
	f.shard = evmShard
	return a
}

// replace builds the candidate change replacing the shard's key set; every successor key signs the possession proof for the
// fixture's context. mutate edits the successor before it is signed.
func (f *assignmentFixture) replace(t *testing.T, a aggregatorShard, installed *types.PartitionDescriptionRecord, mutate func(*types.PartitionDescriptionRecord)) evmassign.Change {
	t.Helper()
	succ, err := evmassign.NewSuccessor(installed, []*types.NodeInfo{a.nextKey.info})
	require.NoError(t, err)
	if mutate != nil {
		mutate(succ)
	}
	p, err := evmassign.SignPoP(a.nextKey.signer, f.pop, succ, a.nextKey.id)
	require.NoError(t, err)
	ch, err := evmassign.EncodeReplaceShardValidators(installed.PartitionID, installed.ShardID, installed, succ, []evmassign.PoP{p})
	require.NoError(t, err)
	return ch
}

func TestFreezeAdmitsAnAggregatorKeyReplacementOnlyWhenItReplacesTheInstalledConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change
		want   error
	}{
		{"a key replacement of an existing shard", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			return []evmassign.Change{f.replace(t, a, a.conf, nil)}
		}, nil},
		{"a proof_type change", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			return []evmassign.Change{f.replace(t, a, a.conf, func(s *types.PartitionDescriptionRecord) { s.PartitionParams["proof_type"] = "sp1" })}
		}, evmassign.ErrConfig},
		{"a replacement of a configuration that is not the installed one", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			stale := *a.conf
			stale.T2Timeout += time.Second
			return []evmassign.Change{f.replace(t, a, &stale, nil)}
		}, evmassign.ErrContext},
		{"a shard that does not exist", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			ghost := *a.conf
			ghost.PartitionID = 77
			return []evmassign.Change{f.replace(t, a, &ghost, nil)}
		}, evmassign.ErrChange},
		{"a reserved kind", func(t *testing.T, f *assignmentFixture, a aggregatorShard) []evmassign.Change {
			ch := f.replace(t, a, a.conf, nil)
			ch.Kind = evmassign.ChangeSplitShard
			return []evmassign.Change{ch}
		}, evmassign.ErrUnsupportedChange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssignmentFixture(t)
			f.useRealOrchestration(t)
			f.seedFees(t)
			a := f.addAggregator(t)
			f.changes = tc.change(t, f, a)
			err := f.admit(t, f.build(t, f.candidate(t)))
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrHandoffRecord)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("an aggregator whose previous replacement is not acknowledged", func(t *testing.T) {
		f := newAssignmentFixture(t)
		f.useRealOrchestration(t)
		f.seedFees(t)
		a := f.addAggregator(t)
		f.installShard(t, a.conf, func(si *ShardInfo) { si.TR.Epoch = si.IR.Epoch + 1 })
		f.shard = types.PartitionShardID{PartitionID: 8, ShardID: f.current.ShardID.Key()}
		f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
		err := f.admit(t, f.build(t, f.candidate(t)))
		require.ErrorIs(t, err, ErrAssignmentAckPending)
	})
	t.Run("a supersession carries no aggregator changes", func(t *testing.T) {
		p := installPendingAssignment(t)
		a := p.f.addAggregator(t)
		binding, err := p.chain(t).Supersession()
		require.NoError(t, err)
		sup := p.supersedeWith(t, binding, 8)
		_ = sup
		p.f.changes = []evmassign.Change{p.f.replace(t, a, a.conf, nil)}
		built := p.f.build(t, p.f.candidate(t))
		p.store.handoffAuth = fixedParentAuthority{predecessor: p.body1, parent: p.f.parent, root: p.f.baseCommittee}
		s := supersession{p: p, built: built}
		_, err = s.addEpoch2(t, p.store, 8, built.prepare.Bytes())
		require.NoError(t, err)
		_, err = s.addEpoch2(t, p.store, 9, built.freeze.Bytes(), built.companion)
		require.ErrorIs(t, err, ErrHandoffRecord)
		require.ErrorIs(t, err, evmassign.ErrChange)
	})
}

// B3: the retired key's first post-boundary request is refused. The replacement activates with the assignment: the shard's
// technical record advances to the successor epoch and the new trust base is installed at once, so the old key cannot certify
// the first block after the boundary. Unchanged shards are untouched, and a restart rebuilds the configuration from history.
func TestAggregatorKeyReplacementActivatesAtTheBoundaryAndSurvivesRestart(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	a := f.addAggregator(t)
	f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)

	confs, err := f.orch.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 1, confs[a.key].Epoch)
	require.EqualValues(t, 7, confs[a.key].EpochStart)
	require.Equal(t, a.nextKey.id, confs[a.key].Validators[0].NodeID)
	before, err := f.orch.ShardConfigs(6)
	require.NoError(t, err)
	require.EqualValues(t, 0, before[a.key].Epoch, "the retired key stays authoritative before the boundary")

	restart := func() *BlockStore {
		s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		return s
	}
	s := restart()
	first := f.addSuccessorBlock(t, s, 7, anchor)
	newHash, err := evmassign.PDRHash(confs[a.key])
	require.NoError(t, err)
	check := func(block *ExecutedBlock, when string) {
		t.Helper()
		si := block.ShardState.States[a.key]
		require.Equal(t, newHash[:], []byte(si.ShardConfHash), when)
		require.EqualValues(t, 1, si.TR.Epoch, when)
		require.EqualValues(t, 0, si.IR.Epoch, when+": the shard's input record is unchanged until it certifies at the new epoch")
		require.Contains(t, si.nodeIDs, a.nextKey.id, when)
		require.NotContains(t, si.nodeIDs, a.oldKey.id, when)
		require.ErrorContains(t, si.Verify(a.oldKey.id, func(abcrypto.Verifier) error { return nil }), "not in the trustbase", when+": the retired key is refused")
		require.NoError(t, si.Verify(a.nextKey.id, func(abcrypto.Verifier) error { return nil }), when)
		_, evmSet := block.ShardState.States[f.shard].nodeIDs, 0
		_ = evmSet
	}
	check(first, "activation block")
	for round := uint64(8); round <= 10; round++ {
		check(f.addSuccessorBlock(t, s, round, nil), "later block")
	}
	check(mustBlock(t, restart(), 10), "after restart")

	t.Run("a lost derived index is repaired from committed data, both configurations", func(t *testing.T) {
		lost := freshOrchestration(t, f)
		require.NoError(t, lost.AddShardConfig(a.conf))
		before, err := lost.ShardConfigs(7)
		require.NoError(t, err)
		require.EqualValues(t, 0, before[a.key].Epoch)
		_, err = New(crypto.SHA256, f.store.storage, lost, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		repaired, err := lost.ShardConfigs(7)
		require.NoError(t, err)
		require.EqualValues(t, 1, repaired[f.shard].Epoch)
		require.EqualValues(t, 1, repaired[a.key].Epoch)
		got, err := evmassign.PDRHash(repaired[a.key])
		require.NoError(t, err)
		require.Equal(t, newHash, got, "the repaired aggregator entry is the identical derived configuration")
	})

	t.Run("a different installed aggregator configuration refuses the install", func(t *testing.T) {
		// History says the change replaced a.conf; an orchestration that holds another genesis entry for the shard must not
		// install it on top.
		other := freshOrchestration(t, f)
		moved := *a.conf
		moved.T2Timeout += time.Second
		require.NoError(t, other.AddShardConfig(&moved))
		_, err := New(crypto.SHA256, f.store.storage, other, logger.New(t), ProfileHandoff)
		require.ErrorIs(t, err, ErrAssignmentHistory)
	})
}
