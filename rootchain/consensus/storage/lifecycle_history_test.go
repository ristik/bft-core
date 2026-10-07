package storage

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/identityfix"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-go-base/types"
)

type lifecycleHistory struct {
	path    string
	genesis *types.PartitionDescriptionRecord
	ids     []evmassign.Identity
	j, k    *types.PartitionDescriptionRecord
}

func evmConf(t *testing.T, epoch, start uint64, params map[string]string, nodes ...string) *types.PartitionDescriptionRecord {
	t.Helper()
	var vs []*types.NodeInfo
	for _, n := range nodes {
		vs = append(vs, newEVMKey(t, n).info)
	}
	return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Epoch: epoch, EpochStart: start, PartitionParams: params, Validators: vs}
}

func newLifecycleHistory(t *testing.T) *lifecycleHistory {
	t.Helper()
	h := &lifecycleHistory{path: filepath.Join(t.TempDir(), "orchestration.db")}
	params := map[string]string{"seal_registry_genesis": "g"}
	h.genesis = evmConf(t, 0, 1, params, "ev-a", "ev-b")
	root := []evmassign.RootMember{{NodeID: "r-a", Key: bytes.Repeat([]byte{1}, 33), Weight: 1}, {NodeID: "r-b", Key: bytes.Repeat([]byte{2}, 33), Weight: 1}}
	h.ids = identityfix.Identities(root, h.genesis, []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "ev-b"}})
	return h
}

func (h *lifecycleHistory) open(t *testing.T) *partitions.Orchestration {
	t.Helper()
	o, err := partitions.NewOrchestration(5, h.path, logger.New(t), partitions.WithNoSync())
	require.NoError(t, err)
	return o
}

// install commits a step of the given kind with a successor derived from the last installed configuration.
func (h *lifecycleHistory) install(t *testing.T, o *partitions.Orchestration, last *types.PartitionDescriptionRecord, kind uint64, epoch, start uint64, supersedes bool) *types.PartitionDescriptionRecord {
	t.Helper()
	succ, err := evmassign.NewSuccessor(last, []*types.NodeInfo{last.Validators[0], last.Validators[1]})
	require.NoError(t, err)
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	c := identityfix.Shaped(evmassign.Candidate{Version: evmassign.CandidateVersion, Predecessor: bytes.Repeat([]byte{byte(epoch)}, 32), Assignment: raw})
	if kind == evmassign.KindRecovery {
		c.Kind, c.PoPs, c.ReplacedAssignment = evmassign.KindRecovery, nil, bytes.Repeat([]byte{4}, 32)
	}
	prov, err := identityfix.ProvenanceFor(c, byte(epoch), epoch+1)
	require.NoError(t, err)
	pb, err := prov.Bytes()
	require.NoError(t, err)
	activated, err := evmassign.Activate(succ, start)
	require.NoError(t, err)
	require.NoError(t, o.InstallDerivedShardConfig(activated, pb))
	return activated
}

// The recovery allowance is read from committed history, never from a flag: it survives a restart, a new attempt and an abort (which
// leave no committed step), and an uncommitted retry consumes nothing.
func TestRecoveryAllowanceIsDerivedFromCommittedHistoryAndSurvivesRestart(t *testing.T) {
	h := newLifecycleHistory(t)
	o := h.open(t)
	require.NoError(t, o.AddShardConfig(h.genesis))
	require.NoError(t, o.SetGenesisIdentities(h.genesis.PartitionID, h.genesis.ShardID, h.ids))

	ctx, err := LifecycleFor(o, 8, types.ShardID{}, 0, h.genesis)
	require.NoError(t, err)
	require.Zero(t, ctx.Pending)
	require.Zero(t, ctx.CommittedRecoveries, "nothing committed: an uncommitted retry or an abort has consumed nothing")
	require.Nil(t, ctx.Head)
	require.Equal(t, h.ids, ctx.Incumbent, "the incumbent is the genesis baseline until a handoff is acknowledged")

	j := h.install(t, o, h.genesis, evmassign.KindPrimary, 1, 7, false)
	ctx, err = LifecycleFor(o, 8, types.ShardID{}, 0, h.genesis)
	require.NoError(t, err)
	require.Equal(t, [2]int{1, 0}, [2]int{ctx.Pending, ctx.CommittedRecoveries})
	require.NotNil(t, ctx.Head)
	require.EqualValues(t, evmassign.KindPrimary, ctx.Head.Candidate.Kind)

	k := h.install(t, o, j, evmassign.KindRecovery, 2, 9, true)
	_ = k
	check := func(t *testing.T, o *partitions.Orchestration) {
		ctx, err := LifecycleFor(o, 8, types.ShardID{}, 0, h.genesis)
		require.NoError(t, err)
		require.Equal(t, [2]int{2, 1}, [2]int{ctx.Pending, ctx.CommittedRecoveries}, "J then K: span two, one committed recovery")
		require.EqualValues(t, evmassign.KindRecovery, ctx.Head.Candidate.Kind)
		// a further candidate of either kind is refused for the spent allowance, before any other rule
		for _, kind := range []uint64{evmassign.KindPrimary, evmassign.KindRecovery} {
			err := evmassign.VerifyLifecycle(evmassign.Candidate{Kind: kind, Authorization: &evmassign.Authorization{}}, ctx)
			require.ErrorIs(t, err, evmassign.ErrRecoveryUsed, "kind %d", kind)
		}
	}
	check(t, o)
	require.NoError(t, o.Close())
	reopened := h.open(t)
	t.Cleanup(func() { _ = reopened.Close() })
	check(t, reopened)

	t.Run("acknowledgement closes the session: a later chain starts from the acknowledged committee", func(t *testing.T) {
		ctx, err := LifecycleFor(reopened, 8, types.ShardID{}, 2, h.genesis)
		require.NoError(t, err)
		require.Zero(t, ctx.Pending)
		require.Zero(t, ctx.CommittedRecoveries)
	})
}

func TestContinuityPolicyIsReadFromTheCommittedConfiguration(t *testing.T) {
	conf := func(params map[string]string) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{PartitionParams: params}
	}
	p, err := ContinuityPolicy(conf(nil))
	require.NoError(t, err)
	require.Equal(t, DevPolicy, p, "absent parameters take the DEV-DEFAULT policy")
	p, err = ContinuityPolicy(conf(map[string]string{ParamContinuityMaxM: "2", ParamContinuityMaxDist: "3/8"}))
	require.NoError(t, err)
	require.Equal(t, continuity.Policy{MaxM: 2, MaxDistNum: 3, MaxDistDen: 8}, p)
	for name, params := range map[string]map[string]string{
		"M not a number":           {ParamContinuityMaxM: "x"},
		"distance without a slash": {ParamContinuityMaxDist: "1"},
		"zero denominator":         {ParamContinuityMaxDist: "1/0"},
		"distance not numeric":     {ParamContinuityMaxDist: "a/b"},
	} {
		_, err := ContinuityPolicy(conf(params))
		require.ErrorIs(t, err, ErrLifecycle, name)
	}
	_, err = ContinuityPolicy(nil)
	require.ErrorIs(t, err, ErrLifecycle)
}

func TestAMissingIncumbentBaselineIsAnInvalidConfiguration(t *testing.T) {
	h := newLifecycleHistory(t)
	o := h.open(t)
	t.Cleanup(func() { _ = o.Close() })
	require.NoError(t, o.AddShardConfig(h.genesis))
	_, err := LifecycleFor(o, 8, types.ShardID{}, 0, h.genesis)
	require.ErrorIs(t, err, ErrLifecycle, "no baseline is not a no-recovery operating mode")
	require.ErrorIs(t, err, partitions.ErrNoBaseline)
	// recording a different baseline for the same shard is a conflict, the same one is idempotent
	require.NoError(t, o.SetGenesisIdentities(8, types.ShardID{}, h.ids))
	require.NoError(t, o.SetGenesisIdentities(8, types.ShardID{}, h.ids))
	other := identityfix.Identities([]evmassign.RootMember{{NodeID: "r-z", Key: bytes.Repeat([]byte{9}, 33), Weight: 1}}, h.genesis, []evmassign.Binding{{RootNodeID: "r-z", EVMNodeID: "ev-a"}})
	require.ErrorIs(t, o.SetGenesisIdentities(8, types.ShardID{}, other), partitions.ErrDerivedConflict)
}
