package consensus

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The startup fence (astra review of #1228, item 3): a root refuses an epoch >= E of a rule it lacks from the verified checkpoint of the
// epoch it is about to install or recover, before any durable install step, so a refused start leaves every store as it found it.

var startupRule = vrschema.RuleID("startup-fence-test-v1")

// scheduleVR is the VR root state a checkpoint commits, holding one Active entry for startupRule effective at root epoch e.
func scheduleVR(t *testing.T, e uint64) []byte {
	t.Helper()
	raw, err := vradmit.RootState{Backoff: vrschema.HandoffBackoff{Epoch: 1, N: 4, Intent: make([]byte, 32)}, Schedule: []vrschema.Activation{{RuleID: startupRule, RootEpoch: e, State: vrschema.ActActive, ChangeID: 1}}}.Encode()
	require.NoError(t, err)
	return raw
}

func dumpDB(t *testing.T, db *memorydb.MemoryDB) string {
	t.Helper()
	var out string
	for it := db.First(); it.Valid(); it.Next() {
		var v any
		require.NoError(t, it.Value(&v))
		out += fmt.Sprintf("%x=%v\n", it.Key(), v)
	}
	return out
}

// durableState is every durable store of the replica, as bytes.
type durableState struct {
	trust, journal, history string
	bolt                    [32]byte
	anchorSafety            string
	trustEpoch2             bool
}

func (r *q3Replica) durable_() durableState {
	r.t.Helper()
	raw, err := os.ReadFile(r.dir + "/root.db")
	require.NoError(r.t, err)
	a, err := r.manager.blockStore().GetDB().(epochAnchorSafetyStore).ReadEpochAnchorSafety()
	require.NoError(r.t, err)
	_, terr := r.trust.GetByEpoch(2)
	return durableState{trust: dumpDB(r.t, r.trustDB), journal: dumpDB(r.t, r.journalDB), history: dumpDB(r.t, r.historyDB),
		bolt: sha256.Sum256(raw), anchorSafety: fmt.Sprintf("%v", a), trustEpoch2: terr == nil}
}

func TestScheduleOfCheckpointAndFence(t *testing.T) {
	s, err := ScheduleOfCheckpoint(nil)
	require.NoError(t, err)
	require.Empty(t, s, "no VR state, no schedule")
	_, err = ScheduleOfCheckpoint([]byte{1, 2})
	require.Error(t, err)
	s, err = ScheduleOfCheckpoint(scheduleVR(t, 5))
	require.NoError(t, err)
	require.Len(t, s, 1)

	lacks, knows := vrrules.Set{}, vrrules.Set{startupRule: "x"}
	head := q3fixture.New(t, q3fixture.Options{ControlVR: scheduleVR(t, 5)}).Snapshot
	require.NoError(t, FenceCheckpoint(lacks, head, 4), "E is not reached")
	require.ErrorIs(t, FenceCheckpoint(lacks, head, 5), vrrules.ErrUpgradeRequired)
	require.ErrorIs(t, FenceCheckpoint(lacks, head, 6), vrrules.ErrUpgradeRequired)
	require.NoError(t, FenceCheckpoint(knows, head, 6), "the rule is known")
	require.NoError(t, FenceCheckpoint(lacks, nil, 6), "no checkpoint, no schedule")
}

// A cold join: a fresh node installs the activation whose verified checkpoint schedules a rule it lacks at the target epoch. It is
// refused with UpgradeRequired and no store changes; the same node with the rule installs it.
func TestColdJoinRefusesAnUnsupportedRuleBeforeAnyDurableWrite(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{ControlVR: scheduleVR(t, 2)})
	r := newQ3Replica(t, f, f.NewNodes[0])
	r.mustOpen(true)
	t.Cleanup(r.close)
	r.manager.rules = vrrules.Set{}
	require.NoError(t, r.rt.Recover(ctx))
	before := r.durable_()

	err := r.rt.Activate(ctx, r.bundle())
	require.ErrorIs(t, err, vrrules.ErrUpgradeRequired)
	require.Contains(t, err.Error(), "UpgradeRequired")
	require.Equal(t, before, r.durable_(), "a refused activation leaves every durable store untouched")
	require.Nil(t, r.manager.epochAnchor)
	_, ok := r.rt.Activated(2)
	require.False(t, ok)
	_, staged, serr := r.rt.StagedBundleAt(ctx, 2)
	require.NoError(t, serr)
	require.False(t, staged)

	// the pass case: the rule is known
	r.manager.rules = vrrules.Set{startupRule: "x"}
	require.NoError(t, r.rt.Activate(ctx, r.bundle()))
	require.NotNil(t, r.manager.epochAnchor)
}

// A rule effective only after the target epoch does not fence it.
func TestColdJoinPassesWhenTheRuleIsNotYetReached(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{ControlVR: scheduleVR(t, 9)})
	r := newQ3Replica(t, f, f.NewNodes[0])
	r.mustOpen(true)
	t.Cleanup(r.close)
	r.manager.rules = vrrules.Set{}
	require.NoError(t, r.rt.Recover(ctx))
	require.NoError(t, r.rt.Activate(ctx, r.bundle()))
	require.NotNil(t, r.manager.epochAnchor)
}

// A restart with a partially staged E: the journal holds the staged activation (the install stopped after the root step), and the
// restarted binary lacks the scheduled rule. Recovery refuses before completing anything, and every store is as the crash left it.
func TestRestartWithAStagedEpochRefusesBeforeRecoveryWritesAnything(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{ControlVR: scheduleVR(t, 2)})
	r := newQ3Replica(t, f, f.NewNodes[0])
	r.mustOpen(true)
	t.Cleanup(r.close)
	r.manager.rules = vrrules.Set{startupRule: "x"} // the first incarnation supports the rule and stages E
	require.NoError(t, r.rt.Recover(ctx))
	r.authority.off.Store(true) // the authority step fails: E is staged and installed in the root, not complete
	require.Error(t, r.rt.Activate(ctx, r.bundle()))
	_, staged, err := r.rt.StagedBundleAt(ctx, 2)
	require.NoError(t, err)
	require.True(t, staged, "E is staged")
	r.close()

	// restart on the downgraded binary: the manager lacks the rule
	r.mustOpen(true)
	before := r.durable_()
	r.manager.rules = vrrules.Set{}
	err = r.rt.Recover(ctx)
	require.ErrorIs(t, err, vrrules.ErrUpgradeRequired)
	require.Equal(t, before, r.durable_(), "a refused recovery leaves every durable store untouched")

	// the pass case: the same restart on a binary that has the rule completes the installation
	r.manager.rules = vrrules.Set{startupRule: "x"}
	require.NoError(t, r.rt.Recover(ctx))
	require.NoError(t, r.rt.Admit(2))
}
