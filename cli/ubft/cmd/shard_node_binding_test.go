package cmd

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bft-core#1057: the health binding names this node, its network and shard, the installed configuration (epoch, hash, the key it names for
// this node) and the verified history; what cannot be read is left out, so a comparison of it fails closed.
func TestTheShardBindingReportsTheInstalledEvidence(t *testing.T) {
	_, pub, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	self, err := libp2ppeer.IDFromPublicKey(pub)
	require.NoError(t, err)
	conf := &types.PartitionDescriptionRecord{NetworkID: 5, PartitionID: 8, ShardID: types.ShardID{}}
	src := shardBindingSource{self: self, shard: conf,
		installed: func() (uint64, bool, []byte) { return 4, true, []byte{0xaa} },
		confHash: func(epoch uint64) ([]byte, bool) {
			if epoch == 4 {
				return []byte{0x01, 0x02}, true
			}
			return nil, false
		},
		history: func() ([]q3active.HistoryEntry, error) {
			return []q3active.HistoryEntry{{Epoch: 1, BodyID: "b1"}, {Epoch: 2, BodyID: "b2", CommitID: "c2"}}, nil
		}}
	b := src.binding()
	require.Equal(t, self.String(), b.NodeID)
	require.Equal(t, uint64(5), b.NetworkID)
	require.Equal(t, uint64(8), b.PartitionID)
	require.Equal(t, conf.ShardID.String(), b.ShardID)
	require.Equal(t, uint64(4), b.ShardEpoch)
	require.True(t, b.Member)
	require.Equal(t, "aa", b.SigKey)
	require.Equal(t, "0102", b.ShardConfHash)
	require.Len(t, b.History, 2)
	require.Equal(t, "b2", b.History[1].BodyID)

	src.installed = func() (uint64, bool, []byte) { return 5, false, nil }
	src.history = func() ([]q3active.HistoryEntry, error) { return nil, errors.New("not loaded") }
	b = src.binding()
	require.False(t, b.Member)
	require.Empty(t, b.SigKey, "not named: no key")
	require.Empty(t, b.ShardConfHash, "no installed hash for the epoch: left out")
	require.Empty(t, b.History, "an unreadable history is left out")
	src.history = nil
	require.Empty(t, src.binding().History, "no Q3 runtime")
}

// bft-core#1061: a restart replays the activation (activationCompleted) before the runtime has completed its epoch; the runtime's later
// completion notifies nobody. The health reads the live lease at every report, so the node that signs is reported active.
func TestARestartAfterActivationReportsTheActiveRole(t *testing.T) {
	runtimeEpoch := uint64(2)
	role := newShardRole(1, false, func() uint64 { return runtimeEpoch })
	notified := 0
	role.subscribe(func() { notified++ })
	health := shardnode.NewHealth()
	health.SetRoleSource(role.published)

	role.activationCompleted(3, true) // the replay at start, the runtime still at epoch 2
	require.Equal(t, "follower", health.Snapshot().Role, "not active before the runtime completes the epoch")
	_, active := role.Lease()
	require.False(t, active)
	before := notified

	runtimeEpoch = 3 // the runtime completes the epoch: no notification
	require.Equal(t, before, notified, "premise: nothing is notified")
	_, active = role.Lease()
	require.True(t, active, "the lease the node signs under is active")
	s := health.Snapshot()
	require.Equal(t, "active", s.Role, "and the health reports what the lease says")
	require.Equal(t, uint64(3), s.RoleEpoch)

	role.assignmentInstalled(false) // a later assignment without this node
	require.Equal(t, "follower", health.Snapshot().Role, "a revocation is reported at once too")
}

// The production wiring reads the role and the binding live (no one-off UpdateRole/UpdateBinding).
func TestShardNodeRunReportsTheLiveRoleAndBinding(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	calls := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name]++
			}
		}
		return true
	})
	require.Equal(t, 1, calls["SetRoleSource"])
	require.Equal(t, 1, calls["SetBindingSource"])
	require.Zero(t, calls["UpdateRole"], "no snapshot of the role that a later lease change would not refresh")
	require.Zero(t, calls["UpdateBinding"])
}
