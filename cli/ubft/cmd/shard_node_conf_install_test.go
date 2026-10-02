package cmd

import (
	"bytes"
	crand "crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// setInstaller is the node surface backed by the real configuration set, recording the order of installs.
type setInstaller struct {
	set   *shardnode.ShardConfSet
	calls []uint64
}

func (s *setInstaller) InstallShardConf(epoch uint64, hash []byte) error {
	s.calls = append(s.calls, epoch)
	return s.set.Install(epoch, hash)
}

// A verified assignment step is the only production source of the node's per-epoch shard configuration set: both its old and its new
// (epoch, hash) are installed, old first, and a contradiction with what is installed stops the handoff from activating.
func TestVerifiedAssignmentStepsAreInstalledIntoTheShardConfigurationSet(t *testing.T) {
	h := func(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }
	genesis := h(1)
	set, err := shardnode.NewShardConfSet(genesis[:])
	require.NoError(t, err)
	node := &setInstaller{set: set}

	t.Run("an assignment step installs the successor epoch's configuration, old before new", func(t *testing.T) {
		step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 0, NewShardEpoch: 1, OldActiveConfHash: genesis, NewActiveConfHash: h(2)}
		require.NoError(t, installAssignmentStepConfs(node, step))
		require.Equal(t, []uint64{0, 1}, node.calls)
		got, err := set.ForEpoch(1)
		require.NoError(t, err)
		want := h(2)
		require.Equal(t, want[:], got)
	})
	t.Run("replaying the step is harmless (restore, then catch-up)", func(t *testing.T) {
		step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 0, NewShardEpoch: 1, OldActiveConfHash: genesis, NewActiveConfHash: h(2)}
		require.NoError(t, installAssignmentStepConfs(node, step))
	})
	t.Run("a root-only step keeps the installed configuration", func(t *testing.T) {
		step := handoff.AssignmentStep{OldShardEpoch: 1, NewShardEpoch: 1, OldActiveConfHash: h(2), NewActiveConfHash: h(2)}
		require.NoError(t, installAssignmentStepConfs(node, step))
	})
	t.Run("a step that contradicts the installed configuration is refused", func(t *testing.T) {
		bad := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 1, NewShardEpoch: 2, OldActiveConfHash: h(9), NewActiveConfHash: h(3)}
		require.ErrorIs(t, installAssignmentStepConfs(node, bad), shardnode.ErrShardConfConflict, "the old side names another hash for epoch 1")
		_, err := set.ForEpoch(2)
		require.ErrorIs(t, err, shardnode.ErrShardConfEpochUnknown, "nothing of a refused step is installed")
		conflictNew := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 1, NewShardEpoch: 1, OldActiveConfHash: h(2), NewActiveConfHash: h(7)}
		require.ErrorIs(t, installAssignmentStepConfs(node, conflictNew), shardnode.ErrShardConfConflict, "the new side names another hash for the installed epoch")
	})
}

// peersAndConfs records both installs a verified assignment step makes.
type recordingConfs struct{ epochs []uint64 }

func (r *recordingConfs) InstallShardConf(epoch uint64, _ []byte) error {
	r.epochs = append(r.epochs, epoch)
	return nil
}

func peerIDOf(t *testing.T) libp2ppeer.ID {
	t.Helper()
	priv, _, err := libp2pcrypto.GenerateEd25519Key(crand.Reader)
	require.NoError(t, err)
	id, err := libp2ppeer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	return id
}

// A VERIFIED assignment bundle installs the shard configuration AND the validator set before the handoff is activated: a joiner may use
// this node's archive from then on (it restores before it can acknowledge), a retired validator may not.
func TestVerifiedAssignmentInstallsTheValidatorSetAndTheConfiguration(t *testing.T) {
	self, kept, retired, joiner := peerIDOf(t), peerIDOf(t), peerIDOf(t), peerIDOf(t)
	nodes := func(ids ...libp2ppeer.ID) []*types.NodeInfo {
		out := make([]*types.NodeInfo, len(ids))
		for i, id := range ids {
			out[i] = &types.NodeInfo{NodeID: id.String(), SigKey: bytes.Repeat([]byte{byte(i + 2)}, 33), Stake: 1}
		}
		return out
	}
	peers, err := shardnode.NewActivePeers(self, nodes(self, kept, retired))
	require.NoError(t, err)
	succ := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, Epoch: 1,
		Validators: nodes(self, kept, joiner)}
	raw, err := types.Cbor.Marshal(succ)
	require.NoError(t, err)
	candidate, err := evmassign.Candidate{Version: evmassign.CandidateVersion, Assignment: raw}.Encode()
	require.NoError(t, err)
	bundle := handoffdelivery.Bundle{Candidate: candidate}
	bundle.Proof.Record.ActivationRound = 7
	genesis, next := [32]byte{1}, [32]byte{2}
	step := handoff.AssignmentStep{Assignment: true, OldShardEpoch: 0, NewShardEpoch: 1, OldActiveConfHash: genesis, NewActiveConfHash: next}

	require.False(t, peers.Allowed(joiner), "a joiner is refused before the step is installed")
	require.True(t, peers.Allowed(retired))
	confs := &recordingConfs{}
	require.NoError(t, installVerifiedAssignment(confs, peers, bundle, step))
	require.Equal(t, []uint64{0, 1}, confs.epochs, "the shard configuration is installed, old before new")
	require.True(t, peers.Allowed(joiner), "a joiner is allowed once the step is installed")
	require.False(t, peers.Allowed(retired), "a validator the assignment retires is refused after activation")
	require.True(t, peers.Allowed(kept))

	t.Run("a root-only bundle leaves the peer set unchanged", func(t *testing.T) {
		require.NoError(t, installVerifiedAssignment(&recordingConfs{}, peers, handoffdelivery.Bundle{}, handoff.AssignmentStep{OldActiveConfHash: next, NewActiveConfHash: next, OldShardEpoch: 1, NewShardEpoch: 1}))
		require.True(t, peers.Allowed(joiner) && !peers.Allowed(retired))
	})
	t.Run("a bundle whose candidate does not decode is refused", func(t *testing.T) {
		require.ErrorIs(t, installVerifiedAssignment(&recordingConfs{}, peers, handoffdelivery.Bundle{Candidate: []byte("garbage")}, step), handoffdelivery.ErrBundle)
	})
}

// The OnInstalled path (the closure that installs a followed handoff before it is activated) must call installVerifiedAssignment, and
// the archive server must authorize peers through the active set. Removing either call changes no behavior a unit test of the helpers
// can see, so this pins the wiring in the source.
func TestTheOnInstalledPathAndTheArchiveServerAreWiredToTheActiveSet(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	calls := func(root ast.Node) map[string]bool {
		found := map[string]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					found[fn.Name] = true
				case *ast.SelectorExpr:
					found[fn.Sel.Name] = true
				}
			}
			return true
		})
		return found
	}
	var onInstalled *ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "OnInstalled" {
				onInstalled, _ = kv.Value.(*ast.FuncLit)
			}
		}
		return true
	})
	require.NotNil(t, onInstalled, "the follower's OnInstalled closure")
	require.True(t, calls(onInstalled)["installVerifiedAssignment"], "OnInstalled installs the verified assignment's configuration and validator set")
	require.True(t, calls(file)["SetPeerAuthorizer"], "the archive server authorizes peers through the active assignment's validators")
}
