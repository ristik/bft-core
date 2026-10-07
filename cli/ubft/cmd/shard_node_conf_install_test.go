package cmd

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/identityfix"
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
	candidate, err := identityfix.Shaped(evmassign.Candidate{Version: evmassign.CandidateVersion, Assignment: raw}).Encode()
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

// After a restart the archive server must not authorize peers from the genesis set while the persisted verified assignment steps are
// still being replayed: the set is held from its creation (before the server is registered) and released only after the replay, at the
// end of the startup for a restarting node and after CatchUp for a restoring one.
func TestTheActivePeerSetIsHeldUntilThePersistedStepsAreReplayed(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	type site struct {
		pos  token.Pos
		root string
	}
	var holds, releases, direct, registers, startups, catchUps []site
	var catchUpFunc *ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 {
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "catchUpHistory" && len(as.Rhs) == 1 {
				if fl, ok := as.Rhs[0].(*ast.FuncLit); ok {
					catchUpFunc = fl
				}
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			recv := ""
			if id, ok := fn.X.(*ast.Ident); ok {
				recv = id.Name
			}
			switch {
			case recv == "activePeers" && fn.Sel.Name == "Hold":
				holds = append(holds, site{call.Pos(), recv})
			case recv == "activePeers" && fn.Sel.Name == "Release":
				direct = append(direct, site{call.Pos(), recv})
			case recv == "archiveServer" && fn.Sel.Name == "Register":
				registers = append(registers, site{call.Pos(), recv})
			case fn.Sel.Name == "CatchUp":
				catchUps = append(catchUps, site{call.Pos(), recv})
			}
		case *ast.Ident:
			switch fn.Name {
			case "runProfile2JournalStartup":
				startups = append(startups, site{call.Pos(), fn.Name})
			case "admitArchivePeers":
				// The only way the hold ends: it validates the configured replicas against the replayed set first.
				releases = append(releases, site{call.Pos(), fn.Name})
			}
		}
		return true
	})
	require.Len(t, holds, 1, "the peer set is held once, at its creation")
	require.Len(t, registers, 1)
	require.Len(t, startups, 1)
	require.Len(t, catchUps, 1)
	require.Empty(t, direct, "the hold ends only through admitArchivePeers, which validates the archive replicas first")
	require.Len(t, releases, 3, "admitted after the startup replay (restart), without history (a profile-off restore) and after CatchUp (restore), and nowhere else")
	require.Less(t, holds[0].pos, registers[0].pos, "held before the archive server is registered")
	require.NotNil(t, catchUpFunc, "the restore's catchUpHistory closure")
	var afterStartup, afterCatchUp bool
	for _, r := range releases {
		inCatchUp := r.pos >= catchUpFunc.Pos() && r.pos <= catchUpFunc.End()
		if r.pos > startups[0].pos && !inCatchUp {
			afterStartup = true
		}
		if inCatchUp && r.pos > catchUps[0].pos {
			afterCatchUp = true
		}
	}
	require.True(t, afterStartup, "a release after runProfile2JournalStartup")
	require.True(t, afterCatchUp, "a release inside the restore's catch-up closure")
}

// The follower's archive fetch names exactly the replica's "not admitted yet" refusal as the retryable sentinel and leaves every other
// error alone, and the follower is wired through that mapping.
func TestTheArchiveFetchMapsOnlyThePeerNotAllowedRefusal(t *testing.T) {
	refused := fmt.Errorf("fetching: %w", archivewiring.ErrPeerNotAllowed)
	mapped := handoffArchiveRefusal(refused)
	require.ErrorIs(t, mapped, shardnode.ErrHandoffPeerNotReady)
	require.ErrorIs(t, mapped, archivewiring.ErrPeerNotAllowed, "the cause stays reachable")
	for _, other := range []error{archivewiring.ErrPendingLimit, archivewiring.ErrTransport, archivewiring.ErrReplica, errors.New("boom")} {
		require.NotErrorIs(t, handoffArchiveRefusal(other), shardnode.ErrHandoffPeerNotReady, "%v is not retried by the catch-up", other)
	}
	require.NoError(t, handoffArchiveRefusal(nil))

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var fetchArchive *ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			// the follower's closure (the journal coordinator has a FetchArchive of its own)
			if sel, ok := as.Lhs[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "FetchArchive" {
				if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == "handoffFollower" {
					fetchArchive, _ = as.Rhs[0].(*ast.FuncLit)
				}
			}
		}
		return true
	})
	require.NotNil(t, fetchArchive, "the follower's FetchArchive closure")
	mappedCall := false
	ast.Inspect(fetchArchive, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "handoffArchiveRefusal" {
				mappedCall = true
			}
		}
		return true
	})
	require.True(t, mappedCall, "FetchArchive returns the replica's refusal through handoffArchiveRefusal")
}

// The follower's OnInstalled closure records a handoff's terminal certificate under the genesis-bound store: the context comes from
// configuredprogress.TerminalContext with the verified snapshot's configuration for exactly the epoch of the certificate's own technical
// record, both the authentication and the store use that context, and nothing in the closure rewrites the observation's genesis pin or
// resolver by hand (the override that stopped validators at the folded s=3 supersession). A unit test of TerminalContext cannot see
// the call site, so this pins it in the source.
func TestTheHandoffTerminalCertificateIsRecordedUnderTheTerminalContext(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
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
	src := func(e ast.Expr) string {
		var b bytes.Buffer
		require.NoError(t, printer.Fprint(&b, fset, e))
		return b.String()
	}
	var terminalCtx []string
	var authenticated, prepared []string
	ast.Inspect(onInstalled, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && (sel.Sel.Name == "ShardConfHash" || sel.Sel.Name == "ConfForEpoch") {
					t.Errorf("OnInstalled assigns %s: the store's genesis pin and resolver are set only by configuredprogress.TerminalContext", src(sel))
				}
			}
			if len(n.Lhs) >= 1 && len(n.Rhs) == 1 && src(n.Lhs[0]) == "terminalCtx" { // terminalCtx, err := ...
				if call, ok := n.Rhs[0].(*ast.CallExpr); ok && src(call.Fun) == "configuredprogress.TerminalContext" {
					for _, a := range call.Args {
						terminalCtx = append(terminalCtx, src(a))
					}
				}
			}
		case *ast.CallExpr:
			switch src(n.Fun) {
			case "rootinput.AuthenticateObservationV2":
				for _, a := range n.Args {
					authenticated = append(authenticated, src(a))
				}
			case "journalStore.PrepareObservation":
				for _, a := range n.Args {
					prepared = append(prepared, src(a))
				}
			}
		}
		return true
	})
	require.Equal(t, []string{"journalCtx", "verified.Shard.ShardConfHash", "verified.Shard.TR.Epoch"}, terminalCtx,
		"the terminal context is the genesis-bound journal context with the snapshot's configuration for the certificate's own shard epoch")
	require.Equal(t, []string{"ctx", "terminalCtx.Observation", "verified.Shard.UC", "verified.Shard.TR"}, authenticated,
		"the certificate is authenticated under the terminal context, with the technical record whose epoch the resolver names")
	require.Equal(t, []string{"ctx", "terminalCtx", "terminal"}, prepared, "the certificate is recorded under the same context")
}

// Every shard-membership consumer in shardNodeRun follows activePeers (the verified, installed assignment), not the genesis validator
// list: dissemination, the archive and journal servers' authorizers, the journal suffix providers and the evidence providers.
func TestShardNodeRunMembershipConsumersFollowTheActivePeers(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	authorizers, restricted, providerSources, fixedProviders := 0, 0, 0, 0
	var disseminatorGetsActive bool
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "SetPeerAuthorizer":
					authorizers++
				case "RestrictToPeers":
					restricted++
				}
			}
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "buildDisseminator" {
				for _, a := range x.Args {
					if i, ok := a.(*ast.Ident); ok && i.Name == "activePeers" {
						disseminatorGetsActive = true
					}
				}
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok {
					switch sel.Sel.Name {
					case "ProviderSource":
						providerSources++
					case "Providers":
						fixedProviders++
					}
				}
			}
		}
		return true
	})
	require.Equal(t, 2, authorizers, "the archive server and the journal server")
	require.Zero(t, restricted, "no fixed allowlist")
	require.Equal(t, 2, providerSources, "the journal suffix coordinator and the evidence recovery")
	require.Zero(t, fixedProviders, "no fixed provider list")
	require.True(t, disseminatorGetsActive)

	// and buildDisseminator hands that source (not a list read from the genesis validators) to the transport
	var fromActive bool
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "buildDisseminator" {
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewNetDisseminatorFrom" && len(call.Args) == 3 {
						if id, ok := call.Args[2].(*ast.Ident); ok && id.Name == "active" {
							fromActive = true
						}
					}
				}
				return true
			})
		}
	}
	require.True(t, fromActive, "buildDisseminator addresses the active peers")
}
