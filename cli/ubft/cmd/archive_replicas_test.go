package cmd

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	p2ptest "github.com/libp2p/go-libp2p/core/test"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func randPeer(t *testing.T) peer.ID {
	t.Helper()
	id, err := p2ptest.RandPeerID()
	require.NoError(t, err)
	return id
}

func nodeInfos(ids ...peer.ID) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(ids))
	for i, id := range ids {
		out[i] = &types.NodeInfo{NodeID: id.String(), SigKey: []byte{byte(i)}, Stake: 1}
	}
	return out
}

func TestArchivePruneRequiresArchiveStore(t *testing.T) {
	if err := shardNodeRun(context.Background(), &shardNodeRunFlags{ArchivePrune: true}, nil); !errors.Is(err, archivewiring.ErrConfig) {
		t.Fatalf("pruning without archive configuration: %v", err)
	}
}

// The structural half stays early: it needs no membership, and every malformed input is the existing configuration error.
func TestParseArchiveReplicasRefusesMalformedConfiguration(t *testing.T) {
	self, a, b, c := randPeer(t), randPeer(t), randPeer(t), randPeer(t)
	for name, raws := range map[string][]string{
		"none":      nil,
		"one":       {a.String()},
		"three":     {a.String(), b.String(), c.String()},
		"malformed": {a.String(), "not-a-peer-id"},
		"empty":     {a.String(), ""},
		"self":      {self.String(), b.String()},
		"self last": {a.String(), self.String()},
		"duplicate": {a.String(), a.String()},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseArchiveReplicas(raws, self)
			require.ErrorIs(t, err, archivewiring.ErrConfig)
			require.Equal(t, [2]peer.ID{}, got, "no half-parsed pair escapes a refusal")
		})
	}
	got, err := parseArchiveReplicas([]string{a.String(), b.String()}, self)
	require.NoError(t, err)
	require.Equal(t, [2]peer.ID{a, b}, got)
	_, err = parseArchiveReplicas([]string{a.String(), c.String()}, self)
	require.NoError(t, err, "membership is not judged here: a replica that a later step installed must parse")
}

func TestRequireArchiveReplicasInstalledRefusesUninstalledPeers(t *testing.T) {
	a, b, stranger := randPeer(t), randPeer(t), randPeer(t)
	installed := []peer.ID{a, b}
	require.NoError(t, requireArchiveReplicasInstalled([2]peer.ID{a, b}, installed))
	require.ErrorIs(t, requireArchiveReplicasInstalled([2]peer.ID{a, stranger}, installed), archivewiring.ErrConfig)
	require.ErrorIs(t, requireArchiveReplicasInstalled([2]peer.ID{stranger, b}, installed), archivewiring.ErrConfig)
	require.ErrorIs(t, requireArchiveReplicasInstalled([2]peer.ID{a, b}, nil), archivewiring.ErrConfig)
}

// A replacement pair is refused against the genesis set and accepted once the persisted replay installed the successor assignment; a
// retired validator is refused after it; a refusal leaves the hold in place and a success ends it.
func TestAReplacementArchiveReplicaPairIsValidatedAgainstTheReplayedSet(t *testing.T) {
	self, b, d, e, other := randPeer(t), randPeer(t), randPeer(t), randPeer(t), randPeer(t)
	genesis := nodeInfos(self, b, d, other)
	replacement := [2]peer.ID{b, e}
	original := [2]peer.ID{b, d}

	t.Run("genesis-only startup is unchanged", func(t *testing.T) {
		peers, err := shardnode.NewActivePeers(self, genesis)
		require.NoError(t, err)
		peers.Hold()
		require.NoError(t, admitArchivePeers(peers, original, true, true))
		require.True(t, peers.Allowed(b), "the hold ended")
		require.ErrorIs(t, admitArchivePeers(peers, replacement, true, true), archivewiring.ErrConfig, "e was never installed")
	})
	t.Run("replacement refused against genesis, accepted after the replay", func(t *testing.T) {
		peers, err := shardnode.NewActivePeers(self, genesis)
		require.NoError(t, err)
		peers.Hold()
		require.ErrorIs(t, admitArchivePeers(peers, replacement, true, true), archivewiring.ErrConfig, "before the replay: only the genesis set")
		require.False(t, peers.Allowed(b), "a refusal never ends the hold")
		require.NoError(t, peers.Install(1, nodeInfos(self, b, e, other)), "the persisted step replaces d with e")
		require.NoError(t, admitArchivePeers(peers, replacement, true, true))
		require.True(t, peers.Allowed(e), "validated, then released")
	})
	t.Run("a retired validator is refused after the replay", func(t *testing.T) {
		peers, err := shardnode.NewActivePeers(self, genesis)
		require.NoError(t, err)
		peers.Hold()
		require.NoError(t, peers.Install(1, nodeInfos(self, b, e, other)))
		require.ErrorIs(t, admitArchivePeers(peers, original, true, true), archivewiring.ErrConfig, "d was retired")
		require.False(t, peers.Allowed(b), "the hold stays")
	})
	t.Run("an unheld node validates without releasing, and without an archive nothing is judged", func(t *testing.T) {
		peers, err := shardnode.NewActivePeers(self, genesis)
		require.NoError(t, err)
		require.ErrorIs(t, admitArchivePeers(peers, replacement, true, false), archivewiring.ErrConfig)
		require.NoError(t, admitArchivePeers(peers, [2]peer.ID{}, false, false))
	})
}

// The restore step order, as runProfile2ArchiveRestore runs it: catch-up installs the steps, then the replicas are validated before the
// hold ends, then the archive setup, then the replay. A failed catch-up or validation never releases the hold or reaches a later step.
func TestRestoreValidatesReplicasAfterCatchUpAndBeforeReleaseSetupOrReplay(t *testing.T) {
	self, b, d, e, other := randPeer(t), randPeer(t), randPeer(t), randPeer(t), randPeer(t)
	newPeers := func() *shardnode.ActivePeers {
		peers, err := shardnode.NewActivePeers(self, nodeInfos(self, b, d, other))
		require.NoError(t, err)
		peers.Hold()
		return peers
	}
	run := func(peers *shardnode.ActivePeers, replicas [2]peer.ID, catchUp func() error) (steps []string, err error) {
		err = runProfile2ArchiveRestore(context.Background(),
			func(context.Context) error {
				steps = append(steps, "catch-up")
				if err := catchUp(); err != nil {
					return err
				}
				return admitArchivePeers(peers, replicas, true, true)
			},
			func(context.Context) error { steps = append(steps, "setup"); return nil },
			func(context.Context) error { steps = append(steps, "replay"); return nil },
			func(context.Context) error { steps = append(steps, "repair"); return nil })
		return steps, err
	}

	t.Run("replacement accepted after the catch-up installed it", func(t *testing.T) {
		peers := newPeers()
		steps, err := run(peers, [2]peer.ID{b, e}, func() error { return peers.Install(1, nodeInfos(self, b, e, other)) })
		require.NoError(t, err)
		require.Equal(t, []string{"catch-up", "setup", "replay", "repair"}, steps)
		require.True(t, peers.Allowed(e))
	})
	t.Run("replacement refused when the catch-up installed nothing", func(t *testing.T) {
		peers := newPeers()
		steps, err := run(peers, [2]peer.ID{b, e}, func() error { return nil })
		require.ErrorIs(t, err, archivewiring.ErrConfig)
		require.Equal(t, []string{"catch-up"}, steps, "no setup, replay or repair after a refusal")
		require.False(t, peers.Allowed(b), "the hold stays")
	})
	t.Run("a failed catch-up never releases the hold", func(t *testing.T) {
		peers := newPeers()
		failure := errors.New("catch-up incomplete")
		steps, err := run(peers, [2]peer.ID{b, d}, func() error { return failure })
		require.ErrorIs(t, err, failure)
		require.Equal(t, []string{"catch-up"}, steps)
		require.False(t, peers.Allowed(b), "the hold stays")
	})
}

// The production order cannot be seen by helper tests: moving the validation before the replay, releasing outside admitArchivePeers,
// enabling the frontier before the validation, or parsing late would all leave them green.
func TestShardNodeRunValidatesArchiveReplicasAfterReplayAndBeforeRelease(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			funcs[fn.Name.Name] = fn
		}
	}
	run := funcs["shardNodeRun"]
	require.NotNil(t, run)
	require.NotContains(t, funcs, "configuredArchiveReplicas", "the combined parse-and-validate is gone")

	type site struct {
		pos  token.Pos
		call *ast.CallExpr
	}
	callsIn := func(root ast.Node) map[string][]site {
		out := map[string][]site{}
		ast.Inspect(root, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				out[fun.Name] = append(out[fun.Name], site{call.Pos(), call})
			case *ast.SelectorExpr:
				name := fun.Sel.Name
				if id, ok := fun.X.(*ast.Ident); ok {
					name = id.Name + "." + name
				}
				out[name] = append(out[name], site{call.Pos(), call})
			}
			return true
		})
		return out
	}
	calls := callsIn(run)

	// Structural parsing is early: before the follower that fetches from the replicas is built, and before any replay.
	require.Len(t, calls["parseArchiveReplicas"], 1)
	var follower token.Pos
	ast.Inspect(run, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if sel, ok := lit.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "HandoffFollower" {
				follower = lit.Pos()
			}
		}
		return true
	})
	require.NotZero(t, follower)
	require.Less(t, calls["parseArchiveReplicas"][0].pos, follower)
	require.Len(t, calls["runProfile2JournalStartup"], 1)
	require.Less(t, calls["parseArchiveReplicas"][0].pos, calls["runProfile2JournalStartup"][0].pos)

	// Membership validation lives only in admitArchivePeers, never against the hold-sensitive Allowed, and every release goes through it.
	require.Empty(t, calls["requireArchiveReplicasInstalled"], "shardNodeRun validates through admitArchivePeers only")
	require.Empty(t, calls["activePeers.Release"], "the hold ends only inside admitArchivePeers, after the validation")
	for _, name := range []string{"admitArchivePeers", "requireArchiveReplicasInstalled"} {
		require.NotContains(t, callsIn(funcs[name]), "peers.Allowed", name+" must not judge by Allowed: the hold makes it refuse everyone")
	}
	admit := callsIn(funcs["admitArchivePeers"])
	require.Len(t, admit["requireArchiveReplicasInstalled"], 1)
	require.Len(t, admit["peers.Release"], 1)
	require.Less(t, admit["requireArchiveReplicasInstalled"][0].pos, admit["peers.Release"][0].pos, "validated before the hold ends")
	require.Equal(t, []string{"peers.Peers"}, installedSource(t, funcs["admitArchivePeers"]), "against the installed set")

	// The three admissions: plain run, restore without history, restore after CatchUp.
	require.Len(t, calls["admitArchivePeers"], 3)
	require.Len(t, calls["catcher.CatchUp"], 1)
	catchUp := calls["catcher.CatchUp"][0]

	var catchUpFunc *ast.FuncLit
	ast.Inspect(run, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "catchUpHistory" {
				catchUpFunc, _ = as.Rhs[0].(*ast.FuncLit)
			}
		}
		return true
	})
	require.NotNil(t, catchUpFunc)
	var plain, noHistory, afterCatchUp []site
	for _, s := range calls["admitArchivePeers"] {
		switch {
		case s.pos > catchUpFunc.Pos() && s.pos < catchUpFunc.End() && s.pos > catchUp.pos:
			afterCatchUp = append(afterCatchUp, s)
		case s.pos > catchUpFunc.Pos() && s.pos < catchUpFunc.End():
			noHistory = append(noHistory, s)
		default:
			plain = append(plain, s)
		}
	}
	require.Len(t, plain, 1)
	require.Len(t, noHistory, 1)
	require.Len(t, afterCatchUp, 1)
	require.Greater(t, plain[0].pos, calls["runProfile2JournalStartup"][0].pos, "a plain run validates after the persisted replay")

	// A failed catch-up returns before the validation and release.
	var checked bool
	for _, stmt := range catchUpFunc.Body.List {
		ifs, ok := stmt.(*ast.IfStmt)
		if !ok || ifs.Init == nil || !(ifs.Init.Pos() <= catchUp.pos && catchUp.pos < ifs.Init.End()) {
			continue
		}
		cond, ok := ifs.Cond.(*ast.BinaryExpr)
		require.True(t, ok)
		lhs, lok := cond.X.(*ast.Ident)
		rhs, rok := cond.Y.(*ast.Ident)
		require.True(t, lok && rok && lhs.Name == "err" && rhs.Name == "nil" && cond.Op == token.NEQ, "the check is exactly err != nil")
		require.NotEmpty(t, ifs.Body.List)
		_, returns := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ReturnStmt)
		require.True(t, returns, "a CatchUp error is returned at once")
		require.Less(t, ifs.End(), afterCatchUp[0].pos)
		checked = true
	}
	require.True(t, checked, "the catch-up error check sits directly in the closure")

	// Frontier enablement is one closure, invoked after the validation: on a plain run after its admission, on a restore as the setup
	// step between the catch-up and the archive replay.
	require.Len(t, calls["journalStore.EnableFrontier"], 1)
	frontierFunc := (*ast.FuncLit)(nil)
	ast.Inspect(run, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "enableArchiveFrontier" {
				frontierFunc, _ = as.Rhs[0].(*ast.FuncLit)
			}
		}
		return true
	})
	require.NotNil(t, frontierFunc)
	require.True(t, calls["journalStore.EnableFrontier"][0].pos > frontierFunc.Pos() && calls["journalStore.EnableFrontier"][0].pos < frontierFunc.End(),
		"EnableFrontier is reachable only through the enableArchiveFrontier closure")
	var directCalls []site
	for _, s := range calls["enableArchiveFrontier"] {
		directCalls = append(directCalls, s)
	}
	require.Len(t, directCalls, 1, "one direct call: the plain-run path")
	require.Greater(t, directCalls[0].pos, plain[0].pos, "after the plain run's validation")
	restoreCall := calls["runProfile2ArchiveRestore"]
	require.Len(t, restoreCall, 1)
	args := restoreCall[0].call.Args
	require.Len(t, args, 5)
	for i, want := range []string{"", "catchUpHistory", "enableArchiveFrontier", "restoreArchive", "repairRestoredHandoffs"} {
		if want == "" {
			continue
		}
		id, ok := args[i].(*ast.Ident)
		require.True(t, ok)
		require.Equal(t, want, id.Name, "argument %d", i)
	}

	// Nothing uses the replicas before the validation: the publisher, the frontier worker and the archive restore come later in the run.
	var publisher, archiveRestore token.Pos
	ast.Inspect(run, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if sel, ok := lit.Type.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Publisher":
					publisher = lit.Pos()
				case "ArchiveRestore":
					archiveRestore = lit.Pos()
				}
			}
		}
		return true
	})
	require.NotZero(t, publisher)
	require.NotZero(t, archiveRestore)
	require.Greater(t, publisher, plain[0].pos)
	require.Greater(t, publisher, afterCatchUp[0].pos)
	require.Greater(t, archiveRestore, afterCatchUp[0].pos)
	require.Greater(t, archiveRestore, noHistory[0].pos)
}

// installedSource names the active-peer accessors the function reads the installed set from.
func installedSource(t *testing.T, fn *ast.FuncDecl) []string {
	t.Helper()
	var out []string
	ast.Inspect(fn, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "peers" && (sel.Sel.Name == "Peers" || sel.Sel.Name == "Allowed") {
				out = append(out, "peers."+sel.Sel.Name)
			}
		}
		return true
	})
	return out
}
