package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The frontier service serves the members of each configured shard's INSTALLED configuration and the validators of the candidate
// staged on this root: a validator admitted by an assignment after the root started is served, and one an assignment removed is not
// (bft-core#524: the set used to be the one the configurations named when the root started).
func TestFrontierServesTheInstalledAssignmentsMembers(t *testing.T) {
	retained, joiner, removed, stranger, otherShard := peerIDOf(t), peerIDOf(t), peerIDOf(t), peerIDOf(t), peerIDOf(t)
	// what the root was started with names `retained` and `removed`; the allowance does not read it
	confs := []*types.PartitionDescriptionRecord{{PartitionID: 8, Validators: []*types.NodeInfo{{NodeID: retained.String()}, {NodeID: removed.String()}}}}
	members := fakeMembers{retained: true, removed: true}
	allowed := frontierAllowed(confs, members)

	require.True(t, allowed(retained))
	require.True(t, allowed(removed), "a member until an assignment removes it")
	require.False(t, allowed(joiner), "not a member yet")
	require.False(t, allowed(stranger))

	// an assignment installs: the joiner replaces the removed validator
	members[joiner], members[removed] = true, false
	require.True(t, allowed(joiner), "admitted by an assignment after the root started: served without a restart")
	require.False(t, allowed(removed), "removed by the assignment: no longer served, although the start configuration names it")
	require.True(t, allowed(retained))

	// the installed configuration of a shard this root is not configured with grants nothing
	require.False(t, frontierAllowed([]*types.PartitionDescriptionRecord{{PartitionID: 9}}, fakeMembers{otherShard: true})(otherShard))

	// a validator of the candidate staged on this root is served before its assignment is installed, and not once the stage is gone
	staged := peerIDOf(t)
	require.False(t, allowed(staged))
	fakeStaged[staged] = true
	t.Cleanup(func() { delete(fakeStaged, staged) })
	require.True(t, allowed(staged), "staged for the next epoch")
	delete(fakeStaged, staged)
	require.False(t, allowed(staged))
}

// Production builds the frontier server from frontierAllowed over the consensus manager, asked on every request: a server built from
// a fixed list would refuse a later joiner again.
func TestServeRootFrontierAuthorizesThroughFrontierAllowed(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "root_node.go", nil, 0)
	require.NoError(t, err)
	var wired, fixed bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serveRootFrontier" {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, _ := sel.X.(*ast.Ident)
			if pkg == nil || pkg.Name != "frontiertransport" {
				return true
			}
			switch sel.Sel.Name {
			case "NewServer":
				fixed = true
			case "NewServerFor":
				if len(call.Args) == 4 {
					inner, ok := call.Args[1].(*ast.CallExpr)
					if id, isID := inner.Fun.(*ast.Ident); ok && isID && id.Name == "frontierAllowed" && len(inner.Args) == 2 {
						cmArg, isCM := inner.Args[1].(*ast.Ident)
						wired = isCM && cmArg.Name == "cm"
					}
				}
			}
			return true
		})
		return false
	})
	require.True(t, wired, "serveRootFrontier builds the frontier server from frontiertransport.NewServerFor(ctx, frontierAllowed(shardConfs, cm), ...)")
	require.False(t, fixed, "serveRootFrontier must not build a fixed-set frontier server")
}
