package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

type fakeMembers map[peer.ID]bool

// staged is the set of peers the fake root has a staged candidate for.
var fakeStaged = map[peer.ID]bool{}

func (fakeMembers) IsStagedRoot(string) bool { return false }

func (fakeMembers) IsStagedValidator(nodeID string) bool {
	id, err := peer.Decode(nodeID)
	return err == nil && fakeStaged[id]
}

func (f fakeMembers) IsShardValidator(partition types.PartitionID, _ types.ShardID, nodeID string) bool {
	id, err := peer.Decode(nodeID)
	return err == nil && partition == 8 && f[id]
}

// The records feed serves the validators named at the root's start, the other roots, and the members of each configured shard's installed
// configuration, so a validator that joined by an assignment is served without a root restart; nobody else.
func TestRecordsFeedServesTheInstalledAssignmentsMembers(t *testing.T) {
	ids := make([]peer.ID, 5)
	for i := range ids {
		ids[i] = peerIDOf(t)
	}
	named, otherRoot, joiner, installedButOtherShard, stranger := ids[0], ids[1], ids[2], ids[3], ids[4]
	static := map[peer.ID]struct{}{named: {}}
	confs := []*types.PartitionDescriptionRecord{{PartitionID: 8}}
	members := fakeMembers{joiner: true}
	allowed := recordsFeedAllowed(static, confs, members, func(id peer.ID) bool { return id == otherRoot })

	require.True(t, allowed(named), "named by the configuration at start")
	require.True(t, allowed(otherRoot), "another root")
	require.True(t, allowed(joiner), "a member of the installed configuration that the start configuration did not name")
	require.False(t, allowed(stranger))

	// the installed configuration of a shard the root is not configured with grants nothing
	other := recordsFeedAllowed(static, []*types.PartitionDescriptionRecord{{PartitionID: 9}}, fakeMembers{installedButOtherShard: true}, func(peer.ID) bool { return false })
	require.False(t, other(installedButOtherShard))

	// a candidate whose assignment is not installed yet is refused until it is
	candidate := peerIDOf(t)
	require.False(t, allowed(candidate), "a candidate that is not installed is refused")
	members[candidate] = true
	require.True(t, allowed(candidate), "and served once the installed configuration names it")

	// a validator of the candidate staged on this root is served before its assignment is installed, and not once the stage is gone
	staged := peerIDOf(t)
	require.False(t, allowed(staged))
	fakeStaged[staged] = true
	require.True(t, allowed(staged), "a staged successor's validator")
	delete(fakeStaged, staged)
	require.False(t, allowed(staged))

	// the membership follows the installed configuration: a validator it stops naming is no longer served
	members[joiner] = false
	require.False(t, allowed(joiner))
}

type fakeFeedRoot struct {
	fakeMembers
	installedRoots peer.IDSlice
	stagedRoots    map[string]bool
}

func (f fakeFeedRoot) Validators() peer.IDSlice    { return f.installedRoots }
func (f fakeFeedRoot) IsStagedRoot(id string) bool { return f.stagedRoots[id] }

// The production authorization serves the installed trust base's roots and the staged successor committee's roots (a joiner root that is
// not installed yet), and nobody else; the server is built from it.
func TestTheRecordsServerAllowsInstalledAndStagedRootsOnly(t *testing.T) {
	installed, joinerRoot, stranger := peerIDOf(t), peerIDOf(t), peerIDOf(t)
	cm := fakeFeedRoot{fakeMembers: fakeMembers{}, installedRoots: peer.IDSlice{installed}, stagedRoots: map[string]bool{}}
	allowed := recordsServerAllowed(nil, nil, cm)
	require.True(t, allowed(installed), "a root of the installed trust base")
	require.False(t, allowed(joinerRoot), "a joiner root is not served before its successor committee is staged")
	cm.stagedRoots[joinerRoot.String()] = true
	require.True(t, allowed(joinerRoot), "a root of the staged successor committee")
	require.False(t, allowed(stranger))
	delete(cm.stagedRoots, joinerRoot.String())
	require.False(t, allowed(joinerRoot), "and not once the stage is gone")
}

// Production builds the records server from recordsServerAllowed over the consensus manager: a server built from anything narrower would
// refuse the joiner root again.
func TestServeRootRecordsAuthorizesThroughRecordsServerAllowed(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "root_node.go", nil, 0)
	require.NoError(t, err)
	var wired bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serveRootRecords" {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewServer" && len(call.Args) == 2 {
				inner, ok := call.Args[1].(*ast.CallExpr)
				if id, isID := inner.Fun.(*ast.Ident); ok && isID && id.Name == "recordsServerAllowed" && len(inner.Args) == 3 {
					cmArg, isCM := inner.Args[2].(*ast.Ident)
					wired = isCM && cmArg.Name == "cm"
				}
			}
			return true
		})
		return false
	})
	require.True(t, wired, "serveRootRecords builds the records server from recordsServerAllowed(allowed, shardConfs, cm)")
}
