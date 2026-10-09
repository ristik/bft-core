package consensus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// stubHistory is a request history that is only ever compared, never consulted.
type stubHistory struct{ storage.RequestHistory }

func (stubHistory) Network() uint64 { return 3 }

// The verifier a recovery builds executes the recovery blocks, so it must already carry the request history of the verifier it replaces: a weighted EVM assignment
// has no unit request context on its ShardInfo (resetTrustBase leaves it nil, MemberCount is 0), and under the legacy dispatch every change request of that shard is
// refused ("IR Change Request contains more requests than registered partition nodes"): a root that lagged a weighted epoch behind could never catch up.
func TestRecoveryVerifierCarriesTheRequestHistoryBeforeAnyBlockIsExecuted(t *testing.T) {
	params := NewConsensusParams()
	var store *storage.BlockStore // only used as the (non-nil interface) state monitor; never called
	replaced, err := NewIRChangeReqVerifier(params, store)
	require.NoError(t, err)
	replaced.SetRequestHistory(stubHistory{})

	v, err := newRecoveryVerifier(params, store, replaced)
	require.NoError(t, err)
	require.NotNil(t, v.RequestHistory(), "the replacement verifier selects the view-aware branch from its first block")
	require.Equal(t, replaced.RequestHistory(), v.RequestHistory())
	var _ storage.RequestViewVerifier = v

	t.Run("a deployment without a history keeps the legacy dispatch", func(t *testing.T) {
		legacy, err := NewIRChangeReqVerifier(params, store)
		require.NoError(t, err)
		v, err := newRecoveryVerifier(params, store, legacy)
		require.NoError(t, err)
		require.Nil(t, v.RequestHistory())
		v, err = newRecoveryVerifier(params, store, nil)
		require.NoError(t, err)
		require.Nil(t, v.RequestHistory())
	})
}

// The recovery's replacement verifier is built only through newRecoveryVerifier: a direct NewIRChangeReqVerifier in onStateResponse, or the history carried after the
// recovery blocks are added, brings the legacy dispatch back for exactly the blocks that matter.
func TestOnStateResponseBuildsItsVerifierOnlyThroughNewRecoveryVerifier(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "consensus_manager.go", nil, 0)
	require.NoError(t, err)
	var calls []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "onStateResponse" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				switch fun := c.Fun.(type) {
				case *ast.Ident:
					calls = append(calls, fun.Name)
				case *ast.SelectorExpr:
					calls = append(calls, fun.Sel.Name)
				}
			}
			return true
		})
	}
	require.NotEmpty(t, calls, "onStateResponse was not found")
	require.Contains(t, calls, "newRecoveryVerifier")
	require.NotContains(t, calls, "NewIRChangeReqVerifier")
	require.NotContains(t, calls, "carryRequestHistory", "the history is carried when the verifier is built, before the recovery blocks are added")
}
