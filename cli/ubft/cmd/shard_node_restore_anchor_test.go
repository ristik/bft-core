package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/registrygenesis"
)

func TestRestoreAcceptsTheGenesisEpochTrustAnchor(t *testing.T) {
	full, path, _ := preparedGenesisFixtureAt(t, 1337, 3)
	origin, _, err := loadGenesisOrigin(full, path, "", 3)
	require.NoError(t, err)
	require.NoError(t, requireRestoreTrustAnchor(true, origin, 3))
}

func TestRestoreRefusesALaterTrustAnchorEpoch(t *testing.T) {
	full, path, _ := preparedGenesisFixture(t, 1337)
	// #347: the loader itself still accepts a later trust base.
	origin, _, err := loadGenesisOrigin(full, path, "", 3)
	require.NoError(t, err)
	for _, trustEpoch := range []uint64{2, 3, 7} {
		err := requireRestoreTrustAnchor(true, origin, trustEpoch)
		require.ErrorIs(t, err, ErrRestoreTrustAnchorEpoch, "trust base at epoch %d, genesis at 1", trustEpoch)
		require.ErrorContains(t, err, "generated at root epoch 1", "reports the genesis epoch")
		require.ErrorContains(t, err, fmt.Sprintf("is at root epoch %d", trustEpoch), "reports the trust base epoch")
		require.ErrorContains(t, err, "--trust-base", "tells the operator which input to correct")
	}
	// Any unequal epoch is refused (an earlier one is refused first by the loader in production).
	full5, path5, _ := preparedGenesisFixtureAt(t, 1337, 5)
	origin5, _, err := loadGenesisOrigin(full5, path5, "", 5)
	require.NoError(t, err)
	require.ErrorIs(t, requireRestoreTrustAnchor(true, origin5, 4), ErrRestoreTrustAnchorEpoch)
}

func TestNonRestoreRunsKeepTheLaterTrustBaseBehaviour(t *testing.T) {
	full, path, _ := preparedGenesisFixture(t, 1337)
	origin, _, err := loadGenesisOrigin(full, path, "", 3)
	require.NoError(t, err)
	require.NoError(t, requireRestoreTrustAnchor(false, origin, 3), "an ordinary run under a later trust base is unchanged (#347)")
	require.NoError(t, requireRestoreTrustAnchor(false, origin, 1))
	require.NoError(t, requireRestoreTrustAnchor(false, registrygenesis.GenesisOrigin{}, 3), "no checked origin: nothing to compare")
}

func TestRestoreAnchorRefusalWritesNothing(t *testing.T) {
	full, path, _ := preparedGenesisFixture(t, 1337)
	origin, _, err := loadGenesisOrigin(full, path, "", 3)
	require.NoError(t, err)
	dir := t.TempDir()
	require.ErrorIs(t, requireRestoreTrustAnchor(true, origin, 3), ErrRestoreTrustAnchorEpoch)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
	require.NoFileExists(t, filepath.Join(dir, "journal.db.trust"))
}

// The refusal must run right after the checked genesis load and before any executor construction or store write, for restore only.
// A helper test cannot see the call being moved or its restore argument dropped.
func TestShardNodeRunChecksTheRestoreAnchorBeforeAnyConstructionOrWrite(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shard_node_run.go", nil, 0)
	require.NoError(t, err)
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "shardNodeRun" {
			run = fn
		}
	}
	require.NotNil(t, run)
	first := map[string]token.Pos{}
	var guard *ast.CallExpr
	ast.Inspect(run.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			if id, ok := fun.X.(*ast.Ident); ok {
				name = id.Name + "." + fun.Sel.Name
			}
		}
		if _, seen := first[name]; !seen {
			first[name] = call.Pos()
		}
		if name == "requireRestoreTrustAnchor" {
			guard = call
		}
		return true
	})
	require.NotNil(t, guard, "shardNodeRun checks the restore trust anchor")
	sel, ok := guard.Args[0].(*ast.SelectorExpr)
	require.True(t, ok)
	require.Equal(t, "Restore", sel.Sel.Name, "the check is gated on the restore flag only")
	require.Less(t, first["loadGenesisOriginLayout"], first["requireRestoreTrustAnchor"], "after the checked genesis load")
	for _, later := range []string{"loadEngineEpochTransition", "buildExecutor", "boltdb.New", "shardnode.NewHistoricalTrustBaseStore", "buildDisseminator", "shardnode.NewActivePeers"} {
		require.Contains(t, first, later)
		require.Less(t, first["requireRestoreTrustAnchor"], first[later], "before %s", later)
	}
}
