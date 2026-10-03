package quorumweight

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// go-base's NewTrustBase must not be called directly either (see the case below).
// go-base's UnicityCertificate.Verify and UnicitySeal.Verify decide the root quorum through the unchecked
// RootTrustBase.VerifyQuorumSignatures (silent skip of unknown signers, wrapping stake sum). Every production call must
// therefore pass the trust base through Checked, and nothing may call the unchecked verifiers directly.
func TestEveryProductionUCVerifyRoutesThroughChecked(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	verifyCalls := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "vendor" || n == "quorumweight" || n == "testutils" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, perr, path)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pos := fset.Position(call.Pos())
			switch {
			case sel.Sel.Name == "VerifyQuorumSignatures":
				t.Errorf("%s: direct call of the unchecked VerifyQuorumSignatures", pos)
			case sel.Sel.Name == "NewTrustBase" && isPackage(sel.X, "types", "basetypes"):
				t.Errorf("%s: direct call of go-base NewTrustBase sums stake unchecked; use quorumweight.NewTrustBase", pos)
			case sel.Sel.Name == "VerifySignatures":
				t.Errorf("%s: direct call of go-base VerifySignatures; use quorumweight.VerifyTrustBase", pos)
			case sel.Sel.Name == "Verify" && len(call.Args) == 5 && !isPackage(sel.X, "handoffdelivery"):
				// (handoffdelivery.Verify is a bundle verifier that checks the old commit proof, not a UC.)
				// UnicityCertificate.Verify(tb, algorithm, partition, shard, shardConfHash)
				verifyCalls++
				inner, ok := call.Args[0].(*ast.CallExpr)
				isolated := false
				if ok {
					if s, ok := inner.Fun.(*ast.SelectorExpr); ok {
						if id, ok := s.X.(*ast.Ident); ok {
							isolated = id.Name == "quorumweight" && s.Sel.Name == "Checked"
						}
					}
				}
				if !isolated {
					t.Errorf("%s: UC Verify must take quorumweight.Checked(trustBase)", pos)
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, verifyCalls, 14, "the walk must see the known UC verification sites")
}

func isPackage(x ast.Expr, names ...string) bool {
	id, ok := x.(*ast.Ident)
	if !ok {
		return false
	}
	for _, n := range names {
		if id.Name == n {
			return true
		}
	}
	return false
}
