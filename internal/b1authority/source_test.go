package b1authority

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3format"
)

func TestUnavailableCapabilityCannotGrantAuthority(t *testing.T) {
	for _, source := range []*Source{nil, {}, Bind(nil)} {
		_, err := source.B1History(0)
		require.ErrorIs(t, err, q3format.ErrHistory)
	}
}

func TestOnlyRuntimeCanBindAuthorityCapability(t *testing.T) {
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	var importers, binders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == "test-nodes" || d.Name() == "build") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		alias := ""
		for _, imp := range f.Imports {
			name, _ := strconv.Unquote(imp.Path.Value)
			if name == "github.com/unicitynetwork/bft-core/internal/b1authority" {
				alias = "b1authority"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
			}
		}
		if alias == "" {
			return nil
		}
		require.NotEqual(t, ".", alias, "authority constructor must remain visible to the importer audit")
		rel, _ := filepath.Rel(root, path)
		importers = append(importers, filepath.ToSlash(rel))
		ast.Inspect(f, func(n ast.Node) bool {
			selector, ok := n.(*ast.SelectorExpr)
			if ok {
				id, ok := selector.X.(*ast.Ident)
				if ok && id.Name == alias && selector.Sel.Name == "Bind" {
					binders = append(binders, filepath.ToSlash(rel))
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"q3active/b1.go", "rootinput/b1.go"}, importers)
	require.Equal(t, []string{"q3active/b1.go"}, binders)
}
