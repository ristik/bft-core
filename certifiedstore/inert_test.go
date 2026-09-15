package certifiedstore_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const importPath = "github.com/unicitynetwork/bft-core/certifiedstore"

// TestNoProductionPackageImportsTheStore is the inertness guard: no non-test Go file outside this package
// imports it, so no node publishes or loads certified records through it yet.
func TestNoProductionPackageImportsTheStore(t *testing.T) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)

	scanned := map[string]bool{}
	var importers []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "test-nodes" || name == "build" ||
				name == "evidence-runs" || name == "node_modules" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, "certifiedstore"+string(filepath.Separator)) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		scanned[filepath.ToSlash(rel)] = true
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
				importers = append(importers, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)

	for _, want := range []string{"shardnode/node.go", "shardnode/store.go", "cli/ubft/cmd/shard_node_run.go", "engineapi/adapter.go"} {
		require.True(t, scanned[want], "expected to scan %s", want)
	}
	require.Empty(t, importers, "production packages must not import %s", importPath)
}
