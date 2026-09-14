package inputcarrier_test

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

const importPath = "github.com/unicitynetwork/bft-core/inputcarrier"

// TestNoProductionPackageImportsTheCarrier is the inertness guard: no non-test Go file outside this
// package imports it, so no production node sends, receives or verifies an envelope.
func TestNoProductionPackageImportsTheCarrier(t *testing.T) {
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
			// test-nodes and evidence directories hold node data (including sparse reth databases),
			// never Go sources.
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
		if strings.HasPrefix(rel, "inputcarrier"+string(filepath.Separator)) {
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

	// Non-vacuity: the production call sites this unit must not reach were actually scanned.
	for _, want := range []string{"shardnode/round.go", "shardnode/net_dissemination.go", "cli/ubft/cmd/shard_node_run.go", "engineapi/adapter.go"} {
		require.True(t, scanned[want], "expected to scan %s", want)
	}
	require.Empty(t, importers, "production packages must not import %s", importPath)
}
