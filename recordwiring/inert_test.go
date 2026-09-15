package recordwiring_test

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

const importPath = "github.com/unicitynetwork/bft-core/recordwiring"

// TestOnlyTheShardNodeCommandImportsTheWiring is the reach guard: the only production importer is the
// shard-node command, which constructs the wiring only when a record store is configured. The round, the
// client, recovery and the executor adapters do not import it.
func TestOnlyTheShardNodeCommandImportsTheWiring(t *testing.T) {
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
		if strings.HasPrefix(rel, "recordwiring"+string(filepath.Separator)) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		scanned[filepath.ToSlash(rel)] = true
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
				importers = append(importers, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	require.NoError(t, err)

	for _, want := range []string{"shardnode/node.go", "shardnode/round.go", "cli/ubft/cmd/shard_node_run.go", "engineapi/adapter.go"} {
		require.True(t, scanned[want], "expected to scan %s", want)
	}
	for _, imp := range importers {
		require.True(t, strings.HasPrefix(imp, "cli/ubft/cmd/"), "only the shard-node command may import %s, found %s", importPath, imp)
	}
}
