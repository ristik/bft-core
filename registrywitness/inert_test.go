package registrywitness_test

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

const importPath = "github.com/unicitynetwork/bft-core/registrywitness"

// TestOnlyLocalAdapterSourceImportsTheWitnessStore keeps the production boundary narrow:
// only the adapter's local proof source (and the B1 pair's admission proof fetcher, which shares its JSON-RPC caller) may activate this RPC witness acquisition path.
func TestOnlyLocalAdapterSourceImportsTheWitnessStore(t *testing.T) {
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
		// recordwiring is reached only through the shard-node command's opt-in record store, which its own
		// guard enforces.
		if strings.HasPrefix(rel, "registrywitness"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "recordwiring"+string(filepath.Separator)) ||
			rel == filepath.Join("parentwitness", "requester.go") {
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

	for _, want := range []string{"rootinput/rootinput.go", "shardnode/round.go", "cli/ubft/cmd/shard_node_run.go", "engineapi/adapter.go"} {
		require.True(t, scanned[want], "expected to scan %s", want)
	}
	require.Equal(t, []string{filepath.Join("cli", "ubft", "cmd", "b1_activation.go"), filepath.Join("engineapi", "parent_witness_source.go")}, importers,
		"only the local adapter source and the B1 activation file (the pair's Update-admission proof fetcher uses the same RPC caller) may import %s", importPath)
}
