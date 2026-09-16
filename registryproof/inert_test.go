package registryproof_test

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

const importPath = "github.com/unicitynetwork/bft-core/registryproof"

// TestNoProductionPackageImportsTheReader is the inertness guard: no non-test Go file outside this package
// imports it, so no node reads the registry through it and the go-ethereum trie packages it links are not
// in any production binary yet.
func TestNoProductionPackageImportsTheReader(t *testing.T) {
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
		// registrygenesis, registrywitness and certifiedstore each have their own guard naming who may import
		// them. recordwiring is reached only through the shard-node command's opt-in record store, which its
		// own guard enforces, and internal/testutils/certifiedchain is test fixture code.
		if strings.HasPrefix(rel, "registryproof"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "registrygenesis"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "registrywitness"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "certifiedstore"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "recordwiring"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, filepath.Join("internal", "testutils", "certifiedchain")+string(filepath.Separator)) {
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
	require.Equal(t, []string{
		filepath.Join("configuredprogress", "codec.go"),
		filepath.Join("parentwitness", "verify.go"),
		filepath.Join("parentwitness", "wire.go"),
		filepath.Join("rootinput", "v2.go"),
	}, importers, "only reviewed inactive proof consumers may import %s", importPath)
}
