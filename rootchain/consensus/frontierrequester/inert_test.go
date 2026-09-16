package frontierrequester_test

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

func TestNoProductionPackageImportsFrontierRequester(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	const importPath = "github.com/unicitynetwork/bft-core/rootchain/consensus/frontierrequester"
	var importers []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "build" || d.Name() == "vendor" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
				rel, _ := filepath.Rel(root, path)
				importers = append(importers, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, importers, "inactive frontier requester must have no production importer")
}
