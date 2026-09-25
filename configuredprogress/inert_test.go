package configuredprogress_test

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

func TestOnlyJournalWiringImportsConfiguredProgress(t *testing.T) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	const importPath = "github.com/unicitynetwork/bft-core/configuredprogress"
	var importers []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "build" || d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == "test-nodes" || d.Name() == "evidence-runs") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, "configuredprogress"+string(filepath.Separator)) || rel == filepath.Join("configuredadmission", "adapter.go") || rel == filepath.Join("rootchain", "consensus", "frontierrequester", "requester.go") {
			return nil
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if e != nil {
			return e
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
				importers = append(importers, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join("archivewiring", "publisher.go"), filepath.Join("archivewiring", "record.go"), filepath.Join("cli", "ubft", "cmd", "shard_node_run.go"), filepath.Join("configuredadmission", "journal.go"), filepath.Join("configuredadmission", "journal_provider.go"), filepath.Join("configuredadmission", "recovery.go")}, importers,
		"configured progress is activated only through explicit journal wiring")
}
