package frontierrequester_test

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
)

// This replaces the former inert pin (#350): the automatic root-quorum freshness requester is active in
// default startup. The assertions are structural, and each has a behavioral twin that runs the same
// wiring end to end (configuredadmission freshness tests; rootchain/consensus TestFreshnessActivation*).

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	return root
}

func productionImporters(t *testing.T, root, importPath string) []string {
	t.Helper()
	var importers []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "build" || d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == "test-nodes") {
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
	return importers
}

func parseFile(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	return f
}

// selectorCalls lists the "pkg.Name" selectors a file references.
func selectors(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				out[id.Name+"."+sel.Sel.Name] = true
			}
		}
		return true
	})
	return out
}

func TestFreshnessRequesterIsActivatedByProductionStartup(t *testing.T) {
	root := repoRoot(t)

	const requester = "github.com/unicitynetwork/bft-core/rootchain/consensus/frontierrequester"
	require.Equal(t, []string{filepath.Join("configuredadmission", "freshness.go")}, productionImporters(t, root, requester),
		"the requester is constructed by configuredadmission's freshness and nowhere else")

	// The shard node's default startup builds the freshness and hands it both to the journal admission
	// factory (which starts the requester) and to the execution-recovery readiness gate (which consults it).
	shard := parseFile(t, filepath.Join(root, "cli", "ubft", "cmd", "shard_node_run.go"))
	fields := map[string]map[string]bool{}
	ast.Inspect(shard, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					if fields[sel.Sel.Name] == nil {
						fields[sel.Sel.Name] = map[string]bool{}
					}
					fields[sel.Sel.Name][key.Name] = true
				}
			}
		}
		return true
	})
	require.True(t, fields["Freshness"]["Opener"] && fields["Freshness"]["TrustBase"], "shard-node run builds configuredadmission.Freshness")
	require.True(t, fields["JournalFactory"]["Freshness"], "the journal admission factory starts the requester")
	require.True(t, fields["ExecutionRecovery"]["Freshness"], "execution-recovery readiness consults the receipt")

	// The root's default startup enables the sampler and signing and registers both protocols.
	rootSel := selectors(parseFile(t, filepath.Join(root, "cli", "ubft", "cmd", "root_node.go")))
	for _, want := range []string{
		"consensus.WithFrontierSampler", "consensus.WithFrontierSigning", "consensus.ValidateFrontierProfile",
		"frontiertransport.FrontierProtocolID", "frontiertransport.CutProtocolID", "frontiertransport.NewServer",
	} {
		require.True(t, rootSel[want], "root-node run must reference %s", want)
	}
}
