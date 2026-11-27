package monitoring

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const repoRoot = ".."

// notMetrics are unicity_* string literals of the code that are not metric names (domain separators).
var notMetrics = map[string]bool{"unicity_tree_root": true}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel)) // #nosec G304 -- repository files
	require.NoError(t, err, rel)
	return string(b)
}

// firstColumn returns the backticked first cell of every table row of a markdown document that matches re.
func firstColumn(doc string, re *regexp.Regexp) []string {
	var out []string
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cell := strings.SplitN(strings.TrimPrefix(line, "| "), " |", 2)[0]
		for _, m := range re.FindAllString(cell, -1) {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// sourceFiles lists the repository's non-test Go files.
func sourceFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(repoRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	require.NoError(t, err)
	return files
}

// goldenEvents reads the published names and the key from testdata/events.golden: literals, independent of the constants in events.go.
func goldenEvents(t *testing.T) (key string, names []string) {
	t.Helper()
	b, err := os.ReadFile("testdata/events.golden")
	require.NoError(t, err)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "key "):
			key = strings.TrimPrefix(line, "key ")
		default:
			names = append(names, line)
		}
	}
	sort.Strings(names)
	return key, names
}

// TestEventCatalogue guards the event names as a compatibility promise: the published literals (testdata/events.golden) are exactly the registered
// names (plus VT-07's external ones), the log key is the published one, the catalogue document lists the same names, and every registered event is
// the LAST argument of every log call that carries its message (checked on the syntax tree, per call site, so one of two sites losing it fails).
func TestEventCatalogue(t *testing.T) {
	key, golden := goldenEvents(t)
	require.Equal(t, key, EventKey, "the log key is published as %q", key)
	var code []string
	seen := map[string]bool{}
	for _, e := range Events {
		require.False(t, seen[e.Name], "event %s is registered twice", e.Name)
		seen[e.Name] = true
		code = append(code, e.Name)
	}
	code = append(code, ExternalEvents...)
	sort.Strings(code)
	require.Equal(t, golden, code, "monitoring.Events differs from testdata/events.golden: a published name was renamed or removed, or a new one is not in the golden list")
	doc := firstColumn(read(t, "docs/operations/monitoring/events.md"), regexp.MustCompile(`[a-z]+(\.[a-z_]+)+`))
	require.Equal(t, golden, doc, "docs/operations/monitoring/events.md differs from the published names")

	consts := regexp.MustCompile(`(?m)^\s+(Ev[A-Za-z]+)\s+= "([a-z_.]+)"`)
	constName := map[string]string{}
	for _, m := range consts.FindAllStringSubmatch(read(t, "monitoring/events.go"), -1) {
		constName[m[2]] = m[1]
		require.True(t, seen[m[2]], "%s = %q is not in monitoring.Events", m[1], m[2])
	}

	// the call sites
	sites := map[string]int{}
	fset := token.NewFileSet()
	for _, f := range sourceFiles(t) {
		file, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, err, f)
		rel := filepath.ToSlash(strings.TrimPrefix(f, repoRoot+string(filepath.Separator)))
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			lit := ""
			for _, a := range call.Args {
				if l := leftmostString(a); l != "" {
					lit = l
					break
				}
			}
			for _, e := range Events {
				if e.File != rel || !msgMatches(lit, e.Msg) {
					continue
				}
				sites[e.Name]++
				require.Equal(t, e.File, rel)
				last := call.Args[len(call.Args)-1]
				want := constName[e.Name]
				if e.Via != "" {
					want = strings.TrimSuffix(e.Via, "(")
				}
				require.True(t, isEventArg(last, want), "%s: the call logging %q at %s must carry event %s as its last argument", rel, e.Msg, fset.Position(call.Pos()), e.Name)
			}
			return true
		})
	}
	// each registered event has a call site; the identity events share one
	for _, e := range Events {
		if e.Via == "" {
			require.NotZero(t, sites[e.Name], "event %s: no log call with message %q in %s (lane scripts grep the message)", e.Name, e.Msg, e.File)
		}
	}
	require.Equal(t, 2, sites[EvShardHandoffActive], "handoff activated is logged at two sites, both with the event")
	require.Equal(t, 2, sites[EvRootHandoffOutcome], "root handoff outcome is logged at two sites, both with the event")
}

func leftmostString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			if err == nil {
				return s
			}
		}
	case *ast.BinaryExpr:
		return leftmostString(v.X)
	}
	return ""
}

// msgMatches: the literal is the message; or the message continued by ":" or " (" (a long message whose head is the pinned one); or, for a
// pinned message that ends in a space (a computed message), any literal with that prefix.
func msgMatches(lit, msg string) bool {
	if lit == "" || msg == "" || !strings.HasPrefix(lit, msg) {
		return false
	}
	if strings.HasSuffix(msg, " ") || len(lit) == len(msg) {
		return true
	}
	rest := lit[len(msg):]
	return strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, " (")
}

// isEventArg: the argument is monitoring.Event(monitoring.<name>) (or Event(<name>) inside the package); for a computed event, Event(<fn>(...)).
func isEventArg(a ast.Expr, name string) bool {
	c, ok := a.(*ast.CallExpr)
	if !ok || len(c.Args) != 1 {
		return false
	}
	switch f := c.Fun.(type) {
	case *ast.SelectorExpr:
		if f.Sel.Name != "Event" {
			return false
		}
	case *ast.Ident:
		if f.Name != "Event" {
			return false
		}
	default:
		return false
	}
	switch v := c.Args[0].(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == name
	case *ast.Ident:
		return v.Name == name
	case *ast.CallExpr:
		switch f := v.Fun.(type) {
		case *ast.SelectorExpr:
			return f.Sel.Name == name
		case *ast.Ident:
			return f.Name == name
		}
	}
	return false
}

// TestMetricsCatalogue guards the metric names: every unicity_* name the code registers is in the catalogue document and every name in the
// document exists in the code, and every name the alert pack and the dashboard use is catalogued.
func TestMetricsCatalogue(t *testing.T) {
	name := regexp.MustCompile(`unicity_[a-z0-9_]+`)
	doc := firstColumn(read(t, "docs/operations/monitoring/metrics-catalogue.md"), name)
	inDoc := map[string]bool{}
	for _, n := range doc {
		inDoc[n] = true
	}
	inCode := map[string]bool{}
	lit := regexp.MustCompile(`"(unicity_[a-z0-9_]+)"`)
	for _, f := range sourceFiles(t) {
		b, err := os.ReadFile(f) // #nosec G304
		require.NoError(t, err)
		for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
			if notMetrics[m[1]] {
				continue
			}
			inCode[m[1]] = true
		}
	}
	for n := range inCode {
		require.True(t, inDoc[n], "%s is registered in the code but not in docs/operations/monitoring/metrics-catalogue.md", n)
	}
	for n := range inDoc {
		require.True(t, inCode[n], "%s is in the catalogue but not in the code", n)
	}
	for _, rel := range []string{"deploy/testnet/monitoring/validator-alerts.yml", "deploy/testnet/monitoring/grafana-validator.json"} {
		for _, n := range name.FindAllString(read(t, rel), -1) {
			if strings.HasPrefix(n, "unicity_alert") {
				continue
			}
			require.True(t, inDoc[n], "%s uses %s, which is not catalogued", rel, n)
		}
	}
}

// TestAlertRunbooks: every alert of the pack has a severity, a for-duration and a runbook section, and every runbook section has an alert.
func TestAlertRunbooks(t *testing.T) {
	rules := read(t, "deploy/testnet/monitoring/validator-alerts.yml")
	books := read(t, "docs/operations/monitoring/runbooks.md")
	alerts := regexp.MustCompile(`(?m)^\s+- alert: (\w+)$`).FindAllStringSubmatch(rules, -1)
	require.NotEmpty(t, alerts)
	require.Equal(t, len(alerts), strings.Count(rules, "        for: "), "every alert has a for-duration")
	require.Equal(t, len(alerts), strings.Count(rules, "          severity: "), "every alert has a severity")
	require.Equal(t, len(alerts), strings.Count(rules, "          runbook: "), "every alert has a runbook annotation")
	have := map[string]bool{}
	for _, m := range alerts {
		have[m[1]] = true
		require.Contains(t, books, "\n## "+m[1]+"\n", "alert %s has no runbook section", m[1])
		require.Contains(t, rules, "runbooks.md#"+strings.ToLower(m[1]))
	}
	for _, m := range regexp.MustCompile(`(?m)^## (Unicity\w+)$`).FindAllStringSubmatch(books, -1) {
		require.True(t, have[m[1]], "runbook section %s has no alert", m[1])
	}
}
