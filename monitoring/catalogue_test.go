package monitoring

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// TestEventCatalogue guards the event names: the catalogue document lists exactly the names the code registers, every registered event is
// logged next to its pinned message in its source file, and no log line uses an event name that is not registered.
func TestEventCatalogue(t *testing.T) {
	doc := firstColumn(read(t, "docs/operations/monitoring/events.md"), regexp.MustCompile(`[a-z]+(\.[a-z_]+)+`))
	var code []string
	seen := map[string]bool{}
	for _, e := range Events {
		require.False(t, seen[e.Name], "event %s is registered twice", e.Name)
		seen[e.Name] = true
		code = append(code, e.Name)
	}
	code = append(code, ExternalEvents...)
	sort.Strings(code)
	require.Equal(t, code, doc, "docs/operations/monitoring/events.md and monitoring.Events differ: a name was renamed, removed or not documented")

	// every constant is registered
	consts := regexp.MustCompile(`(?m)^\s+(Ev[A-Za-z]+)\s+= "([a-z_.]+)"`)
	for _, m := range consts.FindAllStringSubmatch(read(t, "monitoring/events.go"), -1) {
		require.True(t, seen[m[2]], "%s = %q is not in monitoring.Events", m[1], m[2])
	}

	// the source: each event is logged beside its message
	constName := map[string]string{}
	for _, m := range consts.FindAllStringSubmatch(read(t, "monitoring/events.go"), -1) {
		constName[m[2]] = m[1]
	}
	for _, e := range Events {
		src := read(t, e.File)
		use := "monitoring.Event(monitoring." + constName[e.Name] + ")"
		if e.Via != "" {
			use = "monitoring.Event(monitoring." + e.Via
		}
		if e.File == "monitoring/disk.go" || e.File == "monitoring/peers.go" {
			use = "Event(" + constName[e.Name] + ")"
		}
		msg := strings.TrimRight(e.Msg, " ")
		i := strings.Index(src, `"`+msg)
		require.GreaterOrEqual(t, i, 0, "event %s: message %q is gone from %s (lane scripts grep it)", e.Name, e.Msg, e.File)
		end := min(len(src), i+700)
		require.Contains(t, src[i:end], use, "event %s: the log line %q lost its event attribute", e.Name, e.Msg)
	}

	// no unregistered use
	use := regexp.MustCompile(`monitoring\.Event\(monitoring\.(Ev[A-Za-z]+)\)`)
	for _, f := range sourceFiles(t) {
		b, err := os.ReadFile(f) // #nosec G304
		require.NoError(t, err)
		for _, m := range use.FindAllStringSubmatch(string(b), -1) {
			_, ok := map[string]bool{}[m[1]]
			_ = ok
			found := false
			for _, name := range constName {
				if name == m[1] {
					found = true
				}
			}
			require.True(t, found, "%s uses the unknown event %s", f, m[1])
		}
	}
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
