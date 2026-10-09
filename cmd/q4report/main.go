// Command q4report generates the Q4 #51 acceptance report: it maps every mandatory row of the acceptance matrix
// (docs/pos/q4-acceptance-matrix.json) to the evidence that passed or to an explicit gap.
//
//	q4report -matrix docs/pos/q4-acceptance-matrix.json -tests run.json[,run2.json] [-bundles dir] [-cost cost.json] [-src .] [-out report.md] [-json report.json] [-require-complete]
//	q4report ... -lane <live lane evidence dir>   # kind lane / lane-file items read the Q4 live lane's own lane.log and files
//	q4report -static -matrix docs/pos/q4-acceptance-matrix.json -src .      # CI: the matrix itself is consistent; nothing is claimed as run
//
// Evidence is never assumed. A go-test item counts only if the `go test -json` results name that test with action pass; a test that
// is absent from the results is NOT-RUN, a failed one FAILED, and a selector whose test function no longer exists in the source tree
// is stale. A bundle item re-runs the independent replay checker over the exported run bundles. A row can claim a coverage label only
// through evidence carrying it; a required label with neither evidence nor an explicit gap is a hole in the matrix and fails the run.
// Exit status: 0 the report is complete and consistent (gaps are reported, not hidden), 1 a failed, missing, stale or unaccounted row,
// 2 a usage or read error, 3 with -require-complete when any gap remains (the #51 closure check).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4replay"
)

// Matrix is the acceptance matrix: the mandatory rows of the Q4 design with the evidence that closes them.
type Matrix struct {
	Version int    `json:"version"`
	Issue   string `json:"issue"`
	Design  string `json:"design"`
	Rows    []Row  `json:"rows"`
}

// Row is one mandatory matrix row. Required lists the coverage labels the design demands for it (IN-PROCESS, REAL-PROCESS,
// MEASURED, STATIC...); each needs evidence or an explicit gap.
type Row struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Design   string     `json:"design"`
	Class    string     `json:"class,omitempty"` // IN-BOUND, OUTSIDE-ASSUMPTIONS or empty
	Required []string   `json:"required"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Gaps     []Gap      `json:"gaps,omitempty"`
}

// Evidence is one item. Kind go-test: Package and Test name a result of `go test -json` (Test empty = the package passed). Kind
// bundle: the replay bundles whose file name starts with BundlePrefix (at least MinBundles of them) must exist and check clean.
// Kind cost: the query-cost measurements file must show every supported row within budget. Kind lane: the live lane's evidence directory
// (-lane) must show the named step (Step, as printed by the lane: q3_* or the Q4 step title) with its PASS line, from a run whose recorded
// mode is a clean-build evidence run (a development override is never evidence). Kind lane-file: Path, relative to that directory, exists
// and is not empty.
type Evidence struct {
	Kind         string `json:"kind"`
	Label        string `json:"label"`
	Package      string `json:"package,omitempty"`
	Test         string `json:"test,omitempty"`
	BundlePrefix string `json:"bundlePrefix,omitempty"`
	MinBundles   int    `json:"minBundles,omitempty"`
	Step         string `json:"step,omitempty"` // kind lane: the lane step name
	Path         string `json:"path,omitempty"` // kind lane-file: a file of the lane's evidence directory
	// Contains, for a lane-file, are lines the file must contain (e.g. the gate's command and exit status).
	Contains []string `json:"contains,omitempty"`
	Scope    string   `json:"scope,omitempty"` // what the item covers and omits, in words
}

// Gap is an explicit, reasoned absence of evidence for one required label.
type Gap struct {
	Label     string `json:"label"`
	Reason    string `json:"reason"`
	BlockedBy string `json:"blockedBy,omitempty"`
}

// Result of one evidence item.
type Result struct {
	Evidence
	Status string `json:"status"` // PASS FAIL NOT-RUN STALE
	Detail string `json:"detail,omitempty"`
}

// RowReport is one row's verdict.
type RowReport struct {
	Row
	Verdict string   `json:"verdict"` // COMPLETE PARTIAL GAP FAILED NOT-RUN
	Results []Result `json:"results,omitempty"`
	Holes   []string `json:"holes,omitempty"` // required labels with neither evidence nor gap
}

// Report is the whole report.
type Report struct {
	Issue    string         `json:"issue"`
	Rows     []RowReport    `json:"rows"`
	Counts   map[string]int `json:"counts"`
	Bundles  BundleStats    `json:"bundles"`
	Cost     *CostStats     `json:"cost,omitempty"`
	Lane     *LaneStats     `json:"lane,omitempty"`
	Closable bool           `json:"closable"`
	Static   bool           `json:"static,omitempty"`
	Problems []string       `json:"problems,omitempty"`
}

// BundleStats summarises every replay bundle that was re-checked.
type BundleStats struct {
	Checked  int      `json:"checked"`
	Clean    int      `json:"clean"`
	Attempts int      `json:"attempts"`
	Signed   int      `json:"signedVerified"`
	Injected int      `json:"injectedMalformedFlagged"`
	Failed   []string `json:"failed,omitempty"`
}

// LaneStats is the live lane run the report read.
type LaneStats struct {
	Dir      string `json:"dir"`
	Mode     string `json:"mode"`
	Evidence bool   `json:"evidence"` // a clean-build evidence run
	// Attested is true when the run's execution client was a prebuilt binary the operator attested to have built from a fresh private target at the pinned commit
	// (Q4_URETH_FRESH_BUILD=1) rather than one the lane built itself: still an evidence run, but on the operator's word for that one artifact.
	Attested bool `json:"attested,omitempty"`
}

// CostStats reads the query-cost gate measurements.
type CostStats struct {
	Profile   string            `json:"profile"`
	Host      string            `json:"host"`
	Supported int               `json:"supportedRows"`
	Within    int               `json:"supportedWithin"`
	Outside   []json.RawMessage `json:"outsideEnvelope,omitempty"`
}

type costRow struct {
	Kind      string  `json:"kind"`
	Members   int     `json:"members"`
	Distance  uint64  `json:"distance"`
	Ms        float64 `json:"ms"`
	BudgetMs  float64 `json:"budgetMs"`
	MaxWaitMs float64 `json:"maxWaitMs"`
	Supported bool    `json:"supported"`
	Within    bool    `json:"within"`
}

type costFile struct {
	Profile string    `json:"profile"`
	Host    string    `json:"host"`
	Rows    []costRow `json:"rows"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("q4report", flag.ContinueOnError)
	fs.SetOutput(errOut)
	matrix := fs.String("matrix", "docs/pos/q4-acceptance-matrix.json", "acceptance matrix")
	tests := fs.String("tests", "", "comma separated `go test -json` result files")
	bundles := fs.String("bundles", "", "directory of exported replay bundles")
	cost := fs.String("cost", "", "query-cost measurements (Q4_COST_OUT of TestQ4QueryCostGate)")
	lane := fs.String("lane", "", "evidence directory of a Q4 live lane run (lane.log, run-mode.txt, pins.txt, q3/, q4/)")
	src := fs.String("src", ".", "source tree root, to detect stale selectors")
	md := fs.String("out", "", "write the markdown report here (default stdout)")
	js := fs.String("json", "", "write the JSON report here")
	complete := fs.Bool("require-complete", false, "exit 3 unless every row is COMPLETE")
	static := fs.Bool("static", false, "check only the matrix (holes, stale selectors, unknown fields): evidence that was not run is not a problem and no closure is claimed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rep, err := Build(*matrix, splitList(*tests), *bundles, *cost, *src, *static, *lane)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	text := Markdown(rep)
	if *md != "" {
		if err := os.WriteFile(*md, []byte(text), 0o644); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	} else {
		fmt.Fprint(out, text)
	}
	if *js != "" {
		raw, _ := json.MarshalIndent(rep, "", " ")
		if err := os.WriteFile(*js, append(raw, '\n'), 0o644); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	switch {
	case len(rep.Problems) > 0:
		return 1
	case *complete && !rep.Closable:
		return 3
	}
	return 0
}

func splitList(s string) (out []string) {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// goResults reads `go test -json` streams: package|test -> pass, fail or skip (the last terminal action wins).
func goResults(files []string) (map[string]string, error) {
	res := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			var ev struct{ Action, Package, Test string }
			if json.Unmarshal([]byte(line), &ev) != nil {
				continue
			}
			switch ev.Action {
			case "pass", "fail", "skip":
				res[ev.Package+"|"+ev.Test] = ev.Action
			}
		}
	}
	return res, nil
}

var testFunc = regexp.MustCompile(`(?m)^func (Test\w+)\(`)

// declared lists the top-level test functions of every package directory under root, keyed by import-path suffix.
func declared(root string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dir, _ := filepath.Rel(root, filepath.Dir(path))
		dir = filepath.ToSlash(dir)
		if out[dir] == nil {
			out[dir] = map[string]bool{}
		}
		for _, m := range testFunc.FindAllStringSubmatch(string(raw), -1) {
			out[dir][m[1]] = true
		}
		return nil
	})
	return out, err
}

var sanitize = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Build evaluates the matrix against the inputs.
func Build(matrixPath string, testFiles []string, bundleDir, costPath, srcRoot string, static bool, laneDir string) (*Report, error) {
	raw, err := os.ReadFile(matrixPath)
	if err != nil {
		return nil, err
	}
	var m Matrix
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", matrixPath, err)
	}
	results, err := goResults(testFiles)
	if err != nil {
		return nil, err
	}
	decl, err := declared(srcRoot)
	if err != nil {
		return nil, err
	}
	rep := &Report{Issue: m.Issue, Counts: map[string]int{}}

	// bundles: every file is re-checked once
	bundleOK := map[string]bool{}
	if bundleDir != "" {
		ents, err := os.ReadDir(bundleDir)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			b, err := q4replay.Load(filepath.Join(bundleDir, e.Name()))
			if err != nil {
				return nil, err
			}
			r := q4replay.Check(b)
			rep.Bundles.Checked++
			rep.Bundles.Attempts += r.Attempts
			rep.Bundles.Signed += r.Signed
			rep.Bundles.Injected += len(r.Malformed)
			if r.Err() == nil {
				rep.Bundles.Clean++
				bundleOK[e.Name()] = true
			} else {
				rep.Bundles.Failed = append(rep.Bundles.Failed, e.Name())
				rep.Problems = append(rep.Problems, fmt.Sprintf("bundle %s: %v", e.Name(), r.Err()))
			}
		}
	}
	var costData *costFile
	if costPath != "" {
		raw, err := os.ReadFile(costPath)
		if err != nil {
			return nil, err
		}
		costData = new(costFile)
		if err := json.Unmarshal(raw, costData); err != nil {
			return nil, fmt.Errorf("%s: %w", costPath, err)
		}
		rep.Cost = &CostStats{Profile: costData.Profile, Host: costData.Host}
		for _, r := range costData.Rows {
			if r.Supported {
				rep.Cost.Supported++
				if r.Within {
					rep.Cost.Within++
				}
			} else if b, err := json.Marshal(r); err == nil {
				rep.Cost.Outside = append(rep.Cost.Outside, b)
			}
		}
	}

	var laneLog, laneMode string
	if laneDir != "" {
		raw, err := os.ReadFile(filepath.Join(laneDir, "lane.log"))
		if err != nil {
			return nil, err
		}
		laneLog = string(raw)
		if raw, err := os.ReadFile(filepath.Join(laneDir, "run-mode.txt")); err == nil {
			laneMode = strings.TrimSpace(string(raw))
		}
		rep.Lane = &LaneStats{Dir: laneDir, Mode: laneMode, Evidence: strings.HasPrefix(strings.TrimPrefix(laneMode, "Q4 run mode: "), "clean build (evidence run"), Attested: strings.Contains(laneMode, "built by the operator")}
	}
	seen := map[string]bool{}
	for _, row := range m.Rows {
		if seen[row.ID] {
			return nil, fmt.Errorf("matrix: duplicate row id %s", row.ID)
		}
		seen[row.ID] = true
		rr := RowReport{Row: row}
		byLabel := map[string][]Result{}
		for _, ev := range row.Evidence {
			r := Result{Evidence: ev}
			switch ev.Kind {
			case "go-test":
				top := strings.SplitN(ev.Test, "/", 2)[0]
				pkgDir := strings.TrimPrefix(ev.Package, "./")
				if top != "" && !decl[pkgDir][top] {
					r.Status, r.Detail = "STALE", fmt.Sprintf("no %s in %s", top, ev.Package)
					break
				}
				got, ok := results[moduleKey(ev.Package)+"|"+ev.Test]
				switch {
				case !ok:
					r.Status = "NOT-RUN"
				case got == "pass":
					r.Status = "PASS"
				default:
					r.Status, r.Detail = "FAIL", got
				}
			case "bundle":
				n, bad := 0, 0
				for name := range bundleOK {
					if strings.HasPrefix(name, ev.BundlePrefix) {
						n++
					}
				}
				for _, f := range rep.Bundles.Failed {
					if strings.HasPrefix(f, ev.BundlePrefix) {
						bad++
					}
				}
				switch {
				case bad > 0:
					r.Status, r.Detail = "FAIL", fmt.Sprintf("%d bundles fail the replay checker", bad)
				case n < max(ev.MinBundles, 1):
					r.Status, r.Detail = "NOT-RUN", fmt.Sprintf("%d bundles under %q, need %d", n, ev.BundlePrefix, max(ev.MinBundles, 1))
				default:
					r.Status, r.Detail = "PASS", fmt.Sprintf("%d bundles re-checked clean", n)
				}
			case "cost":
				switch {
				case costData == nil:
					r.Status = "NOT-RUN"
				case rep.Cost.Supported == 0:
					r.Status, r.Detail = "NOT-RUN", "no supported rows"
				case rep.Cost.Within != rep.Cost.Supported:
					r.Status, r.Detail = "FAIL", fmt.Sprintf("%d of %d supported rows within budget", rep.Cost.Within, rep.Cost.Supported)
				default:
					r.Status, r.Detail = "PASS", fmt.Sprintf("%d supported rows within budget (%s)", rep.Cost.Supported, costData.Profile)
				}
			case "lane", "lane-file":
				switch {
				case ev.Kind == "lane" && !laneStepDeclared(srcRoot, ev.Step):
					r.Status, r.Detail = "STALE", "the lane scripts declare no step "+ev.Step
				case laneDir == "":
					r.Status = "NOT-RUN"
				case !rep.Lane.Evidence:
					r.Status, r.Detail = "FAIL", "the lane ran as: "+laneMode+" (a development override is not evidence)"
				case ev.Kind == "lane-file":
					path := filepath.Join(laneDir, filepath.FromSlash(ev.Path))
					raw, err := os.ReadFile(path)
					switch {
					case err != nil || len(raw) == 0:
						r.Status, r.Detail = "NOT-RUN", ev.Path+" is missing or empty"
					default:
						r.Status = "PASS"
						for _, want := range ev.Contains {
							if !strings.Contains(string(raw), want) {
								r.Status, r.Detail = "FAIL", ev.Path+" does not contain "+want
							}
						}
					}
				case regexp.MustCompile(`(?m)^\s*PASS: ` + regexp.QuoteMeta(ev.Step) + `\s*$`).MatchString(laneLog):
					r.Status = "PASS"
				case regexp.MustCompile(`(?m)^\s*FAIL: ` + regexp.QuoteMeta(ev.Step) + `\b`).MatchString(laneLog):
					r.Status = "FAIL"
				default:
					r.Status, r.Detail = "NOT-RUN", "the lane log has no PASS line for the step"
				}
			default:
				r.Status, r.Detail = "STALE", "unknown evidence kind "+ev.Kind
			}
			rr.Results = append(rr.Results, r)
			byLabel[ev.Label] = append(byLabel[ev.Label], r)
		}
		gapFor := map[string]bool{}
		for _, g := range row.Gaps {
			gapFor[g.Label] = true
		}
		evidenced, gaps, failed, notRun := 0, 0, false, false
		for _, label := range row.Required {
			rs := byLabel[label]
			ok := len(rs) > 0
			for _, r := range rs {
				switch r.Status {
				case "FAIL", "STALE":
					failed, ok = true, false
				case "NOT-RUN":
					if !static {
						notRun, ok = true, false
					}
				}
			}
			switch {
			case ok:
				evidenced++
			case len(rs) == 0 && gapFor[label]:
				gaps++
			case len(rs) == 0:
				rr.Holes = append(rr.Holes, label)
			}
		}
		switch {
		case len(rr.Holes) > 0:
			rr.Verdict = "FAILED"
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: required label(s) %v have neither evidence nor an explicit gap", row.ID, rr.Holes))
		case failed:
			rr.Verdict = "FAILED"
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: evidence failed or is stale", row.ID))
		case notRun:
			rr.Verdict = "NOT-RUN"
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: evidence was not run", row.ID))
		case gaps == 0:
			rr.Verdict = "COMPLETE"
		case evidenced == 0:
			rr.Verdict = "GAP"
		default:
			rr.Verdict = "PARTIAL"
		}
		rep.Counts[rr.Verdict]++
		rep.Rows = append(rep.Rows, rr)
	}
	rep.Static = static
	rep.Closable = !static && len(rep.Problems) == 0 && rep.Counts["COMPLETE"] == len(rep.Rows)
	return rep, nil
}

// moduleKey is the import path `go test -json` reports for a package given as ./dir.
func moduleKey(pkg string) string {
	return "github.com/unicitynetwork/bft-core/" + strings.TrimPrefix(strings.TrimPrefix(pkg, "./"), "/")
}

// Markdown renders the report.
func Markdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Q4 acceptance report (%s)\n\n", r.Issue)
	verdict := "NOT SATISFIED"
	if r.Closable {
		verdict = "satisfied"
	}
	if r.Static {
		verdict = "not assessed (static matrix check: no evidence was run)"
	}
	fmt.Fprintf(&b, "**Closure of the weighted adversarial gate: %s.** %d rows: ", verdict, len(r.Rows))
	var parts []string
	for _, k := range []string{"COMPLETE", "PARTIAL", "GAP", "NOT-RUN", "FAILED"} {
		if r.Counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", r.Counts[k], k))
		}
	}
	b.WriteString(strings.Join(parts, ", ") + ".\n\n")
	if len(r.Problems) > 0 {
		b.WriteString("## Problems (the report is not trustworthy until these are fixed)\n\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "- %s\n", p)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Replay bundles re-checked offline by the independent checker: %d, clean %d, %d attempts, %d signatures verified, %d deliberately injected malformed sends flagged by their own reason.\n\n",
		r.Bundles.Checked, r.Bundles.Clean, r.Bundles.Attempts, r.Bundles.Signed, r.Bundles.Injected)
	if r.Lane != nil {
		attested := ""
		if r.Lane.Attested {
			attested = " The execution client binary is the operator's attestation of a fresh private build at the pinned commit."
		}
		fmt.Fprintf(&b, "Live lane evidence: `%s`, run mode: %s.%s\n\n", r.Lane.Dir, orDash(r.Lane.Mode), attested)
	}
	if r.Cost != nil {
		fmt.Fprintf(&b, "Query-cost gate (%s, %s): %d of %d supported rows within the frozen budgets.", r.Cost.Profile, r.Cost.Host, r.Cost.Within, r.Cost.Supported)
		for _, raw := range r.Cost.Outside {
			var c costRow
			_ = json.Unmarshal(raw, &c)
			fmt.Fprintf(&b, " Outside the frozen envelope, measured only: %s n=%d d=%d took %.0f ms (frozen budget %.0f ms).", c.Kind, c.Members, c.Distance, c.Ms, c.BudgetMs)
		}
		b.WriteString("\n\n")
	}
	b.WriteString("| Row | Class | Verdict | Evidenced | Explicit gaps |\n|---|---|---|---|---|\n")
	for _, row := range r.Rows {
		var ev, gp []string
		got := map[string]bool{}
		for _, res := range row.Results {
			if res.Status == "PASS" && !got[res.Label] {
				got[res.Label] = true
				ev = append(ev, res.Label)
			}
		}
		for _, g := range row.Gaps {
			gp = append(gp, g.Label)
		}
		sort.Strings(ev)
		fmt.Fprintf(&b, "| %s %s | %s | **%s** | %s | %s |\n", row.ID, row.Title, orDash(row.Class), row.Verdict, orDash(strings.Join(ev, ", ")), orDash(strings.Join(gp, ", ")))
	}
	b.WriteString("\n## Rows\n")
	for _, row := range r.Rows {
		fmt.Fprintf(&b, "\n### %s %s: %s\n\n%s\n\n", row.ID, row.Title, row.Verdict, row.Design)
		for _, res := range row.Results {
			what := res.Test
			switch res.Kind {
			case "bundle":
				what = "bundles " + res.BundlePrefix + "*"
			case "cost":
				what = "query-cost measurements"
			case "lane":
				what = "live lane step " + res.Step
			case "lane-file":
				what = "live lane file " + res.Path
			}
			if res.Package != "" {
				what = res.Package + " " + what
			}
			fmt.Fprintf(&b, "- %s `%s` [%s] %s%s\n", res.Status, what, res.Label, res.Scope, detail(res.Detail))
		}
		for _, g := range row.Gaps {
			blocked := ""
			if g.BlockedBy != "" {
				blocked = " (blocked by " + g.BlockedBy + ")"
			}
			fmt.Fprintf(&b, "- **GAP [%s]** %s%s\n", g.Label, g.Reason, blocked)
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func detail(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// laneStepDeclared: the step name is one the lane scripts declare as a step (a Q3 step function definition or a Q4 step title in a q4_step call), so a
// renamed step makes its evidence stale instead of silently missing; a surviving mention in a comment does not count.
func laneStepDeclared(srcRoot, step string) bool {
	q4 := regexp.MustCompile(`(?m)^\s*q4_step "` + regexp.QuoteMeta(step) + `"`)
	q3 := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(step) + `\(\) \{`)
	for _, f := range []string{"scripts/q4-live-steps.sh", "scripts/q3-weight-activation-steps.sh"} {
		raw, err := os.ReadFile(filepath.Join(srcRoot, f))
		if err == nil && (q4.Match(raw) || q3.Match(raw)) {
			return true
		}
	}
	return false
}
