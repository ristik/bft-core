package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4replay"
)

const pkgPath = "github.com/unicitynetwork/bft-core/pkg"

type fixture struct {
	dir, src, bundles string
}

func newFixture(t *testing.T) *fixture {
	dir := t.TempDir()
	f := &fixture{dir: dir, src: filepath.Join(dir, "src"), bundles: filepath.Join(dir, "bundles")}
	require.NoError(t, os.MkdirAll(filepath.Join(f.src, "pkg"), 0o755))
	require.NoError(t, os.MkdirAll(f.bundles, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(f.src, "pkg", "x_test.go"), []byte("package pkg\n\nfunc TestA(t *testing.T) {}\nfunc TestB(t *testing.T) {}\nfunc TestC(t *testing.T) {}\n"), 0o644))
	return f
}

func (f *fixture) results(t *testing.T, lines ...[3]string) string {
	var b strings.Builder
	for _, l := range lines {
		raw, _ := json.Marshal(map[string]string{"Action": l[0], "Package": pkgPath, "Test": l[1]})
		b.Write(raw)
		b.WriteString("\n")
	}
	path := filepath.Join(f.dir, "r.json")
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o644))
	return path
}

func (f *fixture) matrix(t *testing.T, rows ...Row) string {
	raw, err := json.Marshal(Matrix{Version: 1, Issue: "test", Rows: rows})
	require.NoError(t, err)
	path := filepath.Join(f.dir, "m.json")
	require.NoError(t, os.WriteFile(path, raw, 0o644))
	return path
}

func test(name, label string) Evidence {
	return Evidence{Kind: "go-test", Label: label, Package: "./pkg", Test: name}
}

func TestReportMapsRowsToEvidenceOrExplicitGaps(t *testing.T) {
	f := newFixture(t)
	results := f.results(t, [3]string{"pass", "TestA", ""}, [3]string{"pass", "TestB/sub", ""}, [3]string{"fail", "TestC", ""})
	rows := []Row{
		{ID: "R1", Title: "complete", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{test("TestA", "IN-PROCESS")}},
		{ID: "R2", Title: "partial", Required: []string{"IN-PROCESS", "REAL-PROCESS"}, Evidence: []Evidence{test("TestA", "IN-PROCESS")},
			Gaps: []Gap{{Label: "REAL-PROCESS", Reason: "lane not run", BlockedBy: "#50"}}},
		{ID: "R3", Title: "gap", Required: []string{"REAL-PROCESS"}, Gaps: []Gap{{Label: "REAL-PROCESS", Reason: "lane not run"}}},
	}
	rep, err := Build(f.matrix(t, rows...), []string{results}, f.bundles, "", f.src, false, "")
	require.NoError(t, err)
	require.Empty(t, rep.Problems)
	require.Equal(t, map[string]int{"COMPLETE": 1, "PARTIAL": 1, "GAP": 1}, rep.Counts)
	require.False(t, rep.Closable, "a gap keeps the gate open")
	md := Markdown(rep)
	require.Contains(t, md, "NOT SATISFIED")
	require.Contains(t, md, "**GAP [REAL-PROCESS]** lane not run (blocked by #50)")

	only := []Row{rows[0]}
	rep, err = Build(f.matrix(t, only...), []string{results}, f.bundles, "", f.src, false, "")
	require.NoError(t, err)
	require.True(t, rep.Closable)
	require.Contains(t, Markdown(rep), "satisfied")
}

func TestReportRefusesEveryUnaccountedRow(t *testing.T) {
	f := newFixture(t)
	results := f.results(t, [3]string{"pass", "TestA", ""}, [3]string{"fail", "TestC", ""})
	cases := []struct {
		name string
		row  Row
		want string
	}{
		{"required label with neither evidence nor gap", Row{ID: "H", Required: []string{"IN-PROCESS", "REAL-PROCESS"}, Evidence: []Evidence{test("TestA", "IN-PROCESS")}}, "neither evidence nor an explicit gap"},
		{"failed test", Row{ID: "F", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{test("TestC", "IN-PROCESS")}}, "failed or is stale"},
		{"test absent from the results", Row{ID: "N", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{test("TestB", "IN-PROCESS")}}, "was not run"},
		{"selector that no longer exists", Row{ID: "S", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{test("TestGone", "IN-PROCESS")}}, "failed or is stale"},
		{"unknown evidence kind", Row{ID: "K", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{{Kind: "vibes", Label: "IN-PROCESS"}}}, "failed or is stale"},
		{"a gap does not hide failing evidence of the same label", Row{ID: "G", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{test("TestC", "IN-PROCESS")}, Gaps: []Gap{{Label: "IN-PROCESS", Reason: "x"}}}, "failed or is stale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Build(f.matrix(t, tc.row), []string{results}, f.bundles, "", f.src, false, "")
			require.NoError(t, err)
			require.Len(t, rep.Problems, 1)
			require.Contains(t, rep.Problems[0], tc.want)
			require.False(t, rep.Closable)
		})
	}
	_, err := Build(f.matrix(t, Row{ID: "D"}, Row{ID: "D"}), nil, "", "", f.src, false, "")
	require.ErrorContains(t, err, "duplicate row id")
	raw := `{"version":1,"rows":[{"id":"X","surprise":true}]}`
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "u.json"), []byte(raw), 0o644))
	_, err = Build(filepath.Join(f.dir, "u.json"), nil, "", "", f.src, false, "")
	require.Error(t, err, "an unknown matrix field is refused")
}

// cleanBundle is an empty run of one member that the replay checker accepts; bad adds a member with a zero weight, which it refuses.
func writeBundle(t *testing.T, dir, name string, bad bool) {
	ver, err := newKey()
	require.NoError(t, err)
	e := q4replay.Epoch{Epoch: 1, Scheme: 1, Total: 3, Quorum: 3, Faulty: 0, Members: []q4replay.Member{{Name: "a", ID: "a", PubKey: ver, Weight: 3}}}
	if bad {
		e.Members[0].Weight = 0
	}
	b := &q4replay.Bundle{Version: q4replay.Version, Scenario: name, Class: q4replay.InBound, Epochs: []q4replay.Epoch{e}}
	require.NoError(t, b.Save(filepath.Join(dir, name+".json")))
}

func TestReportRechecksBundlesOffline(t *testing.T) {
	f := newFixture(t)
	writeBundle(t, f.bundles, "TestRow_one", false)
	writeBundle(t, f.bundles, "TestRow_two", false)
	ev := func(prefix string, min int) Row {
		return Row{ID: "B", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{{Kind: "bundle", Label: "IN-PROCESS", BundlePrefix: prefix, MinBundles: min}}}
	}
	rep, err := Build(f.matrix(t, ev("TestRow", 2)), nil, f.bundles, "", f.src, false, "")
	require.NoError(t, err)
	require.Empty(t, rep.Problems)
	require.Equal(t, 2, rep.Bundles.Clean)
	rep, err = Build(f.matrix(t, ev("TestRow", 3)), nil, f.bundles, "", f.src, false, "")
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "evidence was not run", "fewer bundles than the matrix requires")
	writeBundle(t, f.bundles, "TestRow_three", true)
	rep, err = Build(f.matrix(t, ev("TestRow", 2)), nil, f.bundles, "", f.src, false, "")
	require.NoError(t, err)
	require.NotEmpty(t, rep.Bundles.Failed)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "TestRow_three.json")
	require.Equal(t, "FAILED", rep.Rows[0].Verdict)
}

func TestReportReadsTheQueryCostMeasurements(t *testing.T) {
	f := newFixture(t)
	write := func(rows ...costRow) string {
		raw, _ := json.Marshal(costFile{Profile: "ci", Host: "h", Rows: rows})
		path := filepath.Join(f.dir, "cost.json")
		require.NoError(t, os.WriteFile(path, raw, 0o644))
		return path
	}
	row := Row{ID: "Q", Required: []string{"MEASURED"}, Evidence: []Evidence{{Kind: "cost", Label: "MEASURED"}}}
	rep, err := Build(f.matrix(t, row), nil, "", write(costRow{Kind: "cold-restart", Supported: true, Within: true}, costRow{Kind: "cold-restart", Distance: 1_000_000, Ms: 4000, BudgetMs: 2000}), f.src, false, "")
	require.NoError(t, err)
	require.Empty(t, rep.Problems)
	require.Contains(t, Markdown(rep), "Outside the frozen envelope, measured only")
	rep, err = Build(f.matrix(t, row), nil, "", write(costRow{Kind: "cold-restart", Supported: true, Within: false}), f.src, false, "")
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "failed or is stale")
	rep, err = Build(f.matrix(t, row), nil, "", "", f.src, false, "")
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "was not run", "no measurements, no evidence")
}

func TestStaticModeChecksTheMatrixAndClaimsNothing(t *testing.T) {
	f := newFixture(t)
	rows := []Row{{ID: "R", Required: []string{"IN-PROCESS"}, Evidence: []Evidence{test("TestA", "IN-PROCESS")}}}
	rep, err := Build(f.matrix(t, rows...), nil, "", "", f.src, true, "")
	require.NoError(t, err)
	require.Empty(t, rep.Problems, "evidence that was not run is not a problem in the static check")
	require.False(t, rep.Closable, "and the static check never reports closure")
	require.Contains(t, Markdown(rep), "not assessed")
	rows[0].Evidence = []Evidence{test("TestGone", "IN-PROCESS")}
	rep, err = Build(f.matrix(t, rows...), nil, "", "", f.src, true, "")
	require.NoError(t, err)
	require.NotEmpty(t, rep.Problems, "a stale selector is still caught")
	rows[0] = Row{ID: "R", Required: []string{"IN-PROCESS", "REAL-PROCESS"}, Evidence: []Evidence{test("TestA", "IN-PROCESS")}}
	rep, err = Build(f.matrix(t, rows...), nil, "", "", f.src, true, "")
	require.NoError(t, err)
	require.NotEmpty(t, rep.Problems, "and so is a hole")
}

func TestExitStatuses(t *testing.T) {
	f := newFixture(t)
	results := f.results(t, [3]string{"pass", "TestA", ""})
	run1 := func(rows []Row, extra ...string) int {
		out, err := os.Create(filepath.Join(f.dir, "out.txt"))
		require.NoError(t, err)
		defer out.Close()
		args := append([]string{"-matrix", f.matrix(t, rows...), "-tests", results, "-src", f.src}, extra...)
		return run(args, out, out)
	}
	partial := []Row{{ID: "P", Required: []string{"IN-PROCESS", "REAL-PROCESS"}, Evidence: []Evidence{test("TestA", "IN-PROCESS")}, Gaps: []Gap{{Label: "REAL-PROCESS", Reason: "x"}}}}
	require.Equal(t, 0, run1(partial), "gaps are reported, not an error")
	require.Equal(t, 3, run1(partial, "-require-complete"), "the closure check fails while a gap remains")
	require.Equal(t, 1, run1([]Row{{ID: "H", Required: []string{"X"}}}), "a hole is an error")
	require.Equal(t, 2, run([]string{"-matrix", filepath.Join(f.dir, "missing.json")}, os.Stderr, os.Stderr))
}

// newKey is a valid compressed secp256k1 public key for the fixtures.
func newKey() ([]byte, error) {
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	if err != nil {
		return nil, err
	}
	v, err := s.Verifier()
	if err != nil {
		return nil, err
	}
	return v.MarshalPublicKey()
}

func writeLane(t *testing.T, dir, mode, log string) {
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lane.log"), []byte(log), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run-mode.txt"), []byte("Q4 run mode: "+mode+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pins.txt"), []byte("bft-core commit: x\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty.txt"), nil, 0o644))
}

func TestReportReadsTheLiveLaneEvidence(t *testing.T) {
	f := newFixture(t)
	lane := filepath.Join(f.dir, "lane")
	log := "--- Q3 step: q3_activation\n  PASS: q3_activation\n--- Q4 step: heavy root delayed\n  PASS: heavy root delayed\n--- Q4 step: failing row\n  FAIL: failing row\n"
	step := func(name string) Row {
		return Row{ID: "L", Required: []string{"REAL-PROCESS"}, Evidence: []Evidence{{Kind: "lane", Label: "REAL-PROCESS", Step: name}}}
	}
	file := func(path string) Row {
		return Row{ID: "F", Required: []string{"REAL-PROCESS"}, Evidence: []Evidence{{Kind: "lane-file", Label: "REAL-PROCESS", Path: path}}}
	}
	build := func(row Row) *Report {
		rep, err := Build(f.matrix(t, row), nil, "", "", f.src, false, lane)
		require.NoError(t, err)
		return rep
	}

	require.NoError(t, os.MkdirAll(filepath.Join(f.src, "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(f.src, "scripts", "q4-live-steps.sh"), []byte("  q4_step \"heavy root delayed\" x\n  q4_step \"failing row\" y\n  q4_step \"never ran\" z\n# q4_step \"only in a comment\" w\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(f.src, "scripts", "q3-weight-activation-steps.sh"), []byte("q3_activation() { :; }\n# q3_commented() { :; }\n"), 0o644))
	writeLane(t, lane, "clean build (evidence run)", log)
	require.Contains(t, strings.Join(build(step("a step nobody declares")).Problems, "\n"), "failed or is stale")
	require.Contains(t, strings.Join(build(step("only in a comment")).Problems, "\n"), "failed or is stale", "a mention in a comment does not declare a step")
	require.Empty(t, build(step("q3_activation")).Problems)
	require.Empty(t, build(step("heavy root delayed")).Problems)
	require.Empty(t, build(file("pins.txt")).Problems)
	require.Contains(t, strings.Join(build(step("failing row")).Problems, "\n"), "failed or is stale")
	require.Contains(t, strings.Join(build(step("never ran")).Problems, "\n"), "was not run", "no PASS line, no evidence")
	require.Contains(t, strings.Join(build(file("empty.txt")).Problems, "\n"), "was not run", "an empty file is no evidence")
	require.Contains(t, strings.Join(build(file("missing.txt")).Problems, "\n"), "was not run")

	// a lane-file can be required to contain lines: the gate must have been the default function and have exited 0
	require.NoError(t, os.WriteFile(filepath.Join(lane, "gate.txt"), []byte("# command: q4_weighted_epoch_check\n# exit: 0\nok\n"), 0o644))
	gate := func(contains ...string) Row {
		return Row{ID: "G", Required: []string{"REAL-PROCESS"}, Evidence: []Evidence{{Kind: "lane-file", Label: "REAL-PROCESS", Path: "gate.txt", Contains: contains}}}
	}
	require.Empty(t, build(gate("# command: q4_weighted_epoch_check", "# exit: 0")).Problems)
	require.Contains(t, strings.Join(build(gate("# command: true")).Problems, "\n"), "failed or is stale", "an overridden gate is not the evidence")

	// a development override is never evidence, whatever its log says
	writeLane(t, lane, "DEVELOPMENT OVERRIDE: prebuilt ureth /x: NOT EVIDENCE", log)
	rep := build(step("q3_activation"))
	require.Contains(t, strings.Join(rep.Problems, "\n"), "failed or is stale")
	require.False(t, rep.Lane.Evidence)

	// no lane directory given: lane items are not run
	rep, err := Build(f.matrix(t, step("q3_activation")), nil, "", "", f.src, false, "")
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "was not run")
}

func TestReportReadsNamedLiveLaneRuns(t *testing.T) {
	f := newFixture(t)
	a, b := filepath.Join(f.dir, "a"), filepath.Join(f.dir, "b")
	writeLane(t, a, "clean build (evidence run)", "  PASS: q3_activation\n")
	writeLane(t, b, "clean build (evidence run)", "  PASS: q3_pair_controls\n")
	// a Q3 lane records "Q3 run mode: ", which is as much a run mode as the Q4 lane's
	require.NoError(t, os.WriteFile(filepath.Join(b, "run-mode.txt"), []byte("Q3 run mode: clean build (evidence run; Ureth built by the operator)\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(f.src, "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(f.src, "scripts", "q3-weight-activation-steps.sh"), []byte("q3_activation() { :; }\nq3_pair_controls() { :; }\n"), 0o644))
	row := func(lane, step string) Row {
		return Row{ID: "N", Required: []string{"REAL-PROCESS"}, Evidence: []Evidence{{Kind: "lane", Label: "REAL-PROCESS", Lane: lane, Step: step}}}
	}
	build := func(r Row, named ...string) (*Report, error) {
		return Build(f.matrix(t, r), nil, "", "", f.src, false, a, named...)
	}
	rep, err := build(row("q3", "q3_pair_controls"), "q3="+b)
	require.NoError(t, err)
	require.Empty(t, rep.Problems)
	require.Len(t, rep.Lanes, 2)
	require.True(t, rep.Lanes[1].Evidence)
	rep, err = build(row("", "q3_pair_controls"), "q3="+b)
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "was not run", "the default run has no such step: a named run does not leak into it")
	rep, err = build(row("q3", "q3_pair_controls"))
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "was not run", "an item naming a lane that was not given is not run")
	_, err = build(row("q3", "q3_pair_controls"), "q3")
	require.Error(t, err)
	_, err = build(row("q3", "q3_pair_controls"), "q3="+b, "q3="+a)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(b, "run-mode.txt"), []byte("Q3 run mode: DEVELOPMENT OVERRIDE: NOT EVIDENCE\n"), 0o644))
	rep, err = build(row("q3", "q3_pair_controls"), "q3="+b)
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "failed or is stale", "a named run is held to the same evidence rule")
}
