package evmroot

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestP1_ReuseMatrixValidates is the top-level acceptance gate: the assessment
// is internally consistent and satisfies the ticket's acceptance clauses.
func TestP1_ReuseMatrixValidates(t *testing.T) {
	if err := BuildP1ReuseMatrix().Validate(); err != nil {
		t.Fatalf("reuse matrix does not validate: %v", err)
	}
}

// TestP1_NoUpstreamSourceIsPorted encodes the licence finding: every pinned
// Polygon revision is copyleft-incompatible with the Apache-2.0 contract set,
// so the decision must not vendor or port any of them.
func TestP1_NoUpstreamSourceIsPorted(t *testing.T) {
	m := BuildP1ReuseMatrix()
	if !m.SourcesAllCopyleft() {
		t.Fatalf("expected every pinned source to be Apache-incompatible copyleft; sources=%+v", m.Sources)
	}
	if m.AnyVendored() {
		t.Fatalf("a component is marked vendor-port while every source is GPL-3.0-only")
	}
	if m.Decision.Vendored {
		t.Fatalf("decision claims a source was vendored")
	}
	for _, s := range m.Sources {
		if !strings.HasPrefix(s.SPDX, "GPL-3.0") {
			t.Errorf("source %q: expected a GPL-3.0 SPDX id, got %q", s.Key, s.SPDX)
		}
	}
}

// TestP1_EveryRemovalNamesItsAccountingDuty enforces "delete the coupling only
// after identifying any accounting duty it carried".
func TestP1_EveryRemovalNamesItsAccountingDuty(t *testing.T) {
	m := BuildP1ReuseMatrix()
	for _, c := range m.Components {
		if c.Disposition != DispositionRemove {
			continue
		}
		if c.CarriesNoAccountingDuty {
			if c.Note == "" {
				t.Errorf("%q: removed with no accounting duty but no Note explains why", c.Unit)
			}
			continue
		}
		r, ok := m.replacementByKey(c.ReplacesDutyKey)
		if !ok {
			t.Errorf("%q: replaces_duty_key %q has no accounting-replacement entry", c.Unit, c.ReplacesDutyKey)
			continue
		}
		if r.Replacement == "" || r.SpecRef == "" {
			t.Errorf("%q: accounting replacement %q is incomplete", c.Unit, r.Key)
		}
	}
}

// TestP1_ReferenceRowsDropAnUpstreamTestAndReHomeIt enforces that every
// clean-room/port row identifies the upstream test obligation it drops and the
// local home that re-tests the behaviour.
func TestP1_ReferenceRowsDropAnUpstreamTestAndReHomeIt(t *testing.T) {
	m := BuildP1ReuseMatrix()
	seen := 0
	for _, c := range m.Components {
		if c.Disposition != DispositionCleanRoomReference && c.Disposition != DispositionVendorPort {
			continue
		}
		seen++
		if c.RemovedUpstreamTest == "" {
			t.Errorf("%q: no removed_upstream_test", c.Unit)
		}
		if c.LocalHome == "" {
			t.Errorf("%q: no local_home", c.Unit)
		}
	}
	if seen == 0 {
		t.Fatal("expected at least one clean-room-reference row")
	}
}

// TestP1_RootCertifiedLifecycleAndRewardHaveReplacements is the second explicit
// acceptance clause: the root-certified lifecycle and the assigned-weight
// reward each have an explicit accounting replacement with a spec reference.
func TestP1_RootCertifiedLifecycleAndRewardHaveReplacements(t *testing.T) {
	m := BuildP1ReuseMatrix()
	for _, key := range []string{"root-certified-lifecycle", "assigned-weight-reward"} {
		r, ok := m.replacementByKey(key)
		if !ok {
			t.Fatalf("required accounting replacement %q missing", key)
		}
		if len(r.Replacement) < 80 {
			t.Errorf("%q: replacement text is too thin to be explicit (%d chars)", key, len(r.Replacement))
		}
		if !strings.Contains(r.SpecRef, "governance.tex") {
			t.Errorf("%q: spec_ref does not cite governance.tex: %q", key, r.SpecRef)
		}
	}
}

// TestP1_UpstreamTestSuccessIsNotAnAudit enforces the third acceptance clause.
func TestP1_UpstreamTestSuccessIsNotAnAudit(t *testing.T) {
	d := BuildP1ReuseMatrix().Decision
	if !d.UpstreamTestSuiteIsNotASecurityAudit || !d.CompilerModernizationIsNotAnAudit {
		t.Fatal("audit guards must both be asserted")
	}
	if d.SecurityAuditOwner == "" {
		t.Fatal("security audit owner is unset")
	}
	if strings.Contains(strings.ToLower(d.SecurityAuditOwner), "upstream test") {
		t.Fatalf("security audit owner points at an upstream test run: %q", d.SecurityAuditOwner)
	}
}

// TestP1_CheckpointAndBridgeCouplingIsRemoved: the units the ticket names
// specifically (checkpoint reward accrual, bridge/state-sync coupling) are
// dropped, not carried forward.
func TestP1_CheckpointAndBridgeCouplingIsRemoved(t *testing.T) {
	m := BuildP1ReuseMatrix()
	wantRemoved := []string{"CHECKPOINT_REWARD", "StateSender"}
	for _, needle := range wantRemoved {
		found := false
		for _, c := range m.Components {
			if strings.Contains(c.Unit, needle) {
				found = true
				if c.Disposition != DispositionRemove {
					t.Errorf("unit containing %q has disposition %q, want remove", needle, c.Disposition)
				}
			}
		}
		if !found {
			t.Errorf("no component row covers %q", needle)
		}
	}
}

// TestP1_VectorsMatchGolden pins the fixture. Regenerate with:
//
//	go run ./evmroot/cmd/p1matrix -update
func TestP1_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/p1-reuse-matrix.json"
	got, err := MarshalP1ReuseMatrix(BuildP1ReuseMatrix())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/p1matrix -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/p1matrix -update", path)
	}
}

// TestP1_ValidateRejectsABrokenMatrix guards the guard: a matrix that ports a
// GPL source, or removes a coupling without naming its duty, must fail.
func TestP1_ValidateRejectsABrokenMatrix(t *testing.T) {
	t.Run("ported copyleft source", func(t *testing.T) {
		m := BuildP1ReuseMatrix()
		cp := make([]Component, len(m.Components))
		copy(cp, m.Components)
		cp[0].Disposition = DispositionVendorPort
		cp[0].RemovedUpstreamTest = "x"
		cp[0].LocalHome = "x"
		cp[0].Replacement = "x"
		m.Components = cp
		m.Decision.Vendored = true
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation to reject a GPL-3.0 vendor-port")
		}
	})
	t.Run("removal without a named duty", func(t *testing.T) {
		m := BuildP1ReuseMatrix()
		cp := make([]Component, len(m.Components))
		copy(cp, m.Components)
		for i := range cp {
			if cp[i].Disposition == DispositionRemove && !cp[i].CarriesNoAccountingDuty {
				cp[i].ReplacesDutyKey = ""
				break
			}
		}
		m.Components = cp
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation to reject a removal with no accounting duty")
		}
	})
	t.Run("missing required accounting replacement", func(t *testing.T) {
		m := BuildP1ReuseMatrix()
		var kept []AccountingReplacement
		for _, r := range m.AccountingReplacements {
			if r.Key != "assigned-weight-reward" {
				kept = append(kept, r)
			}
		}
		m.AccountingReplacements = kept
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation to require the assigned-weight-reward replacement")
		}
	})
}
