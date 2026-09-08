package evmroot

import (
	"bytes"
	"encoding/json"
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

// TestP1_LicenceGateDependsOnTheDeclaredDestination is the corrected licence finding.
//
// The previous test asserted that "every pinned Polygon revision is copyleft-incompatible with the
// Apache-2.0 contract set, so the decision must not vendor or port any of them". That conclusion
// was reached by ASSUMING the destination licence from the platform's, which review rejected. The
// contracts live in a separate repository, and a separate repository may carry a different licence.
//
// What is asserted now is the actual rule: portability is a function of BOTH licences. Under the
// declared GPL-3.0-only destination a GPL-3.0 source port is permitted; under a permissive
// destination it is not. So "nothing is vendored at this revision" is an ENGINEERING choice about
// which units are worth porting, and this test proves the licence gate is not what is making it.
func TestP1_LicenceGateDependsOnTheDeclaredDestination(t *testing.T) {
	m := BuildP1ReuseMatrix()

	if m.Destination.SPDX == "" || m.Destination.Repository == "" || m.Destination.Boundary == "" {
		t.Fatalf("the destination must be declared as data, not inferred: %+v", m.Destination)
	}
	if !m.SourcesPortableIntoDestination() {
		t.Fatalf("every pinned source should be portable into the declared %s destination; sources=%+v",
			m.Destination.SPDX, m.Sources)
	}
	for _, s := range m.Sources {
		if !strings.HasPrefix(s.SPDX, "GPL-3.0") {
			t.Errorf("source %q: expected a GPL-3.0 SPDX id, got %q", s.Key, s.SPDX)
		}
	}

	// The decision still ports nothing, and that must remain an engineering choice.
	if m.AnyVendored() || m.Decision.Vendored {
		t.Fatalf("this revision vendors no upstream source; the matrix disagrees")
	}

	// A vendor-port row must VALIDATE under the GPL destination...
	ported := BuildP1ReuseMatrix()
	ported.Components = append(ported.Components, Component{
		UpstreamRef:         "matic-contracts",
		Unit:                "hypothetical port, present only in this test",
		Purpose:             "prove the gate admits a GPL source into a GPL destination",
		Target:              "n/a",
		Disposition:         DispositionVendorPort,
		LocalHome:           "n/a",
		RemovedUpstreamTest: "n/a",
		Replacement:         "n/a",
	})
	ported.Decision.Vendored = true
	if err := ported.Validate(); err != nil {
		t.Fatalf("a GPL-3.0 source port into a GPL-3.0 destination must be licence-permitted, got: %v", err)
	}

	// ...and must be REFUSED if the destination were permissive. This is the half the earlier
	// revision hard-coded as the only case.
	apache := ported
	apache.Destination.SPDX = "Apache-2.0"
	err := apache.Validate()
	if err == nil {
		t.Fatal("a GPL-3.0 source port into an Apache-2.0 destination must be refused")
	}
	if !strings.Contains(err.Error(), "not licence-compatible with a Apache-2.0 destination") {
		t.Fatalf("the refusal must name the destination licence it was judged against, got: %v", err)
	}
}

// TestP1_DispositionIsNotCalledCleanRoom guards the provenance wording.
//
// No clean-room process was performed: there was no separated specification team, no separated
// implementation team, and no records proving separation. "No verbatim copying" is not that, and
// naming it so would overstate what this assessment can support.
func TestP1_DispositionIsNotCalledCleanRoom(t *testing.T) {
	m := BuildP1ReuseMatrix()
	blob, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(blob), []byte("clean-room")) || bytes.Contains(bytes.ToLower(blob), []byte("clean room")) {
		t.Error("the matrix claims a clean-room process; use independent implementation with documented provenance")
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
		if c.Disposition != DispositionIndependentImplementation && c.Disposition != DispositionVendorPort {
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
	t.Run("copyleft port into a permissive destination", func(t *testing.T) {
		// The gate still has teeth — but against the DECLARED destination. Porting GPL-3.0 into
		// an Apache-2.0 destination is refused; porting it into the GPL-3.0 destination this
		// assessment actually declares is not, which is what
		// TestP1_LicenceGateDependsOnTheDeclaredDestination covers.
		m := BuildP1ReuseMatrix()
		m.Destination.SPDX = "Apache-2.0"
		cp := make([]Component, len(m.Components))
		copy(cp, m.Components)
		cp[0].Disposition = DispositionVendorPort
		cp[0].RemovedUpstreamTest = "x"
		cp[0].LocalHome = "x"
		cp[0].Replacement = "x"
		m.Components = cp
		m.Decision.Vendored = true
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation to reject a GPL-3.0 vendor-port into an Apache-2.0 destination")
		}
	})
	t.Run("undeclared destination", func(t *testing.T) {
		// The destination must be stated. Leaving it empty used to be impossible because it was
		// hard-coded; now that it is data, an unstated destination must fail rather than default.
		m := BuildP1ReuseMatrix()
		m.Destination.SPDX = ""
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation to reject a matrix with no declared destination licence")
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
