package evmroot

// P1 — Staking component reuse assessment, encoded as checkable data.
//
// This file is the machine-checkable form of the reuse decision. The
// normative narrative is docs/design/p1-staking-component-reuse-assessment.md
// and the decision record is docs/adr/0009-staking-component-reuse.md; this
// model exists so the acceptance invariants are enforced by a test rather
// than asserted in prose:
//
//   - every pinned upstream source has a real revision and an SPDX licence id;
//   - no component is marked for a source port while every pinned source is
//     copyleft-incompatible with the Apache-2.0 contract set;
//   - every removed unit either names the accounting duty it carried and the
//     replacement that assumes it, or is explicitly marked as carrying none;
//   - every reference/port row names the upstream test obligation it drops and
//     the local home that re-tests the behaviour;
//   - the root-certified assignment/retirement lifecycle and the assigned-weight
//     reward each have an explicit, spec-referenced accounting replacement;
//   - a green upstream test suite and a compiler upgrade are not recorded as a
//     security audit.
//
// Normative sources: docs/pos/roadmap.md §P1; docs/pos/specification/governance.tex
// §§ "Stake Registry", "Election", "Trust Base Derivation", "Rewards",
// "Slashing", "Fees", "Economic Invariants", "Upgrade and Delivery Boundaries";
// docs/adr/0006 (D4), docs/adr/0007 (D5).

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// ReuseDisposition is what P1 decides to do with an upstream unit.
type ReuseDisposition string

const (
	// DispositionIndependentImplementation: study the publicly documented
	// algorithm and implement it locally, recording where the understanding came
	// from. No upstream bytes are copied.
	//
	// It is deliberately NOT called "clean-room". A clean-room process is a
	// specific discipline — a separated specification team, a separated
	// implementation team that never sees the original, and records proving the
	// separation. None of that was performed here, and "no verbatim copying" does
	// not amount to it. Claiming the term would overstate the provenance
	// guarantee this assessment can actually support.
	DispositionIndependentImplementation ReuseDisposition = "independent-implementation"
	// DispositionVendorPort: copy upstream source (adapted) into the project.
	// Gated on licence compatibility with the destination contract set.
	DispositionVendorPort ReuseDisposition = "vendor-port"
	// DispositionRemove: the upstream unit is dropped. Any accounting duty it
	// carried must be named and re-homed (or it is marked as carrying none).
	DispositionRemove ReuseDisposition = "remove"
	// DispositionDeferNotApplicable: out of scope for the initial self-bond
	// profile; kept only as a reference for a later optional upgrade.
	DispositionDeferNotApplicable ReuseDisposition = "defer-not-applicable"
)

var (
	hex40Re = regexp.MustCompile(`^[0-9a-f]{40}$`)

	// permissiveSPDX are licences that impose no copyleft on a combined work, so
	// they can be absorbed by a destination under any of the licences below.
	permissiveSPDX = map[string]bool{
		"Apache-2.0":   true,
		"MIT":          true,
		"BSD-2-Clause": true,
		"BSD-3-Clause": true,
		"ISC":          true,
		"CC0-1.0":      true,
		"Unlicense":    true,
	}
)

// portableInto reports whether source SPDX src may be copied into a destination
// licensed dst.
//
// THIS USED TO BE A SINGLE Apache-2.0 TABLE, and that was the central defect of
// the first revision: it assumed the destination licence rather than taking it
// as an input, which made "GPL source cannot be ported" look like a property of
// the source when it was a property of an assumption. The destination is now
// declared per matrix and this function is a function of both.
//
// The table is small and deliberately conservative:
//
//   - into a permissive destination (Apache-2.0, MIT, …): permissive sources
//     only. A GPL-3.0 source cannot be relicensed permissively.
//   - into GPL-3.0-only or GPL-3.0-or-later: GPL-3.0 sources, and permissive
//     sources, which are one-way compatible with the GPL.
//     Apache-2.0 is GPL-3.0-compatible in that direction (ASF and FSF both say
//     so); it is not compatible with GPLv2.
//
// References, cited because a licence claim should be checkable rather than
// asserted: https://www.apache.org/licenses/GPL-compatibility and
// https://www.gnu.org/licenses/license-list.html#GPLCompatibleLicenses
//
// This is an engineering-side compatibility check, not legal advice, and the
// matrix says so in its own decision record.
func portableInto(dst, src string) bool {
	switch dst {
	case "GPL-3.0-only", "GPL-3.0-or-later":
		if src == "GPL-3.0-only" || src == "GPL-3.0-or-later" {
			return true
		}
		return permissiveSPDX[src]
	default:
		// A permissive destination can only absorb permissive sources.
		return permissiveSPDX[src]
	}
}

// UpstreamSource is one pinned candidate revision the assessment considered.
type UpstreamSource struct {
	Key        string `json:"key"`
	Repo       string `json:"repo"`
	Revision   string `json:"revision"`              // 40-hex commit the assessment read
	RevisionAs string `json:"revision_as,omitempty"` // human tag/branch for the revision
	License    string `json:"license"`
	SPDX       string `json:"spdx"`
	Archived   bool   `json:"archived"`
	SolcPragma string `json:"solc_pragma"`
	Deps       string `json:"deps,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Component is one upstream unit and what P1 decides about it.
type Component struct {
	UpstreamRef string           `json:"upstream_ref"` // must match an UpstreamSource.Key
	Unit        string           `json:"unit"`
	Purpose     string           `json:"purpose"`
	Target      string           `json:"target_obligation"`
	Disposition ReuseDisposition `json:"disposition"`

	// Remove rows: identify the accounting duty before deleting the coupling.
	CarriesNoAccountingDuty bool   `json:"carries_no_accounting_duty,omitempty"`
	ReplacesDutyKey         string `json:"replaces_duty_key,omitempty"` // key into AccountingReplacements

	// Reference / port rows: what upstream test is dropped and where the
	// behaviour is re-tested locally.
	RemovedUpstreamTest string `json:"removed_upstream_test,omitempty"`
	LocalHome           string `json:"local_home,omitempty"`

	// Defer rows: the ticket/upgrade that would revisit this.
	DeferredTo string `json:"deferred_to,omitempty"`

	Replacement string `json:"replacement,omitempty"`
	Note        string `json:"note,omitempty"`
}

// AccountingReplacement records where a duty that upstream performed is
// assumed in the new design.
type AccountingReplacement struct {
	Key         string `json:"key"`
	Duty        string `json:"duty"`
	Replacement string `json:"replacement"`
	SpecRef     string `json:"spec_ref"`
}

// ReuseDecision is the normative one-paragraph output plus the guards the
// acceptance criteria call out explicitly.
type ReuseDecision struct {
	Choice                               string `json:"choice"`
	Rationale                            string `json:"rationale"`
	Vendored                             bool   `json:"any_upstream_source_vendored"`
	LicenceConstraint                    string `json:"licence_constraint"`
	UpstreamTestSuiteIsNotASecurityAudit bool   `json:"upstream_test_suite_is_not_a_security_audit"`
	CompilerModernizationIsNotAnAudit    bool   `json:"compiler_modernization_is_not_a_security_audit"`
	SecurityAuditOwner                   string `json:"security_audit_owner"`
}

// Destination is where the contracts will live, and under which licence. It is
// DATA, not an assumption baked into the validator.
//
// The first revision inferred that the contracts had to be Apache-2.0 because
// bft-core is Apache-2.0, and that immutability forced the same conclusion.
// Neither follows. The contracts live in a separate repository, and a separate
// repository may carry a different licence; immutability is a property of the
// deployed bytecode and says nothing about licensing. Recording the destination
// explicitly is what lets the GPL option be assessed at all.
type Destination struct {
	Repository string `json:"repository"`
	SPDX       string `json:"spdx"`
	// Boundary describes the actual source/artifact/interface relationship
	// between this destination and the Apache-2.0 platform, which is what a
	// licence conclusion has to rest on.
	Boundary string `json:"boundary"`
	// LegalReviewOwner names who must confirm the boundary. An engineering
	// assessment can narrow the options; it cannot make the determination.
	LegalReviewOwner string `json:"legal_review_owner"`
}

// ReuseMatrix is the whole assessment as data.
type ReuseMatrix struct {
	Ticket                 string                  `json:"ticket"`
	BaseRevision           string                  `json:"base_revision"`
	Destination            Destination             `json:"destination"`
	Sources                []UpstreamSource        `json:"sources"`
	Components             []Component             `json:"components"`
	AccountingReplacements []AccountingReplacement `json:"accounting_replacements"`
	Decision               ReuseDecision           `json:"decision"`
}

// requiredAccountingDutyKeys must each appear in AccountingReplacements with a
// non-empty Replacement and SpecRef. These are the two duties the P1
// acceptance test names directly.
var requiredAccountingDutyKeys = []string{
	"root-certified-lifecycle",
	"assigned-weight-reward",
}

func (m ReuseMatrix) sourceByKey(k string) (UpstreamSource, bool) {
	for _, s := range m.Sources {
		if s.Key == k {
			return s, true
		}
	}
	return UpstreamSource{}, false
}

func (m ReuseMatrix) replacementByKey(k string) (AccountingReplacement, bool) {
	for _, r := range m.AccountingReplacements {
		if r.Key == k {
			return r, true
		}
	}
	return AccountingReplacement{}, false
}

// AnyVendored reports whether any component is marked for a source port.
func (m ReuseMatrix) AnyVendored() bool {
	for _, c := range m.Components {
		if c.Disposition == DispositionVendorPort {
			return true
		}
	}
	return false
}

// SourcesPortableIntoDestination reports whether every pinned source could be
// copied into the DECLARED destination licence.
//
// The predicate used to be "are all sources copyleft", which only made sense
// while the destination was assumed permissive. Copyleft is not a defect of a
// source; it is a constraint that binds or does not bind depending on where the
// source is going.
func (m ReuseMatrix) SourcesPortableIntoDestination() bool {
	if len(m.Sources) == 0 {
		return false
	}
	for _, s := range m.Sources {
		if !portableInto(m.Destination.SPDX, s.SPDX) {
			return false
		}
	}
	return true
}

// Validate enforces the P1 acceptance invariants. A nil return means the
// assessment is internally consistent and satisfies the ticket's acceptance
// clauses.
func (m ReuseMatrix) Validate() error {
	if m.Ticket == "" || m.BaseRevision == "" {
		return fmt.Errorf("matrix: ticket and base_revision are required")
	}
	if len(m.Sources) == 0 {
		return fmt.Errorf("matrix: no upstream sources pinned")
	}
	seenSrc := map[string]bool{}
	for _, s := range m.Sources {
		if s.Key == "" || s.Repo == "" || s.License == "" || s.SPDX == "" || s.SolcPragma == "" {
			return fmt.Errorf("source %q: key, repo, license, spdx and solc_pragma are all required", s.Key)
		}
		if seenSrc[s.Key] {
			return fmt.Errorf("source %q: duplicate key", s.Key)
		}
		seenSrc[s.Key] = true
		if !hex40Re.MatchString(s.Revision) {
			return fmt.Errorf("source %q: revision %q is not a 40-hex commit", s.Key, s.Revision)
		}
	}

	if len(m.Components) == 0 {
		return fmt.Errorf("matrix: no components assessed")
	}
	for i, c := range m.Components {
		where := fmt.Sprintf("component[%d] %q", i, c.Unit)
		if c.Unit == "" || c.Purpose == "" || c.Target == "" {
			return fmt.Errorf("%s: unit, purpose and target_obligation are required", where)
		}
		if _, ok := m.sourceByKey(c.UpstreamRef); !ok {
			return fmt.Errorf("%s: upstream_ref %q matches no pinned source", where, c.UpstreamRef)
		}
		switch c.Disposition {
		case DispositionRemove:
			if c.CarriesNoAccountingDuty {
				if c.Note == "" {
					return fmt.Errorf("%s: removed with no accounting duty must carry a Note explaining why", where)
				}
			} else {
				if c.ReplacesDutyKey == "" {
					return fmt.Errorf("%s: removed coupling must name the accounting duty it carried (replaces_duty_key) or set carries_no_accounting_duty", where)
				}
				if _, ok := m.replacementByKey(c.ReplacesDutyKey); !ok {
					return fmt.Errorf("%s: replaces_duty_key %q has no entry in accounting_replacements", where, c.ReplacesDutyKey)
				}
			}
		case DispositionIndependentImplementation, DispositionVendorPort:
			if c.RemovedUpstreamTest == "" || c.LocalHome == "" || c.Replacement == "" {
				return fmt.Errorf("%s: reference/port row needs removed_upstream_test, local_home and replacement", where)
			}
		case DispositionDeferNotApplicable:
			if c.DeferredTo == "" {
				return fmt.Errorf("%s: deferred row needs deferred_to", where)
			}
		default:
			return fmt.Errorf("%s: unknown disposition %q", where, c.Disposition)
		}
	}

	// Destination must be declared before any licence conclusion can be checked.
	if m.Destination.SPDX == "" {
		return fmt.Errorf("destination.spdx is empty: the destination licence must be stated, not inferred from the platform")
	}
	if m.Destination.Repository == "" || m.Destination.Boundary == "" || m.Destination.LegalReviewOwner == "" {
		return fmt.Errorf("destination must state repository, boundary and legal_review_owner")
	}

	// Licence gate, now a function of the DECLARED destination rather than an
	// assumed Apache-2.0 one.
	for i, c := range m.Components {
		if c.Disposition != DispositionVendorPort {
			continue
		}
		s, _ := m.sourceByKey(c.UpstreamRef)
		if !portableInto(m.Destination.SPDX, s.SPDX) {
			return fmt.Errorf("component[%d] %q: vendor-port of %s (%s) is not licence-compatible with a %s destination", i, c.Unit, s.Key, s.SPDX, m.Destination.SPDX)
		}
	}
	if m.Decision.Vendored != m.AnyVendored() {
		return fmt.Errorf("decision.any_upstream_source_vendored=%v disagrees with the component rows (%v)", m.Decision.Vendored, m.AnyVendored())
	}

	// Accounting replacements: well-formed, unique, and the required duties present.
	seenDuty := map[string]bool{}
	for _, r := range m.AccountingReplacements {
		if r.Key == "" || r.Duty == "" || r.Replacement == "" || r.SpecRef == "" {
			return fmt.Errorf("accounting replacement %q: key, duty, replacement and spec_ref are all required", r.Key)
		}
		if seenDuty[r.Key] {
			return fmt.Errorf("accounting replacement %q: duplicate key", r.Key)
		}
		seenDuty[r.Key] = true
	}
	for _, k := range requiredAccountingDutyKeys {
		if !seenDuty[k] {
			return fmt.Errorf("accounting replacement %q is required by the acceptance criteria but missing", k)
		}
	}

	// Audit guards.
	if !m.Decision.UpstreamTestSuiteIsNotASecurityAudit || !m.Decision.CompilerModernizationIsNotAnAudit {
		return fmt.Errorf("decision: both audit guards must be asserted true")
	}
	if m.Decision.SecurityAuditOwner == "" {
		return fmt.Errorf("decision: security_audit_owner is required and must not point at upstream")
	}
	if m.Decision.Choice == "" || m.Decision.Rationale == "" || m.Decision.LicenceConstraint == "" {
		return fmt.Errorf("decision: choice, rationale and licence_constraint are required")
	}
	return nil
}

// MarshalP1ReuseMatrix renders the matrix as the golden JSON fixture.
func MarshalP1ReuseMatrix(m ReuseMatrix) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Counts summarises dispositions, for the design-doc table and the test.
func (m ReuseMatrix) Counts() map[ReuseDisposition]int {
	out := map[ReuseDisposition]int{}
	for _, c := range m.Components {
		out[c.Disposition]++
	}
	return out
}

// DutyKeys returns the accounting-replacement keys in sorted order.
func (m ReuseMatrix) DutyKeys() []string {
	ks := make([]string, 0, len(m.AccountingReplacements))
	for _, r := range m.AccountingReplacements {
		ks = append(ks, r.Key)
	}
	sort.Strings(ks)
	return ks
}
