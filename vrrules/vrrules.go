// Package vrrules is what a binary knows of the activation schedule (design section 7.4): the rules it supports, the fence that refuses
// to run past an activation it lacks, and the warning list ahead of it. Rule support decides; the release digest is advisory.
package vrrules

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// TestRuleName is the one real but harmless rule the activation schedule is proven with end to end: it changes no execution, it only
// exists so a release can be scheduled, supported and activated, and a binary without it fenced.
const TestRuleName = "noop-test-v1"

// ErrUpgradeRequired is the refusal to run past an activation this binary lacks.
var ErrUpgradeRequired = errors.New("UpgradeRequired")

// UpgradeRequired names the rule and release that must be installed.
type UpgradeRequired struct {
	RuleID        vrschema.Word
	ReleaseDigest vrschema.Word
	RootEpoch     uint64
	Latched       bool
}

func (e *UpgradeRequired) Error() string {
	return fmt.Sprintf("UpgradeRequired: this binary does not support rule %x, active from root epoch %d (release digest %x); install that release before this epoch",
		e.RuleID[:], e.RootEpoch, e.ReleaseDigest[:])
}

func (e *UpgradeRequired) Is(target error) bool { return target == ErrUpgradeRequired }

// Set is a binary's supported rules.
type Set map[vrschema.Word]string

// Known is the set of this binary (rules_known.go, and the build tag no_test_rule for a binary without the test rule).
func Known() Set { return known() }

// Has reports whether the rule is supported.
func (s Set) Has(rule vrschema.Word) bool { _, ok := s[rule]; return ok }

// Pending is every effective entry of the schedule (Active or Latched, never Superseded) the set does not support, ascending by rule id
// as the schedule lists them.
func Pending(schedule []vrschema.Activation, s Set) []vrschema.Activation {
	var out []vrschema.Activation
	eff := vrschema.Effective(schedule)
	for _, a := range schedule {
		if cur, ok := eff[a.RuleID]; ok && cur == a && !s.Has(a.RuleID) {
			out = append(out, a)
		}
	}
	return out
}

// Fence is the refusal before a node installs or runs root epoch epoch: it fails with the first effective rule with E <= epoch that
// the set lacks.
func Fence(schedule []vrschema.Activation, s Set, epoch uint64) error {
	for _, a := range Pending(schedule, s) {
		if a.RootEpoch <= epoch {
			return &UpgradeRequired{RuleID: a.RuleID, ReleaseDigest: a.ReleaseDigest, RootEpoch: a.RootEpoch, Latched: a.State == vrschema.ActLatched}
		}
	}
	return nil
}
