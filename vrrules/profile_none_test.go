//go:build no_test_rule

package vrrules

// testRuleKnown is whether this build's Known() holds the test rule: the no_test_rule profile (a binary that lacks it) does not.
const testRuleKnown = false
