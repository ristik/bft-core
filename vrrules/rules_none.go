//go:build no_test_rule

package vrrules

// A binary built with -tags no_test_rule lacks the test rule: it is the "old release" of the live acceptance.
func known() Set { return Set{} }
