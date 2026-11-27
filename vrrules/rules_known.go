//go:build !no_test_rule

package vrrules

import "github.com/unicitynetwork/bft-core/vrschema"

func known() Set { return Set{vrschema.RuleID(TestRuleName): TestRuleName} }
