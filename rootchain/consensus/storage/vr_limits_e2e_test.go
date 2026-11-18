package storage_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// Committee limits through the real block executor (VT-06b; design sections 5.2 item 4 and 6.4): the Freeze v5 judges a module output by
// the limits in force in the VR state proven at the frozen parent, not by the CommitteeLimits change the output itself binds (that one is
// active at its boundary and judges the next output). The fixture's module output swaps one member: |K| = |J| = 4.
func TestVRFreezeJudgesAModuleOutputByTheLimitsInForce(t *testing.T) {
	for _, c := range []struct {
		name   string
		limits vrschema.CommitteeLimits
		admit  bool
	}{
		{"in range", vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}, true},
		{"nMax 16 with a committee of 4", vrschema.CommitteeLimits{NMin: 1, NTarget: 8, NMax: 16}, true},
		{"nMax lowered below the size: no progress", vrschema.CommitteeLimits{NMin: 1, NTarget: 3, NMax: 3}, false},
		{"nMin raised above the size: no progress", vrschema.CommitteeLimits{NMin: 5, NTarget: 5, NMax: 16}, false},
		{"MaxCommittee for both bounds", vrschema.CommitteeLimits{NMin: 16, NTarget: 16, NMax: 16}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newVXFixture(t)
			f.limits = &c.limits
			f.build()
			g := f.genesis()
			prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
			_, err := f.exec(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
			if c.admit {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, vradmit.ErrLimits)
			}
		})
	}
}
