package vradmit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// VT-06b edge cases of the committee limits (design sections 3.5.3, 5.2 item 4 and 6.4). The world's committee swaps one member, |K| = 4 to
// |J| = 4, on a module output; the limits in force are those of the state proven at P, never the ones the output itself binds.
func TestCommitteeLimitsEdgesOnAModuleOutput(t *testing.T) {
	for _, c := range []struct {
		name   string
		limits vrschema.CommitteeLimits
		admit  bool
	}{
		{"inside the range", vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}, true},
		{"exactly nMax", vrschema.CommitteeLimits{NMin: 1, NTarget: 4, NMax: 4}, true},
		{"exactly nMin", vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 16}, true},
		{"the widest range", vrschema.CommitteeLimits{NMin: 1, NTarget: 8, NMax: 16}, true},
		{"nMax lowered below the current size: a same-size swap makes no progress", vrschema.CommitteeLimits{NMin: 1, NTarget: 3, NMax: 3}, false},
		{"nMax lowered to the minimum", vrschema.CommitteeLimits{NMin: 1, NTarget: 1, NMax: 1}, false},
		{"nMin raised above the current size: a same-size swap makes no progress", vrschema.CommitteeLimits{NMin: 5, NTarget: 5, NMax: 16}, false},
		{"nMin raised to MaxCommittee", vrschema.CommitteeLimits{NMin: 16, NTarget: 16, NMax: 16}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.build()
			w.state.Limits = c.limits
			require.True(t, c.limits.Valid())
			_, err := VerifyRegistryOutput(w.admission())
			if c.admit {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrLimits)
			}
			// a native output is exempt from the limits whatever they are
			n := newWorld(t)
			n.snap, n.pol, n.native = vrschema.Word{}, vrschema.Word{}, true
			n.build()
			n.state.Limits = c.limits
			_, err = VerifyRegistryOutput(n.admission())
			require.NoError(t, err, "native outputs are exempt")
		})
	}
}

func TestLimitsSatisfiedAtMaxCommittee(t *testing.T) {
	full := vrschema.CommitteeLimits{NMin: 4, NTarget: 10, NMax: 16}
	require.True(t, LimitsSatisfied(full, 16, 16), "a full committee inside the range")
	require.True(t, LimitsSatisfied(full, 15, 16))
	require.True(t, LimitsSatisfied(full, 16, 4))

	// lowering nMax below the size of a full committee shrinks it over several outputs, each strictly closer
	lowered := vrschema.CommitteeLimits{NMin: 1, NTarget: 3, NMax: 5}
	require.False(t, LimitsSatisfied(lowered, 16, 16), "no progress")
	require.False(t, LimitsSatisfied(lowered, 16, 16-0))
	require.True(t, LimitsSatisfied(lowered, 16, 15), "one fewer is strictly closer")
	require.True(t, LimitsSatisfied(lowered, 16, 5), "straight to the range")
	require.True(t, LimitsSatisfied(lowered, 16, 1))
	require.False(t, LimitsSatisfied(lowered, 15, 16), "growing away from the range")
	require.True(t, LimitsSatisfied(lowered, 6, 5))
	require.False(t, LimitsSatisfied(lowered, 6, 6))
	require.True(t, LimitsSatisfied(lowered, 3, 3), "inside the range, an unchanged size is fine")
	require.True(t, LimitsSatisfied(lowered, 3, 5))

	// a committee below nMin must grow
	raised := vrschema.CommitteeLimits{NMin: 8, NTarget: 8, NMax: 16}
	require.True(t, LimitsSatisfied(raised, 4, 5))
	require.False(t, LimitsSatisfied(raised, 4, 4))
	require.False(t, LimitsSatisfied(raised, 4, 3))
}

func TestCommitteeLimitsQueueCheck(t *testing.T) {
	for _, c := range []struct {
		l  [3]uint64
		ok bool
	}{
		{[3]uint64{1, 1, 1}, true}, {[3]uint64{4, 10, 16}, true}, {[3]uint64{16, 16, 16}, true},
		{[3]uint64{0, 1, 1}, false}, {[3]uint64{2, 1, 3}, false}, {[3]uint64{1, 4, 3}, false}, {[3]uint64{1, 16, 17}, false}, {[3]uint64{17, 17, 17}, false},
		{[3]uint64{1, 1, 1 << 32}, false},
	} {
		p, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, c.l[0], c.l[1], c.l[2])
		if err != nil {
			require.False(t, c.ok, "%v", c.l) // outside uint32: refused by the ABI shape
			continue
		}
		err = vrschema.QueueCheck(vrschema.KindCommitteeLimits, p, vrschema.QueueEnv{})
		require.Equal(t, c.ok, err == nil, "%v: %v", c.l, err)
	}
}
