package vrrules

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func TestFenceAndPending(t *testing.T) {
	known := vrschema.RuleID("known")
	unk := vrschema.RuleID("unknown")
	s := Set{known: "known"}
	sched := []vrschema.Activation{
		{RuleID: unk, ReleaseDigest: vrschema.Word{1}, RootEpoch: 7, State: vrschema.ActSuperseded, ChangeID: 1},
		{RuleID: unk, ReleaseDigest: vrschema.Word{2}, RootEpoch: 9, State: vrschema.ActActive, ChangeID: 2},
		{RuleID: known, RootEpoch: 5, State: vrschema.ActLatched, ChangeID: 3},
	}
	require.Len(t, Pending(sched, s), 1)
	require.NoError(t, Fence(sched, s, 8), "before E")
	err := Fence(sched, s, 9)
	require.ErrorIs(t, err, ErrUpgradeRequired)
	var u *UpgradeRequired
	require.True(t, errors.As(err, &u))
	require.Equal(t, vrschema.Word{2}, u.ReleaseDigest, "the superseded entry never counts")
	require.EqualValues(t, 9, u.RootEpoch)
	require.NoError(t, Fence(nil, s, 100))
	require.True(t, Known().Has(vrschema.RuleID(TestRuleName)) || len(Known()) == 0)
}
