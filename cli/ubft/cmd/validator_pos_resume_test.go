package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// pos-publish resumes at the first unfinished step: after each step committed, only the later steps are planned.
func TestPlanPosPublishResumesAfterEachStep(t *testing.T) {
	const members = 4
	for name, c := range map[string]struct {
		pops      uint32
		finalized bool
		vrState   uint8
		want      [3]bool
	}{
		"nothing done":               {0, false, 1, [3]bool{true, true, true}},
		"some proofs stored":         {2, false, 1, [3]bool{true, true, true}},
		"all proofs stored":          {members, false, 1, [3]bool{false, true, true}},
		"the candidate is finalized": {members, true, 1, [3]bool{false, false, true}},
		"published in VR":            {members, true, 2, [3]bool{false, false, false}},
		"a later VR state":           {members, true, 6, [3]bool{false, false, false}},
		"acknowledged":               {members, true, 5, [3]bool{false, false, false}},
	} {
		got, err := planPosPublish(members, c.pops, c.finalized, c.vrState)
		require.NoError(t, err, name)
		require.Equal(t, c.want, got, name)
	}
	// Invalidated and Rejected are refusals with a clear message, whatever the election holds
	for _, st := range []uint8{3, 4} {
		for _, finalized := range []bool{false, true} {
			_, err := planPosPublish(members, members, finalized, st)
			require.ErrorIs(t, err, ErrValidator)
			require.ErrorContains(t, err, vrOutputState(st))
		}
	}
}

func TestSameDelegation(t *testing.T) {
	a := vrclient.Delegation{RootNodeID: [32]byte{1}, RootKey: []byte{2}, EvmNodeID: [32]byte{3}, EvmKey: []byte{4}, OperatorPayee: [20]byte{5}}
	require.True(t, sameDelegation(a, a))
	b := a
	b.OperatorPayee = [20]byte{6}
	require.False(t, sameDelegation(a, b))
	b = a
	b.EvmKey = []byte{9}
	require.False(t, sameDelegation(a, b))
	require.False(t, sameDelegation(a, vrclient.Delegation{}))
}
