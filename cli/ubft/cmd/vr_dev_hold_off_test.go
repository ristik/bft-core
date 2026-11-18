//go:build !vrdev

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A production build (no vrdev tag) has no readiness hold, whatever the environment says.
func TestAProductionBuildHasNoReadinessHold(t *testing.T) {
	t.Setenv("UBFT_VR_MEMBER_HOLD", "1")
	m, err := vrMemberConfig(t.TempDir(), "")
	require.NoError(t, err)
	require.Nil(t, m.Hold)
}
