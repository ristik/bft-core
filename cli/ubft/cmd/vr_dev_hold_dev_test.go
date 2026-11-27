//go:build vrdev

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The vrdev build's readiness hold: off unless UBFT_VR_MEMBER_HOLD=1, and then held while <home>/vr-member.hold exists.
func TestTheDevBuildHoldsTheReadinessWhileTheMarkerExists(t *testing.T) {
	home := t.TempDir()
	require.Nil(t, devMemberHold(home))
	t.Setenv("UBFT_VR_MEMBER_HOLD", "1")
	hold := devMemberHold(home)
	require.NotNil(t, hold)
	require.False(t, hold())
	require.NoError(t, os.WriteFile(filepath.Join(home, "vr-member.hold"), nil, 0o600))
	require.True(t, hold())
}
