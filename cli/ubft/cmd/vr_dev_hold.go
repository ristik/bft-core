//go:build vrdev

package cmd

import (
	"os"
	"path/filepath"
)

// devMemberHold is a development test hook of the vrdev build (scripts/vr-boundary-steps.sh): with UBFT_VR_MEMBER_HOLD=1 the member holds its
// readiness back while <home>/vr-member.hold exists. A production build has no such hook.
func devMemberHold(home string) func() bool {
	if os.Getenv("UBFT_VR_MEMBER_HOLD") != "1" {
		return nil
	}
	hold := filepath.Join(home, "vr-member.hold")
	return func() bool { _, err := os.Stat(hold); return err == nil }
}
