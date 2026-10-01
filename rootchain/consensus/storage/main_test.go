package storage

import (
	"os"
	"testing"
)

// The fixtures of this package run compressed timelines (a handoff activates a few rounds after its Prepare), so the Prepare
// activation floor is lowered for them; TestPrepareActivationFloorIsEnforcedByBlockValidation restores it.
func TestMain(m *testing.M) {
	prepareActivationFloor = 0
	os.Exit(m.Run())
}
