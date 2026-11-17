package evmroot

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// The VR root state is the last positional slot of the control state: absent (and the P85 encoding unchanged) when empty, committed by the
// digest when present, with the earlier slots kept even when they are empty.
func TestControlStateVRSlot(t *testing.T) {
	s := ControlState{Network: 5, Epoch: 1, PredecessorBodyID: make([]byte, 32), Phase: "idle", Pos: []byte{1}}
	p85 := s.Bytes()
	s.VR = nil
	require.Equal(t, p85, s.Bytes())
	s.VR = []byte{7}
	vr := s.Bytes()
	require.NotEqual(t, p85, vr)
	require.True(t, bytes.HasSuffix(vr, []byte{0x40, 0x41, 7}), "an empty UnackedParent slot precedes the VR slot")
	d := s.Digest()
	s.VR = []byte{8}
	require.NotEqual(t, d, s.Digest())
}
