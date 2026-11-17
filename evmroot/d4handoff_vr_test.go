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

// The P85 endorsed state's primary result is the slot after VR, positional, absent when empty.
func TestControlStatePrimaryResultSlot(t *testing.T) {
	s := ControlState{Network: 5, Epoch: 1, PredecessorBodyID: make([]byte, 32), Phase: "endorsed", FrozenParent: make([]byte, 32), Pos: []byte{1}}
	without := s.Bytes()
	s.PrimaryResult = bytes.Repeat([]byte{9}, 32)
	with := s.Bytes()
	require.NotEqual(t, without, with)
	require.True(t, bytes.HasSuffix(with, append([]byte{0x40, 0x40, 0x58, 0x20}, s.PrimaryResult...)), "empty UnackedParent and VR slots precede it")
}
