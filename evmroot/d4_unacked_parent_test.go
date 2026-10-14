package evmroot

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// The marker of an unacknowledged root-only handoff (ControlState.UnackedParent, #604) decides what the next Prepare may do, so roots,
// checkpoints and recovery must agree on it through the control digest. This pins the digest: the optional tail is positional
// (FrozenParent, Pos, UnackedParent), absent entirely when the marker is empty (so every existing digest is unchanged), and the marker
// changes the digest by its presence and by its value.
func TestControlDigestCommitsTheUnackedParent(t *testing.T) {
	base := ControlState{Network: 5, Epoch: 2, Attempt: 1, OrderedRound: 40, PredecessorBodyID: bytes.Repeat([]byte{1}, 32), Phase: "idle",
		RecordBytes: []byte{9}, PreviousDigest: bytes.Repeat([]byte{2}, 32)}
	head := func() cArray {
		return cArray{cText("UNICITY_ROOT_HANDOFF_STATE"), cUint(1), cUint(5), cUint(2), cBytes(base.PredecessorBodyID), cUint(1), cText("idle"), cUint(40),
			cBytes(base.RecordBytes), cBytes(base.PreviousDigest)}
	}
	marker := bytes.Repeat([]byte{0x42}, 32)

	// empty marker: the encodings that existed before the field are unchanged
	require.Equal(t, marshalCBOR(head()), base.Bytes())
	withParent := base
	withParent.FrozenParent = bytes.Repeat([]byte{3}, 32)
	require.Equal(t, marshalCBOR(append(head(), cBytes(withParent.FrozenParent))), withParent.Bytes())
	withPos := withParent
	withPos.Pos = []byte{7, 7}
	require.Equal(t, marshalCBOR(append(head(), cBytes(withPos.FrozenParent), cBytes(withPos.Pos))), withPos.Bytes())

	// the marker is the third optional slot; the slots before it stay in place even when empty
	marked := base
	marked.UnackedParent = marker
	require.Equal(t, marshalCBOR(append(head(), cBytes(nil), cBytes(nil), cBytes(marker))), marked.Bytes())
	full := withPos
	full.UnackedParent = marker
	require.Equal(t, marshalCBOR(append(head(), cBytes(full.FrozenParent), cBytes(full.Pos), cBytes(marker))), full.Bytes())

	// presence and value both change the digest
	other := marked
	other.UnackedParent = bytes.Repeat([]byte{0x43}, 32)
	require.NotEqual(t, base.Digest(), marked.Digest())
	require.NotEqual(t, marked.Digest(), other.Digest())
	require.NotEqual(t, withPos.Digest(), full.Digest())
}
