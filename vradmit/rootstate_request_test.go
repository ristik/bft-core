package vradmit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func testRequest(intent byte) vrschema.PoPRequest {
	return vrschema.PoPRequest{Epoch: 3, Network: 7, Predecessor: bytes.Repeat([]byte{1}, 32), ResultID: bytes.Repeat([]byte{2}, 32), Attempt: 0,
		Roster: []uint64{1, 2, 3, 5}, Deadline: 4_106, Intent: bytes.Repeat([]byte{intent}, 32)}
}

// #1319: the PoP request is encoded only while held (version 3), so a state without one keeps its version 2 bytes and digest; the
// encoding round-trips exactly, the request is committed once per intent, and the block end drops it once the epoch is another.
func TestRootStateCarriesThePoPRequestOnlyWhileHeld(t *testing.T) {
	s := GenesisRootState(3, 4)
	v2, err := s.Encode()
	require.NoError(t, err)
	d2, err := s.Digest()
	require.NoError(t, err)

	held, err := s.ApplyPoPRequest(testRequest(9))
	require.NoError(t, err)
	raw, err := held.Encode()
	require.NoError(t, err)
	require.NotEqual(t, v2, raw)
	back, err := DecodeRootState(raw)
	require.NoError(t, err)
	require.Equal(t, testRequest(9), *back.Request)
	again, err := back.Encode()
	require.NoError(t, err)
	require.Equal(t, raw, again)

	_, err = held.ApplyPoPRequest(testRequest(9))
	require.ErrorIs(t, err, vrschema.ErrPoPMiss, "once per intent")
	newer, err := held.ApplyPoPRequest(testRequest(8))
	require.NoError(t, err, "a newer intent's request replaces it")
	require.Equal(t, bytes.Repeat([]byte{8}, 32), newer.Request.Intent)

	cleared := held
	cleared.Request = nil
	raw, err = cleared.Encode()
	require.NoError(t, err)
	require.Equal(t, v2, raw)
	d, err := cleared.Digest()
	require.NoError(t, err)
	require.Equal(t, d2, d)

	same, err := held.EndBlock(3, 50, ControlOf(nil), 4)
	require.NoError(t, err)
	require.NotNil(t, same.Request, "the same epoch keeps it")
	moved := held
	moved.Backoff.Epoch = 4
	moved, err = moved.EndBlock(4, 50, ControlOf(nil), 4)
	require.NoError(t, err)
	require.Nil(t, moved.Request, "another epoch drops it")

	bad := testRequest(9)
	bad.Roster = []uint64{2, 1}
	_, err = s.ApplyPoPRequest(bad)
	require.ErrorIs(t, err, vrschema.ErrPoPMiss)
	held.Request = &bad
	_, err = held.Encode()
	require.ErrorIs(t, err, ErrRootState)
}
