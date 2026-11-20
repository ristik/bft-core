package cmd

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestActivationGateIsMandatoryOnAVRGeneration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// a VR generation without a source, or without the registry code pin, refuses to start
	_, _, err := newActivationGate(ctx, log, "", vrFence{VR: true})
	require.ErrorIs(t, err, errVRFenceRequired)
	_, _, err = newActivationGate(ctx, log, "http://127.0.0.1:1", vrFence{VR: true})
	require.ErrorIs(t, err, errVRFenceRequired)

	// a generation without VR keeps today's behaviour: no source, no gate
	g, closeFn, err := newActivationGate(ctx, log, "", vrFence{})
	require.NoError(t, err)
	require.Nil(t, g)
	closeFn()

	pin1 := [32]byte{1}
	_, _, err = newActivationGate(ctx, log, "http://127.0.0.1:1", vrFence{VR: true, CodeHash: &pin1})
	require.ErrorIs(t, err, errVRFenceRequired, "the generation's genesis pin is mandatory too")

	// with the pin and a URL the gate exists (the connection is lazy, nothing is read here)
	pin, err := parseCodeHash("0x" + string(make([]byte, 0)) + "0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	g, closeFn, err = newActivationGate(ctx, log, "http://127.0.0.1:1", vrFence{VR: true, CodeHash: pin, GenesisHash: &pin1})
	require.NoError(t, err)
	require.NotNil(t, g)
	closeFn()
	_, err = parseCodeHash("0x01")
	require.Error(t, err)
}
