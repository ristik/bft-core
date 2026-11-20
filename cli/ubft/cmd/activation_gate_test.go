package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
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

type fakeCommitted struct {
	shardnode.Executor
	ref shardnode.BlockRef
	err error
}

func (f fakeCommitted) Finalized(context.Context) (shardnode.BlockRef, error) { return f.ref, f.err }

func TestCommittedAnchorNeverPanics(t *testing.T) {
	ctx := context.Background()
	// an RPC error yields an empty reference: an error, not a conversion panic
	_, _, err := committedAnchor(ctx, fakeCommitted{err: errors.New("rpc down")})
	require.Error(t, err)
	// a short hash is refused
	_, _, err = committedAnchor(ctx, fakeCommitted{ref: shardnode.BlockRef{Number: 3, Hash: shardnode.Hash{1, 2}}})
	require.Error(t, err)
	// an executor with no committed block
	_, _, err = committedAnchor(ctx, nil)
	require.Error(t, err)
	h := make(shardnode.Hash, 32)
	h[0] = 7
	got, n, err := committedAnchor(ctx, fakeCommitted{ref: shardnode.BlockRef{Number: 3, Hash: h}})
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	require.Equal(t, byte(7), got[0])
}

func TestDeferredProvisioningCarriesTheStartupPins(t *testing.T) {
	word, code, gen, other := [32]byte{1}, [32]byte{2}, [32]byte{3}, [32]byte{9}
	// startup URL + file {profile, genesis}: the URL is not a conflict, it stands
	got, url, err := mergePins(vrFence{VR: true, NetworkWord: &word}, "http://x", "", &code, &gen)
	require.NoError(t, err)
	require.Equal(t, "http://x", url)
	require.Equal(t, vrFence{VR: true, NetworkWord: &word, CodeHash: &code, GenesisHash: &gen}, got)
	// startup genesis + file {profile, URL}: the genesis (omitted in the file) stands
	got, url, err = mergePins(vrFence{VR: true, NetworkWord: &word, GenesisHash: &gen}, "", "http://y", &code, nil)
	require.NoError(t, err)
	require.Equal(t, "http://y", url)
	require.Equal(t, vrFence{VR: true, NetworkWord: &word, CodeHash: &code, GenesisHash: &gen}, got)
	// the same pins as an immediate start with everything given, and equal values on both sides
	imm := vrFence{VR: true, NetworkWord: &word, CodeHash: &code, GenesisHash: &gen}
	got, url, err = mergePins(imm, "http://x", "http://x", &code, &gen)
	require.NoError(t, err)
	require.Equal(t, imm, got)
	require.Equal(t, "http://x", url)
	// a pin only the file gives stands
	got, _, err = mergePins(vrFence{VR: true, NetworkWord: &word}, "", "http://x", &code, &gen)
	require.NoError(t, err)
	require.Equal(t, &gen, got.GenesisHash)
	require.Equal(t, &word, got.NetworkWord)
	// two present, different values conflict
	_, _, err = mergePins(vrFence{VR: true, GenesisHash: &other}, "", "http://x", &code, &gen)
	require.Error(t, err)
	_, _, err = mergePins(vrFence{VR: true, CodeHash: &other}, "", "http://x", &code, &gen)
	require.Error(t, err)
	_, _, err = mergePins(vrFence{VR: true}, "http://a", "http://b", &code, &gen)
	require.Error(t, err)
}
