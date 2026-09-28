package handoffdelivery

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
)

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestFrameBoundaryAndDecodeGuards(t *testing.T) {
	req := request{Epoch: 2}
	var frame bytes.Buffer
	require.NoError(t, writeFrame(&frame, req, maxRequestBytes))
	raw := bytes.Clone(frame.Bytes())
	size := int(binary.BigEndian.Uint32(raw[:4]))
	require.Equal(t, len(raw)-4, size)
	var exact bytes.Buffer
	require.NoError(t, writeFrame(&exact, req, size))
	require.ErrorIs(t, writeFrame(io.Discard, req, size-1), ErrBundle)
	var decoded request
	require.NoError(t, readFrame(bytes.NewReader(raw), &decoded, size))
	require.Equal(t, req.Epoch, decoded.Epoch)
	require.ErrorIs(t, readFrame(bytes.NewReader(raw), &decoded, size-1), ErrBundle)
	boom := errors.New("write failed")
	require.ErrorIs(t, writeAll(failingWriter{boom}, []byte{1}), boom)
	require.ErrorIs(t, writeFrame(failingWriter{boom}, req, size), boom)
	bad := []byte{0, 0, 0, 1, 0xff}
	require.Error(t, readFrame(bytes.NewReader(bad), &decoded, size))
}

type testProvider struct{ bundle *Bundle }

func (p testProvider) HandoffBundle(context.Context, uint64) (*Bundle, error) {
	if p.bundle == nil {
		return nil, errors.New("unavailable")
	}
	return p.bundle, nil
}

func TestBundleTransportBoundsAndEpochSelection(t *testing.T) {
	server, err := NewServer(testProvider{})
	require.NoError(t, err)
	var exchange bytes.Buffer
	require.NoError(t, writeFrame(&exchange, request{Epoch: 2}, maxRequestBytes))
	require.NoError(t, server.Serve(context.Background(), &exchange))
	var rsp response
	require.NoError(t, readFrame(&exchange, &rsp, maxResponseBytes))
	require.Equal(t, "handoff unavailable", rsp.Error)

	bundle := &Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}},
		Body: evmroot.TrustBaseBodyV2{Epoch: 2}}
	server, err = NewServer(testProvider{bundle: bundle})
	require.NoError(t, err)
	exchange.Reset()
	require.NoError(t, writeFrame(&exchange, request{Epoch: 3}, maxRequestBytes))
	require.NoError(t, server.Serve(context.Background(), &exchange))
	require.NoError(t, readFrame(&exchange, &rsp, maxResponseBytes))
	require.Equal(t, "handoff epoch mismatch", rsp.Error)

	var oversized bytes.Buffer
	oversized.Write([]byte{0x01, 0x00, 0x00, 0x00})
	require.ErrorIs(t, readFrame(&oversized, &request{}, maxRequestBytes), ErrBundle)
}
