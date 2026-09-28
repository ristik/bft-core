package handoffdelivery

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
)

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
