package gettrustbase

import (
	"bufio"
	"bytes"
	"github.com/unicitynetwork/bft-go-base/types"
	"testing"

	"github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

type testPeer struct{ p *network.Peer }

func testutilsPeer(t *testing.T) *testPeer {
	return &testPeer{p: peer.CreatePeer(t, peer.CreatePeerConfiguration(t))}
}

// decodeFrame reads one length-prefixed response frame.
func decodeFrame(b []byte) (*types.TrustBaseResponse, [][]byte, error) {
	raw, err := readFrame(bufio.NewReader(bytes.NewReader(b)), types.DefaultTrustBaseMaxResponse)
	if err != nil {
		return nil, nil, err
	}
	r, _, err := types.DecodeTrustBaseResponse(raw, types.TrustBasePageLimits)
	return r, nil, err
}
