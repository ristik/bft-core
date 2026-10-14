package gettrustbase

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

type testPeer struct{ p *network.Peer }

func testutilsPeer(t *testing.T) *testPeer {
	return &testPeer{p: peer.CreatePeer(t, peer.CreatePeerConfiguration(t))}
}

// decodeFrame reads one length-prefixed response frame.
func decodeFrame(b []byte) (*Response, [][]byte, error) {
	raw, err := readFrame(bufio.NewReader(bytes.NewReader(b)), DefaultMaxResponse)
	if err != nil {
		return nil, nil, err
	}
	r, _, err := DecodeResponse(raw, PageLimits)
	return r, nil, err
}
