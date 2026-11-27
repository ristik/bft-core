package network

import (
	"context"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A shard reads certification responses from root streams: the V2 and V3 receive protocols carry their declared payload limits (#952), which the
// stream handler enforces from the announced length (Test_LibP2PNetwork_MaxFrameSize), so an oversized frame is refused before decoding.
func TestShardReceiveProtocolsCarryTheirFrameLimits(t *testing.T) {
	limits := map[string]uint64{}
	for _, d := range shardReceiveProtocols() {
		limits[d.ProtocolID] = d.MaxFrameSize
	}
	require.EqualValues(t, certification.MaxCertificationResponseV1Frame, limits[ProtocolUnicityCertificates], "#956: the legacy frame is bounded too")
	require.EqualValues(t, certification.MaxCertificationResponseV2Frame, limits[ProtocolUnicityCertificatesV2])
	require.EqualValues(t, certification.MaxCertificationResponseV3Frame, limits[ProtocolUnicityCertificatesV3])
	require.Greater(t, limits[ProtocolUnicityCertificatesV3], limits[ProtocolUnicityCertificatesV2], "V3 also carries the attached entries")
	require.Len(t, limits, 3)
}

// #952, send side: the network serializer refuses a V3 response above the frame limit the shards enforce on receive, so it is never written to a stream.
func TestSerializeRefusesAnOversizeV3Response(t *testing.T) {
	cr := &certification.CertificationResponse{Partition: 1, Status: certification.CertStatusRequestInvalid,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1}}}
	require.NoError(t, cr.SetTechnicalRecord(certification.TechnicalRecord{Round: 1, Epoch: 1, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	entry := make([]byte, certification.MaxTrustBaseUpdateBytes)
	cr.Message = strings.Repeat("x", certification.MaxCertificationResponseV2Frame)
	_, err := serializeMsg(certification.NewCertificationResponseV3(cr, [][]byte{entry, entry}))
	require.ErrorIs(t, err, certification.ErrResponseV3)
	cr.Message = "ok"
	_, err = serializeMsg(certification.NewCertificationResponseV3(cr, [][]byte{entry, entry}))
	require.NoError(t, err)
}

// v1Response is a legacy response whose CBOR payload is exactly size bytes (the message is the padding).
func v1Response(t *testing.T, size int) (*certification.CertificationResponse, []byte) {
	t.Helper()
	cr := &certification.CertificationResponse{Partition: 1, Status: certification.CertStatusRequestInvalid,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1}}}
	require.NoError(t, cr.SetTechnicalRecord(certification.TechnicalRecord{Round: 1, Epoch: 1, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	encode := func(n int) []byte {
		cr.Message = strings.Repeat("x", n)
		data, err := types.Cbor.Marshal(cr)
		require.NoError(t, err)
		return data
	}
	lo, hi := 0, size // the payload grows with the message: find the message length that gives exactly size
	for lo < hi {
		mid := (lo + hi) / 2
		if len(encode(mid)) < size {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	data := encode(lo)
	require.Len(t, data, size, "the padding reaches the exact size")
	return cr, data
}

func TestTheLegacyFrameLimitIsDerivedFromTheV2Limit(t *testing.T) {
	require.Equal(t, certification.MaxCertificationResponseV2Frame, certification.MaxCertificationResponseV1Frame)
}

// #956, send side: the legacy serializer writes a payload of exactly the limit and refuses one byte more.
func TestLegacyFrameSendBoundary(t *testing.T) {
	limit := certification.MaxCertificationResponseV1Frame
	cr, _ := v1Response(t, limit)
	f := &certificationFrames{cr: cr}
	frame, err := f.legacy()
	require.NoError(t, err)
	require.NotEmpty(t, frame)

	over, _ := v1Response(t, limit+1)
	_, err = (&certificationFrames{cr: over}).legacy()
	require.ErrorIs(t, err, ErrLegacyFrameTooLarge)
}

// #956, receive side over a real stream: a legacy frame of exactly the limit is delivered; one byte more is refused from the announced length and never decoded.
func TestLegacyFrameReceiveBoundary(t *testing.T) {
	limit := certification.MaxCertificationResponseV1Frame
	senderPeer, p := createPeer(t), createPeer(t)
	nw, err := NewLibP2PNetwork(p, 10, observability.Default(t))
	require.NoError(t, err)
	senderPeer.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
	// the descriptors a shard really registers (not a test copy), so removing the V1 limit from them fails this test
	require.NoError(t, nw.RegisterReceiveProtocols(shardReceiveProtocols()))
	write := func(data []byte) {
		s, err := senderPeer.CreateStream(context.Background(), p.ID(), ProtocolUnicityCertificates)
		require.NoError(t, err)
		_, _ = s.Write(frameMsg(data))
		_ = s.Close()
	}
	_, over := v1Response(t, limit+1)
	write(over)
	requireNoMore(t, nw) // the oversized frame is not decoded or enqueued

	_, exact := v1Response(t, limit)
	write(exact)
	got, ok := recv(t, nw).(*certification.CertificationResponse)
	require.True(t, ok)
	again, err := types.Cbor.Marshal(got)
	require.NoError(t, err)
	require.Len(t, again, limit, "the frame of exactly the limit arrived whole")
}
