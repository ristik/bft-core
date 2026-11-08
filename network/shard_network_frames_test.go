package network

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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
