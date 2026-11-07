package network

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
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
