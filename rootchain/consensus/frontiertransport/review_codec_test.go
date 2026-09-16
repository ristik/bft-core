package frontiertransport

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-go-base/types"
)

func reviewFrontierRequest(shard []byte) FrontierRequest {
	return FrontierRequest{Version: 1, Context: frontiercodec.Context{
		NetworkID: 5, PartitionID: 1, RootEpoch: 1,
		CanonicalShardBytes:   shard,
		FullShardConfHash:     bytes.Repeat([]byte{1}, 32),
		GenesisOriginIdentity: bytes.Repeat([]byte{2}, 32),
	}, Nonce: bytes.Repeat([]byte{3}, 32)}
}

func TestReviewRequestShardIdentityBounds(t *testing.T) {
	long := make([]byte, 513)
	long[len(long)-1] = 0x40 // 4097 bits: byte length alone cannot enforce 4096 bits.
	for _, tc := range []struct {
		name  string
		shard []byte
	}{
		{"absent", nil},
		{"missing end marker", []byte{0}},
		{"trailing zero", []byte{0x80, 0}},
		{"one bit past bound", long},
		{"past byte bound", append(bytes.Repeat([]byte{0}, 513), 0x80)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewFrontierRequest(tc.shard)
			_, err := EncodeFrontierRequest(r)
			require.Error(t, err)
			raw, err := types.Cbor.Marshal(r) // bypass sender validation to test the receiver independently.
			require.NoError(t, err)
			_, err = DecodeFrontierRequest(raw)
			require.Error(t, err)
			cut := CutRequest{Version: r.Version, Context: r.Context, Nonce: r.Nonce, AcquisitionBinding: bytes.Repeat([]byte{4}, 32), Floor: 7}
			_, err = EncodeCutRequest(cut)
			require.Error(t, err)
			raw, err = types.Cbor.Marshal(cut)
			require.NoError(t, err)
			_, err = DecodeCutRequest(raw)
			require.Error(t, err)
		})
	}
}

func TestReviewRequestAcceptsCanonicalShardAtBoundaryWithoutMutation(t *testing.T) {
	boundary := make([]byte, 513)
	boundary[len(boundary)-1] = 0x80
	for _, shard := range [][]byte{{0x80}, {0x40}, boundary} {
		r := reviewFrontierRequest(bytes.Clone(shard))
		before := bytes.Clone(r.Context.CanonicalShardBytes)
		raw, err := EncodeFrontierRequest(r)
		require.NoError(t, err)
		require.Equal(t, before, r.Context.CanonicalShardBytes)
		decoded, err := DecodeFrontierRequest(raw)
		require.NoError(t, err)
		require.Equal(t, before, decoded.Context.CanonicalShardBytes)
		decoded.Context.CanonicalShardBytes[0] ^= 0xff
		again, err := DecodeFrontierRequest(raw)
		require.NoError(t, err)
		require.Equal(t, before, again.Context.CanonicalShardBytes)
	}
}
