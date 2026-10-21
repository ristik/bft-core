package bridgeprofile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// gateOf is the protocol-4 gate over explicit dimensions: Cfg and envelope bytes, history bytes, leaves with RSMT siblings each,
// and the batch charge of the anchor table.
func gateOf(cfg, envelope, history, leaves, siblings int, batch uint64) uint64 {
	g := Gate{Intrinsic: IntrinsicGas(cfg, envelope), B2: B2Gas(KernelRequestBytes(cfg, history), leaves), Batch: batch}
	gas, _, err := LeafPathGas(LeafProof{Bitmap: bitmapOf(siblings), Siblings: make([][32]byte, siblings)})
	if err != nil {
		panic(err)
	}
	g.RSMT = uint64(leaves) * gas
	return g.Total()
}

func bitmapOf(n int) (b [32]byte) {
	for i := 0; i < n; i++ {
		b[i/8] |= 0x80 >> uint(i%8)
	}
	return
}

// TestGateWorkedTable pins the gate formula of briefs/b1-any-age-contract.md section 5 to the contract's worked budget table:
// Cfg 512 bytes, history 16,384 bytes, sixteen leaves with eight RSMT siblings each, and the table's envelope sizes and native
// batch charges (which b1ref's worked vectors produce). The rows price each shape; none is refused (owner section 36).
func TestGateWorkedTable(t *testing.T) {
	for _, row := range []struct {
		envelope int
		batch    uint64
		gate     uint64
	}{
		{24_768, 132_730, 4_301_234},   // N=4, A=1
		{29_088, 353_428, 4_936_652},   // N=4, A=4, distinct epochs
		{46_368, 517_720, 6_759_824},   // N=4, A=16, shared seal
		{46_368, 1_326_220, 7_568_324}, // N=4, A=16, distinct epochs
		{42_016, 468_520, 6_292_832},   // N=16, A=8, shared seal
		{42_016, 1_349_820, 7_174_132}, // N=16, A=8, distinct epochs
		{60_704, 2_702_476, 10_320_836},
	} {
		require.Equal(t, row.gate, gateOf(512, row.envelope, 16_384, 16, 8, row.batch), "envelope %d batch %d", row.envelope, row.batch)
	}
	require.Equal(t, uint64(591_120), B2Gas(KernelRequestBytes(512, 16_384), 16))
}
