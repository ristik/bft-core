package nb2ref

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
)

func TestFlatResourceBoundaryFixtures(t *testing.T) {
	type budget struct {
		Object, Layer        string
		Inclusive, FirstOver int
	}
	bounds := []budget{
		{"cold calldata", "contract ABI framing", FlatMaxCalldata, FlatMaxCalldata + 1},
		{"signed transaction", "wallet and peer/pool admission", 524288, 524289},
		{"ordinary gas capacity", "deployment block admission", 60_000_000, 60_000_001},
		{"worst approved submitted gas", "wallet and release qualification", 24_000_000, 24_000_001},
		{"separately framed receipt", "contract packet framing", FlatMaxReceipt, FlatMaxReceipt + 1},
		{"EVM UC", "receipt proof decoding", MaxEVMUCBytes, MaxEVMUCBytes + 1},
		{"header RLP", "receipt proof decoding", MaxHeaderBytes, MaxHeaderBytes + 1},
		{"receipt path nodes", "receipt proof decoding", MaxReceiptNodes, MaxReceiptNodes + 1},
		{"receipt branch", "receipt proof decoding", MaxReceiptBranchNodeLen, MaxReceiptBranchNodeLen + 1},
		{"receipt leaf", "receipt proof decoding", MaxReceiptLeafNodeLen, MaxReceiptLeafNodeLen + 1},
		{"root reason", "flat evidence object decoding", MaxJustificationBytes, MaxJustificationBytes + 1},
		{"root mint", "flat evidence object decoding", FlatMaxRootMint, FlatMaxRootMint + 1},
		{"child mint", "flat evidence object decoding", FlatMaxChildMint, FlatMaxChildMint + 1},
		{"allocation bytes", "flat evidence object decoding", FlatMaxAllocation, FlatMaxAllocation + 1},
		{"sum steps", "flat evidence object decoding", 256, 257},
		{"mint proof and transfer count", "flat evidence object decoding", FlatMaxPair, FlatMaxPair + 1},
		{"transfer pair", "flat evidence object decoding", FlatMaxPair, FlatMaxPair + 1},
		{"aggregator UC", "flat evidence object decoding", MaxAggregatorUCBytes, MaxAggregatorUCBytes + 1},
		{"RSMT and sparse path bytes", "native/packet opening decoding", 8224, 8225},
		{"page openings", "contract packet framing", FlatMaxPages, FlatMaxPages + 1},
		{"operations", "contract packet framing", FlatMaxOperations, FlatMaxOperations + 1},
		{"batch input", "B1 aggregate scanner", b1ref.MaxCallBytes, b1ref.MaxCallBytes + 1},
		{"B1 claims", "B1 aggregate scanner", b1ref.MaxClaims, b1ref.MaxClaims + 1},
		{"B1 seal signatures", "B1 native scanner", b1ref.MaxSigsPerSeal, b1ref.MaxSigsPerSeal + 1},
		{"B1 shard path steps", "B1 native scanner", b1ref.MaxShardSiblings, b1ref.MaxShardSiblings + 1},
		{"B1 unicity path steps", "B1 native scanner", b1ref.MaxUnicitySteps, b1ref.MaxUnicitySteps + 1},
		{"gap proofs", "cold packet framing", FlatMaxGaps, FlatMaxGaps + 1},
	}
	if dir := os.Getenv("NB2_FLAT_VECTOR_OUT"); dir != "" {
		data, err := json.MarshalIndent(bounds, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "layer-boundaries.json"), append(data, '\n'), 0644))
	}

	t.Run("32-and-33-pages", func(t *testing.T) {
		e := mustFlatEvidence(t, bytes.Repeat([]byte{0x48}, 33*FlatPageBytes))
		p := FlatRunPacket{Header: e.Header(), Operations: []FlatOperation{{Code: FlatTransfer, Claims: []FlatClaimOpening{{}}}}}
		for i := range uint64(FlatMaxPages) {
			page, err := e.Page(i)
			require.NoError(t, err)
			require.True(t, page.verifies(p.Header))
			p.Pages = append(p.Pages, page)
		}
		wire, err := p.Calldata()
		require.NoError(t, err)
		decoded, err := DecodeFlatRun(wire)
		require.NoError(t, err)
		require.Len(t, decoded.Pages, FlatMaxPages)
		raw, err := FlatRun.DecodeCalldata(wire)
		require.NoError(t, err)
		raw[43] = 33
		_, err = DecodeFlatRun(wire)
		require.ErrorIs(t, err, ErrFlatPacket)
		flatRecordRefusal(t, "page-count-33", wire, "BadPacket", nil)
	})

	t.Run("depth-16-and-17", func(t *testing.T) {
		nested := func(n int) []byte { return append(bytes.Repeat([]byte{0x81}, n), 0x00) }
		_, err := scanOne(nested(16))
		require.NoError(t, err)
		_, err = scanOne(nested(17))
		require.ErrorIs(t, err, ErrInputTooLarge)
		raw := CBytes(nested(16))
		b, err := scanOne(raw)
		require.NoError(t, err)
		content, err := b.bstr()
		require.NoError(t, err)
		_, err = scanOne(content)
		require.NoError(t, err)
		for _, bytes := range [][]byte{{0x98, 1, 0}, {0x9f, 0, 0xff}, {0xd9, 0x98}, {0xa0}, {0x60}} {
			_, err = scanOne(bytes)
			require.Error(t, err)
		}
	})
}
