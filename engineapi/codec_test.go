package engineapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// samplePayload is a fully populated ExecutionPayloadV3 whose slice fields are
// non-nil. That keeps a JSON round trip comparable with require.Equal instead
// of tripping over a nil-vs-empty difference that would hide a real one.
func samplePayload() ExecutionPayloadV3 {
	return ExecutionPayloadV3{
		ParentHash:    fixedHash(0x11),
		FeeRecipient:  data20{0x22},
		StateRoot:     fixedHash(0x33),
		ReceiptsRoot:  fixedHash(0x44),
		LogsBloom:     data{0x01, 0x02},
		PrevRandao:    fixedHash(0x55),
		BlockNumber:   quantity(7),
		GasLimit:      quantity(30_000_000),
		GasUsed:       quantity(21_000),
		Timestamp:     quantity(1_700_000_000),
		ExtraData:     data{0xde, 0xad},
		BaseFeePerGas: quantity(1_000_000_000),
		BlockHash:     fixedHash(0x66),
		Transactions:  []data{{0xaa}, {0xbb, 0xcc}},
		Withdrawals:   []WithdrawalV1{},
		BlobGasUsed:   quantity(0),
		ExcessBlobGas: quantity(0),
	}
}

// sampleCompanion is a populated SealCompanion with a non-nil witness list, so
// it compares equal after a JSON round trip.
func sampleCompanion() *SealCompanion {
	return &SealCompanion{
		RootInput:  data{0x01, 0x02, 0x03},
		Witnesses:  []data{{0xaa, 0xbb}, {0xcc}},
		Provenance: "build",
	}
}

func TestProposalEnvelopeRoundTripsWithAndWithoutSealCompanion(t *testing.T) {
	payload := samplePayload()

	withCompanion := ProposalEnvelope{
		ExecutionPayload:            payload,
		ExpectedBlobVersionedHashes: []data32{},
		SealCompanion:               sampleCompanion(),
	}
	raw, err := json.Marshal(withCompanion)
	require.NoError(t, err)
	var decodedWith ProposalEnvelope
	require.NoError(t, json.Unmarshal(raw, &decodedWith))
	require.Equal(t, withCompanion, decodedWith)

	withoutCompanion := ProposalEnvelope{
		ExecutionPayload:            payload,
		ExpectedBlobVersionedHashes: []data32{},
	}
	raw, err = json.Marshal(withoutCompanion)
	require.NoError(t, err)
	var decodedWithout ProposalEnvelope
	require.NoError(t, json.Unmarshal(raw, &decodedWithout))
	require.Equal(t, withoutCompanion, decodedWithout)
	require.Nil(t, decodedWithout.SealCompanion)
}

func TestProposalEnvelopeWithoutSealCompanionMatchesLegacyJSON(t *testing.T) {
	payload := samplePayload()

	// The pre-W1 shape: exactly the two fields the envelope had before
	// sealCompanion existed.
	type legacyEnvelope struct {
		ExecutionPayload            ExecutionPayloadV3 `json:"executionPayload"`
		ExpectedBlobVersionedHashes []data32           `json:"expectedBlobVersionedHashes"`
	}
	legacy, err := json.Marshal(legacyEnvelope{
		ExecutionPayload:            payload,
		ExpectedBlobVersionedHashes: []data32{},
	})
	require.NoError(t, err)

	current, err := json.Marshal(ProposalEnvelope{
		ExecutionPayload:            payload,
		ExpectedBlobVersionedHashes: []data32{},
	})
	require.NoError(t, err)

	require.Equal(t, string(legacy), string(current),
		"an envelope with no companion must be byte-identical to the pre-W1 format")
	require.NotContains(t, string(current), "sealCompanion",
		"the omitempty pointer must not appear at all")
}

func TestDecodeBlockWithoutSealCompanionLeavesItNil(t *testing.T) {
	payload := samplePayload()
	block, err := EncodeBlock(payload)
	require.NoError(t, err)

	envelope, err := DecodeBlock(block)
	require.NoError(t, err)
	require.Nil(t, envelope.SealCompanion,
		"W1 populates nothing, so an envelope from EncodeBlock decodes with a nil companion")
	require.Equal(t, payload, envelope.ExecutionPayload)
	require.Equal(t, []data32{}, envelope.ExpectedBlobVersionedHashes)
}

func TestDecodeBlockDecodesASealCompanion(t *testing.T) {
	raw, err := json.Marshal(ProposalEnvelope{
		ExecutionPayload:            samplePayload(),
		ExpectedBlobVersionedHashes: []data32{},
		SealCompanion:               sampleCompanion(),
	})
	require.NoError(t, err)

	envelope, err := DecodeBlock(shardnode.Block{Raw: raw})
	require.NoError(t, err)
	require.Equal(t, sampleCompanion(), envelope.SealCompanion)
}

func TestBlockSizeIsThePayloadJSONAlone(t *testing.T) {
	payload := samplePayload()
	block, err := EncodeBlock(payload)
	require.NoError(t, err)

	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	// BlockSize is the payload JSON length, not the envelope's. If EncodeBlock ever sized the
	// envelope instead, this would be larger.
	require.Equal(t, uint64(len(payloadJSON)), block.BlockSize)

	// TRIPWIRE: the companion cannot reach BlockSize today only because EncodeBlock has no
	// parameter for it. W2 gives EncodeBlock a companion, and the invariant then stops being
	// architectural and starts being testable. When that lands, this test must be strengthened to
	// encode the same payload with and without a companion and assert an identical BlockSize. Until
	// then there is nothing here to compare: there is no companion-bearing call to make.
}

func TestSealCompanionVector(t *testing.T) {
	companion := SealCompanion{
		RootInput:  data{0x01, 0x02, 0x03},
		Witnesses:  []data{{0xaa, 0xbb}, {0xcc}},
		Provenance: "build",
	}

	raw, err := json.Marshal(companion)
	require.NoError(t, err)
	// This is the wire contract ureth's
	// reth_unicity_execution::wire::SealCompanion decodes under
	// deny_unknown_fields: exactly rootInput, witnesses and provenance, in
	// that order, with 0x-prefixed hex DATA. Any fourth key or a base64 byte
	// string is a hard decode error on the other side.
	require.Equal(t,
		`{"rootInput":"0x010203","witnesses":["0xaabb","0xcc"],"provenance":"build"}`,
		string(raw))
}

func TestSealCompanionEmptyWitnessesEncodeAsArray(t *testing.T) {
	// A nil witness slice is the dangerous case: Go marshals it to null, and
	// ureth's Vec<Bytes> will not decode null. It has to be [].
	nilWitnesses, err := json.Marshal(SealCompanion{RootInput: data{0x01}, Provenance: "build"})
	require.NoError(t, err)
	require.Equal(t,
		`{"rootInput":"0x01","witnesses":[],"provenance":"build"}`,
		string(nilWitnesses))
	require.NotContains(t, string(nilWitnesses), "null")

	// An explicit empty slice must encode identically.
	emptyWitnesses, err := json.Marshal(SealCompanion{
		RootInput:  data{0x01},
		Witnesses:  []data{},
		Provenance: "build",
	})
	require.NoError(t, err)
	require.Equal(t, string(nilWitnesses), string(emptyWitnesses))
}
