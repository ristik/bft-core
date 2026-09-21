// Package engineapi is one shardnode.Executor implementation: it drives an
// Ethereum execution client (reth) over the standard Engine API. Every
// Ethereum-specific type and every JSON-RPC method name is confined to this
// package — see docs/adr/0001-executor-boundary.md decision 1.
//
// Types here are hand-rolled against the Cancun Engine API spec
// (execution-apis/src/engine/cancun.md) rather than imported from
// go-ethereum, to keep that dependency indirect (decision 1 again). Pinned
// to the V3 method family; see decision 3 and adapter.go's startup
// capability check for why V3 is a schedule commitment, not just a version
// number.
package engineapi

// ExecutionPayloadV3 is the Cancun execution payload: everything
// engine_newPayloadV3 validates and engine_getPayloadV3 returns (wrapped —
// see GetPayloadV3Response). Field order here follows the spec's own
// ordering, not alphabetical, so a diff against the spec stays legible.
type ExecutionPayloadV3 struct {
	ParentHash    data32         `json:"parentHash"`
	FeeRecipient  data20         `json:"feeRecipient"`
	StateRoot     data32         `json:"stateRoot"`
	ReceiptsRoot  data32         `json:"receiptsRoot"`
	LogsBloom     data           `json:"logsBloom"`
	PrevRandao    data32         `json:"prevRandao"`
	BlockNumber   quantity       `json:"blockNumber"`
	GasLimit      quantity       `json:"gasLimit"`
	GasUsed       quantity       `json:"gasUsed"`
	Timestamp     quantity       `json:"timestamp"`
	ExtraData     data           `json:"extraData"`
	BaseFeePerGas quantity       `json:"baseFeePerGas"`
	BlockHash     data32         `json:"blockHash"`
	Transactions  []data         `json:"transactions"` // each entry: one RLP-encoded signed transaction
	Withdrawals   []WithdrawalV1 `json:"withdrawals"`
	BlobGasUsed   quantity       `json:"blobGasUsed"`
	ExcessBlobGas quantity       `json:"excessBlobGas"`
}

// WithdrawalV1 — always an empty slice in this framework (RoundParams
// derivation table, "withdrawals"): there is no beacon chain to originate
// one from. The type still needs to exist so ExecutionPayloadV3/
// PayloadAttributesV3 round-trip through a real reth's JSON encoding.
type WithdrawalV1 struct {
	Index          quantity `json:"index"`
	ValidatorIndex quantity `json:"validatorIndex"`
	Address        data20   `json:"address"`
	Amount         quantity `json:"amount"`
}

// ForkchoiceStateV1 names the three block hashes a forkchoiceUpdated call
// sets. This framework always sets all three to the same hash — see
// adapter.go's Commit — because there is no separate notion of "safe" vs
// "finalized" here: a Unicity Certificate is absolute, one-shot finality,
// not the head/safe/finalized ladder Ethereum's own consensus uses.
type ForkchoiceStateV1 struct {
	HeadBlockHash      data32 `json:"headBlockHash"`
	SafeBlockHash      data32 `json:"safeBlockHash"`
	FinalizedBlockHash data32 `json:"finalizedBlockHash"`
}

// PayloadAttributesV3 is what engineapi/params.go derives, deterministically,
// from a shardnode.RoundParams — see the derivation table in
// docs/engine-api-adapter-plan.md §6. ParentBeaconBlockRoot is included here
// (required by V3) even though, unlike real Ethereum, it never needs to be
// disseminated to followers: every validator derives it independently from
// the same certificate (see codec.go's ProposalEnvelope for what actually
// gets sent over the wire, and why this field is deliberately absent from it).
type PayloadAttributesV3 struct {
	Timestamp             quantity       `json:"timestamp"`
	PrevRandao            data32         `json:"prevRandao"`
	SuggestedFeeRecipient data20         `json:"suggestedFeeRecipient"`
	Withdrawals           []WithdrawalV1 `json:"withdrawals"`
	ParentBeaconBlockRoot data32         `json:"parentBeaconBlockRoot"`
}

// UnicityPayloadAttributes is the payloadAttributes parameter of
// engine_forkchoiceUpdatedWithSealV1: the standard V3 attributes above plus the
// 32-byte commitment the built block's header extraData must carry.
//
// It is a distinct type rather than an extra field on PayloadAttributesV3
// because reth's own UnicityPayloadAttributes is a distinct type that flattens
// the stock attributes and adds commitment as a REQUIRED field
// (crates/unicity/payload/src/lib.rs). Sending the plain V3 attributes to the
// seal sibling would fail to decode on the far side with a missing-field error,
// not merely omit a default, so this mirrors the far side exactly. The standard
// ForkchoiceUpdatedV3 keeps the plain type and emits exactly the same JSON it
// did before.
type UnicityPayloadAttributes struct {
	PayloadAttributesV3
	Commitment data32 `json:"commitment"`
}

// PayloadStatus mirrors the enum PayloadStatusV1.status takes. See
// docs/engine-api-adapter-plan.md §6 "Status policy" for what each value
// means for certification, and adapter.go's toStatus for the mapping onto
// shardnode.Status.
type PayloadStatus string

const (
	PayloadStatusValid            PayloadStatus = "VALID"
	PayloadStatusInvalid          PayloadStatus = "INVALID"
	PayloadStatusSyncing          PayloadStatus = "SYNCING"
	PayloadStatusAccepted         PayloadStatus = "ACCEPTED"
	PayloadStatusInvalidBlockHash PayloadStatus = "INVALID_BLOCK_HASH"
)

// PayloadStatusV1 is returned by both engine_newPayloadV3 and as the
// payloadStatus field of engine_forkchoiceUpdatedV3's response.
type PayloadStatusV1 struct {
	Status          PayloadStatus `json:"status"`
	LatestValidHash *data32       `json:"latestValidHash"`
	ValidationError *string       `json:"validationError"`
}

// ForkchoiceUpdatedResponse is engine_forkchoiceUpdatedV3's result.
// PayloadID is non-nil only when payloadAttributes was supplied and
// building started — i.e. only when this call was the leader's Build.
type ForkchoiceUpdatedResponse struct {
	PayloadStatus PayloadStatusV1 `json:"payloadStatus"`
	PayloadID     *data           `json:"payloadId"`
}

// BlobsBundleV1 accompanies a payload when it carries blob transactions.
// Exec-mode prohibits blob transactions outright (see the ProposalEnvelope
// doc comment in codec.go) — a non-empty bundle here is a bug to catch, not
// a payload to propagate. The type exists so GetPayloadV3Response decodes
// a real reth response correctly regardless.
type BlobsBundleV1 struct {
	Commitments []data `json:"commitments"`
	Proofs      []data `json:"proofs"`
	Blobs       []data `json:"blobs"`
}

// GetPayloadV3Response is engine_getPayloadV3's actual result shape — a
// wrapper, not a bare ExecutionPayloadV3. BlockValue and
// ShouldOverrideBuilder are for MEV-Boost-style builder markets, irrelevant
// to a single-designated-leader shard; kept only so decoding a real
// response doesn't drop fields silently.
type GetPayloadV3Response struct {
	ExecutionPayload      ExecutionPayloadV3 `json:"executionPayload"`
	BlockValue            quantity           `json:"blockValue"`
	BlobsBundle           BlobsBundleV1      `json:"blobsBundle"`
	ShouldOverrideBuilder bool               `json:"shouldOverrideBuilder"`
}

// GetPayloadWithSealV1Response is engine_getPayloadWithSealV1's result. It is
// NOT the stock ExecutionPayloadEnvelopeV3: D2 fixes the shape as
// { executionPayload, blockValue, sealCompanion }, with no blobsBundle and no
// shouldOverrideBuilder.
//
// BlockValue keeps the same quantity type as GetPayloadV3Response above.
// reth's U256 serialises through ruint as a minimal 0x-prefixed lowercase hex
// number — "0x0" for zero, "0x1234" for 4660, no leading zeros — which is
// exactly the QUANTITY convention quantity implements, so the two agree on the
// wire. quantity is uint64, so a block value above 2^64-1 would be refused on
// decode; exec-mode values are far below that, and this keeps the one existing
// block-value type rather than adding a second 256-bit one for a single field.
type GetPayloadWithSealV1Response struct {
	ExecutionPayload ExecutionPayloadV3 `json:"executionPayload"`
	BlockValue       quantity           `json:"blockValue"`
	SealCompanion    SealCompanion      `json:"sealCompanion"`
}
