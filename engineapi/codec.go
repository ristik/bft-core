package engineapi

import (
	"encoding/json"
	"fmt"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// ProposalEnvelope is what the leader disseminates to followers — not a
// bare ExecutionPayloadV3. engine_newPayloadV3 takes three parameters
// (executionPayload, expectedBlobVersionedHashes, parentBeaconBlockRoot); a
// follower needs enough to reconstruct that exact call.
//
// parentBeaconBlockRoot is deliberately NOT a field here. Unlike real
// Ethereum, where the beacon root comes from consensus-layer state the EL
// cannot derive on its own, this framework's derivation (params.go) makes
// it a pure function of RoundParams — which every validator already has
// from the same certificate. Each follower recomputes it locally via
// DeriveAttributes rather than trusting a copied value; see
// docs/adr/0001-executor-boundary.md decision 2's sibling reasoning about
// not trusting recoverable values blindly.
//
// Blob transactions are prohibited outright for exec-mode, not merely
// unimplemented: ExpectedBlobVersionedHashes is always an explicit empty
// slice, never omitted or null, and Adapter.Build rejects any transaction
// carrying a blob before it can ever reach this envelope. A populated
// BlobsBundleV1 anywhere in this package is a bug, not a payload to
// propagate — see the build plan §6.
type ProposalEnvelope struct {
	ExecutionPayload            ExecutionPayloadV3 `json:"executionPayload"`
	ExpectedBlobVersionedHashes []data32           `json:"expectedBlobVersionedHashes"`
}

// EncodeBlock wraps a sealed, non-quiet ExecutionPayloadV3 into a
// shardnode.Block. Quiet rounds never reach this function — see adapter.go
// Seal, which detects an empty transaction list itself and constructs the
// quiet Block directly, the same way executortest.Fake does for its own
// zero-entries case.
func EncodeBlock(payload ExecutionPayloadV3) (shardnode.Block, error) {
	envelope := ProposalEnvelope{
		ExecutionPayload:            payload,
		ExpectedBlobVersionedHashes: []data32{},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: encoding proposal envelope: %w", err)
	}

	// BlockSize: the canonical JSON encoding of the execution payload
	// itself (excluding envelope-only dissemination metadata). This is a
	// deliberate, documented deviation from the build plan's original
	// "RLP-encoded block length" guidance — see the doc comment below for
	// why, and docs/adr/0001-executor-boundary.md for the fuller rationale.
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: encoding execution payload for sizing: %w", err)
	}

	return shardnode.Block{
		Number:     uint64(payload.BlockNumber),
		Hash:       shardnode.Hash(payload.BlockHash[:]),
		StateRoot:  shardnode.Hash(payload.StateRoot[:]),
		ParentHash: shardnode.Hash(payload.ParentHash[:]),
		Raw:        raw,
		BlockSize:  uint64(len(payloadJSON)), // #nosec G115 -- bounded by a single block's JSON size
		StateSize:  0,
	}, nil
}

// DecodeBlock is the follower side: recover the envelope a Verify /
// newPayload call needs from a disseminated Block.Raw.
func DecodeBlock(b shardnode.Block) (ProposalEnvelope, error) {
	var envelope ProposalEnvelope
	if err := json.Unmarshal(b.Raw, &envelope); err != nil {
		return ProposalEnvelope{}, fmt.Errorf("engineapi: decoding proposal envelope: %w", err)
	}
	return envelope, nil
}

/*
Why JSON size, not RLP size, for BlockSize:

docs/engine-api-adapter-plan.md's normative table specifies the canonical
Ethereum RLP block encoding, precisely to avoid an encoding that isn't
guaranteed byte-stable across implementations. That guidance is correct in
general — but implementing a hand-rolled RLP encoder for a full Cancun block
header (EIP-1559 base fee, EIP-4895 withdrawals, EIP-4844 blob fields,
EIP-4788 beacon root) without a reference implementation to verify against
is a real, separate undertaking, and this environment has no live reth to
cross-check the result against.

For exec-mode specifically, the property BlockSize actually needs is
narrower than full cross-implementation canonicality: every validator in
this shard runs the identical engineapi build, so Go's encoding/json
producing a stable byte length for a fixed struct type across calls in the
same binary is sufficient for quorum to form. It stops being sufficient the
moment a second, independently-built engineapi implementation (a different
language, a different JSON library) needs to agree on the same BlockSize —
at which point RLP's actual cross-implementation stability starts to matter
and this should be revisited.
*/
