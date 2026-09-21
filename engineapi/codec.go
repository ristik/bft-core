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

	// SealCompanion is D2 §2's envelope-only dissemination metadata: the root
	// input, its authentication witnesses, and a provenance label. It is a
	// pointer with omitempty so an envelope without one encodes to exactly the
	// JSON this type produced before the field existed. W1 carries the field;
	// W2 populates it and W3 consumes it. It is deliberately outside
	// BlockSize, which EncodeBlock computes from ExecutionPayload alone,
	// because the companion is dissemination metadata, not block content.
	SealCompanion *SealCompanion `json:"sealCompanion,omitempty"`
}

// SealCompanion is what ureth's
// reth_unicity_execution::wire::SealCompanion deserializes. The wire contract
// is exact: the keys are rootInput, witnesses and provenance; rootInput and
// each witness are 0x-prefixed hex DATA strings; and ureth declares
// deny_unknown_fields, so a fourth key is a hard decode error rather than
// something ignored. TestSealCompanionVector pins the exact bytes.
//
// Provenance carries D2's "build" | "newPayload" | "devp2p" | "reexec"
// label. It is not a commitment field, so the set is documented but not
// enforced here, matching the ureth side.
type SealCompanion struct {
	RootInput  data   `json:"rootInput"`
	Witnesses  []data `json:"witnesses"`
	Provenance string `json:"provenance"`
}

// MarshalJSON normalizes a nil witness slice to an empty array. A nil Go slice
// marshals to JSON null, and ureth's Vec<Bytes> will not accept null, so an
// empty witness list has to be [] instead. See Client.NewPayloadV3 for the
// same normalization of expectedBlobVersionedHashes, and the same bug.
func (c SealCompanion) MarshalJSON() ([]byte, error) {
	witnesses := c.Witnesses
	if witnesses == nil {
		witnesses = []data{}
	}
	return json.Marshal(struct {
		RootInput  data   `json:"rootInput"`
		Witnesses  []data `json:"witnesses"`
		Provenance string `json:"provenance"`
	}{
		RootInput:  c.RootInput,
		Witnesses:  witnesses,
		Provenance: c.Provenance,
	})
}

// SealBuildInput is the sealBuildInput parameter of
// engine_forkchoiceUpdatedWithSealV1, and the JSON envelope ureth's
// reth_unicity_execution::wire::SealBuildInput deserializes under
// deny_unknown_fields: exactly rootInput and transitions.
//
// RootInput is canonical CBOR for one root input, a 0x-prefixed hex DATA
// string. Transitions is the outer committed-body array; for this unit it is
// ALWAYS empty, and an empty array here means "none are pending", never "some
// are pending and could not be authenticated". rootinput.Derive refuses when
// committed trust-base bodies or handoff acknowledgements are pending
// (rootinput/rootinput.go), and f2c-root-input-wiring-contract.md §8 lists
// that refusal as one that must survive wiring — so dropping or misencoding
// them would silently turn a refusal into an acceptance.
type SealBuildInput struct {
	RootInput   data   `json:"rootInput"`
	Transitions []data `json:"transitions"`
}

// MarshalJSON normalizes a nil transitions slice to an empty array, for the
// same reason SealCompanion normalizes its witnesses: a nil Go slice marshals
// to JSON null, and ureth's Vec<Bytes> will not accept null.
func (s SealBuildInput) MarshalJSON() ([]byte, error) {
	transitions := s.Transitions
	if transitions == nil {
		transitions = []data{}
	}
	return json.Marshal(struct {
		RootInput   data   `json:"rootInput"`
		Transitions []data `json:"transitions"`
	}{
		RootInput:   s.RootInput,
		Transitions: transitions,
	})
}

// EncodeBlock wraps a sealed, non-quiet ExecutionPayloadV3 into a
// shardnode.Block with no dissemination companion. It is
// EncodeBlockWithSealCompanion with a nil companion.
func EncodeBlock(payload ExecutionPayloadV3) (shardnode.Block, error) {
	return EncodeBlockWithSealCompanion(payload, nil)
}

// EncodeBlockWithSealCompanion is EncodeBlock with a seal companion attached
// for dissemination. Quiet rounds never reach this function — see adapter.go
// Seal, which detects an empty transaction list itself and constructs the quiet
// Block directly, the same way executortest.Fake does for its own zero-entries
// case.
//
// The companion is envelope-only metadata: BlockSize stays the canonical JSON
// of the execution payload alone, never the envelope's, so attaching one cannot
// move a value the root chain hashes into its quorum key.
func EncodeBlockWithSealCompanion(payload ExecutionPayloadV3, companion *SealCompanion) (shardnode.Block, error) {
	envelope := ProposalEnvelope{
		ExecutionPayload:            payload,
		ExpectedBlobVersionedHashes: []data32{},
		SealCompanion:               companion,
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
