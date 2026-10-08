package engineapi

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
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
// uses rootInput, witnesses and provenance for existing deployments. The
// inactive fresh B1 profile additionally carries b1Update as hex DATA. PR4 must
// update ureth's deny_unknown_fields decoder before activation. The legacy wire
// bytes remain pinned by TestSealCompanionVector.
//
// Provenance carries D2's "build" | "newPayload" | "devp2p" | "reexec"
// label. It is not a commitment field, so the set is documented but not
// enforced here, matching the ureth side.
type SealCompanion struct {
	B1Update data `json:"b1Update,omitempty"`
	// RootRecords is the canonical root-record import companion whose SHA-256 the root input commits to (rootRecordsHash).
	RootRecords data   `json:"rootRecords,omitempty"`
	RootInput   data   `json:"rootInput"`
	Witnesses   []data `json:"witnesses"`
	Provenance  string `json:"provenance"`

	// Pair is the canonical pair binding (pairbinding.go). It is the receiving pair's own, set only on the request to the local execution
	// client; it is never part of the disseminated block, so a decoded or encoded dissemination companion never carries one.
	Pair data `json:"-"`
}

// SealCompanionWitnessCount is the exact number of witness entries bft-core writes and accepts: two.
//
// Position 0 is the bound authorizing certificate (types.UnicityCertificate) and position 1 is the
// bound technical record (certification.TechnicalRecord), both encoded with types.Cbor — the canonical
// CBOR this repository already puts a certificate under on the wire (inputcarrier/envelope.go,
// recordwiring/capture.go, shardnode/commitobserver.go, shardnode/store.go). Both are needed because
// rootinput.Derive authenticates the certificate against the record it commits to by hash, and the
// companion.rootInput carries no decoder in this tree (evmroot is an encode-only model), so the
// record must travel rather than be read back out of the root input. This supersedes the earlier
// single-witness design in the W3 brief; see docs/design/f2c-root-input-wiring-contract.md §3.1 step 1
// ("read the bound UC_-/TE_- from the companion").
//
// The length is fixed at two. Any other length is a refusal, and a third position would be a
// deliberate contract change, not an extension a future caller may slip in.
const SealCompanionWitnessCount = 2

// encodeSealCompanionWitnesses returns the witnesses list for a block bound to uc and tr:
// [canonical CBOR of the certificate, canonical CBOR of the technical record], in that order.
func encodeSealCompanionWitnesses(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) ([]data, error) {
	if uc == nil || tr == nil {
		return nil, fmt.Errorf("%w: both the bound certificate and technical record are required", ErrCompanionWitnesses)
	}
	ucBytes, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, fmt.Errorf("engineapi: encoding the bound certificate: %w", err)
	}
	trBytes, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, fmt.Errorf("engineapi: encoding the bound technical record: %w", err)
	}
	return []data{ucBytes, trBytes}, nil
}

// decodeSealCompanionWitnesses decodes the exactly-two witnesses written by encodeSealCompanionWitnesses.
//
// It refuses a wrong length, a decode failure, and any encoding that is not the canonical encoding of
// its own contents (the same rule inputcarrier.Decode applies): the bytes judged are the bytes that
// arrived.
func decodeSealCompanionWitnesses(witnesses []data) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	if len(witnesses) != SealCompanionWitnessCount {
		return nil, nil, fmt.Errorf("%w: companion carries %d witnesses; exactly %d ([bound certificate, bound technical record]) are required",
			ErrCompanionWitnesses, len(witnesses), SealCompanionWitnessCount)
	}
	uc := &types.UnicityCertificate{}
	if err := decodeCanonicalWitness(witnesses[0], uc); err != nil {
		return nil, nil, fmt.Errorf("%w: bound certificate at witness 0: %w", ErrCompanionWitnesses, err)
	}
	tr := &certification.TechnicalRecord{}
	if err := decodeCanonicalWitness(witnesses[1], tr); err != nil {
		return nil, nil, fmt.Errorf("%w: bound technical record at witness 1: %w", ErrCompanionWitnesses, err)
	}
	return uc, tr, nil
}

// decodeCanonicalWitness decodes b into v and requires v to re-encode to exactly b.
func decodeCanonicalWitness(b []byte, v any) error {
	if err := types.Cbor.Unmarshal(b, v); err != nil {
		return err
	}
	again, err := types.Cbor.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return fmt.Errorf("not the canonical encoding of its own contents")
	}
	return nil
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
		B1Update    data   `json:"b1Update,omitempty"`
		RootRecords data   `json:"rootRecords,omitempty"`
		RootInput   data   `json:"rootInput"`
		Witnesses   []data `json:"witnesses"`
		Provenance  string `json:"provenance"`
		pairWire
	}{
		B1Update:    c.B1Update,
		RootRecords: c.RootRecords,
		RootInput:   c.RootInput,
		Witnesses:   witnesses,
		Provenance:  c.Provenance,
		pairWire:    pairWire{PairBinding: pairField(c.Pair, false)},
	})
}

// SealBuildInput is the sealBuildInput parameter of
// engine_forkchoiceUpdatedWithSealV1, and the JSON envelope ureth's
// reth_unicity_execution::wire::SealBuildInput deserializes under
// deny_unknown_fields: rootInput and transitions. Inactive fresh B1 adds
// b1Update; the matching ureth decoder change is an activation prerequisite.
//
// RootInput is canonical CBOR for one root input. Transitions is the outer
// committed-body array passed to ureth's execution path. It mirrors the
// authenticated transition sequence encoded in RootInput; the adapter derives
// both from the same verified parent snapshot. An empty array means no
// transition is pending, never that unauthenticated data was dropped.
type SealBuildInput struct {
	B1Update    data   `json:"b1Update,omitempty"`
	RootRecords data   `json:"rootRecords,omitempty"`
	RootInput   data   `json:"rootInput"`
	Transitions []data `json:"transitions"`

	// Pair is the canonical pair binding for this build job (pairbinding.go); empty for a client without one.
	Pair data `json:"-"`
	// PairEmpty sends the binding field present but empty: the missing-evidence control, which must reach the client's own guard.
	PairEmpty bool `json:"-"`
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
		B1Update    data   `json:"b1Update,omitempty"`
		RootRecords data   `json:"rootRecords,omitempty"`
		RootInput   data   `json:"rootInput"`
		Transitions []data `json:"transitions"`
		pairWire
	}{
		B1Update:    s.B1Update,
		RootRecords: s.RootRecords,
		RootInput:   s.RootInput,
		Transitions: transitions,
		pairWire:    pairWire{PairBinding: pairField(s.Pair, s.PairEmpty)},
	})
}

// EncodeBlock wraps a sealed, non-quiet ExecutionPayloadV3 into a
// shardnode.Block with no dissemination companion. It is
// EncodeBlockWithSealCompanion with a nil companion.
func EncodeBlock(payload ExecutionPayloadV3) (shardnode.Block, error) {
	return EncodeBlockWithSealCompanion(payload, nil)
}

// EncodeBlockWithSealCompanion is EncodeBlock with a seal companion attached
// for dissemination. An empty user transaction list still carries a real
// execution payload and its seal companion.
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
