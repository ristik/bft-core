package inputcarrier

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

// VersionV2 is the inactive configured-genesis-origin carrier version. It preserves the five-field
// envelope layout; selecting it does not advertise a transport capability or activate the profile.
const VersionV2 uint64 = 2

// EncodeV2 returns the canonical five-field encoding of a version-2 envelope.
func EncodeV2(e Envelope, l Limits) ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	if err := l.checkVersion(e, VersionV2); err != nil {
		return nil, err
	}
	b, err := types.Cbor.Marshal(envelopeWire{Version: e.Version, ShardRound: e.ShardRound, BlockHash: e.BlockHash, Certificate: e.Certificate, TechnicalRecord: e.TechnicalRecord})
	if err != nil {
		return nil, fmt.Errorf("inputcarrier: encoding v2 envelope: %w", err)
	}
	return b, nil
}

// DecodeV2 accepts exactly one canonical version-2 envelope and owns all returned slices.
func DecodeV2(b []byte, l Limits) (Envelope, error) {
	if err := l.validate(); err != nil {
		return Envelope{}, err
	}
	if len(b) == 0 || len(b) > l.FrameBytes() {
		return Envelope{}, fmt.Errorf("%w: %d bytes, bound 1..%d", ErrMalformedEnvelope, len(b), l.FrameBytes())
	}
	var w envelopeWire
	if err := types.Cbor.Unmarshal(b, &w); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}
	e := Envelope{Version: w.Version, ShardRound: w.ShardRound, BlockHash: bytes.Clone(w.BlockHash), Certificate: bytes.Clone(w.Certificate), TechnicalRecord: bytes.Clone(w.TechnicalRecord)}
	if err := l.checkVersion(e, VersionV2); err != nil {
		return Envelope{}, err
	}
	again, err := EncodeV2(e, l)
	if err != nil {
		return Envelope{}, err
	}
	if !bytes.Equal(again, b) {
		return Envelope{}, fmt.Errorf("%w: not the canonical encoding of its own contents", ErrMalformedEnvelope)
	}
	return e, nil
}

// VerifyV2 authenticates a version-2 carrier, derives the inactive root input, then checks the block
// header's parent and extraData commitment. The snapshot and continuity premise remain caller-owned.
func VerifyV2(ctx context.Context, oc rootinput.ObservationContextV2, dc rootinput.ContextV2, env Envelope, h Header) (rootinput.ResultV2, error) {
	env = env.clone()
	hash, parent, extra := bytes.Clone(h.Hash), bytes.Clone(h.ParentHash), bytes.Clone(h.ExtraData)
	dc.ParentHash = bytes.Clone(dc.ParentHash)
	if err := DefaultLimits.checkVersion(env, VersionV2); err != nil {
		return rootinput.ResultV2{}, err
	}
	if len(hash) != 32 {
		return rootinput.ResultV2{}, fmt.Errorf("%w: header hash must be 32 bytes, got %d", ErrEnvelopeBinding, len(hash))
	}
	if env.ShardRound != dc.Round {
		return rootinput.ResultV2{}, fmt.Errorf("%w: envelope is for shard round %d, the pinned round is %d", ErrEnvelopeBinding, env.ShardRound, dc.Round)
	}
	if !bytes.Equal(env.BlockHash, hash) {
		return rootinput.ResultV2{}, fmt.Errorf("%w: envelope is bound to block %x, not %x", ErrEnvelopeBinding, env.BlockHash, hash)
	}
	uc := &types.UnicityCertificate{}
	if err := decodeCanonical(env.Certificate, uc); err != nil {
		return rootinput.ResultV2{}, fmt.Errorf("%w: certificate: %w", ErrMalformedEnvelope, err)
	}
	tr := &certification.TechnicalRecord{}
	if err := decodeCanonical(env.TechnicalRecord, tr); err != nil {
		return rootinput.ResultV2{}, fmt.Errorf("%w: technical record: %w", ErrMalformedEnvelope, err)
	}
	obs, err := rootinput.AuthenticateObservationV2(ctx, oc, uc, tr)
	if err != nil {
		return rootinput.ResultV2{}, fmt.Errorf("inputcarrier: %w", err)
	}
	dc.Context = ctx
	res, err := rootinput.DeriveV2(dc, obs)
	if err != nil {
		return rootinput.ResultV2{}, fmt.Errorf("inputcarrier: %w", err)
	}
	if !bytes.Equal(parent, res.Input.ParentHash) || !bytes.Equal(extra, res.Commitment[:]) {
		return rootinput.ResultV2{}, fmt.Errorf("%w: block header does not carry the derived v2 parent/commitment", ErrEnvelopeBinding)
	}
	return res, nil
}
