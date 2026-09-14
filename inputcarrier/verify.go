package inputcarrier

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrEnvelopeBinding is an envelope that is well formed but bound to a different round or block than
// the one it is being checked against. It is separate from every rootinput refusal: the evidence may
// be genuine, it is just not evidence about this block.
var ErrEnvelopeBinding = errors.New("inputcarrier: envelope bound to another block")

// Header is the part of the block the envelope travels with that Verify reads. Header fields only;
// nothing here is a claim the block makes about its own validity.
type Header struct {
	Hash       []byte // the block hash, 32 bytes
	ParentHash []byte // the header's parentHash, 32 bytes
	ExtraData  []byte // the header's extraData
}

/*
Verify authenticates the evidence in env for the block described by h, under the caller's context c.

Everything the verifier owns comes from c: configured identity and trust, the pinned round, the pinned
certified parent and the committed cursor. Nothing comes from the envelope except the certificate and
technical record, which are evidence and are authenticated here, by the same rootinput path a builder
uses (rootinput.AcceptBlock over rootinput.Derive). There is no parameter through which a caller or a
peer could assert that anything was already verified.

Order: the envelope and header are copied at entry, before any decoding or trust lookup, so a caller
changing its slices mid-call cannot change what is judged (#141). Then the envelope's own form, then its
binding to this round and this block, then the evidence decoded canonically, then rootinput. A refusal
from rootinput is returned wrapped, and errors.Is still reaches its class.
*/
func Verify(ctx context.Context, c rootinput.Context, env Envelope, h Header) (rootinput.Result, error) {
	// Untested by construction, kept as defence in depth: every direct read of the caller's slices
	// below happens before the trust lookup, and rootinput.AcceptBlock takes its own copy of the parent
	// and extraData before its lookup (#141). Removing these copies therefore changes no outcome today;
	// they keep that true if a later edit reads a caller slice after the lookup.
	env = env.clone()
	hash, parent, extra := bytes.Clone(h.Hash), bytes.Clone(h.ParentHash), bytes.Clone(h.ExtraData)

	if err := DefaultLimits.check(env); err != nil {
		return rootinput.Result{}, err
	}
	if len(hash) != 32 {
		return rootinput.Result{}, fmt.Errorf("%w: header hash must be 32 bytes, got %d", ErrEnvelopeBinding, len(hash))
	}
	if env.ShardRound != c.Round {
		return rootinput.Result{}, fmt.Errorf("%w: envelope is for shard round %d, the pinned round is %d", ErrEnvelopeBinding, env.ShardRound, c.Round)
	}
	if !bytes.Equal(env.BlockHash, hash) {
		return rootinput.Result{}, fmt.Errorf("%w: envelope is bound to block %x, not %x", ErrEnvelopeBinding, env.BlockHash, hash)
	}

	uc := &types.UnicityCertificate{}
	if err := decodeCanonical(env.Certificate, uc); err != nil {
		return rootinput.Result{}, fmt.Errorf("%w: certificate: %w", ErrMalformedEnvelope, err)
	}
	tr := &certification.TechnicalRecord{}
	if err := decodeCanonical(env.TechnicalRecord, tr); err != nil {
		return rootinput.Result{}, fmt.Errorf("%w: technical record: %w", ErrMalformedEnvelope, err)
	}

	res, err := rootinput.AcceptBlock(ctx, c, uc, tr, rootinput.BlockBinding{ParentHash: parent, ExtraData: extra})
	if err != nil {
		return rootinput.Result{}, fmt.Errorf("inputcarrier: %w", err)
	}
	return res, nil
}

// decodeCanonical decodes b into v and requires v to re-encode to exactly b.
func decodeCanonical(b []byte, v any) error {
	if err := types.Cbor.Unmarshal(b, v); err != nil {
		return err
	}
	again, err := types.Cbor.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return errors.New("not the canonical encoding of its own contents")
	}
	return nil
}
