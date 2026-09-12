package rootinput

/*
Replay acceptance: is a block that already exists the one a certificate authorizes?

#139 (docs/design/f2c-root-input-wiring-contract.md §2) recorded this call path as MISSING and
defined it rather than borrowing one. The nearest existing predicate, shardnode.VerifyAnchorEvidence,
answers a different question (which certified block an executor must commit to across a quiet tail);
it authenticates no EVM payload and derives no canonical root input, so it is not a replay acceptance
test and this is not built on it.

WHAT THIS DECIDES. Given a block's header binding and the stored authorization for its round, does
that block commit to the canonical root input this configuration derives? That is the D1 half:
authorization, commitment and parent binding.

WHAT IT NEVER DECIDES. Nothing about the body: transactions, gas, fees, forced entries and seal
outcomes are D2's rules (evmroot.ValidateImport), and this predicate deliberately stops at the header
so it cannot be mistaken for a body check. It also grants nothing. Acceptance here is memoryless, so
a genuine block replays successfully every time it is offered; whether a round may be answered again
is the caller's applied state and, for signing, the signing record (#105 step 2).

WHERE THE INPUTS COME FROM, for a replay specifically. Every field is read from this node's own
configuration or from authenticated storage AS OF THE REPLAYED ROUND, never from the block and never
from the node's current position:

  - the authorization is the certificate and technical record stored for that round, re-authenticated
    here rather than trusted because they were stored;
  - the certified parent is the parent recorded for that round;
  - the seal-registry cursor is the value committed as of that round. The CURRENT cursor is not a
    substitute: it has moved on, and using it rejects history that was valid when it was written.
*/

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrBindingMismatch is a block that does not commit to the canonical root input this context and
// authorization derive. It is separate from the refusals Derive raises: those say the authorization
// is not this node's to act on, while this one says the authorization is fine and the block is not
// the one it authorizes.
var ErrBindingMismatch = errors.New("rootinput: block binding mismatch")

// BlockBinding is the part of a block header this predicate reads. Header only, by construction:
// there is no field here through which a body could be smuggled in, and nothing here is a claim the
// block makes about its own validity.
type BlockBinding struct {
	// ParentHash is the header's parentHash, 32 bytes.
	ParentHash []byte

	// ExtraData is the header's extraData. D1 §4 makes it exactly the 32-byte commitment
	// SHA-256(CBOR(rootInput)); anything else is a refusal rather than something to truncate or
	// pad to fit.
	ExtraData []byte
}

/*
AcceptBlock reports whether the block described by b is the one that uc and tr authorize under c.

The order is deliberate. The authorization is established first, by the same Derive every builder and
follower uses, so a block is never compared against a commitment derived from a certificate this node
has not authenticated. Only then is the block's own binding checked, and the two failures are
reported separately: an unauthenticated or out-of-context authorization is not the same situation as
a block that does not match a good one, and an operator needs to tell them apart.

The returned Result is the authenticated derivation, so a caller that accepts a block holds the
verified representation rather than having to re-derive it.
*/
func AcceptBlock(ctx context.Context, c Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, b BlockBinding) (Result, error) {
	res, err := Derive(ctx, c, uc, tr)
	if err != nil {
		return Result{}, err
	}

	// The parent is checked before the commitment even though the commitment already covers it. A
	// block built on the wrong parent and a block whose commitment is wrong for the right parent are
	// different faults, and collapsing them into one comparison would report the first as the second.
	if len(b.ParentHash) != 32 {
		return Result{}, fmt.Errorf("%w: header parent hash must be 32 bytes, got %d", ErrBindingMismatch, len(b.ParentHash))
	}
	if !bytes.Equal(b.ParentHash, res.Input.ParentHash) {
		return Result{}, fmt.Errorf("%w: header parent %x is not the certified parent %x this round builds on",
			ErrBindingMismatch, b.ParentHash, res.Input.ParentHash)
	}

	if len(b.ExtraData) != 32 {
		return Result{}, fmt.Errorf("%w: extraData must be the 32-byte input commitment, got %d bytes", ErrBindingMismatch, len(b.ExtraData))
	}
	if !bytes.Equal(b.ExtraData, res.Commitment[:]) {
		return Result{}, fmt.Errorf("%w: extraData %x is not SHA-256(CBOR(rootInput)) %x for this authorization",
			ErrBindingMismatch, b.ExtraData, res.Commitment[:])
	}
	return res, nil
}
