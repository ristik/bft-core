package signingauthority

import (
	"bytes"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// MaxUnsignedRequestBytes bounds the complete signature-free certification request. The design note
// proposes 1 MiB per request (§5). A larger proof profile needs an explicit version and review
// rather than a truncating authority.
const MaxUnsignedRequestBytes = 1 << 20

// Request is the only shape this authority admits. It carries the authorization (a Unicity
// Certificate and the TechnicalRecord bound to it) together with the certification request the
// shard node proposes to sign, and it carries no bytes for the authority to sign blindly and no
// claim about its own authenticity. A field saying "this was verified" would be worth nothing here,
// because verifying it is the authority's own job (§4).
type Request struct {
	// UC is the certificate that assigns the work. Its trust base comes from the authority, never
	// from this request.
	UC *types.UnicityCertificate

	// Technical is the record bound to UC by UC.TRHash. The assigned round and epoch are read from
	// here after that binding is checked, never from the proposal.
	Technical *certification.TechnicalRecord

	// Proposed is the complete certification request, with its Signature left unset. The authority
	// derives the bytes to sign from this structure itself.
	Proposed *certification.BlockCertificationRequest
}

// snapshot returns a copy of the request that this authority owns, together with the complete
// signature-free preimage it encodes.
//
// It exists because the caller keeps its own structures and may change them at any time, including
// while the authority waits for its trust base. Everything the authority checks, and the preimage it
// returns, must be one message rather than two: the proposal is serialized once, and the structure
// that is then validated is decoded back from exactly those bytes, so "what was checked" and "what
// is returned" cannot drift apart in either direction. The certificate and technical record are
// copied for the same reason.
func (r Request) snapshot() (Request, []byte, error) {
	// The size bound is applied to the encoding, before anything is decoded or retained (§5).
	unsigned, err := r.Proposed.Bytes()
	if err != nil {
		return Request{}, nil, fmt.Errorf("%w: encoding the proposal: %w", ErrProposalMismatch, err)
	}
	if len(unsigned) > MaxUnsignedRequestBytes {
		return Request{}, nil, fmt.Errorf("%w: %d bytes, limit is %d", ErrRequestTooLarge, len(unsigned), MaxUnsignedRequestBytes)
	}

	var proposed certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(unsigned, &proposed); err != nil {
		return Request{}, nil, fmt.Errorf("%w: decoding the proposal: %w", ErrProposalMismatch, err)
	}
	// The decoded copy must encode back to the same bytes. Without this, a decoder that normalised
	// anything would leave the validated structure and the returned preimage different again, which
	// is the defect this function exists to remove rather than to move.
	//
	// It is defence in depth against a future encoder, and it is deliberately recorded as untested:
	// the bytes checked here were produced by the canonical encoder a few lines above, so no input
	// reachable through this package can make the comparison fail. A mutation that disables it
	// therefore survives the suite. Removing it would be reasonable only alongside a decision that
	// the encoding is canonical by contract.
	again, err := proposed.Bytes()
	if err != nil {
		return Request{}, nil, fmt.Errorf("%w: re-encoding the proposal: %w", ErrProposalMismatch, err)
	}
	if !bytes.Equal(again, unsigned) {
		return Request{}, nil, fmt.Errorf("%w: the proposal does not re-encode to the bytes it was read from", ErrProposalMismatch)
	}

	uc, err := cborCopy[types.UnicityCertificate](r.UC)
	if err != nil {
		return Request{}, nil, fmt.Errorf("%w: copying the certificate: %w", ErrUnauthenticated, err)
	}
	tr, err := cborCopy[certification.TechnicalRecord](r.Technical)
	if err != nil {
		return Request{}, nil, fmt.Errorf("%w: copying the technical record: %w", ErrUnauthenticated, err)
	}
	return Request{UC: uc, Technical: tr, Proposed: &proposed}, unsigned, nil
}

func cborCopy[T any](v *T) (*T, error) {
	encoded, err := types.Cbor.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out T
	if err := types.Cbor.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r Request) validate() error {
	if r.UC == nil || r.UC.InputRecord == nil || r.UC.UnicitySeal == nil {
		return fmt.Errorf("%w: the request carries no complete certificate", ErrUnauthenticated)
	}
	if r.Technical == nil {
		return fmt.Errorf("%w: the request carries no technical record", ErrUnauthenticated)
	}
	if r.Proposed == nil || r.Proposed.InputRecord == nil {
		return fmt.Errorf("%w: the request carries no complete proposal", ErrProposalMismatch)
	}
	if len(r.Proposed.Signature) != 0 {
		// An already signed request is not a thing to sign again. It also tells the authority that
		// the caller has a signing path of its own, which this profile does not permit.
		return fmt.Errorf("%w: the proposal already carries a signature", ErrProposalMismatch)
	}
	return nil
}
