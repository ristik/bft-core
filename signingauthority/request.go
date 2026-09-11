package signingauthority

import (
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
