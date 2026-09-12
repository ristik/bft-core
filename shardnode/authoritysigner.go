package shardnode

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
SigningAuthorityClient is the part of a signing authority a shard node may use.

It is an interface rather than the concrete type for one reason beyond testing: it does not contain
ReplaceSession. Replacing a client is the operator control plane, and a shard process that could
call it could take itself back into service after being fenced, which is exactly what fencing is for.
Leaving the method out means the shard cannot mint a session, structurally rather than by convention:
its session is issued elsewhere and handed to it.

There is also no constructor here, and no key: a restarting shard node cannot bring an authority back
with it. If the authority is gone, this node does not sign (§1, §6).
*/
type SigningAuthorityClient interface {
	Reserve(ctx context.Context, session signingauthority.Session, req signingauthority.Request) (*signingauthority.Authorization, error)
	Sign(session signingauthority.Session) error
	RetainResponse(session signingauthority.Session) error
	Release(session signingauthority.Session, round uint64, digest [32]byte) ([]byte, error)
}

/*
NewAuthoritySigner routes this round's certification requests through a signing authority.

The session is supplied, never created here. The sequence is the contract's: reserve the complete
request for its assigned round, sign what the authority now owns, retain the response before any of
it can leave, and only then release it. A client that dies between any two of those steps repeats
them and gets the same bytes; a client that comes back with a different candidate for the same round
is refused rather than served.
*/
func NewAuthoritySigner(client SigningAuthorityClient, session signingauthority.Session) CertificationSigner {
	return &authoritySigner{client: client, session: session}
}

type authoritySigner struct {
	client  SigningAuthorityClient
	session signingauthority.Session
}

func (a *authoritySigner) Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	if proposed == nil {
		return nil, fmt.Errorf("shardnode: no proposal to sign")
	}
	request := signingauthority.Request{UC: uc, Technical: tr, Proposed: proposed}

	authorization, err := a.client.Reserve(ctx, a.session, request)
	if err != nil {
		return nil, fmt.Errorf("reserving the round with the signing authority: %w", err)
	}
	if err := a.client.Sign(a.session); err != nil {
		return nil, fmt.Errorf("signing at the signing authority: %w", err)
	}
	if err := a.client.RetainResponse(a.session); err != nil {
		return nil, fmt.Errorf("retaining the signed response: %w", err)
	}
	released, err := a.client.Release(a.session, authorization.AssignedRound, authorization.UnsignedDigest)
	if err != nil {
		return nil, fmt.Errorf("releasing the signed response: %w", err)
	}

	var signed certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(released, &signed); err != nil {
		return nil, fmt.Errorf("decoding the signed response: %w", err)
	}
	// The client checks what it was handed before it puts it on the wire (§5). The response must be
	// the request this round proposed, signed, and nothing else: an authority that returned another
	// round's answer, or a different candidate for this one, must not be forwarded by this node.
	unsigned, err := signed.Bytes()
	if err != nil {
		return nil, fmt.Errorf("re-encoding the signed response: %w", err)
	}
	if !bytes.Equal(unsigned, authorization.Unsigned) {
		return nil, fmt.Errorf("the signing authority returned a different request than the one reserved for round %d", authorization.AssignedRound)
	}
	if len(signed.Signature) == 0 {
		return nil, fmt.Errorf("the signing authority returned an unsigned request for round %d", authorization.AssignedRound)
	}
	return &signed, nil
}
