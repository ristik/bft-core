package shardnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
SigningAuthorityClient is the part of a signing authority a shard node is given.

It declares the four client operations and nothing else: no session replacement, no key, no
constructor. That narrows what this code can call, which is worth having and is not by itself a
trust boundary — a value whose dynamic type is *signingauthority.Authority can be asserted to an
interface that does have ReplaceSession, and in this unactivated profile the round still holds the
legacy key. The boundary is the authority being somewhere else, with its own credentials and its own
lifetime (§3, §6); this interface is what the shard node is allowed to say across it.

The session is deliberately absent from these methods. A client is admitted for one generation, and
which session that is belongs to whoever provisioned the client: an in-process deployment binds it
with signingauthority.NewLocalClient, and a shard node talking to an authority process holds a
credential its operator issued and no session at all.
*/
type SigningAuthorityClient interface {
	Reserve(ctx context.Context, req signingauthority.Request) (*signingauthority.Authorization, error)
	Sign(ctx context.Context) error
	RetainResponse(ctx context.Context) error
	Release(ctx context.Context, round uint64, digest [32]byte) ([]byte, error)
}

/*
NewAuthoritySigner routes this round's certification requests through a signing authority.

The client is provisioned, and so is the expected signing key: neither is taken from a response. The
sequence is the contract's: reserve the complete request for its assigned round, sign what the
authority now owns, retain the response before any of it can leave, and only then release it.

Every answer is checked against this round's own work rather than against another answer. The signer
takes its own copy of the proposed request before it calls the client at all, and that copy — its
preimage, its digest and its assigned round — is what both the reservation and the released response
have to match. Two remote answers agreeing with each other establishes nothing about either.
*/
func NewAuthoritySigner(client SigningAuthorityClient, authorityKey abcrypto.Verifier) (CertificationSigner, error) {
	if client == nil {
		return nil, fmt.Errorf("shardnode: no signing authority client")
	}
	if authorityKey == nil {
		return nil, fmt.Errorf("shardnode: no expected signing key for the authority")
	}
	return &authoritySigner{client: client, authorityKey: authorityKey}, nil
}

type authoritySigner struct {
	client SigningAuthorityClient
	// authorityKey is the enrolled authority's signing key, provisioned with this node's
	// configuration. It is never read out of a response: a key carried by the answer being checked
	// would verify any answer.
	authorityKey abcrypto.Verifier
}

func (a *authoritySigner) Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	if proposed == nil {
		return nil, fmt.Errorf("shardnode: no proposal to sign")
	}
	// The local expectation, fixed before any client call and owned by this signer: a copy of the
	// proposal that nothing else holds a reference to, its signature-free preimage, the digest of
	// that preimage and the round it is for.
	owned, err := cloneRequest(proposed)
	if err != nil {
		return nil, fmt.Errorf("taking the proposal: %w", err)
	}
	if owned.InputRecord == nil {
		return nil, fmt.Errorf("shardnode: the proposal carries no input record")
	}
	expectedUnsigned, err := owned.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding the proposal: %w", err)
	}
	expectedRound := owned.InputRecord.RoundNumber
	expectedDigest := sha256.Sum256(expectedUnsigned)

	authorization, err := a.client.Reserve(ctx, signingauthority.Request{UC: uc, Technical: tr, Proposed: owned})
	if err != nil {
		return nil, fmt.Errorf("reserving the round with the signing authority: %w", err)
	}
	if authorization == nil {
		return nil, fmt.Errorf("the signing authority reserved nothing for round %d", expectedRound)
	}
	// The reservation is checked against this round's work, not against the release that follows.
	if authorization.AssignedRound != expectedRound {
		return nil, fmt.Errorf("the signing authority reserved round %d for a proposal for round %d", authorization.AssignedRound, expectedRound)
	}
	if !bytes.Equal(authorization.Unsigned, expectedUnsigned) {
		return nil, fmt.Errorf("the signing authority reserved a different request than the one proposed for round %d", expectedRound)
	}
	if authorization.UnsignedDigest != expectedDigest {
		return nil, fmt.Errorf("the signing authority reserved a digest that does not name the request proposed for round %d", expectedRound)
	}

	if err := a.client.Sign(ctx); err != nil {
		return nil, fmt.Errorf("signing at the signing authority: %w", err)
	}
	if err := a.client.RetainResponse(ctx); err != nil {
		return nil, fmt.Errorf("retaining the signed response: %w", err)
	}
	// Released by the local round and digest, so a client that answered with someone else's round
	// cannot also choose which response is asked for.
	released, err := a.client.Release(ctx, expectedRound, expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("releasing the signed response: %w", err)
	}
	if len(released) == 0 {
		return nil, fmt.Errorf("the signing authority released nothing for round %d", expectedRound)
	}

	var signed certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(released, &signed); err != nil {
		return nil, fmt.Errorf("decoding the signed response: %w", err)
	}
	unsigned, err := signed.Bytes()
	if err != nil {
		return nil, fmt.Errorf("re-encoding the signed response: %w", err)
	}
	if !bytes.Equal(unsigned, expectedUnsigned) {
		return nil, fmt.Errorf("the signing authority returned a different request than the one proposed for round %d", expectedRound)
	}
	// A signature is what the authority was asked for, so its presence is not the check: the
	// released response must verify under the enrolled key this node was configured with. This does
	// not stop an authority from signing two different requests, which is what the record inside
	// the authority is for; it stops a corrupt or misrouted answer from being cached as a completed
	// round and sent to the root chain.
	if err := signed.IsValid(a.authorityKey); err != nil {
		return nil, fmt.Errorf("the signing authority's response for round %d does not verify under the enrolled signing key: %w", expectedRound, err)
	}
	return &signed, nil
}

// cloneRequest returns a copy of a certification request that shares nothing with the original,
// including its InputRecord, which is a pointer the caller keeps.
func cloneRequest(req *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	encoded, err := types.Cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding: %w", err)
	}
	var owned certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(encoded, &owned); err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}
	return &owned, nil
}
