package shardnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
SigningAuthorityClient is the part of a signing authority a shard node is given.

It declares the four client operations and nothing else: no session replacement, no key, no
constructor. That narrows what this code can call, which is worth having and is not by itself a
trust boundary: a value whose dynamic type is *signingauthority.Authority can be asserted to an
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
takes its own copy of the proposed request before it calls the client at all, and that copy (its
preimage, its digest and its assigned round) is what both the reservation and the released response
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

// RestoreReadiness checks the surviving authority's independent high-water
// record. Round zero is an availability preflight; a nonzero round may be
// signed only at or above the recorded reservation. Reserve repeats this check
// atomically, so a concurrent authority operation cannot bypass it.
func (a *authoritySigner) RestoreReadiness(ctx context.Context, round uint64) error {
	status, err := a.RestoreStatus(ctx)
	if err != nil {
		return err
	}
	if status.Faulted || status.KeyLost || status.Generation == 0 || status.HasReservation != (status.ReservedRound != 0) {
		return fmt.Errorf("shardnode: surviving signing authority has inconsistent high-water state")
	}
	if round != 0 && round < status.ReservedRound {
		return fmt.Errorf("shardnode: signing-stale: proposed round %d is below signing authority high-water %d", round, status.ReservedRound)
	}
	return nil
}

// RestoreStatus exposes only the authority's read-only high-water and scope
// diagnostics to operator status and restore readiness checks.
func (a *authoritySigner) RestoreStatus(ctx context.Context) (signingauthority.Status, error) {
	probe, ok := a.client.(interface {
		RestoreStatus(context.Context) (signingauthority.Status, error)
	})
	if !ok {
		return signingauthority.Status{}, fmt.Errorf("shardnode: signing authority has no restore-status probe")
	}
	status, err := probe.RestoreStatus(ctx)
	if err != nil {
		return signingauthority.Status{}, fmt.Errorf("shardnode: reading signing authority: %w", err)
	}
	return status, nil
}

/*
recordKeepingSigner is a CertificationSigner whose every signature is admitted by an independent
signing record: the authority's, which refuses a lower assigned round, refuses different bytes for the
round it holds, and answers identical bytes with the one response it retained (#105 step 4).

It is sealed on purpose. The method is unexported, so only this package can implement it: authoritySigner,
and DeferredAuthoritySigner by delegation to one (it signs nothing before its key is bound). A restored Round signs through a signer only if it has this property (see
Round.abstainRestored); a local key, a test double or a wrapper does not have it and cannot claim it.
What the property does not include, and what each request establishes for itself: that the credential
is current, that the authority still holds the key of its lifetime, that the request authenticates,
and that the response verifies under the configured key.
*/
type recordKeepingSigner interface {
	CertificationSigner
	signsOnlyWhatAnIndependentRecordAdmits()
}

func (a *authoritySigner) signsOnlyWhatAnIndependentRecordAdmits() {}

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

// ErrAuthorityKeyUnbound is a signing request made before the authority's expected key is known. A deferred signer fails closed: it
// signs nothing until the key has been bound from a verified source.
var ErrAuthorityKeyUnbound = errors.New("shardnode: the signing authority's expected key is not bound yet")

// ErrAuthorityKeyConflict is a second, different expected key for a deferred signer that is already bound. The authority's key is fixed
// for its lifetime, so a verified configuration that names this node with another key is an inconsistency, never a rotation.
//
// A joiner whose installed history names it with SEVERAL keys (a later rotation) binds the latest, after the replay; the authority's key is
// fixed for its lifetime, so a new authority key is a new node identity, not a rebinding.
var ErrAuthorityKeyConflict = errors.New("shardnode: the signing authority's expected key is already bound to a different key")

/*
DeferredAuthoritySigner is an authority signer whose expected key is not known when the node starts: a JOINER, whose key appears only
in a shard configuration the genesis one precedes. The client is provisioned as for NewAuthoritySigner; the expected key is bound later,
once, from a configuration the node has VERIFIED (the activated assignment of a verified handoff bundle), and never from the authority's
own answer. Until it is bound the signer refuses every request (ErrAuthorityKeyUnbound); once bound it is exactly NewAuthoritySigner's.
It keeps the record-keeping property of that signer: the restore readiness and status probes need the client only.
*/
type DeferredAuthoritySigner struct {
	mu     sync.Mutex
	client SigningAuthorityClient
	bound  *authoritySigner
	key    []byte
}

func NewDeferredAuthoritySigner(client SigningAuthorityClient) (*DeferredAuthoritySigner, error) {
	if client == nil {
		return nil, fmt.Errorf("shardnode: no signing authority client")
	}
	return &DeferredAuthoritySigner{client: client}, nil
}

// BindKey fixes the expected key. Binding the same key again is a no-op; a different one is ErrAuthorityKeyConflict.
func (d *DeferredAuthoritySigner) BindKey(key abcrypto.Verifier) error {
	if key == nil {
		return fmt.Errorf("shardnode: no expected signing key for the authority")
	}
	raw, err := key.MarshalPublicKey()
	if err != nil {
		return fmt.Errorf("shardnode: reading the expected signing key: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.bound != nil {
		if !bytes.Equal(d.key, raw) {
			return ErrAuthorityKeyConflict
		}
		return nil
	}
	d.bound, d.key = &authoritySigner{client: d.client, authorityKey: key}, bytes.Clone(raw)
	return nil
}

// Bound reports whether the expected key has been bound.
func (d *DeferredAuthoritySigner) Bound() bool { return d.current() != nil }

func (d *DeferredAuthoritySigner) current() *authoritySigner {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bound
}

func (d *DeferredAuthoritySigner) signsOnlyWhatAnIndependentRecordAdmits() {}

func (d *DeferredAuthoritySigner) Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	s := d.current()
	if s == nil {
		return nil, ErrAuthorityKeyUnbound
	}
	return s.Sign(ctx, uc, tr, proposed)
}

func (d *DeferredAuthoritySigner) RestoreReadiness(ctx context.Context, round uint64) error {
	return (&authoritySigner{client: d.client}).RestoreReadiness(ctx, round)
}

func (d *DeferredAuthoritySigner) RestoreStatus(ctx context.Context) (signingauthority.Status, error) {
	return (&authoritySigner{client: d.client}).RestoreStatus(ctx)
}
