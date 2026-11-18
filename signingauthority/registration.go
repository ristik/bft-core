package signingauthority

import (
	"bytes"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// VR registration and binding rotation (VT-10, astra's design for #1201). The authority's key is the validator's EVM key, so the EVM
// possession proof of VR.register / VR.proposeBinding is its signature over vrschema.RegistrationDigest. Like the other EVM signatures
// here this operation takes typed inputs, never a digest: the digest is computed inside the authority from the pinned deployment, the
// request's owner, identity and registration, and only that digest is signed, for this authority's own enrolled node and key. Operator
// channel only; the member's possession-proof endpoint never reaches it.

// RegistrationDeployment pins the VR deployment a registration digest binds: its network word, the chain id and VR's address. It is
// fixed when the authority starts; no request names a deployment.
type RegistrationDeployment struct {
	Network, ChainID [32]byte
	Registry         [20]byte
}

// RegistrationAuthorization is one registration the operator has authorized this authority to sign: the action (the domain), the owner
// account that sends the transaction, the identity (0 for a registration), the root node binding and the payee. The EVM node and key
// are always the authority's own and are not part of the authorization.
type RegistrationAuthorization struct {
	Domain     string
	Owner      [20]byte
	ID         uint64
	RootNodeID string
	RootKey    []byte
	Payee      [20]byte
}

// RegistrationPolicy is what an operator starts an authority with to let it sign registrations: the pinned deployment and the authorized
// registrations. It is immutable for the authority's lifetime (the key does not outlive the process either).
type RegistrationPolicy struct {
	Deployment RegistrationDeployment
	Authorized []RegistrationAuthorization
}

// WithRegistrationPolicy enables SignRegistration under the policy.
func WithRegistrationPolicy(p RegistrationPolicy) Option {
	return func(a *Authority) error {
		if len(p.Authorized) == 0 {
			return fmt.Errorf("the registration policy authorizes nothing")
		}
		cp := RegistrationPolicy{Deployment: p.Deployment}
		for _, x := range p.Authorized {
			if x.Domain != vrschema.RegisterDomainText && x.Domain != vrschema.BindingDomainText {
				return fmt.Errorf("%w: policy entry domain %q", ErrRegistrationDomain, x.Domain)
			}
			x.RootKey = bytes.Clone(x.RootKey)
			cp.Authorized = append(cp.Authorized, x)
		}
		a.registration = &cp
		return nil
	}
}

// RegistrationRequest asks for the possession signature this authority's key owes a registration (domain unicity.vr.register, ID 0) or a
// binding proposal (domain unicity.vr.binding, the identity's nonzero ID). Owner is the account that sends the transaction (msg.sender).
type RegistrationRequest struct {
	Domain       string
	Owner        [20]byte
	ID           uint64
	Registration vrschema.Registration
}

// SignRegistration signs vrschema.RegistrationDigest as low-s r||s||v with v 27/28, after it checked: the domain is one of the two and
// agrees with the identity id; a policy is configured and authorizes this action, owner, identity, root binding and payee; the
// registration is well formed (shape, both compressed keys on the curve, distinct keys); and its EVM node and key are exactly this
// authority's enrolled node and key.
func (a *Authority) SignRegistration(req RegistrationRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	binding := false
	switch {
	case req.Domain == vrschema.RegisterDomainText && req.ID == 0:
	case req.Domain == vrschema.BindingDomainText && req.ID != 0:
		binding = true
	default:
		return nil, fmt.Errorf("%w: %q for identity %d", ErrRegistrationDomain, req.Domain, req.ID)
	}
	if a.registration == nil {
		return nil, fmt.Errorf("%w: this authority was started without a registration policy", ErrRegistrationUnauthorized)
	}
	hs, pub, err := a.ethSigner()
	if err != nil {
		return nil, err
	}
	r := req.Registration
	if err := r.ValidShape(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrContextMismatch, err)
	}
	for _, k := range [][]byte{r.RootKey, r.EVMKey} {
		if _, err := ethcrypto.DecompressPubkey(k); err != nil {
			return nil, fmt.Errorf("%w: a key is not a point of the curve", ErrContextMismatch)
		}
	}
	if r.EVMNodeID != a.enroll.NodeID || !bytes.Equal(r.EVMKey, pub) {
		return nil, fmt.Errorf("%w: the registration names another EVM node or key than this authority's", ErrContextMismatch)
	}
	ok := false
	for _, x := range a.registration.Authorized {
		if x.Domain == req.Domain && x.Owner == req.Owner && x.ID == req.ID && x.RootNodeID == r.RootNodeID && bytes.Equal(x.RootKey, r.RootKey) && x.Payee == r.Payee {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("%w: no policy entry for this action, owner, identity, root binding and payee", ErrRegistrationUnauthorized)
	}
	d := a.registration.Deployment
	digest := vrschema.RegistrationDigest(binding, d.Network, d.ChainID, d.Registry, req.Owner, req.ID, r)
	return ethSign(hs, digest)
}
