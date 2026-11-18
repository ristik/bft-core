package signingauthority

import (
	"math/big"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrschema"
)

type regFixture struct {
	a      *Authority
	pub    []byte
	depl   RegistrationDeployment
	req    RegistrationRequest
	policy RegistrationPolicy
}

func newRegFixture(t *testing.T, policy bool) *regFixture {
	t.Helper()
	f := newFixture(t, 1)
	probe, err := New(f.enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	_ = probe // the key is generated per authority: the policy names the root binding, not the EVM key
	rootKey, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	rk := ethcrypto.CompressPubkey(&rootKey.PublicKey)
	owner, payee := [20]byte{0xaa, 1}, [20]byte{0xbb, 2}
	depl := RegistrationDeployment{Network: vrschema.Keccak([]byte("net")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry}
	x := RegistrationAuthorization{Domain: vrschema.RegisterDomainText, Owner: owner, RootNodeID: "root-1", RootKey: rk, Payee: payee}
	p := RegistrationPolicy{Deployment: depl, Authorized: []RegistrationAuthorization{x,
		{Domain: vrschema.BindingDomainText, Owner: owner, ID: 7, RootNodeID: "root-1", RootKey: rk, Payee: payee}}}
	var opts []Option
	if policy {
		opts = append(opts, WithRegistrationPolicy(p))
	}
	a, err := New(f.enroll, trustStub{tb: f.tb}, opts...)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	req := RegistrationRequest{Domain: vrschema.RegisterDomainText, Owner: owner, Registration: vrschema.Registration{RootNodeID: "root-1", RootKey: rk,
		EVMNodeID: testNodeID, EVMKey: pub, Payee: payee, Nonce: 4}}
	return &regFixture{a: a, pub: pub, depl: depl, req: req, policy: p}
}

// The signature is over the digest the authority computed itself, in the contracts' format, and recovers the authority's key.
func TestRegistrationSignatureIsTheDigestsLowSRSV(t *testing.T) {
	f := newRegFixture(t, true)
	for _, binding := range []bool{false, true} {
		req := f.req
		if binding {
			req.Domain, req.ID = vrschema.BindingDomainText, 7
		}
		sig, err := f.a.SignRegistration(req)
		require.NoError(t, err)
		require.Len(t, sig, 65)
		require.Contains(t, []byte{27, 28}, sig[64])
		s := new(big.Int).SetBytes(sig[32:64])
		require.True(t, s.Cmp(new(big.Int).Rsh(ethcrypto.S256().Params().N, 1)) <= 0, "low s")
		d := vrschema.RegistrationDigest(binding, f.depl.Network, f.depl.ChainID, f.depl.Registry, req.Owner, req.ID, req.Registration)
		rec := append(append([]byte(nil), sig[:64]...), sig[64]-27)
		got, err := ethcrypto.SigToPub(d[:], rec)
		require.NoError(t, err)
		require.Equal(t, f.pub, ethcrypto.CompressPubkey(got), "binding=%v", binding)
		// bound to its fields: another nonce is another digest
		other := req.Registration
		other.Nonce++
		d2 := vrschema.RegistrationDigest(binding, f.depl.Network, f.depl.ChainID, f.depl.Registry, req.Owner, req.ID, other)
		g2, err := ethcrypto.SigToPub(d2[:], rec)
		if err == nil {
			require.NotEqual(t, f.pub, ethcrypto.CompressPubkey(g2))
		}
	}
}

func TestRegistrationRefusals(t *testing.T) {
	f := newRegFixture(t, true)
	other, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	otherPub := ethcrypto.CompressPubkey(&other.PublicKey)
	offCurve := append([]byte{2}, make([]byte, 32)...) // x = 0 is not on secp256k1
	for name, tc := range map[string]struct {
		mutate func(*RegistrationRequest)
		err    error
	}{
		"the PoP domain":              {func(r *RegistrationRequest) { r.Domain = "UNICITY_H3_EVM_ASSIGNMENT_POP" }, ErrRegistrationDomain},
		"an unknown domain":           {func(r *RegistrationRequest) { r.Domain = "unicity.vr.exit" }, ErrRegistrationDomain},
		"register with an id":         {func(r *RegistrationRequest) { r.ID = 7 }, ErrRegistrationDomain},
		"binding without an id":       {func(r *RegistrationRequest) { r.Domain = vrschema.BindingDomainText }, ErrRegistrationDomain},
		"another EVM key":             {func(r *RegistrationRequest) { r.Registration.EVMKey = otherPub }, ErrContextMismatch},
		"an unenrolled EVM node":      {func(r *RegistrationRequest) { r.Registration.EVMNodeID = "node-2" }, ErrContextMismatch},
		"a short key":                 {func(r *RegistrationRequest) { r.Registration.RootKey = r.Registration.RootKey[:20] }, ErrContextMismatch},
		"an off-curve root key":       {func(r *RegistrationRequest) { r.Registration.RootKey = offCurve }, ErrContextMismatch},
		"the root key as the EVM key": {func(r *RegistrationRequest) { r.Registration.RootKey = r.Registration.EVMKey }, ErrContextMismatch},
		"a zero payee":                {func(r *RegistrationRequest) { r.Registration.Payee = [20]byte{} }, ErrContextMismatch},
		"an empty node id":            {func(r *RegistrationRequest) { r.Registration.RootNodeID = "" }, ErrContextMismatch},
		"another owner":               {func(r *RegistrationRequest) { r.Owner[0] ^= 1 }, ErrRegistrationUnauthorized},
		"another payee":               {func(r *RegistrationRequest) { r.Registration.Payee[0] ^= 1 }, ErrRegistrationUnauthorized},
		"another root node":           {func(r *RegistrationRequest) { r.Registration.RootNodeID = "root-2" }, ErrRegistrationUnauthorized},
		"another root key":            {func(r *RegistrationRequest) { r.Registration.RootKey = otherPub }, ErrRegistrationUnauthorized},
		"another identity":            {func(r *RegistrationRequest) { r.Domain, r.ID = vrschema.BindingDomainText, 8 }, ErrRegistrationUnauthorized},
	} {
		req := f.req
		req.Registration.RootKey = append([]byte(nil), req.Registration.RootKey...)
		tc.mutate(&req)
		sig, err := f.a.SignRegistration(req)
		require.ErrorIs(t, err, tc.err, name)
		require.Empty(t, sig, name)
	}
	// a nonce is the contract's to check: the authority signs any
	req := f.req
	req.Registration.Nonce = 1 << 40
	_, err = f.a.SignRegistration(req)
	require.NoError(t, err)
}

// Without a policy the authority signs no registration; a retired or key-lost authority neither.
func TestRegistrationNeedsAPolicy(t *testing.T) {
	f := newRegFixture(t, false)
	_, err := f.a.SignRegistration(f.req)
	require.ErrorIs(t, err, ErrRegistrationUnauthorized)
	_, err = New(newFixture(t, 1).enroll, trustStub{}, WithRegistrationPolicy(RegistrationPolicy{}))
	require.Error(t, err)
}
