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
	require.ErrorIs(t, f.a.ReloadRegistrationAuthorizations(f.depl, nil), ErrRegistrationUnauthorized, "no pin to keep: no reload")
}

// The operator refreshes the authorizations of the running authority: a pin-only start signs nothing, a reload authorizes a registration,
// a later one a rotation for the assigned id, and the key, the pin and the signing record are the same throughout.
func TestRegistrationPolicyReloadKeepsKeyPinAndRecord(t *testing.T) {
	f := newRegFixture(t, true)
	reg, bind := f.policy.Authorized[0], f.policy.Authorized[1]
	require.NoError(t, f.a.ReloadRegistrationAuthorizations(f.depl, nil))
	_, err := f.a.SignRegistration(f.req)
	require.ErrorIs(t, err, ErrRegistrationUnauthorized)

	before := f.a.Status()
	require.NoError(t, f.a.ReloadRegistrationAuthorizations(f.depl, []RegistrationAuthorization{reg}))
	_, err = f.a.SignRegistration(f.req)
	require.NoError(t, err)
	rot := f.req
	rot.Domain, rot.ID = vrschema.BindingDomainText, 7
	_, err = f.a.SignRegistration(rot)
	require.ErrorIs(t, err, ErrRegistrationUnauthorized, "no rotation is authorized yet")

	require.NoError(t, f.a.ReloadRegistrationAuthorizations(f.depl, []RegistrationAuthorization{reg, bind}))
	sig, err := f.a.SignRegistration(rot)
	require.NoError(t, err)
	d := vrschema.RegistrationDigest(true, f.depl.Network, f.depl.ChainID, f.depl.Registry, rot.Owner, 7, rot.Registration)
	got, err := ethcrypto.SigToPub(d[:], append(append([]byte(nil), sig[:64]...), sig[64]-27))
	require.NoError(t, err)
	require.Equal(t, f.pub, ethcrypto.CompressPubkey(got), "the same key, under the pin from startup")
	pub, err := f.a.SigningPublicKey()
	require.NoError(t, err)
	require.Equal(t, f.pub, pub)
	require.Equal(t, before, f.a.Status(), "a possession-style signature touches no signing record")
	require.ErrorIs(t, f.a.ReloadRegistrationAuthorizations(f.depl, []RegistrationAuthorization{{Domain: "x"}}), ErrRegistrationDomain)
	// a list made for another deployment (staging against production) is refused whole, and what was authorized stays
	for name, d := range map[string]RegistrationDeployment{
		"another network":  {Network: [32]byte{9}, ChainID: f.depl.ChainID, Registry: f.depl.Registry},
		"another chain id": {Network: f.depl.Network, ChainID: vrschema.U64(99), Registry: f.depl.Registry},
		"another registry": {Network: f.depl.Network, ChainID: f.depl.ChainID, Registry: [20]byte{9}},
	} {
		require.ErrorIs(t, f.a.ReloadRegistrationAuthorizations(d, nil), ErrRegistrationUnauthorized, name)
	}
	_, err = f.a.SignRegistration(rot)
	require.NoError(t, err, "a refused reload changed nothing")
}

// A policy entry that can never match, or an incomplete deployment pin, is refused when the policy is given.
func TestRegistrationPolicyRefusesEntriesThatCanNeverMatch(t *testing.T) {
	f := newRegFixture(t, true)
	good := f.policy.Authorized[0]
	other, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	for name, mutate := range map[string]func(*RegistrationAuthorization){
		"register with an id":   func(x *RegistrationAuthorization) { x.ID = 7 },
		"binding without an id": func(x *RegistrationAuthorization) { x.Domain = vrschema.BindingDomainText },
		"a short root key":      func(x *RegistrationAuthorization) { x.RootKey = []byte{1} },
		"an off-curve root key": func(x *RegistrationAuthorization) { x.RootKey = append([]byte{2}, make([]byte, 32)...) },
		"no root node id":       func(x *RegistrationAuthorization) { x.RootNodeID = "" },
		"a zero owner":          func(x *RegistrationAuthorization) { x.Owner = [20]byte{} },
		"a zero payee":          func(x *RegistrationAuthorization) { x.Payee = [20]byte{} },
	} {
		x := good
		x.RootKey = ethcrypto.CompressPubkey(&other.PublicKey)
		mutate(&x)
		fx := newFixture(t, 1)
		_, err := New(fx.enroll, trustStub{tb: fx.tb}, WithRegistrationPolicy(RegistrationPolicy{Deployment: f.depl, Authorized: []RegistrationAuthorization{x}}))
		require.Error(t, err, name)
		require.Error(t, f.a.ReloadRegistrationAuthorizations(f.depl, []RegistrationAuthorization{x}), name)
	}
	for name, d := range map[string]RegistrationDeployment{
		"no network":  {ChainID: f.depl.ChainID, Registry: f.depl.Registry},
		"no chain id": {Network: f.depl.Network, Registry: f.depl.Registry},
		"no registry": {Network: f.depl.Network, ChainID: f.depl.ChainID},
	} {
		fx := newFixture(t, 1)
		_, err := New(fx.enroll, trustStub{tb: fx.tb}, WithRegistrationPolicy(RegistrationPolicy{Deployment: d}))
		require.Error(t, err, name)
	}
}

// At `apply` time a joiner's authority is still pending (no configuration hash): it signs a registration all the same.
func TestAPendingAuthoritySignsARegistration(t *testing.T) {
	f := newFixture(t, 1)
	enroll := f.enroll
	enroll.ShardConfHash = nil
	rk, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	rkb := ethcrypto.CompressPubkey(&rk.PublicKey)
	owner, payee := [20]byte{1}, [20]byte{2}
	depl := RegistrationDeployment{Network: vrschema.Keccak([]byte("n")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry}
	a, err := New(enroll, trustStub{tb: f.tb}, WithRegistrationPolicy(RegistrationPolicy{Deployment: depl, Authorized: []RegistrationAuthorization{
		{Domain: vrschema.RegisterDomainText, Owner: owner, RootNodeID: "r", RootKey: rkb, Payee: payee}}}))
	require.NoError(t, err)
	t.Cleanup(a.Close)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	_, err = a.SignRegistration(RegistrationRequest{Domain: vrschema.RegisterDomainText, Owner: owner,
		Registration: vrschema.Registration{RootNodeID: "r", RootKey: rkb, EVMNodeID: testNodeID, EVMKey: pub, Payee: payee}})
	require.NoError(t, err)
}
