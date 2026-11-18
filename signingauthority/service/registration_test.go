package service

import (
	"context"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

func registrationFixture(t *testing.T) (*fixture, signingauthority.RegistrationRequest, signingauthority.RegistrationDeployment) {
	rk, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	rootKey := ethcrypto.CompressPubkey(&rk.PublicKey)
	owner, payee := [20]byte{0xaa}, [20]byte{0xbb}
	depl := signingauthority.RegistrationDeployment{Network: vrschema.Keccak([]byte("n")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry}
	f := newFixtureWith(t, nil, func(*types.RootTrustBaseV1) []signingauthority.Option {
		return []signingauthority.Option{signingauthority.WithRegistrationPolicy(signingauthority.RegistrationPolicy{Deployment: depl,
			Authorized: []signingauthority.RegistrationAuthorization{{Domain: vrschema.RegisterDomainText, Owner: owner, RootNodeID: "r", RootKey: rootKey, Payee: payee}}})}
	})
	_, pub, err := f.operator.Enrollment(context.Background())
	require.NoError(t, err)
	return f, signingauthority.RegistrationRequest{Domain: vrschema.RegisterDomainText, Owner: owner,
		Registration: vrschema.Registration{RootNodeID: "r", RootKey: rootKey, EVMNodeID: "node-1", EVMKey: pub, Payee: payee, Nonce: 2}}, depl
}

// The operator channel signs the registration digest the authority computed, and its refusals keep their names across the wire.
func TestTheOperatorChannelSignsARegistrationAndRefusesByName(t *testing.T) {
	f, req, depl := registrationFixture(t)
	sig, err := f.operator.SignRegistration(context.Background(), req)
	require.NoError(t, err)
	d := vrschema.RegistrationDigest(false, depl.Network, depl.ChainID, depl.Registry, req.Owner, 0, req.Registration)
	got, err := ethcrypto.SigToPub(d[:], append(append([]byte(nil), sig[:64]...), sig[64]-27))
	require.NoError(t, err)
	require.Equal(t, req.Registration.EVMKey, ethcrypto.CompressPubkey(got))

	bad := req
	bad.Domain = "UNICITY_H3_EVM_ASSIGNMENT_POP"
	_, err = f.operator.SignRegistration(context.Background(), bad)
	require.ErrorIs(t, err, signingauthority.ErrRegistrationDomain)
	bad = req
	bad.Registration.EVMNodeID = "node-2"
	_, err = f.operator.SignRegistration(context.Background(), bad)
	require.ErrorIs(t, err, signingauthority.ErrContextMismatch)
	bad = req
	bad.Owner = [20]byte{1}
	_, err = f.operator.SignRegistration(context.Background(), bad)
	require.ErrorIs(t, err, signingauthority.ErrRegistrationUnauthorized)
}

// Neither the shard node's client channel nor the member's possession-proof channel serves it.
func TestRegistrationSigningIsOperatorOnly(t *testing.T) {
	f, req, _ := registrationFixture(t)
	client := f.admit(t)
	_, has := reflectMethods(client)["SignRegistration"]
	require.False(t, has)
	answer, err := rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(opSignRegistration), Credential: client.ex.credential})
	require.NoError(t, err)
	require.Equal(t, errWrongEndpoint.Error(), answer.Refusal)
	require.Empty(t, answer.Payload)
	_ = req
}
