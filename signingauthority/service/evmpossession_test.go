package service

import (
	"context"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

func (f *fixture) electionRequest(t *testing.T) signingauthority.ElectionPoPRequest {
	t.Helper()
	_, key, err := f.operator.Enrollment(context.Background())
	require.NoError(t, err)
	p := evmstatetest.Load(t, "../../rootchain/evmstate/testdata/publication.json")
	c := p.Candidate
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: testPartitionID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500000000, Epoch: 1, Validators: []*types.NodeInfo{{NodeID: "node-1", SigKey: key, Stake: 1}}}
	c.Assignment, err = types.Cbor.Marshal(pdr)
	require.NoError(t, err)
	c.Network, c.Predecessor = 5, make([]byte, 32)
	c.Predecessor[0] = 1
	c.Identities = append([]evmassign.Identity(nil), c.Identities...)
	c.Identities[0].EVMKey, c.Identities[0].EVMNodeID = key, "node-1"
	// a primary candidate carries one handoff possession proof per successor validator: the authority gives its own
	ctx, err := c.PoPContext()
	require.NoError(t, err)
	pop, err := f.operator.SignHandoffPoP(context.Background(), signingauthority.HandoffPoPRequest{Domain: evmassign.PoPDomain, NodeID: "node-1", Successor: pdr, Context: ctx})
	require.NoError(t, err)
	c.PoPs = []evmassign.PoP{pop}
	return signingauthority.ElectionPoPRequest{Candidate: c, Deployment: p.Deployment, Attempt: 3}
}

func (f *fixture) delegationRequest(t *testing.T) signingauthority.DelegationPossessionRequest {
	t.Helper()
	_, key, err := f.operator.Enrollment(context.Background())
	require.NoError(t, err)
	node, err := evmassign.NodeIDWord("node-1")
	require.NoError(t, err)
	root, err := evmassign.NodeIDWord("r-joiner")
	require.NoError(t, err)
	return signingauthority.DelegationPossessionRequest{Network: [32]byte{7}, Chain: [32]byte{31: 0x7a}, Election: [20]byte{0xF6},
		Request: evmassign.DelegationRequest{Id: 5, Generation: 1, Expiry: 99, Binding: evmassign.DelegationBinding{RootNodeID: root,
			RootKey: append([]byte{2}, make([]byte, 32)...), EvmNodeID: node, EvmKey: key, OperatorPayee: ethcommon.Address{1}}}}
}

func recovers(t *testing.T, digest [32]byte, sig []byte) []byte {
	t.Helper()
	require.Len(t, sig, 65)
	rec := append([]byte(nil), sig...)
	rec[64] -= 27
	pub, err := ethcrypto.SigToPub(digest[:], rec)
	require.NoError(t, err)
	return ethcrypto.CompressPubkey(pub)
}

// The operator channel serves both EVM possession signatures, and each is the digest evmassign computes, signed by the authority's key.
func TestTheOperatorChannelSignsTheEVMPossessions(t *testing.T) {
	f := newFixture(t)
	_, key, err := f.operator.Enrollment(context.Background())
	require.NoError(t, err)

	er := f.electionRequest(t)
	pop, err := f.operator.SignElectionPoP(context.Background(), er)
	require.NoError(t, err)
	digest, id, err := evmassign.ElectionPoPDigest(er.Candidate, er.Deployment, er.Attempt, key, "node-1")
	require.NoError(t, err)
	require.Equal(t, id, pop.ID)
	require.Equal(t, key, pop.EVMKey)
	require.Equal(t, key, recovers(t, digest, pop.Signature))

	dr := f.delegationRequest(t)
	sig, err := f.operator.SignDelegationPossession(context.Background(), dr)
	require.NoError(t, err)
	require.Equal(t, key, recovers(t, evmassign.DelegationDigest(dr.Network, dr.Chain, dr.Election, dr.Request), sig))
}

// The shard node's client channel never reaches either, with its own credential or the operator's.
func TestTheClientChannelRefusesTheEVMPossessions(t *testing.T) {
	f := newFixture(t)
	client := f.admit(t)
	for _, o := range []op{opSignElectionPoP, opSignDelegationPossession} {
		for name, credential := range map[string][]byte{"the client's credential": client.ex.credential, "the operator's credential": f.operator.ex.credential} {
			answer, err := rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(o), Credential: credential, Payload: []byte{0x80}})
			require.NoError(t, err)
			require.Empty(t, answer.Payload, "%v, %s: nothing was signed", o, name)
			require.Equal(t, errWrongEndpoint.Error(), answer.Refusal, "%v, %s", o, name)
		}
	}
	for _, m := range []string{"SignElectionPoP", "SignDelegationPossession"} {
		_, has := reflectMethods(client)[m]
		require.False(t, has, m)
	}
}

// A request for another key, node or context is refused across the wire under its contract name.
func TestTheEVMPossessionRefusalsKeepTheirNamesAcrossTheWire(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*signingauthority.ElectionPoPRequest){
		"another network":   func(r *signingauthority.ElectionPoPRequest) { r.Candidate.Network = 6 },
		"another validator": func(r *signingauthority.ElectionPoPRequest) { r.Candidate.Identities[0].EVMNodeID = "node-2" },
		"the key is not a member's": func(r *signingauthority.ElectionPoPRequest) {
			r.Candidate.Identities[0].EVMKey = append([]byte{2}, make([]byte, 32)...)
		},
	} {
		bad := f.electionRequest(t)
		mutate(&bad)
		_, err := f.operator.SignElectionPoP(context.Background(), bad)
		require.ErrorIs(t, err, signingauthority.ErrContextMismatch, name)
	}
	for name, mutate := range map[string]func(*signingauthority.DelegationPossessionRequest){
		"another key": func(r *signingauthority.DelegationPossessionRequest) {
			r.Request.Binding.EvmKey = append([]byte{3}, make([]byte, 32)...)
		},
		"another node": func(r *signingauthority.DelegationPossessionRequest) { r.Request.Binding.EvmNodeID[1] ^= 1 },
	} {
		bad := f.delegationRequest(t)
		mutate(&bad)
		_, err := f.operator.SignDelegationPossession(context.Background(), bad)
		require.ErrorIs(t, err, signingauthority.ErrContextMismatch, name)
	}
}

// foreignKey is a valid compressed key that is nobody's in the candidate.
func foreignKey(t *testing.T) []byte {
	k, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	return ethcrypto.CompressPubkey(&k.PublicKey)
}
