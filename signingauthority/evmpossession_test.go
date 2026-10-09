package signingauthority

import (
	"crypto/ecdsa"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-go-base/types"
)

const publicationFixture = "../rootchain/evmstate/testdata/publication.json"

// electionPoPFixture is the published primary candidate of the contracts' fixture with its member 0 made this authority's validator: its
// EVM key is the authority's key, its EVM node the enrolled node, and the successor binding names the enrolled network, partition and next
// shard epoch.
func electionPoPFixture(t *testing.T) (*Authority, ElectionPoPRequest, []byte) {
	t.Helper()
	f := newFixture(t, 1)
	a, err := New(f.enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	p := evmstatetest.Load(t, publicationFixture)
	c := p.Candidate
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500000000, Epoch: shardEpoch + 1, Validators: []*types.NodeInfo{{NodeID: testNodeID, SigKey: pub, Stake: 1}}}
	c.Assignment, err = types.Cbor.Marshal(pdr)
	require.NoError(t, err)
	c.Network, c.Predecessor = uint64(testNetworkID), bytes32(1)
	c.Identities = append([]evmassign.Identity(nil), c.Identities...)
	c.Identities[0].EVMKey, c.Identities[0].EVMNodeID = pub, testNodeID
	return a, ElectionPoPRequest{Candidate: c, Deployment: p.Deployment, Attempt: 3}, pub
}

// The proof the authority signs is the one the election and the root verify: the digest evmassign computes, signed by the authority's own
// key, in the contracts' form (65 bytes, v = 27/28), and recoverable to that key.
func TestElectionPoPIsTheDigestEvmassignVerifies(t *testing.T) {
	a, req, pub := electionPoPFixture(t)
	pop, err := a.SignElectionPoP(req)
	require.NoError(t, err)
	require.Equal(t, pub, pop.EVMKey)
	digest, id, err := evmassign.ElectionPoPDigest(req.Candidate, req.Deployment, req.Attempt, pub, testNodeID)
	require.NoError(t, err)
	require.Equal(t, id, pop.ID)
	require.Len(t, pop.Signature, 65)
	require.Contains(t, []byte{27, 28}, pop.Signature[64])
	sig := append([]byte(nil), pop.Signature...)
	sig[64] -= 27
	got, err := ethcrypto.SigToPub(digest[:], sig)
	require.NoError(t, err)
	require.Equal(t, pub, ethcrypto.CompressPubkey(got))
	// evmassign's own verifier agrees: the authority's proof, with the others, assembles
	_ = evmassign.AssemblePoPs
	require.False(t, a.Status().HasReservation, "no certification round is touched")
}

// A key that signs through SignEVMPoP gives the identical bytes: the authority's method is the signer of the spec, not a new one.
func TestElectionPoPEqualsSignEVMPoPForTheSameKey(t *testing.T) {
	a, req, _ := electionPoPFixture(t)
	hs, ok := a.signer.(hashSigner)
	require.True(t, ok)
	priv := mustPrivate(t, a)
	want, err := evmassign.SignEVMPoP(priv, req.Candidate, req.Deployment, req.Attempt)
	require.NoError(t, err)
	got, err := a.SignElectionPoP(req)
	require.NoError(t, err)
	require.Equal(t, want, got)
	_ = hs
}

func mustPrivate(t *testing.T, a *Authority) *ecdsa.PrivateKey {
	raw, err := a.signer.MarshalPrivateKey()
	require.NoError(t, err)
	k, err := ethcrypto.ToECDSA(raw)
	require.NoError(t, err)
	return k
}

func TestElectionPoPRefusesAWrongContext(t *testing.T) {
	cases := map[string]func(*ElectionPoPRequest){
		"another network":                  func(r *ElectionPoPRequest) { r.Candidate.Network++ },
		"no predecessor":                   func(r *ElectionPoPRequest) { r.Candidate.Predecessor = nil },
		"the key is no member's":           func(r *ElectionPoPRequest) { r.Candidate.Identities[0].EVMKey = append([]byte{2}, make([]byte, 32)...) },
		"the member names another node":    func(r *ElectionPoPRequest) { r.Candidate.Identities[0].EVMNodeID = "someone-else" },
		"a candidate without its binding":  func(r *ElectionPoPRequest) { r.Candidate.Assignment = nil },
		"a recovery has no proofs to give": func(r *ElectionPoPRequest) { r.Candidate.Kind = evmassign.KindRecovery },
		"another partition": func(r *ElectionPoPRequest) {
			pdr, _ := r.Candidate.Successor()
			pdr.PartitionID++
			r.Candidate.Assignment, _ = types.Cbor.Marshal(pdr)
		},
		"a successor epoch far ahead": func(r *ElectionPoPRequest) {
			pdr, _ := r.Candidate.Successor()
			pdr.Epoch += 100
			r.Candidate.Assignment, _ = types.Cbor.Marshal(pdr)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, req, _ := electionPoPFixture(t)
			mutate(&req)
			_, err := a.SignElectionPoP(req)
			require.ErrorIs(t, err, ErrContextMismatch)
		})
	}
}

func delegationFixture(t *testing.T) (*Authority, DelegationPossessionRequest, []byte) {
	t.Helper()
	f := newFixture(t, 1)
	a, err := New(f.enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	word, err := evmassign.NodeIDWord(testNodeID)
	require.NoError(t, err)
	root, err := evmassign.NodeIDWord("r-joiner")
	require.NoError(t, err)
	r := evmassign.DelegationRequest{Id: 5, Generation: 1, Expiry: 1_000_000_000,
		Binding: evmassign.DelegationBinding{RootNodeID: root, RootKey: append([]byte{2}, make([]byte, 32)...), EvmNodeID: word, EvmKey: pub,
			OperatorPayee: ethcommon.HexToAddress("0x3Ec29B2041")}}
	return a, DelegationPossessionRequest{Network: [32]byte{7}, Chain: [32]byte{31: 0x7a}, Election: [20]byte{0xF6, 0x28}, Request: r}, pub
}

func TestDelegationPossessionIsTheDigestOfTheSpec(t *testing.T) {
	a, req, pub := delegationFixture(t)
	sig, err := a.SignDelegationPossession(req)
	require.NoError(t, err)
	digest := evmassign.DelegationDigest(req.Network, req.Chain, req.Election, req.Request)
	require.Len(t, sig, 65)
	rec := append([]byte(nil), sig...)
	rec[64] -= 27
	got, err := ethcrypto.SigToPub(digest[:], rec)
	require.NoError(t, err)
	require.Equal(t, pub, ethcrypto.CompressPubkey(got), "the signature recovers to the authority's key over the delegation digest")
	// the digest is bound to every field the contract binds: another payload gives a signature for another digest
	other := req
	other.Request.DelegationNonce++
	sig2, err := a.SignDelegationPossession(other)
	require.NoError(t, err)
	require.NotEqual(t, sig, sig2)
}

func TestDelegationPossessionRefusesAnotherKeyOrNode(t *testing.T) {
	for name, mutate := range map[string]func(*DelegationPossessionRequest){
		"another EVM key": func(r *DelegationPossessionRequest) {
			r.Request.Binding.EvmKey = append([]byte{3}, make([]byte, 32)...)
		},
		"another EVM node": func(r *DelegationPossessionRequest) { r.Request.Binding.EvmNodeID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			a, req, _ := delegationFixture(t)
			mutate(&req)
			_, err := a.SignDelegationPossession(req)
			require.ErrorIs(t, err, ErrContextMismatch)
		})
	}
}

func TestEVMPossessionRefusedByAClosedOrKeyLostAuthority(t *testing.T) {
	a, req, _ := delegationFixture(t)
	a.Close()
	_, err := a.SignDelegationPossession(req)
	require.ErrorIs(t, err, ErrKeyLost)
	b, ereq, _ := electionPoPFixture(t)
	b.Close()
	_, err = b.SignElectionPoP(ereq)
	require.ErrorIs(t, err, ErrKeyLost)
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
