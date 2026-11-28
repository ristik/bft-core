package service

import (
	"context"
	"fmt"
	"testing"
	"time"

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

// The pinned P85 possession: the operator channel pins once, signs the pinned election's digest and refuses the rest; the client channel
// never reaches either operation.
func TestTheOperatorChannelSignsThePinnedPosPoP(t *testing.T) {
	src := &posSource{view: signingauthority.PosDeploymentView{Network: [32]byte{7}, ChainID: [32]byte{31: 0x7a}, Election: [20]byte{0xF6}}}
	f := newFixtureWith(t, nil, func(*types.RootTrustBaseV1) []signingauthority.Option {
		return []signingauthority.Option{signingauthority.WithPosSource(src, 0x7a)}
	})
	ctx := context.Background()
	_, key, err := f.operator.Enrollment(ctx)
	require.NoError(t, err)
	req := signingauthority.PosPoPRequest{ResultID: [32]byte{1}, AssignmentID: [32]byte{2}, Snapshot: [32]byte{3}, Attempt: 2, ID: 5, Generation: 1}
	_, err = f.operator.SignPosPoP(ctx, req)
	require.ErrorIs(t, err, signingauthority.ErrPosPolicy, "no pin, no proof")

	pin := signingauthority.PosPolicy{Network: [32]byte{7}, ChainID: [32]byte{31: 0x7a}, Election: [20]byte{0xF6}, IDs: []uint64{5}}
	require.NoError(t, f.operator.SetPosPolicy(ctx, pin))
	require.NoError(t, f.operator.SetPosPolicy(ctx, pin))
	other := pin
	other.Election = [20]byte{0xF7}
	require.ErrorIs(t, f.operator.SetPosPolicy(ctx, other), signingauthority.ErrPosPolicyConflict)
	require.NoError(t, f.operator.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{5}}), "the deployment fields are derived")

	pop, err := f.operator.SignPosPoP(ctx, req)
	require.NoError(t, err)
	var d evmassign.ElectionDeployment
	d.NetworkWord, d.ChainID, d.Election = pin.Network, pin.ChainID, pin.Election
	require.Equal(t, key, recovers(t, evmassign.PoPDigest(d, req.ResultID, req.AssignmentID, req.Snapshot, req.Attempt, req.ID, req.Generation, key), pop.Signature))
	req.ID = 4
	_, err = f.operator.SignPosPoP(ctx, req)
	require.ErrorIs(t, err, signingauthority.ErrPosPolicy)

	client := f.admit(t)
	for _, o := range []op{opSignPosPoP, opSetPosPolicy, opPosPolicyStatus} {
		answer, err := rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(o), Credential: client.ex.credential, Payload: []byte{0x80}})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal, "%v", o)
	}
}

// posSource is the execution client's view of the P85 deployment; err, when set, is the answer instead.
type posSource struct {
	view signingauthority.PosDeploymentView
	err  error
}

func (p *posSource) ReadPosDeployment(context.Context, signingauthority.PosQuery) (signingauthority.PosDeploymentView, error) {
	return p.view, p.err
}

// #1222: the operator channel's pin is verified, and the refusals cross the wire by name: a wrong field is refused, a source that does
// not answer is pending.
func TestTheOperatorChannelPinIsVerified(t *testing.T) {
	src := &posSource{view: signingauthority.PosDeploymentView{Network: [32]byte{7}, ChainID: [32]byte{31: 0x7a}, Election: [20]byte{0xF6}}}
	f := newFixtureWith(t, nil, func(*types.RootTrustBaseV1) []signingauthority.Option {
		return []signingauthority.Option{signingauthority.WithPosSource(src, 0x7a)}
	})
	ctx := context.Background()
	wrong := signingauthority.PosPolicy{Network: [32]byte{8}, IDs: []uint64{5}}
	require.ErrorIs(t, f.operator.SetPosPolicy(ctx, wrong), signingauthority.ErrPosPolicy)
	src.err = fmt.Errorf("%w: down", signingauthority.ErrPosPending)
	require.ErrorIs(t, f.operator.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{5}}), signingauthority.ErrPosPending)
	src.err = nil
	require.NoError(t, f.operator.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{5}}))
}

// hungSource answers no read until released, whatever the read's context: an endpoint that connects and never answers.
type hungSource struct {
	view    signingauthority.PosDeploymentView
	entered chan struct{}
	release chan struct{}
}

func (h *hungSource) ReadPosDeployment(context.Context, signingauthority.PosQuery) (signingauthority.PosDeploymentView, error) {
	h.entered <- struct{}{}
	<-h.release
	return h.view, nil
}

// sol's round 2 on #1328: across the wire a pin that waited out another verification is busy (nothing kept), distinct from a pending pin
// (kept), and it answers within the server's pin bound, before the operator client's deadline.
func TestTheOperatorChannelTellsABusyPinFromAPendingOne(t *testing.T) {
	src := &hungSource{view: signingauthority.PosDeploymentView{Network: [32]byte{7}, ChainID: [32]byte{31: 0x7a}, Election: [20]byte{0xF6}},
		entered: make(chan struct{}, 4), release: make(chan struct{})}
	f := newConfiguredFixture(t, nil, func(*types.RootTrustBaseV1) []signingauthority.Option {
		return []signingauthority.Option{signingauthority.WithPosSource(src, 0x7a)}
	}, ManagedSession{}, Config{PinTimeout: 300 * time.Millisecond})
	ctx := context.Background()
	// two operator connections: one connection answers its requests in order
	other, err := NewOperatorClient(ClientConfig{Dial: f.operatorDial, Credential: f.operatorCredential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })
	first := make(chan error, 1)
	go func() { first <- other.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{6}}) }()
	<-src.entered
	err = f.operator.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{5}})
	require.ErrorIs(t, err, signingauthority.ErrPosBusy, "the second pin waited out the first's verification")
	require.NotErrorIs(t, err, signingauthority.ErrPosPending, "and is not reported as kept")
	close(src.release)
	<-first // the first pin's answer was due long ago (its client may have given up); the authority finishes verifying it
	require.NoError(t, f.operator.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{6}}), "identity 6 is the verified pin")
	require.ErrorIs(t, f.operator.SetPosPolicy(ctx, signingauthority.PosPolicy{IDs: []uint64{5}}), signingauthority.ErrPosPolicyConflict,
		"the busy request for identity 5 was neither kept nor merged")
}
