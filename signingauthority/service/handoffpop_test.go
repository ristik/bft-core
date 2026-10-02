package service

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

func (f *fixture) popRequest(t *testing.T) signingauthority.HandoffPoPRequest {
	t.Helper()
	_, key, err := f.operator.Enrollment(context.Background())
	require.NoError(t, err)
	succ := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: testPartitionID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500000000, Epoch: 1, Validators: []*types.NodeInfo{{NodeID: "node-1", SigKey: key, Stake: 1}}}
	return signingauthority.HandoffPoPRequest{Domain: evmassign.PoPDomain, NodeID: "node-1", Successor: succ,
		Context: evmassign.PoPContext{Network: 5, Attempt: 3, Predecessor: [32]byte{1}}}
}

// The operator channel serves the handoff possession proof, and it is the proof the handoff verifies.
func TestTheOperatorChannelSignsTheHandoffPoPAndItVerifiesInTheHandoff(t *testing.T) {
	f := newFixture(t)
	req := f.popRequest(t)
	pop, err := f.operator.SignHandoffPoP(context.Background(), req)
	require.NoError(t, err)
	require.NoError(t, evmassign.VerifyPoPs(req.Context, req.Successor, []evmassign.PoP{pop}))
}

// The shard node's client channel never reaches it: with its own credential, or the operator's, the operation is not served there.
func TestTheClientChannelRefusesTheHandoffPoP(t *testing.T) {
	f := newFixture(t)
	client := f.admit(t)
	req := f.popRequest(t)
	succ, err := types.Cbor.Marshal(req.Successor)
	require.NoError(t, err)
	payload, err := types.Cbor.Marshal(handoffPoPPayload{Domain: req.Domain, Network: req.Context.Network, Attempt: req.Context.Attempt,
		Predecessor: req.Context.Predecessor[:], Successor: succ, NodeID: req.NodeID})
	require.NoError(t, err)
	for name, credential := range map[string][]byte{"the client's credential": client.ex.credential, "the operator's credential": f.operator.ex.credential} {
		answer, err := rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(opSignHandoffPoP), Credential: credential, Payload: payload})
		require.NoError(t, err)
		require.Empty(t, answer.Payload, "%s: nothing was signed", name)
		require.NotEmpty(t, answer.Refusal, name)
	}
	answer, err := rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(opSignHandoffPoP), Credential: client.ex.credential, Payload: payload})
	require.NoError(t, err)
	require.Equal(t, errWrongEndpoint.Error(), answer.Refusal, "the client endpoint does not serve a possession proof")
	// The client API has no such method either.
	_, has := reflectMethods(client)["SignHandoffPoP"]
	require.False(t, has)
}

// A wrong domain or context is refused across the wire under its own contract name.
func TestTheHandoffPoPRefusalsKeepTheirNamesAcrossTheWire(t *testing.T) {
	f := newFixture(t)
	req := f.popRequest(t)
	wrongDomain := req
	wrongDomain.Domain = "UNICITY_H3_EVM_ASSIGNMENT"
	_, err := f.operator.SignHandoffPoP(context.Background(), wrongDomain)
	require.ErrorIs(t, err, signingauthority.ErrPoPDomain)

	for name, mutate := range map[string]func(*signingauthority.HandoffPoPRequest){
		"another node":       func(r *signingauthority.HandoffPoPRequest) { r.NodeID = "node-2" },
		"another network":    func(r *signingauthority.HandoffPoPRequest) { r.Context.Network = 6 },
		"another partition":  func(r *signingauthority.HandoffPoPRequest) { r.Successor.PartitionID++ },
		"not the next epoch": func(r *signingauthority.HandoffPoPRequest) { r.Successor.Epoch = 5 },
	} {
		bad := f.popRequest(t)
		mutate(&bad)
		_, err := f.operator.SignHandoffPoP(context.Background(), bad)
		require.ErrorIs(t, err, signingauthority.ErrContextMismatch, name)
	}
}

func reflectMethods(v any) map[string]struct{} {
	out := map[string]struct{}{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumMethod(); i++ {
		out[t.Method(i).Name] = struct{}{}
	}
	return out
}

// syncBuffer is a log sink the server goroutines and the test can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// The possession proof is the authority's only signature outside certification, so every signing is audited, and a refusal is not
// logged as one.
func TestASignedHandoffPoPIsLoggedAndARefusalIsNot(t *testing.T) {
	var sink syncBuffer
	f := newFixtureWithLog(t, slog.New(slog.NewTextHandler(&sink, &slog.HandlerOptions{Level: slog.LevelInfo})))
	req := f.popRequest(t)
	_, err := f.operator.SignHandoffPoP(context.Background(), req)
	require.NoError(t, err)
	line := sink.String()
	require.Contains(t, line, "signed a handoff possession proof")
	require.Contains(t, line, "node=node-1")
	require.Contains(t, line, "attempt=3")
	require.Contains(t, line, "successorEpoch=")
	require.Contains(t, line, "predecessor=01")

	sink.Reset()
	req.Domain = "certification"
	_, err = f.operator.SignHandoffPoP(context.Background(), req)
	require.ErrorIs(t, err, signingauthority.ErrPoPDomain)
	require.NotContains(t, sink.String(), "signed a handoff possession proof")
	require.Contains(t, sink.String(), "refusing a handoff possession proof")
}
