package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

// popFixture serves the fixture's authority a second time with a possession-proof endpoint.
func (f *fixture) popFixture(t *testing.T) (dial Dialer, credential []byte) {
	t.Helper()
	credential, err := NewCredential()
	require.NoError(t, err)
	server, err := NewServer(f.authority, Config{OperatorCredential: f.operatorCredential, PoPCredential: credential})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	dir := socketDir(t)
	l, err := ListenUnix(filepath.Join(dir, "pop.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = server.Serve(l, PoPEndpoint) }()
	return UnixDialer(filepath.Join(dir, "pop.sock")), credential
}

// The automated member signs the handoff possession proof over its own endpoint, and the handoff verifies it.
func TestThePoPEndpointSignsTheHandoffPoPForTheMember(t *testing.T) {
	f := newFixture(t)
	dial, credential := f.popFixture(t)
	c, err := NewPoPClient(ClientConfig{Dial: dial, Credential: credential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	req := f.popRequest(t)
	pop, err := c.SignHandoffPoP(context.Background(), req)
	require.NoError(t, err)
	require.NoError(t, evmassign.VerifyPoPs(req.Context, req.Successor, []evmassign.PoP{pop}))
	// the authority's own checks apply on this channel too
	bad := f.popRequest(t)
	bad.NodeID = "node-2"
	_, err = c.SignHandoffPoP(context.Background(), bad)
	require.ErrorIs(t, err, signingauthority.ErrContextMismatch)
	bad = f.popRequest(t)
	bad.Domain = "UNICITY_H3_EVM_ASSIGNMENT"
	_, err = c.SignHandoffPoP(context.Background(), bad)
	require.ErrorIs(t, err, signingauthority.ErrPoPDomain)
}

// The member's credential reaches nothing but the possession proof: every other operation is refused on its endpoint, and its credential
// is refused on the operator and client endpoints.
func TestThePoPEndpointServesNothingElse(t *testing.T) {
	f := newFixture(t)
	dial, credential := f.popFixture(t)
	for _, o := range []op{opReplaceSession, opStatus, opEnrollment, opCompleteEnrollment, opAdvanceEpoch, opAdvanceWithProof, opSignElectionPoP,
		opSignDelegationPossession, opReserve, opSign, opRestoreStatus} {
		answer, err := rawCall(t, dial, wireRequest{Version: protocolVersion, Op: uint64(o), Credential: credential})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal, o.String())
		require.Empty(t, answer.Payload, o.String())
	}
	// the operator's credential does not open it, and neither does none
	payload, err := types.Cbor.Marshal(handoffPoPPayload{Domain: evmassign.PoPDomain})
	require.NoError(t, err)
	for name, cred := range map[string][]byte{"operator": f.operatorCredential, "none": nil} {
		answer, err := rawCall(t, dial, wireRequest{Version: protocolVersion, Op: uint64(opSignHandoffPoP), Credential: cred, Payload: payload})
		require.NoError(t, err)
		require.Equal(t, errOperatorUnauthenticated.Error(), answer.Refusal, name)
	}
	// the member's credential opens no other endpoint
	answer, err := rawCall(t, f.operatorDial, wireRequest{Version: protocolVersion, Op: uint64(opStatus), Credential: credential})
	require.NoError(t, err)
	require.Equal(t, errOperatorUnauthenticated.Error(), answer.Refusal)
	answer, err = rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(opRestoreStatus), Credential: credential})
	require.NoError(t, err)
	require.NotEmpty(t, answer.Refusal)
}

// An authority configured without a member credential serves nothing on a possession-proof endpoint, and the credential may not be the operator's.
func TestThePoPCredentialIsSeparate(t *testing.T) {
	f := newFixture(t)
	_, err := NewServer(f.authority, Config{OperatorCredential: f.operatorCredential, PoPCredential: f.operatorCredential})
	require.Error(t, err)
	_, err = NewServer(f.authority, Config{OperatorCredential: f.operatorCredential, PoPCredential: []byte("short")})
	require.Error(t, err)
}
