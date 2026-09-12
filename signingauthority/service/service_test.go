package service

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const testPartitionID types.PartitionID = 0x01020304

// fixture is one authority behind its two endpoints, with certificates it will authenticate.
type fixture struct {
	authority *signingauthority.Authority
	trustBase *types.RootTrustBaseV1
	server    *Server
	operator  *OperatorClient
	clientDir Dialer

	rootSigner abcrypto.Signer
	uc         *types.UnicityCertificate
	tr         *certification.TechnicalRecord
	proposed   *certification.BlockCertificationRequest
}

type staticTrust struct{ tb *types.RootTrustBaseV1 }

func (s staticTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

// socketDir is short on purpose: a Unix socket path is limited to about 100 bytes, and the default
// temporary directory on macOS is long enough to matter.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "f6c-sa-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)

	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: testPartitionID}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)

	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: 6, Epoch: 0, Leader: "node-1", StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	stateRoot := bytes.Repeat([]byte{0xa1}, 32)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: 5, PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: stateRoot,
		BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, rootSigner, ir, pdr, 41, zero, trHash)

	authority, err := signingauthority.New(signingauthority.Enrollment{
		AuthorityID: "authority-1", NodeID: "node-1", NetworkID: 5, PartitionID: testPartitionID,
		ShardID: types.ShardID{}, ShardEpoch: 0, RootEpoch: signingauthority.PinRootEpoch(1),
		ShardConfHash: confHash, Profile: signingauthority.ProfileLegacyBCRv1,
	}, staticTrust{tb: tb})
	require.NoError(t, err)
	t.Cleanup(authority.Close)

	operatorCredential, err := NewCredential()
	require.NoError(t, err)
	server, err := NewServer(authority, Config{OperatorCredential: operatorCredential})
	require.NoError(t, err)
	t.Cleanup(server.Close)

	dir := socketDir(t)
	clientListener, err := ListenUnix(filepath.Join(dir, "client.sock"))
	require.NoError(t, err)
	operatorListener, err := ListenUnix(filepath.Join(dir, "operator.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientListener.Close(); _ = operatorListener.Close() })
	go func() { _ = server.Serve(clientListener, ClientEndpoint) }()
	go func() { _ = server.Serve(operatorListener, OperatorEndpoint) }()

	operator, err := NewOperatorClient(ClientConfig{
		Dial: UnixDialer(filepath.Join(dir, "operator.sock")), Credential: operatorCredential, Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = operator.Close() })

	return &fixture{
		authority: authority, trustBase: tb, server: server, operator: operator,
		clientDir:  UnixDialer(filepath.Join(dir, "client.sock")),
		rootSigner: rootSigner, uc: uc, tr: tr,
		proposed: &certification.BlockCertificationRequest{
			PartitionID: testPartitionID, ShardID: types.ShardID{}, NodeID: "node-1",
			InputRecord: &types.InputRecord{
				Version: 1, RoundNumber: 6, Epoch: 0, PreviousHash: stateRoot,
				Hash: bytes.Repeat([]byte{0xc1}, 32), BlockHash: bytes.Repeat([]byte{0xc2}, 32),
				SummaryValue: []byte{}, Timestamp: uc.UnicitySeal.Timestamp,
			},
		},
	}
}

// admit issues a session through the operator endpoint and provisions a client with the credential.
func (f *fixture) admit(t *testing.T) *Client {
	t.Helper()
	credential, err := f.operator.ReplaceSession(context.Background())
	require.NoError(t, err)
	client, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: credential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func (f *fixture) request() signingauthority.Request {
	return signingauthority.Request{UC: f.uc, Technical: f.tr, Proposed: f.proposed}
}

func TestAFullExchangeAcrossTheBoundary(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	client := f.admit(t)

	authorization, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)
	require.EqualValues(t, 6, authorization.AssignedRound)
	require.NotEmpty(t, authorization.Unsigned)
	require.NotEqual(t, [32]byte{}, authorization.UnsignedDigest)

	require.NoError(t, client.Sign(ctx))
	require.NoError(t, client.RetainResponse(ctx))
	released, err := client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)

	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(released, &signed))
	unsigned, err := signed.Bytes()
	require.NoError(t, err)
	require.Equal(t, authorization.Unsigned, unsigned, "the released response is the reserved request, signed")

	_, key, err := f.operator.Enrollment(ctx)
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(key)
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(verifier), "and it verifies under the enrolled key")

	// The same release replays rather than repeating the work.
	again, err := client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)
	require.Equal(t, released, again)
}

func TestTheEndpointsDoNotServeEachOther(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	client := f.admit(t)

	t.Run("a client cannot replace its own session", func(t *testing.T) {
		// Asked on the endpoint the shard node can reach, with the credential it holds.
		answer, err := rawCall(t, f.clientDir, wireRequest{
			Version: protocolVersion, Op: uint64(opReplaceSession), Credential: client.credential,
		})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal)
	})

	t.Run("a client credential does not open the operator endpoint", func(t *testing.T) {
		operator, err := NewOperatorClient(ClientConfig{
			Dial: f.operator.dial, Credential: client.credential, Timeout: 5 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = operator.Close() })
		_, err = operator.ReplaceSession(ctx)
		require.ErrorIs(t, err, errOperatorUnauthenticated)
	})

	t.Run("an operator credential does not sign", func(t *testing.T) {
		answer, err := rawCall(t, f.operator.dial, wireRequest{
			Version: protocolVersion, Op: uint64(opReserve), Credential: f.operator.credential,
		})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal,
			"the operator endpoint refuses signing work before any credential decides anything")
	})

	t.Run("an operator credential presented to the client endpoint is fenced", func(t *testing.T) {
		strayClient, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: f.operator.credential})
		require.NoError(t, err)
		t.Cleanup(func() { _ = strayClient.Close() })
		_, err = strayClient.Reserve(ctx, f.request())
		require.ErrorIs(t, err, signingauthority.ErrFenced)
	})
}

func TestReplacingTheSessionFencesTheCredentialItReplaced(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	first := f.admit(t)
	_, err := first.Reserve(ctx, f.request())
	require.NoError(t, err)

	second := f.admit(t)

	_, err = first.Reserve(ctx, f.request())
	require.ErrorIs(t, err, signingauthority.ErrFenced,
		"the credential the operator replaced is the thing that stops working")
	require.ErrorIs(t, first.Sign(ctx), signingauthority.ErrFenced)
	require.ErrorIs(t, first.RetainResponse(ctx), signingauthority.ErrFenced)
	_, err = first.Release(ctx, 6, [32]byte{})
	require.ErrorIs(t, err, signingauthority.ErrFenced)

	// And the new client is admitted for the same reservation, which the authority still holds.
	authorization, err := second.Reserve(ctx, f.request())
	require.NoError(t, err)
	require.EqualValues(t, 6, authorization.AssignedRound)
}

func TestAClientWithNoIssuedSessionIsFenced(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	credential, err := NewCredential()
	require.NoError(t, err)
	client, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: credential})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Reserve(ctx, f.request())
	require.ErrorIs(t, err, signingauthority.ErrFenced,
		"a credential nobody issued is in the same position as one that was replaced")
}

func TestRefusalsKeepTheirNamesAcrossTheWire(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	client := f.admit(t)

	t.Run("signing before reserving", func(t *testing.T) {
		require.ErrorIs(t, client.Sign(ctx), signingauthority.ErrNoReservation)
	})

	authorization, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)

	t.Run("releasing before the response is retained", func(t *testing.T) {
		require.NoError(t, client.Sign(ctx))
		_, err := client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
		require.ErrorIs(t, err, signingauthority.ErrResponseNotRetained)
	})

	t.Run("releasing bytes that are not the reserved ones", func(t *testing.T) {
		_, err := client.Release(ctx, authorization.AssignedRound, [32]byte{})
		require.ErrorIs(t, err, signingauthority.ErrConflict)
	})

	t.Run("a different candidate for the reserved round", func(t *testing.T) {
		other := *f.proposed
		other.BlockSize += 100
		req := f.request()
		req.Proposed = &other
		_, err := client.Reserve(ctx, req)
		require.ErrorIs(t, err, signingauthority.ErrConflict,
			"the round's own reason survives the transport, so an operator reads the same word either way")
	})

	t.Run("a certificate this authority was not enrolled for", func(t *testing.T) {
		elsewhere := *f.proposed
		elsewhere.PartitionID = testPartitionID + 1
		req := f.request()
		req.Proposed = &elsewhere
		_, err := client.Reserve(ctx, req)
		require.ErrorIs(t, err, signingauthority.ErrContextMismatch)
	})
}

func TestAnOversizeFrameIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	f := newFixture(t)
	client := f.admit(t)

	conn, err := f.clientDir(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Only the header is sent: a body this size is never written, and the server must not wait for
	// one or allocate it.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(MaxFrameBytes+1))
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write(header[:])
	require.NoError(t, err)

	var response wireResponse
	require.NoError(t, readFrame(conn, &response))
	require.Equal(t, errFrameTooLarge.Error(), response.Refusal)

	// The connection is finished after that refusal, and the authority still serves everyone else.
	_, err = client.Reserve(context.Background(), f.request())
	require.NoError(t, err)
}

func TestAFrameOfAnotherProtocolVersionIsRefused(t *testing.T) {
	f := newFixture(t)
	client := f.admit(t)
	answer, err := rawCall(t, f.clientDir, wireRequest{
		Version: protocolVersion + 1, Op: uint64(opSign), Credential: client.credential,
	})
	require.NoError(t, err)
	require.Equal(t, signingauthority.ErrUnsupportedVersion.Error(), answer.Refusal,
		"nothing is coerced to fit a version this authority does not implement")
}

func TestAnAbsentAuthorityIsUnavailableAndNothingElse(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	client := f.admit(t)
	_, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)

	t.Run("nothing listening", func(t *testing.T) {
		credential, err := NewCredential()
		require.NoError(t, err)
		gone, err := NewClient(ClientConfig{
			Dial:       UnixDialer(filepath.Join(socketDir(t), "absent.sock")),
			Credential: credential, Timeout: 2 * time.Second,
		})
		require.NoError(t, err)
		_, err = gone.Reserve(ctx, f.request())
		require.ErrorIs(t, err, signingauthority.ErrUnavailable)
		require.NotErrorIs(t, err, signingauthority.ErrFenced, "an absent authority has refused nothing")
	})

	t.Run("the authority stops answering mid-life", func(t *testing.T) {
		f.server.Close()
		require.ErrorIs(t, client.Sign(ctx), signingauthority.ErrUnavailable)
	})
}

func TestADroppedConnectionIsRetriedOnce(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	client := f.admit(t)
	_, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)

	// The authority closed the idle connection, the way a server reclaiming idle connections does.
	client.mu.Lock()
	require.NotNil(t, client.conn)
	require.NoError(t, client.conn.Close())
	client.mu.Unlock()

	require.NoError(t, client.Sign(ctx),
		"a connection that went away between two operations is reconnected, not reported as unavailability")
}

func TestTheClientOffersTheFourOperationsAndNothingElse(t *testing.T) {
	// The shard node's end of the boundary: no session replacement, no key, no status.
	var methods []string
	for i := 0; i < reflect.TypeOf(&Client{}).NumMethod(); i++ {
		methods = append(methods, reflect.TypeOf(&Client{}).Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Close", "Release", "Reserve", "RetainResponse", "Sign"}, methods)

	var operatorMethods []string
	for i := 0; i < reflect.TypeOf(&OperatorClient{}).NumMethod(); i++ {
		operatorMethods = append(operatorMethods, reflect.TypeOf(&OperatorClient{}).Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Close", "Enrollment", "ReplaceSession", "Status"}, operatorMethods,
		"and the control plane does not sign")
}

// rebindBounded serves the same authority through a second server whose bounds a test can reach: one
// connection at a time, and a connection that says nothing closed quickly.
func (f *fixture) rebindBounded(t *testing.T, maxConnections int, idle time.Duration) (Dialer, *OperatorClient) {
	t.Helper()
	operatorCredential, err := NewCredential()
	require.NoError(t, err)
	server, err := NewServer(f.authority, Config{
		OperatorCredential: operatorCredential, MaxConnections: maxConnections, IdleTimeout: idle,
	})
	require.NoError(t, err)
	t.Cleanup(server.Close)

	dir := socketDir(t)
	clientListener, err := ListenUnix(filepath.Join(dir, "client.sock"))
	require.NoError(t, err)
	operatorListener, err := ListenUnix(filepath.Join(dir, "operator.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientListener.Close(); _ = operatorListener.Close() })
	go func() { _ = server.Serve(clientListener, ClientEndpoint) }()
	go func() { _ = server.Serve(operatorListener, OperatorEndpoint) }()

	operator, err := NewOperatorClient(ClientConfig{
		Dial: UnixDialer(filepath.Join(dir, "operator.sock")), Credential: operatorCredential, Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = operator.Close() })
	return UnixDialer(filepath.Join(dir, "client.sock")), operator
}

func TestConnectionsAreBoundedAndIdleOnesAreClosed(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	dial, operator := f.rebindBounded(t, 1, 300*time.Millisecond)
	credential, err := operator.ReplaceSession(ctx)
	require.NoError(t, err)

	t.Run("a second connection is refused rather than queued", func(t *testing.T) {
		held, err := dial(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = held.Close() })
		require.NoError(t, held.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, writeFrame(held, wireRequest{Version: protocolVersion, Op: uint64(opSign), Credential: credential}))
		var answer wireResponse
		require.NoError(t, readFrame(held, &answer))

		second, err := dial(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = second.Close() })
		require.NoError(t, second.SetDeadline(time.Now().Add(5*time.Second)))
		err = writeFrame(second, wireRequest{Version: protocolVersion, Op: uint64(opSign), Credential: credential})
		if err == nil {
			err = readFrame(second, &answer)
		}
		require.Error(t, err, "over the bound, a connection is closed rather than served")
	})

	t.Run("a connection that says nothing is closed", func(t *testing.T) {
		silent, err := dial(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = silent.Close() })
		// The client's own deadline is far away, so what ends this read has to be the server.
		require.NoError(t, silent.SetDeadline(time.Now().Add(30*time.Second)))
		started := time.Now()
		var answer wireResponse
		require.Error(t, readFrame(silent, &answer))
		require.Less(t, time.Since(started), 5*time.Second,
			"the idle timeout is the server's, so a client cannot hold a slot by saying nothing")
	})
}

func TestMessagesTheClientsWouldNeverSendAreRefused(t *testing.T) {
	f := newFixture(t)
	client := f.admit(t)

	t.Run("a release naming a digest of the wrong length", func(t *testing.T) {
		payload, err := types.Cbor.Marshal(releasePayload{Round: 6, Digest: []byte{1, 2, 3, 4}})
		require.NoError(t, err)
		answer, err := rawCall(t, f.clientDir, wireRequest{
			Version: protocolVersion, Op: uint64(opRelease), Credential: client.credential, Payload: payload,
		})
		require.NoError(t, err)
		require.Equal(t, errMalformed.Error(), answer.Refusal,
			"a digest that cannot name a reservation is a malformed message, not a conflict about bytes")
	})

	t.Run("an empty credential", func(t *testing.T) {
		answer, err := rawCall(t, f.clientDir, wireRequest{Version: protocolVersion, Op: uint64(opSign)})
		require.NoError(t, err)
		require.Equal(t, signingauthority.ErrFenced.Error(), answer.Refusal,
			"presenting nothing is not a way to be admitted")
	})

	t.Run("an operation this protocol does not define", func(t *testing.T) {
		answer, err := rawCall(t, f.clientDir, wireRequest{
			Version: protocolVersion, Op: 4242, Credential: client.credential,
		})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal)
	})

	t.Run("a reserve payload that is not a request", func(t *testing.T) {
		answer, err := rawCall(t, f.clientDir, wireRequest{
			Version: protocolVersion, Op: uint64(opReserve), Credential: client.credential,
			Payload: []byte("not CBOR this authority will read"),
		})
		require.NoError(t, err)
		require.Equal(t, errMalformed.Error(), answer.Refusal)
	})
}

// rawCall sends one frame exactly as given, bypassing the clients, so a test can present a message
// the clients would never construct.
func rawCall(t *testing.T, dial Dialer, req wireRequest) (wireResponse, error) {
	t.Helper()
	conn, err := dial(context.Background())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	if err := writeFrame(conn, req); err != nil {
		return wireResponse{}, err
	}
	var response wireResponse
	if err := readFrame(conn, &response); err != nil {
		return wireResponse{}, err
	}
	return response, nil
}
