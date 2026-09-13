package service

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

	operatorDial       Dialer
	operatorCredential []byte

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
		operatorDial:       UnixDialer(filepath.Join(dir, "operator.sock")),
		operatorCredential: operatorCredential,
		clientDir:          UnixDialer(filepath.Join(dir, "client.sock")),
		rootSigner:         rootSigner, uc: uc, tr: tr,
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
			Version: protocolVersion, Op: uint64(opReplaceSession), Credential: client.ex.credential,
		})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal)
	})

	t.Run("a client credential does not open the operator endpoint", func(t *testing.T) {
		operator, err := NewOperatorClient(ClientConfig{
			Dial: f.operator.ex.dial, Credential: client.ex.credential, Timeout: 5 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = operator.Close() })
		_, err = operator.ReplaceSession(ctx)
		require.ErrorIs(t, err, errOperatorUnauthenticated)
	})

	t.Run("an operator credential does not sign", func(t *testing.T) {
		answer, err := rawCall(t, f.operator.ex.dial, wireRequest{
			Version: protocolVersion, Op: uint64(opReserve), Credential: f.operator.ex.credential,
		})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal,
			"the operator endpoint refuses signing work before any credential decides anything")
	})

	t.Run("an operator credential presented to the client endpoint is fenced", func(t *testing.T) {
		strayClient, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: f.operator.ex.credential})
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
		Version: protocolVersion + 1, Op: uint64(opSign), Credential: client.ex.credential,
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
	withHeldConnection(t, client.ex, func(conn net.Conn) net.Conn {
		require.NotNil(t, conn)
		require.NoError(t, conn.Close())
		return conn
	})

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
	require.ElementsMatch(t, []string{"Close", "CompleteEnrollment", "Enrollment", "ReplaceSession", "Status"}, operatorMethods,
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
			Version: protocolVersion, Op: uint64(opRelease), Credential: client.ex.credential, Payload: payload,
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
			Version: protocolVersion, Op: 4242, Credential: client.ex.credential,
		})
		require.NoError(t, err)
		require.Equal(t, errWrongEndpoint.Error(), answer.Refusal)
	})

	t.Run("a reserve payload that is not a request", func(t *testing.T) {
		answer, err := rawCall(t, f.clientDir, wireRequest{
			Version: protocolVersion, Op: uint64(opReserve), Credential: client.ex.credential,
			Payload: []byte("not CBOR this authority will read"),
		})
		require.NoError(t, err)
		require.Equal(t, errMalformed.Error(), answer.Refusal)
	})
}

// withHeldConnection takes the exchange's operation slot, the way a call does, so a test can look at
// the connection it keeps, or put one there, without racing an operation.
func withHeldConnection(t *testing.T, ex *exchange, f func(net.Conn) net.Conn) {
	t.Helper()
	ex.sem <- struct{}{}
	defer func() { <-ex.sem }()
	ex.conn = f(ex.conn)
}

// stalledAuthority accepts connections and answers nothing, which is what a wedged authority host
// looks like from the shard side: the socket is there, the process is not answering.
func stalledAuthority(t *testing.T) Dialer {
	t.Helper()
	path := filepath.Join(socketDir(t), "stalled.sock")
	listener, err := ListenUnix(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return UnixDialer(path)
}

func TestASocketPathIsClaimedNotShared(t *testing.T) {
	path := filepath.Join(socketDir(t), "client.sock")
	first, err := ListenUnix(path)
	require.NoError(t, err)

	second, err := ListenUnix(path)
	require.ErrorIs(t, err, ErrPathHeld,
		"a path being served is not free, and taking it over would put a second authority where a shard node dials one")
	require.Nil(t, second)

	// The claim ends with the listener, so an authority that was stopped leaves the path usable.
	require.NoError(t, first.Close())
	third, err := ListenUnix(path)
	require.NoError(t, err)
	require.NoError(t, third.Close())
}

func TestConcurrentSessionReplacementsLeaveExactlyOneUsableCredential(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	const operators = 4
	operatorClients := make([]*OperatorClient, operators)
	for i := range operatorClients {
		operator, err := NewOperatorClient(ClientConfig{
			Dial: f.operatorDial, Credential: f.operatorCredential, Timeout: 10 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = operator.Close() })
		// Connected before the section is held: accepting a connection also takes the server's lock,
		// and a replacement still waiting to be accepted would never reach the window being tested.
		_, err = operator.Status(ctx)
		require.NoError(t, err)
		operatorClients[i] = operator
	}

	// A credential is lost when the authority advances its generation for one replacement while
	// another replacement is installing its credential. Left to the scheduler that window is a few
	// instructions wide and only sometimes split, so the test holds the server's section open instead:
	// while it is held, no replacement may have reached the authority. The check is non-fatal so the
	// section is always released.
	before := f.authority.Status().Generation
	credentials := make([][]byte, operators)
	errs := make([]error, operators)
	var wg sync.WaitGroup
	f.server.mu.Lock()
	for i, operator := range operatorClients {
		wg.Add(1)
		go func(i int, operator *OperatorClient) {
			defer wg.Done()
			credentials[i], errs[i] = operator.ReplaceSession(ctx)
		}(i, operator)
	}
	advancedOutside := assert.Never(t, func() bool { return f.authority.Status().Generation != before },
		300*time.Millisecond, 10*time.Millisecond,
		"a replacement advances the authority only inside the section that installs its credential")
	f.server.mu.Unlock()
	wg.Wait()
	require.True(t, advancedOutside)
	require.Equal(t, before+operators, f.authority.Status().Generation)

	usable := 0
	for i, credential := range credentials {
		require.NoError(t, errs[i])
		client, err := NewClient(ClientConfig{Dial: f.clientDir, Credential: credential, Timeout: 10 * time.Second})
		require.NoError(t, err)
		_, err = client.Reserve(ctx, f.request())
		if err == nil {
			usable++
		} else {
			require.ErrorIs(t, err, signingauthority.ErrFenced,
				"a credential that lost the race is fenced, which is what a replaced client is")
		}
		require.NoError(t, client.Close())
	}
	require.Equal(t, 1, usable,
		"the credential the server admits names the session the authority is holding: concurrent replacement fences all but one, not all of them")
}

func TestACancelledCallDoesNotWaitForTheAuthority(t *testing.T) {
	f := newFixture(t)
	credential, err := f.operator.ReplaceSession(context.Background())
	require.NoError(t, err)
	// A timeout far longer than this test would tolerate: what ends the call has to be the context.
	client, err := NewClient(ClientConfig{Dial: stalledAuthority(t), Credential: credential, Timeout: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	_, err = client.Reserve(ctx, f.request())
	require.ErrorIs(t, err, signingauthority.ErrUnavailable,
		"an authority that never answered gave no decision, so this is unavailability")
	require.ErrorIs(t, err, context.Canceled, "and the reason is the caller's, not an invented one")
	require.Less(t, time.Since(started), 30*time.Second,
		"a cancelled caller is not held until the configured timeout: a connection blocked in a read is woken")

	// A call made with a context that is already over does not reach for the authority at all.
	over, stop := context.WithCancel(context.Background())
	stop()
	require.ErrorIs(t, client.Sign(over), signingauthority.ErrUnavailable)
}

func TestTheConfiguredTimeoutBoundsTheWholeOperationIncludingTheRetry(t *testing.T) {
	f := newFixture(t)
	credential, err := f.operator.ReplaceSession(context.Background())
	require.NoError(t, err)
	const timeout = 400 * time.Millisecond
	dial := stalledAuthority(t)
	client, err := NewClient(ClientConfig{Dial: dial, Credential: credential, Timeout: timeout})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// A cached connection that stalls: the first attempt runs out of time, and the retry is the one
	// that must not be given a second timeout of its own.
	stalled, err := dial(context.Background())
	require.NoError(t, err)
	withHeldConnection(t, client.ex, func(net.Conn) net.Conn { return stalled })

	started := time.Now()
	err = client.Sign(context.Background())
	elapsed := time.Since(started)
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.GreaterOrEqual(t, elapsed, timeout, "the timeout is what bounds it")
	require.Less(t, elapsed, 2*timeout,
		"and it bounds the operation, not each attempt: a round waiting on this was promised one timeout")
}

func TestTheClientBudgetIncludesWaitingForTheSlot(t *testing.T) {
	ex := newExchange(ClientConfig{
		Credential: make([]byte, CredentialBytes), Timeout: 50 * time.Millisecond,
		Dial: func(context.Context) (net.Conn, error) { return nil, errors.New("never reached") },
	})
	// Another operation holds the slot for longer than this call's whole budget.
	ex.sem <- struct{}{}
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		_, err := ex.call(context.Background(), opSign, nil)
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
	}
	elapsed := time.Since(started)
	<-ex.sem
	if err == nil {
		// Unwind the queued call before failing, so the goroutine does not outlive the test.
		err = <-done
		t.Fatalf("a call queued behind another waited %s past a 50ms budget, and returned %v once released", elapsed, err)
	}
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"a round queued behind another operation is waiting on its authority, and its timeout counts that wait")
}

// blockedTrust is a trust source whose lookup waits until its context ends or the test releases it:
// a root chain the authority cannot currently reach.
type blockedTrust struct {
	entered chan struct{}
	release chan struct{}
	free    func()
}

func (b blockedTrust) GetByEpoch(ctx context.Context, _ uint64) (*types.RootTrustBaseV1, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
		return nil, errors.New("released by the test")
	}
}

// blockedServer serves an authority whose trust lookups block, on one end of a pipe, and returns the
// other end with a client credential for it.
func (f *fixture) blockedServer(t *testing.T, cfg Config) (*Server, blockedTrust, net.Conn, []byte) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	trust := blockedTrust{
		entered: make(chan struct{}, 1), release: release,
		free: func() { once.Do(func() { close(release) }) },
	}
	enrollment := f.authority.Enrollment()
	enrollment.SigningKeyFingerprint = nil
	authority, err := signingauthority.New(enrollment, trust)
	require.NoError(t, err)
	t.Cleanup(authority.Close)

	cfg.OperatorCredential = f.operatorCredential
	server, err := NewServer(authority, cfg)
	require.NoError(t, err)
	t.Cleanup(server.Close)
	// Registered after Close so it runs before it: a test that fails with a lookup still blocked must
	// not leave its own cleanup waiting on that lookup.
	t.Cleanup(trust.free)
	credential, err := server.replaceSession()
	require.NoError(t, err)

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
	require.True(t, server.track())
	go func() {
		defer server.wg.Done()
		server.serveConn(remote, ClientEndpoint)
	}()
	require.NoError(t, local.SetDeadline(time.Now().Add(10*time.Second)))
	return server, trust, local, credential
}

func (f *fixture) sendReserve(t *testing.T, conn net.Conn, credential []byte) {
	t.Helper()
	payload, err := encodeRequest(f.request())
	require.NoError(t, err)
	require.NoError(t, writeFrame(conn, wireRequest{
		Version: protocolVersion, Op: uint64(opReserve), Credential: credential, Payload: payload,
	}))
}

func TestClosingTheServerCancelsWorkWaitingInsideTheAuthority(t *testing.T) {
	f := newFixture(t)
	// An operation deadline far beyond the test, so what ends the lookup has to be Close.
	server, trust, conn, credential := f.blockedServer(t, Config{OperationTimeout: time.Hour})
	f.sendReserve(t, conn, credential)
	select {
	case <-trust.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the reserve did not reach the trust lookup")
	}

	closed := make(chan struct{})
	go func() {
		server.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited on an operation blocked inside the authority instead of cancelling it")
	}
	require.False(t, server.authority.Status().HasReservation,
		"the cancelled lookup authenticated nothing, so nothing was admitted")
}

func TestAnOperationWaitingInsideTheAuthorityHasADeadline(t *testing.T) {
	f := newFixture(t)
	const timeout = 200 * time.Millisecond
	server, trust, conn, credential := f.blockedServer(t, Config{OperationTimeout: timeout})

	started := time.Now()
	f.sendReserve(t, conn, credential)
	var answer wireResponse
	require.NoError(t, readFrame(conn, &answer), "the server answers once its own deadline passes")
	elapsed := time.Since(started)
	<-trust.entered
	require.Equal(t, signingauthority.ErrUnauthenticated.Error(), answer.Refusal,
		"an input the authority could not authenticate in time was not authenticated")
	require.GreaterOrEqual(t, elapsed, timeout)
	require.Less(t, elapsed, 5*time.Second)
	require.False(t, server.authority.Status().HasReservation)

	// The deadline belongs to that operation, not to the connection or the server: both keep serving.
	require.NoError(t, writeFrame(conn, wireRequest{Version: protocolVersion, Op: uint64(opSign), Credential: credential}))
	require.NoError(t, readFrame(conn, &answer))
	require.Equal(t, signingauthority.ErrNoReservation.Error(), answer.Refusal)
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
