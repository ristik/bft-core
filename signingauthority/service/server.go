package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Endpoint says which side of the boundary a listener serves. There is no endpoint that serves
// both, and no operation that both endpoints serve.
type Endpoint int

const (
	// ClientEndpoint serves the shard node: reserve, sign, retain, release.
	ClientEndpoint Endpoint = iota
	// OperatorEndpoint serves the operator: session replacement, status, enrollment.
	OperatorEndpoint
)

func (e Endpoint) String() string {
	if e == OperatorEndpoint {
		return "operator"
	}
	return "client"
}

// Config is what an operator provides when starting an authority process.
type Config struct {
	// OperatorCredential admits the operator endpoint. It is provisioned here, by whoever starts
	// the process, and the server neither generates nor stores it anywhere else. At least
	// CredentialBytes of entropy.
	OperatorCredential []byte

	// MaxConnections bounds concurrent connections per endpoint. Bounding the queue is the
	// transport's job, not the authority's, which serialises behind one mutex.
	MaxConnections int

	// IdleTimeout is how long a connection has to produce its next complete message. It is an
	// absolute deadline on the read rather than a gap between bytes, so it bounds a connection that
	// dribbles a message as well as one that says nothing. WriteTimeout bounds one answer.
	IdleTimeout  time.Duration
	WriteTimeout time.Duration

	// OperationTimeout bounds the work one request does inside the authority, such as the trust
	// lookup behind a reserve. It is separate from the socket deadlines because those bound reading
	// and writing, and cannot reach work that is waiting on something other than the connection.
	OperationTimeout time.Duration

	Log *slog.Logger
}

// DefaultConfig fills in the bounds. The credential is left empty on purpose: there is no default
// for a secret.
func DefaultConfig() Config {
	return Config{
		MaxConnections:   8,
		IdleTimeout:      5 * time.Minute,
		WriteTimeout:     30 * time.Second,
		OperationTimeout: 30 * time.Second,
	}
}

/*
Server answers for one authority, on two endpoints.

It holds the session. A client is admitted by a credential the server issued when the operator
replaced the session, and the server maps that credential to the session it is holding; the client
never sees a signingauthority.Session and cannot name one. Replacing the session invalidates the old
credential in the same step that fences the old generation inside the authority, so the two cannot
drift apart.
*/
type Server struct {
	authority *signingauthority.Authority
	cfg       Config
	log       *slog.Logger

	mu         sync.Mutex
	session    signingauthority.Session
	hasSession bool
	credential []byte

	closeOnce sync.Once
	closed    chan struct{}
	// lifetime is the parent of every dispatched operation, and Close cancels it. Closing a
	// connection wakes a handler blocked on the socket, but not one waiting inside the authority, so
	// shutdown has to reach that work through its context.
	lifetime context.Context
	end      context.CancelFunc
	// draining is set under mu before the wait below begins. A connection accepted after that point
	// is not tracked and not served: adding to a WaitGroup that is already being waited on is a race
	// whether or not it is ever observed, and "the listener is about to close anyway" is not a
	// reason to leave one in.
	draining bool
	wg       sync.WaitGroup
}

// NewServer wraps an authority. It does not listen: the caller provides listeners, so that a
// deployment chooses where each endpoint lives and a test can use a socket pair.
func NewServer(authority *signingauthority.Authority, cfg Config) (*Server, error) {
	if authority == nil {
		return nil, errors.New("service: no authority")
	}
	if len(cfg.OperatorCredential) < CredentialBytes {
		return nil, fmt.Errorf("service: the operator credential must be at least %d bytes", CredentialBytes)
	}
	defaults := DefaultConfig()
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaults.MaxConnections
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaults.WriteTimeout
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = defaults.OperationTimeout
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cfg.OperatorCredential = append([]byte(nil), cfg.OperatorCredential...)
	lifetime, end := context.WithCancel(context.Background())
	return &Server{
		authority: authority, cfg: cfg, log: log, closed: make(chan struct{}),
		lifetime: lifetime, end: end,
	}, nil
}

// NewCredential draws a bearer credential from the system random source.
func NewCredential() ([]byte, error) {
	credential := make([]byte, CredentialBytes)
	if _, err := rand.Read(credential); err != nil {
		return nil, fmt.Errorf("drawing a credential: %w", err)
	}
	return credential, nil
}

/*
Serve accepts connections on one endpoint until the listener is closed.

Each connection is served sequentially: one request, one response, then the next. There is no
pipelining and no correlation identifier, because a client that could have two operations in flight
on one connection could not tell which answer belongs to which, and the operations here are a
sequence over one reservation rather than independent calls.
*/
func (s *Server) Serve(l net.Listener, endpoint Endpoint) error {
	slots := make(chan struct{}, s.cfg.MaxConnections)
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			return fmt.Errorf("accepting on the %s endpoint: %w", endpoint, err)
		}
		select {
		case slots <- struct{}{}:
		default:
			// Over the bound: refused now rather than queued indefinitely, so an authority cannot
			// be made unavailable to its shard node by connections nobody is using.
			s.log.Warn("refusing a connection over the configured bound",
				slog.String("endpoint", endpoint.String()), slog.Int("maxConnections", s.cfg.MaxConnections))
			_ = conn.Close()
			continue
		}
		if !s.track() {
			_ = conn.Close()
			<-slots
			return nil
		}
		go func() {
			defer s.wg.Done()
			defer func() { <-slots }()
			s.serveConn(conn, endpoint)
		}()
	}
}

/*
Close stops serving. It does NOT close the authority: the key's lifetime is the authority's, and
deciding it ends belongs to whoever created it.

Operations still running are cancelled rather than waited for, so a trust lookup that never returns
cannot hold shutdown open. Cancelling one stops its waiting and nothing else: a reservation the
authority has already admitted stays admitted (§6).
*/
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.draining = true
		s.mu.Unlock()
		close(s.closed)
		s.end()
	})
	s.wg.Wait()
}

// track registers one connection, or reports that this server is draining and will serve no more.
func (s *Server) track() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return false
	}
	s.wg.Add(1)
	return true
}

func (s *Server) serveConn(conn net.Conn, endpoint Endpoint) {
	defer func() { _ = conn.Close() }()
	// A connection blocked in a read does not notice the server closing, so closing it is how this
	// one is woken. The watcher ends with the connection rather than with the server, or a process
	// serving many short connections would accumulate one goroutine each.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-s.closed:
			_ = conn.Close()
		case <-done:
		}
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		var req wireRequest
		if err := readFrame(conn, &req); err != nil {
			if errors.Is(err, errFrameTooLarge) || errors.Is(err, errMalformed) {
				// The connection cannot be trusted to be at a frame boundary any more, so the
				// refusal is the last thing said on it.
				s.log.Warn("closing a connection after a frame this endpoint will not read",
					slog.String("endpoint", endpoint.String()), slog.String("err", err.Error()))
				s.respond(conn, refusalName(err), nil)
			}
			return
		}
		payload, err := s.operate(endpoint, req)
		if err != nil {
			s.log.Debug("refusing an operation",
				slog.String("endpoint", endpoint.String()), slog.String("op", op(req.Op).String()),
				slog.String("refusal", refusalName(err)), slog.String("err", err.Error()))
			if !s.respond(conn, refusalName(err), nil) {
				return
			}
			continue
		}
		if !s.respond(conn, "", payload) {
			return
		}
	}
}

/*
operate runs one dispatched request under the server's own context: bounded by OperationTimeout and
cancelled by Close.

It is deliberately not tied to the connection. A client that goes away mid-request has not withdrawn
anything, and the authority decides for itself what an admitted reservation means; what the server
bounds is how long it will work, and whether it is still running at all.
*/
func (s *Server) operate(endpoint Endpoint, req wireRequest) ([]byte, error) {
	ctx, cancel := context.WithTimeout(s.lifetime, s.cfg.OperationTimeout)
	defer cancel()
	return s.dispatch(ctx, endpoint, req)
}

func (s *Server) respond(conn net.Conn, refusal string, payload []byte) bool {
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	if err := writeFrame(conn, wireResponse{Version: protocolVersion, Refusal: refusal, Payload: payload}); err != nil {
		s.log.Debug("a response could not be written", slog.String("err", err.Error()))
		return false
	}
	return true
}

// dispatch decides, in this order: the protocol version, whether this endpoint serves the operation
// at all, and only then the credential. Answering "wrong endpoint" before looking at a credential is
// deliberate: it tells a misconfigured operator what is wrong without either credential being
// involved in the answer.
func (s *Server) dispatch(ctx context.Context, endpoint Endpoint, req wireRequest) ([]byte, error) {
	if req.Version != protocolVersion {
		return nil, fmt.Errorf("%w: this authority speaks version %d", signingauthority.ErrUnsupportedVersion, protocolVersion)
	}
	operation := op(req.Op)
	switch endpoint {
	case OperatorEndpoint:
		if !operation.servedToOperator() {
			return nil, fmt.Errorf("%w: %s is not an operator operation", errWrongEndpoint, operation)
		}
		if subtle.ConstantTimeCompare(req.Credential, s.cfg.OperatorCredential) != 1 {
			return nil, errOperatorUnauthenticated
		}
		return s.operatorOp(ctx, operation, req.Payload)
	case ClientEndpoint:
		if !operation.servedToClient() {
			return nil, fmt.Errorf("%w: %s is not a client operation", errWrongEndpoint, operation)
		}
		session, err := s.sessionFor(req.Credential)
		if err != nil {
			return nil, err
		}
		return s.clientOp(ctx, session, operation, req.Payload)
	}
	return nil, fmt.Errorf("%w: unknown endpoint", errMalformed)
}

/*
sessionFor maps a presented credential to the session this server holds.

A credential that is not the current one is signing-session-fenced, which is what the authority
itself answers an old generation. That includes the case where no session has been issued yet: a
client holding a credential for a session that does not exist is in the same position as one holding
a credential for a session that has been replaced, and neither is admitted.
*/
func (s *Server) sessionFor(credential []byte) (signingauthority.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasSession {
		return signingauthority.Session{}, fmt.Errorf("%w: no session has been issued", signingauthority.ErrFenced)
	}
	if subtle.ConstantTimeCompare(credential, s.credential) != 1 {
		return signingauthority.Session{}, fmt.Errorf("%w: this credential is not the current one", signingauthority.ErrFenced)
	}
	return s.session, nil
}

func (s *Server) clientOp(ctx context.Context, session signingauthority.Session, operation op, payload []byte) ([]byte, error) {
	switch operation {
	case opReserve:
		var wire reservePayload
		if err := types.Cbor.Unmarshal(payload, &wire); err != nil {
			return nil, fmt.Errorf("%w: %v", errMalformed, err)
		}
		req, err := decodeRequest(wire)
		if err != nil {
			return nil, err
		}
		authorization, err := s.authority.Reserve(ctx, session, req)
		if err != nil {
			return nil, err
		}
		return types.Cbor.Marshal(authorizationPayload{
			AssignedRound:  authorization.AssignedRound,
			AssignedEpoch:  authorization.AssignedEpoch,
			ID:             authorization.ID,
			Unsigned:       authorization.Unsigned,
			UnsignedDigest: authorization.UnsignedDigest[:],
		})
	case opSign:
		return nil, s.authority.Sign(session)
	case opRetainResponse:
		return nil, s.authority.RetainResponse(session)
	case opRelease:
		var wire releasePayload
		if err := types.Cbor.Unmarshal(payload, &wire); err != nil {
			return nil, fmt.Errorf("%w: %v", errMalformed, err)
		}
		if len(wire.Digest) != 32 {
			return nil, fmt.Errorf("%w: a release names a 32-byte digest", errMalformed)
		}
		var digest [32]byte
		copy(digest[:], wire.Digest)
		return s.authority.Release(session, wire.Round, digest)
	case opRestoreStatus:
		status := s.authority.Status()
		return types.Cbor.Marshal(statusPayload{RootEpoch: status.RootEpoch, ShardEpoch: status.ShardEpoch,
			Generation: status.Generation, ReservedRound: status.ReservedRound,
			HasReservation: status.HasReservation, ResponseRetained: status.ResponseRetained,
			Faulted: status.Faulted, KeyLost: status.KeyLost})
	}
	return nil, fmt.Errorf("%w: %s", errWrongEndpoint, operation)
}

func (s *Server) operatorOp(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	switch operation {
	case opAdvanceEpoch:
		var wire advanceEpochPayload
		if err := types.Cbor.Unmarshal(payload, &wire); err != nil {
			return nil, fmt.Errorf("%w: successor context: %v", errMalformed, err)
		}
		var conf types.PartitionDescriptionRecord
		var trust types.RootTrustBaseV1
		if err := types.Cbor.Unmarshal(wire.Configuration, &conf); err != nil {
			return nil, fmt.Errorf("%w: successor configuration: %v", errMalformed, err)
		}
		if err := types.Cbor.Unmarshal(wire.TrustBase, &trust); err != nil {
			return nil, fmt.Errorf("%w: successor trust: %v", errMalformed, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.authority.AdvanceEpoch(ctx, &conf, &trust); err != nil {
			s.log.Warn("refusing epoch advance", slog.String("err", err.Error()))
			return nil, err
		}
		s.hasSession = false
		s.credential = nil
		return nil, nil
	case opSignHandoffPoP:
		var wire handoffPoPPayload
		if err := types.Cbor.Unmarshal(payload, &wire); err != nil {
			return nil, fmt.Errorf("%w: handoff possession proof request: %v", errMalformed, err)
		}
		if len(wire.Predecessor) != 32 {
			return nil, fmt.Errorf("%w: the context names 32-byte hashes", errMalformed)
		}
		var succ types.PartitionDescriptionRecord
		if err := types.Cbor.Unmarshal(wire.Successor, &succ); err != nil {
			return nil, fmt.Errorf("%w: successor binding: %v", errMalformed, err)
		}
		request := signingauthority.HandoffPoPRequest{Domain: wire.Domain, Successor: &succ, NodeID: wire.NodeID,
			Context: evmassign.PoPContext{Network: wire.Network, Attempt: wire.Attempt}}
		copy(request.Context.Predecessor[:], wire.Predecessor)
		pop, err := s.authority.SignHandoffPoP(request)
		if err != nil {
			s.log.Warn("refusing a handoff possession proof", slog.String("err", err.Error()))
			return nil, err
		}
		// The authority's only signature outside certification: audit every one, not only the refusals.
		s.log.Info("signed a handoff possession proof",
			slog.String("node", wire.NodeID), slog.Uint64("successorEpoch", succ.Epoch), slog.Uint64("attempt", wire.Attempt),
			slog.String("predecessor", fmt.Sprintf("%x", wire.Predecessor)))
		return types.Cbor.Marshal(pop)
	case opCompleteEnrollment:
		var conf types.PartitionDescriptionRecord
		if err := types.Cbor.Unmarshal(payload, &conf); err != nil {
			return nil, fmt.Errorf("%w: shard configuration: %v", errMalformed, err)
		}
		if err := s.authority.CompleteEnrollment(&conf); err != nil {
			// The operator's client receives only the refusal's name, so the reason is logged here,
			// where whoever runs this process can read which check the configuration failed.
			s.log.Warn("refusing to complete the enrollment", slog.String("err", err.Error()))
			return nil, err
		}
		s.log.Info("enrollment complete",
			slog.String("shardConfHash", fmt.Sprintf("%x", s.authority.Enrollment().ShardConfHash)))
		return nil, nil
	case opReplaceSession:
		return s.replaceSession()
	case opStatus, opRestoreStatus:
		status := s.authority.Status()
		return types.Cbor.Marshal(statusPayload{
			RootEpoch: status.RootEpoch, ShardEpoch: status.ShardEpoch,
			Generation: status.Generation, ReservedRound: status.ReservedRound,
			HasReservation: status.HasReservation, ResponseRetained: status.ResponseRetained,
			Faulted: status.Faulted, KeyLost: status.KeyLost,
		})
	case opEnrollment:
		enrollment, err := types.Cbor.Marshal(s.authority.Enrollment())
		if err != nil {
			return nil, fmt.Errorf("encoding the enrollment: %w", err)
		}
		// A missing key is reported as a refusal rather than as an enrollment without one: an
		// operator asking what this authority is must not receive a half-answer.
		key, err := s.authority.SigningPublicKey()
		if err != nil {
			return nil, err
		}
		return types.Cbor.Marshal(enrollmentPayload{Enrollment: enrollment, PublicKey: key})
	}
	return nil, fmt.Errorf("%w: %s", errWrongEndpoint, operation)
}

/*
replaceSession fences the current client and issues the credential for the new one.

The whole replacement is one critical section, and this is the reason: the authority decides the
order of two concurrent replacements, and the server must store them in that same order. Advancing
the generation outside the lock lets a replacement that won inside the authority lose the race to
install its credential, which leaves the server admitting a credential the authority has already
fenced. Both operators would then hold a credential that cannot be used, and an operator would read
that as an authority that has broken rather than as one it has to ask again.

Within the section the authority advances its generation first. If that fails there is no new
credential and the old one keeps working, because the old generation is still the current one inside
the authority: the two must not disagree about who is admitted. If it succeeds, the old credential
stops being accepted in the same step, and the new credential is returned exactly once. The server
keeps only what it needs to compare against, and cannot produce it again for anyone who missed it.
*/
func (s *Server) replaceSession() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, err := s.authority.ReplaceSession()
	if err != nil {
		return nil, err
	}
	credential, err := NewCredential()
	if err != nil {
		// The generation has already advanced, so the previous client is fenced whatever happens
		// here. Leaving the server with no admitted credential is the safe side of that: nothing is
		// admitted until the operator asks again and gets one.
		s.hasSession = false
		s.credential = nil
		return nil, err
	}
	s.session = session
	s.hasSession = true
	s.credential = append([]byte(nil), credential...)
	return credential, nil
}

func decodeRequest(wire reservePayload) (signingauthority.Request, error) {
	var (
		uc        types.UnicityCertificate
		technical certification.TechnicalRecord
		proposed  certification.BlockCertificationRequest
	)
	if err := types.Cbor.Unmarshal(wire.UC, &uc); err != nil {
		return signingauthority.Request{}, fmt.Errorf("%w: certificate: %v", errMalformed, err)
	}
	if err := types.Cbor.Unmarshal(wire.Technical, &technical); err != nil {
		return signingauthority.Request{}, fmt.Errorf("%w: technical record: %v", errMalformed, err)
	}
	if err := types.Cbor.Unmarshal(wire.Proposed, &proposed); err != nil {
		return signingauthority.Request{}, fmt.Errorf("%w: proposed request: %v", errMalformed, err)
	}
	return signingauthority.Request{UC: &uc, Technical: &technical, Proposed: &proposed}, nil
}

// ErrPathHeld is a socket path an authority process is already serving. It is reported rather than
// taken over: see ListenUnix.
var ErrPathHeld = errors.New("service: the socket path is held by a running authority")

// lockSuffix names the file whose lock is a claim on one socket path. It sits next to the socket
// rather than inside it, because the socket is removed and recreated and the claim must outlive that.
const lockSuffix = ".lock"

/*
ListenUnix creates a Unix domain socket for one endpoint, in a directory only its owner may enter.

The socket file itself is created with the process umask applied, so the directory is what carries
the access decision: 0700, owned by the user running the authority. Credentials admit operations;
the file mode is what keeps a stranger from reaching the endpoint to present one.

Claiming the path comes first, and it is an exclusive lock on a file beside it, held for as long as
the listener is open. Without it, a second authority started on the same path would remove the socket
and listen on it, and the shard node dialling that path would then be reaching a different authority
with a different key while the first one was still running and still holding its reservation. There
is nothing in the exchange that would notice: the operations are the same and the refusals are the
same. Two authorities for one enrolled node is the condition §3 exists to prevent, so this is refused
as ErrPathHeld rather than resolved in favour of whoever started last.

The lock is what tells a socket left by a process that is gone from one a process is still serving:
the kernel releases it when that process dies, and only then is removing the socket file correct.
*/
func ListenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating the socket directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restricting the socket directory: %w", err)
	}
	lock, err := os.OpenFile(path+lockSuffix, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the socket claim: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: %s (%v)", ErrPathHeld, path, err)
	}
	// Past the claim, an existing socket is one nobody is serving.
	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			_ = lock.Close()
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("removing a stale socket: %w", err)
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		_ = lock.Close()
		return nil, fmt.Errorf("restricting the socket: %w", err)
	}
	return &claimedListener{Listener: l, lock: lock}, nil
}

// claimedListener holds the claim on its path for as long as it is open. The lock file is left in
// place on close: what matters is the lock, and the next authority on this path locks the same file.
type claimedListener struct {
	net.Listener
	lock *os.File
}

func (l *claimedListener) Close() error {
	err := l.Listener.Close()
	if lockErr := l.lock.Close(); err == nil {
		err = lockErr
	}
	return err
}
