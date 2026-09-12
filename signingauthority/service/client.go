package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Dialer opens one connection to an endpoint. A deployment passes a Unix socket dialer; a test may
// pass anything that produces a connected net.Conn.
type Dialer func(ctx context.Context) (net.Conn, error)

// UnixDialer dials a Unix domain socket.
func UnixDialer(path string) Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
}

// ClientConfig is what a shard node is provisioned with to reach its authority.
type ClientConfig struct {
	// Dial opens the client endpoint.
	Dial Dialer
	// Credential is the client credential the operator issued when it replaced the session. The
	// shard node holds this and nothing else: no key, no session, no operator credential.
	Credential []byte
	// Timeout bounds one operation when the caller's context has no earlier deadline.
	Timeout time.Duration
}

/*
Client is a shard node's end of the boundary.

It implements the four client operations of shardnode.SigningAuthorityClient and nothing else.
Anything that is not an answer from the authority is signingauthority.ErrUnavailable: no process
listening, a connection that died, a deadline. That distinction matters at the round, which abstains
either way but records what happened, and it is the reason this type never invents an outcome when
it does not have one.

One connection is kept and reused. If a call fails on a cached connection before any answer arrives,
it is retried once on a fresh one: an authority that closed an idle connection, or was restarted,
must not read as unavailable to a node that has simply not spoken for a while. The retry is safe
because every operation here is idempotent by contract — the same reservation, the same signature
over it and the same retained response replay rather than repeat — and it happens at most once, so a
genuinely unreachable authority is still reported promptly.
*/
type Client struct {
	dial       Dialer
	credential []byte
	timeout    time.Duration

	mu   sync.Mutex
	conn net.Conn
}

// NewClient provisions a client. It does not connect: an authority that is not up yet is a liveness
// question, not a configuration error.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Dial == nil {
		return nil, errors.New("service: no dialer for the authority")
	}
	if len(cfg.Credential) < CredentialBytes {
		return nil, fmt.Errorf("service: the client credential must be at least %d bytes", CredentialBytes)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		dial:       cfg.Dial,
		credential: append([]byte(nil), cfg.Credential...),
		timeout:    timeout,
	}, nil
}

// Close drops the connection. The session and the key are not the client's to end.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropLocked()
}

func (c *Client) Reserve(ctx context.Context, req signingauthority.Request) (*signingauthority.Authorization, error) {
	payload, err := encodeRequest(req)
	if err != nil {
		return nil, err
	}
	answer, err := c.call(ctx, opReserve, payload)
	if err != nil {
		return nil, err
	}
	var wire authorizationPayload
	if err := types.Cbor.Unmarshal(answer, &wire); err != nil {
		return nil, fmt.Errorf("decoding the authorization: %w", err)
	}
	if len(wire.UnsignedDigest) != 32 {
		return nil, fmt.Errorf("the authority named a %d-byte digest", len(wire.UnsignedDigest))
	}
	authorization := &signingauthority.Authorization{
		AssignedRound: wire.AssignedRound,
		AssignedEpoch: wire.AssignedEpoch,
		ID:            wire.ID,
		Unsigned:      wire.Unsigned,
	}
	copy(authorization.UnsignedDigest[:], wire.UnsignedDigest)
	return authorization, nil
}

func (c *Client) Sign(ctx context.Context) error {
	_, err := c.call(ctx, opSign, nil)
	return err
}

func (c *Client) RetainResponse(ctx context.Context) error {
	_, err := c.call(ctx, opRetainResponse, nil)
	return err
}

func (c *Client) Release(ctx context.Context, round uint64, digest [32]byte) ([]byte, error) {
	payload, err := types.Cbor.Marshal(releasePayload{Round: round, Digest: digest[:]})
	if err != nil {
		return nil, fmt.Errorf("encoding the release: %w", err)
	}
	return c.call(ctx, opRelease, payload)
}

// call runs one operation, retrying once on a cached connection that turned out to be dead.
func (c *Client) call(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cached := c.conn != nil
	answer, err := c.attemptLocked(ctx, operation, payload)
	if err == nil {
		return answer, nil
	}
	if !errors.Is(err, signingauthority.ErrUnavailable) || !cached {
		return nil, err
	}
	_ = c.dropLocked()
	return c.attemptLocked(ctx, operation, payload)
}

func (c *Client) attemptLocked(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	conn, err := c.connectLocked(ctx)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	_ = conn.SetDeadline(deadline)

	request := wireRequest{Version: protocolVersion, Op: uint64(operation), Credential: c.credential, Payload: payload}
	if err := writeFrame(conn, request); err != nil {
		_ = c.dropLocked()
		return nil, fmt.Errorf("%w: sending %s: %v", signingauthority.ErrUnavailable, operation, err)
	}
	var response wireResponse
	if err := readFrame(conn, &response); err != nil {
		_ = c.dropLocked()
		return nil, fmt.Errorf("%w: reading the answer to %s: %v", signingauthority.ErrUnavailable, operation, err)
	}
	if response.Version != protocolVersion {
		_ = c.dropLocked()
		return nil, fmt.Errorf("%w: the authority answered version %d", signingauthority.ErrUnsupportedVersion, response.Version)
	}
	if response.Refusal != "" {
		return nil, refusalError(response.Refusal)
	}
	return response.Payload, nil
}

func (c *Client) connectLocked(ctx context.Context) (net.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", signingauthority.ErrUnavailable, err)
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func encodeRequest(req signingauthority.Request) ([]byte, error) {
	if req.UC == nil || req.Technical == nil || req.Proposed == nil {
		return nil, fmt.Errorf("%w: a request carries a certificate, a technical record and a proposal", errMalformed)
	}
	uc, err := types.Cbor.Marshal(req.UC)
	if err != nil {
		return nil, fmt.Errorf("encoding the certificate: %w", err)
	}
	technical, err := types.Cbor.Marshal(req.Technical)
	if err != nil {
		return nil, fmt.Errorf("encoding the technical record: %w", err)
	}
	proposed, err := types.Cbor.Marshal(req.Proposed)
	if err != nil {
		return nil, fmt.Errorf("encoding the proposal: %w", err)
	}
	return types.Cbor.Marshal(reservePayload{UC: uc, Technical: technical, Proposed: proposed})
}
