package service

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	// Timeout bounds one whole operation, the reconnect below included. A caller's own deadline
	// applies when it is earlier. Zero means DefaultTimeout.
	Timeout time.Duration
}

/*
Client is a shard node's end of the boundary.

It implements the four client operations of shardnode.SigningAuthorityClient and nothing else.
Anything that is not an answer from the authority is signingauthority.ErrUnavailable: no process
listening, a connection that died, a deadline, a caller that cancelled. That distinction matters at
the round, which abstains either way but records what happened, and it is the reason this type never
invents an outcome when it does not have one.

One connection is kept and reused. If a call fails on a cached connection before any answer arrives,
it is retried once on a fresh one: an authority that closed an idle connection, or was restarted,
must not read as unavailable to a node that has simply not spoken for a while. The retry is safe
because every operation here is idempotent by contract (the same reservation, the same signature over
it and the same retained response replay rather than repeat), it happens at most once, and it runs
under the same deadline as the attempt it follows.
*/
type Client struct {
	ex *exchange
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
	return &Client{ex: newExchange(cfg)}, nil
}

// Close drops the connection. The session and the key are not the client's to end.
func (c *Client) Close() error {
	return c.ex.close()
}

func (c *Client) Reserve(ctx context.Context, req signingauthority.Request) (*signingauthority.Authorization, error) {
	payload, err := encodeRequest(req)
	if err != nil {
		return nil, err
	}
	answer, err := c.ex.call(ctx, opReserve, payload)
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
	_, err := c.ex.call(ctx, opSign, nil)
	return err
}

func (c *Client) RetainResponse(ctx context.Context) error {
	_, err := c.ex.call(ctx, opRetainResponse, nil)
	return err
}

func (c *Client) Release(ctx context.Context, round uint64, digest [32]byte) ([]byte, error) {
	payload, err := types.Cbor.Marshal(releasePayload{Round: round, Digest: digest[:]})
	if err != nil {
		return nil, fmt.Errorf("encoding the release: %w", err)
	}
	return c.ex.call(ctx, opRelease, payload)
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
