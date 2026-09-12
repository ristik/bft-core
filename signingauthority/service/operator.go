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

/*
OperatorClient is the control plane's end of the boundary.

It exists so that the operations a shard node must never perform have somewhere else to live: it
replaces the session, reads status and reads the enrollment, and it cannot reserve, sign, retain or
release. Its credential is the operator's, not the shard's, and neither endpoint accepts the other's.

Issuing a session is an operator act with a consequence: the previous client is fenced. That is the
intended way to take a shard process out of service and the reason this is not something the shard
can ask for.
*/
type OperatorClient struct {
	dial       Dialer
	credential []byte
	timeout    time.Duration

	mu   sync.Mutex
	conn net.Conn
}

// NewOperatorClient provisions the control-plane client.
func NewOperatorClient(cfg ClientConfig) (*OperatorClient, error) {
	if cfg.Dial == nil {
		return nil, errors.New("service: no dialer for the authority")
	}
	if len(cfg.Credential) < CredentialBytes {
		return nil, fmt.Errorf("service: the operator credential must be at least %d bytes", CredentialBytes)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &OperatorClient{dial: cfg.Dial, credential: append([]byte(nil), cfg.Credential...), timeout: timeout}, nil
}

func (o *OperatorClient) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dropLocked()
}

/*
ReplaceSession fences the current client and returns the credential for the next one.

The credential is returned once. The authority does not store it in a form it can hand out again, so
an operator that loses it replaces the session again, which fences again — losing a credential is not
a way to recover one.
*/
func (o *OperatorClient) ReplaceSession(ctx context.Context) ([]byte, error) {
	return o.call(ctx, opReplaceSession, nil)
}

// Status reports what the authority is holding.
func (o *OperatorClient) Status(ctx context.Context) (signingauthority.Status, error) {
	answer, err := o.call(ctx, opStatus, nil)
	if err != nil {
		return signingauthority.Status{}, err
	}
	var wire statusPayload
	if err := types.Cbor.Unmarshal(answer, &wire); err != nil {
		return signingauthority.Status{}, fmt.Errorf("decoding the status: %w", err)
	}
	return signingauthority.Status{
		Generation: wire.Generation, ReservedRound: wire.ReservedRound,
		HasReservation: wire.HasReservation, ResponseRetained: wire.ResponseRetained,
		Faulted: wire.Faulted, KeyLost: wire.KeyLost,
	}, nil
}

// Enrollment reports the immutable scope this authority signs for, and the public half of the key it
// generated. This is how a deployment learns the key to check responses against: from the authority,
// through the operator, at provisioning time.
func (o *OperatorClient) Enrollment(ctx context.Context) (signingauthority.Enrollment, []byte, error) {
	answer, err := o.call(ctx, opEnrollment, nil)
	if err != nil {
		return signingauthority.Enrollment{}, nil, err
	}
	var wire enrollmentPayload
	if err := types.Cbor.Unmarshal(answer, &wire); err != nil {
		return signingauthority.Enrollment{}, nil, fmt.Errorf("decoding the enrollment: %w", err)
	}
	var enrollment signingauthority.Enrollment
	if err := types.Cbor.Unmarshal(wire.Enrollment, &enrollment); err != nil {
		return signingauthority.Enrollment{}, nil, fmt.Errorf("decoding the enrollment: %w", err)
	}
	return enrollment, wire.PublicKey, nil
}

func (o *OperatorClient) call(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	cached := o.conn != nil
	answer, err := o.attemptLocked(ctx, operation, payload)
	if err == nil {
		return answer, nil
	}
	if !errors.Is(err, signingauthority.ErrUnavailable) || !cached {
		return nil, err
	}
	_ = o.dropLocked()
	return o.attemptLocked(ctx, operation, payload)
}

func (o *OperatorClient) attemptLocked(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	if o.conn == nil {
		conn, err := o.dial(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", signingauthority.ErrUnavailable, err)
		}
		o.conn = conn
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(o.timeout)
	}
	_ = o.conn.SetDeadline(deadline)

	if err := writeFrame(o.conn, wireRequest{
		Version: protocolVersion, Op: uint64(operation), Credential: o.credential, Payload: payload,
	}); err != nil {
		_ = o.dropLocked()
		return nil, fmt.Errorf("%w: sending %s: %v", signingauthority.ErrUnavailable, operation, err)
	}
	var response wireResponse
	if err := readFrame(o.conn, &response); err != nil {
		_ = o.dropLocked()
		return nil, fmt.Errorf("%w: reading the answer to %s: %v", signingauthority.ErrUnavailable, operation, err)
	}
	if response.Version != protocolVersion {
		_ = o.dropLocked()
		return nil, fmt.Errorf("%w: the authority answered version %d", signingauthority.ErrUnsupportedVersion, response.Version)
	}
	if response.Refusal != "" {
		return nil, refusalError(response.Refusal)
	}
	return response.Payload, nil
}

func (o *OperatorClient) dropLocked() error {
	if o.conn == nil {
		return nil
	}
	err := o.conn.Close()
	o.conn = nil
	return err
}
