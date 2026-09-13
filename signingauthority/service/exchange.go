package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/unicitynetwork/bft-core/signingauthority"
)

// DefaultTimeout bounds one operation when a client is provisioned without one.
const DefaultTimeout = 30 * time.Second

/*
exchange is the connection-keeping half of both clients.

It runs one operation at a time, keeps the connection between operations, and turns everything that
is not an answer from the authority into signingauthority.ErrUnavailable. Both the shard's client and
the operator's use it, so the rules about cancellation, deadlines and the single retry cannot differ
between the two ends of the boundary.
*/
type exchange struct {
	dial       Dialer
	credential []byte
	timeout    time.Duration

	// sem admits one operation at a time. It is a channel rather than a mutex because waiting for it
	// has to be interruptible: a caller whose context has ended must not be held behind an operation
	// that is still running. Whoever holds sem owns conn.
	sem  chan struct{}
	conn net.Conn
}

func newExchange(cfg ClientConfig) *exchange {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &exchange{
		dial:       cfg.Dial,
		credential: append([]byte(nil), cfg.Credential...),
		timeout:    timeout,
		sem:        make(chan struct{}, 1),
	}
}

/*
call runs one operation under a single deadline.

The deadline covers the whole operation: reaching the authority, sending the request, reading the
answer, and the one retry below. It is the earlier of the caller's own deadline and the configured
timeout, so a caller that asks for less gets less and a caller that asks for nothing still gets a
bound. The retry does not extend it. A shard node waiting here is a round that has not voted yet, and
the operator who configured a timeout was not promised two of them.

A context that ends stops the call wherever it is, including blocked in a read (see interrupt).
*/
func (e *exchange) call(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	// A caller that has already given up does not reach for the authority at all.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", signingauthority.ErrUnavailable, err)
	}
	// The budget starts before waiting for the slot. A call queued behind another is still a round
	// waiting on its authority, and its timeout has to count that wait too.
	ctx, cancel := context.WithDeadline(ctx, e.deadline(ctx))
	defer cancel()

	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: waiting for the previous operation: %w", signingauthority.ErrUnavailable, ctx.Err())
	}
	defer func() { <-e.sem }()

	cached := e.conn != nil
	answer, err := e.attempt(ctx, operation, payload)
	if err == nil {
		return answer, nil
	}
	// The retry is for a connection that was already open and turned out to be dead. It is not a
	// second chance at a deadline that has passed, or at a caller that has given up.
	if !errors.Is(err, signingauthority.ErrUnavailable) || !cached || ended(ctx) != nil {
		return nil, err
	}
	_ = e.drop()
	return e.attempt(ctx, operation, payload)
}

/*
ended reports why a context is over, including a deadline that has passed but not yet been noticed.

The connection's deadline is the context's deadline, and the two expire on separate clocks: a read
can return its i/o timeout before the context's own timer has marked it done. Asking ctx.Err() alone
at that moment says the caller still has time, which would permit a retry past the deadline and name
the mechanism rather than the reason.
*/
func ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (e *exchange) deadline(ctx context.Context) time.Time {
	configured := time.Now().Add(e.timeout)
	if caller, ok := ctx.Deadline(); ok && caller.Before(configured) {
		return caller
	}
	return configured
}

func (e *exchange) attempt(ctx context.Context, operation op, payload []byte) ([]byte, error) {
	conn, err := e.connect(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := interrupt(ctx, conn)
	defer stop()

	request := wireRequest{Version: protocolVersion, Op: uint64(operation), Credential: e.credential, Payload: payload}
	if err := writeFrame(conn, request); err != nil {
		_ = e.drop()
		return nil, e.unavailable(ctx, "sending %s: %v", operation, err)
	}
	var response wireResponse
	if err := readFrame(conn, &response); err != nil {
		_ = e.drop()
		return nil, e.unavailable(ctx, "reading the answer to %s: %v", operation, err)
	}
	if response.Version != protocolVersion {
		_ = e.drop()
		return nil, fmt.Errorf("%w: the authority answered version %d", signingauthority.ErrUnsupportedVersion, response.Version)
	}
	if response.Refusal != "" {
		return nil, refusalError(response.Refusal)
	}
	return response.Payload, nil
}

func (e *exchange) connect(ctx context.Context) (net.Conn, error) {
	if e.conn != nil {
		return e.conn, nil
	}
	conn, err := e.dial(ctx)
	if err != nil {
		return nil, e.unavailable(ctx, "%v", err)
	}
	e.conn = conn
	return conn, nil
}

func (e *exchange) close() error {
	e.sem <- struct{}{}
	defer func() { <-e.sem }()
	return e.drop()
}

func (e *exchange) drop() error {
	if e.conn == nil {
		return nil
	}
	err := e.conn.Close()
	e.conn = nil
	return err
}

/*
unavailable names what went wrong, and prefers the context's reason when there is one.

When a call ends because the caller cancelled or the deadline passed, the I/O failure underneath it
is a deadline this code set on purpose. Reporting that would describe the mechanism instead of the
reason, and an operator reading a round's abstention should see which of the two happened.
*/
func (e *exchange) unavailable(ctx context.Context, format string, args ...any) error {
	if err := ended(ctx); err != nil {
		return fmt.Errorf("%w: %w", signingauthority.ErrUnavailable, err)
	}
	return fmt.Errorf("%w: %s", signingauthority.ErrUnavailable, fmt.Sprintf(format, args...))
}

/*
interrupt ends a blocked read or write when the caller's context does.

A net.Conn takes no context, and a connection blocked reading an answer notices nothing else, so a
deadline in the past is how it is woken. Without this, a cancelled call still waits for the timeout,
which is exactly what a shard node shutting down, or a round that has moved on, cannot afford.

The watcher is stopped before this returns, so it cannot put a deadline on a connection that a later
operation has taken over.
*/
func interrupt(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now().Add(-time.Second))
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}
