package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Disseminator carries the round's leader-built Block to the shard's other
// validators. It is the one part of the framework whose implementation an
// Executor is allowed to influence — see docs/adr/0001-executor-boundary.md
// §"Dissemination splits along the boundary": an EVM executor needs the
// leader's exact ordered payload, byte for byte, while an accumulator
// executor needs only the same set of entries and can tolerate unordered,
// deduplicating delivery. The Disseminator interface itself carries no
// opinion either way — Block.Raw is already executor-encoded by the time it
// reaches here, so this package only ever moves bytes.
type Disseminator interface {
	// Publish sends b to the shard's other validators for round. Called by
	// the round's leader only; implementations may fire-and-forget.
	Publish(ctx context.Context, round uint64, b Block) error

	// Await blocks until the leader's Block for round has arrived, or ctx
	// is done. Called by every non-leader validator, once per round.
	Await(ctx context.Context, round uint64) (Block, error)
}

// ErrDisseminationClosed is returned by Await after Close.
var ErrDisseminationClosed = errors.New("shardnode: dissemination closed")

// LoopbackDisseminator delivers Publish straight to local Await calls, with
// no network involved. It exists for two things: driving round.go's own
// unit tests without libp2p, and single-validator operation (quorum 1),
// where the leader is always this node and there is nothing to disseminate
// to. It is not multi-validator-capable — see network's
// libp2p-backed Disseminator (C2.2 in the build plan) for that.
type LoopbackDisseminator struct {
	mu     sync.Mutex
	waiter map[uint64]chan Block
	closed bool
}

func NewLoopbackDisseminator() *LoopbackDisseminator {
	return &LoopbackDisseminator{waiter: make(map[uint64]chan Block)}
}

func (d *LoopbackDisseminator) Publish(_ context.Context, round uint64, b Block) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrDisseminationClosed
	}
	ch := d.chanFor(round)
	select {
	case ch <- b:
	default:
		// A round is only ever published once by an honest leader; a
		// second publish for the same round indicates a bug in the caller,
		// not a condition Await needs to handle.
	}
	return nil
}

func (d *LoopbackDisseminator) Await(ctx context.Context, round uint64) (Block, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return Block{}, ErrDisseminationClosed
	}
	ch := d.chanFor(round)
	d.mu.Unlock()

	select {
	case b := <-ch:
		return b, nil
	case <-ctx.Done():
		return Block{}, fmt.Errorf("awaiting round %d: %w", round, ctx.Err())
	}
}

func (d *LoopbackDisseminator) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, ch := range d.waiter {
		close(ch)
	}
}

// chanFor must be called with d.mu held.
func (d *LoopbackDisseminator) chanFor(round uint64) chan Block {
	ch, ok := d.waiter[round]
	if !ok {
		ch = make(chan Block, 1)
		d.waiter[round] = ch
	}
	return ch
}
