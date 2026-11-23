package shardnode

import (
	"context"
	"errors"
	"sync"
)

// RootActivation identifies the locally verified live root context. Epochs
// select the certificate verifier and BodyID binds the installed lineage entry.
type RootActivation struct {
	Epoch  uint64
	BodyID [32]byte
}

var ErrRootActivationSuperseded = errors.New("shardnode: work superseded by a verified root activation")

// RootActivationGate belongs to the shard's verified trust store. Only local
// installation advances it. Speculative work observes cancellation. Publication
// and release are serialized with installation.
type RootActivationGate struct {
	mu       sync.RWMutex
	current  RootActivation
	pending  RootActivation
	lifetime context.Context
	cancel   context.CancelFunc
}

func NewRootActivationGate(initial RootActivation) *RootActivationGate {
	ctx, cancel := context.WithCancel(context.Background())
	return &RootActivationGate{current: initial, lifetime: ctx, cancel: cancel}
}

func (g *RootActivationGate) Current() RootActivation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.current
}

// Begin closes speculative work once the successor is verified. It does not
// admit the successor while its durable handoff and execution context install.
func (g *RootActivationGate) Begin(next RootActivation) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.checkNext(next); err != nil || next == g.current {
		return err
	}
	g.pending = next
	g.cancel()
	return nil
}

func (g *RootActivationGate) checkNext(next RootActivation) error {
	if next != g.current && (next.Epoch <= g.current.Epoch || next.Epoch-g.current.Epoch != 1 ||
		(g.pending.Epoch != 0 && g.pending != next)) {
		return ErrRootActivationSuperseded
	}
	return nil
}

func (g *RootActivationGate) Install(next RootActivation) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.checkNext(next); err != nil || next == g.current {
		return err
	}
	g.cancel()
	g.current, g.pending = next, RootActivation{}
	g.lifetime, g.cancel = context.WithCancel(context.Background())
	return nil
}

type rootActivationContext struct {
	gate *RootActivationGate
	id   RootActivation
}
type rootActivationKey struct{}

func (g *RootActivationGate) work(ctx context.Context, epoch uint64) (context.Context, func(), error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.current.Epoch != epoch || g.pending.Epoch != 0 {
		return ctx, func() {}, ErrRootActivationSuperseded
	}
	ctx = context.WithValue(ctx, rootActivationKey{}, rootActivationContext{gate: g, id: g.current})
	run, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(g.lifetime, func() { cancel(ErrRootActivationSuperseded) })
	return run, func() { stop(); cancel(nil) }, nil
}

func (g *RootActivationGate) withEpoch(epoch uint64, fn func() error) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.current.Epoch != epoch || g.pending.Epoch != 0 {
		return ErrRootActivationSuperseded
	}
	return fn()
}

func rootActivationOf(ctx context.Context) RootActivation {
	scope, _ := ctx.Value(rootActivationKey{}).(rootActivationContext)
	return scope.id
}

func underRootActivation(ctx context.Context, fn func() error) error {
	if scope, ok := ctx.Value(rootActivationKey{}).(rootActivationContext); ok {
		return scope.gate.withEpoch(scope.id.Epoch, fn)
	}
	return fn()
}
