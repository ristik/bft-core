package service

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/unicitynetwork/bft-core/signingauthority"
)

// ReloadingClient is a Client that follows session replacement in-process: when the authority refuses an operation as fenced (the
// operator advanced the epoch or replaced the session), it reads the current credential again and, when it changed, connects under the
// new one. The shard process keeps running through every authority order (phase 2).
//
// Timeout. One call of the wrapper has one budget: the configured timeout (DefaultTimeout when zero) from the moment the call starts, or
// the caller's earlier deadline. A fenced Reserve (or RestoreStatus) is retried once under the new session within that same budget, never
// with a fresh one. The budget bounds the authority exchanges; the credential loader callback is not interrupted by it.
//
// Retries. Only a fenced Reserve is retried: the authority refused it before reserving anything. A fenced Sign, RetainResponse or Release
// is reported (the round abstains); the next operation uses the new session. The wrapper does NOT bind a Reserve→Release sequence to one
// session: each operation uses the client current when it starts. What keeps that safe is the authority itself (it checks the presented
// credential on every operation, rejects a reservation of another enrollment, and keeps its high-water record across sessions).
//
// Reload. A reload reads the credential without holding any lock, installs the new client only if the client it replaces is still the
// current one (so a slower, older read never overwrites a newer installation), and closes the replaced client in the background (a close
// waits for its exchange slot, which no caller waits behind). A cancelled caller does not reload and does not retry.
type ReloadingClient struct {
	load    func() ([]byte, error)
	cfg     ClientConfig
	mu      sync.Mutex
	current *Client
	cred    []byte
}

// NewReloadingClient provisions a client whose credential is read by load, now and after every fenced refusal. cfg.Credential is ignored.
func NewReloadingClient(cfg ClientConfig, load func() ([]byte, error)) (*ReloadingClient, error) {
	if load == nil {
		return nil, errors.New("service: no credential loader")
	}
	cred, err := load()
	if err != nil {
		return nil, err
	}
	cfg.Credential = cred
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &ReloadingClient{load: load, cfg: cfg, current: client, cred: bytes.Clone(cred)}, nil
}

func (r *ReloadingClient) client() *Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// budget is the call's one deadline: the effective timeout from now (a zero Timeout is the client's DefaultTimeout, as newExchange
// normalizes it), or the caller's earlier deadline. It bounds the authority exchanges of both attempts; the credential loader is a
// synchronous callback it does not interrupt (the production loader reads one small local file).
func (r *ReloadingClient) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := r.cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

// reload switches from used to the current credential if it differs, and reports whether a newer client is now current. It does nothing
// for a cancelled caller, holds no lock while reading the credential or closing, and never replaces a client installed after used.
func (r *ReloadingClient) reload(ctx context.Context, used *Client) bool {
	if ctx.Err() != nil {
		return false
	}
	cred, err := r.load()
	if err != nil || ctx.Err() != nil {
		return false
	}
	r.mu.Lock()
	if r.current != used {
		// another reload already replaced the client this call used: that one is current, use it
		r.mu.Unlock()
		return true
	}
	if bytes.Equal(cred, r.cred) {
		r.mu.Unlock()
		return false
	}
	cfg := r.cfg
	cfg.Credential = cred
	next, err := NewClient(cfg)
	if err != nil {
		r.mu.Unlock()
		return false
	}
	old := r.current
	r.current, r.cred = next, bytes.Clone(cred)
	r.mu.Unlock()
	go func() { _ = old.Close() }() // waits for its in-flight exchange, behind no caller
	return true
}

func fenced(err error) bool { return errors.Is(err, signingauthority.ErrFenced) }

func (r *ReloadingClient) Reserve(ctx context.Context, req signingauthority.Request) (*signingauthority.Authorization, error) {
	ctx, cancel := r.budget(ctx)
	defer cancel()
	used := r.client()
	auth, err := used.Reserve(ctx, req)
	if fenced(err) && r.reload(ctx, used) {
		return r.client().Reserve(ctx, req)
	}
	return auth, err
}

func (r *ReloadingClient) Sign(ctx context.Context) error {
	used := r.client()
	err := used.Sign(ctx)
	if fenced(err) {
		r.reload(ctx, used)
	}
	return err
}

func (r *ReloadingClient) RetainResponse(ctx context.Context) error {
	used := r.client()
	err := used.RetainResponse(ctx)
	if fenced(err) {
		r.reload(ctx, used)
	}
	return err
}

func (r *ReloadingClient) Release(ctx context.Context, round uint64, digest [32]byte) ([]byte, error) {
	used := r.client()
	out, err := used.Release(ctx, round, digest)
	if fenced(err) {
		r.reload(ctx, used)
	}
	return out, err
}

func (r *ReloadingClient) RestoreStatus(ctx context.Context) (signingauthority.Status, error) {
	ctx, cancel := r.budget(ctx)
	defer cancel()
	used := r.client()
	status, err := used.RestoreStatus(ctx)
	if fenced(err) && r.reload(ctx, used) {
		return r.client().RestoreStatus(ctx)
	}
	return status, err
}

// Close drops the connection in use.
func (r *ReloadingClient) Close() error { return r.client().Close() }
