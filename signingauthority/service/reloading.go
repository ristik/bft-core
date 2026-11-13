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
// new one. The shard process keeps running through every authority order; nothing is restarted to pick up a new session (phase 2).
//
// Only a Reserve that was fenced is retried under the new session: the authority refused it before reserving anything, so the same
// request is the first attempt of the new session. A fenced Sign, RetainResponse or Release is not retried (the reservation it continues
// belongs to the fenced session); the round abstains and the next round uses the new session. The authority's own high-water record is
// what makes every signature unique; this client only chooses which session to ask.
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

// reload switches to the current credential if it differs from the one in use, and reports whether it did.
func (r *ReloadingClient) reload() bool {
	cred, err := r.load()
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if bytes.Equal(cred, r.cred) {
		return false
	}
	cfg := r.cfg
	cfg.Credential = cred
	next, err := NewClient(cfg)
	if err != nil {
		return false
	}
	_ = r.current.Close()
	r.current, r.cred = next, bytes.Clone(cred)
	return true
}

func fenced(err error) bool { return errors.Is(err, signingauthority.ErrFenced) }

func (r *ReloadingClient) Reserve(ctx context.Context, req signingauthority.Request) (*signingauthority.Authorization, error) {
	auth, err := r.client().Reserve(ctx, req)
	if fenced(err) && r.reload() {
		return r.client().Reserve(ctx, req)
	}
	return auth, err
}

func (r *ReloadingClient) Sign(ctx context.Context) error {
	err := r.client().Sign(ctx)
	if fenced(err) {
		r.reload()
	}
	return err
}

func (r *ReloadingClient) RetainResponse(ctx context.Context) error {
	err := r.client().RetainResponse(ctx)
	if fenced(err) {
		r.reload()
	}
	return err
}

func (r *ReloadingClient) Release(ctx context.Context, round uint64, digest [32]byte) ([]byte, error) {
	out, err := r.client().Release(ctx, round, digest)
	if fenced(err) {
		r.reload()
	}
	return out, err
}

func (r *ReloadingClient) RestoreStatus(ctx context.Context) (signingauthority.Status, error) {
	status, err := r.client().RestoreStatus(ctx)
	if fenced(err) && r.reload() {
		return r.client().RestoreStatus(ctx)
	}
	return status, err
}

// Close drops the connection in use.
func (r *ReloadingClient) Close() error { return r.client().Close() }
