package configuredprogress

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrAdmissionBusy   = errors.New("configuredprogress: observation authentication busy")
	ErrAdmissionClosed = errors.New("configuredprogress: admission coordinator closed")
)

const (
	admissionAttempts = 3
	admissionDuration = 5 * time.Second
	admissionSpacing  = time.Second
	admissionCooldown = 10 * time.Second
)

// AdmissionGate serializes the short invalidation and durable commit boundaries with
// finality-changing work. Implementations must honor ctx and must not call the delivery
// callback while held.
type AdmissionGate interface {
	WithinFinality(context.Context, func() error) error
}

// AdmissionConfig creates an inactive persistence-before-delivery coordinator. Context trust
// lookups, Gate and Deliver must honor cancellation. Invalidate is a short, synchronous,
// non-reentrant notification of the coordinator's sticky internal refusal; it cannot grant
// readiness. Deliver must be idempotent and must not synchronously call Close (the worker owns
// delivery). No callback result grants freshness, continuity, execution or signing authority.
type AdmissionConfig struct {
	Store      *Store
	Context    Context
	Gate       AdmissionGate
	Invalidate func()
	Deliver    func(context.Context, rootinput.VerifiedObservationV2) error
}

// AdmissionResult describes ingress handling, not persistence or readiness.
type AdmissionResult uint8

const (
	AdmissionQueued AdmissionResult = iota
	AdmissionCoalesced
	AdmissionUnsupported
)

// AdmissionStatus is a process-local diagnostic. No field grants freshness or readiness.
type AdmissionStatus struct {
	BootstrapInvalidated bool
	UnsupportedSeen      bool
	PendingFirst         bool
	PendingLatest        bool
	DeliveryPending      bool
	EpisodeActive        bool
	LastError            error
}

type admissionClock interface {
	Episode(context.Context, time.Duration) (context.Context, context.CancelFunc)
	Wait(context.Context, time.Duration) error
}

type wallAdmissionClock struct{}

func (wallAdmissionClock) Episode(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
func (wallAdmissionClock) Wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type admissionPolicy struct {
	attempts int
	duration time.Duration
	spacing  time.Duration
	cooldown time.Duration
}

// AdmissionCoordinator owns one bounded authentication slot, one worker episode, one
// immutable pending first-ordinary pair and one replaceable newest pair. Episode deadlines
// are cooperative: an operating-system-stalled syncing transaction cannot be forcibly canceled.
type AdmissionCoordinator struct {
	store      *Store
	ctx        Context
	gate       AdmissionGate
	invalidate func()
	deliver    func(context.Context, rootinput.VerifiedObservationV2) error
	clock      admissionClock
	policy     admissionPolicy

	ctxRun       context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	shutdownDone chan struct{}
	shutdownOnce sync.Once
	wake         chan struct{}
	auth         chan struct{}

	mu                   sync.Mutex
	closed               bool
	bootstrapInvalidated bool
	invalidationNotified bool
	unsupportedSeen      bool
	firstKnown           bool
	pendingFirst         *rootinput.VerifiedObservationV2
	pendingLatest        *rootinput.VerifiedObservationV2
	obligation           *rootinput.VerifiedObservationV2
	episode              bool
	lastErr              error
}

func NewAdmissionCoordinator(ctx context.Context, cfg AdmissionConfig) (*AdmissionCoordinator, error) {
	return newAdmissionCoordinator(ctx, cfg, wallAdmissionClock{}, admissionPolicy{attempts: admissionAttempts, duration: admissionDuration, spacing: admissionSpacing, cooldown: admissionCooldown})
}

func newAdmissionCoordinator(ctx context.Context, cfg AdmissionConfig, clock admissionClock, policy admissionPolicy) (*AdmissionCoordinator, error) {
	if cfg.Store == nil || cfg.Gate == nil || cfg.Invalidate == nil || cfg.Deliver == nil || clock == nil || policy.attempts < 1 || policy.duration <= 0 || policy.spacing < 0 || policy.cooldown < 0 {
		return nil, ErrSettings
	}
	owned, err := ownContext(cfg.Context)
	if err != nil {
		return nil, err
	}
	st, _, err := cfg.Store.Load(ctx, owned)
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithCancel(ctx)
	c := &AdmissionCoordinator{store: cfg.Store, ctx: owned, gate: cfg.Gate, invalidate: cfg.Invalidate, deliver: cfg.Deliver, clock: clock, policy: policy, ctxRun: run, cancel: cancel, done: make(chan struct{}), shutdownDone: make(chan struct{}), wake: make(chan struct{}, 1), auth: make(chan struct{}, 1)}
	if st.Ordinary() {
		c.bootstrapInvalidated = true
		c.firstKnown = true
	}
	if observed, ok := st.Observed(); ok {
		ownedObserved := observed
		c.obligation = &ownedObserved
	}
	initialWake := c.obligation != nil || (c.bootstrapInvalidated && !c.invalidationNotified)
	go c.run()
	if initialWake {
		c.signal()
	}
	return c, nil
}

// Submit bounds concurrent authentication to one caller, owns and authenticates UC/TR off
// the finality gate, then queues only authenticated v2 observations. It accepts no freshness input.
func (c *AdmissionCoordinator) Submit(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (AdmissionResult, error) {
	select {
	case c.auth <- struct{}{}:
		defer func() { <-c.auth }()
	default:
		return 0, ErrAdmissionBusy
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, ErrAdmissionClosed
	}
	authCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctxRun, cancel)
	defer func() { stop(); cancel() }()
	if err := c.ctxRun.Err(); err != nil {
		return 0, ErrAdmissionClosed
	}
	if err := checkAdmissionEvidenceBounds(uc, tr); err != nil {
		return 0, err
	}
	o, err := rootinput.AuthenticateObservationV2(authCtx, c.ctx.Observation, uc, tr)
	if err != nil {
		if rootinput.IsUnsupportedObservationV2(err) {
			if e := c.markInvalid(authCtx, true); e != nil {
				return 0, e
			}
			return AdmissionUnsupported, err
		}
		return 0, err
	}
	if o.Class() != evmroot.OriginBootstrapV2 {
		if err = c.markInvalid(authCtx, false); err != nil {
			return 0, err
		}
	} else if err = authCtx.Err(); err != nil {
		return 0, err
	}
	if _, _, err = pairFromObservation(o); err != nil {
		if markErr := c.markInvalid(authCtx, true); markErr != nil {
			return 0, markErr
		}
		return AdmissionUnsupported, err
	}
	return c.queue(o)
}

// checkAdmissionEvidenceBounds makes caller-owned aggregate sizes finite before rootinput
// copies or marshals them. The exact canonical pair bound is checked again after authentication.
func checkAdmissionEvidenceBounds(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	const maxNodes = 4 * 65536
	type budget struct{ nodes, bytes int }
	b := budget{}
	path := map[uintptr]bool{}
	var walk func(reflect.Value, int) error
	walk = func(v reflect.Value, depth int) error {
		if !v.IsValid() {
			return nil
		}
		if depth > maxNestedLevels {
			return fmt.Errorf("%w: evidence nesting", ErrBounds)
		}
		b.nodes++
		if b.nodes > maxNodes {
			return fmt.Errorf("%w: evidence elements", ErrBounds)
		}
		switch v.Kind() {
		case reflect.Interface:
			if !v.IsNil() {
				return walk(v.Elem(), depth+1)
			}
		case reflect.Pointer:
			if v.IsNil() {
				return nil
			}
			p := v.Pointer()
			if path[p] {
				return fmt.Errorf("%w: cyclic evidence", ErrBounds)
			}
			path[p] = true
			err := walk(v.Elem(), depth+1)
			delete(path, p)
			return err
		case reflect.String:
			b.bytes += v.Len()
		case reflect.Slice:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				b.bytes += v.Len()
				break
			}
			if v.Len() > 65536 {
				return fmt.Errorf("%w: evidence array elements", ErrBounds)
			}
			for i := 0; i < v.Len(); i++ {
				if err := walk(v.Index(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Array:
			for i := 0; i < v.Len(); i++ {
				if err := walk(v.Index(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Map:
			if v.Len() > 65536 {
				return fmt.Errorf("%w: evidence map elements", ErrBounds)
			}
			it := v.MapRange()
			for it.Next() {
				if err := walk(it.Key(), depth+1); err != nil {
					return err
				}
				if err := walk(it.Value(), depth+1); err != nil {
					return err
				}
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if err := walk(v.Field(i), depth+1); err != nil {
					return err
				}
			}
		}
		if b.bytes > MaxPairBytes {
			return fmt.Errorf("%w: evidence byte content", ErrBounds)
		}
		return nil
	}
	if err := walk(reflect.ValueOf(uc), 0); err != nil {
		return err
	}
	return walk(reflect.ValueOf(tr), 0)
}

func (c *AdmissionCoordinator) markInvalid(ctx context.Context, unsupported bool) error {
	c.mu.Lock()
	c.bootstrapInvalidated = true
	c.unsupportedSeen = c.unsupportedSeen || unsupported
	c.mu.Unlock()
	err := c.notifyInvalidation(ctx)
	if err != nil {
		c.signal()
	}
	return err
}

func (c *AdmissionCoordinator) notifyInvalidation(ctx context.Context) error {
	return c.gate.WithinFinality(ctx, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		notify := !c.invalidationNotified
		c.invalidationNotified = true
		c.mu.Unlock()
		if notify {
			c.invalidate()
		}
		return nil
	})
}

func (c *AdmissionCoordinator) queue(o rootinput.VerifiedObservationV2) (AdmissionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, ErrAdmissionClosed
	}
	result := AdmissionQueued
	if c.pendingLatest != nil {
		rel, err := compareObservations(*c.pendingLatest, o)
		if err != nil {
			return 0, err
		}
		switch rel {
		case relationDuplicate, relationStale:
			result = AdmissionCoalesced
			c.signalLocked()
			return result, nil
		}
	}
	if c.obligation != nil {
		rel, err := compareObservations(*c.obligation, o)
		if err != nil {
			return 0, err
		}
		if rel == relationDuplicate || rel == relationStale {
			c.signalLocked()
			return AdmissionCoalesced, nil
		}
	}
	owned := o
	if o.Class() != evmroot.OriginBootstrapV2 && c.pendingFirst == nil && !c.firstKnown {
		first := owned
		c.pendingFirst = &first
	}
	c.pendingLatest = &owned
	c.signalLocked()
	return result, nil
}

func (c *AdmissionCoordinator) signal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signalLocked()
}
func (c *AdmissionCoordinator) signalLocked() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *AdmissionCoordinator) run() {
	defer close(c.done)
	for {
		select {
		case <-c.ctxRun.Done():
			return
		case <-c.wake:
		}
		c.runEpisode()
		if c.hasWork() {
			if c.clock.Wait(c.ctxRun, c.policy.cooldown) != nil {
				return
			}
			c.signal()
		}
	}
}

func (c *AdmissionCoordinator) runEpisode() {
	c.mu.Lock()
	c.episode = true
	c.lastErr = nil
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.episode = false
		c.mu.Unlock()
	}()
	episodeCtx, cancel := c.clock.Episode(c.ctxRun, c.policy.duration)
	defer cancel()
	for attempts := 0; attempts < c.policy.attempts && episodeCtx.Err() == nil; attempts++ {
		worked, err := c.step(episodeCtx)
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		if err == nil && !c.hasWork() {
			return
		}
		if !worked && err == nil {
			return
		}
		if attempts+1 < c.policy.attempts {
			if err := c.clock.Wait(episodeCtx, c.policy.spacing); err != nil {
				return
			}
		}
	}
}

// step performs at most one durable commit or one delivery; both consume the shared episode budget.
func (c *AdmissionCoordinator) step(ctx context.Context) (bool, error) {
	c.mu.Lock()
	first, latest, obligation := c.pendingFirst, c.pendingLatest, c.obligation
	needsInvalidation := c.bootstrapInvalidated && !c.invalidationNotified
	c.mu.Unlock()
	if needsInvalidation {
		return true, c.notifyInvalidation(ctx)
	}
	if first != nil {
		return true, c.persist(ctx, *first, true)
	}
	if latest != nil {
		return true, c.persist(ctx, *latest, false)
	}
	if obligation != nil {
		err := c.deliver(ctx, *obligation)
		if err == nil {
			c.mu.Lock()
			if c.obligation != nil && sameObservation(*c.obligation, *obligation) {
				c.obligation = nil
			}
			c.mu.Unlock()
		}
		return true, err
	}
	return false, nil
}

func sameObservation(a, b rootinput.VerifiedObservationV2) bool {
	rel, err := compareObservations(a, b)
	return err == nil && rel == relationDuplicate
}

func (c *AdmissionCoordinator) persist(ctx context.Context, o rootinput.VerifiedObservationV2, first bool) error {
	p, _, err := c.store.PrepareObservation(ctx, c.ctx, o)
	if err != nil {
		return err
	}
	var current rootinput.VerifiedObservationV2
	err = c.gate.WithinFinality(ctx, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var commitErr error
		current, _, commitErr = c.store.CommitObservation(p)
		return commitErr
	})
	if err != nil {
		return err
	}
	st, _, err := c.store.Load(ctx, c.ctx)
	if err != nil {
		return err
	}
	if first {
		got, ok := st.FirstOrdinary()
		if !ok || !sameObservation(got, o) {
			return fmt.Errorf("%w: another first ordinary observation was latched", ErrConflict)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if first && c.pendingFirst != nil && sameObservation(*c.pendingFirst, o) {
		c.pendingFirst = nil
		c.firstKnown = true
	}
	if c.pendingLatest != nil {
		rel, compareErr := compareObservations(current, *c.pendingLatest)
		if compareErr == nil && (rel == relationDuplicate || rel == relationStale) {
			c.pendingLatest = nil
		}
	}
	if c.pendingLatest == nil {
		owned := current
		c.obligation = &owned
	}
	return nil
}

func (c *AdmissionCoordinator) hasWork() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return (c.bootstrapInvalidated && !c.invalidationNotified) || c.pendingFirst != nil || c.pendingLatest != nil || c.obligation != nil
}

func (c *AdmissionCoordinator) Status() AdmissionStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return AdmissionStatus{BootstrapInvalidated: c.bootstrapInvalidated, UnsupportedSeen: c.unsupportedSeen, PendingFirst: c.pendingFirst != nil, PendingLatest: c.pendingLatest != nil, DeliveryPending: c.obligation != nil, EpisodeActive: c.episode, LastError: c.lastErr}
}

func (c *AdmissionCoordinator) Close() error {
	c.shutdownOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.cancel()
		// Authentication is the only Submit work outside the worker. Wait until its bounded
		// slot is released so Close cannot return before a Submit callback has stopped.
		c.auth <- struct{}{}
		<-c.auth
		<-c.done
		close(c.shutdownDone)
	})
	<-c.shutdownDone
	return nil
}
