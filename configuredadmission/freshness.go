package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierrequester"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrFreshnessRequired means bootstrap is still the only known state and no live
	// root-quorum receipt vouches for it: the node must not lead or sign (F6e section 5).
	ErrFreshnessRequired = errors.New("configuredadmission: bootstrap needs a live fresh root-quorum receipt")
	// ErrFreshnessUnavailable means the receipt mechanism cannot run at all in this process
	// (not started, stopped, or its fixed profile was refused). It never falls back to genesis.
	ErrFreshnessUnavailable = errors.New("configuredadmission: bootstrap freshness is unavailable")
	// ErrBootstrapRefused means authenticated unsupported evidence was seen: bootstrap is
	// refused for this process and there is no ordinary progress to continue from.
	ErrBootstrapRefused = errors.New("configuredadmission: bootstrap is refused after unsupported root evidence")
)

const (
	guardAuthTimeout = 10 * time.Second
	bootstrapClass   = evmroot.OriginBootstrapV2
)

// Freshness is the shard node's automatic root-quorum bootstrap freshness (F6f, #350). It is
// created before the node runs, handed to the journal admission factory (which starts it) and to
// the execution-recovery readiness gate (which consults it). Nothing here is persisted: a
// restarted process begins without a receipt, and a store that already holds ordinary progress
// never needs one.
type Freshness struct {
	Opener    frontiertransport.StreamOpener
	TrustBase *types.RootTrustBaseV1
	Logger    *slog.Logger

	mu        sync.Mutex
	guard     *bootstrapGuard
	requester receiptSource
	startErr  error
}

// receiptSource is the part of the requester that readiness consults.
type receiptSource interface {
	Current() frontierrequester.Receipt
	Validate(frontierrequester.Receipt) error
}

// RootPeers derives the root requester peers from a trust base: a root's node ID is its peer ID.
func RootPeers(tb *types.RootTrustBaseV1) ([]frontierrequester.RootPeer, error) {
	if tb == nil {
		return nil, frontierrequester.ErrSettings
	}
	peers := make([]frontierrequester.RootPeer, 0, len(tb.RootNodes))
	for _, n := range tb.RootNodes {
		id, err := peer.Decode(n.NodeID)
		if err != nil {
			return nil, fmt.Errorf("%w: root node %q is not a peer ID: %v", frontierrequester.ErrSettings, n.NodeID, err)
		}
		peers = append(peers, frontierrequester.RootPeer{Author: n.NodeID, PeerID: id})
	}
	return peers, nil
}

// start builds the guard and requester for one admission and, unless ordinary progress is already
// durable, runs the requester until bootstrap is superseded or ctx ends. It never fails the node:
// a profile the protocol cannot serve leaves bootstrap unready with the reason reported, because
// ordinary operation does not need a receipt.
func (f *Freshness) start(ctx context.Context, c configuredprogress.Context, store *configuredprogress.Store, submit func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error) *bootstrapGuard {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(err error) *bootstrapGuard {
		f.startErr = fmt.Errorf("%w: %v", ErrFreshnessUnavailable, err)
		if f.Logger != nil {
			f.Logger.ErrorContext(ctx, "bootstrap freshness cannot start; a node with no ordinary progress stays unready", slog.String("error", err.Error()))
		}
		return nil
	}
	if f.Opener == nil || f.TrustBase == nil {
		return fail(frontierrequester.ErrSettings)
	}
	st, _, err := store.Load(ctx, c)
	if err != nil {
		return fail(err)
	}
	g, err := newBootstrapGuard(ctx, c, f.TrustBase, st.Ordinary(), submit, f.Logger)
	if err != nil {
		return fail(err)
	}
	peers, err := RootPeers(f.TrustBase)
	if err != nil {
		return fail(err)
	}
	o := c.Observation
	r, err := frontierrequester.New(frontierrequester.Config{
		Process: ctx,
		Profile: frontierclient.Profile{TrustBase: f.TrustBase, NetworkID: o.NetworkID, PartitionID: o.PartitionID, ShardID: o.ShardID, FullShardConfHash: o.ShardConfHash, RootEpoch: o.RootEpoch, GenesisOriginIdentity: c.Origin.Identity().Bytes()},
		Peers:   peers, Opener: f.Opener, Admission: g,
		Report: func(err error) {
			if f.Logger == nil {
				return
			}
			if err != nil {
				f.Logger.WarnContext(ctx, "bootstrap receipt acquisition failed; the node stays unready until a root quorum confirms the initial state", slog.String("error", err.Error()))
				return
			}
			f.Logger.InfoContext(ctx, "bootstrap receipt acquired from a fresh root quorum")
		},
	})
	if err != nil {
		return fail(err)
	}
	f.guard, f.requester = g, r
	if g.BootstrapState().Allowed() {
		go func() {
			err := r.Maintain(ctx)
			if f.Logger != nil && !errors.Is(err, context.Canceled) {
				f.Logger.InfoContext(ctx, "bootstrap freshness acquisition ended", slog.String("reason", err.Error()))
			}
		}()
	}
	return g
}

// Require is the readiness predicate. It is nil when the node may act on its held certificate as far
// as bootstrap freshness goes: either ordinary progress is known (it never needs a receipt), or
// bootstrap is the only known state and a live receipt exists. It is cheap and is called both when
// readiness is prepared and again inside the finality gate before building or signing.
func (f *Freshness) Require() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	g, r, startErr := f.guard, f.requester, f.startErr
	f.mu.Unlock()
	if g == nil || r == nil {
		if startErr != nil {
			return startErr
		}
		return fmt.Errorf("%w: not started", ErrFreshnessUnavailable)
	}
	state := g.BootstrapState()
	if state.Closed || state.ProcessStopped {
		return fmt.Errorf("%w: stopped", ErrFreshnessUnavailable)
	}
	if state.Allowed() {
		if err := r.Validate(r.Current()); err != nil {
			return fmt.Errorf("%w: %v", ErrFreshnessRequired, err)
		}
		return nil
	}
	if state.UnsupportedSeen {
		return ErrBootstrapRefused
	}
	return nil // ordinary progress is known: no bootstrap receipt applies
}

// Status is a diagnostic snapshot of the guard (nil when freshness never started).
func (f *Freshness) Status() (BootstrapGuardStatus, bool) {
	f.mu.Lock()
	g := f.guard
	f.mu.Unlock()
	if g == nil {
		return BootstrapGuardStatus{}, false
	}
	return g.Status(), true
}

type fixedTrust struct{ trust *types.RootTrustBaseV1 }

func (t fixedTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	b, err := types.Cbor.Marshal(t.trust)
	if err != nil {
		return nil, err
	}
	var out types.RootTrustBaseV1
	if err = types.Cbor.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BootstrapGuardStatus is a process-local diagnostic. No field grants readiness.
type BootstrapGuardStatus struct {
	Invalidated     bool
	UnsupportedSeen bool
	FirstOrdinary   []byte
	LatestOrdinary  []byte
}

// bootstrapGuard is the journal path's counterpart of configuredprogress.AdmissionCoordinator for
// the requester: the live sticky bootstrap-invalidation latch and the acknowledged retention
// boundary for authenticated negative evidence. It owns no persistence: ordinary evidence is
// forwarded to the journal admission, which persists it exactly as it persists any certificate.
type bootstrapGuard struct {
	process context.Context
	obs     rootinput.ObservationContextV2
	binding [32]byte
	forward func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
	log     *slog.Logger

	mu          sync.Mutex
	invalidated bool
	unsupported bool
	first       []byte
	latest      []byte
	queued      *pairValue
	forwarding  bool
}

type pairValue struct {
	uc *types.UnicityCertificate
	tr *certification.TechnicalRecord
}

func newBootstrapGuard(process context.Context, c configuredprogress.Context, trust *types.RootTrustBaseV1, ordinaryKnown bool, forward func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error, log *slog.Logger) (*bootstrapGuard, error) {
	if c.Observation.RootEpoch != trust.Epoch {
		return nil, fmt.Errorf("%w: trust base epoch %d differs from the pinned root epoch %d", frontierrequester.ErrSettings, trust.Epoch, c.Observation.RootEpoch)
	}
	b, err := types.Cbor.Marshal(trust)
	if err != nil {
		return nil, err
	}
	var owned types.RootTrustBaseV1
	if err = types.Cbor.Unmarshal(b, &owned); err != nil {
		return nil, err
	}
	// Like the coordinator, authenticate against the one fixed trust snapshot: a claim of another
	// root epoch must surface as unsupported evidence, not be resolved by epoch history.
	obs := c.Observation
	obs.ShardConfHash = bytes.Clone(obs.ShardConfHash)
	obs.TrustBases = fixedTrust{trust: &owned}
	obs.EpochAuthority = nil
	binding, err := rootinput.AdmissionProfileBindingV2(obs, &owned, c.Origin.Identity().Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", frontierrequester.ErrSettings, err)
	}
	return &bootstrapGuard{process: process, obs: obs, binding: binding, forward: forward, log: log, invalidated: ordinaryKnown}, nil
}

func (g *bootstrapGuard) EvidenceProfileBinding() [32]byte { return g.binding }

func (g *bootstrapGuard) BootstrapState() configuredprogress.BootstrapAdmissionState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return configuredprogress.BootstrapAdmissionState{BootstrapInvalidated: g.invalidated, UnsupportedSeen: g.unsupported, ProcessStopped: g.process.Err() != nil}
}

// NoteOrdinary latches bootstrap invalidation. The journal admission calls it as soon as it has
// authenticated an ordinary certificate, before that certificate is persisted: learning ordinary
// progress ends bootstrap eligibility whether or not the write succeeds.
func (g *bootstrapGuard) NoteOrdinary() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.invalidated = true
	g.mu.Unlock()
}

func (g *bootstrapGuard) Status() BootstrapGuardStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return BootstrapGuardStatus{Invalidated: g.invalidated, UnsupportedSeen: g.unsupported, FirstOrdinary: bytes.Clone(g.first), LatestOrdinary: bytes.Clone(g.latest)}
}

// AcknowledgePair reauthenticates evidence the requester collected under the fixed local trust and
// latches the invalidation before returning. Ordinary evidence is retained (first and latest
// only) and handed to the journal admission in the background; the hand-off needs neither the
// requester's context nor a successful write for the latch to hold.
func (g *bootstrapGuard) AcknowledgePair(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (bool, error) {
	if g == nil || uc == nil || tr == nil {
		return false, configuredprogress.ErrSettings
	}
	if g.process.Err() != nil {
		return false, configuredprogress.ErrAdmissionClosed
	}
	raw, err := pairBytes(uc, tr)
	if err != nil {
		return false, err
	}
	authCtx, cancel := context.WithTimeout(context.WithoutCancel(g.process), guardAuthTimeout)
	defer cancel()
	o, err := rootinput.AuthenticateObservationV2(authCtx, g.obs, uc, tr)
	if err != nil {
		if rootinput.IsUnsupportedObservationV2(err) {
			g.mu.Lock()
			g.invalidated, g.unsupported = true, true
			g.mu.Unlock()
			return true, err
		}
		return false, err
	}
	if o.Class() == bootstrapClass {
		return false, fmt.Errorf("%w: bootstrap evidence is not negative", configuredprogress.ErrConflict)
	}
	g.mu.Lock()
	g.invalidated = true
	if len(g.first) == 0 {
		g.first = bytes.Clone(raw)
	}
	g.latest = bytes.Clone(raw)
	g.queued = &pairValue{uc: o.Certificate(), tr: o.TechnicalRecord()}
	start := !g.forwarding && g.forward != nil
	if start {
		g.forwarding = true
	}
	g.mu.Unlock()
	if start {
		go g.drain()
	}
	return true, nil
}

// drain submits only the newest retained ordinary pair to the journal admission, one at a time.
// A failed submission is not retried here: the journal admission keeps its own pending retry for
// authenticated certificates, and the root feeds the same progress through the normal path.
func (g *bootstrapGuard) drain() {
	for {
		g.mu.Lock()
		next := g.queued
		g.queued = nil
		if next == nil || g.process.Err() != nil {
			g.forwarding = false
			g.mu.Unlock()
			return
		}
		g.mu.Unlock()
		if err := g.forward(g.process, next.uc, next.tr); err != nil && g.log != nil {
			g.log.WarnContext(g.process, "ordinary evidence found during bootstrap acquisition was not admitted", slog.String("error", err.Error()))
		}
	}
}

func pairBytes(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) ([]byte, error) {
	ub, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, err
	}
	tb, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, err
	}
	if len(ub)+len(tb) > configuredprogress.MaxPairBytes {
		return nil, configuredprogress.ErrBounds
	}
	return append(ub, tb...), nil
}
