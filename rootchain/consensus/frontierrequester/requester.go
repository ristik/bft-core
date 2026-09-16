// Package frontierrequester implements the inactive bounded acquisition of a
// root frontier quorum and committed cut. It performs no node registration,
// readiness transition, bootstrap activation, or durable permission write.
package frontierrequester

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	OverallDuration  = 30 * time.Second
	ExchangeDuration = 5 * time.Second
	ReceiptLifetime  = 5 * time.Minute
	MaxPeers         = 64
	MaxPasses        = 2
	PassBackoff      = 5 * time.Second
)

var (
	ErrSettings    = errors.New("frontier requester: invalid settings")
	ErrUnavailable = errors.New("frontier requester: evidence unavailable")
	ErrOrdinary    = errors.New("frontier requester: ordinary evidence observed")
	ErrUnsupported = errors.New("frontier requester: unsupported evidence observed")
	ErrExpired     = errors.New("frontier requester: acquisition expired")
	ErrInvalidated = errors.New("frontier requester: receipt invalidated")
)

type RootPeer struct {
	Author string
	PeerID peer.ID
}

type Config struct {
	Process   context.Context
	Profile   frontierclient.Profile
	Peers     []RootPeer
	Opener    frontiertransport.StreamOpener
	Admission *configuredprogress.AdmissionCoordinator
}

type clock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }
func (wallClock) Wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Receipt is an opaque process-local handle. Validity can only be checked
// against the Requester that issued it; copying does not detach it from live
// invalidation, replacement, caller cancellation, or expiry.
type Receipt struct {
	owner      *Requester
	generation uint64
	nonce      [32]byte
	binding    [32]byte
	pair       [32]byte
	cutRoot    [32]byte
	expires    time.Time
}

func (r Receipt) Valid() bool { return r.owner != nil && r.owner.Validate(r) == nil }

type Result struct {
	Receipt Receipt
	Err     error
}

// Resolution is owned evidence selected by a currently valid process-local
// receipt. CutRoot and CutRound identify the verified committed cut for
// diagnostics and continuity checks; they grant no portable authority.
type Resolution struct {
	UC       *types.UnicityCertificate
	TR       *certification.TechnicalRecord
	CutRoot  [32]byte
	CutRound uint64
}

type Requester struct {
	process   context.Context
	profile   frontierclient.Profile
	peers     []RootPeer
	opener    frontiertransport.StreamOpener
	admission *configuredprogress.AdmissionCoordinator
	clock     clock
	random    io.Reader

	mu         sync.Mutex
	running    bool
	generation uint64
	current    *frontierclient.Collector
	caller     context.Context
	receipt    Receipt
	invalid    bool
	handoffErr error
}

func New(cfg Config) (*Requester, error) {
	return newRequester(cfg, wallClock{}, rand.Reader)
}

func newRequester(cfg Config, clk clock, random io.Reader) (*Requester, error) {
	if cfg.Process == nil || cfg.Opener == nil || cfg.Admission == nil || clk == nil || random == nil || len(cfg.Peers) == 0 || len(cfg.Peers) > MaxPeers || cfg.Profile.TrustBase == nil {
		return nil, ErrSettings
	}
	callerObservation := rootinput.ObservationContextV2{NetworkID: cfg.Profile.NetworkID, PartitionID: cfg.Profile.PartitionID, ShardID: cfg.Profile.ShardID, ShardConfHash: cfg.Profile.FullShardConfHash, RootEpoch: cfg.Profile.RootEpoch}
	if _, err := rootinput.AdmissionProfileBindingV2(callerObservation, cfg.Profile.TrustBase, cfg.Profile.GenesisOriginIdentity); err != nil {
		return nil, fmt.Errorf("%w: profile bounds", ErrSettings)
	}
	profile, err := ownProfile(cfg.Profile)
	if err != nil {
		return nil, err
	}
	// A throwaway collector applies the complete fixed-profile validation.
	probeNonce := make([]byte, 32)
	probeNonce[31] = 1
	probe := profile
	probe.Nonce = probeNonce
	if _, err = frontierclient.NewCollector(probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSettings, err)
	}
	observation := rootinput.ObservationContextV2{NetworkID: profile.NetworkID, PartitionID: profile.PartitionID, ShardID: profile.ShardID, ShardConfHash: bytes.Clone(profile.FullShardConfHash), RootEpoch: profile.RootEpoch}
	binding, err := rootinput.AdmissionProfileBindingV2(observation, profile.TrustBase, profile.GenesisOriginIdentity)
	if err != nil || binding != cfg.Admission.EvidenceProfileBinding() {
		return nil, fmt.Errorf("%w: admission profile mismatch", ErrSettings)
	}
	authors := make(map[string]struct{}, len(profile.TrustBase.RootNodes))
	for _, n := range profile.TrustBase.RootNodes {
		authors[n.NodeID] = struct{}{}
	}
	seenAuthors, seenPeers := make(map[string]struct{}, len(cfg.Peers)), make(map[peer.ID]struct{}, len(cfg.Peers))
	peers := make([]RootPeer, len(cfg.Peers))
	for i, p := range cfg.Peers {
		if p.Author == "" || len(p.Author) > frontiercodec.MaxAuthor || p.PeerID == "" || len(p.PeerID) > frontiercodec.MaxAuthor {
			return nil, ErrSettings
		}
		if _, ok := authors[p.Author]; !ok {
			return nil, ErrSettings
		}
		if _, ok := seenAuthors[p.Author]; ok {
			return nil, ErrSettings
		}
		if _, ok := seenPeers[p.PeerID]; ok {
			return nil, ErrSettings
		}
		seenAuthors[p.Author], seenPeers[p.PeerID] = struct{}{}, struct{}{}
		peers[i] = p
	}
	if uint64(len(peers)) < profile.TrustBase.QuorumThreshold {
		return nil, ErrSettings
	}
	return &Requester{process: cfg.Process, profile: profile, peers: peers, opener: cfg.Opener, admission: cfg.Admission, clock: clk, random: random}, nil
}

func ownProfile(p frontierclient.Profile) (frontierclient.Profile, error) {
	b, err := types.Cbor.Marshal(p.TrustBase)
	if err != nil {
		return frontierclient.Profile{}, ErrSettings
	}
	var trust types.RootTrustBaseV1
	if err = types.Cbor.Unmarshal(b, &trust); err != nil {
		return frontierclient.Profile{}, ErrSettings
	}
	p.TrustBase = &trust
	p.FullShardConfHash = bytes.Clone(p.FullShardConfHash)
	p.GenesisOriginIdentity = bytes.Clone(p.GenesisOriginIdentity)
	p.Nonce = nil
	return p, nil
}

type exchangeResult struct {
	peer RootPeer
	res  frontiertransport.ExchangeResult
}

func (r *Requester) Acquire(ctx context.Context) Result {
	if ctx == nil {
		return Result{Err: ErrSettings}
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return Result{Err: ErrUnavailable}
	}
	if r.admission == nil || !r.admission.BootstrapState().Allowed() {
		r.mu.Unlock()
		return Result{Err: ErrInvalidated}
	}
	r.running = true
	r.generation++
	generation := r.generation
	r.current, r.receipt, r.invalid, r.handoffErr, r.caller = nil, Receipt{}, false, nil, ctx
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.running = false; r.mu.Unlock() }()

	// The episode includes nonce generation and all local collector setup.
	started := r.clock.Now()
	var nonce [32]byte
	if _, err := io.ReadFull(r.random, nonce[:]); err != nil {
		return Result{Err: err}
	}
	profile := r.profile
	profile.Nonce = nonce[:]
	collector, err := frontierclient.NewCollector(profile)
	if err != nil {
		return Result{Err: err}
	}
	r.mu.Lock()
	r.current = collector
	r.mu.Unlock()
	budget, err := frontiertransport.NewReceiveBudget(frontiertransport.MaxReceiveBudget)
	if err != nil {
		return Result{Err: err}
	}
	remaining := OverallDuration - r.clock.Now().Sub(started)
	if remaining <= 0 {
		return Result{Err: ErrExpired}
	}
	episode, cancel := context.WithTimeout(ctx, remaining)
	stopProcess := context.AfterFunc(r.process, cancel)
	defer func() { stopProcess(); cancel() }()
	requestContext := frontiercodec.Context{NetworkID: profile.NetworkID, PartitionID: profile.PartitionID, CanonicalShardBytes: profile.ShardID.Bytes(), FullShardConfHash: bytes.Clone(profile.FullShardConfHash), RootEpoch: profile.RootEpoch, GenesisOriginIdentity: bytes.Clone(profile.GenesisOriginIdentity)}
	frontierReq := frontiertransport.FrontierRequest{Version: frontiercodec.Version, Context: requestContext, Nonce: nonce[:]}

	for pass := 0; pass < MaxPasses; pass++ {
		r.runFrontierBatch(episode, frontierReq, budget, collector)
		if r.hasNegative(collector) {
			return Result{Err: r.negativeError(collector)}
		}
		if collector.Snapshot().Candidate().Valid() {
			break
		}
		if pass+1 < MaxPasses {
			if err := r.clock.Wait(episode, PassBackoff); err != nil {
				break
			}
		}
	}
	snapshot := collector.Snapshot()
	if !snapshot.Candidate().Valid() {
		return Result{Err: preferEpisode(episode, budget, ErrUnavailable)}
	}
	candidate := snapshot.Candidate()
	binding := collector.AcquisitionBinding()
	cutReq := frontiertransport.CutRequest{Version: frontiercodec.Version, Context: requestContext, Nonce: nonce[:], AcquisitionBinding: binding[:], Floor: candidate.Floor()}
	var lastCutErr error
	for pass := 0; pass < MaxPasses; pass++ {
		lastCutErr = r.runCuts(episode, cutReq, budget, collector)
		if r.hasNegative(collector) {
			return Result{Err: r.negativeError(collector)}
		}
		if collector.Snapshot().VerifiedCut().Valid() {
			break
		}
		if pass+1 < MaxPasses {
			if err := r.clock.Wait(episode, PassBackoff); err != nil {
				break
			}
		}
	}
	snapshot = collector.Snapshot()
	cut := snapshot.VerifiedCut()
	if contextExpired(episode) || contextExpired(r.process) || contextExpired(ctx) {
		return Result{Err: ErrExpired}
	}
	if snapshot.Exhausted() || !snapshot.Candidate().Valid() || !cut.Valid() || cut.AcquisitionBinding() != binding || cut.PairIdentity() != snapshot.Candidate().PairIdentity() {
		fallback := error(ErrUnavailable)
		if lastCutErr != nil {
			fallback = fmt.Errorf("%w: cut: %v", ErrUnavailable, lastCutErr)
		}
		return Result{Err: preferEpisode(episode, budget, fallback)}
	}
	var cutRoot [32]byte
	copy(cutRoot[:], cut.RootHash())
	receipt := Receipt{owner: r, generation: generation, nonce: nonce, binding: binding, pair: cut.PairIdentity(), cutRoot: cutRoot, expires: started.Add(ReceiptLifetime)}
	r.mu.Lock()
	if r.generation != generation || r.invalid || r.current != collector || contextExpired(r.process) || contextExpired(ctx) || contextExpired(episode) || !r.clock.Now().Before(receipt.expires) || !r.admission.BootstrapState().Allowed() {
		r.mu.Unlock()
		return Result{Err: ErrInvalidated}
	}
	r.receipt = receipt
	r.mu.Unlock()
	return Result{Receipt: receipt}
}

func (r *Requester) runCuts(ctx context.Context, request frontiertransport.CutRequest, budget *frontiertransport.ReceiveBudget, collector *frontierclient.Collector) error {
	// A cut can be large. Query providers serially until one verifies so several
	// concurrent declared-body reservations cannot consume the shared 1-MiB cap
	// before the first proof is authenticated.
	var lastErr error
	for _, p := range r.peers {
		result := frontiertransport.ExchangeCut(ctx, r.opener, p.PeerID, request, budget, ExchangeDuration)
		if result.Complete {
			_, lastErr = collector.AddCut(result.Raw)
			r.acknowledgeNegatives(collector)
		} else {
			lastErr = result.Err
		}
		snapshot := collector.Snapshot()
		if snapshot.VerifiedCut().Valid() || snapshot.Ordinary() || snapshot.Unsupported() || snapshot.Exhausted() {
			return lastErr
		}
	}
	return lastErr
}

func (r *Requester) runFrontierBatch(ctx context.Context, request frontiertransport.FrontierRequest, budget *frontiertransport.ReceiveBudget, collector *frontierclient.Collector) {
	jobs := make(chan RootPeer)
	results := make(chan exchangeResult, len(r.peers))
	workers := 4
	if len(r.peers) < workers {
		workers = len(r.peers)
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				result := frontiertransport.ExchangeFrontier(ctx, r.opener, p.PeerID, request, budget, ExchangeDuration)
				results <- exchangeResult{peer: p, res: result}
			}
		}()
	}
	go func() {
		for _, p := range r.peers {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	for result := range results {
		if result.res.Complete {
			collector.AddFrom(result.res.Raw, result.peer.Author)
			r.acknowledgeNegatives(collector)
		}
	}
}

func (r *Requester) acknowledgeNegatives(c *frontierclient.Collector) {
	s := c.Snapshot()
	if !s.Ordinary() && !s.Unsupported() {
		return
	}
	r.mu.Lock()
	r.invalid = true
	r.receipt = Receipt{}
	r.mu.Unlock()
	for _, evidence := range []frontierclient.PairEvidence{s.FirstOrdinary(), s.LatestOrdinaryArrival(), s.FirstUnsupported(), s.LatestUnsupportedArrival()} {
		if !evidence.Valid() {
			continue
		}
		uc, tr, err := evidence.CertificateAndTechnical()
		if err != nil {
			r.mu.Lock()
			r.handoffErr = err
			r.mu.Unlock()
			continue
		}
		retained, ackErr := r.admission.AcknowledgePair(uc, tr)
		if !retained {
			r.mu.Lock()
			r.handoffErr = ackErr
			r.mu.Unlock()
		}
	}
}

func (r *Requester) hasNegative(c *frontierclient.Collector) bool {
	s := c.Snapshot()
	return s.Ordinary() || s.Unsupported()
}

func (r *Requester) negativeError(c *frontierclient.Collector) error {
	r.mu.Lock()
	handoffErr := r.handoffErr
	r.mu.Unlock()
	if handoffErr != nil {
		return fmt.Errorf("frontier requester: negative evidence handoff: %w", handoffErr)
	}
	s := c.Snapshot()
	if s.Ordinary() {
		return ErrOrdinary
	}
	return ErrUnsupported
}

func preferEpisode(ctx context.Context, budget *frontiertransport.ReceiveBudget, fallback error) error {
	if contextExpired(ctx) {
		return ErrExpired
	}
	s := budget.Snapshot()
	if s.Committed >= s.Limit {
		return frontiertransport.ErrBudget
	}
	return fallback
}

func contextExpired(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

// Validate rechecks the live process/generation/caller and collector state.
// Old Receipt copies cannot bypass later invalidation or replacement.
func (r *Requester) Validate(receipt Receipt) error {
	if r == nil || receipt.owner != r {
		return ErrInvalidated
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.validateLocked(receipt)
}

func (r *Requester) validateLocked(receipt Receipt) error {
	if r.receipt.owner != r || receipt.generation != r.generation || receipt.generation != r.receipt.generation || receipt.nonce != r.receipt.nonce || receipt.binding != r.receipt.binding || receipt.pair != r.receipt.pair || receipt.cutRoot != r.receipt.cutRoot || r.invalid || r.handoffErr != nil || contextExpired(r.process) || contextExpired(r.caller) || !r.clock.Now().Before(receipt.expires) || !r.admission.BootstrapState().Allowed() {
		return ErrInvalidated
	}
	s := r.current.Snapshot()
	if s.Exhausted() || s.Ordinary() || s.Unsupported() || !s.Candidate().Valid() || !s.VerifiedCut().Valid() || s.Candidate().AcquisitionBinding() != receipt.binding || s.VerifiedCut().PairIdentity() != receipt.pair {
		return ErrInvalidated
	}
	return nil
}

// Resolve returns owned genuine assignment evidence only while receipt remains
// valid in this Requester. Mutating the result cannot change retained evidence.
func (r *Requester) Resolve(receipt Receipt) (Resolution, error) {
	if r == nil || receipt.owner != r {
		return Resolution{}, ErrInvalidated
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.validateLocked(receipt); err != nil {
		return Resolution{}, err
	}
	s := r.current.Snapshot()
	var pair frontiercodec.Pair
	if err := types.Cbor.Unmarshal(s.Candidate().CanonicalPair(), &pair); err != nil || pair.UC == nil || pair.TR == nil {
		return Resolution{}, ErrInvalidated
	}
	// A marshal round-trip ensures no decoded slice aliases the collector's
	// retained canonical bytes.
	owned, err := types.Cbor.Marshal(pair)
	if err != nil {
		return Resolution{}, ErrInvalidated
	}
	if err = types.Cbor.Unmarshal(owned, &pair); err != nil {
		return Resolution{}, ErrInvalidated
	}
	cut := s.VerifiedCut()
	return Resolution{UC: pair.UC, TR: pair.TR, CutRoot: receipt.cutRoot, CutRound: cut.CommittedRound()}, nil
}
