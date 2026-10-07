package engineapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// The companion-boundary refusals, each named so a caller can tell one from another (F2c §8). None is
// a generic failure and none is a fallback: a block whose companion is absent, malformed, bound to
// different bytes, or unauthenticated against this node's own configuration is refused, never routed
// to the stock V3 path.
var (
	// ErrCompanionMissing means the proposal envelope carried no seal companion at all.
	ErrCompanionMissing = errors.New("engineapi: block has no seal companion")
	// ErrCompanionWitnesses means the witness list is not the required two canonical entries.
	ErrCompanionWitnesses = errors.New("engineapi: seal companion witnesses are not the required [certificate, technical record] pair")
	// ErrCompanionBinding means the leader's published rootInput is not the bytes this node derives.
	ErrCompanionBinding = errors.New("engineapi: seal companion rootInput does not match the canonical derivation")
	// ErrCompanionCommitment means the block header does not commit to the derived input.
	ErrCompanionCommitment = errors.New("engineapi: block extraData does not match the derived commitment")
	// ErrCompanionUnauthenticated is retained for callers of the former v1 adapter.
	ErrCompanionUnauthenticated = errors.New("engineapi: seal companion failed VerifyCompanionWitnesses")
	// ErrParentWitnessUnavailable means the exact certified parent's local RPC proof is not available.
	ErrParentWitnessUnavailable = errors.New("engineapi: v2 parent registry witness unavailable")
)

// Adapter implements shardnode.Executor by driving reth over the Engine
// API. It is the only place in this package that touches shardnode types —
// everything else (types.go, client.go, params.go, codec.go) is pure
// Engine-API-facing machinery Adapter composes.
type Adapter struct {
	engine       *Client
	eth          *EthClient
	log          *slog.Logger
	feeCollector [20]byte
	sealPinMu    sync.Mutex
	sealPinned   bool
	sealID       [32]byte

	// verifier is the derivation context the seal build path authenticates a certificate against.
	// Nil for an adapter that only runs the non-deriving checks (the doctor command); Build refuses
	// rather than deriving against an invented context. See VerifierContext and F2c §3.
	verifier            *VerifierContext
	pair                *PairConfig // nil: no pair binding is sent (an execution client without ureth#52)
	pairPinsOK          atomic.Bool
	transitionMu        sync.RWMutex
	installedTransition []byte

	mu            sync.Mutex
	pending       map[shardnode.BuildID]buildContext
	parentWitness *ParentWitnessSource
	witnessClosed bool
}

// buildContext is what Build remembers so Seal — called later, with only a
// BuildID — can (a) ask reth for the right payload, (b) construct a correct
// quiet-round echo without re-deriving the parent from scratch, and (c) fill
// the seal companion's witnesses from the authorization this round was built
// on rather than from anything ureth returns.
type buildContext struct {
	payloadID    data
	b1Update     []byte
	b1Input      []byte
	b1Commitment [32]byte
	parent       shardnode.BlockRef
	// certificate and technicalRecord are the authenticated, owned copies
	// rootinput.Derive produced. Seal encodes exactly these as the two companion
	// witnesses — the certificate the block binds and the record it commits to.
	certificate     *types.UnicityCertificate
	technicalRecord *certification.TechnicalRecord
}

type Config struct {
	EngineURL    string // authenticated engine_* endpoint, e.g. http://localhost:8551
	EthURL       string // plain eth_* endpoint, e.g. http://localhost:8545
	Secret       Secret
	FeeCollector [20]byte // configured execution fee recipient; must match the client's fee collector

	// Verifier is the derivation context Adapter.Build authenticates the authorizing certificate
	// against. It is required to build through the seal siblings and is deliberately nil for an
	// adapter that only runs the non-deriving checks: where the derivation context comes from is the
	// node's own configuration, never the certificate, so Build refuses without it rather than
	// inferring one (F2c §3).
	Verifier *VerifierContext

	// Pair enables the paired-execution binding (pairbinding.go). Nil sends none.
	Pair *PairConfig
}

// VerifierContext holds the verifier-owned identity and trust pins for v2 derivation.
// Round and the certified parent come from RoundParams on every call.
type VerifierContext struct {
	// B1 is configured only by inactive acceptance fixtures until PR4.
	B1             *b1paired.Config
	NetworkID      types.NetworkID
	PartitionID    types.PartitionID
	ShardID        types.ShardID
	ShardConfHash  []byte
	RootEpoch      uint64
	TrustBases     rootinput.TrustBases
	EpochAuthority rootinput.RootEpochAuthority
	// Transition is the canonical acknowledgement derived from an installed
	// profile-2 anchor and delivered through the authenticated local link.
	Transition   []byte
	transitionMu sync.RWMutex
	transitions  map[uint64]handoff.EVMTransition
	// confForEpoch is the node's installed shard configuration for a shard epoch (SetConfForEpoch). With it set, a certificate
	// must commit to exactly the configuration installed for the shard epoch its technical record names, so authenticating one
	// certificate costs one lookup however many assignments were installed before it. Without it only the pinned ShardConfHash
	// is accepted.
	confForEpoch func(shardEpoch uint64) ([]byte, bool)
	Cursor       SealRegistryCursor // retained for callers of the former v1 API; v2 reads the verified parent snapshot

	// GenesisOrigin is the checked execution genesis this node was configured with, and
	// BootstrapSnapshot is the verified snapshot of its own block 0. Both are verifier-owned: they come
	// from the finalized genesis artifact validated against this node's own full shard configuration and
	// pinned artifact, never from a peer, a certificate or the executor. The zero value means no
	// origin was configured; v2 derivation refuses it.
	GenesisOrigin     registrygenesis.GenesisOrigin
	BootstrapSnapshot registryproof.Snapshot
}

// InstallHandoffTransition retains a locally verified one-step transition for the
// first EVM block whose parent still carries the predecessor root epoch. Steps are
// keyed by their old root epoch; a supersession folds consecutive steps when the
// acknowledgement is finally built.
func (v *VerifierContext) InstallHandoffTransition(bundle handoffdelivery.Bundle, checked handoffdelivery.Verified) error {
	if v == nil || bundle.Proof.Record.Epoch == ^uint64(0) || bundle.Body.Epoch != bundle.Proof.Record.Epoch+1 || checked.Genesis.Epoch != bundle.Body.Epoch {
		return handoff.ErrBoundary
	}
	// The old committee commits the successor assignment hash. The snapshot
	// carries the shard's last assignment; an assignment handoff advances it by one
	// shard round and epoch, which the successor certificate re-authenticates.
	if checked.Shard.TR == nil {
		return handoff.ErrBoundary
	}
	step, err := handoffdelivery.AssignmentStepOf(bundle, checked)
	if err != nil {
		return handoff.ErrBoundary
	}
	t, err := handoff.BuildTransition(bundle.Proof.Record, bundle.Proof.Control.FrozenParent, bundle.Body.Epoch,
		checked.Genesis.ID(), checked.Shard.IRTR, step)
	if err != nil {
		return handoff.ErrBoundary
	}
	v.transitionMu.Lock()
	defer v.transitionMu.Unlock()
	if v.transitions == nil {
		v.transitions = make(map[uint64]handoff.EVMTransition)
	}
	if old, ok := v.transitions[t.OldRootEpoch]; ok && old != t {
		return handoff.ErrSuccessor
	}
	v.transitions[t.OldRootEpoch] = t
	return nil
}

// SetConfForEpoch installs the per-epoch shard configuration lookup. It is set once, before the node runs, from the same set the
// certificate admission uses, so the adapter and the admission cannot disagree about which configuration a shard epoch carries.
func (v *VerifierContext) SetConfForEpoch(f func(shardEpoch uint64) ([]byte, bool)) {
	v.transitionMu.Lock()
	defer v.transitionMu.Unlock()
	v.confForEpoch = f
}

func (v *VerifierContext) installedConfForEpoch() func(uint64) ([]byte, bool) {
	v.transitionMu.RLock()
	defer v.transitionMu.RUnlock()
	return v.confForEpoch
}

// ErrAssignmentSpanUnavailable reports that the committed handoff steps between the
// registry's root epoch and the authenticated observation are not all retained. It
// is a typed unavailable, never a bare epoch jump: the caller resumes catch-up.
var ErrAssignmentSpanUnavailable = errors.New("engineapi: committed EVM assignment span is not fully retained")

func (v *VerifierContext) transitionFor(oldEpoch, newEpoch uint64) ([]byte, error) {
	v.transitionMu.RLock()
	if newEpoch > oldEpoch && newEpoch-oldEpoch <= handoff.MaxSupersessionSpan {
		steps := make([]handoff.EVMTransition, 0, newEpoch-oldEpoch)
		complete := true
		for e := oldEpoch; e < newEpoch; e++ {
			step, ok := v.transitions[e]
			if !ok || step.NewRootEpoch != e+1 {
				complete = false
				break
			}
			steps = append(steps, step)
		}
		v.transitionMu.RUnlock()
		if complete {
			folded, err := handoff.FoldTransitions(steps)
			if err != nil {
				return nil, errors.Join(rootinput.ErrV2Context, err)
			}
			return folded.Encode()
		}
		if v.EpochAuthority != nil {
			return nil, fmt.Errorf("%w: %w", ErrAssignmentSpanUnavailable, rootinput.ErrV2Context)
		}
	} else {
		v.transitionMu.RUnlock()
	}
	if v.EpochAuthority != nil {
		return nil, rootinput.ErrV2Context
	}
	if len(v.Transition) == 0 {
		return nil, rootinput.ErrV2Context
	}
	t, err := handoff.DecodeEVMTransition(v.Transition)
	if err != nil || t.OldRootEpoch != oldEpoch || t.NewRootEpoch != newEpoch {
		return nil, rootinput.ErrV2Context
	}
	return bytes.Clone(v.Transition), nil
}

type historicalReplayKey struct{}

// HistoricalContext scopes per-UC-epoch authentication to replay and peer
// recovery calls. A live build never inherits historical authority.
func (a *Adapter) HistoricalContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, historicalReplayKey{}, true)
}

func NewAdapter(cfg Config, log *slog.Logger) *Adapter {
	a := &Adapter{
		engine:       NewClient(cfg.EngineURL, cfg.Secret),
		eth:          NewEthClient(cfg.EthURL),
		log:          log,
		feeCollector: cfg.FeeCollector,
		verifier:     cfg.Verifier,
		pair:         cfg.Pair,
		pending:      make(map[shardnode.BuildID]buildContext),
	}
	return a
}

// InstallEpochTransition advances the verifier-owned acknowledgement after the
// shard has checked the native handoff bundle. Replaying the same transition
// after restart is idempotent; a skipped or conflicting transition is refused.
func (a *Adapter) InstallEpochTransition(raw []byte) error {
	transition, err := handoff.DecodeEVMTransition(raw)
	if err != nil || a.verifier == nil {
		return rootinput.ErrV2Context
	}
	a.transitionMu.Lock()
	defer a.transitionMu.Unlock()
	current := a.verifier.RootEpoch
	previous := a.installedTransition
	if len(previous) == 0 {
		previous = a.verifier.Transition
	}
	if len(previous) != 0 {
		old, err := handoff.DecodeEVMTransition(previous)
		if err != nil {
			return rootinput.ErrV2Context
		}
		if old.NewRootEpoch == transition.NewRootEpoch && bytes.Equal(previous, raw) {
			return nil
		}
		current = old.NewRootEpoch
	}
	if transition.OldRootEpoch != current {
		return rootinput.ErrV2Context
	}
	a.installedTransition = bytes.Clone(raw)
	return nil
}

// RequireSealCapabilities makes the three engine_*WithSealV1 siblings part of the startup capability
// check, while dropping the stock newPayloadV3 requirement for a seal-path deployment. The
// shard-node executor selects this at startup; generic non-seal clients retain the stock V3 set.
func (a *Adapter) RequireSealCapabilities() { a.engine.RequireSealCapabilities() }

// CheckCapabilities is the startup check from
// docs/adr/0001-executor-boundary.md decision 3: it refuses to start
// against a client that does not offer every method this adapter calls on its selected path.
//
// What it establishes is narrow, and was previously overstated here.
// engine_exchangeCapabilities reports what a client BUILD supports, not
// what the loaded chain spec has SCHEDULED. A client whose spec activates
// Prague at genesis offers the V3 set too, and passes this check. Nor does
// generating a chain spec with `ubft engine-api genesis` establish
// anything about the remote client: producing the intended file locally is
// not evidence that this endpoint loaded it, and two specs with identical
// genesis state and identical current capabilities can still schedule
// different future forks.
//
// So the fork schedule is verified separately, by CheckExecutionProfile
// reading the standard eth_config (EIP-7910) — see profile.go. An earlier
// revision of this comment called it an operator constraint no startup
// check could verify; the Engine API offers no such read, but the eth_*
// namespace does. What this check buys is catching the wrong URL, the
// wrong JWT and a clearly incompatible client build before the node can
// vote. Call it once, before Run.
func (a *Adapter) CheckCapabilities(ctx context.Context) error {
	missing, err := a.engine.ExchangeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("engineapi: checking capabilities: %w", err)
	}
	if len(missing) > 0 {
		return fmt.Errorf("engineapi: execution client is missing required capabilities: %v", missing)
	}
	return nil
}

// CheckChainID verifies the execution client is running the chain this shard is
// configured for, by comparing eth_chainId against the shard conf's chain_id
// partition param — over BOTH configured connections.
//
// Why both. --engine-url and --eth-url are separate flags, so nothing structurally
// stops an operator from pointing them at two different execution clients. The Engine
// connection is the one that decides what this node votes for: Build, Seal and Commit
// all go over it. The plain connection only answers header lookups. Checking the plain
// endpoint alone therefore verifies the chain of a client that does not produce our
// blocks. Asking the same question on the authenticated Engine port needs no new Engine
// method and no client divergence — the Engine API specification's "underlying protocol"
// section requires eth_chainId there, and the pinned client serves it (see Client.ChainID).
//
// Requiring both to equal the configured value also makes them equal to each other, so a
// mispaired pair of clients on different chains is refused here rather than surviving to
// produce blocks nobody certifies.
//
// Scope, stated because it is easy to overclaim. Agreement on chain id establishes
// agreement on chain id. It does NOT establish that the two URLs address the same client
// PROCESS — two clients on the same chain agree on this value and on genesis (see
// CheckGenesisHash), and only diverge once they build different blocks. It also says
// nothing about future fork activations. What it does rule out is the mispairing that
// actually happens in deployment: an endpoint left pointing at another shard's client, or
// at a client started from a different genesis.
func (a *Adapter) CheckChainID(ctx context.Context, want uint64) error {
	engineID, err := a.engine.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("engineapi: reading chain id over the Engine connection: %w", err)
	}
	if engineID != want {
		return fmt.Errorf("engineapi: execution client reports chainId=%d, shard conf says %d", engineID, want)
	}
	ethID, err := a.eth.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("engineapi: reading chain id over the plain connection: %w", err)
	}
	if ethID != want {
		return fmt.Errorf("engineapi: --eth-url reports chainId=%d but --engine-url reports %d "+
			"(shard conf says %d): the two URLs address different execution clients", ethID, engineID, want)
	}
	return nil
}

// CheckGenesisHash verifies the execution client's block 0 is the one this deployment was
// configured for — again over both connections, for the reasons on CheckChainID.
//
// Chain id does not establish this: two chains can share a chain id and differ in allocation,
// fork schedule or any other genesis field, and `ubft engine-api genesis` derives the chain spec
// from the shard conf but not the allocation, so a same-chainId/different-genesis client is a real
// deployment mistake rather than a hypothetical.
//
// `want` must be operator-configured. Deriving it from the client under test would compare a value
// with itself and prove nothing (issue #89 item 2).
//
// Scope: this binds the genesis BLOCK on both connections. It does not establish same-process
// identity, and it does not establish agreement on any fork activation after genesis — a matching
// genesis hash says nothing about a fork scheduled by timestamp later in the chain's life, because
// a fork that has not activated changes no genesis header field. CheckExecutionProfile binds that.
func (a *Adapter) CheckGenesisHash(ctx context.Context, want shardnode.Hash) error {
	if len(want) == 0 {
		return fmt.Errorf("engineapi: no expected genesis hash configured")
	}
	engineGenesis, err := a.engine.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return fmt.Errorf("engineapi: reading genesis block over the Engine connection: %w", err)
	}
	if !bytes.Equal(engineGenesis.Hash[:], want) {
		return fmt.Errorf("engineapi: execution client genesis is %x, configured expectation is %x",
			engineGenesis.Hash[:], want)
	}
	ethGenesis, err := a.eth.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return fmt.Errorf("engineapi: reading genesis block over the plain connection: %w", err)
	}
	if !bytes.Equal(ethGenesis.Hash[:], engineGenesis.Hash[:]) {
		return fmt.Errorf("engineapi: --eth-url genesis is %x but --engine-url genesis is %x: "+
			"the two URLs address different execution clients", ethGenesis.Hash[:], engineGenesis.Hash[:])
	}
	return nil
}

// CheckEndpointsPaired compares the genesis block the two configured URLs report, without
// needing an operator-supplied expectation, and returns the hash they agreed on.
//
// CheckChainID and CheckGenesisHash already cross-compare, but the first is coarse (two
// clients on one chain id agree) and the second only runs when --expected-genesis-hash is
// set. This makes the pairing check unconditional: it costs one extra request and catches
// the same-chain-id/different-genesis mispairing on a deployment that has not configured an
// expected hash. It is strictly a pairing check — it asserts nothing about whether that
// shared genesis is the RIGHT one, which is what CheckGenesisHash is for.
//
// It returns the agreed hash so a caller that wants to REPORT the genesis (doctor does) can
// use the value this check actually validated rather than issuing another request. That
// matters for the same reason #89 item 4 did: two requests can disagree, and a report built
// from a second query can describe a state the check never saw.
func (a *Adapter) CheckEndpointsPaired(ctx context.Context) (shardnode.Hash, error) {
	engineGenesis, err := a.engine.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return nil, fmt.Errorf("engineapi: reading genesis block over the Engine connection: %w", err)
	}
	ethGenesis, err := a.eth.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return nil, fmt.Errorf("engineapi: reading genesis block over the plain connection: %w", err)
	}
	if !bytes.Equal(ethGenesis.Hash[:], engineGenesis.Hash[:]) {
		return nil, fmt.Errorf("engineapi: --eth-url genesis is %x but --engine-url genesis is %x: "+
			"the two URLs address different execution clients", ethGenesis.Hash[:], engineGenesis.Hash[:])
	}
	return shardnode.Hash(engineGenesis.Hash[:]), nil
}

func (a *Adapter) Head(ctx context.Context) (shardnode.BlockRef, error) {
	h, err := a.eth.GetBlockByNumber(ctx, "latest")
	if err != nil {
		return shardnode.BlockRef{}, fmt.Errorf("engineapi: reading head: %w", err)
	}
	return shardnode.BlockRef{
		Number:    uint64(h.Number),
		Hash:      shardnode.Hash(h.Hash[:]),
		StateRoot: shardnode.Hash(h.StateRoot[:]),
	}, nil
}

// Finalized reports the executor's finalized identity. Recovery must check it
// before moving forkchoice; Commit alone would set finalized to the new head.
func (a *Adapter) Finalized(ctx context.Context) (shardnode.BlockRef, error) {
	h, err := a.eth.GetBlockByNumber(ctx, "finalized")
	if err != nil {
		// A fresh ureth datadir has no finalized forkchoice marker until its
		// first Engine call. Genesis is the sole safe implicit finality value.
		// Never infer finality from a non-genesis latest head.
		genesis, genesisErr := a.eth.GetBlockByNumber(ctx, "0x0")
		latest, latestErr := a.eth.GetBlockByNumber(ctx, "latest")
		if genesisErr == nil && latestErr == nil && latest.Hash == genesis.Hash && latest.Number == 0 {
			return shardnode.BlockRef{Number: 0, Hash: shardnode.Hash(genesis.Hash[:]), StateRoot: shardnode.Hash(genesis.StateRoot[:])}, nil
		}
		return shardnode.BlockRef{}, fmt.Errorf("engineapi: reading finalized head: %w", err)
	}
	return shardnode.BlockRef{Number: uint64(h.Number), Hash: shardnode.Hash(h.Hash[:]), StateRoot: shardnode.Hash(h.StateRoot[:])}, nil
}

// Header returns identity and parent linkage for bounded ancestry checks.
func (a *Adapter) Header(ctx context.Context, hash shardnode.Hash) (shardnode.BlockRef, shardnode.Hash, error) {
	h32, err := toData32(hash)
	if err != nil {
		return shardnode.BlockRef{}, nil, err
	}
	h, err := a.eth.GetBlockByHash(ctx, h32)
	if err != nil {
		return shardnode.BlockRef{}, nil, fmt.Errorf("engineapi: reading header %x: %w", hash, err)
	}
	return shardnode.BlockRef{Number: uint64(h.Number), Hash: shardnode.Hash(h.Hash[:]), StateRoot: shardnode.Hash(h.StateRoot[:])}, shardnode.Hash(h.ParentHash[:]), nil
}

// GetBlockReceipts captures the complete consensus receipt list from the
// execution RPC for an exact certified hash.
func (a *Adapter) GetBlockReceipts(ctx context.Context, hash [32]byte) ([][]byte, error) {
	return a.eth.GetBlockReceipts(ctx, data32(hash))
}

// RecoveryForkchoice advances only the head. The proven, compatible finalized
// identity stays in place until the complete certified target can be committed.
func (a *Adapter) RecoveryForkchoice(ctx context.Context, head, finalized shardnode.Hash) (shardnode.Status, error) {
	h, err := toData32(head)
	if err != nil {
		return shardnode.StatusInvalid, err
	}
	f, err := toData32(finalized)
	if err != nil {
		return shardnode.StatusInvalid, err
	}
	resp, err := a.engine.ForkchoiceUpdatedV3(ctx, ForkchoiceStateV1{HeadBlockHash: h, SafeBlockHash: f, FinalizedBlockHash: f}, nil)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: recovery forkchoice: %w", err)
	}
	return toStatus(resp.PayloadStatus.Status), nil
}

// CheckParentWitness checks the exact certified head before Build is enabled.
func (a *Adapter) CheckParentWitness(ctx context.Context, parent shardnode.BlockRef) error {
	if parent.Number == 0 {
		return nil
	}
	a.mu.Lock()
	source := a.parentWitness
	a.mu.Unlock()
	if source == nil {
		return ErrParentWitnessUnavailable
	}
	_, err := source.Acquire(ctx, parent)
	return err
}

// GenesisBlock answers from the client's chain configuration: block number zero, which is fixed by
// the chain spec this client was started with and does not move with what it has committed. That is
// what makes it usable as an execution identity — see shardnode.Executor.GenesisBlock, and note that
// `ubft shard-node run` separately refuses to start when this hash does not match a configured
// --expected-genesis-hash, so the value the round loop compares against is the configured one.
func (a *Adapter) GenesisBlock(ctx context.Context) (shardnode.BlockRef, error) {
	h, err := a.eth.GetBlockByNumber(ctx, "0x0")
	if err != nil {
		return shardnode.BlockRef{}, fmt.Errorf("engineapi: reading genesis block: %w", err)
	}
	return shardnode.BlockRef{
		Number:    uint64(h.Number),
		Hash:      shardnode.Hash(h.Hash[:]),
		StateRoot: shardnode.Hash(h.StateRoot[:]),
	}, nil
}

// Commit issues a forkchoiceUpdated pinning head/safe/finalized to hash —
// see ForkchoiceStateV1's doc comment for why all three are always the same
// value here. This is also round.go's crash-recovery retry target (see
// shardnode/round.go's reconcile and docs/adr/0001-executor-boundary.md
// decision 2): calling it with a hash reth was never told to build is safe
// and simply reports SYNCING if reth doesn't have that block, which is
// exactly the outcome the recovery path needs to distinguish "recovered"
// from "genuinely gone."
func (a *Adapter) Commit(ctx context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	h32, err := toData32(hash)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: commit: %w", err)
	}
	state := ForkchoiceStateV1{HeadBlockHash: h32, SafeBlockHash: h32, FinalizedBlockHash: h32}
	resp, err := a.engine.ForkchoiceUpdatedV3(ctx, state, nil)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: forkchoiceUpdated (commit): %w", err)
	}
	return toStatus(resp.PayloadStatus.Status), nil
}

// deriveV2 authenticates the bound observation before reading a parent witness.
// The parent subject is always the certified BlockRef supplied by the round.
func (a *Adapter) deriveV2(ctx context.Context, p shardnode.RoundParams, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (rootinput.ResultV2, error) {
	rootEpoch := a.verifier.RootEpoch
	a.transitionMu.RLock()
	transitionBytes := bytes.Clone(a.installedTransition)
	dynamic := len(a.installedTransition) != 0
	a.transitionMu.RUnlock()
	if a.verifier.EpochAuthority != nil {
		var ready bool
		rootEpoch, ready = a.verifier.EpochAuthority.CurrentRootEpoch()
		if !ready {
			return rootinput.ResultV2{}, rootinput.ErrV2Context
		}
	} else {
		if len(transitionBytes) == 0 {
			transitionBytes = bytes.Clone(a.verifier.Transition)
		}
		if len(transitionBytes) != 0 {
			installed, err := handoff.DecodeEVMTransition(transitionBytes)
			if err != nil || (!dynamic && installed.OldRootEpoch != rootEpoch) {
				return rootinput.ResultV2{}, fmt.Errorf("%w: invalid installed transition", rootinput.ErrV2Context)
			}
			rootEpoch = installed.NewRootEpoch
		}
	}
	observationContext := rootinput.ObservationContextV2{
		NetworkID: a.verifier.NetworkID, PartitionID: a.verifier.PartitionID,
		ShardID: a.verifier.ShardID, ShardConfHash: a.verifier.ShardConfHash,
		ConfForEpoch: a.verifier.installedConfForEpoch(),
		RootEpoch:    a.verifier.RootEpoch, TrustBases: a.verifier.TrustBases,
		EpochAuthority: a.verifier.EpochAuthority,
	}
	if a.verifier.EpochAuthority == nil {
		observationContext.RootEpoch = rootEpoch
	}
	historical, _ := ctx.Value(historicalReplayKey{}).(bool)
	var o rootinput.VerifiedObservationV2
	var err error
	if historical {
		o, err = rootinput.AuthenticateHistoricalObservationV2(ctx, observationContext, uc, tr)
	} else {
		o, err = rootinput.AuthenticateObservationV2(ctx, observationContext, uc, tr)
	}
	if err != nil {
		return rootinput.ResultV2{}, err
	}
	var snapshot registryproof.Snapshot
	var proof shardnode.ProofEvidence
	if p.Parent.Number == 0 {
		if !a.verifier.BootstrapSnapshot.Valid() || !bytes.Equal(p.Parent.Hash, a.verifier.GenesisOrigin.BlockHash().Bytes()) || !bytes.Equal(p.Parent.StateRoot, a.verifier.GenesisOrigin.StateRoot().Bytes()) {
			return rootinput.ResultV2{}, fmt.Errorf("%w: bootstrap parent differs from configured genesis", ErrParentWitnessMismatch)
		}
		snapshot = a.verifier.BootstrapSnapshot
		proof.SnapshotID = fmt.Sprintf("genesis:%x", p.Parent.Hash)
	} else {
		a.mu.Lock()
		source := a.parentWitness
		a.mu.Unlock()
		if source == nil {
			return rootinput.ResultV2{}, fmt.Errorf("%w: no source for parent block %d", ErrParentWitnessUnavailable, p.Parent.Number)
		}
		snapshot, proof, err = source.AcquireWithProvenance(ctx, p.Parent)
		if err != nil {
			return rootinput.ResultV2{}, err
		}
		if a.log != nil {
			a.log.InfoContext(ctx, "acquired certified parent registry witness",
				slog.Uint64("round", p.Round), slog.Uint64("parentNumber", p.Parent.Number),
				slog.String("parentHash", fmt.Sprintf("%x", p.Parent.Hash)), slog.String("snapshotID", proof.SnapshotID), slog.Time("verifiedAt", proof.VerifiedAt))
		}
	}
	pendingTransition := snapshot.Fields().RootEpoch != o.Origin().RootEpoch
	var transition []byte
	if pendingTransition {
		transition, err = a.verifier.transitionFor(snapshot.Fields().RootEpoch, o.Origin().RootEpoch)
		if err != nil {
			if a.verifier.EpochAuthority != nil || !dynamic {
				return rootinput.ResultV2{}, err
			}
			installed, decodeErr := handoff.DecodeEVMTransition(transitionBytes)
			if decodeErr != nil || installed.OldRootEpoch != snapshot.Fields().RootEpoch || installed.NewRootEpoch != o.Origin().RootEpoch {
				return rootinput.ResultV2{}, rootinput.ErrV2Context
			}
			transition = transitionBytes
		}
	}
	derived, err := rootinput.DeriveV2(rootinput.ContextV2{
		Context: ctx, B1: a.verifier.B1, Genesis: a.verifier.GenesisOrigin, Parent: snapshot,
		Round: p.Round, ParentHash: p.Parent.Hash,
		TransitionsPending: pendingTransition, Transition: transition,
	}, o)
	if err == nil {
		shardnode.RecordProofEvidence(ctx, proof)
		if a.log != nil {
			a.log.InfoContext(ctx, "derived root input from parent witness", slog.Uint64("round", p.Round),
				slog.String("parentHash", fmt.Sprintf("%x", p.Parent.Hash)), slog.String("snapshotID", proof.SnapshotID),
				slog.Time("verifiedAt", proof.VerifiedAt), slog.String("commitment", fmt.Sprintf("%x", derived.Commitment)))
		}
	}
	return derived, err
}

func (a *Adapter) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	prepared, err := a.PrepareBuild(ctx, p)
	if err != nil {
		return "", err
	}
	return prepared(ctx)
}

// PrepareBuild performs certificate authentication and bounded proof RPC before Round acquires
// its finality gate. The returned closure performs the final Engine forkchoice mutation only
// after Round revalidates readiness under that gate.
func (a *Adapter) PrepareBuild(ctx context.Context, p shardnode.RoundParams) (func(context.Context) (shardnode.BuildID, error), error) {
	if a.verifier == nil {
		return nil, errors.New("engineapi: build requires a verifier context — NetworkID, PartitionID, ShardID, ShardConfHash and TrustBases come from this node's own configuration, never from the certificate (docs/design/f2c-root-input-wiring-contract.md §3)")
	}
	derived, err := a.deriveV2(ctx, p, p.AuthorizingCertificate, p.AuthorizingTechnicalRecord)
	if err != nil {
		return nil, fmt.Errorf("engineapi: deriving root input for round %d: %w", p.Round, err)
	}
	return func(runCtx context.Context) (shardnode.BuildID, error) {
		return a.buildDerived(runCtx, p, derived)
	}, nil
}

func (a *Adapter) buildDerived(ctx context.Context, p shardnode.RoundParams, derived rootinput.ResultV2) (shardnode.BuildID, error) {
	parentHash32, err := toData32(p.Parent.Hash)
	if err != nil {
		return "", fmt.Errorf("engineapi: build: %w", err)
	}

	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash32)
	if err != nil {
		return "", fmt.Errorf("engineapi: looking up parent header %x: %w", parentHash32, err)
	}
	attrs := DeriveAttributesV2(derived.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)}, a.feeCollector)

	sealAttrs := UnicityPayloadAttributes{
		PayloadAttributesV3: attrs,
		Commitment:          data32(derived.Commitment),
	}

	state := ForkchoiceStateV1{HeadBlockHash: parentHash32, SafeBlockHash: parentHash32, FinalizedBlockHash: parentHash32}
	buildInput := sealBuildInput(derived)
	if buildInput.Pair, err = a.pairBuildBinding(ctx, derived, parentHeader, attrs); err != nil {
		return "", fmt.Errorf("engineapi: pair binding for the build: %w", err)
	}
	resp, err := a.engine.ForkchoiceUpdatedWithSealV1(ctx, state, &sealAttrs, buildInput)
	if err != nil {
		return "", fmt.Errorf("engineapi: forkchoiceUpdatedWithSealV1 (build): %w", err)
	}
	if resp.PayloadStatus.Status != PayloadStatusValid {
		return "", fmt.Errorf("%w: forkchoiceUpdatedWithSealV1 refused a build on the trusted parent (status %s): %s",
			shardnode.ErrBuildUnavailable, resp.PayloadStatus.Status, errString(resp.PayloadStatus.ValidationError))
	}
	if resp.PayloadID == nil {
		return "", errors.New("engineapi: forkchoiceUpdatedWithSealV1 accepted payloadAttributes but returned no payload id")
	}

	id := shardnode.BuildID(hex.EncodeToString(*resp.PayloadID))
	a.mu.Lock()
	a.pending[id] = buildContext{
		payloadID: *resp.PayloadID,
		b1Update:  bytes.Clone(derived.B1Update), b1Input: bytes.Clone(derived.Encoded), b1Commitment: derived.Commitment,
		parent:          p.Parent,
		certificate:     derived.Observation.Certificate(),
		technicalRecord: derived.Observation.TechnicalRecord(),
	}
	a.mu.Unlock()
	return id, nil
}

func sealBuildInput(derived rootinput.ResultV2) SealBuildInput {
	transitions := make([]data, len(derived.Input.Transitions))
	for i, transition := range derived.Input.Transitions {
		transitions[i] = data(bytes.Clone(transition))
	}
	return SealBuildInput{RootInput: data(bytes.Clone(derived.Encoded)), Transitions: transitions, B1Update: data(bytes.Clone(derived.B1Update))}
}

// Seal retrieves the built payload. An empty user transaction list still
// produces an execution block: system transitions can change its state, and
// an idle M1 shard must keep advancing the EVM height.
func (a *Adapter) Seal(ctx context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	a.mu.Lock()
	bc, ok := a.pending[id]
	if ok {
		delete(a.pending, id)
	}
	a.mu.Unlock()
	if !ok {
		return shardnode.Block{}, shardnode.ErrNotFound
	}

	resp, err := a.engine.GetPayloadWithSealV1(ctx, bc.payloadID)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: getPayloadWithSealV1: %w", err)
	}

	if len(bc.b1Update) > 0 && (uint64(resp.ExecutionPayload.GasLimit) != a.verifier.B1.Profile.MaxGas || !bytes.Equal(resp.SealCompanion.B1Update, bc.b1Update) || !bytes.Equal(resp.SealCompanion.RootInput, bc.b1Input) || !bytes.Equal(resp.ExecutionPayload.ExtraData, bc.b1Commitment[:])) {
		return shardnode.Block{}, ErrCompanionBinding
	}
	// Even an empty user transaction list is a real execution payload: system contracts
	// (including the beacon-root update) may change state, and M1 must advance EVM
	// height through idle periods. The payload still needs its normal seal companion.

	// ureth deliberately returns witnesses empty (D2 §"The authentication lifecycle": witnesses are
	// verifier-owned and the execution client holds no trust base), so the leader supplies them before
	// dissemination; without them a follower has nothing to authenticate. rootInput and provenance
	// come back from ureth and are left as they are. The list is exactly [bound certificate, bound
	// technical record] — see SealCompanionWitnessCount for why both travel and why the length is
	// fixed. The pair was authenticated by Build, so an encoding failure here is a local fault and is
	// surfaced rather than turned into an unfilled companion no follower could authenticate.
	witnesses, err := encodeSealCompanionWitnesses(bc.certificate, bc.technicalRecord)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: sealing round: %w", err)
	}
	if a.log != nil {
		a.log.InfoContext(ctx, "sealed execution payload",
			slog.String("blockHash", fmt.Sprintf("%x", resp.ExecutionPayload.BlockHash)),
			slog.String("parentHash", fmt.Sprintf("%x", resp.ExecutionPayload.ParentHash)),
			slog.Int("userTransactions", len(resp.ExecutionPayload.Transactions)),
			slog.String("rootInput", fmt.Sprintf("%x", resp.SealCompanion.RootInput)),
			slog.String("commitment", fmt.Sprintf("%x", resp.ExecutionPayload.ExtraData)))
	}
	return EncodeBlockWithSealCompanion(resp.ExecutionPayload, &SealCompanion{
		B1Update:   resp.SealCompanion.B1Update,
		RootInput:  resp.SealCompanion.RootInput,
		Witnesses:  witnesses,
		Provenance: resp.SealCompanion.Provenance,
	})
}

// CheckBlockBinding computes the Cancun header hash from the raw envelope and
// the independently derived beacon root. It runs before a follower retains
// a candidate, so a leader cannot consume journal capacity with arbitrary
// claimed hashes. This does not import the payload or move forkchoice.
func (a *Adapter) CheckBlockBinding(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) error {
	envelope, err := DecodeBlock(b)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, b.Raw) {
		return errors.New("engineapi: proposal envelope is not canonical JSON; refusing journal retention")
	}
	if a.verifier == nil {
		return errors.New("engineapi: block binding requires a verifier context")
	}
	if len(envelope.ExpectedBlobVersionedHashes) != 0 {
		return errors.New("engineapi: blob transactions are not admitted")
	}
	if envelope.SealCompanion == nil || len(envelope.SealCompanion.Provenance) > 16 {
		return errors.New("engineapi: missing or oversized seal companion")
	}
	companionUC, companionTR, err := decodeSealCompanionWitnesses(envelope.SealCompanion.Witnesses)
	if err != nil {
		return err
	}
	cu, err := types.Cbor.Marshal(companionUC)
	if err != nil {
		return err
	}
	pu, err := types.Cbor.Marshal(p.AuthorizingCertificate)
	if err != nil {
		return err
	}
	ct, err := types.Cbor.Marshal(companionTR)
	if err != nil {
		return err
	}
	pt, err := types.Cbor.Marshal(p.AuthorizingTechnicalRecord)
	if err != nil {
		return err
	}
	if !bytes.Equal(cu, pu) || !bytes.Equal(ct, pt) {
		return errors.New("engineapi: companion authorization differs from held certificate and technical record")
	}
	input, err := a.deriveV2(ctx, p, p.AuthorizingCertificate, p.AuthorizingTechnicalRecord)
	if err != nil {
		if errors.Is(err, ErrParentWitnessUnavailable) || errors.Is(err, ErrParentWitnessBudget) || errors.Is(err, ErrParentWitnessStopped) || errors.Is(err, ErrParentWitnessSuperseded) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %w", shardnode.ErrBlockBindingUnavailable, err)
		}
		return fmt.Errorf("engineapi: block binding authorizing pair: %w", err)
	}
	parentHash, err := toData32(p.Parent.Hash)
	if err != nil {
		return err
	}
	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash)
	if err != nil {
		return fmt.Errorf("%w: parent header: %w", shardnode.ErrBlockBindingUnavailable, err)
	}
	attrs := DeriveAttributesV2(input.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)}, a.feeCollector)
	payload := envelope.ExecutionPayload
	if a.verifier.B1 != nil && uint64(payload.GasLimit) != a.verifier.B1.Profile.MaxGas {
		return b1paired.ErrAdmission
	}
	if !bytes.Equal(envelope.SealCompanion.B1Update, input.B1Update) || !bytes.Equal(envelope.SealCompanion.RootInput, input.Encoded) || !bytes.Equal(payload.ExtraData, input.Commitment[:]) {
		return ErrCompanionBinding
	}
	if b.Number != uint64(payload.BlockNumber) || !bytes.Equal(b.Hash, payload.BlockHash[:]) || !bytes.Equal(b.ParentHash, payload.ParentHash[:]) || !bytes.Equal(b.StateRoot, payload.StateRoot[:]) || !bytes.Equal(p.Parent.Hash, payload.ParentHash[:]) || b.Number != p.Parent.Number+1 {
		return errors.New("engineapi: outer block identity differs from raw execution payload")
	}
	withdrawals := make([]*gethtypes.Withdrawal, 0, len(payload.Withdrawals))
	for _, w := range payload.Withdrawals {
		withdrawals = append(withdrawals, &gethtypes.Withdrawal{Index: uint64(w.Index), Validator: uint64(w.ValidatorIndex), Address: common.Address(w.Address), Amount: uint64(w.Amount)})
	}
	if len(payload.LogsBloom) != 256 || len(payload.ExtraData) > 32 {
		return errors.New("engineapi: invalid raw header bloom or extraData length")
	}
	txs := make(gethtypes.Transactions, len(payload.Transactions))
	for i, tx := range payload.Transactions {
		var decoded gethtypes.Transaction
		if err := decoded.UnmarshalBinary(tx); err != nil {
			return fmt.Errorf("engineapi: decoding raw transaction %d: %w", i, err)
		}
		if len(decoded.BlobHashes()) != 0 {
			return errors.New("engineapi: blob transaction is not admitted")
		}
		txs[i] = &decoded
	}
	blobGas, excessBlobGas := uint64(payload.BlobGasUsed), uint64(payload.ExcessBlobGas)
	beaconRoot := common.Hash(attrs.ParentBeaconBlockRoot)
	withdrawalsRoot := gethtypes.DeriveSha(gethtypes.Withdrawals(withdrawals), trie.NewStackTrie(nil))
	header := &gethtypes.Header{
		ParentHash: common.Hash(payload.ParentHash), UncleHash: gethtypes.EmptyUncleHash, Coinbase: common.Address(payload.FeeRecipient), Root: common.Hash(payload.StateRoot), TxHash: gethtypes.DeriveSha(txs, trie.NewStackTrie(nil)), ReceiptHash: common.Hash(payload.ReceiptsRoot), Bloom: gethtypes.BytesToBloom(payload.LogsBloom), Difficulty: new(big.Int), Number: new(big.Int).SetUint64(uint64(payload.BlockNumber)), GasLimit: uint64(payload.GasLimit), GasUsed: uint64(payload.GasUsed), Time: uint64(payload.Timestamp), Extra: payload.ExtraData, MixDigest: common.Hash(payload.PrevRandao), BaseFee: new(big.Int).SetUint64(uint64(payload.BaseFeePerGas)), WithdrawalsHash: &withdrawalsRoot, BlobGasUsed: &blobGas, ExcessBlobGas: &excessBlobGas, ParentBeaconRoot: &beaconRoot,
	}
	if computed := header.Hash(); computed != common.Hash(payload.BlockHash) {
		return fmt.Errorf("engineapi: raw payload block hash %x is not its computed header hash %x", payload.BlockHash, computed)
	}
	return nil
}

// Verify authenticates the block-bound certificate and technical record against this node's v2
// configuration and checked genesis snapshot. It compares the canonical bytes and header commitment
// before asking the execution client to execute. The follower never re-selects from its own inbox.
func (a *Adapter) Verify(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	if len(b.Raw) == 0 {
		if a.verifier != nil && a.verifier.B1 != nil {
			return shardnode.StatusInvalid, ErrCompanionMissing
		}
		// Quiet block: must be exactly the parent's Number/StateRoot,
		// unchanged. Nothing to execute — see Seal's quiet case above,
		// which this mirrors, including deliberately NOT checking b.Hash
		// against p.Parent.Hash: Seal's echo always sets Hash nil (never
		// the parent's real hash — see that comment for why), so a
		// same-as-parent Hash comparison here would reject every honest
		// quiet block. executortest.Fake.Verify's quiet check has the same
		// shape, for the same reason.
		if b.Number == p.Parent.Number && bytes.Equal(b.StateRoot, p.Parent.StateRoot) {
			if p.Parent.Number > 0 {
				if a.verifier == nil {
					return shardnode.StatusInvalid, errors.New("engineapi: quiet verification requires a verifier context")
				}
				if _, err := a.deriveV2(ctx, p, p.AuthorizingCertificate, p.AuthorizingTechnicalRecord); err != nil {
					if isParentWitnessAcquisitionError(err) {
						if errors.Is(err, ErrParentWitnessUnavailable) {
							return shardnode.StatusSyncing, transientParentWitnessError{err}
						}
						return shardnode.StatusSyncing, err
					}
					return shardnode.StatusInvalid, err
				}
			}
			if a.log != nil {
				a.log.InfoContext(ctx, "verified quiet block", slog.Uint64("round", p.Round),
					slog.String("parentHash", fmt.Sprintf("%x", p.Parent.Hash)),
					slog.String("snapshotID", shardnode.CurrentProofEvidence(ctx).SnapshotID), slog.String("status", "VALID"))
			}
			return shardnode.StatusValid, nil
		}
		return shardnode.StatusInvalid, nil
	}

	envelope, err := DecodeBlock(b)
	if err != nil {
		return shardnode.StatusInvalid, nil //nolint:nilerr // a malformed envelope is an invalid block, not a local error
	}

	// From here on the block is authenticated before it is executed. A missing companion is a
	// refusal, never a fallback to the stock V3 path: a block disseminated without one cannot be
	// authenticated by anyone, and silently executing it as a V3 payload would skip exactly the
	// boundary this unit exists to install.
	if a.verifier == nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verifying round %d: no verifier context — a follower authenticates the bound certificate against its own configured trust base, partition, shard, configuration hash and cursor (docs/design/f2c-root-input-wiring-contract.md §3), and no such context is configured", p.Round)
	}
	if envelope.SealCompanion == nil {
		return shardnode.StatusInvalid, fmt.Errorf("%w: round %d", ErrCompanionMissing, p.Round)
	}
	companion := envelope.SealCompanion
	if a.verifier.B1 != nil && uint64(envelope.ExecutionPayload.GasLimit) != a.verifier.B1.Profile.MaxGas {
		return shardnode.StatusInvalid, b1paired.ErrAdmission
	}

	// Witnesses[0] and witnesses[1] are the bound certificate and the record it commits to, in the
	// canonical-CBOR encoding this repository already uses for both. A wrong length, a decode
	// failure, or a re-encode that is not byte-identical is a refusal.
	uc, tr, err := decodeSealCompanionWitnesses(companion.Witnesses)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verifying round %d: %w", p.Round, err)
	}

	derived, err := a.deriveV2(ctx, p, uc, tr)
	if err != nil {
		if isParentWitnessAcquisitionError(err) {
			if errors.Is(err, ErrParentWitnessUnavailable) {
				return shardnode.StatusSyncing, transientParentWitnessError{err}
			}
			return shardnode.StatusSyncing, fmt.Errorf("engineapi: acquiring parent witness for round %d: %w", p.Round, err)
		}
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: authenticating the bound certificate for round %d: %w", p.Round, err)
	}

	// The leader published bytes; this node derived bytes. They must be the same bytes. This is
	// sharper than a field-by-field comparison: a substituted transition, a swapped record, a wrong
	// origin or a wrong parent all fail on the encoding itself. It also pins that the companion's
	// rootInput is the canonical encoding and not merely a decodable variant.
	if !bytes.Equal(companion.B1Update, derived.B1Update) || !bytes.Equal(companion.RootInput, derived.Encoded) {
		return shardnode.StatusInvalid, fmt.Errorf("%w: round %d: companion rootInput %x is not the canonical derivation %x",
			ErrCompanionBinding, p.Round, companion.RootInput, derived.Encoded)
	}

	// And the header itself must commit to that same input.
	if !bytes.Equal(envelope.ExecutionPayload.ExtraData, derived.Commitment[:]) {
		return shardnode.StatusInvalid, fmt.Errorf("%w: round %d: header extraData %x, derived commitment %x",
			ErrCompanionCommitment, p.Round, envelope.ExecutionPayload.ExtraData, derived.Commitment[:])
	}
	parentHash32, err := toData32(p.Parent.Hash)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verify: %w", err)
	}
	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash32)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: looking up parent header for verification: %w", err)
	}

	// Only now, with the input authenticated, are the execution parameters computable: they are functions of
	// the bound certificate's root round and reference time, both read from derived.Input. The payload
	// fields are checked last of the checks, so a block that fails authentication is reported as an
	// authentication failure rather than as a field divergence. A divergence stays StatusInvalid with
	// the local warning, not an error return, exactly as before the reordering.
	attrs := DeriveAttributesV2(derived.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)}, a.feeCollector)
	claimed := PayloadFields{
		Timestamp:             envelope.ExecutionPayload.Timestamp,
		PrevRandao:            envelope.ExecutionPayload.PrevRandao,
		SuggestedFeeRecipient: envelope.ExecutionPayload.FeeRecipient,
		Withdrawals:           envelope.ExecutionPayload.Withdrawals,
	}
	if err := VerifyPayloadFieldsV2(derived.Input, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)}, a.feeCollector, claimed); err != nil {
		if a.log != nil {
			a.log.WarnContext(ctx, "rejecting round before execution: attributes diverge from local derivation",
				slog.String("status", "INVALID"), slog.String("err", err.Error()))
		}
		return shardnode.StatusInvalid, nil
	}

	// parentBeaconBlockRoot is never trusted from the envelope (it isn't even a field in it — see
	// codec.go's ProposalEnvelope doc comment): derive it from the authenticated input, the same way
	// the leader was required to, and feed our own value into newPayloadWithSealV1. The comparison
	// above does NOT cover it: PayloadFields deliberately omits ParentBeaconBlockRoot, because the
	// payload carries no such field to compare against (VerifyPayloadFields says so in its own doc).
	// A leader that built against a different value is caught by reth instead, as a
	// stateRoot/blockHash mismatch reported INVALID.
	//
	// Only now does the execution client see it, over the JWT-authenticated Engine connection, with
	// reth accepting the verdict produced above.
	own := *companion
	if own.Pair, err = a.pairImportBinding(ctx, derived, parentHeader, envelope.ExecutionPayload.BlockHash); err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: pair binding for the import: %w", err)
	}
	status, err := a.engine.NewPayloadWithSealV1(ctx, envelope.ExecutionPayload, envelope.ExpectedBlobVersionedHashes, attrs.ParentBeaconBlockRoot, own)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: newPayloadWithSealV1: %w", err)
	}
	if a.log != nil {
		a.log.InfoContext(ctx, "verified execution payload",
			slog.Uint64("round", p.Round),
			slog.String("snapshotID", shardnode.CurrentProofEvidence(ctx).SnapshotID),
			slog.String("blockHash", fmt.Sprintf("%x", envelope.ExecutionPayload.BlockHash)),
			slog.String("status", string(status.Status)),
			slog.String("rootInput", fmt.Sprintf("%x", derived.Encoded)),
			slog.String("commitment", fmt.Sprintf("%x", derived.Commitment)))
	}
	return toStatus(status.Status), nil
}

func toStatus(s PayloadStatus) shardnode.Status {
	switch s {
	case PayloadStatusValid:
		return shardnode.StatusValid
	case PayloadStatusSyncing:
		return shardnode.StatusSyncing
	case PayloadStatusAccepted:
		return shardnode.StatusAccepted
	case PayloadStatusInvalid, PayloadStatusInvalidBlockHash:
		return shardnode.StatusInvalid
	default:
		return shardnode.StatusInvalid
	}
}

func toData32(h shardnode.Hash) (data32, error) {
	var d data32
	if len(h) != 32 {
		return d, fmt.Errorf("expected a 32-byte hash, got %d bytes", len(h))
	}
	copy(d[:], h)
	return d, nil
}

func errString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ shardnode.Executor = (*Adapter)(nil)
