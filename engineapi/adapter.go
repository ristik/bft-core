package engineapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// Adapter implements shardnode.Executor by driving reth over the Engine
// API. It is the only place in this package that touches shardnode types —
// everything else (types.go, client.go, params.go, codec.go) is pure
// Engine-API-facing machinery Adapter composes.
type Adapter struct {
	engine *Client
	eth    *EthClient
	log    *slog.Logger

	mu      sync.Mutex
	pending map[shardnode.BuildID]buildContext
}

// buildContext is what Build remembers so Seal — called later, with only a
// BuildID — can (a) ask reth for the right payload and (b) construct a
// correct quiet-round echo without re-deriving the parent from scratch.
type buildContext struct {
	payloadID data
	parent    shardnode.BlockRef
}

type Config struct {
	EngineURL string // authenticated engine_* endpoint, e.g. http://localhost:8551
	EthURL    string // plain eth_* endpoint, e.g. http://localhost:8545
	Secret    Secret
}

func NewAdapter(cfg Config, log *slog.Logger) *Adapter {
	return &Adapter{
		engine:  NewClient(cfg.EngineURL, cfg.Secret),
		eth:     NewEthClient(cfg.EthURL),
		log:     log,
		pending: make(map[shardnode.BuildID]buildContext),
	}
}

// CheckCapabilities is the startup check from
// docs/adr/0001-executor-boundary.md decision 3: it refuses to start
// against a client that does not offer the exact V3 method set this
// adapter speaks.
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
// So the fork schedule is an OPERATOR CONSTRAINT of the pinned deployment
// profile (docs/design/f1-baseline.md §5.8), not a property any startup
// check verifies. What this check does buy is catching the wrong URL, the
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
// genesis hash says nothing about a fork scheduled by timestamp later in the chain's life. See
// CheckCapabilities on why no startup check can supply that guarantee.
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

func (a *Adapter) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	parentHash32, err := toData32(p.Parent.Hash)
	if err != nil {
		return "", fmt.Errorf("engineapi: build: %w", err)
	}

	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash32)
	if err != nil {
		return "", fmt.Errorf("engineapi: looking up parent header %x: %w", parentHash32, err)
	}
	attrs, err := DeriveAttributes(p, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)})
	if err != nil {
		return "", fmt.Errorf("engineapi: deriving payload attributes: %w", err)
	}

	state := ForkchoiceStateV1{HeadBlockHash: parentHash32, SafeBlockHash: parentHash32, FinalizedBlockHash: parentHash32}
	resp, err := a.engine.ForkchoiceUpdatedV3(ctx, state, &attrs)
	if err != nil {
		return "", fmt.Errorf("engineapi: forkchoiceUpdated (build): %w", err)
	}
	if resp.PayloadStatus.Status != PayloadStatusValid {
		return "", fmt.Errorf("engineapi: forkchoiceUpdated (build) on our own trusted head returned %s, not VALID: %v",
			resp.PayloadStatus.Status, errString(resp.PayloadStatus.ValidationError))
	}
	if resp.PayloadID == nil {
		return "", errors.New("engineapi: forkchoiceUpdated accepted payloadAttributes but returned no payload id")
	}

	id := shardnode.BuildID(hex.EncodeToString(*resp.PayloadID))
	a.mu.Lock()
	a.pending[id] = buildContext{payloadID: *resp.PayloadID, parent: p.Parent}
	a.mu.Unlock()
	return id, nil
}

// Seal retrieves the built payload and decides, only now, whether the round
// was quiet — see the build plan §6's note on why this can't be known
// before sealing: there is no txpool-inspection API, and
// parentBeaconBlockRoot moves the state root on every produced block
// regardless of transaction count (EIP-4788), so "empty payload" is the
// only reliable signal.
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

	resp, err := a.engine.GetPayloadV3(ctx, bc.payloadID)
	if err != nil {
		return shardnode.Block{}, fmt.Errorf("engineapi: getPayload: %w", err)
	}

	if len(resp.ExecutionPayload.Transactions) == 0 {
		// Quiet: echo the parent's Number/StateRoot, matching
		// executortest.Fake's own convention for the same case — round.go's
		// quiet-detection compares against Expectation.PreviousHash, not
		// against anything Executor-specific, so every Executor must agree
		// on this shape.
		//
		// Hash is deliberately nil here, NOT bc.parent.Hash — this is not
		// optional cosmetic parity with Fake, it's load-bearing. Fake's own
		// genesis head has a nil Hash by construction (executortest.New),
		// which is what makes blockHashOrFallback's genesis fallback (use
		// StateRoot instead of Hash) trigger correctly. A real execution
		// client's genesis always has a real, non-nil block hash — echoing
		// it here would hand the framework that SAME real hash to use as
		// the genesis round's BlockHash, aliasing a certified round to a
		// block that already existed before this round ran, rather than a
		// value distinct to this round. See docs/troubleshooting.md and
		// TestAdapter_Seal_QuietRound_EchoesParentWithNilHash.
		return shardnode.Block{
			Number:     bc.parent.Number,
			Hash:       nil,
			StateRoot:  bc.parent.StateRoot,
			ParentHash: bc.parent.Hash,
			Raw:        nil,
			BlockSize:  0,
			StateSize:  0,
		}, nil
	}

	return EncodeBlock(resp.ExecutionPayload)
}

// Verify is where C2.3's follower-side validation actually happens: cheap,
// local recompute-and-compare first (params.Verify — no RPC call), then
// only if that passes, the expensive newPayloadV3 call that actually
// executes the block. A leader that altered the timestamp or fee recipient
// is rejected before reth ever sees the payload.
func (a *Adapter) Verify(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	if len(b.Raw) == 0 {
		// Quiet block: must be exactly the parent's Number/StateRoot,
		// unchanged. Nothing to execute — see Seal's quiet case above,
		// which this mirrors, including deliberately NOT checking b.Hash
		// against p.Parent.Hash: Seal's echo always sets Hash nil (never
		// the parent's real hash — see that comment for why), so a
		// same-as-parent Hash comparison here would reject every honest
		// quiet block. executortest.Fake.Verify's quiet check has the same
		// shape, for the same reason.
		if b.Number == p.Parent.Number && bytes.Equal(b.StateRoot, p.Parent.StateRoot) {
			return shardnode.StatusValid, nil
		}
		return shardnode.StatusInvalid, nil
	}

	envelope, err := DecodeBlock(b)
	if err != nil {
		return shardnode.StatusInvalid, nil //nolint:nilerr // a malformed envelope is an invalid block, not a local error
	}

	parentHash32, err := toData32(p.Parent.Hash)
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: verify: %w", err)
	}
	parentHeader, err := a.eth.GetBlockByHash(ctx, parentHash32)
	if err != nil {
		// We can't tell yet whether the block is bad or we're just behind
		// on the parent — SYNCING is the honest answer, matching the same
		// distinction the Engine API itself draws.
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: looking up parent header for verification: %w", err)
	}

	claimed := PayloadFields{
		Timestamp:             envelope.ExecutionPayload.Timestamp,
		PrevRandao:            envelope.ExecutionPayload.PrevRandao,
		SuggestedFeeRecipient: envelope.ExecutionPayload.FeeRecipient,
		Withdrawals:           envelope.ExecutionPayload.Withdrawals,
	}
	if err := VerifyPayloadFields(p, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)}, claimed); err != nil {
		if a.log != nil {
			a.log.WarnContext(ctx, "rejecting round before execution: attributes diverge from local derivation", slog.String("err", err.Error()))
		}
		return shardnode.StatusInvalid, nil
	}

	// parentBeaconBlockRoot is never trusted from the envelope (it isn't
	// even a field in it — see codec.go's ProposalEnvelope doc comment):
	// derive it the same way the leader was required to, and feed our own
	// value into newPayload. A leader that built against a different value
	// gets caught here, as a state-root mismatch, not by comparing the
	// value directly.
	attrs, err := DeriveAttributes(p, ParentHeader{Timestamp: uint64(parentHeader.Timestamp)})
	if err != nil {
		return shardnode.StatusInvalid, fmt.Errorf("engineapi: re-deriving attributes for newPayload: %w", err)
	}

	status, err := a.engine.NewPayloadV3(ctx, envelope.ExecutionPayload, envelope.ExpectedBlobVersionedHashes, attrs.ParentBeaconBlockRoot)
	if err != nil {
		return shardnode.StatusSyncing, fmt.Errorf("engineapi: newPayload: %w", err)
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
