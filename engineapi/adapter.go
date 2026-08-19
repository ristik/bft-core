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
// docs/adr/0001-executor-boundary.md decision 3: capability exchange is
// necessary but not sufficient on its own (a chain spec that scheduled
// Prague at genesis would still pass it on a reth build that also speaks
// V4), so this is paired with T1.2's explicit fork-schedule generation —
// but the capability check is what actually stops the process from
// starting against a clearly incompatible execution client. Call it once,
// before Run.
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
		// Quiet: echo the parent exactly, matching executortest.Fake's own
		// convention for the same case — round.go's quiet-detection
		// compares against Expectation.PreviousHash, not against anything
		// Executor-specific, so every Executor must agree on this shape.
		return shardnode.Block{
			Number:     bc.parent.Number,
			Hash:       bc.parent.Hash,
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
		// Quiet block: must be exactly the parent, unchanged. Nothing to
		// execute — see Seal's quiet case above, which this mirrors.
		if b.Number == p.Parent.Number && bytes.Equal(b.StateRoot, p.Parent.StateRoot) && bytes.Equal(b.Hash, p.Parent.Hash) {
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
