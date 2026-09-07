package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// Submitter sends a signed BlockCertificationRequest toward the root chain.
// Implemented by BFTClient, which owns the network connection and root-node
// selection; round.go depends only on this narrow interface so it can be
// unit-tested without libp2p.
type Submitter interface {
	Submit(ctx context.Context, req *certification.BlockCertificationRequest) error
}

// Round drives one shard validator's Executor through the round protocol
// described in docs/shard-protocol.md: on every Unicity Certificate, commit
// what was just certified, then build or verify the next round's candidate
// and submit it for certification. It has no network code and no root-chain
// protocol knowledge beyond the certification/types packages — those live
// in BFTClient.
type Round struct {
	nodeID      string
	partitionID types.PartitionID
	shardID     types.ShardID

	executor     Executor
	disseminator Disseminator
	signer       abcrypto.Signer
	submitter    Submitter
	log          *slog.Logger
	metrics      *Metrics // optional; every use is nil-safe, see metrics.go
	health       *Health  // optional; every use is nil-safe, see health.go

	// awaitTimeout bounds how long a follower waits for the leader's
	// disseminated block before giving up on this round. Without a bound,
	// a leader that never publishes (crashed, partitioned) would block
	// HandleCertificate forever — which blocks BFTClient's entire message
	// loop, not just this round, since HandleCertificate is called
	// synchronously from it. See docs/engine-api-adapter-plan.md C2.5: a
	// missed proposal should cost this validator one round (it abstains,
	// the timeout fires, the next UC — likely a repeat — starts the next
	// attempt), not the rest of its lifetime. This is a coarser version of
	// C2.5's full policy — a fixed timeout rather than one derived from T2
	// with SYNCING/ACCEPTED-aware retry — good enough to make the failure
	// mode "abstain and recover" instead of "hang," which is what a live
	// multi-validator run needs to not be fatal on its own.
	awaitTimeout time.Duration

	mu      sync.Mutex
	pending *pendingSubmission // what we last submitted, awaiting certification
}

// DefaultAwaitTimeout is used when NewRound is not given a more specific
// value — see Round.awaitTimeout.
const DefaultAwaitTimeout = 5 * time.Second

type pendingSubmission struct {
	round uint64
	hash  Hash // block hash to Commit once certified

	// needsCommit is true iff the executor's own head actually moved this
	// round — NOT the same test as whether the InputRecord we submitted was
	// "quiet" (that compares against the root chain's PreviousHash, which
	// is nil at genesis even though a real executor's genesis state root
	// is not). The two coincide everywhere except the very first round: a
	// genesis round is always non-quiet from the root chain's point of view
	// (nil ≠ any real hash) but the executor may still report no change
	// (e.g. an Executor whose genesis Build with zero entries simply
	// echoes head) — see BlockHashOrFallback and TestRound_SingleValidator_GenesisToThreeRounds.
	needsCommit bool

	submittedAt time.Time // for Metrics.recordQuorumLatency
}

func NewRound(nodeID string, partitionID types.PartitionID, shardID types.ShardID, executor Executor, disseminator Disseminator, signer abcrypto.Signer, submitter Submitter, log *slog.Logger) *Round {
	return &Round{
		nodeID:       nodeID,
		partitionID:  partitionID,
		shardID:      shardID,
		executor:     executor,
		disseminator: disseminator,
		signer:       signer,
		submitter:    submitter,
		log:          log,
		awaitTimeout: DefaultAwaitTimeout,
	}
}

// SetAwaitTimeout overrides the default wait for the leader's disseminated
// block — see awaitTimeout. Deployments that know their shard's T2 should
// set this below it, so a stalled leader is discovered and abstained from
// well before the root chain would time the round out anyway.
func (r *Round) SetAwaitTimeout(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.awaitTimeout = d
}

// SetMetrics attaches an optional Metrics recorder. Safe to call, or not, at
// any point before Run starts — round.go never assumes it's set.
func (r *Round) SetMetrics(m *Metrics) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics = m
}

// SetHealth attaches an optional Health snapshot. Safe to call, or not, at
// any point before Run starts.
func (r *Round) SetHealth(h *Health) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = h
}

// HandleCertificate is the framework's single entry point, called once for
// every UC classified as UCValid or UCRepeat (UCDuplicate is filtered out
// before reaching here — see BFTClient). It commits the previous round's
// result, then drives the round tr describes.
func (r *Round) HandleCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.commitPrevious(ctx, uc); err != nil {
		return fmt.Errorf("committing previously certified round: %w", err)
	}

	exp, err := ExpectationFromCertificate(uc, tr.Round, tr.Epoch)
	if err != nil {
		return fmt.Errorf("deriving next round expectation: %w", err)
	}

	head, err := r.executor.Head(ctx)
	if err != nil {
		r.health.updateExecutorStatus(false, err.Error())
		return fmt.Errorf("reading executor head: %w", err)
	}
	r.health.updateExecutorStatus(true, "")
	// exp.PreviousHash is nil exactly when the root chain has never
	// certified anything for this shard yet (its genesis IR.Hash is nil —
	// see rootchain/consensus/storage/sharding.go NewShardInfo). An
	// Executor's own genesis state, by contrast, is a real value (an EVM
	// genesis block has a real state root; Fake's is 32 zero bytes) — the
	// two are never byte-equal, and that is expected, not divergence: there
	// is nothing yet to compare against. Only compare once the root chain
	// has a real PreviousHash to hold the executor to.
	if len(exp.PreviousHash) > 0 && !bytes.Equal(head.StateRoot, exp.PreviousHash) {
		head, err = r.reconcile(ctx, uc, exp, head)
		if err != nil {
			return err
		}
	}

	sealHash, err := SealHash(uc)
	if err != nil {
		return fmt.Errorf("reading certificate seal hash: %w", err)
	}

	block, params, err := r.produceBlock(ctx, head, exp, sealHash, tr.Leader)
	if err != nil {
		return fmt.Errorf("producing round %d block: %w", exp.Round, err)
	}

	verifyStart := time.Now()
	status, err := r.verifyWithRetry(ctx, block, params)
	r.metrics.recordVerifyDuration(ctx, time.Since(verifyStart), tr.Leader == r.nodeID)
	if err != nil {
		return fmt.Errorf("self-verifying round %d block: %w", exp.Round, err)
	}
	switch status {
	case StatusValid:
		// proceed
	case StatusSyncing, StatusAccepted:
		// Retried until r.awaitTimeout and still not resolved — abstain
		// from this round rather than treat "not yet validated" the same
		// as "rejected". The next certificate (likely a repeat UC) starts
		// the next attempt; see docs/engine-api-adapter-plan.md §6's
		// status policy table.
		r.metrics.recordIRDivergence(ctx, "self_verify_pending_timeout")
		if r.log != nil {
			r.log.WarnContext(ctx, "abstaining from round: executor still reports pending status after the retry deadline",
				slog.Uint64("round", exp.Round), slog.String("status", status.String()))
		}
		return nil
	default: // StatusInvalid or anything else
		r.metrics.recordIRDivergence(ctx, "self_verify_rejected")
		return fmt.Errorf("shardnode: executor rejected its own round %d block with status %s — refusing to submit it for certification", exp.Round, status)
	}

	// irQuiet: what the root chain will see (compared against its own
	// PreviousHash). executorChanged: what actually happened locally
	// (compared against this executor's own pre-round head). They diverge
	// only at genesis — see pendingSubmission.needsCommit.
	irQuiet := bytes.Equal(block.StateRoot, exp.PreviousHash)
	executorChanged := !bytes.Equal(block.StateRoot, head.StateRoot)
	blockHashForIR := BlockHashOrFallback(block, irQuiet)

	ir, err := BuildInputRecord(exp, block.StateRoot, blockHashForIR, irQuiet)
	if err != nil {
		return fmt.Errorf("building input record for round %d: %w", exp.Round, err)
	}
	if err := ValidateLocal(ir, exp); err != nil {
		r.metrics.recordIRDivergence(ctx, "local_validation_failed")
		return fmt.Errorf("shardnode: locally-built input record for round %d would be rejected by the root chain: %w", exp.Round, err)
	}

	req := &certification.BlockCertificationRequest{
		PartitionID: r.partitionID,
		ShardID:     r.shardID,
		NodeID:      r.nodeID,
		InputRecord: ir,
		// BlockSize/StateSize come from the Executor, not a framework
		// default: they are hashed into the root chain's quorum key
		// alongside the InputRecord (rootchain/request_buffer.go's Add),
		// so a hardcoded 0 here would silently agree by accident rather
		// than by the Executor's own deterministic accounting.
		BlockSize: block.BlockSize,
		StateSize: block.StateSize,
	}
	if err := req.Sign(r.signer); err != nil {
		return fmt.Errorf("signing certification request: %w", err)
	}

	r.pending = &pendingSubmission{round: exp.Round, hash: block.Hash, needsCommit: executorChanged, submittedAt: time.Now()}
	r.health.updateSubmitted(exp.Round)

	if r.log != nil {
		r.log.InfoContext(ctx, "submitting block certification request",
			slog.Uint64("round", exp.Round), slog.Bool("quiet", irQuiet), slog.Bool("leader", tr.Leader == r.nodeID))
	}
	return r.submitter.Submit(ctx, req)
}

// commitPrevious finalizes what uc just certified. It is a no-op the very
// first time HandleCertificate is called (nothing pending yet — the
// executor already holds whatever state uc.InputRecord.Hash represents,
// since either it's genesis or a resumed node's store already recorded it)
// and a no-op when the last round submitted was quiet (nothing changed, so
// nothing to commit).
func (r *Round) commitPrevious(ctx context.Context, uc *types.UnicityCertificate) error {
	if r.pending == nil {
		return nil
	}
	p := r.pending
	r.pending = nil

	// Recorded for every confirmed round, quiet or not — both are "this
	// round reached quorum," which is what the metric is for.
	r.metrics.recordRoundCertified(ctx)
	if !p.submittedAt.IsZero() {
		r.metrics.recordQuorumLatency(ctx, time.Since(p.submittedAt))
	}

	if !p.needsCommit {
		return nil
	}
	status, err := r.executor.Commit(ctx, p.hash)
	if err != nil {
		return err
	}
	if status != StatusValid {
		r.metrics.recordIRDivergence(ctx, "commit_failed")
		return fmt.Errorf("shardnode: executor could not commit round %d (hash %x, status %s) — this node has fallen behind and needs to resync (see docs/troubleshooting.md)",
			p.round, p.hash, status)
	}
	if !bytes.Equal(uc.InputRecord.Hash, p.hash) && r.log != nil {
		r.log.WarnContext(ctx, "certified hash differs from what this node submitted — following the root chain's decision",
			slog.String("certified", fmt.Sprintf("%x", uc.InputRecord.Hash)), slog.String("submitted", fmt.Sprintf("%x", p.hash)))
	}
	return nil
}

// reconcile is the crash-recovery path: head diverges from what uc just
// certified, and r.pending — the in-memory record commitPrevious would
// normally use — is empty, because it never survives a restart. That does
// not necessarily mean the certified block is lost: an Executor backed by
// a persistent store (reth writes a block to disk the moment newPayload
// succeeds, before any forkchoiceUpdate makes it canonical) may still have
// it sitting right there, simply never finalized because the process died
// between submitting the request and processing the confirming UC.
//
// So Commit is retried directly against the root-chain-certified hash
// before giving up. This is the one place the framework calls Commit with
// no local memory of ever having produced that block — Executor
// implementations must treat Commit as idempotent and safe to call
// speculatively, not assume it always follows a Build/Seal/Verify triple
// from the same process lifetime. See
// docs/adr/0001-executor-boundary.md §"Recovery relies on executor
// durability, not a replayable log" for the scope this covers (a same-host
// restart with the executor's data intact) and what it does not (recovery
// after the executor itself lost the block, e.g. disk loss — out of scope
// for exec-mode).
func (r *Round) reconcile(ctx context.Context, uc *types.UnicityCertificate, exp Expectation, head BlockRef) (BlockRef, error) {
	r.metrics.recordIRDivergence(ctx, "head_diverged")
	// Commit is keyed by block hash everywhere else in this file (see
	// pendingSubmission.hash, always a Block.Hash) — never by state root.
	// uc.InputRecord.BlockHash is the certificate's own copy of that same
	// value, which is why it's usable here even though r.pending (the only
	// other place this framework remembers a block hash) is gone.
	//
	// KNOWN DEFECT (issue #92, reproduced by
	// shardnode/round_quiet_recovery_test.go). A quiet certificate carries a
	// nil BlockHash by construction (see BuildInputRecord), so when a node
	// that is behind a state-changing block processes a quiet certificate,
	// the target below is EMPTY. This comment used to claim that was
	// harmless because "Commit will correctly report StatusSyncing for it".
	// That is true of the in-memory fake executor and false of the Engine
	// API adapter, which rejects a non-32-byte hash outright
	// ("expected a 32-byte hash, got 0 bytes" — see
	// engineapi.TestAdapterCommitRejectsEmptyHash). It is why a fake-only
	// chaos suite never surfaced this path.
	//
	// The consequence is not merely a bad error message: an authenticated
	// target for the missed block is available in the certificate chain the
	// node already holds, and recovery does not use it, so a node whose
	// executor still has the payload sitting there un-canonical fails
	// exactly as hard as one that never received it. Selecting and
	// authenticating that target is #92's remaining work; this comment is
	// corrected here so the code no longer asserts something the tests
	// disprove.
	blockHash := Hash(uc.InputRecord.BlockHash)
	if r.log != nil {
		r.log.WarnContext(ctx, "executor head diverges from certified state — attempting recovery via Commit before giving up",
			slog.String("executorHead", fmt.Sprintf("%x", head.StateRoot)), slog.String("certifiedStateRoot", fmt.Sprintf("%x", exp.PreviousHash)),
			slog.String("certifiedBlockHash", fmt.Sprintf("%x", blockHash)))
	}
	status, err := r.executor.Commit(ctx, blockHash)
	if err != nil {
		return head, fmt.Errorf("shardnode: recovery commit failed: %w", err)
	}
	if status != StatusValid {
		return head, fmt.Errorf("shardnode: executor head %x diverges from root-chain-certified state %x and recovery commit(blockHash=%x) returned %s (not %s) — cannot safely build round %d; this node has fallen out of sync and needs manual recovery (see docs/troubleshooting.md)",
			head.StateRoot, exp.PreviousHash, blockHash, status, StatusValid, exp.Round)
	}
	newHead, err := r.executor.Head(ctx)
	if err != nil {
		return head, fmt.Errorf("reading executor head after recovery commit: %w", err)
	}
	if !bytes.Equal(newHead.StateRoot, exp.PreviousHash) {
		return head, fmt.Errorf("shardnode: recovery commit reported %s but executor head is still %x, not the certified %x — refusing to build round %d",
			StatusValid, newHead.StateRoot, exp.PreviousHash, exp.Round)
	}
	if r.log != nil {
		r.log.InfoContext(ctx, "recovered: executor already held the certified block, now committed", slog.Uint64("round", exp.Round))
	}
	return newHead, nil
}

// verifyRetryInterval is the poll spacing verifyWithRetry uses while an
// Executor reports StatusSyncing/StatusAccepted. Not configurable — the
// budget that matters is the deadline (r.awaitTimeout), not how finely it's
// polled.
const verifyRetryInterval = 100 * time.Millisecond

// verifyWithRetry applies the status policy from
// docs/engine-api-adapter-plan.md §6: StatusSyncing and StatusAccepted both
// mean "not yet validated," not "rejected" — retry until r.awaitTimeout
// elapses before giving up. StatusValid and StatusInvalid both return
// immediately, since neither benefits from waiting. Shares its deadline
// budget with the disseminator-await timeout (both are "how long is this
// validator willing to wait before abstaining from the round") rather than
// introducing a second, independently-tuned timeout.
func (r *Round) verifyWithRetry(ctx context.Context, block Block, params RoundParams) (Status, error) {
	deadline := time.Now().Add(r.awaitTimeout)
	for {
		status, err := r.executor.Verify(ctx, block, params)
		if err != nil {
			return status, err
		}
		if status != StatusSyncing && status != StatusAccepted {
			return status, nil
		}
		if !time.Now().Before(deadline) {
			return status, nil // caller treats a still-pending status as abstain, not reject
		}
		select {
		case <-ctx.Done():
			return status, fmt.Errorf("verify retry: %w", ctx.Err())
		case <-time.After(verifyRetryInterval):
		}
	}
}

// produceBlock builds (leader) or awaits and verifies-for-dissemination-only
// (follower) the candidate for this round. Note: the leader's block is
// still passed through executor.Verify by the caller (HandleCertificate) —
// produceBlock only obtains it.
func (r *Round) produceBlock(ctx context.Context, head BlockRef, exp Expectation, sealHash Hash, leader string) (Block, RoundParams, error) {
	params := RoundParams{
		Round:     exp.Round,
		Epoch:     exp.Epoch,
		Timestamp: exp.Timestamp,
		SealHash:  sealHash,
		Leader:    leader,
		Parent:    head,
	}

	if leader == r.nodeID {
		buildStart := time.Now()
		id, err := r.executor.Build(ctx, params)
		if err != nil {
			return Block{}, params, fmt.Errorf("build: %w", err)
		}
		block, err := r.executor.Seal(ctx, id)
		r.metrics.recordBuildDuration(ctx, time.Since(buildStart))
		if err != nil {
			return Block{}, params, fmt.Errorf("seal: %w", err)
		}
		if r.disseminator != nil {
			if err := r.disseminator.Publish(ctx, exp.Round, block); err != nil {
				return Block{}, params, fmt.Errorf("publishing round %d block: %w", exp.Round, err)
			}
		}
		return block, params, nil
	}

	if r.disseminator == nil {
		return Block{}, params, errors.New("shardnode: not leader this round and no disseminator configured — cannot obtain the leader's block")
	}
	awaitCtx, cancel := context.WithTimeout(ctx, r.awaitTimeout)
	defer cancel()
	block, err := r.disseminator.Await(awaitCtx, exp.Round)
	if err != nil {
		return Block{}, params, fmt.Errorf("awaiting round %d block from leader %s: %w (this validator abstains from the round; the next certificate — likely a repeat UC — will start a fresh attempt)", exp.Round, leader, err)
	}
	return block, params, nil
}

// BlockHashOrFallback returns the InputRecord's BlockHash for a non-quiet
// round. Ordinarily that is the executor's own Block.Hash; the fallback to
// StateRoot exists for one specific case — the very first round ever
// certified, whose root-chain PreviousHash is nil (see
// docs/shard-protocol.md §"Genesis is always non-quiet") while an
// Executor's own genesis head has no meaningful "block hash" distinct from
// its state root. Every round after that has a real, executor-assigned
// block hash and this fallback never triggers.
func BlockHashOrFallback(b Block, quiet bool) []byte {
	if quiet {
		return nil
	}
	if len(b.Hash) == 0 {
		return b.StateRoot
	}
	return b.Hash
}

// SealHash extracts UnicitySeal.Hash — see RoundParams.SealHash for why this
// is the field to use for round-derived randomness, and specifically why it
// is not a hash of the certificate as a whole.
func SealHash(uc *types.UnicityCertificate) (Hash, error) {
	if uc == nil || uc.UnicitySeal == nil {
		return nil, fmt.Errorf("shardnode: certificate has no unicity seal")
	}
	return Hash(uc.UnicitySeal.Hash), nil
}
