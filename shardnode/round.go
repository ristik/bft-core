package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
	// certSigner is the single funnel every certification request goes through (#105 step 3).
	// It starts as the local key, which is what deployments do today; SetCertificationSigner
	// replaces it with a signing authority, and that is an explicit deployment decision.
	certSigner CertificationSigner
	submitter  Submitter
	log        *slog.Logger
	metrics    *Metrics // optional; every use is nil-safe, see metrics.go
	health     *Health  // optional; every use is nil-safe, see health.go

	// awaitTimeout bounds how long a follower waits for the leader's
	// disseminated block before giving up on this round. Without a bound,
	// a leader that never publishes (crashed, partitioned) would block
	// HandleCertificate forever — which blocks BFTClient's entire message
	// loop, not just this round, since HandleCertificate is called
	// synchronously from it. See docs/engine-api-adapter-plan.md C2.5: a
	// missed proposal should cost this validator one round (it abstains,
	// the timeout fires, the next UC — likely a repeat — starts the next
	// attempt), not the rest of its lifetime. This is a coarser version of
	// C2.5's full policy — SYNCING/ACCEPTED-aware retry is still missing —
	// but it is no longer a fixed value: cli/ubft derives it from the shard
	// conf's T2 via AwaitTimeoutForT2, because a budget longer than T2 makes
	// a validator consume certificates slower than the root chain issues
	// them and fall permanently behind. That was measured, not predicted;
	// see AwaitTimeoutForT2.
	awaitTimeout time.Duration

	mu      sync.Mutex
	pending *pendingSubmission // what we last submitted, awaiting certification

	// evidence is the optional serving buffer (evidencebuffer.go): what this node retains so that
	// it can SERVE the evidence chain a returning peer needs, over ProtocolAnchorEvidence. It is
	// fed here because HandleCertificate is the one place a certificate and the technical record
	// bound to it arrive together, already authenticated by BFTClient.
	//
	// It is a provider-side concern only. Nothing in this node's own round depends on it, no round
	// outcome changes with it present or absent, and a node that never sets one simply never
	// registers the protocol and serves nobody. Recovery — using somebody else's buffer to repair
	// this node's own anchor — is a separate decision and is not wired anywhere yet.
	evidence *EvidenceBuffer

	// finality serializes every executor call that changes what the executor considers canonical or
	// final — this file's commits and Build, and the recovery applier's commit. See finality.go for
	// why Round.mu is not that guarantee: it is a round lock, and it stopped being sufficient the
	// moment a second thing could commit.
	finality *FinalityGate

	// recovery is the authenticated-evidence recovery lifecycle (§6.3, §6.4), attached by
	// SetRecovery. Nil on a node that does not run it, and every use below is guarded: a node
	// without it behaves exactly as it did before, refusing rather than recovering.
	recovery *RecoveryStack

	// continuity is the live execution anchor and the interval this node has itself verified
	// quiet since it (see anchor.go, and docs/design/f6b-quiet-uc-recovery.md §3.3). It is what
	// gives reconcile a block hash to recover to when the certificate in hand is quiet and
	// therefore carries none — issue #92.
	//
	// In-process only. It is deliberately NOT restored from the checkpoint: an older checkpoint
	// replays perfectly (§6.1), so a restored anchor may only authorize a vote once the
	// independent monotonic signing contract (#105) exists. Persisting it is a later PR;
	// retaining it across quiet rounds WITHIN a process is what this one delivers.
	//
	// Note that the anchor is NOT the P-sign gate and never was: it says which block the executor
	// must be at, not whether this process is allowed to vote at all. That gate is restoredFrom
	// below, and it is enforced separately — an anchor arrives from the next non-quiet certificate
	// whether the process restarted or not.
	continuity continuityState

	// completed is the last round this node signed a request for, together with the certificate
	// that authorized it. A re-delivery of that same certificate re-sends those exact bytes
	// instead of rebuilding — see the replay guard in HandleCertificate.
	completed *completedRound
	// restoredFrom, when non-nil, is the partition round of the certificate this process was
	// resumed from (node.go's LoadLUC / verifyRestoredLUC / SeedLUC sequence). A Round marked this
	// way observes, reconciles and stays diagnosable, but never signs — see abstainRestored.
	restoredFrom *uint64
	// executorGenesis is the executor's block ZERO, read from it once via Executor.GenesisBlock.
	//
	// It is deliberately NOT "the first head this process observed". That was the previous
	// revision and it was unsound: a new process can attach to an executor that has already
	// committed blocks, so "this process has not committed" does not imply "nothing has
	// committed", and an arbitrary observed tip — block 99 with an arbitrary hash — was accepted
	// as the configured genesis. Block zero comes from the chain configuration and does not move.
	executorGenesis *BlockRef
	// inRecovery is set while HandleCertificate has DROPPED r.mu to run a recovery attempt against
	// the executor. BFTClient.Run drives certificates sequentially from one goroutine, so a second
	// entry cannot happen — and dropping a lock on the strength of "cannot happen" is exactly the
	// kind of claim that should be enforced rather than believed.
	inRecovery bool
	// warnedRestored keeps the abstention out of the log on every subsequent round; it is a
	// steady state for as long as the process lives, not an event.
	warnedRestored bool
}

// DefaultAwaitTimeout is the fallback when nothing better is known about the shard — see
// Round.awaitTimeout and AwaitTimeoutForT2, which is what production actually uses.
const DefaultAwaitTimeout = 5 * time.Second

/*
completedRound is one round this node has already built, signed and attempted to send, keyed by the
authorization that produced it.

It exists because a re-delivery must not produce a SECOND, DIFFERENT signed request for the same
round. The delivery layer re-drives a certificate whose application failed, and a checkpoint write
is part of applying one — so an ordinary "the store was full" failure, after the round had been
built and sent, re-entered HandleCertificate. The round was then rebuilt against whatever the
executor had by then, and a mempool that had gained one transaction was enough to make the node sign
a different input record for the same round under the same authorizing certificate. Two conflicting
signed statements for one round is what non-equivocation means, whatever the cause.

So the round is made idempotent in its authorization: the same certificate, assigning the same next
round, replays as the same bytes. A genuinely new authorization — a repeat certificate at a later
root round, which assigns a fresh round — is a different key and rebuilds, which is correct.
*/
type completedRound struct {
	round          uint64 // the round this request is for (TechnicalRecord.Round)
	partitionRound uint64 // the certificate that authorized it
	rootRound      uint64
	req            *certification.BlockCertificationRequest
}

func (c *completedRound) authorizes(uc *types.UnicityCertificate, exp Expectation) bool {
	return c != nil && c.round == exp.Round &&
		c.partitionRound == uc.GetRoundNumber() && c.rootRound == uc.GetRootRoundNumber()
}

// MinAwaitTimeout floors the derived budget. A shard with a very short T2 still has to allow the
// leader time to build, seal and publish a block over the local network; below this the follower
// would abstain from rounds nobody was late for.
const MinAwaitTimeout = 200 * time.Millisecond

/*
AwaitTimeoutForT2 derives a follower's missing-leader await budget from the shard's own T2 timeout.
T2 is the inactivity timeout before the root chain instructs the shard to retry, NOT the normal
root or shard round interval. Test lanes use at least 5 seconds. Production should choose T2 with
a substantial margin over both normal round durations (approximately 10x as a starting sizing
rule, to be validated against execution and network latency). This helper does not choose T2.
For valid shard configurations the returned wait is SHORTER than T2.

Why, measured rather than argued. A follower waits for the leader's block SYNCHRONOUSLY: while it
waits it processes nothing else, because HandleCertificate is called from BFTClient's single message
loop. So the await budget is an upper bound on how fast the node can consume certificates. The root
chain issues one per T2 when a shard is not reaching quorum — exactly the situation a dead or silent
leader creates — so a budget longer than T2 means the node consumes certificates strictly slower
than they arrive. It does not merely lose the round it is waiting on; it falls further behind on
every round after it, and never catches up while the condition lasts.

That is not hypothetical. On a four-validator shard with T2=3s and the 5s default, a validator whose
leader had stopped publishing accepted exactly one certificate every 5.00s — the await budget, not
the round rate — logging "awaiting round N: context deadline exceeded" and immediately accepting the
next queued certificate, for as long as it was observed. See docs/design/f1-baseline.md §5.8.

Nothing in the framework was choosing this value: NewRound installed DefaultAwaitTimeout and
SetAwaitTimeout had no caller outside tests, so every deployment ran at 5s whatever its T2 was,
including the ones whose own comment said to set it lower.

Half of T2 is deliberate rather than tuned: it leaves the node the other half to finish the round
and be ready for the next certificate, and it makes the relationship to T2 visible instead of
encoding a constant that happens to work at one configuration.
*/
func AwaitTimeoutForT2(t2 time.Duration) time.Duration {
	if t2 <= 0 {
		return DefaultAwaitTimeout
	}
	d := t2 / 2
	if d < MinAwaitTimeout {
		d = MinAwaitTimeout
	}
	if d > DefaultAwaitTimeout {
		d = DefaultAwaitTimeout
	}
	return d
}

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
		certSigner:   LocalKeySigner(signer),
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

// SetEvidenceBuffer attaches the optional serving buffer, which is then fed by every certificate
// this node handles. Safe to call, or not, at any point before Run starts.
/*
SetRecovery attaches the authenticated-evidence recovery lifecycle, and the finality gate it shares
with this round's own executor calls.

Call after NewRound, before Run. A Round with none behaves exactly as it did before any of §6 existed
— it observes, reconciles from what it saw itself, and refuses when it cannot — which is what makes
this a deployment decision rather than a change to the protocol.
*/
func (r *Round) SetRecovery(s *RecoveryStack) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recovery = s
	if s != nil {
		r.finality = s.Gate
		// The stack owns the buffer's feed, so the standalone one is cleared rather than left to
		// run alongside it. Two feeds would hand the buffer every certificate twice; it refuses the
		// duplicate correctly, but a design that relies on a component refusing what we chose to
		// send it twice is one bug away from relying on it accepting.
		r.evidence = nil
	}
}

func (r *Round) SetEvidenceBuffer(b *EvidenceBuffer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evidence = b
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
/*
SetCertificationSigner routes this round's certification requests through the given signer, in place
of the local key. Call after NewRound, before Run.

This is how a deployment turns on an independent signing authority (#105), and it is deliberately a
separate, explicit step: nothing about constructing a round switches it on, and the round is handed a
signer it cannot create, cannot configure and cannot bypass. If the signer refuses, this node
abstains; it never falls back to the local key.
*/
func (r *Round) SetCertificationSigner(s CertificationSigner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == nil {
		return
	}
	r.certSigner = s
}

func (r *Round) SetHealth(h *Health) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = h
	if r.restoredFrom != nil {
		// Report it immediately rather than on the first certificate: a node that is up but not
		// yet receiving UCs must not read as a voting validator in the meantime.
		r.health.updateVoting(false, nonVotingRestored)
	}
}

// nonVotingRestored is the health reason for the P-sign gate — see MarkRestored.
const nonVotingRestored = "restored from a persisted certificate: non-voting until the monotonic signing contract (#105) exists"

/*
MarkRestored records that this process resumed from a persisted certificate for partition round
`round`, which makes it NON-VOTING for its whole lifetime. Call before Run; node.go calls it exactly
when the checkpoint produced a certificate that authenticated (see New).

Why a node that just proved its checkpoint genuine may not vote (design §6.1, #105). Verification
establishes that the file is authentic, not that it is CURRENT. An entire older checkpoint replays
perfectly: every signature, context check and consecutive-round check holds for a file whose latest
certificate is round 12 while the shard has reached round 13. Restoring it rolls the observation
cursor backwards, and that cursor is what stops this node acting twice in one round — so a node
resumed from a stale file can re-enter partition rounds it has already voted in and sign again.
That is a safety problem, not a liveness one, and it is not detectable from the file, from the
certificates, or from the executor (after a run of quiet rounds the executor's head is the same
whatever the current round is).

This is not a hypothetical staleness either: the checkpoint is written by persistingDriver AFTER
HandleCertificate returns, and HandleCertificate has by then already SUBMITTED for the next round.
So a saved certificate for round N always coexists with a vote this node cast in round N+1, and
`luc.RoundNumber` is by construction behind the highest round it has signed in. A restart followed
by a repeat certificate for N+1 — which is exactly what the root chain sends when it times out
waiting — puts the node back in a round it has already voted in, free to submit a different input
record for it.

Closing it needs a monotonic, crash-safe, non-rollback record of the highest round this node has
SIGNED in, held independently of the replayable evidence file — #105's subject, not this PR's. Until
that exists the fail-closed side is the only sound one, and this is that side, made explicit rather
than left to be implied by the absence of an anchor: an anchor gate alone lets one non-quiet
certificate re-authorize a restored process a round later, which is the same hazard with a delay.

What it withholds is exactly the vote. It still observes every certificate, keeps its continuity
state, reconciles and commits so its executor stays with the shard, and — this matters for liveness —
still builds and disseminates the block in the rounds it leads, because publishing a block is not
signing a statement about one. See the gate in HandleCertificate for what happened when it withheld
that too.

The cost is real and deliberate: a restarted validator contributes no certification requests until
it is restarted again with #105's contract in place, so a shard that restarts more than its quorum
margin stalls.
*/
func (r *Round) MarkRestored(round uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restoredFrom = &round
	// Reported as soon as it is known, in whichever order the two are wired: a node that is up
	// but not yet receiving certificates must not read as a voting validator in the meantime.
	r.health.updateVoting(false, nonVotingRestored)
}

// HandleCertificate is the framework's single entry point, called for every
// UC classified as UCValid or UCRepeat — and, once, for a UCDuplicate of a
// certificate whose previous delivery failed, which is how a failed apply is
// retried (see BFTClient.handleCertificationResponse). It observes the
// certificate, commits the previous round's result, and then drives the round
// tr describes. Every step is idempotent, because that retry re-runs all of
// them.
func (r *Round) HandleCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.inRecovery {
		// See Round.inRecovery. Reaching this means a second certificate is being handled while the
		// first has the lock dropped, which BFTClient.Run does not do — so it is a wiring fault in
		// whatever is driving this Round, and continuing would interleave two rounds.
		return fmt.Errorf("shardnode: HandleCertificate re-entered while a recovery attempt is running off the round lock — certificates must be driven sequentially")
	}

	// OBSERVATION COMES FIRST, BEFORE ANY FALLIBLE APPLICATION. uc is authenticated evidence
	// (P-ctx, verified by BFTClient) about what the root chain certified; whether this node then
	// manages to apply it is a separate question with a separate answer. Folding it in here means
	// a certified block hash is recorded even when the Commit below fails.
	//
	// This ordering is load-bearing, not cosmetic (design §5, §5.1). commitPrevious clears
	// r.pending and then commits; when that Commit returns SYNCING it returns an error and the
	// round ends. With observation after it, the certificate that named the block was never
	// recorded, so the next quiet certificate found no anchor and refused `no-anchor` — a
	// transient, retryable executor failure turned into a permanent inability to recover, with
	// the payload sitting right there. `anchor.round > appliedRound` is the normal retryable
	// state; the anchor must therefore be written when its certificate verifies, never when it
	// is applied.
	//
	// If uc is non-quiet it becomes the anchor, so reconcile targets this very block — the
	// behaviour that always worked. If uc is quiet the anchor stays where the last state-changing
	// round put it, which is exactly the target that used to be missing.
	// EVERY certificate is traced, not only the ones that change something. #92's open restart
	// refusals turn on which round arrived versus which round the previous certificate ASSIGNED,
	// and on whether an anchor was ever held — none of which can be recovered afterwards from a
	// line that was only written when the state moved. The cost is one debug line per certificate.
	obs := r.continuity.observeTraced(uc, tr.Round)
	if r.log != nil {
		r.log.LogAttrs(ctx, slog.LevelDebug, "continuity: observed certificate",
			append(obs.LogAttrs(),
				slog.Uint64("rootRound", uc.GetRootRoundNumber()),
				slog.String("nodeID", r.nodeID))...)
	}

	// RETENTION FOR OTHER NODES, alongside this node's own observation and under the same rule:
	// before anything fallible, and never able to fail the round. What is retained is what this
	// node has already authenticated, so retaining it costs no trust; failing to retain it costs
	// only this node's ability to help somebody else recover, which is an availability property and
	// is logged rather than escalated. A refusal here means the buffer would not stand behind what
	// it was handed — a defect on this delivery path, not a reason to stop building rounds.
	if r.evidence != nil {
		if err := r.evidence.Observe(uc, tr); err != nil && r.log != nil {
			r.log.LogAttrs(ctx, slog.LevelWarn, "evidence buffer refused an observation",
				slog.String("err", err.Error()),
				slog.Uint64("round", uc.GetRoundNumber()),
				slog.String("nodeID", r.nodeID))
		}
	}
	// The recovery lifecycle observes here too, and for the same reason: this is the one place a
	// certificate and the technical record bound to it arrive together, already authenticated. Both
	// halves get the same feed — what a node retains for others and what it may later reason from
	// about itself are the same certificates, and letting them diverge would mean a node able to
	// prove something to a peer that it could not prove to itself.
	r.recovery.observe(ctx, uc, tr, r.nodeID)

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
	if r.executorGenesis == nil {
		g, gerr := r.executor.GenesisBlock(ctx)
		if gerr != nil {
			return fmt.Errorf("reading executor genesis block: %w", gerr)
		}
		r.executorGenesis = &g
	}

	// THE GENESIS PATH, gated. exp.PreviousHash is empty exactly when the root chain has certified
	// nothing for this shard, so the executor must still be at its own genesis block. Without this
	// a node whose executor is at some arbitrary later block signs the shard's first round on it,
	// and every check downstream is then anchored to that block.
	if len(exp.PreviousHash) == 0 && !sameBlockRef(head, *r.executorGenesis) {
		r.metrics.recordIRDivergence(ctx, "identity_genesis_head_mismatch")
		r.health.updateVoting(false, "executor is not at its configured genesis block")
		return fmt.Errorf("shardnode: the root chain has certified nothing for this shard yet, so the executor must be at its genesis block %d/%x, but its head is %d/%x — refusing to build round %d",
			r.executorGenesis.Number, r.executorGenesis.Hash, head.Number, head.Hash, exp.Round)
	}
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

	// P-id, evaluated for EVERY round and EVERY process (§4). The state root is now equal — either
	// it always was, or reconcile just made it so — and that is not sufficient on its own: two
	// different blocks can share a post-state, so a node that missed a non-quiet interval and came
	// back to the same state root by a different block would otherwise sign on the wrong block
	// (§3.3.1, row 2). An earlier revision of the transition table had precisely that fast path
	// and it was removed as unsound.
	//
	// The VOTING verdict is applied further down, immediately before signing, and the round is
	// otherwise driven to completion — see the gate there for why refusing to build was measurably
	// worse. The LEADERSHIP verdict is applied before Build, below.
	//
	// A restored process is NOT exempt from the check, though an earlier revision made it so on
	// the grounds that it may not vote anyway. That confused two requirements: P-sign decides
	// whether a node may SIGN, P-id decides whether it may make its execution client FINALIZE a
	// block. A restored node holds no anchor and so cannot satisfy P-id, which is precisely why it
	// must not lead — skipping the check let it reach Build, and Build sets head, safe and
	// finalized to the parent. Being unable to vote is not an exemption from the identity
	// requirement for finality-changing Engine calls.
	var identityErr error
	if len(exp.PreviousHash) > 0 {
		// head may move: a successful evidence recovery commits the certified block, and the parent
		// every later step builds on is the executor's head AFTER that, not before.
		head, identityErr = r.identityCheck(ctx, uc, head, exp)
	}
	if identityErr != nil && r.log != nil {
		// The other half of the trace: what the executor actually reported when the refusal was
		// decided. Without it the log says which rule fired but not against what.
		r.log.LogAttrs(ctx, slog.LevelDebug, "continuity: refusal operands",
			slog.Uint64("round", exp.Round),
			slog.String("refusal", identityErr.Error()),
			slog.Uint64("headNumber", head.Number),
			slog.String("headBlock", fmt.Sprintf("%x", head.Hash)),
			slog.String("headStateRoot", fmt.Sprintf("%x", head.StateRoot)),
			slog.String("certifiedPreviousHash", fmt.Sprintf("%x", exp.PreviousHash)),
			slog.Uint64("continuityThrough", r.continuity.through),
			slog.Uint64("expectedNext", r.continuity.expectedNext),
			slog.Bool("anchorHeld", r.continuity.anchor != nil),
			slog.String("anchorBlock", anchorHashForLog(r.continuity.anchor)))
	}

	// REPLAY OF AN AUTHORIZATION ALREADY ANSWERED. Everything above this point is idempotent by
	// construction — observing a certificate twice changes nothing, and commitPrevious commits only
	// what the certificate certifies — but building is not: it would produce a fresh candidate from
	// whatever the executor holds now. Re-send exactly what was signed for this authorization.
	if r.completed.authorizes(uc, exp) {
		if r.log != nil {
			r.log.DebugContext(ctx, "re-delivery of an authorization already answered: re-sending the identical signed request",
				slog.Uint64("round", exp.Round), slog.Uint64("partitionRound", uc.GetRoundNumber()))
		}
		return r.send(ctx, r.completed.req, exp.Round)
	}

	sealHash, err := SealHash(uc)
	if err != nil {
		return fmt.Errorf("reading certificate seal hash: %w", err)
	}

	// LEADERSHIP REQUIRES P-id, because building is not a neutral act. Executor.Build asks the
	// execution client to move its forkchoice to the parent — engineapi sends head, safe AND
	// finalized as p.Parent.Hash — so a leader that builds on a head it cannot prove is certified
	// makes the client finalize that head, before any vote is withheld and beyond any later
	// undoing. Following is different: a follower awaits and verifies, and engineapi's Verify is
	// newPayload only, which stores the payload without moving the forkchoice. So an abstaining
	// node keeps receiving payloads — which is what lets it recover — and does not lead.
	leader := tr.Leader
	if identityErr != nil && leader == r.nodeID {
		r.metrics.recordIRDivergence(ctx, "identity_declined_leadership")
		if r.log != nil {
			r.log.WarnContext(ctx, "declining to lead this round: cannot prove the executor is on the certified block, and building would finalize it",
				slog.Uint64("round", exp.Round), slog.String("reason", identityErr.Error()),
				slog.Bool("restored", r.restoredFrom != nil))
		}
		r.health.updateVoting(false, r.nonVotingReason(identityErr))
		return nil
	}

	block, params, err := r.produceBlock(ctx, head, exp, sealHash, leader)
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

	// Recorded before the gate below, and deliberately: a non-voting node still commits what the
	// shard certifies, so it stays a warm follower rather than drifting behind and needing
	// recovery on every round.
	r.pending = &pendingSubmission{round: exp.Round, hash: block.Hash, needsCommit: executorChanged, submittedAt: time.Now()}

	// P-id's verdict (§4 rows 2, 8, 10). Withholding the SIGNATURE is the whole of it; the block
	// above was still built or verified, and commitPrevious will still apply what the shard
	// certifies, so this node stays with the chain instead of falling off it.
	//
	// It used to refuse before produceBlock, which is what the transition table's "abstain: do not
	// build" says. Measured on a four-validator real-reth devnet, that reading is self-defeating:
	// a node that does not build also never runs Verify, so its execution client never receives the
	// payload, so it cannot commit the block, so it is permanently behind — and the row's own
	// requirement to "stay recoverable" fails. Building keeps the executor in lockstep, and the
	// next non-quiet certificate then installs an anchor that matches its head, which re-arms
	// voting on its own. The safety property is untouched: no certification request is signed
	// while this node cannot prove which certified block it stands on.
	if identityErr != nil {
		r.health.updateVoting(false, r.nonVotingReason(identityErr))
		if r.log != nil {
			r.log.WarnContext(ctx, "abstaining from the vote: this node cannot prove its executor is on the certified block",
				slog.Uint64("round", exp.Round), slog.String("reason", identityErr.Error()))
		}
		return nil
	}

	// P-sign (§4, §6.1). THE VOTE is what a restored process withholds — not its participation.
	// It has by now observed the certificate, reconciled, and built or verified this round's block
	// and disseminated it if it is the leader; what it does not do is sign a certification request
	// for it. Nothing below this line runs, so no request is ever signed, not merely never sent.
	//
	// That distinction is load-bearing and was measured, not assumed. An earlier revision returned
	// before produceBlock, so a restored LEADER published nothing and every validator in the rounds
	// it led timed out awaiting a proposal: scripts/chaos-evm.sh -v 7 stalled at the cold-restart
	// scenario with quorum numerically intact. Disseminating a block is not signing a statement
	// about it, so withholding it buys no safety and costs the shard every round this node leads.
	if r.abstainRestored(ctx, exp) {
		return nil
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
	// Signing goes through the configured signer, and its refusal is final for this round.
	//
	// A refusal is not a delivery failure: the certificate has been observed, committed and
	// reconciled by everything above, so this node keeps following the shard and abstains from the
	// vote. What it must not do is get a different answer — rebuilding the candidate, retrying with
	// other bytes, or signing locally because the authority said no would each defeat the record
	// that produced the refusal (§8.3).
	signed, err := r.certSigner.Sign(ctx, uc, tr, req)
	if err != nil {
		r.metrics.recordIRDivergence(ctx, "signing_declined")
		r.health.updateVoting(false, signingDeclinedReason(err))
		if r.log != nil {
			r.log.WarnContext(ctx, "abstaining from the vote: the certification request was not signed",
				slog.Uint64("round", exp.Round), slog.String("err", err.Error()))
		}
		return nil
	}
	req = signed

	// Retained before the send, not after it: what must not change on a replay is the SIGNED
	// bytes, and they exist from here on whether or not the send succeeds.
	r.completed = &completedRound{
		round:          exp.Round,
		partitionRound: uc.GetRoundNumber(),
		rootRound:      uc.GetRootRoundNumber(),
		req:            req,
	}
	r.health.updateSubmitted(exp.Round)
	r.health.updateVoting(true, "")

	if r.log != nil {
		r.log.InfoContext(ctx, "submitting block certification request",
			slog.Uint64("round", exp.Round), slog.Bool("quiet", irQuiet), slog.Bool("leader", leader == r.nodeID))
	}
	return r.send(ctx, req, exp.Round)
}

// ErrSubmissionFailed marks a failure to SEND an already-applied round's certification request.
//
// It exists so the delivery layer can tell the two halves of HandleCertificate apart. Everything
// before the send is APPLICATION — observing the certificate, committing what it certified,
// reconciling — and if that fails the certificate should be retried. The send is not: by the time
// it runs, the certificate in hand has been fully applied, and what failed belongs to the NEXT
// round's proposal. Treating the two the same is what let a transport error cause a
// retransmission to re-enter the round and commit an uncertified proposal.
var ErrSubmissionFailed = errors.New("shardnode: certification request was not sent")

// submitRetries is how many extra times an uncertain send is retried with the SAME signed bytes.
// Small on purpose: the request is only useful while its round is current, and the root chain
// discards a stale one. Re-signing is never an option — a retry must not put different bytes for
// the same round on the wire.
const submitRetries = 2

const submitRetryInterval = 100 * time.Millisecond

func (r *Round) send(ctx context.Context, req *certification.BlockCertificationRequest, round uint64) error {
	var err error
	for attempt := 0; ; attempt++ {
		if err = r.submitter.Submit(ctx, req); err == nil {
			return nil
		}
		if attempt >= submitRetries || ctx.Err() != nil {
			break
		}
		if r.log != nil {
			r.log.WarnContext(ctx, "retrying the certification request send with the same signed bytes",
				slog.Uint64("round", round), slog.Int("attempt", attempt+1), slog.String("err", err.Error()))
		}
		select {
		case <-ctx.Done():
		case <-time.After(submitRetryInterval):
		}
	}
	r.metrics.recordIRDivergence(ctx, "submit_failed")
	return fmt.Errorf("%w for round %d after %d attempts: %w", ErrSubmissionFailed, round, submitRetries+1, err)
}

// nonVotingReason reports the most actionable reason this node is not voting. A restored process is
// non-voting for its whole lifetime whatever else is true, so that fact leads; an identity refusal
// on top of it is the detail.
// nonVotingSigningDeclined prefixes the health reason when the signer refused, so an operator can
// tell "this node could not prove where it stands" (P-id) from "this node was not permitted to sign"
// (the authority's record, fencing, or its absence).
const nonVotingSigningDeclined = "the certification request was not signed"

func signingDeclinedReason(err error) string {
	return nonVotingSigningDeclined + ": " + err.Error()
}

func (r *Round) nonVotingReason(identityErr error) string {
	if r.restoredFrom != nil {
		if identityErr != nil {
			return nonVotingRestored + " (and " + identityErr.Error() + ")"
		}
		return nonVotingRestored
	}
	return identityErr.Error()
}

// identityCheck evaluates P-id (§4 rows 1, 2, 8, 10, 13) and returns the named refusal, or nil.
// It decides nothing on its own: HandleCertificate applies the verdict at the signing gate, so the
// diagnostic is computed from the head as it was BEFORE this round's block was built while the
// consequence lands where it belongs.
func (r *Round) identityCheck(ctx context.Context, uc *types.UnicityCertificate, head BlockRef, exp Expectation) (BlockRef, error) {
	err := r.continuity.checkHeadIdentity(head, Hash(exp.PreviousHash), r.executorGenesis)
	if err == nil {
		return head, nil
	}
	var rte *recoveryTargetError
	reason := "unknown"
	if errors.As(err, &rte) {
		reason = rte.reason
	}
	// The state agrees and this node still cannot name the block that produced it — row 8 after a
	// restart, row 10 after a missed certificate. reconcile is never entered on this path, because
	// there is nothing to reconcile: the executor is exactly where the certificate says. What is
	// missing is the IDENTITY, and authenticated evidence supplies precisely that.
	//
	// Applying it here commits a block the executor may already hold as canonical, which the
	// Executor contract makes a no-op returning VALID. It restores P-id and NOTHING ELSE: a
	// restored process still does not vote, because that gate is restoredFrom and #105, and it is
	// enforced separately further down. Recovering an execution identity is not re-authorization.
	if newHead, res, ok := r.applyVerifiedAnchor(ctx, uc, exp, head); ok {
		if idErr := r.continuity.checkHeadIdentity(newHead, Hash(exp.PreviousHash), r.executorGenesis); idErr == nil {
			r.metrics.recordIRDivergence(ctx, "identity_recovered_from_evidence")
			return newHead, nil
		}
		head = newHead
	} else if res.Outcome != ApplyNotAttempted {
		r.metrics.recordIRDivergence(ctx, "identity_evidence_"+strings.ReplaceAll(res.Outcome.String(), "-", "_"))
	}
	r.recovery.seek(ctx, reason, r.nodeID)

	r.metrics.recordIRDivergence(ctx, "identity_"+strings.ReplaceAll(reason, "-", "_"))
	return head, fmt.Errorf("shardnode: executor head is not the certified execution head for round %d (%w) — refusing to build or sign; a matching state root is not evidence of the same block (see docs/troubleshooting.md)",
		exp.Round, err)
}

// abstainRestored reports whether this round must stop short of building and signing because the
// process was resumed from a persisted certificate — see MarkRestored for why that is a safety
// gate and not a convenience. Everything before it in HandleCertificate (observation, commit,
// reconciliation) has already happened; only the vote is withheld.
func (r *Round) abstainRestored(ctx context.Context, exp Expectation) bool {
	if r.restoredFrom == nil {
		return false
	}
	r.metrics.recordIRDivergence(ctx, "restored_non_voting")
	r.health.updateVoting(false, nonVotingRestored)
	if r.log != nil {
		if !r.warnedRestored {
			r.warnedRestored = true
			r.log.WarnContext(ctx, "resumed from a persisted certificate: this node follows and reconciles but will NOT vote until the monotonic signing record (#105) exists — restart is not by itself authorization to sign (design §6.1)",
				slog.Uint64("restoredFromRound", *r.restoredFrom), slog.Uint64("round", exp.Round))
		} else {
			r.log.DebugContext(ctx, "abstaining: restored process is non-voting", slog.Uint64("round", exp.Round))
		}
	}
	return true
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

	// Does this certificate decide the round this node proposed for? If not, the proposal is still
	// outstanding and must be left where it is: consuming it here meant that one re-delivery of an
	// earlier certificate silently discarded the record of a round that was about to be certified.
	ir := uc.InputRecord
	if ir == nil || ir.RoundNumber != p.round {
		r.metrics.recordIRDivergence(ctx, "commit_not_certified")
		if r.log != nil {
			r.log.DebugContext(ctx, "not committing: this certificate is not about the round this node proposed for",
				slog.Uint64("proposedRound", p.round), slog.Uint64("certifiedRound", uc.GetRoundNumber()))
		}
		return nil
	}
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

	// NOTHING IS COMMITTED THAT THIS CERTIFICATE DOES NOT CERTIFY.
	//
	// r.pending is a PROPOSAL: the block this node built or verified for the round it last
	// submitted. Committing is a different act — for the Engine adapter it sets head, safe and
	// FINALIZED — and it may only ever apply to a block the root chain has certified.
	//
	// The two were conflated, and a plain transport failure was enough to expose it. Submit
	// returning an error ended HandleCertificate with the next round's proposal already installed
	// as pending; BFTClient recorded the certificate as unapplied; the retransmission re-entered
	// HandleCertificate; and commitPrevious finalised that uncertified proposal. Nothing later can
	// undo a finalisation.
	//
	// So the target comes from the certificate, and only when the certificate is about the round
	// this node proposed for. A certificate for another round — a replay of the one before it, a
	// repeat of an earlier round — certifies nothing about the proposal and commits nothing.
	if len(ir.BlockHash) == 0 {
		// The round was certified QUIET: the root chain says no block was produced, whatever this
		// node built. There is nothing certified to commit.
		r.metrics.recordIRDivergence(ctx, "commit_certified_quiet")
		return nil
	}
	target := Hash(ir.BlockHash)
	if !bytes.Equal(target, p.hash) && r.log != nil {
		// Following the root chain's decision means committing ITS block, not this node's. The
		// previous revision logged this line and then committed p.hash anyway — and compared the
		// certified STATE root against a BLOCK hash to decide whether to log it, so it fired on
		// every ordinary non-quiet round against a real executor.
		r.log.WarnContext(ctx, "the certified block differs from the one this node proposed — committing the certified one",
			slog.String("certified", fmt.Sprintf("%x", target)), slog.String("proposed", fmt.Sprintf("%x", p.hash)))
	}
	status, err := r.commitFinal(ctx, "round-commit", target)
	if err != nil {
		return err
	}
	if status != StatusValid {
		r.metrics.recordIRDivergence(ctx, "commit_failed")
		return fmt.Errorf("shardnode: executor could not commit round %d (hash %x, status %s) — this node has fallen behind and needs to resync (see docs/troubleshooting.md)",
			p.round, target, status)
	}
	return nil
}

// sameBlockRef compares two heads by every field that identifies a block. Number and state root
// alone are not identity — that is the whole subject of P-id — and neither is a hash on its own.
/*
commitFinal and buildFinal are the only ways this file reaches a finality-changing executor call.

The gate is taken per OPERATION rather than for the whole round. Holding it across HandleCertificate
would be simpler and wrong in one specific way: recovery from authenticated evidence is applied from
inside reconcile, and the applier takes the gate for its own commit — a round-wide hold would have
the round waiting on itself.

A nil gate means an unwired node, where Round.mu is still the only concurrency there is. That is the
pre-recovery arrangement and it stays correct on its own; the gate is what keeps it correct once a
second thing can commit.
*/
/*
applyVerifiedAnchor makes one bounded recovery attempt and, if the executor reaches the certified
block, adopts the verified anchor as this node's own.

IT RUNS OFF THE ROUND LOCK. Review found the attempt — Commit, Head, sometimes GenesisBlock, plus
re-verifying a retained bundle — running under r.mu, where nothing else about this node can be read
or configured until an executor answers. The shape is snapshot, execute, revalidate, install:

  - SNAPSHOT while the lock is held. Everything the attempt is about is already a value: the
    certificate, the expectation derived from it, and the head just read. Nothing is re-read
    off-lock.
  - EXECUTE with the lock dropped, so a slow or unreachable executor delays only this round.
  - REVALIDATE and INSTALL under the lock again. The anchor is adopted only if it still explains the
    state THIS round is building on — the snapshot's, not whatever is current — so an attempt that
    was overtaken installs nothing rather than installing something about another round.

DROPPING A LOCK MID-OPERATION IS A CLAIM, so it is enforced rather than assumed: BFTClient.Run calls
HandleCertificate sequentially from one goroutine, and inRecovery below makes a second entry while
the lock is dropped a loud refusal instead of a silent interleaving.

BOTH HALVES, OR NEITHER. Committing the block without installing the anchor leaves this node at the
right block and still unable to say which block produced the state — so P-id goes on refusing and the
next certificate re-commits a block the executor already holds. Installing the anchor without the
commit would be worse: it would claim an execution identity the executor does not have. The predicate
established both facts at once, so they are adopted together.

The interval adopted is exactly what was verified: the anchor's block, quiet through the round this
certificate carries, with the next round taken from the authenticated technical record (exp.Round) —
the same assignment the live path uses, never round+1.
*/
func (r *Round) applyVerifiedAnchor(ctx context.Context, uc *types.UnicityCertificate, exp Expectation, head BlockRef) (BlockRef, ApplyResult, bool) {
	if r.recovery == nil || r.recovery.Applier == nil {
		return head, ApplyResult{Outcome: ApplyNotAttempted}, false
	}
	// The snapshot. Every operand is copied out before the lock is dropped; nothing below reads
	// Round state until it is held again.
	snapCertifiedState := Hash(bytes.Clone(exp.PreviousHash))
	snapRound, snapNext := uc.GetRoundNumber(), exp.Round

	r.inRecovery = true
	r.mu.Unlock()
	newHead, res, ok := r.recovery.apply(ctx, uc, head, r.nodeID)
	r.mu.Lock()
	r.inRecovery = false

	if !ok {
		return newHead, res, false
	}
	// Revalidate against the SNAPSHOT. The anchor must explain the state this round was asked to
	// build on; anything else is an answer about a different question, and installing it would put
	// this node's own cursor somewhere no certificate it holds points.
	//
	// Redundant as the code stands, and kept deliberately: TargetApplier.Apply already refuses a
	// target whose state does not match the binding it was given, and that binding is built from
	// the same certificate this snapshot came from. What this line states is the property that
	// makes dropping the lock safe, so that a future change to either side has to break it visibly
	// rather than silently. No fixture reaches it, and no mutation of it fails a test — that is a
	// property of it being unreachable, not of it being untested, and it is recorded here rather
	// than implied.
	if res.Target == nil || !bytes.Equal(res.Target.StateRoot, snapCertifiedState) {
		if r.log != nil {
			r.log.WarnContext(ctx, "a recovery attempt completed for a state this round is not building on; nothing installed",
				slog.String("certifiedState", fmt.Sprintf("%x", snapCertifiedState)),
				slog.String("anchorState", fmt.Sprintf("%x", anchorStateForLog(res.Target))),
				slog.Uint64("round", snapRound))
		}
		return newHead, res, false
	}
	r.continuity.installVerified(res.Target, snapRound, snapNext)
	return newHead, res, true
}

func anchorStateForLog(a *ExecutionAnchor) string {
	if a == nil {
		return "none"
	}
	return fmt.Sprintf("%x", a.StateRoot)
}

func (r *Round) commitFinal(ctx context.Context, who string, hash Hash) (Status, error) {
	if r.finality != nil {
		release, err := r.finality.acquire(ctx, who)
		if err != nil {
			return StatusSyncing, err
		}
		defer release()
	}
	return r.executor.Commit(ctx, hash)
}

func (r *Round) buildFinal(ctx context.Context, params RoundParams) (BuildID, error) {
	// Build sets head, safe and finalized on the parent before any payload exists, so it changes
	// finality even though it reads as "start a block".
	if r.finality != nil {
		release, err := r.finality.acquire(ctx, "build")
		if err != nil {
			return "", err
		}
		defer release()
	}
	return r.executor.Build(ctx, params)
}

func sameBlockRef(a, b BlockRef) bool {
	return a.Number == b.Number && bytes.Equal(a.Hash, b.Hash) && bytes.Equal(a.StateRoot, b.StateRoot)
}

// reconcile is the crash-recovery path: head diverges from what uc just
// certified, and r.pending — the in-memory record commitPrevious would
// normally use — is empty, because it never survives a restart. That does
// not necessarily mean the certified block is lost: an Executor backed by
// a persistent store may still have it sitting right there, simply never
// finalized because the process died between submitting the request and
// processing the confirming UC.
//
// MEASURED CORRECTION (issue #92 stage 2, scripts/reth-payload-retention.sh).
// This used to assert that "reth writes a block to disk the moment
// newPayload succeeds, before any forkchoiceUpdate makes it canonical".
// Against the pinned client that holds only WITHIN an execution-client
// process lifetime: forkchoiceUpdated to an accepted-but-unfinalised block
// returns VALID while the client lives, and after restarting the CLIENT on
// the same datadir the same target returns SYNCING — unavailable for
// immediate forkchoice, which is not a claim that it is invalid or
// physically gone.
//
// Which restart happened therefore matters. A shard-node-only restart
// leaves the executor running, so it does not by itself destroy the block
// and this path can work — but that is not a guarantee the executor ever
// received or still holds the payload; only the executor's own answer
// establishes that. An execution-client restart leaves the target
// unavailable for immediate forkchoice, and the payload has to be
// re-acquired. See docs/design/f6b-quiet-uc-recovery.md §1.1 for the
// restart matrix.
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

	// THE TARGET. Commit is keyed by block hash everywhere in this file, never by state root.
	//
	// This used to be uc.InputRecord.BlockHash unconditionally, which is the #92 defect: a quiet
	// certificate carries nil there by construction (BuildInputRecord), so a node behind a
	// state-changing block that received a quiet certificate asked its executor to commit
	// nothing. The fake tolerated it by reporting SYNCING; the Engine API adapter rejects a
	// non-32-byte hash outright, which is why a fake-only chaos suite never surfaced it.
	//
	// The target now comes from the live continuity state (anchor.go). When uc is NON-QUIET this
	// is uc's own block — observe installed it a moment ago, so the previous behaviour is
	// unchanged. When uc is QUIET it is the last state-changing certified block, which is the
	// value that was missing. Commit(nil) is unreachable: recoveryTarget refuses rather than
	// returning an empty hash.
	blockHash, targetErr := r.continuity.recoveryTarget(Hash(exp.PreviousHash))
	if targetErr != nil {
		var rte *recoveryTargetError
		reason := "unknown"
		if errors.As(targetErr, &rte) {
			reason = rte.reason
		}

		// THE #92 PATH. This node cannot say which certified block produced the state it is being
		// asked to build on — `no-anchor` after a restart, or `continuity-gap` after a missed
		// certificate. Everything it observed itself is exhausted; authenticated evidence from a
		// peer is the remaining way to name that block, and it is subject to exactly the same
		// checks its own observations were (§3, §6.3).
		//
		// The attempt comes BEFORE the refusal and the refusal still stands if it fails, so a node
		// without the lifecycle wired, or one whose peers cannot help, ends exactly where it did
		// before: refusing, with the reason named.
		if newHead, res, ok := r.applyVerifiedAnchor(ctx, uc, exp, head); ok {
			r.metrics.recordIRDivergence(ctx, "recovery_from_evidence")
			if r.log != nil {
				r.log.InfoContext(ctx, "recovered from authenticated peer evidence: the certified block is committed",
					slog.Uint64("round", exp.Round),
					slog.String("blockHash", fmt.Sprintf("%x", newHead.Hash)),
					slog.String("liveAnchorRefusal", reason))
			}
			return newHead, nil
		} else if res.Outcome != ApplyNotAttempted {
			r.metrics.recordIRDivergence(ctx, "recovery_evidence_"+strings.ReplaceAll(res.Outcome.String(), "-", "_"))
		}
		// Ask for evidence for NEXT time. A fetch does not complete inside this round — it is
		// bounded background work off this lock (§6.3) — so the certificate that discovers the gap
		// starts the attempt and a later one applies it. That is the same rhythm the live path has.
		r.recovery.seek(ctx, reason, r.nodeID)

		r.metrics.recordIRDivergence(ctx, "recovery_"+strings.ReplaceAll(reason, "-", "_"))
		return head, fmt.Errorf("shardnode: executor head %x diverges from root-chain-certified state %x and this node cannot identify the certified block to recover to (%w) — refusing to build round %d; it must resync (see docs/troubleshooting.md)",
			head.StateRoot, exp.PreviousHash, targetErr, exp.Round)
	}

	if r.log != nil {
		r.log.WarnContext(ctx, "executor head diverges from certified state — attempting recovery via Commit before giving up",
			slog.String("executorHead", fmt.Sprintf("%x", head.StateRoot)),
			slog.String("certifiedStateRoot", fmt.Sprintf("%x", exp.PreviousHash)),
			slog.String("recoveryBlockHash", fmt.Sprintf("%x", blockHash)),
			slog.Uint64("anchorRound", r.continuity.anchor.Round),
			slog.Bool("targetFromQuietInterval", len(uc.InputRecord.BlockHash) == 0))
	}

	// Idempotent by contract: Commit on an already-canonical hash is a no-op returning VALID, so
	// a retry after a failed apply is safe and does not double-execute anything.
	status, err := r.commitFinal(ctx, "reconcile", blockHash)
	if err != nil {
		return head, fmt.Errorf("shardnode: recovery commit failed: %w", err)
	}
	switch status {
	case StatusValid:
		// proceed to the post-conditions below
	case StatusSyncing, StatusAccepted:
		// UNAVAILABLE, NOT INVALID. The executor does not have the payload — expected after an
		// execution-client restart (§1.1) and retryable. The anchor is deliberately RETAINED:
		// the authority to retry is exactly what would be lost by dropping it, and the next
		// certificate (likely a repeat) is the next attempt.
		r.metrics.recordIRDivergence(ctx, "recovery_unavailable")
		return head, fmt.Errorf("shardnode: certified block %x is unavailable in the executor (status %s) — cannot build round %d yet; retaining the anchor and retrying on the next certificate",
			blockHash, status, exp.Round)
	default:
		// StatusInvalid: the executor rejected the payload. A fault, not a wait.
		r.metrics.recordIRDivergence(ctx, "recovery_invalid_payload")
		return head, fmt.Errorf("shardnode: executor REJECTED certified block %x with status %s while recovering round %d — this is a fault, not an availability problem; manual recovery required (see docs/troubleshooting.md)",
			blockHash, status, exp.Round)
	}

	newHead, err := r.executor.Head(ctx)
	if err != nil {
		return head, fmt.Errorf("reading executor head after recovery commit: %w", err)
	}
	// BOTH post-conditions, per P-id (§4). State-root equality alone is not sufficient: two
	// different blocks can share a post-state, so a node that checked only the state root could
	// resume on the wrong block and vote on it.
	if !bytes.Equal(newHead.Hash, blockHash) {
		return head, fmt.Errorf("shardnode: recovery commit reported %s but executor head block is %x, not the certified %x — refusing to build round %d",
			StatusValid, newHead.Hash, blockHash, exp.Round)
	}
	if !bytes.Equal(newHead.StateRoot, exp.PreviousHash) {
		return head, fmt.Errorf("shardnode: recovery commit reported %s but executor head state is %x, not the certified %x — refusing to build round %d",
			StatusValid, newHead.StateRoot, exp.PreviousHash, exp.Round)
	}
	if r.log != nil {
		r.log.InfoContext(ctx, "recovered: executor held the certified block, now committed",
			slog.Uint64("round", exp.Round),
			slog.String("blockHash", fmt.Sprintf("%x", blockHash)),
			slog.Uint64("anchorRound", r.continuity.anchor.Round))
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
		id, err := r.buildFinal(ctx, params)
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
