package shardnode

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
The restart boundaries #92's acceptance list asks for, and the acceptance ledger (§1.2.1) recorded
as unestablished: R4, a Commit interrupted in flight, and R5/R6, a process resumed from a
certificate older than the state its executor already holds.

WHAT A "PROCESS RESTART" IS HERE. Exactly one thing survives it, and that is the whole subject:
the executor, and the single certificate FileStore persisted. Everything else — the verified target,
the retained bundle, the applier's budget, the round's continuity anchor, and the record that a
Commit was ever attempted — is process memory and is gone. So each fixture below builds a process,
destroys it, and builds a second one over the SAME executor, driving the second through the
production restoration sequence LoadLUC -> verifyRestoredLUC -> resumeFrom. Reusing the same Round
would test nothing: the point is what a process with no memory of the attempt does.

R5 AND R6 ARE ONE STATE, which is why one fixture covers both. R5 is "the Commit succeeded but the
anchor was not yet adopted"; R6 is "the anchor was adopted but the certificate was not yet
persisted" — adoption happens inside HandleCertificate and persistingDriver calls SaveLUC only after
it returns. The adoption is memory-only either way, so both restarts leave identical durable state:
an older certificate on disk and an executor ahead of it. TestRestart_ResumingOlderThanTheExecutor
asserts that equality directly rather than assuming it.

WHAT THESE FIXTURES DO NOT MODEL, stated so they are not over-read: power loss, an interrupted
write, or any fsync guarantee. The executor is a live process that keeps its state across the shard
node's restart, which is the deployment #92 is about; storage durability is #14's. The delayed case
does retain an executor-side operation across restart and releases its completion independently
of the new process's requests.
*/

// errCommitInterrupted is what an in-flight Commit "returns" when the process it was running in
// dies: nothing. The fixture has to hand the caller something, and an error is the honest choice —
// the one thing the dead process certainly did not learn is the outcome.
var errCommitInterrupted = errors.New("the process died while this Commit was in flight")

// restartExecutor is the execution client: it outlives every shard-node process in these tests,
// which is the arrangement being tested. It answers Head from whatever the last applied Commit left
// it at, so "what does the returning process find" is a fact about the executor rather than a
// parameter of the round.
type restartExecutor struct {
	mu      sync.Mutex
	head    BlockRef
	genesis BlockRef
	// blocks maps a committable block hash to the head committing it produces. It deliberately
	// contains the OLDER block as well as the newer one, so that a node trying to roll its
	// executor back to the checkpoint would succeed — and be caught by assertion — rather than
	// being saved by a fixture that could not express the move.
	blocks  map[string]BlockRef
	commits []Hash

	// interrupt, when set, is consumed by the next Commit and models the process dying during it.
	// applies says what the EXECUTOR did with the call whose answer was lost.
	interrupt *struct{ applies bool }
	// latchNext makes the next Commit ADMIT the operation and leave it running. This is the third
	// thing that can happen to a call whose caller dies: not "it applied" and not "it did not", but
	// "it is still going". The operation belongs to the executor from that moment on — it outlives
	// the process that asked for it and completes on its own, which is what makes it different from
	// a later request that happens to succeed.
	latchNext bool
	pending   *pendingCommit
	// syncingFor makes the next n fresh requests answer SYNCING without applying the block.
	// It tests a retry, not an operation surviving restart; pending models the latter.
	syncingFor int
}

// pendingCommit is one executor-side operation still in progress. release lets the test decide when
// the executor finishes it; done is how the test joins the worker, so a failure cannot leave a
// goroutine running past the test that made it.
type pendingCommit struct {
	hash      Hash
	release   chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (p *pendingCommit) finish() { p.closeOnce.Do(func() { close(p.release) }) }

func newRestartExecutor(head, genesis BlockRef) *restartExecutor {
	return &restartExecutor{head: head, genesis: genesis, blocks: map[string]BlockRef{}}
}

func (e *restartExecutor) Head(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, nil
}

func (e *restartExecutor) GenesisBlock(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.genesis, nil
}

func (e *restartExecutor) Commit(_ context.Context, hash Hash) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commits = append(e.commits, Hash(append([]byte(nil), hash...)))
	if in := e.interrupt; in != nil {
		e.interrupt = nil
		if in.applies {
			e.applyLocked(hash)
		}
		return StatusSyncing, errCommitInterrupted
	}
	if e.latchNext {
		e.latchNext = false
		p := &pendingCommit{
			hash:    Hash(append([]byte(nil), hash...)),
			release: make(chan struct{}),
			done:    make(chan struct{}),
		}
		e.pending = p
		go func() {
			defer close(p.done)
			<-p.release
			e.mu.Lock()
			defer e.mu.Unlock()
			e.applyLocked(p.hash)
			e.pending = nil
		}()
		// The caller is about to die and learns nothing. The operation does not die with it.
		return StatusSyncing, errCommitInterrupted
	}
	if e.pending != nil {
		// A request for a block the executor is already working on starts nothing and applies
		// nothing: it is answered SYNCING, and the operation that will change the head is still the
		// one admitted before the restart.
		return StatusSyncing, nil
	}
	if e.syncingFor > 0 {
		e.syncingFor--
		return StatusSyncing, nil
	}
	e.applyLocked(hash)
	return StatusValid, nil
}

func (e *restartExecutor) applyLocked(hash Hash) {
	if ref, ok := e.blocks[string(hash)]; ok {
		e.head = ref
	}
}

func (e *restartExecutor) Build(context.Context, RoundParams) (BuildID, error) { return "build", nil }

func (e *restartExecutor) Seal(context.Context, BuildID) (Block, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// A quiet block on top of the current head: this shard has nothing to execute, which is the
	// situation the whole quiet-tail design is about.
	return Block{Number: e.head.Number, Hash: e.head.Hash, StateRoot: e.head.StateRoot, ParentHash: e.head.Hash}, nil
}

func (e *restartExecutor) Verify(context.Context, Block, RoundParams) (Status, error) {
	return StatusValid, nil
}

func (e *restartExecutor) currentHead() BlockRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head
}

func (e *restartExecutor) commitTargets() []Hash {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Hash(nil), e.commits...)
}

func (e *restartExecutor) dieDuringNextCommit(applies bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.interrupt = &struct{ applies bool }{applies: applies}
}

// admitAndKeepRunning arms the next Commit to be admitted and left in progress, so that the
// operation survives the process that asked for it.
func (e *restartExecutor) admitAndKeepRunning(t *testing.T) {
	e.mu.Lock()
	e.latchNext = true
	e.mu.Unlock()
	// Whatever the test does or fails to do, the worker is released and joined before the test ends.
	t.Cleanup(func() {
		e.mu.Lock()
		p := e.pending
		e.mu.Unlock()
		if p == nil {
			return
		}
		p.finish()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("the executor's pending operation never finished")
		}
	})
}

func (e *restartExecutor) pendingCommitHash(t *testing.T) Hash {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NotNil(t, e.pending, "the executor should still be working on the admitted operation")
	return e.pending.hash
}

// completePending releases the operation the executor admitted before the restart and waits for it,
// bounded. Nothing else in the test may move the head while this runs.
func (e *restartExecutor) completePending(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	p := e.pending
	e.mu.Unlock()
	require.NotNil(t, p, "there is no pending operation to complete")
	p.finish()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the executor's pending operation never completed")
	}
}

func (e *restartExecutor) answerSyncing(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncingFor = n
}

/*
restartScenario is one shard history, shared by both fixtures.

	round 8   state Z -> state A, block A    assigns 10   <- the certificate that gets persisted
	round 10  state A -> state B, block B    assigns 12   <- the block a returning node must reach
	round 12  quiet at B                     assigns 16
	round 16  quiet at B                     assigns 19   <- the tail, redeliverable to any process
	round 19  quiet at B                     assigns 23
	round 23  quiet at B                     assigns 27
	round 27  quiet at B                     assigns 31

Rounds are non-consecutive throughout, because certified partition rounds are not consecutive and a
fixture that pretended otherwise would not exercise the assigned-round contiguity the evidence
predicate actually uses.

The node under test is named for the leader every technical record assigns, so it WOULD build and
sign each round. That is what makes "it signed nothing" evidence rather than an artifact of a
fixture in which nothing could have been signed; newProcess's control half proves the same
certificates over a process that did not restore do reach a submission.
*/
type restartScenario struct {
	f                              *evidenceFixture
	providerHost                   *network.Peer
	older, source, mid             EvidenceLink
	tail                           []EvidenceLink
	stateA, stateB, blockA, blockB []byte
	behind, ahead, genesis         BlockRef
}

const restartLeader = "leader"

func newRestartScenario(t *testing.T) *restartScenario {
	t.Helper()
	f := newEvidenceFixture(t)
	stateZ, stateA, stateB := h32(0x09), h32(0x0a), h32(0x0b)
	blockA, blockB := h32(0xaa), h32(0xbb)

	s := &restartScenario{
		f:      f,
		older:  f.cert(8, 90, stateZ, stateA, blockA, 10),
		source: f.cert(10, 100, stateA, stateB, blockB, 12),
		mid:    f.cert(12, 110, stateB, stateB, nil, 16),
		tail: []EvidenceLink{
			f.cert(16, 120, stateB, stateB, nil, 19),
			f.cert(19, 130, stateB, stateB, nil, 23),
			f.cert(23, 140, stateB, stateB, nil, 27),
			f.cert(27, 150, stateB, stateB, nil, 31),
		},
		stateA: stateA, stateB: stateB, blockA: blockA, blockB: blockB,
		genesis: BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x02))},
		behind:  BlockRef{Number: 4, Hash: Hash(blockA), StateRoot: Hash(stateA)},
		ahead:   BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)},
	}

	// One node that stayed up and retained what it observed. Its own rounds fail at a stub
	// executor; retention happens before anything fallible, which is the ordering that makes it a
	// provider at all.
	ph := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	providerExec := &headlessExecutor{err: errors.New("the provider's own round is not under test")}
	provider := NewRound("provider", evidencePartitionID, types.ShardID{}, providerExec,
		NewLoopbackDisseminator(), nil, nil, nil)
	stack, err := NewRecoveryStack(
		RecoveryOptions{Serve: true, Buffer: DefaultEvidenceBufferLimits, Transport: DefaultEvidenceTransportLimits},
		RecoveryDeps{Host: ph, Executor: providerExec, PartitionID: evidencePartitionID,
			TrustBases: f.trust, Gate: NewFinalityGate()})
	require.NoError(t, err)
	t.Cleanup(stack.Close)
	provider.SetRecovery(stack)
	for _, l := range append([]EvidenceLink{s.older, s.source, s.mid}, s.tail...) {
		require.Error(t, provider.HandleCertificate(context.Background(), l.UC, l.Technical))
	}
	count, from, to := stack.Buffer.Retained()
	require.Equal(t, 7, count)
	require.EqualValues(t, 8, from)
	require.EqualValues(t, 27, to)
	s.providerHost = ph
	return s
}

// newExecutor returns an execution client at the given head, able to reach either certified block.
func (s *restartScenario) newExecutor(head BlockRef) *restartExecutor {
	e := newRestartExecutor(head, s.genesis)
	e.blocks[string(s.blockA)] = s.behind
	e.blocks[string(s.blockB)] = s.ahead
	return e
}

// newProcess builds one shard-node process over an executor that outlives it: a Round with the
// recovery lifecycle wired to the retaining provider, plus the submitter that records whether
// anything was signed. The caller destroys it by calling the returned stop.
func (s *restartScenario) newProcess(t *testing.T, exec Executor) (*Round, *RecoveryStack, *countingSubmitter, func()) {
	t.Helper()
	h := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	h.Network().Peerstore().AddAddrs(s.providerHost.ID(), s.providerHost.MultiAddresses(), peerstore.PermanentAddrTTL)

	sub := &countingSubmitter{}
	round := NewRound(restartLeader, evidencePartitionID, types.ShardID{}, exec,
		NewLoopbackDisseminator(), s.f.sign, sub, nil)
	round.SetAwaitTimeout(50 * time.Millisecond)
	round.SetHealth(NewHealth())
	stack, err := NewRecoveryStack(
		RecoveryOptions{
			Serve: true, Recover: true,
			Providers: EvidenceProviders{s.providerHost.ID()}, ShardConfHash: s.f.conf,
			Buffer: DefaultEvidenceBufferLimits, Transport: DefaultEvidenceTransportLimits,
			Evidence: DefaultAnchorEvidenceLimits, Budget: DefaultRecoveryBudget, Apply: DefaultApplyBudget,
		},
		RecoveryDeps{Host: h, Executor: exec, PartitionID: evidencePartitionID,
			TrustBases: s.f.trust, Gate: NewFinalityGate()})
	require.NoError(t, err)
	round.SetRecovery(stack)
	stop := func() {
		stack.Close()
	}
	t.Cleanup(stop)
	return round, stack, sub, stop
}

// restore runs the production restoration sequence over a process, from a certificate written to a
// real FileStore: load, authenticate, resume. Nothing here is a shortcut past Node.New's order.
func (s *restartScenario) restore(t *testing.T, round *Round, checkpoint EvidenceLink) {
	t.Helper()
	store := NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
	require.NoError(t, store.SaveLUC(checkpoint.UC))

	loaded, err := store.LoadLUC()
	require.NoError(t, err)
	require.NoError(t, verifyRestoredLUC(loaded, s.f.trust, evidencePartitionID, types.ShardID{}),
		"the checkpoint is genuine — authenticity is not currency, which is the next assertion's subject")

	client := &BFTClient{}
	resumeFrom(client, round, loaded)
	require.NotNil(t, client.luc, "the certificate cursor is restored")
	require.NotNil(t, round.restoredFrom)
	require.Nil(t, round.continuity.anchor, "and no execution anchor came back with it")
}

// deliver drives one certificate from the tail into a process, returning whatever HandleCertificate
// answered. Refusals are ordinary here: a node that cannot name the certified block refuses the
// round, and that refusal is the behaviour under test rather than a test failure.
func (s *restartScenario) deliver(t *testing.T, round *Round, i int) error {
	t.Helper()
	l := s.tail[i]
	return round.HandleCertificate(context.Background(), l.UC, l.Technical)
}

// interruptedCommitInFlight builds a process behind the certified block, drives it until the
// recovery applier is inside Commit, and kills it there. It returns after the process is destroyed,
// so everything the caller then observes is a fact about the executor alone.
func (s *restartScenario) interruptedCommitInFlight(t *testing.T, exec *restartExecutor, applies bool) {
	t.Helper()
	round, stack, sub, stop := s.newProcess(t, exec)

	err := s.deliver(t, round, 0)
	require.Error(t, err, "it cannot name the block that produced the state it is asked to build on")
	require.ErrorContains(t, err, "no-anchor")
	require.Empty(t, exec.commitTargets(), "and it committed nothing on the strength of not knowing")

	st := waitRecovered(t, stack.Requester)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	exec.dieDuringNextCommit(applies)
	err = s.deliver(t, round, 1)
	require.Error(t, err, "the Commit never answered, so the round could not complete")

	attempted := exec.commitTargets()
	require.Len(t, attempted, 1, "exactly one Commit was in flight when the process died")
	require.Equal(t, Hash(s.blockB), attempted[0], "and it named the certified block")
	require.Empty(t, sub.rounds(), "nothing was signed before the interruption either")

	stop() // the process dies here: the verified target, the anchor and the attempt go with it
}

// admittedCommitStillRunning is interruptedCommitInFlight's third sibling: the executor ADMITS the
// Commit and is still working on it when the caller dies. What survives the process is the
// operation, not the Round — the dead process's Go stack unwinds exactly as it would when its
// transport is cancelled.
func (s *restartScenario) admittedCommitStillRunning(t *testing.T, exec *restartExecutor) {
	t.Helper()
	round, stack, sub, stop := s.newProcess(t, exec)

	require.Error(t, s.deliver(t, round, 0))
	st := waitRecovered(t, stack.Requester)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	exec.admitAndKeepRunning(t)
	require.Error(t, s.deliver(t, round, 1), "the Commit was admitted, not answered")
	require.Equal(t, Hash(s.blockB), exec.pendingCommitHash(t),
		"and the executor is still working on the certified block")
	require.Equal(t, Hash(s.blockA), exec.currentHead().Hash, "which has not changed the head yet")
	require.Empty(t, sub.rounds())

	stop()
}

/*
R4: a Commit interrupted in flight, decided after the restart by reading the live executor head.

The returning process cannot know what happened to the call, so it must not carry an assumption
either way. These cases cover both resolved outcomes and a fresh request answered SYNCING.
TestRestart_AnAdmittedCommitCompletesAfterTheProcessIsGone covers an operation still pending at restart.

What must hold in every case: the executor ends on the certified block, no Commit ever names the
block the persisted checkpoint remembers, and nothing is signed.
*/
func TestRestart_InFlightCommitIsDecidedByTheLiveExecutorHead(t *testing.T) {
	t.Run("the interrupted Commit never applied: the returning process redoes it", func(t *testing.T) {
		s := newRestartScenario(t)
		exec := s.newExecutor(s.behind)
		s.interruptedCommitInFlight(t, exec, false)
		require.Equal(t, Hash(s.blockA), exec.currentHead().Hash,
			"the executor is where it was: the call it was given had no effect")

		round, stack, sub, _ := s.newProcess(t, exec)
		s.restore(t, round, s.older)
		before := len(exec.commitTargets())

		require.Error(t, s.deliver(t, round, 0), "the new process holds no anchor either, and says so")
		st := waitRecovered(t, stack.Requester)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.NoError(t, s.deliver(t, round, 1), "with the target re-derived, the round completes")

		require.Equal(t, Hash(s.blockB), exec.currentHead().Hash, "the certified block, reached the second time")
		s.requireNoRollback(t, exec, before)
		require.Empty(t, sub.rounds(), "and a restored process signs nothing, however well it recovered")
	})

	t.Run("the interrupted Commit applied and the answer was lost: no second execution", func(t *testing.T) {
		s := newRestartScenario(t)
		exec := s.newExecutor(s.behind)
		s.interruptedCommitInFlight(t, exec, true)
		require.Equal(t, Hash(s.blockB), exec.currentHead().Hash,
			"the executor applied the block; only the answer was lost")

		round, stack, sub, _ := s.newProcess(t, exec)
		s.restore(t, round, s.older)
		before := len(exec.commitTargets())

		// The state root now matches what the certificates build on, so nothing looks wrong — and
		// the node still may not act, because a matching state root is not proof of which block
		// produced it. It asks, and the answer is what lets it proceed.
		require.NoError(t, s.deliver(t, round, 1),
			"refusing to lead is not a processing error")
		require.False(t, round.health.Snapshot().Voting)
		st := waitRecovered(t, stack.Requester)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.NoError(t, s.deliver(t, round, 2))

		require.Equal(t, Hash(s.blockB), exec.currentHead().Hash)
		require.Equal(t, before, len(exec.commitTargets()),
			"the executor was already on the certified block, so adopting the anchor took no Commit "+
				"at all — recognising a canonical block is not the same act as making one canonical")
		require.NotNil(t, round.continuity.anchor)
		require.Equal(t, Hash(s.blockB), round.continuity.anchor.BlockHash,
			"and what it adopted is the block the authenticated evidence names, not the one on disk")
		require.Empty(t, sub.rounds())
	})

	t.Run("a fresh attempt the executor cannot satisfy yet: retryable, and the target is kept", func(t *testing.T) {
		// Note what this case is and is not. The operation the dead process started is over; what
		// the returning process meets is a NEW request that the executor cannot satisfy yet, and
		// the head later moves because a later request succeeds. The genuinely delayed completion —
		// where the operation admitted before the restart is still running and finishes on its own —
		// is the case below, and review was right that this one does not stand in for it.
		s := newRestartScenario(t)
		exec := s.newExecutor(s.behind)
		s.interruptedCommitInFlight(t, exec, false)

		round, stack, sub, _ := s.newProcess(t, exec)
		s.restore(t, round, s.older)
		before := len(exec.commitTargets())

		require.Error(t, s.deliver(t, round, 0))
		st := waitRecovered(t, stack.Requester)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

		// The next attempt reaches an executor that has not finished: SYNCING, with no error of its
		// own. That is unavailability, which is retryable — the distinction the whole applier
		// vocabulary exists to keep.
		exec.answerSyncing(1)
		err := s.deliver(t, round, 1)
		require.Error(t, err, "the block is not canonical yet, so this node still cannot prove its identity")
		require.ErrorContains(t, err, "no-anchor",
			"and the refusal is still the honest one: nothing was adopted")

		require.Equal(t, ApplyPayloadUnavailable, stack.Applier.Status().Last,
			"an executor that has not finished is UNAVAILABLE, which is retryable — never a fault")
		require.True(t, stack.Applier.Status().Last.Retryable())

		mid := exec.commitTargets()
		require.Len(t, mid[before:], 1, "one attempt, which reached Commit")
		require.Equal(t, Hash(s.blockB), mid[len(mid)-1])

		// The authority to retry is exactly what a failed attempt must not discard, so it is
		// asserted where it lives rather than inferred from the next round succeeding.
		target, ok := stack.Requester.Target()
		require.True(t, ok, "the verified target survived the failed attempt")
		require.Equal(t, Hash(s.blockB), target.Anchor.BlockHash)

		require.NoError(t, s.deliver(t, round, 2))
		after := exec.commitTargets()
		require.Greater(t, len(after), len(mid), "the retry reached Commit again")
		require.Equal(t, Hash(s.blockB), after[len(after)-1], "with the same target, re-derived from the same evidence")
		require.Equal(t, Hash(s.blockB), exec.currentHead().Hash)
		s.requireNoRollback(t, exec, before)
		require.Empty(t, sub.rounds())
	})
}

// requireNoRollback asserts that nothing the process did after index `from` asked the executor to go
// back to the block the persisted checkpoint names. The fixture's executor CAN make that move — the
// older block is in its map — so this is a refusal that was available and not taken.
func (s *restartScenario) requireNoRollback(t *testing.T, exec *restartExecutor, from int) {
	t.Helper()
	for i, target := range exec.commitTargets()[from:] {
		require.Equal(t, Hash(s.blockB), target,
			"commit %d after the restart named something other than the certified block", i)
	}
}

// recoveredAndAdopted drives a process all the way through recovery — the executor reaches the
// certified block AND the anchor is installed — and then destroys it without persisting any of the
// certificates it handled. That is R6: the adoption happened, the checkpoint on disk did not move.
func (s *restartScenario) recoveredAndAdopted(t *testing.T, exec *restartExecutor) {
	t.Helper()
	round, stack, sub, stop := s.newProcess(t, exec)

	require.Error(t, s.deliver(t, round, 0), "the first certificate finds no anchor and asks")
	st := waitRecovered(t, stack.Requester)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	require.NoError(t, s.deliver(t, round, 1))

	require.Equal(t, Hash(s.blockB), exec.currentHead().Hash)
	require.NotNil(t, round.continuity.anchor, "this process DID adopt the anchor")
	require.Equal(t, Hash(s.blockB), round.continuity.anchor.BlockHash)
	require.Equal(t, []uint64{23}, sub.rounds(),
		"this process had not restored, so it signed the round it led — which is what makes the "+
			"restored process's silence later a property of the gate and not of the fixture")
	stop()
}

// resumeAhead runs the second process for the R5/R6 fixtures: restored from the older checkpoint,
// over an executor that already holds the certified block. It returns what was observed.
type resumeObservation struct {
	commitsAfterRestore []Hash
	headAfter           BlockRef
	anchor              Hash
	signed              []uint64
	voting              bool
}

func (s *restartScenario) resumeAhead(t *testing.T, exec *restartExecutor) resumeObservation {
	t.Helper()
	round, stack, sub, _ := s.newProcess(t, exec)
	s.restore(t, round, s.older)
	before := len(exec.commitTargets())

	// A matching state root is not identity, so the restored process refuses the round rather than
	// leading it — and declining to lead is not a processing error.
	require.NoError(t, s.deliver(t, round, 1))
	require.False(t, round.health.Snapshot().Voting)
	require.Contains(t, round.health.Snapshot().NonVotingReason, "no-anchor")

	st := waitRecovered(t, stack.Requester)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
	require.NoError(t, s.deliver(t, round, 2))

	var anchor Hash
	if round.continuity.anchor != nil {
		anchor = round.continuity.anchor.BlockHash
	}
	return resumeObservation{
		commitsAfterRestore: exec.commitTargets()[before:],
		headAfter:           exec.currentHead(),
		anchor:              anchor,
		signed:              sub.rounds(),
		voting:              round.health.Snapshot().Voting,
	}
}

/*
R5 and R6: a process resumed from a certificate older than the state its executor already holds.

This is the state both boundaries leave behind. The executor is on the certified block; the only
certificate on disk names an earlier one; and nothing tells the returning process which of the two
is current except what it can authenticate. Rolling back to the checkpoint would be a correct-looking
disaster — the file is genuine, it just is not current — and the fixture's executor would carry the
rollback out if it were asked, so refusing it is a fact about the code rather than about the stub.
*/
func TestRestart_ResumingOlderThanTheExecutor(t *testing.T) {
	t.Run("the executor is ahead: the node reconciles forward from evidence, never back to the checkpoint", func(t *testing.T) {
		s := newRestartScenario(t)
		exec := s.newExecutor(s.behind)
		s.recoveredAndAdopted(t, exec)

		got := s.resumeAhead(t, exec)

		require.Empty(t, got.commitsAfterRestore,
			"the executor was already on the certified block, so nothing needed committing. A repeat "+
				"Commit of that same block would be permissible — it is idempotent by contract — but "+
				"asking the executor first is what keeps a retry from ever being a second execution")
		require.Equal(t, s.ahead, got.headAfter, "and the head did not move at all, forward or back")
		require.Equal(t, Hash(s.blockB), got.anchor,
			"what it adopted came from authenticated evidence, not from the certificate on disk")
		require.Empty(t, got.signed, "and a restored process signs nothing")
		require.False(t, got.voting)
	})

	t.Run("adoption before the restart changes nothing, because it was never persisted", func(t *testing.T) {
		// R5 is "the Commit landed, the anchor was not adopted"; R6 is "the anchor was adopted, the
		// certificate was not persisted". The ledger treats them as one boundary on the grounds
		// that the difference is memory-only. That is the claim, so it is measured: two processes
		// are killed in the two states, and the process that comes back must not be able to tell.
		r5 := newRestartScenario(t)
		execR5 := r5.newExecutor(r5.behind)
		r5.interruptedCommitInFlight(t, execR5, true) // committed, never adopted
		gotR5 := r5.resumeAhead(t, execR5)

		r6 := newRestartScenario(t)
		execR6 := r6.newExecutor(r6.behind)
		r6.recoveredAndAdopted(t, execR6) // committed AND adopted, never persisted
		gotR6 := r6.resumeAhead(t, execR6)

		require.Equal(t, gotR5, gotR6,
			"the two boundaries leave the same durable state, so the returning process behaves identically")
		require.Empty(t, gotR5.commitsAfterRestore)
		require.Equal(t, Hash(r5.blockB), gotR5.anchor)
	})

	t.Run("the fixture could carry out the rollback, which is what makes refusing it a result", func(t *testing.T) {
		// An assertion that nothing rolled the executor back is worth only as much as the
		// executor's ability to be rolled back. This states that ability directly, so the
		// refusals above cannot quietly become true of a stub that was never able to move.
		s := newRestartScenario(t)
		exec := s.newExecutor(s.ahead)
		status, err := exec.Commit(context.Background(), Hash(s.blockA))
		require.NoError(t, err)
		require.Equal(t, StatusValid, status)
		require.Equal(t, s.behind, exec.currentHead(),
			"committing the block the checkpoint names moves this executor BACKWARDS — no production "+
				"path above ever asks it to")
	})

	t.Run("control: the same certificates over a process that did not restore are signed", func(t *testing.T) {
		// Without this, "it signed nothing" above could be true because these fixtures never permit
		// a signature at all. The only difference here is the restoration: same certificates, same
		// executor state, same node — which is the leader every technical record assigns.
		s := newRestartScenario(t)
		exec := s.newExecutor(s.behind)
		s.recoveredAndAdopted(t, exec)

		round, stack, sub, _ := s.newProcess(t, exec)
		require.NoError(t, s.deliver(t, round, 1), "no anchor yet: it declines to lead and asks")
		require.Empty(t, sub.rounds())
		st := waitRecovered(t, stack.Requester)
		require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)
		require.NoError(t, s.deliver(t, round, 2))

		require.Equal(t, []uint64{27}, sub.rounds(),
			"a process that did not restore signs the round it leads, once it can prove its executor's identity")
		require.True(t, round.health.Snapshot().Voting)
		require.Empty(t, exec.commitTargets()[1:],
			"and it too committed nothing: being already canonical is not a restoration-only property")
	})
}

/*
R4, the delayed completion: the operation the dead process started is STILL RUNNING when its
successor starts, and finishes on its own.

This is the case the first revision of these fixtures missed, and the miss is worth naming because
it is the recurring one in this programme: a scripted SYNCING answer to a NEW request looks exactly
like an old operation still in flight, and it is not — in that version the head moved because a later
Commit succeeded, so nothing was being carried across the restart at all. Here the executor admits
one operation before the process dies, answers every later request SYNCING without starting a second
one, and applies the block only when the original operation completes. The head therefore moves with
no new request behind it, which is asserted directly by counting.
*/
func TestRestart_AnAdmittedCommitCompletesAfterTheProcessIsGone(t *testing.T) {
	s := newRestartScenario(t)
	exec := s.newExecutor(s.behind)
	s.admittedCommitStillRunning(t, exec)

	round, stack, sub, _ := s.newProcess(t, exec)
	s.restore(t, round, s.older)

	require.Error(t, s.deliver(t, round, 0), "the new process holds no anchor and says so")
	st := waitRecovered(t, stack.Requester)
	require.Equal(t, RecoveryReady, st.State, "err: %v", st.LastErr)

	// The returning process meets the executor exactly as it is: an old head, and an operation it
	// knows nothing about still running underneath.
	require.Equal(t, Hash(s.blockA), exec.currentHead().Hash)
	require.Equal(t, Hash(s.blockB), exec.pendingCommitHash(t))

	err := s.deliver(t, round, 1)
	require.Error(t, err, "the certified block is not canonical yet, so identity cannot be proven")
	require.ErrorContains(t, err, "no-anchor")
	require.Equal(t, ApplyPayloadUnavailable, stack.Applier.Status().Last,
		"an executor still working is UNAVAILABLE — retryable, never a fault")
	require.True(t, stack.Applier.Status().Last.Retryable())

	target, ok := stack.Requester.Target()
	require.True(t, ok, "the authenticated target is retained across the wait")
	require.Equal(t, Hash(s.blockB), target.Anchor.BlockHash)
	require.Empty(t, sub.rounds(), "and nothing is signed while the node cannot prove where it is")

	// THE OPERATION COMPLETES, on the executor's own schedule and with no request behind it.
	requestsBefore := len(exec.commitTargets())
	exec.completePending(t)
	require.Equal(t, requestsBefore, len(exec.commitTargets()),
		"no new Commit was issued: the head is about to move because the operation admitted BEFORE "+
			"the restart finished, which is the whole point of this case")
	require.Equal(t, s.ahead, exec.currentHead(), "and it moved to the certified block")

	// The next certificate finds the executor already there. Adoption comes from the authenticated
	// evidence the node retained, not from a request that produced the state.
	require.NoError(t, s.deliver(t, round, 2))
	require.Equal(t, requestsBefore, len(exec.commitTargets()),
		"and no Commit was needed to adopt a block the executor already holds")
	require.NotNil(t, round.continuity.anchor)
	require.Equal(t, Hash(s.blockB), round.continuity.anchor.BlockHash)
	require.Equal(t, s.ahead, exec.currentHead(), "exact head and state, unchanged by the adoption")
	require.Empty(t, sub.rounds(), "and a restored process still signs nothing")
	require.False(t, round.health.Snapshot().Voting)

	s.requireNoRollback(t, exec, 0)
}
