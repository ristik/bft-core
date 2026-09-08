package executortest

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// Factory returns a fresh, independent Executor instance, agreeing with
// every other instance the same Factory produces on genesis state — the way
// four validators' executors must agree without coordinating.
type Factory func(t *testing.T) shardnode.Executor

// RunConformance exercises the build → seal → verify → commit cycle that
// every shardnode.Executor implementation must support, plus the four
// Status values a round driver has to branch on. Call it once per
// implementation:
//
//	func TestFakeConformance(t *testing.T) {
//	    executortest.RunConformance(t, func(t *testing.T) shardnode.Executor { return executortest.New() })
//	}
func RunConformance(t *testing.T, newExecutor Factory) {
	t.Helper()
	ctx := context.Background()

	t.Run("two fresh instances agree on genesis", func(t *testing.T) {
		a := newExecutor(t)
		b := newExecutor(t)
		ha, err := a.Head(ctx)
		require.NoError(t, err)
		hb, err := b.Head(ctx)
		require.NoError(t, err)
		require.Equal(t, ha, hb)
	})

	t.Run("build, seal, then leader-side commit advances head", func(t *testing.T) {
		e := newExecutor(t)
		head, err := e.Head(ctx)
		require.NoError(t, err)

		addEntries(t, e, []byte("entry-1"))
		id, err := e.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)

		block, err := e.Seal(ctx, id)
		require.NoError(t, err)
		require.NotEqual(t, head.StateRoot, block.StateRoot, "a non-quiet block must move the state root")
		require.NotEmpty(t, block.Hash, "a non-quiet block must have a block hash")

		commitLeaderSealed(t, e, block)

		newHead, err := e.Head(ctx)
		require.NoError(t, err)
		require.Equal(t, block.StateRoot, newHead.StateRoot)
		require.Equal(t, block.Hash, newHead.Hash)
	})

	t.Run("quiet build leaves the state root unchanged", func(t *testing.T) {
		e := newExecutor(t)
		head, err := e.Head(ctx)
		require.NoError(t, err)

		id, err := e.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		block, err := e.Seal(ctx, id)
		require.NoError(t, err)

		require.True(t, bytes.Equal(head.StateRoot, block.StateRoot),
			"quiet round must produce a block whose StateRoot is byte-identical to head, not merely equal in value")
	})

	t.Run("independent instances given identical entries produce identical blocks", func(t *testing.T) {
		a := newExecutor(t)
		b := newExecutor(t)
		head, err := a.Head(ctx)
		require.NoError(t, err)

		addEntries(t, a, []byte("same"), []byte("entries"))
		addEntries(t, b, []byte("same"), []byte("entries"))

		idA, err := a.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		idB, err := b.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)

		blockA, err := a.Seal(ctx, idA)
		require.NoError(t, err)
		blockB, err := b.Seal(ctx, idB)
		require.NoError(t, err)

		require.Equal(t, blockA.StateRoot, blockB.StateRoot, "determinism: same head + same entries must yield the same state root")
		require.Equal(t, blockA.Hash, blockB.Hash, "determinism: same head + same entries must yield the same block hash")
		// BlockSize/StateSize are hashed into the root chain's quorum key
		// alongside the InputRecord (rootchain/request_buffer.go's Add) —
		// as fatal to disagree on as the state root itself.
		require.Equal(t, blockA.BlockSize, blockB.BlockSize, "determinism: BlockSize feeds the quorum hash and must match across validators")
		require.Equal(t, blockA.StateSize, blockB.StateSize, "determinism: StateSize feeds the quorum hash and must match across validators")
	})

	t.Run("verify accepts a block that correctly extends head", func(t *testing.T) {
		leader := newExecutor(t)
		follower := newExecutor(t)
		head, err := leader.Head(ctx)
		require.NoError(t, err)

		addEntries(t, leader, []byte("payload"))
		id, err := leader.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		block, err := leader.Seal(ctx, id)
		require.NoError(t, err)

		status, err := follower.Verify(ctx, block, shardnode.RoundParams{})
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)
	})

	t.Run("verify rejects a block with a tampered parent hash", func(t *testing.T) {
		leader := newExecutor(t)
		follower := newExecutor(t)
		head, err := leader.Head(ctx)
		require.NoError(t, err)

		addEntries(t, leader, []byte("payload"))
		id, err := leader.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		block, err := leader.Seal(ctx, id)
		require.NoError(t, err)

		block.ParentHash = append(shardnode.Hash{0xff}, block.ParentHash...)

		status, err := follower.Verify(ctx, block, shardnode.RoundParams{})
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusInvalid, status)
	})

	t.Run("verify rejects a block with a tampered state root", func(t *testing.T) {
		leader := newExecutor(t)
		follower := newExecutor(t)
		head, err := leader.Head(ctx)
		require.NoError(t, err)

		addEntries(t, leader, []byte("payload"))
		id, err := leader.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		block, err := leader.Seal(ctx, id)
		require.NoError(t, err)

		block.StateRoot = append(shardnode.Hash{0xff}, block.StateRoot...)

		status, err := follower.Verify(ctx, block, shardnode.RoundParams{})
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusInvalid, status)
	})

	t.Run("commit after verify advances the follower's head to match the leader's", func(t *testing.T) {
		leader := newExecutor(t)
		follower := newExecutor(t)
		head, err := leader.Head(ctx)
		require.NoError(t, err)

		addEntries(t, leader, []byte("payload"))
		id, err := leader.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		block, err := leader.Seal(ctx, id)
		require.NoError(t, err)

		commitLeaderSealed(t, leader, block)

		status, err := follower.Verify(ctx, block, shardnode.RoundParams{})
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)

		status, err = follower.Commit(ctx, block.Hash)
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)

		leaderHead, err := leader.Head(ctx)
		require.NoError(t, err)
		followerHead, err := follower.Head(ctx)
		require.NoError(t, err)
		require.Equal(t, leaderHead, followerHead)
	})

	t.Run("commit is idempotent: re-committing the canonical head returns valid", func(t *testing.T) {
		// The Executor contract requires Commit to be safe to call speculatively
		// (docs/adr/0001-executor-boundary.md decision 2), and #92's recovery path depends on it:
		// it re-commits the retained anchor on every certificate until it succeeds, so an
		// executor that reported "not found" for a block it had already made canonical would make
		// every retry after the first look like an unavailable payload.
		//
		// A real client agrees — forkchoiceUpdated to the current canonical head returns VALID —
		// and the in-memory Fake did not until this case was added, which is exactly the
		// fake-versus-adapter divergence that let #92 go unnoticed by a fake-only suite.
		leader := newExecutor(t)
		follower := newExecutor(t)
		head, err := leader.Head(ctx)
		require.NoError(t, err)

		addEntries(t, leader, []byte("payload"))
		id, err := leader.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
		require.NoError(t, err)
		block, err := leader.Seal(ctx, id)
		require.NoError(t, err)

		status, err := follower.Verify(ctx, block, shardnode.RoundParams{})
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)

		status, err = follower.Commit(ctx, block.Hash)
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)
		first, err := follower.Head(ctx)
		require.NoError(t, err)

		// Twice more: the head must not move and the status must not degrade.
		for i := 0; i < 2; i++ {
			status, err = follower.Commit(ctx, block.Hash)
			require.NoError(t, err)
			require.Equal(t, shardnode.StatusValid, status, "re-committing the canonical head must stay valid")
			again, err := follower.Head(ctx)
			require.NoError(t, err)
			require.Equal(t, first, again, "a repeated commit must have no additional effect")
		}
	})

	t.Run("commit of an empty hash is never valid", func(t *testing.T) {
		// #92: a quiet certificate carries a nil BlockHash, and the framework used to pass it
		// straight to Commit. The framework no longer does, but an Executor must not report
		// success for it either — an empty hash is not the canonical head, even at genesis where
		// the head's own hash is empty too.
		e := newExecutor(t)
		status, err := e.Commit(ctx, nil)
		if err == nil {
			require.NotEqual(t, shardnode.StatusValid, status,
				"an empty commit target must never be reported as valid")
		}
	})

	t.Run("commit of a hash never verified reports syncing, not an error", func(t *testing.T) {
		e := newExecutor(t)
		status, err := e.Commit(ctx, shardnode.Hash{0x01, 0x02, 0x03})
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusSyncing, status)
	})

	t.Run("seal of an unknown build id returns ErrNotFound", func(t *testing.T) {
		e := newExecutor(t)
		_, err := e.Seal(ctx, shardnode.BuildID("does-not-exist"))
		require.ErrorIs(t, err, shardnode.ErrNotFound)
	})

	t.Run("two consecutive quiet rounds keep head identical", func(t *testing.T) {
		e := newExecutor(t)
		head0, err := e.Head(ctx)
		require.NoError(t, err)

		for i := 0; i < 2; i++ {
			head, err := e.Head(ctx)
			require.NoError(t, err)
			id, err := e.Build(ctx, shardnode.RoundParams{Round: uint64(i + 1), Parent: head})
			require.NoError(t, err)
			block, err := e.Seal(ctx, id)
			require.NoError(t, err)
			require.True(t, bytes.Equal(head0.StateRoot, block.StateRoot), "quiet round %d moved the state root", i)
		}
	})
}

// addEntries queues entries via the Fake-specific AddEntries method when the
// Executor under test supports it; other implementations may pre-populate
// pending work through their own constructors instead, in which case this
// is a no-op and the caller's Build will operate on whatever that
// implementation was seeded with.
func addEntries(t *testing.T, e shardnode.Executor, entries ...[]byte) {
	t.Helper()
	if f, ok := e.(interface{ AddEntries(...[]byte) }); ok {
		f.AddEntries(entries...)
	}
}

// commitLeaderSealed commits a just-sealed block on the leader side, using
// the Fake-specific CommitSealed fast path when available and falling back
// to Commit-by-hash (which every Executor must support, since it is part of
// the interface) otherwise.
func commitLeaderSealed(t *testing.T, e shardnode.Executor, b shardnode.Block) {
	t.Helper()
	if f, ok := e.(interface {
		CommitSealed(shardnode.Block)
	}); ok {
		f.CommitSealed(b)
		return
	}
	status, err := e.Commit(context.Background(), b.Hash)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
}
