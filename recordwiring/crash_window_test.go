package recordwiring_test

/*
F6i section 3: the crash window between the record and the checkpoint (#14).

persistingDriver calls SaveLUC only after the round's HandleCertificate returns, and the capturer
publishes from inside the round. A crash between those two writes leaves the record naming a block
whose certificate is newer than the checkpoint cursor. The two artifacts are not, and need not be, in
one transaction: each is independently authenticated on restart, so the acceptance line needs a
defined outcome for the window rather than a shared transaction.

The property is that a record ahead of the cursor is not an error. Reload reads the record and the
executor only, so it cannot fall back to the record as a cursor; the node resumes from the older
cursor under the restored-signing restriction, follows the live feed, and treats the durable record
as readiness for a block, never as authority to vote.

This test lives in recordwiring rather than shardnode because recordwiring imports shardnode and the
reach guards forbid the reverse. The resumption uses SeedLUC and MarkRestored, the exported halves of
the unexported resumeFrom sequence; the pairing itself is tested in shardnode.
*/

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
	"github.com/unicitynetwork/bft-go-base/types"
)

// sealCountingExecutor counts the blocks sealed, so the test can show that the node not only
// abstains but actually builds the round the live feed assigns. A record ahead of the cursor is not
// a reason to stop following the shard.
type sealCountingExecutor struct {
	*executortest.Fake
	mu    sync.Mutex
	seals int
}

func (e *sealCountingExecutor) Seal(ctx context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	b, err := e.Fake.Seal(ctx, id)
	if err == nil {
		e.mu.Lock()
		e.seals++
		e.mu.Unlock()
	}
	return b, err
}

func (e *sealCountingExecutor) sealed() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seals
}

func TestRecordAheadOfTheCheckpointIsNotAnError(t *testing.T) {
	ctx := context.Background()
	c := certifiedchain.New(t, 3, 4)
	d := mustDeployment(t, c)
	b4 := c.Blocks[4]

	// The durable record is at block 4. The cursor this process resumes from is older, block 1's
	// certificate, which is the state a crash between the record write and the cursor write leaves.
	path := filepath.Join(t.TempDir(), "certified.db")
	publish(t, path, d, c, 0, 4)

	olderUC, _ := c.Certificate(1)
	cursorPath := filepath.Join(t.TempDir(), "luc.cbor")
	require.NoError(t, shardnode.NewFileStore(cursorPath).SaveLUC(olderUC))
	cursorBefore, err := os.ReadFile(cursorPath)
	require.NoError(t, err)

	// The executor is at the recorded block, so Reload reports its ordinary outcome for it.
	fake := executortest.New()
	fake.CommitSealed(shardnode.Block{Number: b4.Number, Hash: b4.Hash.Bytes(), StateRoot: b4.StateRoot.Bytes()})
	exec := &sealCountingExecutor{Fake: fake}

	store, err := recordwiring.OpenStore(path, 8)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	res := recordwiring.Reload(ctx, store, d, exec)
	require.Equal(t, recordwiring.OutcomeDurableReady, res.Outcome, "%v", res.Err)
	require.Equal(t, b4.Hash, res.Record.BlockHash(), "the record ahead of the cursor is durable-ready for its block")

	// Resume from the older cursor under the restored-signing restriction. SeedLUC and MarkRestored
	// are the two halves of resumeFrom; the recordwiring test cannot call the unexported function.
	sub := &recordingSubmitter{}
	round := shardnode.NewRound("leader", types.PartitionID(8), types.ShardID{}, exec, shardnode.NewLoopbackDisseminator(), c.Signer, sub, nil)
	health := shardnode.NewHealth()
	round.SetHealth(health)
	client := &shardnode.BFTClient{}
	require.NoError(t, client.SeedLUC(olderUC))
	round.MarkRestored(olderUC.GetRoundNumber())

	require.False(t, health.Snapshot().Voting,
		"a durable record is not authority to vote: the restored-signing restriction still holds")

	// The live feed delivers the certificate for the recorded block, which the node follows.
	liveUC, liveTR := c.Certificate(4)
	require.NoError(t, round.HandleCertificate(ctx, liveUC, liveTR), "following the live feed is not an error")
	require.False(t, health.Snapshot().Voting)
	require.Empty(t, sub.rounds(), "and a record that is ahead signs nothing on its own")
	require.Equal(t, 1, exec.sealed(), "the node still built the round the live certificate assigns")

	// The executor stayed at the recorded block; nothing rolled it back to the cursor's block.
	head, err := exec.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, b4.Hash.Bytes(), []byte(head.Hash))
	require.Equal(t, b4.StateRoot.Bytes(), []byte(head.StateRoot))

	// Nothing fell back to the record as a cursor: the checkpoint is byte for byte the older
	// certificate. Reload takes the record and the executor only, so it has no cursor to write.
	cursorAfter, err := os.ReadFile(cursorPath)
	require.NoError(t, err)
	require.Equal(t, cursorBefore, cursorAfter, "reloading the record does not rewrite the cursor")
	restored, err := shardnode.NewFileStore(cursorPath).LoadLUC()
	require.NoError(t, err)
	require.Equal(t, olderUC.GetRoundNumber(), restored.GetRoundNumber(), "the cursor is still the older certificate")
}
