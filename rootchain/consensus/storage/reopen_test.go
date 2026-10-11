package storage

import (
	"crypto"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// A root must be able to start again over the block store it wrote: what the database holds after any sequence of blocks, QCs and
// timeout certificates must load. Two ways it did not, both ending in "cannot add block for round N, parent block M not found" at
// the next start: a timeout certificate deleted its round's block from the database whatever the tree did with it (bft-core#567),
// and a commit pruned the database by round number while the tree pruned by ancestry (bft-core#474).
func TestBlockStoreReopensOverItsOwnStore(t *testing.T) {
	irVer := mockIRVerifier{verify: func(uint64, *types.IRChangeReq) (*basetypes.InputRecord, error) {
		return nil, errors.New("no IR changes in this test")
	}}
	qcFor := func(round, parent uint64, rh []byte) *types.QuorumCert {
		return &types.QuorumCert{
			VoteInfo:         &types.RoundInfo{RoundNumber: round, ParentRoundNumber: parent, CurrentRootHash: rh},
			LedgerCommitInfo: &basetypes.UnicitySeal{Version: 1},
		}
	}
	tcFor := func(round uint64) *types.TimeoutCert {
		return &types.TimeoutCert{Timeout: &types.Timeout{Round: round}}
	}
	type env struct {
		bs    *BlockStore
		open  func() (*BlockStore, error)
		rh    map[uint64][]byte
		irVer mockIRVerifier
	}
	setup := func(t *testing.T) *env {
		dir := t.TempDir()
		db, err := NewBoltStorage(filepath.Join(dir, "blocks.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		log := logger.New(t)
		orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), log)
		require.NoError(t, err)
		t.Cleanup(func() { _ = orchestration.Close() })
		open := func() (*BlockStore, error) { return New(crypto.SHA256, db, orchestration, log) }
		bs, err := open()
		require.NoError(t, err)
		return &env{bs: bs, open: open, rh: map[uint64][]byte{}, irVer: irVer}
	}
	add := func(t *testing.T, e *env, round uint64, qc *types.QuorumCert) {
		t.Helper()
		_, err := e.bs.ProcessQc(qc)
		require.NoError(t, err)
		rh, err := e.bs.Add(&types.BlockData{Round: round, Payload: &types.Payload{}, Qc: qc}, e.irVer)
		require.NoError(t, err)
		e.rh[round] = rh
	}
	reopened := func(t *testing.T, e *env, want ...uint64) {
		t.Helper()
		bs, err := e.open()
		require.NoError(t, err, "the root cannot start over its own block store")
		require.ElementsMatch(t, want, roundsOf(bs.blockTree.GetAllUncommittedNodes()), "the uncommitted blocks after the restart")
	}

	t.Run("a commit abandons a sibling fork above the committed round", func(t *testing.T) {
		// genesis (1) <- 2 <- 3 <- 4, and a sibling 5 that extends round 2. The QC of round 4 commits round 3: the tree prunes round 2
		// and, by ancestry, the sibling 5. The database used to prune by round number only, keeping 5 with its parent 2 deleted
		// (bft-core#474).
		e := setup(t)
		add(t, e, 2, e.bs.GetHighQc())
		add(t, e, 3, qcFor(2, 1, e.rh[2]))
		add(t, e, 4, qcFor(3, 2, e.rh[3]))
		_, err := e.bs.Add(&types.BlockData{Round: 5, Payload: &types.Payload{}, Qc: qcFor(2, 1, e.rh[2])}, e.irVer)
		require.NoError(t, err)
		b3, err := e.bs.Block(3)
		require.NoError(t, err)
		commit3 := qcFor(4, 3, e.rh[4])
		commit3.LedgerCommitInfo.RootChainRoundNumber, commit3.LedgerCommitInfo.Hash = 3, b3.RootHash
		_, err = e.bs.ProcessQc(commit3)
		require.NoError(t, err)
		require.EqualValues(t, 3, e.bs.blockTree.Root().GetRound())
		require.ElementsMatch(t, []uint64{4}, roundsOf(e.bs.blockTree.GetAllUncommittedNodes()), "the tree dropped the sibling")
		reopened(t, e, 4)
	})

	t.Run("the timed-out round's block has a child", func(t *testing.T) {
		// genesis (1) <- 2 <- 3 <- 4: this root has the proposal of round 4, which carries the QC of round 3, when the timeout
		// certificate of round 3 reaches it (the other roots voted for 3 and then timed out on it)
		e := setup(t)
		add(t, e, 2, e.bs.GetHighQc())
		add(t, e, 3, qcFor(2, 1, e.rh[2]))
		add(t, e, 4, qcFor(3, 2, e.rh[3]))
		_ = e.bs.ProcessTc(tcFor(3)) // the tree keeps a block that has a child; what ProcessTc reports is not the subject here
		require.Contains(t, roundsOf(e.bs.blockTree.GetAllUncommittedNodes()), uint64(3), "the tree still holds round 3")
		reopened(t, e, 2, 3, 4)
	})

	t.Run("the timed-out round's block is re-attached by a late QC and extended", func(t *testing.T) {
		e := setup(t)
		add(t, e, 2, e.bs.GetHighQc())
		add(t, e, 3, qcFor(2, 1, e.rh[2]))
		require.NoError(t, e.bs.ProcessTc(tcFor(3)))
		add(t, e, 4, qcFor(3, 2, e.rh[3])) // the late QC of round 3, then the block that extends it
		reopened(t, e, 2, 3, 4)
	})

	t.Run("the timed-out round's block is set aside and the chain goes on without it", func(t *testing.T) {
		e := setup(t)
		add(t, e, 2, e.bs.GetHighQc())
		add(t, e, 3, qcFor(2, 1, e.rh[2]))
		require.NoError(t, e.bs.ProcessTc(tcFor(3)))
		add(t, e, 4, qcFor(2, 1, e.rh[2])) // round 4 extends round 2 under the TC
		// a restart may or may not bring the set-aside block back as a leaf; it must not fail, and 2 and 4 must be there
		bs, err := e.open()
		require.NoError(t, err, "the root cannot start over its own block store")
		rounds := roundsOf(bs.blockTree.GetAllUncommittedNodes())
		require.Contains(t, rounds, uint64(2))
		require.Contains(t, rounds, uint64(4))
	})

	t.Run("a block set aside by its timeout certificate is stored again when it is re-attached", func(t *testing.T) {
		e := setup(t)
		add(t, e, 2, e.bs.GetHighQc())
		add(t, e, 3, qcFor(2, 1, e.rh[2]))
		stored := func() []uint64 {
			blocks, err := e.bs.storage.LoadBlocks()
			require.NoError(t, err)
			return roundsOf(blocks)
		}
		require.NoError(t, e.bs.ProcessTc(tcFor(3)))
		require.NotContains(t, stored(), uint64(3), "the tree let go of round 3, so the database dropped it with the certificate")
		// anything that looks the round up brings it back under its parent; from then on a child may be stored on top of it
		_, err := e.bs.blockTree.FindBlock(3)
		require.NoError(t, err)
		require.Contains(t, stored(), uint64(3), "back in the tree, back in the database")
		reopened(t, e, 2, 3)
	})

	t.Run("the database keeps a timed-out round's block unless it is told to drop it", func(t *testing.T) {
		db, err := NewBoltStorage(filepath.Join(t.TempDir(), "blocks.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		require.NoError(t, db.WriteBlock(&ExecutedBlock{BlockData: &types.BlockData{Round: 7}}, false))
		require.NoError(t, db.WriteTC(tcFor(7), false))
		blocks, err := db.LoadBlocks()
		require.NoError(t, err)
		require.Equal(t, []uint64{7}, roundsOf(blocks), "kept")
		last, err := db.ReadLastTC()
		require.NoError(t, err)
		require.EqualValues(t, 7, last.GetRound(), "and the certificate is stored either way")
		require.NoError(t, db.WriteTC(tcFor(7), true))
		blocks, err = db.LoadBlocks()
		require.NoError(t, err)
		require.Empty(t, blocks, "dropped")
	})
}
