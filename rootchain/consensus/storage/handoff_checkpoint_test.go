package storage

import (
	"bytes"
	"crypto"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// commitRound commits the block of `round` with a commit certificate for it: the same certificate for every root, as every honest root
// sees the same one (only its signature subset may differ, which these tests do not model).
func commitRound(t *testing.T, s *BlockStore, round uint64) {
	t.Helper()
	b, err := s.Block(round)
	require.NoError(t, err)
	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round + 1, ParentRoundNumber: round, Epoch: 1},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: round, Epoch: 1, Hash: b.RootHash}})
	require.NoError(t, err)
}

type committedHandoff struct {
	s      *BlockStore
	dbPath string
}

// newCommittedHandoff builds a root that commits the handoff record at round 4 and then commits `later` more (empty) blocks, so its
// current committed root is round 4+later while the record was carried by round 4.
func newCommittedHandoff(t *testing.T, later int, beforeCommit ...func(BoltDB)) committedHandoff {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	s.handoffAuth = testRecordAuthority{}
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	tr, err := s.blockTree.Root().ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}].TR.Hash()
	require.NoError(t, err)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	for r := uint64(5); r < uint64(5+later); r++ {
		addProfileBlock(t, s, r, nil)
	}
	for _, f := range beforeCommit {
		f(db)
	}
	for r := uint64(4); r < uint64(4+later+1); r++ {
		commitRound(t, s, r)
	}
	return committedHandoff{s: s, dbPath: path}
}

func checkpointBytes(t *testing.T, s *BlockStore) []byte {
	t.Helper()
	head, path, record, err := s.HandoffCheckpoint()
	require.NoError(t, err)
	require.EqualValues(t, 4, record.OrderedRound)
	raw, err := types.Cbor.Marshal(canonicalCheckpoint{Block: head, Path: path})
	require.NoError(t, err)
	return raw
}

// Two roots that committed the same handoff at different times, with different "current root" views, serve byte-identical checkpoints:
// the block that carried the commit record, not whatever block is the committed root when they are asked.
func TestRootsWithDifferentCommitTimingsServeTheSameCheckpoint(t *testing.T) {
	early := newCommittedHandoff(t, 0) // the record's block is still the committed root
	late := newCommittedHandoff(t, 3)  // three empty blocks have committed since
	require.EqualValues(t, 4, early.s.blockTree.Root().GetRound())
	require.EqualValues(t, 7, late.s.blockTree.Root().GetRound())
	a, b := checkpointBytes(t, early.s), checkpointBytes(t, late.s)
	require.Equal(t, a, b)

	head, _, _, err := late.s.HandoffCheckpoint()
	require.NoError(t, err)
	require.EqualValues(t, 4, head.Block.Round, "the block that carries the record")
	require.NotEmpty(t, head.Block.Payload.HandoffRecords)
	_, err = late.s.Block(4)
	require.Error(t, err, "that block is pruned from the block store: the checkpoint is the only copy")
}

// A restart between the commit and the serving still serves the checkpoint that was captured when the record committed.
func TestTheCheckpointSurvivesARestartAfterLaterCommits(t *testing.T) {
	h := newCommittedHandoff(t, 2)
	want := checkpointBytes(t, h.s)
	require.NoError(t, h.s.storage.(BoltDB).Close())

	db, err := NewBoltStorage(h.dbPath, WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	reopened, err := New(crypto.SHA256, db, h.s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	require.Equal(t, want, checkpointBytes(t, reopened))
}

// A stored checkpoint that is not a checkpoint at all, or that is another record's, is refused, never served.
func TestAStoredCheckpointOfAnotherRecordOrGarbageIsRefused(t *testing.T) {
	donor := newCommittedHandoff(t, 0)
	head, path, _, err := donor.s.HandoffCheckpoint()
	require.NoError(t, err)
	head.Control.RecordBytes = append(append([]byte(nil), head.Control.RecordBytes...), 0) // another record than the one the root commits
	anotherRecord, err := types.Cbor.Marshal(canonicalCheckpoint{Block: head, Path: path})
	require.NoError(t, err)

	for name, stored := range map[string][]byte{"garbage": []byte("not a checkpoint"), "another record": anotherRecord} {
		t.Run(name, func(t *testing.T) {
			h := newCommittedHandoff(t, 1, func(db BoltDB) { require.NoError(t, db.StoreHandoffCheckpoint(2, stored)) })
			_, _, _, err := h.s.HandoffCheckpoint()
			require.ErrorIs(t, err, ErrHandoffRecord)
		})
	}
}

// Without a stored checkpoint (a root whose commit predates the capture, or one that learned the state by recovery) the root serves its
// current committed root, as before: valid, but not canonical. The store is what makes it canonical.
func TestWithoutAStoredCheckpointTheCurrentCommittedRootIsServed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(crypto.SHA256, plainStore{db}, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	s.handoffAuth = testRecordAuthority{}
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	zero := make([]byte, 32)
	body, frozen := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	tr, err := s.blockTree.Root().ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}].TR.Hash()
	require.NoError(t, err)
	addProfileBlock(t, s, 2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	addProfileBlock(t, s, 3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	addProfileBlock(t, s, 4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	addProfileBlock(t, s, 5, nil)
	commitRound(t, s, 4)
	commitRound(t, s, 5)
	head, _, _, err := s.HandoffCheckpoint()
	require.NoError(t, err)
	require.EqualValues(t, 5, head.Block.Round)
}

// plainStore hides the checkpoint methods of the Bolt store, as a store without checkpoint retention.
type plainStore struct{ PersistentStore }

// The shard entries come from a map; their order is canonical (partition, then shard), call after call.
func TestShardEntriesAreInCanonicalOrder(t *testing.T) {
	states := map[types.PartitionShardID]*ShardInfo{}
	key := []byte{0x3, 0x24, 0x8b, 0x61, 0x68, 0x51, 0xac, 0x6e, 0x43, 0x7e, 0xc2, 0x4e, 0xcc, 0x21, 0x9e, 0x5b, 0x42, 0x43, 0xdf, 0xa5, 0xdb, 0xdb, 0x8, 0xce, 0xa6, 0x48, 0x3a, 0xc9, 0xe0, 0xdc, 0x6b, 0x55, 0xcd}
	for p := types.PartitionID(20); p >= 8; p-- {
		conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: p, PartitionTypeID: 8, Validators: []*types.NodeInfo{{NodeID: "n", SigKey: key, Stake: 1}}}
		si, err := NewShardInfo(conf, crypto.SHA256)
		require.NoError(t, err)
		states[types.PartitionShardID{PartitionID: p, ShardID: conf.ShardID.Key()}] = si
	}
	block := &ExecutedBlock{ShardState: ShardStates{States: states}}
	var first []types.PartitionID
	for i := 0; i < 40; i++ {
		info, err := toRecoveryShardInfo(block)
		require.NoError(t, err)
		var order []types.PartitionID
		for _, e := range info {
			order = append(order, e.Partition)
		}
		if first == nil {
			first = order
			for j := 1; j < len(order); j++ {
				require.Less(t, order[j-1], order[j], fmt.Sprint(order))
			}
		}
		require.Equal(t, first, order)
	}
}

// recoverFrom is a second root that recovers from the donor's committed head, as a lagging root does from a peer's state.
func recoverFrom(t *testing.T, donor committedHandoff) *BlockStore {
	t.Helper()
	state, err := donor.s.GetState()
	require.NoError(t, err)
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovered.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewFromState(crypto.SHA256, state.CommittedHead, db, donor.s.orchestration, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	s.handoffAuth = testRecordAuthority{}
	return s
}

// A root that recovers with the block that carries the record as its head captures the canonical checkpoint itself: its checkpoint is
// byte-identical to the donor's, before and after it commits a later block (which would otherwise skip the capture).
func TestARootRecoveredWithTheCarrierAsHeadServesTheCanonicalCheckpoint(t *testing.T) {
	donor := newCommittedHandoff(t, 0)
	want := checkpointBytes(t, donor.s)
	recovered := recoverFrom(t, donor)
	require.EqualValues(t, 4, recovered.blockTree.Root().GetRound())
	require.Equal(t, want, checkpointBytes(t, recovered))

	addProfileBlock(t, recovered, 5, nil)
	commitRound(t, recovered, 5)
	require.EqualValues(t, 5, recovered.blockTree.Root().GetRound())
	require.Equal(t, want, checkpointBytes(t, recovered), "a later commit does not change what it serves")
}

// A root that recovers to a head PAST the carrier cannot capture it (every peer pruned it): it refuses, with ErrHandoffRecord, and never
// serves the current root, which would be a non-canonical copy that the bundle archive then keeps for good.
func TestARootRecoveredPastTheCarrierRefusesToServeTheCheckpoint(t *testing.T) {
	donor := newCommittedHandoff(t, 2)
	require.EqualValues(t, 6, donor.s.blockTree.Root().GetRound())
	recovered := recoverFrom(t, donor)
	require.EqualValues(t, 6, recovered.blockTree.Root().GetRound())
	_, _, _, err := recovered.HandoffCheckpoint()
	require.ErrorIs(t, err, ErrHandoffRecord)
	// while a root that committed it serves it
	require.NotEmpty(t, checkpointBytes(t, donor.s))
}
