package storage

import (
	"bytes"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

var leaderCommittee = []string{"a", "b", "c", "d"}

type fakeLeaderInputs struct {
	reputation bool
	err        error
	committee  []string
}

func (f fakeLeaderInputs) LeaderCommittee(uint64) ([]string, bool, error) {
	if f.committee != nil {
		return f.committee, f.reputation, f.err
	}
	return leaderCommittee, f.reputation, f.err
}

// leaderStore is a profile store whose head carries a ring, as an epoch of the policy has after its first ordinary block.
func leaderStore(t *testing.T) *BlockStore {
	t.Helper()
	s := profileStore(t)
	root := s.blockTree.Root()
	ring, err := rctypes.NewLeaderState(bytes.Repeat([]byte{7}, 32), root.BlockData.Epoch, root.GetRound()+1, 4, root.GetRound()+1)
	require.NoError(t, err)
	ring.Records = ring.Records[:1]
	ring.Records[0].Round = root.GetRound()
	root.ShardState.Leader = ring
	s.SetLeaderInputs(fakeLeaderInputs{reputation: true})
	return s
}

func leaderQC(round, epoch uint64, signers ...string) *rctypes.QuorumCert {
	sigs := map[string]hex.Bytes{}
	for _, s := range signers {
		sigs[s] = hex.Bytes{1}
	}
	return &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round, Epoch: epoch}, Signatures: sigs}
}

func leaderBlock(s *BlockStore, round uint64, qc *rctypes.QuorumCert, records [][]byte) *rctypes.BlockData {
	return &rctypes.BlockData{Version: 3, Round: round, Epoch: s.blockTree.Root().BlockData.Epoch, Payload: &rctypes.Payload{Version: 3, HandoffRecords: records}, Qc: qc}
}

func TestLeaderRingAppendsTheCarriedQCsSigners(t *testing.T) {
	s := leaderStore(t)
	epoch := s.blockTree.Root().BlockData.Epoch
	_, err := s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "b", "c"), nil), nil)
	require.NoError(t, err)
	b := mustBlock(t, s, 2)
	last := b.ShardState.Leader.Records[len(b.ShardState.Leader.Records)-1]
	require.EqualValues(t, 2, last.Round)
	require.Equal(t, []byte{0b0111}, last.Voters)
	require.Equal(t, 1, len(s.blockTree.Root().ShardState.Leader.Records), "the parent's ring is not touched")
}

// The state root binds exactly the signer set of Signatures: two blocks that differ in another signer subset differ in the root, and
// neither SealSignatures, nor the author changes it.
func TestLeaderRingRootBindsOnlyTheSigners(t *testing.T) {
	root := func(qc *rctypes.QuorumCert, author string) []byte {
		s := leaderStore(t)
		block := leaderBlock(s, 2, qc, nil)
		block.Author = author
		_, err := s.Add(block, nil)
		require.NoError(t, err)
		return mustBlock(t, s, 2).RootHash
	}
	epoch := leaderStore(t).blockTree.Root().BlockData.Epoch
	base := root(leaderQC(1, epoch, "a", "b", "c"), "a")
	require.NotEqual(t, base, root(leaderQC(1, epoch, "a", "b", "d"), "a"), "another valid signer subset")
	seal := leaderQC(1, epoch, "a", "b", "c")
	seal.SealSignatures = map[string]hex.Bytes{"d": {2}}
	require.Equal(t, base, root(seal, "a"), "SealSignatures are not an input")
	require.Equal(t, base, root(leaderQC(1, epoch, "a", "b", "c"), "d"), "the author is not an input")
}

func TestLeaderRingRefusals(t *testing.T) {
	s := leaderStore(t)
	epoch := s.blockTree.Root().BlockData.Epoch
	_, err := s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "z"), nil), nil)
	require.ErrorIs(t, err, rctypes.ErrLeaderState, "a signer outside the committee")
	_, err = s.Add(leaderBlock(s, 2, leaderQC(1, epoch), nil), nil)
	require.ErrorIs(t, err, rctypes.ErrLeaderState, "no signers")

	sentinel := errors.New("no history")
	s.SetLeaderInputs(fakeLeaderInputs{reputation: true, err: sentinel})
	_, err = s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "b", "c"), nil), nil)
	require.ErrorIs(t, err, ErrLeaderInputs)
	require.ErrorIs(t, err, sentinel)
	s.SetLeaderInputs(nil)
	_, err = s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "b", "c"), nil), nil)
	require.ErrorIs(t, err, ErrLeaderInputs, "a ring with nobody to name its committee")
	s.SetLeaderInputs(fakeLeaderInputs{reputation: false})
	_, err = s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "b", "c"), nil), nil)
	require.ErrorIs(t, err, ErrLeaderInputs, "a ring in an epoch of another policy")
	s.SetLeaderInputs(fakeLeaderInputs{reputation: true, committee: []string{"a", "b", "c"}})
	_, err = s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "b", "c"), nil), nil)
	require.ErrorIs(t, err, ErrLeaderInputs, "a ring of four members under a committee of three")
}

func TestABlockWithoutARingIsUnchanged(t *testing.T) {
	plain, ringed := profileStore(t), profileStore(t)
	ringed.SetLeaderInputs(fakeLeaderInputs{reputation: true})
	a := addProfileBlock(t, plain, 2, nil)
	b := addProfileBlock(t, ringed, 2, nil)
	require.Nil(t, b.ShardState.Leader, "only the epoch's first ordinary block starts a ring")
	require.Equal(t, a.RootHash, b.RootHash)
}

// The suffix of a sealed epoch keeps the closing block's root: nothing in the ring moves, however far its header rounds go.
func TestLeaderRingIsFrozenInTheSuffix(t *testing.T) {
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	s := leaderStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	epoch := s.blockTree.Root().BlockData.Epoch
	add := func(round uint64, records [][]byte) *ExecutedBlock {
		t.Helper()
		_, err := s.Add(leaderBlock(s, round, leaderQC(round-1, epoch, "a", "b", "c"), records), nil)
		require.NoError(t, err)
		return mustBlock(t, s, round)
	}
	add(2, [][]byte{record("prepare", 2, 7, zero, body, zero)})
	add(3, [][]byte{record("freeze", 3, 7, frozen, body, zero)})
	closing := add(4, [][]byte{record("commit", 4, 7, frozen, body, tr)})
	require.Equal(t, "committed", closing.ShardState.Control.Phase)
	require.EqualValues(t, 4, closing.ShardState.Leader.Records[len(closing.ShardState.Leader.Records)-1].Round, "the closing carrier appended normally")
	want, err := closing.ShardState.Leader.Digest()
	require.NoError(t, err)

	previous := closing
	for _, round := range []uint64{5, 6, 7} {
		suffix := add(round, nil)
		got, err := suffix.ShardState.Leader.Digest()
		require.NoError(t, err)
		require.Equal(t, want, got, "no append, no eviction at round %d", round)
		require.Equal(t, closing.RootHash, suffix.RootHash)
		require.NoError(t, checkStoredSuffix(previous, suffix))
		require.NotSame(t, closing.ShardState.Leader, suffix.ShardState.Leader)
		previous = suffix
	}
	forged := *previous
	forged.ShardState.Leader = previous.ShardState.Leader.Clone()
	forged.ShardState.Leader.Records = forged.ShardState.Leader.Records[1:]
	require.ErrorIs(t, checkStoredSuffix(closing, &forged), ErrHandoffSuffix)
	forged.ShardState.Leader = nil
	require.ErrorIs(t, checkStoredSuffix(closing, &forged), ErrHandoffSuffix)

	// sealed: the head reads as sealed and the suffix's header round is not the ring's
	round, ring, sealed := func() (uint64, *rctypes.LeaderState, bool) {
		return previous.GetRound(), previous.ShardState.Leader, previous.ShardState.Control.Phase == "committed"
	}()
	require.True(t, sealed)
	voters, err := ring.Select(round+1000, round, sealed)
	require.NoError(t, err)
	require.Equal(t, []byte{0b0111}, voters)
}

func leaderCheckpoint(t *testing.T, b *ExecutedBlock) *abdrc.CommittedBlock {
	t.Helper()
	shards, err := toRecoveryShardInfo(b)
	require.NoError(t, err)
	return &abdrc.CommittedBlock{Block: b.BlockData, Control: b.ShardState.Control, Leader: b.ShardState.Leader, ShardInfo: shards,
		CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: b.RootHash}}}
}

// The two restore routes: the certified root is recomputed with the leaf, so a tampered or missing leaf is refused, and an untampered one
// comes back whole, on either the head's route or the codec.
func TestLeaderRingIsBoundByTheRestoredRoot(t *testing.T) {
	s := leaderStore(t)
	epoch := s.blockTree.Root().BlockData.Epoch
	_, err := s.Add(leaderBlock(s, 2, leaderQC(1, epoch, "a", "b", "c"), nil), nil)
	require.NoError(t, err)
	b := mustBlock(t, s, 2)

	head := leaderCheckpoint(t, b)
	restored, err := NewRootBlock(head, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.NoError(t, err)
	require.Equal(t, b.RootHash, restored.RootHash)
	require.Equal(t, b.ShardState.Leader, restored.ShardState.Leader)

	raw, err := types.Cbor.Marshal(head)
	require.NoError(t, err)
	var decoded abdrc.CommittedBlock
	require.NoError(t, types.Cbor.Unmarshal(raw, &decoded))
	require.Equal(t, head.Leader, decoded.Leader)

	state, err := types.Cbor.Marshal(b.ShardState)
	require.NoError(t, err)
	var states ShardStates
	require.NoError(t, types.Cbor.Unmarshal(state, &states))
	require.Equal(t, b.ShardState.Leader, states.Leader)

	for name, mutate := range map[string]func(*abdrc.CommittedBlock){
		"missing leaf": func(h *abdrc.CommittedBlock) { h.Leader = nil },
		"voters": func(h *abdrc.CommittedBlock) {
			h.Leader.Records[len(h.Leader.Records)-1].Voters = []byte{0b1011}
		},
		"genesis": func(h *abdrc.CommittedBlock) { h.Leader.Genesis[0] ^= 1 },
		"floor":   func(h *abdrc.CommittedBlock) { h.Leader.Records[0].Round-- },
	} {
		h := leaderCheckpoint(t, b)
		h.Leader = h.Leader.Clone()
		mutate(h)
		_, err := NewRootBlock(h, crypto.SHA256, s.orchestration, ProfileHandoff)
		require.ErrorIs(t, err, ErrControlCheckpoint, name)
	}
	for name, mutate := range map[string]func(*abdrc.CommittedBlock){
		"another epoch": func(h *abdrc.CommittedBlock) { h.Leader.Epoch++ },
		"last record":   func(h *abdrc.CommittedBlock) { h.Leader.Records[len(h.Leader.Records)-1].Round++ },
	} {
		h := leaderCheckpoint(t, b)
		h.Leader = h.Leader.Clone()
		mutate(h)
		_, err := NewRootBlock(h, crypto.SHA256, s.orchestration, ProfileHandoff)
		require.Error(t, err, name)
		require.False(t, errors.Is(err, ErrControlCheckpoint), "%s is judged before the root: %v", name, err)
	}
}

func TestReservedPartitionsCannotBeShards(t *testing.T) {
	require.True(t, rctypes.ReservedPartition(rctypes.LeaderPartition))
	require.True(t, rctypes.ReservedPartition(rctypes.ControlPartition))
	require.False(t, rctypes.ReservedPartition(1))
	require.EqualValues(t, evmroot.D4ControlPartition, rctypes.ControlPartition)
	require.NotEqual(t, rctypes.LeaderPartition, rctypes.ControlPartition)
}

// The producers of the leaf, not a hand-built head: what the store itself hands out, as a state message and as a handoff checkpoint, rebuilds
// to the certified root only if it carries the leaf.
func TestLeaderRingTravelsWithWhatTheStoreProduces(t *testing.T) {
	zero := make([]byte, 32)
	body, frozen, tr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	s := leaderStore(t)
	installTestFrozenShard(t, s, bytes.Repeat([]byte{0x42}, 32))
	epoch := s.blockTree.Root().BlockData.Epoch

	state, err := s.blockTree.CurrentState()
	require.NoError(t, err)
	require.NotNil(t, state.CommittedHead.Leader, "the state message carries the ring")
	restored, err := NewRootBlock(state.CommittedHead, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.NoError(t, err)
	require.Equal(t, s.blockTree.Root().RootHash, restored.RootHash)

	add := func(round uint64, rec []byte) *ExecutedBlock {
		t.Helper()
		_, err := s.Add(leaderBlock(s, round, leaderQC(round-1, epoch, "a", "b", "c"), [][]byte{rec}), nil)
		require.NoError(t, err)
		return mustBlock(t, s, round)
	}
	add(2, record("prepare", 2, 7, zero, body, zero))
	add(3, record("freeze", 3, 7, frozen, body, zero))
	closing := add(4, record("commit", 4, 7, frozen, body, tr))
	closing.CommitQc = &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: closing.RootHash}}
	head, _, err := checkpointOf(closing)
	require.NoError(t, err)
	require.NotNil(t, head.Leader, "the handoff checkpoint carries the ring")
	back, err := NewRootBlock(head, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.NoError(t, err)
	require.Equal(t, closing.RootHash, back.RootHash)

	// a sealed head's last record is the closing block, whatever the suffix's header round
	forged := *head
	forged.Leader = head.Leader.Clone()
	forged.Leader.Records = append(forged.Leader.Records, rctypes.LeaderRecord{Round: 5, Voters: []byte{0b0111}})
	_, err = NewRootBlock(&forged, crypto.SHA256, s.orchestration, ProfileHandoff)
	require.ErrorIs(t, err, rctypes.ErrLeaderState)
	require.NotErrorIs(t, err, ErrControlCheckpoint, "judged before the root")
}

// The frontier rebuilds the unicity tree from a copy of the committed state: without the leaf it cannot reach the certified root.
func TestFrontierCutRebuildsTheRootWithTheLeaderLeaf(t *testing.T) {
	ring, err := rctypes.NewLeaderState(bytes.Repeat([]byte{7}, 32), 1, 1, 4, 1)
	require.NoError(t, err)
	bt, root, key, _ := reviewCutTreeWithLeaves(t, initialControl(5), ring)
	cut, err := bt.ReadFrontierCutSnapshot(key.PartitionID, root.ShardState.States[key].LastCR.Shard)
	require.NoError(t, err)
	require.True(t, bytes.Equal(root.RootHash, cut.RootHash))
}
