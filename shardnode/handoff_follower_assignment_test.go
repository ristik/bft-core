package shardnode

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

// stepHistory accepts every bundle and reports which shard configuration hash the follower expected the root to
// certify for it; each handoff names the hash that takes over after it.
type stepHistory struct {
	next     map[uint64][]byte
	expected map[uint64][]byte
	order    []uint64
}

func (*stepHistory) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return &types.RootTrustBaseV1{}, nil
}

func (h *stepHistory) InstallHandoff(_ context.Context, b handoffdelivery.Bundle, _ types.PartitionID, _ types.ShardID, conf []byte) (handoffdelivery.Verified, error) {
	h.expected[b.Body.Epoch] = bytes.Clone(conf)
	h.order = append(h.order, b.Body.Epoch)
	return handoffdelivery.Verified{NextConfHash: h.next[b.Body.Epoch]}, nil
}

// Every handoff is checked against the assignment that is active when it commits, not the genesis one: two consecutive
// EVM rotations, a supersession after a rotation, then a root-only handoff, replayed again after a restart.
func TestHandoffFollowerChecksEachHandoffAgainstTheActiveAssignment(t *testing.T) {
	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	genesis, s1, s2, s3 := hash(1), hash(2), hash(3), hash(4)
	next := map[uint64][]byte{2: s1, 3: s2, 4: s3, 5: s3}    // rotation, rotation, supersession of s2 by s3, root-only
	want := map[uint64][]byte{2: genesis, 3: s1, 4: s2, 5: s3} // the hash the root certifies when each commits
	dir := t.TempDir()
	newFollower := func(h *stepHistory) *HandoffFollower {
		return &HandoffFollower{Host: testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), History: h,
			AnchorEpoch: 1, Directory: dir, ConfHash: genesis}
	}
	h := &stepHistory{next: next, expected: map[uint64][]byte{}}
	f := newFollower(h)
	for epoch := uint64(2); epoch <= 5; epoch++ {
		require.NoError(t, f.save(epoch, handoffdelivery.Bundle{
			Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: epoch - 1}},
			Body:  evmroot.TrustBaseBodyV2{Epoch: epoch}}))
	}
	require.NoError(t, f.Restore(context.Background()))
	require.Equal(t, []uint64{2, 3, 4, 5}, h.order)
	require.Equal(t, want, h.expected)

	restarted := &stepHistory{next: next, expected: map[uint64][]byte{}}
	require.NoError(t, newFollower(restarted).Restore(context.Background()))
	require.Equal(t, want, restarted.expected, "a restart derives the same active assignment from the durable handoffs")
}

// verifyingHistory is the production check without the durable trust store: the real Verify.
type verifyingHistory struct {
	fixture   handoffbundle.Fixture
	installed int
}

func (h *verifyingHistory) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return h.fixture.Old, nil
}

func (h *verifyingHistory) InstallHandoff(_ context.Context, b handoffdelivery.Bundle, p types.PartitionID, s types.ShardID, conf []byte) (handoffdelivery.Verified, error) {
	v, err := handoffdelivery.Verify(b, h.fixture.Old, p, s, conf)
	if err == nil {
		h.installed++
	}
	return v, err
}

// A byzantine root serves an assignment step with its candidate removed. Verify refuses it, so the follower stores
// nothing, and a restart finds no durable bundle to wedge on.
func TestHandoffFollowerNeverPersistsABundleWithoutItsCandidate(t *testing.T) {
	preimage := []byte("the assignment candidate the successor body binds")
	f := handoffbundle.NewBound(t, preimage)
	stripped := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	history := &verifyingHistory{fixture: f}
	dir := t.TempDir()
	offered := 0
	callbacks := 0
	build := func() *HandoffFollower {
		return &HandoffFollower{Host: testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), History: history,
			Partition: f.Partition, Shard: f.Shard, ConfHash: f.ConfHash, AnchorEpoch: 1, Directory: dir,
			ArchiveReplicas: []peer.ID{"archive"},
			FetchArchive: func(context.Context, peer.ID, uint64) (handoffdelivery.Bundle, error) {
				offered++
				return stripped, nil
			},
			OnInstalled: func(context.Context, handoffdelivery.Bundle, handoffdelivery.Verified) error { callbacks++; return nil }}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	require.NoError(t, build().Run(ctx))
	require.Positive(t, offered, "the stripped bundle was offered")
	require.Zero(t, history.installed)
	require.Zero(t, callbacks)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "an unverified bundle is never persisted")

	restarted := build()
	require.NoError(t, restarted.Restore(context.Background()), "a restart is not wedged by anything the byzantine root served")
	require.Zero(t, callbacks)
}
