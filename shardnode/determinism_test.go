package shardnode_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// broadcastDisseminator is round_test.go's LoopbackDisseminator generalized
// to more than one Await-ing consumer: every validator but the leader needs
// the SAME published Block for a round, not just one of them. This is what
// C2's live NetDisseminator does over libp2p; here it does the identical job
// in-process so the determinism harness below needs no network at all — see
// docs/engine-api-adapter-plan.md C2.4.
type broadcastDisseminator struct {
	mu    sync.Mutex
	round map[uint64]*broadcastRound
}

type broadcastRound struct {
	ready chan struct{}
	block shardnode.Block
}

func newBroadcastDisseminator() *broadcastDisseminator {
	return &broadcastDisseminator{round: make(map[uint64]*broadcastRound)}
}

func (d *broadcastDisseminator) entryFor(round uint64) *broadcastRound {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.round[round]
	if !ok {
		e = &broadcastRound{ready: make(chan struct{})}
		d.round[round] = e
	}
	return e
}

func (d *broadcastDisseminator) Publish(_ context.Context, round uint64, b shardnode.Block) error {
	e := d.entryFor(round)
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-e.ready:
		// Already published for this round — an honest leader publishes
		// once; ignore a duplicate rather than panic on a closed channel.
	default:
		e.block = b
		close(e.ready)
	}
	return nil
}

func (d *broadcastDisseminator) Await(ctx context.Context, round uint64) (shardnode.Block, error) {
	e := d.entryFor(round)
	select {
	case <-e.ready:
		return e.block, nil
	case <-ctx.Done():
		return shardnode.Block{}, fmt.Errorf("awaiting round %d: %w", round, ctx.Err())
	}
}

// determinismValidator is one in-process replica in the harness: its own
// Fake executor (independent state, never shared with the others) driven by
// its own Round, all pointed at the one shared broadcastDisseminator so the
// leader's block really does reach every follower exactly as it would over
// the network.
type determinismValidator struct {
	nodeID string
	exec   *executortest.Fake
	round  *shardnode.Round
	sub    *recordingSubmitter
}

func newDeterminismValidator(t *testing.T, disseminator *broadcastDisseminator) *determinismValidator {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pk, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	nodeID := "node-" + string(pk[:8])

	exec := executortest.New()
	sub := &recordingSubmitter{}
	r := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, disseminator, signer, sub, nil)
	return &determinismValidator{nodeID: nodeID, exec: exec, round: r, sub: sub}
}

// TestDeterminism_UCStreamReplayedAcrossValidatorsConvergesToIdenticalState
// replays one root-chain UC stream through N independent in-process
// validators — rotating which one is leader every round, exactly as a real
// shard would — and checks that every validator's Executor ends up with
// byte-identical state after each round is certified. Leader and followers
// take different code paths to get there (Build+Seal vs. Await the
// disseminated block, see produceBlock), so this is the thing that actually
// needs proving: that a follower committing what it merely received produces
// the same result as the leader who built it, on every validator, every
// round. That is the property an EVM executor (independent reth processes,
// each applying the same disseminated payload) depends on for safety — see
// docs/adr/0001-executor-boundary.md.
func TestDeterminism_UCStreamReplayedAcrossValidatorsConvergesToIdenticalState(t *testing.T) {
	ctx := context.Background()
	const n = 4
	const rounds = 6 // more than n, so leadership rotates through twice

	disseminator := newBroadcastDisseminator()
	validators := make([]*determinismValidator, n)
	for i := range validators {
		validators[i] = newDeterminismValidator(t, disseminator)
	}

	uc := genesisUC(1000)
	for round := uint64(1); round <= rounds; round++ {
		leader := validators[(round-1)%n]

		// The leader must run first: it is the one that Builds, Seals and
		// Publishes to the shared disseminator. Followers' HandleCertificate
		// blocks in Await until that Publish happens, so processing them
		// before the leader (or concurrently, without care) would just make
		// them wait out the full await timeout instead of exercising the
		// real dissemination path.
		require.NoErrorf(t, leader.round.HandleCertificate(ctx, uc, tr(round, 0, leader.nodeID)),
			"round %d, leader %s", round, leader.nodeID)
		for _, v := range validators {
			if v == leader {
				continue
			}
			require.NoErrorf(t, v.round.HandleCertificate(ctx, uc, tr(round, 0, leader.nodeID)),
				"round %d, follower %s", round, v.nodeID)
		}

		// Every validator — leader and followers alike — must have submitted
		// the identical InputRecord for this round: followers derive theirs
		// from the disseminated Block, not by building their own, so any
		// divergence here means dissemination or IR construction is not
		// actually reproducing the leader's result.
		want := leader.sub.last(t).InputRecord
		for _, v := range validators {
			got := v.sub.last(t).InputRecord
			require.Equalf(t, want.Hash, got.Hash, "round %d: validator %s StateRoot diverged from leader %s", round, v.nodeID, leader.nodeID)
			require.Equalf(t, want.BlockHash, got.BlockHash, "round %d: validator %s BlockHash diverged from leader %s", round, v.nodeID, leader.nodeID)
			require.Equalf(t, want.PreviousHash, got.PreviousHash, "round %d: validator %s PreviousHash diverged from leader %s", round, v.nodeID, leader.nodeID)
		}

		// The root chain certifies exactly what the leader submitted — the
		// honest-majority happy path, same convention as certifyFrom in
		// round_test.go.
		uc = certifyFrom(leader.sub.last(t), round+1, 1000+round)
	}

	// One last UC so the final round's commitPrevious actually runs on every
	// validator, then compare committed Executor state head-to-head — not
	// just what was submitted, but what each independently ended up with on
	// disk (in Fake's case, in memory).
	finalLeader := validators[rounds%n]
	require.NoError(t, finalLeader.round.HandleCertificate(ctx, uc, tr(rounds+1, 0, finalLeader.nodeID)))
	for _, v := range validators {
		if v == finalLeader {
			continue
		}
		require.NoError(t, v.round.HandleCertificate(ctx, uc, tr(rounds+1, 0, finalLeader.nodeID)))
	}
	want, err := validators[0].exec.Head(ctx)
	require.NoError(t, err)
	for _, v := range validators[1:] {
		got, err := v.exec.Head(ctx)
		require.NoError(t, err)
		require.Equalf(t, want.StateRoot, got.StateRoot, "validator %s committed state diverged from %s", v.nodeID, validators[0].nodeID)
		require.Equalf(t, want.Number, got.Number, "validator %s committed block number diverged from %s", v.nodeID, validators[0].nodeID)
	}
}
