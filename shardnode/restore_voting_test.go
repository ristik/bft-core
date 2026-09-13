package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// steadyExecutor is a minimal Executor pinned at one block: enough to reach the point where a Round
// decides whether to submit, and nothing more. It is written here rather than reused from
// shardnode/executortest because that package imports shardnode, so an in-package test cannot
// import it — and this test needs the unexported restore path (FileStore, verifyRestoredLUC,
// resumeFrom) that only an in-package test can reach.
type steadyExecutor struct {
	mu        sync.Mutex
	head      BlockRef
	headCalls int
	seals     int
	commits   []Hash
}

func (e *steadyExecutor) Head(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.headCalls++
	return e.head, nil
}

// GenesisBlock answers from configuration, not from the head: this stub is pinned at one block, so
// its genesis is the block zero it was configured with.
func (e *steadyExecutor) GenesisBlock(context.Context) (BlockRef, error) {
	return BlockRef{Number: 0, Hash: []byte{0x00}, StateRoot: []byte{0x00}}, nil
}

func (e *steadyExecutor) Commit(_ context.Context, hash Hash) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commits = append(e.commits, hash)
	return StatusValid, nil
}

func (e *steadyExecutor) Build(context.Context, RoundParams) (BuildID, error) { return "b", nil }

func (e *steadyExecutor) Seal(context.Context, BuildID) (Block, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seals++
	// A quiet block: the state does not move, which is the ordinary shape of an idle round.
	return Block{Number: e.head.Number, Hash: e.head.Hash, StateRoot: e.head.StateRoot, ParentHash: e.head.Hash}, nil
}

func (e *steadyExecutor) Verify(context.Context, Block, RoundParams) (Status, error) {
	return StatusValid, nil
}

func (e *steadyExecutor) observed() (heads, seals int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.headCalls, e.seals
}

// countingSubmitter is the thing under test in this file: whether anything is signed at all.
type countingSubmitter struct {
	mu   sync.Mutex
	sent []uint64
	reqs []*certification.BlockCertificationRequest
}

func (s *countingSubmitter) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, req.InputRecord.RoundNumber)
	s.reqs = append(s.reqs, req)
	return nil
}

func (s *countingSubmitter) requests() []*certification.BlockCertificationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*certification.BlockCertificationRequest(nil), s.reqs...)
}

func (s *countingSubmitter) rounds() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.sent...)
}

/*
TestRestoredNodeIsNonVoting exercises the real restore-to-signing boundary: the production sequence
LoadLUC -> verifyRestoredLUC -> resumeFrom, and then certificates driven through the real Round to
the point where it would submit.

This is the boundary that was open. Node.New loaded the persisted certificate, authenticated it,
seeded the certificate cursor, and then built an UNRESTRICTED Round — so a resumed process signed
from its next certificate onward, with nothing standing between "the checkpoint decoded and
verified" and "this node votes again". Verification proves a checkpoint GENUINE, not CURRENT: an
entire older checkpoint replays perfectly (§6.1, and continuity_counterexample_test.go), restoring
one rolls the observation cursor backwards, and that cursor is what stops this node acting twice in
one round. A node resumed from a stale file could re-enter partition rounds it had already voted in
and sign again — a safety problem, not a liveness one.

The predecessor of this test asserted that two zero-valued Round structs had no anchor. That is true
of any zero-valued struct and exercised no signing path at all, which is why it passed while the
node signed.

Since #105 step 4 this test covers the signer that keeps no independent record, which is still refused
unconditionally: the round here signs with the local key. A restored round signing through a signing
authority's record, and only what that record admits, is asserted in
restore_authority_process_test.go against a real authority process.
*/
func TestRestoredNodeIsNonVoting(t *testing.T) {
	ctx := context.Background()

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)

	prevState := bytes.Repeat([]byte{0xa0}, 32)
	stateRoot := bytes.Repeat([]byte{0xa1}, 32)
	blockHash := bytes.Repeat([]byte{0xb1}, 32)
	zero := make([]byte, 32)

	technicalFor := func(round uint64) *certification.TechnicalRecord {
		return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: "restored-node", StatHash: zero, FeeHash: zero}
	}
	sign := func(round, rootRound uint64, prev, hash, block []byte, next uint64) *types.UnicityCertificate {
		t.Helper()
		ir := &types.InputRecord{
			Version: 1, RoundNumber: round, PreviousHash: prev, Hash: hash, BlockHash: block,
			SummaryValue: []byte{}, Timestamp: 1,
		}
		trHash, err := technicalFor(next).Hash()
		require.NoError(t, err)
		return testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, zero, trHash)
	}

	// The checkpoint on disk: round 4, non-quiet, leaving the executor at blockHash/stateRoot.
	checkpoint := sign(4, 40, prevState, stateRoot, blockHash, 5)

	// The certificates that arrive next. Round 5 is NON-QUIET: it installs an anchor that exactly
	// matches the executor's head, so it is the certificate that would re-authorize a restored
	// process if the only barrier were "has this Round seen a block hash yet". Round 6 is an
	// ordinary quiet continuation.
	nonQuiet5 := sign(5, 41, prevState, stateRoot, blockHash, 6)
	quiet6 := sign(6, 42, stateRoot, stateRoot, nil, 7)

	newRoundOver := func(exec Executor, sub Submitter) *Round {
		return NewRound("restored-node", authPartitionID, types.ShardID{}, exec,
			NewLoopbackDisseminator(), signer, sub, nil)
	}
	newExecutor := func() *steadyExecutor {
		return &steadyExecutor{head: BlockRef{Number: 4, Hash: blockHash, StateRoot: stateRoot}}
	}

	t.Run("control: the same certificates over a process that did not restore are voted on", func(t *testing.T) {
		// Without this the test below could pass because the fixtures never permit a vote at all.
		exec, sub := newExecutor(), &countingSubmitter{}
		round := newRoundOver(exec, sub)
		require.NoError(t, round.HandleCertificate(ctx, nonQuiet5, technicalFor(6)))
		require.NoError(t, round.HandleCertificate(ctx, quiet6, technicalFor(7)))
		require.Equal(t, []uint64{6, 7}, sub.rounds(), "an ordinary running node votes on these")
	})

	t.Run("the production restore sequence yields a node that follows but never signs", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "luc.cbor")
		store := NewFileStore(path)
		require.NoError(t, store.SaveLUC(checkpoint))

		// --- restart: exactly what Node.New does, in the same order ---
		loaded, err := store.LoadLUC()
		require.NoError(t, err)
		require.NoError(t, verifyRestoredLUC(loaded, stubTrustBaseStore{tb: tb}, authPartitionID, types.ShardID{}, confHash),
			"the checkpoint is genuine — which is the whole point: authenticity is not currency")

		exec, sub := newExecutor(), &countingSubmitter{}
		round := newRoundOver(exec, sub)
		health := NewHealth()
		round.SetHealth(health)
		client := &BFTClient{}
		resumeFrom(client, round, loaded)

		require.NotNil(t, client.luc, "the certificate cursor is restored")
		require.False(t, health.Snapshot().Voting, "and the node reports itself non-voting before any UC arrives")
		require.Contains(t, health.Snapshot().NonVotingReason, "#105")

		require.NoError(t, round.HandleCertificate(ctx, nonQuiet5, technicalFor(6)),
			"abstaining is not an error: the node follows the shard normally")
		require.Empty(t, sub.rounds(), "a restored process must not sign")

		// The independent half of the hazard: a non-quiet certificate installs an anchor that
		// matches this executor's head exactly. An anchor-presence gate alone would re-authorize
		// the restored process here, one round after the restart.
		require.NotNil(t, round.continuity.anchor, "it did observe the certificate")
		require.Equal(t, blockHash, []byte(round.continuity.anchor.BlockHash))

		require.NoError(t, round.HandleCertificate(ctx, quiet6, technicalFor(7)))
		require.Empty(t, sub.rounds(), "still non-voting a round later, anchor or no anchor")

		// Observing, reconciling and BLOCK PRODUCTION are all permitted, and all happened: the
		// executor was consulted every round and sealed a block in each, because this node was
		// the leader (technicalFor names it). Only the certification request is withheld.
		//
		// This is not incidental. A gate that also stopped block production would leave every
		// round led by a restored node with no proposal at all, stalling validators that are
		// themselves perfectly healthy — measured in scripts/chaos-evm.sh before the gate was
		// narrowed to the signature.
		headCalls, seals := exec.observed()
		require.Equal(t, 2, headCalls)
		require.Equal(t, 2, seals, "a non-voting node still leads its rounds and publishes blocks")
		require.False(t, health.Snapshot().Voting)
	})

	t.Run("restoring the cursor without the signing gate is not expressible", func(t *testing.T) {
		// resumeFrom is the only production caller of SeedLUC, and it does both halves. This
		// asserts the pairing directly, so that a future change that seeds a cursor somewhere
		// else has to confront the gate rather than silently bypass it.
		exec, sub := newExecutor(), &countingSubmitter{}
		round := newRoundOver(exec, sub)
		client := &BFTClient{}
		resumeFrom(client, round, checkpoint)
		require.NotNil(t, client.luc)
		require.NotNil(t, round.restoredFrom)
		require.Equal(t, uint64(4), *round.restoredFrom)
	})
}
