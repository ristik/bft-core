package consensus

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/rootchain/posreject"
)

// Test 8 of briefs/73-reject-result-design.md at the consensus manager: a non-leader discovers a due result and offers it, the leader orders
// it in the only position the payload accepts, before a fresh Prepare, and only when the root state accepts it in that very block.

func rejection(witness []byte) drctypes.PosControl {
	return drctypes.PosControl{Network: testDeployment.RootNetwork, Op: drctypes.OpRejectResult, Reject: &drctypes.RejectContext{Attempt: 1},
		Data: make([]byte, 32), WitnessHash: sha256.Sum256(witness)}
}

func TestARejectionIsPlacedAfterTheClosuresBeforeTheRetirementsAndStamped(t *testing.T) {
	cm := retirementCM(t)
	block := proposalBlock(closure(1), closure(2), preparedRetirement(4, 1).Control)
	var trials int
	added := cm.addRejection(context.Background(), block, []drctypes.PosControl{rejection([]byte("w"))},
		func(b *drctypes.BlockData) error { trials++; return b.Payload.IsValid() })
	require.True(t, added)
	got := block.Payload.PosControls
	require.Equal(t, []uint64{drctypes.OpCloseLiability, drctypes.OpCloseLiability, drctypes.OpRejectResult, drctypes.OpRetirement},
		[]uint64{got[0].Op, got[1].Op, got[2].Op, got[3].Op})
	require.EqualValues(t, 1, got[2].OrderingEpoch)
	require.EqualValues(t, 12, got[2].OrderingRound, "stamped with the position of the block that orders it")
	require.NoError(t, block.Payload.IsValid())
	require.Equal(t, 1, trials)
}

// A candidate the root state refuses (not due any more, stale EVM state, a live handoff) is left out and the next one is tried; the proposal
// never waits for one, and the trials are bounded.
func TestARejectionTheRootStateRefusesIsLeftOut(t *testing.T) {
	cm := retirementCM(t)
	bad, good := rejection([]byte("bad")), rejection([]byte("good"))
	block := proposalBlock(closure(1))
	added := cm.addRejection(context.Background(), block, []drctypes.PosControl{bad, good}, func(b *drctypes.BlockData) error {
		for _, c := range b.Payload.PosControls {
			if c.WitnessHash == bad.WitnessHash {
				return storage.ErrRejectNotDue
			}
		}
		return nil
	})
	require.True(t, added)
	require.Equal(t, good.WitnessHash, block.Payload.PosControls[1].WitnessHash)

	refused := proposalBlock(closure(1))
	many := make([]drctypes.PosControl, 10)
	for i := range many {
		many[i] = rejection([]byte{byte(i)})
	}
	var trials int
	require.False(t, cm.addRejection(context.Background(), refused, many, func(*drctypes.BlockData) error { trials++; return errors.New("refused") }))
	require.Len(t, refused.Payload.PosControls, 1, "the proposal goes out without one")
	require.Equal(t, maxPosTrials, trials)
}

// A block that orders a handoff record takes no rejection (the executor applies the record first, and a live handoff is protected); a block
// that already carries one takes no second.
func TestNoRejectionWhereTheBlockOrdersAHandoffRecordOrAlreadyHasOne(t *testing.T) {
	cm := retirementCM(t)
	w := []byte("queued")
	require.NoError(t, cm.blockStore.StoreWitness(w))
	cm.posQueue.items = []posSubmission{{control: rejection(w), witness: sha256.Sum256(w), expires: 1 << 40, key: []byte{1}}}
	withRecord := proposalBlock()
	withRecord.Payload.HandoffRecords = [][]byte{{1}}
	require.False(t, cm.orderRejectionWith(context.Background(), withRecord, 11, trialOK))
	require.Empty(t, withRecord.Payload.PosControls)
	already := proposalBlock(rejection([]byte("one")))
	require.False(t, cm.orderRejectionWith(context.Background(), already, 11, trialOK))
	require.Len(t, already.Payload.PosControls, 1)
	plain := proposalBlock()
	require.True(t, cm.orderRejectionWith(context.Background(), plain, 11, trialOK), "the control: a queued rejection is ordered")
}

// The automatic path end to end, with no operator: a non-leader's builder finds the fixture's lost result in a real state, offers it through
// the signed submission path, the leader takes it into its queue (the witness pulled as a voter would), prefers it to a fresh Prepare and
// orders it.
func TestANonLeadersDueRejectionReachesTheLeaderAndIsOrderedBeforeAFreshPrepare(t *testing.T) {
	cms := submissionCMs(t)
	leader, other := cms[0], cms[1]
	r := evmstatetest.LoadRejectable(t, "../evmstate/testdata/publication.json", "lost", 100_000)
	var offered []*drctypes.PosControl
	svc, err := posreject.New(posreject.Config{Deployment: testDeployment, Pins: r.Pins, Proofs: func([32]byte) evmstate.ProofSource { return r.Source },
		Submit: func(ctx context.Context, c drctypes.PosControl, witness []byte) error {
			offered = append(offered, &c)
			return other.SubmitPosControl(ctx, c, witness)
		}})
	require.NoError(t, err)
	rc := storage.RejectionContext{Parent: storage.EVMParent{StateRoot: r.StateRoot, BlockHash: [32]byte{0xb1}}, Predecessor: [32]byte{0x77}, Attempt: 0}
	svc.Prepare(rc)
	svc.Wait()
	require.Len(t, offered, 1, "offered by the non-leader without an operator")
	require.Equal(t, 1, other.posQueue.len())

	// what the network delivers to the leader: the signed submission; the leader pulls the witness from the submitter
	p, ok := svc.Ready(rc)
	require.True(t, ok)
	require.NoError(t, leader.blockStore.StoreWitness(p.Witness))
	require.NoError(t, leader.onPosControlSubmission(context.Background(), signed(t, other, *offered[0])))

	parentQC := leader.blockStore.GetHighQc()
	round := parentQC.GetRound() + 1
	require.False(t, leader.preferRejectionWith(context.Background(), parentQC.GetRound(), round, parentQC,
		func(*drctypes.BlockData) error { return storage.ErrRejectNotQuiet }), "a rejection the root state refuses never holds a Prepare back")
	require.True(t, leader.preferRejectionWith(context.Background(), parentQC.GetRound(), round, parentQC, trialOK),
		"a valid due rejection is ordered before a fresh Prepare")
	block := proposalBlock()
	require.True(t, leader.orderRejectionWith(context.Background(), block, parentQC.GetRound(), trialOK))
	require.Equal(t, r.ResultID[:], block.Payload.PosControls[0].Data)
}

// Nothing ready, nothing preferred: a leader with no rejection never holds a Prepare back.
func TestWithoutARejectionThePrepareIsNotHeldBack(t *testing.T) {
	cm := retirementCM(t)
	parentQC := cm.blockStore.GetHighQc()
	require.False(t, cm.preferRejectionWith(context.Background(), parentQC.GetRound(), parentQC.GetRound()+1, parentQC,
		func(*drctypes.BlockData) error { t.Fatal("no trial for nothing"); return nil }))
}

// A committed resolution ends the builder's offers for the result.
func TestACommittedResolutionEndsTheOffers(t *testing.T) {
	cm := retirementCM(t)
	rp := &fakeRejections{pending: [][32]byte{{1}, {2}}}
	svc := cm.blockStore.PosServices()
	svc.Rejections = rp
	cm.forgetResolvedRejections()
	require.Empty(t, rp.resolved, "the committed root here resolved neither")
}

type fakeRejections struct {
	pending  [][32]byte
	resolved [][32]byte
}

func (f *fakeRejections) Prepare(storage.RejectionContext) {}
func (f *fakeRejections) Ready(storage.RejectionContext) (storage.PreparedRejection, bool) {
	return storage.PreparedRejection{}, false
}
func (f *fakeRejections) Resolved(id [32]byte) { f.resolved = append(f.resolved, id) }
func (f *fakeRejections) Pending() [][32]byte  { return f.pending }
