package consensus

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type fakeRetirements struct {
	ready   []storage.PreparedRetirement
	forWhat storage.EVMParent
	pending []storage.RetirementKey
	ordered []storage.RetirementKey
	asked   []int
}

func (f *fakeRetirements) Prepare(storage.EVMParent)        {}
func (f *fakeRetirements) Pending() []storage.RetirementKey { return f.pending }
func (f *fakeRetirements) Ordered(id, generation uint64) {
	f.ordered = append(f.ordered, storage.RetirementKey{ID: id, Generation: generation})
}
func (f *fakeRetirements) Ready(p storage.EVMParent, max int) []storage.PreparedRetirement {
	f.asked = append(f.asked, max)
	if p != f.forWhat {
		return nil
	}
	return f.ready[:min(max, len(f.ready))]
}

func preparedRetirement(id, generation uint64) storage.PreparedRetirement {
	witness := []byte{byte(id), byte(generation), 0xee}
	data := make([]byte, 96)
	data[31], data[63] = byte(id), byte(generation)
	return storage.PreparedRetirement{ID: id, Generation: generation, Witness: witness, Control: drctypes.PosControl{
		Network: testDeployment.RootNetwork, Op: drctypes.OpRetirement, Retire: &drctypes.RetireContext{}, Data: data, WitnessHash: sha256.Sum256(witness)}}
}

func proposalBlock(controls ...drctypes.PosControl) *drctypes.BlockData {
	return &drctypes.BlockData{Version: 3, Round: 12, Epoch: 1, Payload: &drctypes.Payload{Version: 3, PosControls: controls}}
}

func closure(epoch uint64) drctypes.PosControl {
	c := drctypes.PosControl{Network: testDeployment.RootNetwork, Op: drctypes.OpCloseLiability, Close: &drctypes.CloseContext{ClosedEpoch: epoch}, Data: make([]byte, 192)}
	c.Data[56] = 1
	return c
}

func idsOf(controls []drctypes.PosControl) (out [][2]uint64) {
	for _, c := range controls {
		if c.Op == drctypes.OpRetirement {
			out = append(out, retirementKeyOf(c))
		}
	}
	return out
}

func retirementCM(t *testing.T) *ConsensusManager {
	t.Helper()
	return submissionCMs(t)[0]
}

var parentP = storage.EVMParent{StateRoot: [32]byte{1}, BlockHash: [32]byte{2}}

func trialOK(*drctypes.BlockData) error { return nil }

func TestPreparedRetirementsAreOrderedAfterTheClosuresInAscendingKeyOrderAndStamped(t *testing.T) {
	cm := retirementCM(t)
	rp := &fakeRetirements{forWhat: parentP, ready: []storage.PreparedRetirement{preparedRetirement(4, 1), preparedRetirement(9, 1)}}
	block := proposalBlock(closure(1), closure(2), preparedRetirement(6, 1).Control) // a submitted one in between
	block.Payload.PosControls[2].Data = preparedRetirement(6, 1).Control.Data
	var trials int
	cm.addRetirements(context.Background(), block, 11, parentP, rp, func(b *drctypes.BlockData) error { trials++; return b.Payload.IsValid() })

	got := block.Payload.PosControls
	require.Len(t, got, 5)
	require.Equal(t, drctypes.OpCloseLiability, got[0].Op, "the mandatory closures keep their first place")
	require.Equal(t, drctypes.OpCloseLiability, got[1].Op)
	require.Equal(t, [][2]uint64{{4, 1}, {6, 1}, {9, 1}}, idsOf(got), "ascending (id, generation) among the Retirements")
	for _, c := range got[2:] {
		if c.Op == drctypes.OpRetirement && (retirementKeyOf(c) != [2]uint64{6, 1}) {
			require.EqualValues(t, 1, c.OrderingEpoch)
			require.EqualValues(t, 12, c.OrderingRound, "stamped with the position of the block that orders it")
		}
	}
	require.NoError(t, block.Payload.IsValid(), "a valid payload")
	require.Equal(t, 2, trials, "each added Retirement was trial-executed on the whole block")
	for _, p := range rp.ready {
		require.True(t, cm.blockStore.HasWitness(p.Control.WitnessHash), "the witness is retained before the block is proposed")
	}
}

func TestNothingIsAddedForAnotherParentOrWhenNothingIsReady(t *testing.T) {
	cm := retirementCM(t)
	other := storage.EVMParent{StateRoot: [32]byte{9}}
	rp := &fakeRetirements{forWhat: other, ready: []storage.PreparedRetirement{preparedRetirement(1, 1)}}
	block := proposalBlock(closure(1))
	cm.addRetirements(context.Background(), block, 11, parentP, rp, trialOK)
	require.Len(t, block.Payload.PosControls, 1, "the parent moved on while the proof was collected: the stale proof is not used")
	// a slow or missing RPC: nothing is ready, the proposal goes out without a Retirement
	rp = &fakeRetirements{forWhat: parentP}
	cm.addRetirements(context.Background(), block, 11, parentP, rp, func(*drctypes.BlockData) error { t.Fatal("no trial for nothing"); return nil })
	require.Len(t, block.Payload.PosControls, 1)
}

func TestARetirementTheRootStateRefusesIsLeftOutAndNeverBlocksTheProposal(t *testing.T) {
	cm := retirementCM(t)
	rp := &fakeRetirements{forWhat: parentP, ready: []storage.PreparedRetirement{preparedRetirement(1, 1), preparedRetirement(2, 1), preparedRetirement(3, 1)}}
	block := proposalBlock(closure(1))
	cm.addRetirements(context.Background(), block, 11, parentP, rp, func(b *drctypes.BlockData) error {
		for _, k := range idsOf(b.Payload.PosControls) {
			if k[0] == 2 {
				return errors.New("progress below the liability anchor")
			}
		}
		return nil
	})
	require.Equal(t, [][2]uint64{{1, 1}, {3, 1}}, idsOf(block.Payload.PosControls), "the refused one is skipped, the others are still ordered")
	require.Equal(t, drctypes.OpCloseLiability, block.Payload.PosControls[0].Op)
}

func TestTheWorkOfOneProposalIsBounded(t *testing.T) {
	cm := retirementCM(t)
	var ready []storage.PreparedRetirement
	for i := uint64(1); i <= 20; i++ {
		ready = append(ready, preparedRetirement(i, 1))
	}
	rp := &fakeRetirements{forWhat: parentP, ready: ready}

	block := proposalBlock()
	cm.addRetirements(context.Background(), block, 11, parentP, rp, trialOK)
	require.Len(t, block.Payload.PosControls, maxRetirementsPerBlock)
	require.Equal(t, []int{maxRetirementsPerBlock}, rp.asked, "no more is asked for than fits")

	// every one refused: at most maxRetirementTrials trial executions are spent and the block is as it was
	block = proposalBlock(closure(1))
	var trials int
	cm.addRetirements(context.Background(), block, 11, parentP, rp, func(*drctypes.BlockData) error { trials++; return errors.New("refused") })
	require.Equal(t, maxRetirementTrials, trials)
	require.Len(t, block.Payload.PosControls, 1)

	// a block already at the control cap takes none
	full := make([]drctypes.PosControl, drctypes.MaxPosControls)
	for i := range full {
		full[i] = closure(uint64(i + 1))
	}
	block = proposalBlock(full...)
	cm.addRetirements(context.Background(), block, 11, parentP, rp, func(*drctypes.BlockData) error { t.Fatal("no room, no trial"); return nil })
	require.Len(t, block.Payload.PosControls, drctypes.MaxPosControls)
}

func TestARetirementAnOperatorAlreadySubmittedIsNotOrderedTwice(t *testing.T) {
	cm := retirementCM(t)
	p := preparedRetirement(5, 2)
	rp := &fakeRetirements{forWhat: parentP, ready: []storage.PreparedRetirement{p}}
	block := proposalBlock(p.Control)
	cm.addRetirements(context.Background(), block, 11, parentP, rp, func(*drctypes.BlockData) error { t.Fatal("already in the block"); return nil })
	require.Len(t, block.Payload.PosControls, 1)
}

func TestACommittedRetirementEndsItsRequest(t *testing.T) {
	rp := &fakeRetirements{pending: []storage.RetirementKey{{ID: 1, Generation: 1}, {ID: 3, Generation: 2}}}
	forgetOrdered(rp, func(id, generation uint64) bool { return id == 3 && generation == 2 })
	require.Equal(t, []storage.RetirementKey{{ID: 3, Generation: 2}}, rp.ordered)
	// a chain with no Retirement builder does nothing at all
	cm := retirementCM(t)
	require.Nil(t, cm.retirementProposer())
	cm.forgetOrderedRetirements()
	cm.prepareRetirements(context.Background(), proposalBlock())
	cm.orderRetirements(context.Background(), proposalBlock(), 11)
}

func TestInsertRetirementKeepsTheOnlyOrderAPayloadAccepts(t *testing.T) {
	var controls []drctypes.PosControl
	controls = append(controls, closure(1))
	for _, id := range []uint64{7, 2, 9, 2} {
		controls = insertRetirement(controls, preparedRetirement(id, 1).Control)
		if id == 2 && len(idsOf(controls)) == 4 {
			break
		}
	}
	got := idsOf(controls)
	for i := 1; i < len(got); i++ {
		require.LessOrEqual(t, got[i-1][0], got[i][0])
	}
	require.Equal(t, drctypes.OpCloseLiability, controls[0].Op)
}
