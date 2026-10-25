package storage_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// The counter regressions of contracts#73 (briefs/73-reject-result-design.md, tests 1, 2 and 4) through the real authority: the witness is
// gathered from a real Merkle-Patricia state built from the contracts' own fixture, whose election attempt is 1, and verified by
// evmstate.Authority. The root attempt the control names is the root's, deliberately unlike the election's.

const fixtureReservedAt = 100_000 // PublicationFixture.t.sol reserves at registry progress 100,000

type realReject struct {
	r        *evmstatetest.Rejectable
	services *storage.PosServices
	block    *rctypes.BlockData
	control  rctypes.PosControl
}

type witnessMap map[[32]byte][]byte

func (m witnessMap) Witness(h [32]byte) ([]byte, error) { return m[h], nil }

type noClosures struct{}

func (noClosures) VerifyClosure([]byte, uint64) (storage.ClosureFacts, error) {
	return storage.ClosureFacts{}, storage.ErrPosControlRefused
}

func newRealReject(t *testing.T, scenario string, progress, rootAttempt uint64) realReject {
	r := evmstatetest.LoadRejectable(t, "../../evmstate/testdata/publication.json", scenario, progress)
	dep := storage.PosDeployment{RootNetwork: 7, Deployment: evmassign.Deployment{NetworkWord: r.Pins.NetworkWord, ChainID: [32]byte{31: 9},
		Custody: r.Pins.Custody}, Election: r.Pins.Election}
	hash := sha256.Sum256(r.Witness)
	return realReject{r: r,
		services: &storage.PosServices{Deployment: dep, Authority: noClosures{}, Witnesses: witnessMap{hash: r.Witness}, EVM: evmstate.Authority{Pins: r.Pins}},
		block:    &rctypes.BlockData{Epoch: 1, Round: 50, Timestamp: 2_000, Payload: &rctypes.Payload{}},
		control: rctypes.PosControl{Network: 7, ChainID: dep.ChainID, Custody: dep.Custody, OrderingEpoch: 1, OrderingRound: 50,
			Op: rctypes.OpRejectResult, WitnessHash: hash, Data: r.ResultID[:],
			Reject: &rctypes.RejectContext{PredecessorBodyID: [32]byte{0x77}, Attempt: rootAttempt, EVMStateRoot: r.StateRoot}}}
}

func (x realReject) run(ctl *evmroot.ControlState) (*evmroot.ControlState, []rootrecords.Record, rootrecords.State, error) {
	return storage.RejectForTest(rootrecords.NewState(1, 1), ctl, x.r.StateRoot, nil, x.block, x.control, x.services)
}

func controlAt(phase string, attempt uint64) *evmroot.ControlState {
	pred := [32]byte{0x77}
	return &evmroot.ControlState{Network: 7, Epoch: 1, PredecessorBodyID: pred[:], Phase: phase, Attempt: attempt, OrderedRound: 40}
}

// Test 1: a lost result at an idle root. The election's attempt is 1, the root's next attempt 0: the rejection is accepted, one
// SessionClosed of the result, aborted at 0 (the next Prepare is attempt 1). Before #73 the unlike counters refused it for good.
func TestRealRejectOfALostResultAtAnIdleRootDespiteUnlikeCounters(t *testing.T) {
	x := newRealReject(t, "lost", fixtureReservedAt, 0)
	require.EqualValues(t, 1, x.r.ElectionAttempt, "premise: the counters differ")
	replaced, records, state, err := x.run(controlAt("idle", 0))
	require.NoError(t, err)
	require.Equal(t, "aborted", replaced.Phase)
	require.EqualValues(t, 0, replaced.Attempt)
	require.Len(t, records, 1)
	require.Equal(t, rootrecords.KindSessionClosed, records[0].Kind)
	require.Equal(t, x.r.ResultID[:], records[0].Data)
	require.True(t, state.IsResolved(x.r.ResultID))
}

// Test 2: the root's counter ran ahead of the election's (Prepare-only Aborts at the root: aborted at 2, next 3) and the result is mature.
// The rejection at 3 is accepted; at the aborted attempt itself, or at the election's attempt, it is refused.
func TestRealRejectAfterRootAttemptsDrifted(t *testing.T) {
	mature := uint64(fixtureReservedAt + storage.ResultReservationLifetimeProgress)
	for _, scenario := range []string{"reserved", "published"} {
		x := newRealReject(t, scenario, mature, 3)
		replaced, records, _, err := x.run(controlAt("aborted", 2))
		require.NoError(t, err, scenario)
		require.EqualValues(t, 3, replaced.Attempt, scenario)
		require.Len(t, records, 1, scenario)
		for _, stale := range []uint64{2, x.r.ElectionAttempt} {
			y := newRealReject(t, scenario, mature, stale)
			_, records, _, err := y.run(controlAt("aborted", 2))
			require.ErrorIs(t, err, storage.ErrRejectAttempt, "%s at %d", scenario, stale)
			require.Empty(t, records)
		}
	}
}

// Test 4: the loss branch. A young result proven lost is accepted, published or not, with the counters unlike; the identical unlost state
// is refused as not due, and only a mature one is accepted. A witness of another result, or none, is no rejection.
func TestRealRejectLossBranch(t *testing.T) {
	for _, scenario := range []string{"reservedLost", "lost"} {
		_, records, _, err := newRealReject(t, scenario, fixtureReservedAt, 0).run(controlAt("idle", 0))
		require.NoError(t, err, scenario)
		require.Len(t, records, 1, scenario)
	}
	for _, scenario := range []string{"reserved", "published"} {
		_, records, _, err := newRealReject(t, scenario, fixtureReservedAt, 0).run(controlAt("idle", 0))
		require.ErrorIs(t, err, storage.ErrRejectNotDue, scenario)
		require.Empty(t, records)
		_, _, _, err = newRealReject(t, scenario, fixtureReservedAt+storage.ResultReservationLifetimeProgress-1, 0).run(controlAt("idle", 0))
		require.ErrorIs(t, err, storage.ErrRejectNotDue, "%s one round short", scenario)
	}

	x := newRealReject(t, "lost", fixtureReservedAt, 0)
	other := [32]byte{0xab}
	x.control.Data = other[:]
	_, records, _, err := x.run(controlAt("idle", 0))
	require.ErrorIs(t, err, storage.ErrPosControlRefused, "the witness proves another result")
	require.Empty(t, records)

	y := newRealReject(t, "lost", fixtureReservedAt, 0)
	y.services.Witnesses = witnessMap{}
	_, _, _, err = y.run(controlAt("idle", 0))
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable, "a missing witness is unavailable, never a rejection")
}
