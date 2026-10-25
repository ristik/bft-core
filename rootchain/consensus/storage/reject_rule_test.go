package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// The tests of briefs/73-reject-result-design.md ("Required tests") at the control executor; the counter regressions with real
// contract-derived witnesses are reject_real_test.go.

// Test 3: the age is exact and cannot wrap. Unlost, 1,023 rounds after the reservation refuses and 1,024 accepts; a registry behind the
// reservation refuses; values near the top of uint64 neither wrap into eligibility nor out of it.
func TestRejectDueAgeIsExactAndDoesNotWrap(t *testing.T) {
	const max = math.MaxUint64
	life := uint64(ResultReservationLifetimeProgress)
	for _, c := range []struct {
		name           string
		reservedAt, at uint64
		lost, due      bool
	}{
		{"one round short", 100, 100 + life - 1, false, false},
		{"exactly the lifetime", 100, 100 + life, false, true},
		{"the registry is behind the reservation", 100, 99, false, false},
		{"lost needs no age", 100, 100, true, true},
		{"lost does not excuse a registry behind", 100, 99, true, false},
		{"reserved near the top: reservedAt+life would wrap", max - 5, max, false, false},
		{"reserved exactly the lifetime below the top", max - life, max, false, true},
		{"the widest distance", 0, max, false, true},
		{"the registry at zero under a top reservation", max, 0, true, false},
	} {
		got := RejectDue(RejectFacts{ReservedAt: c.reservedAt, Progress: c.at, Lost: c.lost})
		require.Equal(t, c.due, got, c.name)
	}
	require.EqualValues(t, 1024, ResultReservationLifetimeProgress, "one consensus constant")
}

// Test 3, continued: only proven progress matures a reservation. The same young facts are refused at any carrying round and time.
func TestRejectIsNotMaturedByTheCarryingRoundOrTime(t *testing.T) {
	for _, round := range []uint64{50, 50 + ResultReservationLifetimeProgress, 1 << 40} {
		f := newEVMFx(t, rctypes.OpRejectResult)
		f.evm.reject.Progress = f.evm.reject.ReservedAt + ResultReservationLifetimeProgress - 1
		f.block.Round, f.ctl.OrderingRound = round, round
		f.block.Timestamp = 2_000 + round*1_000
		_, err := f.run()
		require.ErrorIs(t, err, ErrRejectNotDue, "round %d", round)
		require.Empty(t, f.step.records)
	}
}

// Test 4 at the executor: a young lost reservation is accepted, the identical unlost one refused.
func TestRejectOfAYoungResultNeedsItsProvenLoss(t *testing.T) {
	f := newEVMFx(t, rctypes.OpRejectResult)
	f.evm.reject.Progress = f.evm.reject.ReservedAt
	_, err := f.run()
	require.ErrorIs(t, err, ErrRejectNotDue)
	f.evm.reject.Lost = true
	replaced, err := f.run()
	require.NoError(t, err)
	require.Equal(t, "aborted", replaced.Phase)
}

// rejectOver runs the fixture's due rejection over a control state at a carrying round.
func rejectOver(t *testing.T, ctl *evmroot.ControlState, round, attempt uint64) (*evmfxResult, error) {
	t.Helper()
	f := newEVMFx(t, rctypes.OpRejectResult)
	f.env.Control = ctl
	f.block.Round, f.ctl.OrderingRound, f.ctl.Reject.Attempt = round, round, attempt
	replaced, err := f.run()
	return &evmfxResult{f: f, replaced: replaced}, err
}

type evmfxResult struct {
	f        *evmFx
	replaced *evmroot.ControlState
}

func preparedAt(round, attempt uint64) *evmroot.ControlState {
	return &evmroot.ControlState{Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "prepared", Attempt: attempt, OrderedRound: round}
}

// Test 5: a Prepare that lapsed is quiet for a rejection only once its cooldown has passed: at r+24 (still freezing) and r+48 (cooling
// down) it is refused, at r+49 accepted, aborted at the next attempt. The next Prepare takes the attempt after that, and a late Freeze of
// the dead attempt stays refused.
func TestRejectFollowsALapsedPrepareOnlyAfterItsCooldown(t *testing.T) {
	const r, attempt = uint64(100), uint64(2)
	lapse, cooldown := uint64(PrepareFreezeLapseRounds), uint64(PrepareCooldownRounds)
	for _, round := range []uint64{r, r + 1, r + lapse, r + lapse + 1, r + lapse + cooldown} {
		_, err := rejectOver(t, preparedAt(r, attempt), round, attempt+1)
		require.ErrorIs(t, err, ErrRejectNotQuiet, "round r+%d", round-r)
	}
	res, err := rejectOver(t, preparedAt(r, attempt), r+lapse+cooldown+1, attempt+1)
	require.NoError(t, err)
	require.Equal(t, "aborted", res.replaced.Phase)
	require.EqualValues(t, attempt+1, res.replaced.Attempt)
	require.Len(t, res.f.step.records, 1)
	_, err = rejectOver(t, preparedAt(r, attempt), r+lapse+cooldown+1, attempt)
	require.ErrorIs(t, err, ErrRejectAttempt, "the dead Prepare's own attempt is not the next")

	// the next Prepare uses attempt+2; attempt+1 is the rejection's; a Freeze of the dead attempt is no Prepare
	auth := testRecordAuthority{predecessor: bytes32(0x77)}
	round := r + lapse + cooldown + 2
	record := func(kind string, a uint64) []byte {
		return (evmroot.OrderedHandoffRecord{Network: 7, Epoch: 1, Attempt: a, OrderedRound: round, PredecessorBodyID: bytes32(0x77),
			FrozenID: make([]byte, 32), NextBodyID: bytes32(0x44), ActivationRound: round + PrepareActivationFloorRounds + 1,
			SuccessorTRHash: make([]byte, 32), Kind: kind}).Bytes()
	}
	_, err = applyHandoffRecord(res.replaced, record("prepare", attempt+1), 7, 1, round, auth, nil)
	require.ErrorIs(t, err, ErrHandoffRecord, "the rejection's attempt is not reused")
	next, err := applyHandoffRecord(res.replaced, record("prepare", attempt+2), 7, 1, round, auth, nil)
	require.NoError(t, err)
	require.Equal(t, "prepared", next.Phase)
	_, err = applyHandoffRecord(res.replaced, record("freeze", attempt), 7, 1, round, auth, nil)
	require.ErrorIs(t, err, ErrFreezeBeforePrepare, "a late Freeze of the dead attempt is refused")
}

// The dead-Prepare predicate is the lapse plus the cooldown, by subtraction: a Prepare ordered near the top of uint64 is never dead at a
// small round (the sum would wrap), and only a prepared state qualifies.
func TestPrepareDeadAfterCooldownDoesNotWrap(t *testing.T) {
	gap := uint64(PrepareFreezeLapseRounds + PrepareCooldownRounds)
	// ordered+48 wraps to 37 here: an additive form would call this Prepare dead at round 100 (rev on #858)
	nearTop := preparedAt(math.MaxUint64-10, 0)
	require.Less(t, nearTop.OrderedRound+gap, uint64(100), "premise: the sum wraps below the round")
	require.False(t, PrepareDeadAfterCooldown(nearTop, 100))
	require.False(t, PrepareDeadAfterCooldown(preparedAt(100, 0), 100+gap))
	require.True(t, PrepareDeadAfterCooldown(preparedAt(100, 0), 100+gap+1))
	require.True(t, PrepareMayFollowLapse(preparedAt(100, 0), 100+gap+1), "the fresh-Prepare rule shares the predicate")
	for _, phase := range []string{"idle", "aborted", "endorsed", "committed"} {
		c := preparedAt(100, 0)
		c.Phase = phase
		require.False(t, PrepareDeadAfterCooldown(c, 1<<40), phase)
	}
}

// Test 6: the same mature facts are accepted in idle and after a Prepare-only Abort, and refused while a handoff is live: a Prepare ordered
// in the carrying block itself (the control state is the one after the block's handoff record), an endorsed or committed one, a committed
// handoff awaiting its acknowledgement, a frozen tracker. A primary Abort that already resolved the result leaves nothing to close.
func TestRejectProtectsALiveHandoff(t *testing.T) {
	idle := &evmroot.ControlState{Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "idle"}
	_, err := rejectOver(t, idle, 50, 0)
	require.NoError(t, err, "the control: idle")
	aborted := *idle
	aborted.Phase, aborted.Attempt, aborted.OrderedRound = "aborted", 4, 49
	_, err = rejectOver(t, &aborted, 50, 5)
	require.NoError(t, err, "after a Prepare-only Abort")

	for name, ctl := range map[string]*evmroot.ControlState{
		"a Prepare in the carrying block": preparedAt(50, 0),
		"an endorsed handoff":             {Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "endorsed", OrderedRound: 1},
		"a committed handoff":             {Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "committed", OrderedRound: 1},
	} {
		_, err := rejectOver(t, ctl, 50, 1)
		require.ErrorIs(t, err, ErrRejectNotQuiet, name)
	}
	for name, mutate := range map[string]func(s *rootrecords.State){
		"a primary awaiting its acknowledgement":  func(s *rootrecords.State) { s.Pending = []rootrecords.PendingH{{Epoch: 1, HRound: 9}} },
		"a recovery awaiting its acknowledgement": func(s *rootrecords.State) { s.Pending = []rootrecords.PendingH{{Epoch: 1}, {Epoch: 1, HRound: 9}} },
		"a frozen tracker":                        func(s *rootrecords.State) { s.Frozen = true },
	} {
		f := newEVMFx(t, rctypes.OpRejectResult)
		mutate(&f.step.state)
		_, err := f.run()
		require.ErrorIs(t, err, ErrRejectNotQuiet, name)
		require.Empty(t, f.step.records, name)
	}

	// the result's primary was aborted after its Freeze: the Abort closed it, so a rejection of it projects nothing more
	f := newEVMFx(t, rctypes.OpRejectResult)
	var res [32]byte
	copy(res[:], f.ctl.Data)
	closed, _, err := f.step.state.SessionClosed(res, 40, 1_000)
	require.NoError(t, err)
	f.step.state = closed
	f.env.Control = &aborted
	f.ctl.Reject.Attempt = 5
	_, err = f.run()
	require.ErrorIs(t, err, ErrResolvedResult)
	require.Empty(t, f.step.records, "no second SessionClosed")
}

// Test 7 at the executor: an accepted rejection resolves the result for good. The state that carries it survives its own encoding (the
// checkpoint and restart form); a repeated rejection, at any attempt, and a primary Freeze naming the result are refused, without a record;
// a root-only step's unacknowledged parent is kept.
func TestRejectedResultIsFencedForGood(t *testing.T) {
	af := newAssignmentFixture(t)
	af.pop.Attempt = 7 // a fresh root attempt: the fence is the result, not the numbering
	built := af.build(t, af.candidate(t))
	candidate, err := evmassign.DecodeCandidate(built.preimage)
	require.NoError(t, err)
	res := candidate.ResultID()

	f := newEVMFx(t, rctypes.OpRejectResult)
	f.ctl.Data, f.evm.reject = res[:], dueReject(res)
	parent := bytes32(0x99)
	f.env.Control.UnackedParent = parent
	replaced, err := f.run()
	require.NoError(t, err)
	require.Equal(t, parent, replaced.UnackedParent, "the rejection is no acknowledgement of a root-only step")
	require.True(t, f.step.state.IsResolved(res))

	restored, err := rootrecords.DecodeState(f.step.state.Bytes())
	require.NoError(t, err)
	require.True(t, restored.IsResolved(res), "Resolved survives the encoding a checkpoint and a restart read back")

	for _, attempt := range []uint64{0, 1, 2} {
		g := newEVMFx(t, rctypes.OpRejectResult)
		g.ctl.Data, g.evm.reject = res[:], dueReject(res)
		g.step.state = restored
		g.env.Control = replaced
		g.ctl.Reject.Attempt = attempt
		_, err := g.run()
		require.ErrorIs(t, err, ErrResolvedResult, "attempt %d", attempt)
		require.Empty(t, g.step.records)
	}

	// a primary Freeze of the result, under a fresh root attempt, with the publication's old evidence: refused before admission
	step := posStep{on: true, state: restored}
	require.ErrorIs(t, step.refuseResolved(built.companion), ErrResolvedResult)
	require.NoError(t, (&posStep{on: true, state: rootrecords.NewState(1, 1)}).refuseResolved(built.companion),
		"the control: an unresolved result is admission's to judge")
}

// Test 7, rev2's note: refuseResolved leaves a Freeze whose companion has no readable candidate to the admission itself. With the result
// resolved in the store (here by the Abort of its primary; a RejectResult resolves it in the same State.Resolved), a retry of its Freeze is
// refused with the valid companion by the fence, and with an empty or malformed companion by admission; none changes the control state.
func TestAFreezeOfAResolvedResultIsRefusedWhateverItsCompanion(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	first := f.build(t, f.candidate(t))
	require.NoError(t, f.admit(t, first))
	abort := first.freeze
	abort.Kind, abort.OrderedRound = "abort", 4
	f.addAt(t, 4, abort.Bytes(), f.abortCompanionFor(t, abort))
	candidate, err := evmassign.DecodeCandidate(first.preimage)
	require.NoError(t, err)
	pos, err := loadPos(mustBlock(t, f.store, 4).ShardState.Control)
	require.NoError(t, err)
	require.True(t, pos.on && pos.state.IsResolved(candidate.ResultID()), "premise: the result is resolved")

	f.pop.Attempt = 1
	f.base = 5
	retry := f.build(t, f.candidate(t))
	f.addAt(t, 5, retry.prepare.Bytes())
	for name, companion := range map[string][]byte{
		"the valid companion": retry.companion,
		"an empty companion":  {},
		"a truncated one":     retry.companion[:len(retry.companion)/2],
	} {
		err := f.tryAt(t, 6, retry.freeze.Bytes(), companion)
		require.ErrorIs(t, err, ErrHandoffRecord, name)
		if name == "the valid companion" {
			require.ErrorIs(t, err, ErrResolvedResult, name)
		}
	}
	require.Equal(t, "prepared", mustBlock(t, f.store, 5).ShardState.Control.Phase, "no refused Freeze changed anything")
}

// RejectionParent mirrors the executor: no context under a live Prepare, the next attempt after an Abort and after a Prepare dead past its
// cooldown, the parent's EVM state and the root's authority; RejectionResolved sees a result the branch resolved.
func TestRejectionParentFollowsTheRejectionRule(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedEVMState(t)
	first := f.build(t, f.candidate(t))
	require.NoError(t, f.admit(t, first)) // Prepare at 2, Freeze at 3
	_, ok, err := f.store.RejectionParent(2, 3)
	require.NoError(t, err)
	require.False(t, ok, "a live Prepare")
	_, ok, err = f.store.RejectionParent(3, 4)
	require.NoError(t, err)
	require.False(t, ok, "an endorsed handoff")

	abort := first.freeze
	abort.Kind, abort.OrderedRound = "abort", 4
	f.addAt(t, 4, abort.Bytes(), f.abortCompanionFor(t, abort))
	rc, ok, err := f.store.RejectionParent(4, 5)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, rc.Attempt, "the next root attempt after the aborted 0")
	require.Equal(t, f.predecessor, rc.Predecessor[:])
	require.NotEqual(t, [32]byte{}, rc.Parent.StateRoot)
	candidate, err := evmassign.DecodeCandidate(first.preimage)
	require.NoError(t, err)
	require.True(t, f.store.RejectionResolved(4, candidate.ResultID()), "the Abort of its primary resolved the result on this branch")
	require.False(t, f.store.RejectionResolved(2, candidate.ResultID()))
}

func TestRejectionParentAfterALapsedPrepareWaitsForTheCooldown(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedEVMState(t)
	first := f.build(t, f.candidate(t))
	f.addAt(t, 2, first.prepare.Bytes())
	gap := uint64(PrepareFreezeLapseRounds + PrepareCooldownRounds)
	for r := uint64(3); r <= 2+gap; r++ {
		f.addAt(t, r)
	}
	_, ok, err := f.store.RejectionParent(2+gap-1, 2+gap)
	require.NoError(t, err)
	require.False(t, ok, "the cooldown has not passed")
	rc, ok, err := f.store.RejectionParent(2+gap, 2+gap+1)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, rc.Attempt)
}

// seedEVMState is seedFees with a certified EVM state root, the P a control names.
func (f *assignmentFixture) seedEVMState(t *testing.T) {
	t.Helper()
	f.installShard(t, f.current, func(si *ShardInfo) {
		si.IR.BlockHash = bytes.Clone(f.parent)
		si.IR.Hash = bytes.Repeat([]byte{0xe2}, 32)
		si.Fees["ev-a"] = 7
		var err error
		si.TR.FeeHash, err = si.feeHash(crypto.SHA256)
		require.NoError(t, err)
	})
}

// The halt of the test-9 rehearsal (run 40154398105): a rejection ordered at an idle root left an aborted control state with no ordered
// record, every later proposal's profile check refused it (ErrControlCheckpoint at SuffixParent) and the roots stopped proposing. Through
// the real store: the block that orders the rejection, the profile check of the next proposal on it, and that next block.
func TestTheChainProceedsAfterARejection(t *testing.T) {
	result := [32]byte{0xe5}
	evm := &fakeEVM{reject: dueReject(result)}
	s, svc, b8 := ackedEpochTwo(t, evm, 8)
	ctl := b8.ShardState.Control
	require.Equal(t, "idle", ctl.Phase, "premise: the rejection is taken from an idle root")
	c := rctypes.PosControl{Network: 5, ChainID: svc.Deployment.ChainID, Custody: svc.Deployment.Custody, OrderingEpoch: 2, OrderingRound: 9,
		Op: rctypes.OpRejectResult, Data: result[:], WitnessHash: sha256.Sum256([]byte("accounts")),
		Reject: &rctypes.RejectContext{PredecessorBodyID: [32]byte(ctl.PredecessorBodyID), EVMBlockHash: [32]byte(bytes.Repeat([]byte{0x77}, 32)),
			EVMStateRoot: [32]byte(bytes.Repeat([]byte{0x78}, 32))}}
	_, err := s.Add(&rctypes.BlockData{Version: 3, Round: 9, Epoch: 2, Timestamp: 1_001,
		Payload: &rctypes.Payload{Version: 3, PosControls: []rctypes.PosControl{c}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 8, Epoch: 2, CurrentRootHash: b8.RootHash}}}, nil)
	require.NoError(t, err)
	b9 := mustBlock(t, s, 9)
	require.Equal(t, "aborted", b9.ShardState.Control.Phase)
	require.Len(t, b9.ShardState.Records, 1)
	require.Equal(t, rootrecords.KindSessionClosed, b9.ShardState.Records[0].Kind)

	_, err = s.SuffixParent(9, 2)
	require.NoError(t, err, "the next proposal can be built on the rejection")
	_, err = s.Add(&rctypes.BlockData{Version: 3, Round: 10, Epoch: 2, Timestamp: 1_002, Payload: &rctypes.Payload{Version: 3},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 9, Epoch: 2, CurrentRootHash: b9.RootHash}}}, nil)
	require.NoError(t, err)
	require.Equal(t, "aborted", mustBlock(t, s, 10).ShardState.Control.Phase)
}

// Every state a rejection leaves (from idle, after an ordered Abort, after a dead Prepare) is a valid control checkpoint; a recordless
// aborted state is valid only without a frozen parent and with the digest link, and an ordered Abort's record is still checked.
func TestARejectionLeavesAValidControlCheckpoint(t *testing.T) {
	idle := &evmroot.ControlState{Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "idle"}
	abortRecord := (evmroot.OrderedHandoffRecord{Network: 7, Epoch: 1, Attempt: 4, OrderedRound: 49, PredecessorBodyID: bytes32(0x77),
		FrozenID: make([]byte, 32), NextBodyID: bytes32(0x44), ActivationRound: 60, SuccessorTRHash: make([]byte, 32), Kind: "abort"}).Bytes()
	ordered := &evmroot.ControlState{Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "aborted", Attempt: 4, OrderedRound: 49,
		RecordBytes: abortRecord, PreviousDigest: bytes32(0x01)}
	require.NoError(t, validateControl(ordered), "premise: an ordered Abort's state")
	for name, c := range map[string]struct {
		ctl            *evmroot.ControlState
		round, attempt uint64
	}{
		"idle":         {idle, 50, 0},
		"after abort":  {ordered, 50, 5},
		"dead Prepare": {preparedAt(100, 2), 100 + PrepareFreezeLapseRounds + PrepareCooldownRounds + 1, 3},
	} {
		res, err := rejectOver(t, c.ctl, c.round, c.attempt)
		require.NoError(t, err, name)
		require.NoError(t, validateControl(res.replaced), name)
	}

	res, err := rejectOver(t, idle, 50, 0)
	require.NoError(t, err)
	frozen := *res.replaced
	frozen.FrozenParent = bytes32(0x99)
	require.ErrorIs(t, validateControl(&frozen), ErrControlCheckpoint, "a recordless aborted state names no frozen parent")
	unlinked := *res.replaced
	unlinked.PreviousDigest = nil
	require.ErrorIs(t, validateControl(&unlinked), ErrControlCheckpoint, "a recordless aborted state keeps the digest link")
	stale := *ordered
	stale.Attempt = 5
	require.ErrorIs(t, validateControl(&stale), ErrControlCheckpoint, "an ordered Abort's record is still checked against the state")
}
