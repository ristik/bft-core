package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1306: a handoff record every root refuses must not stall the root chain. The leader trial-executes its own proposal before it signs it;
// a refused record is left out and the block is an ordinary one that carries the buffered requests. A deterministic refusal is remembered,
// so the record is neither ordered nor trial-executed again; a local one is retried the next round.

const refusedPartition types.PartitionID = 8

func refusedFreeze(attempt uint64) [][]byte {
	r := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: attempt, OrderedRound: 2, ActivationRound: 40, PredecessorBodyID: bytes.Repeat([]byte{1}, 32),
		FrozenID: bytes.Repeat([]byte{2}, 32), NextBodyID: bytes.Repeat([]byte{3}, 32), SuccessorTRHash: make([]byte, 32), Kind: "freeze"}
	return [][]byte{r.Bytes(), {0xa5}}
}

// refusingLeader is a handoff-profile leader whose handoff source orders the given records and whose trial execution returns refusal; it
// counts the trials.
func refusingLeader(t *testing.T, records func() [][]byte, refusal *error) (*ConsensusManager, *int, func() *abdrc.ProposalMsg) {
	f := newPlanFixture(t)
	cm := f.cm
	cm.leaderSelector = constLeader{leader: cm.id}
	trials := 0
	cm.handoffSource = func(uint64, *rctypes.QuorumCert) ([][]byte, error) { return records(), nil }
	cm.handoffTrial = func(b *rctypes.BlockData) error {
		require.NotEmpty(t, b.Payload.HandoffRecords, "only a block that orders a handoff record is trial-executed here")
		trials++
		return *refusal
	}
	// every call proposes the same round on the same parent again (the reservation is forgotten): what changes between the calls is only
	// what the leader remembers
	cm.safety.storage = forgetfulProposals{cm.safety.storage}
	cm.pacemaker.Reset(context.Background(), cm.blockStore().GetHighQc().GetRound(), nil, nil)
	t.Cleanup(cm.pacemaker.Stop)
	propose := func() *abdrc.ProposalMsg {
		bufferRequest(cm, refusedPartition)
		cm.processNewRoundEvent(context.Background())
		return f.mockNet.WaitRootProposal(t)
	}
	return cm, &trials, propose
}

func TestLeaderLeavesOutARefusedFreezeAndDoesNotReproposeIt(t *testing.T) {
	refusal := errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, vradmit.ErrH3, evmassign.ErrEVMOnly)
	cm, trials, propose := refusingLeader(t, func() [][]byte { return refusedFreeze(0) }, &refusal)

	p := propose()
	require.Empty(t, p.Block.Payload.HandoffRecords, "the refused Freeze is left out")
	require.Contains(t, requestedPartitions(p.Block.Payload), refusedPartition, "the block is an ordinary one: it certifies the shards")
	require.Equal(t, 1, *trials)
	got := cm.HandoffRefusals()
	require.Len(t, got, 1)
	require.Equal(t, "freeze", got[0].Kind)
	require.EqualValues(t, 0, got[0].Attempt)
	require.Equal(t, [32]byte(bytes.Repeat([]byte{3}, 32)), got[0].Body)
	require.Contains(t, got[0].Reason, "EVM-only")
	require.Equal(t, p.Block.Round, got[0].FirstRound)
	require.EqualValues(t, 1, refusedCount(t, cm, "freeze", handoffRefusedDeterministic))

	// the next round neither trials nor orders the remembered Freeze
	p = propose()
	require.Empty(t, p.Block.Payload.HandoffRecords)
	require.Contains(t, requestedPartitions(p.Block.Payload), refusedPartition)
	require.Equal(t, 1, *trials, "a remembered refusal is not trial-executed again")
	require.Len(t, cm.HandoffRefusals(), 1)
	require.EqualValues(t, 1, refusedCount(t, cm, "freeze", handoffRefusedDeterministic), "logged and counted once")

	// an epoch switch forgets it
	cm.resetVolatile()
	require.Empty(t, cm.HandoffRefusals())
	require.Zero(t, cm.refused.len())
}

// A refusal that can clear by itself is retried every round and the record is ordered once it clears: an input this root lacks, and the two
// admission items that read state ordinary blocks change while the EVM is frozen (review of #1307, P2-1): the shard acknowledgement gate
// (another shard acknowledges its pending configuration in an ordinary block) and the activation gates (the committed support table).
func TestLeaderRetriesAHandoffRecordRefusedForALocalReason(t *testing.T) {
	for name, cause := range map[string]error{
		"VR input unavailable":    errors.Join(storage.ErrVRUnavailable, errors.New("VR proof at the frozen parent")),
		"acknowledgement gate":    errors.Join(storage.ErrVRFreeze, fmt.Errorf("%w: entry 0 (-1: the EVM shard)", vradmit.ErrAckGate)),
		"activation gates":        errors.Join(storage.ErrVRFreeze, vradmit.ErrActivation, errors.New("support is not sufficient yet")),
		"acknowledgement pending": storage.ErrAssignmentAckPending,
		"an unclassified refusal": errors.New("invalid root handoff record"),
	} {
		t.Run(name, func(t *testing.T) {
			refusal := errors.Join(storage.ErrHandoffRecord, cause)
			cm, trials, propose := refusingLeader(t, func() [][]byte { return refusedFreeze(0) }, &refusal)

			p := propose()
			require.Empty(t, p.Block.Payload.HandoffRecords, "the refused record is left out of this round")
			require.Contains(t, requestedPartitions(p.Block.Payload), refusedPartition)
			require.Empty(t, cm.HandoffRefusals(), "a local refusal is not remembered")
			require.EqualValues(t, 1, refusedCount(t, cm, "freeze", handoffRefusedLocal))

			p = propose()
			require.Equal(t, 2, *trials, "the next round tries it again")
			require.Empty(t, p.Block.Payload.HandoffRecords)
			require.EqualValues(t, 2, refusedCount(t, cm, "freeze", handoffRefusedLocal))

			// once the cause clears (the gate holds, the input arrived), the record is ordered alone
			refusal = nil
			p = propose()
			require.Equal(t, 3, *trials)
			require.Len(t, p.Block.Payload.HandoffRecords, 2, "the admitted Freeze and its companion")
			require.Empty(t, p.Block.Payload.Requests, "a record block carries no change request")
		})
	}
}

// The default trial is the block store's own execution (handoffTrial unset): a handoff record the real executor refuses is left out, and
// the trial leaves the block store as it was.
func TestLeaderTrialIsTheRealExecutorAndStoresNothing(t *testing.T) {
	f := newPlanFixture(t)
	cm := f.cm
	cm.leaderSelector = constLeader{leader: cm.id}
	cm.safety.storage = forgetfulProposals{cm.safety.storage}
	sourced := 0
	// a Freeze on an idle control state: every root's executor refuses it (no Prepare bound a frozen parent)
	cm.handoffSource = func(uint64, *rctypes.QuorumCert) ([][]byte, error) { sourced++; return refusedFreeze(0), nil }
	store := cm.blockStore()
	highQC := store.GetHighQc()
	committed := store.CommittedRound()
	parent, err := store.Block(highQC.GetRound())
	require.NoError(t, err)
	parentHash := []byte(bytes.Clone(parent.RootHash))
	cm.pacemaker.Reset(context.Background(), highQC.GetRound(), nil, nil)
	t.Cleanup(cm.pacemaker.Stop)
	round := cm.pacemaker.GetCurrentRound()

	bufferRequest(cm, refusedPartition)
	cm.processNewRoundEvent(context.Background())
	p := f.mockNet.WaitRootProposal(t)
	require.Equal(t, 1, sourced)
	require.Empty(t, p.Block.Payload.HandoffRecords, "the real executor refuses the Freeze: it is left out")
	require.Contains(t, requestedPartitions(p.Block.Payload), refusedPartition)
	require.EqualValues(t, 1, refusedCount(t, cm, "freeze", handoffRefusedLocal), "an ErrHandoffRecord-only refusal is local")

	require.Same(t, store, cm.blockStore())
	require.Equal(t, highQC, cm.blockStore().GetHighQc(), "the trial stores nothing: the high QC")
	require.Equal(t, committed, cm.blockStore().CommittedRound(), "the committed round")
	_, err = cm.blockStore().Block(round)
	require.Error(t, err, "no block of the proposal round")
	after, err := cm.blockStore().Block(highQC.GetRound())
	require.NoError(t, err)
	require.Equal(t, parentHash, []byte(after.RootHash), "the parent's state")
}

// forgetfulProposals forgets every proposal reservation, so a test leader can propose the same round again.
type forgetfulProposals struct{ SafetyStorage }

func (forgetfulProposals) ReadProposalRecord() (storage.ProposalRecord, error) {
	return storage.ProposalRecord{}, nil
}
func (forgetfulProposals) ReserveProposal(storage.ProposalRecord) error { return nil }

func refusedCount(t *testing.T, x *ConsensusManager, kind, class string) float64 {
	var m dto.Metric
	require.NoError(t, x.handoffRefusedCnt.WithLabelValues(kind, class).Write(&m))
	return m.GetCounter().GetValue()
}

func TestHandoffRefusalClass(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, vradmit.ErrH3), handoffRefusedDeterministic},
		{vradmit.ErrCertificate, handoffRefusedDeterministic},
		{errors.New("VR Freeze refused: the frozen commitment"), handoffRefusedLocal}, // an unclassified error is never remembered
		{errors.Join(storage.ErrVRFreeze, storage.ErrVRUnavailable), handoffRefusedLocal},
		{errors.Join(storage.ErrHandoffRecord, storage.ErrWitnessUnavailable), handoffRefusedLocal},
		{storage.ErrAssignmentAckPending, handoffRefusedLocal},
		// the admission items that read state ordinary blocks change (review of #1307, P2-1)
		{errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, fmt.Errorf("%w: entry 2", vradmit.ErrAckGate)), handoffRefusedLocal},
		{errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, vradmit.ErrActivation), handoffRefusedLocal},
		// the items the Prepare fixes stay deterministic
		{errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, vradmit.ErrCommit), handoffRefusedDeterministic},
		{errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, vradmit.ErrVerdicts), handoffRefusedDeterministic},
		{errors.Join(storage.ErrHandoffRecord, storage.ErrVRFreeze, vradmit.ErrInconsistent), handoffRefusedDeterministic},
	} {
		require.Equal(t, c.want, handoffRefusalClass(c.err), "%v", c.err)
	}
}

// Layer B: a leader does not order the Prepare of a plan whose candidate item (5) of admission refuses; it is judged once per intent
// identity, and a later attempt is judged again.
func TestVRRecordsForRoundSkipsThePrepareOfARefusedCandidate(t *testing.T) {
	w := newVRWorld(t)
	svc := w.planned()
	plan, _ := svc.Plan()
	checks := 0
	verdict := errors.Join(vradmit.ErrH3, evmassign.ErrEVMOnly)
	v := &vrHandoff{svc: svc,
		leader: func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
			return vrschedule.LeaderStep{Kind: "prepare", Records: [][]byte{{1}}}, nil
		},
		queryAt: func(*storage.ExecutedBlock) (storage.VRIntentQuery, bool, error) {
			return storage.VRIntentQuery{}, true, nil
		},
		derive: func(storage.VRIntentQuery) (vrschedule.Derived, bool, error) {
			return vrschedule.Derived{VRIntent: storage.VRIntent{Digest: plan.Intent}}, true, nil
		},
		reject: func(context.Context, uint64, uint64, *rctypes.QuorumCert) bool { return false },
		candidateCheck: func(parentRound, round uint64, p vrschedule.PreparePlan) error {
			require.EqualValues(t, 9, parentRound)
			require.Equal(t, plan.Intent, p.Intent)
			checks++
			return verdict
		},
	}
	x := vrManager(v)
	x.handoffRefusedCnt = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"kind", "class"})
	parent := idleParent(plan.Epoch)
	qc := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 9}}

	recs, err := x.vrRecordsForRound(10, parent, qc)
	require.NoError(t, err)
	require.Empty(t, recs, "the candidate is refused: no Prepare, the block is an ordinary one")
	require.Equal(t, 1, checks)
	got := x.HandoffRefusals()
	require.Len(t, got, 1)
	require.Equal(t, "prepare", got[0].Kind)
	require.Equal(t, plan.Intent, got[0].Intent, "the VR intent and result of the held plan are reported")
	require.Equal(t, [32]byte(plan.Result), got[0].Result)

	recs, _ = x.vrRecordsForRound(11, parent, qc)
	require.Empty(t, recs)
	require.Equal(t, 1, checks, "judged once per intent identity")
	recs, _ = x.vrRecordsForRound(11, parent, qc)
	require.Empty(t, recs)
	require.EqualValues(t, 2, refusedCount(t, x, "prepare", handoffRefusedDeterministic), "every leader round that leaves it out counts, once")

	// an input the check lacks does not hold the Prepare back: the Freeze judges the candidate in full, as before
	x.refused.reset()
	verdict = storage.ErrVRUnavailable
	recs, _ = x.vrRecordsForRound(12, parent, qc)
	require.Len(t, recs, 1)
	require.Empty(t, x.HandoffRefusals())

	// a candidate the check admits is prepared
	verdict = nil
	recs, _ = x.vrRecordsForRound(13, parent, qc)
	require.Len(t, recs, 1)
}

// The memory of a dead intent is pruned: another epoch, a passed attempt, a VR intent this root no longer holds.
func TestHandoffRefusalsArePrunedWithTheirIntent(t *testing.T) {
	x := &ConsensusManager{}
	note := func(epoch, attempt uint64, intent byte) {
		e := HandoffRefused{Kind: "freeze", Epoch: epoch, Attempt: attempt, Intent: [32]byte{intent}}
		x.refused.add(refusalKey(5, epoch, nil, attempt, []byte{intent}, "freeze"), e)
	}
	note(1, 0, 0)
	note(1, 1, 0)
	note(2, 0, 0)
	x.pruneHandoffRefusals(&evmroot.ControlState{Epoch: 1, Attempt: 1})
	got := x.HandoffRefusals()
	require.Len(t, got, 1)
	require.EqualValues(t, 1, got[0].Attempt)

	for i := 0; i < 2*maxHandoffRefusals; i++ {
		note(1, uint64(10+i), 0)
	}
	require.Len(t, x.HandoffRefusals(), maxHandoffRefusals, "bounded")
}

// A remembered Freeze is neither returned nor announced as ordered (review of #1307, P2-2): vrRecordsForRound drops it before the
// vr.handoff.ordering line.
func TestVRRecordsForRoundDropsARememberedFreezeBeforeOrdering(t *testing.T) {
	w := newVRWorld(t)
	svc := w.planned()
	plan, _ := svc.Plan()
	records := refusedFreeze(plan.Attempt)
	v := &vrHandoff{svc: svc,
		leader: func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
			return vrschedule.LeaderStep{Kind: "freeze", Records: records}, nil
		}}
	x := vrManager(v)
	var logs bytes.Buffer
	x.log = slog.New(slog.NewTextHandler(&logs, nil))
	parent := idleParent(plan.Epoch)
	parent.ShardState.Control.Phase = "prepared"

	recs, err := x.vrRecordsForRound(10, parent, nil)
	require.NoError(t, err)
	require.Len(t, recs, 2, "not remembered: the Freeze is ordered")
	require.Contains(t, logs.String(), "event=vr.handoff.ordering")

	r, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.True(t, x.refused.add(recordRefusalKey(r), HandoffRefused{Kind: "freeze", Epoch: r.Epoch, Attempt: r.Attempt, FirstRound: 10, LastRound: 10}))
	logs.Reset()
	recs, err = x.vrRecordsForRound(11, parent, nil)
	require.NoError(t, err)
	require.Empty(t, recs, "a remembered Freeze is not ordered again")
	require.NotContains(t, logs.String(), "vr.handoff.ordering", "nor announced as ordering")
	require.EqualValues(t, 11, x.HandoffRefusals()[0].LastRound)
}
