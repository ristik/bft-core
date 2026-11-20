package consensus

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1221: the VR leader's exact-recovery proposal path. The eligibility is judged over the real committed chain of the Q3 harness (a
// committed, unacknowledged primary on the frozen parent, identity history, the one-shot allowance); the routing of the leader's records
// over a held plan and the committed control state.

// recoveryWorld is a replica with an activated primary pending on block 7 and the recovery candidate derived from it.
type recoveryWorld struct {
	r         *q3Replica
	f         *q3fixture.Fixture
	key       types.PartitionShardID
	installed *types.PartitionDescriptionRecord
	block     *storage.ExecutedBlock
	binding   *evmassign.Supersession
	second    *q3fixture.Fixture
	candidate evmassign.Candidate
}

func newRecoveryWorld(t *testing.T) *recoveryWorld { return newRecoveryWorldAs(t, nil, 0) }

// newRecoveryWorldAs is the world as root number index of the successor committee; with a fixture it is another root of the same chain.
func newRecoveryWorldAs(t *testing.T, same *q3fixture.Fixture, index int) *recoveryWorld {
	t.Helper()
	r, f, key, installed, pending, binding := pendingPrimaryAs(t, same, index)
	block, err := r.manager.blockStore().Block(7)
	require.NoError(t, err)
	second := q3fixture.New(t, q3fixture.Options{After: f, Assignment: true, Recovery: true, Installed: installed, ShardState: pending,
		MutateCandidate: func(c *evmassign.Candidate) { c.Supersedes = binding }})
	c, err := evmassign.DecodeCandidate(second.Candidate)
	require.NoError(t, err)
	require.Equal(t, evmassign.KindRecovery, c.Kind)
	return &recoveryWorld{r: r, f: f, key: key, installed: installed, block: block, binding: binding, second: second, candidate: c}
}

func TestVRRecoveryEligibility(t *testing.T) {
	w := newRecoveryWorld(t)
	x := w.r.manager
	require.NoError(t, x.vrRecoveryEligibleAt(w.block, w.candidate), "a committed unacknowledged primary, the recovery unused, the derived K")

	t.Run("not the derived recovery", func(t *testing.T) {
		for name, mutate := range map[string]func(*evmassign.Candidate){
			"replaces another assignment": func(c *evmassign.Candidate) { c.ReplacedAssignment = bytes.Repeat([]byte{1}, 32) },
			"another committee":           func(c *evmassign.Candidate) { c.Identities = c.Identities[:len(c.Identities)-1] },
			"a primary":                   func(c *evmassign.Candidate) { c.Kind = evmassign.KindPrimary },
		} {
			c := w.candidate
			c.Identities = append([]evmassign.Identity(nil), c.Identities...)
			mutate(&c)
			require.ErrorIs(t, x.vrRecoveryEligibleAt(w.block, c), ErrVRRecoveryIneligible, name)
		}
	})

	t.Run("the primary was acknowledged first", func(t *testing.T) {
		acked := *w.block
		states := map[types.PartitionShardID]*storage.ShardInfo{}
		for k, v := range w.block.ShardState.States {
			cp := *v
			states[k] = &cp
		}
		si := states[w.key]
		si.TR.Epoch = si.IR.Epoch
		acked.ShardState.States = states
		err := x.vrRecoveryEligibleAt(&acked, w.candidate)
		require.ErrorIs(t, err, ErrVRRecoveryIneligible)
		require.ErrorContains(t, err, "acknowledged")
	})
}

func TestVRRecoveryIsRefusedOnceUsed(t *testing.T) {
	w := newRecoveryWorld(t)
	x := w.r.manager
	require.NoError(t, x.vrRecoveryEligibleAt(w.block, w.candidate))
	// the recovery commits: the chain now holds the primary and its recovery
	require.NoError(t, w.r.rt.Activate(context.Background(), q3active.Bundle{Envelope: w.second.EnvelopeBytes, Snapshot: w.second.Snapshot, Candidate: w.second.Candidate}))
	err := x.vrRecoveryEligibleAt(w.block, w.candidate)
	require.ErrorIs(t, err, ErrVRRecoveryIneligible)
	require.ErrorIs(t, err, evmassign.ErrRecoveryUsed, "one recovery per primary")
}

// The pure rule: no pending primary, a spent allowance.
func TestRecoveryEligiblePureRule(t *testing.T) {
	w := newRecoveryWorld(t)
	chain, err := storage.CommittedChain(w.r.orchestration, w.key.PartitionID, types.ShardID{}, 0)
	require.NoError(t, err)
	lctx, err := storage.LifecycleFor(w.r.orchestration, w.key.PartitionID, types.ShardID{}, 0, w.installed)
	require.NoError(t, err)
	require.Len(t, chain.Steps, 1)
	require.NoError(t, recoveryEligible(w.candidate, lctx, w.installed))

	none := lctx
	none.Pending, none.Head = 0, nil
	require.ErrorIs(t, recoveryEligible(w.candidate, none, w.installed), ErrVRRecoveryIneligible)
	used := lctx
	used.CommittedRecoveries = 1
	require.ErrorIs(t, recoveryEligible(w.candidate, used, w.installed), evmassign.ErrRecoveryUsed)
}

// vrBytes is a VR root state whose stored backoff attempt is the given one.
func vrBytes(t *testing.T, epoch, attempt uint64) []byte {
	t.Helper()
	st := vradmit.GenesisRootState(epoch, 4)
	st.Backoff.Attempt = attempt
	raw, err := st.Encode()
	require.NoError(t, err)
	return raw
}

func recoveryPlanOf(w *recoveryWorld, attempt uint64, id byte) abdrc.HandoffApprovalMsg {
	return abdrc.HandoffApprovalMsg{Attempt: attempt, CandidatePreimage: w.second.Candidate, Body: []byte{id}, Candidate: bytes.Repeat([]byte{id}, 32)}
}

// The leader's routing of a VR chain's round.
func TestVRRecoveryRoute(t *testing.T) {
	w := newRecoveryWorld(t)
	var verdict error
	judged := 0
	w.r.manager.vr = &vrHandoff{recoveryEligible: func(*storage.ExecutedBlock, evmassign.Candidate) error { judged++; return verdict }}
	x := w.r.manager
	idle := &evmroot.ControlState{Epoch: 2, Phase: "idle", VR: vrBytes(t, 2, 0)}

	require.False(t, x.vrRecoveryRoute(w.block, idle, 20), "no request: the VR path")
	require.Zero(t, judged)

	x.setHandoffIntent(abdrc.HandoffApprovalMsg{Attempt: 0, Body: []byte{1}, Candidate: bytes.Repeat([]byte{1}, 32), CandidatePreimage: []byte{0xa0}})
	require.False(t, x.vrRecoveryRoute(w.block, idle, 20), "an intent that is no recovery is the VR path's, and is kept")
	require.NotNil(t, x.pendingIntent(0))
	require.Zero(t, judged)

	plan := recoveryPlanOf(w, 0, 2)
	x.setHandoffIntent(plan)
	require.True(t, x.vrRecoveryRoute(w.block, idle, 20), "a held, eligible recovery")
	require.Equal(t, 1, judged, "eligibility is re-judged at proposal time")
	require.NotNil(t, x.pendingIntent(0))

	verdict = ErrVRRecoveryIneligible // J' acknowledged first, or K no longer fits
	require.False(t, x.vrRecoveryRoute(w.block, idle, 21))
	require.Nil(t, x.pendingIntent(0), "the request is dropped")
	verdict = nil
	require.False(t, x.vrRecoveryRoute(w.block, idle, 22), "and stays dropped: the operator requests again")

	// an aborted attempt plans the next one
	x.setHandoffIntent(recoveryPlanOf(w, 4, 3))
	aborted := &evmroot.ControlState{Epoch: 2, Phase: "aborted", Attempt: 3, VR: vrBytes(t, 2, 4)}
	require.True(t, x.vrRecoveryRoute(w.block, aborted, 30))
	require.False(t, x.vrRecoveryRoute(w.block, &evmroot.ControlState{Epoch: 2, Phase: "aborted", Attempt: 7, VR: vrBytes(t, 2, 8)}, 30), "another attempt's intent is dead")
}

func TestVRRecoveryRouteFollowsTheCommittedPrepare(t *testing.T) {
	w := newRecoveryWorld(t)
	x := w.r.manager
	x.vr = &vrHandoff{recoveryEligible: func(*storage.ExecutedBlock, evmassign.Candidate) error { return ErrVRRecoveryIneligible }}
	body := bytes.Repeat([]byte{0x77}, 32)
	prepare := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 2, Attempt: 0, OrderedRound: 10, ActivationRound: 200, PredecessorBodyID: bytes.Repeat([]byte{1}, 32),
		NextBodyID: body, FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	prepared := &evmroot.ControlState{Epoch: 2, Phase: "prepared", Attempt: 0, OrderedRound: 10, RecordBytes: prepare.Bytes(), VR: vrBytes(t, 2, 0)}

	require.False(t, x.vrRecoveryRoute(w.block, prepared, 12), "a Prepare of no plan this root holds (a VR primary's, or a restart lost the plan)")

	var id [32]byte
	copy(id[:], body)
	x.handoffPlans = map[[32]byte]*pendingHandoff{id: {plan: recoveryPlanOf(w, 0, 9), body: planBody{id: id}}}
	require.True(t, x.vrRecoveryRoute(w.block, prepared, 12), "the Freeze and H of a held recovery's Prepare, whatever the eligibility says now: the EVM is frozen")
	endorsed := *prepared
	endorsed.Phase = "endorsed"
	require.False(t, x.vrRecoveryRoute(w.block, &endorsed, 13), "endorsed: the retained candidate decides, a cached plan does not")
	x.vr.retained = func([]byte) ([]byte, error) { return w.second.Candidate, nil }
	require.True(t, x.vrRecoveryRoute(w.block, &endorsed, 13))

	x.handoffPlans[id].plan.CandidatePreimage = nil // another plan under the same body: not a recovery
	require.False(t, x.vrRecoveryRoute(w.block, prepared, 12))

	// a lapsed Prepare is dead: the next attempt follows the held intent
	x.handoffPlans = nil
	x.vr.recoveryEligible = func(*storage.ExecutedBlock, evmassign.Candidate) error { return nil }
	x.setHandoffIntent(recoveryPlanOf(w, 1, 5))
	lapsedAt := uint64(10) + storage.PrepareFreezeLapseRounds + 1000
	prepared.VR = vrBytes(t, 2, 1)
	require.True(t, storage.PrepareLapsed(prepared, lapsedAt), "premise")
	require.True(t, x.vrRecoveryRoute(w.block, prepared, lapsedAt))
}

// parentOf is the stored block 7 (the primary pending on frozen parent P) made the parent of the leader's round: an idle VR control state,
// the EVM shard certified at P with its installed epoch ahead of the acknowledged one.
func (w *recoveryWorld) idleVRParent(t *testing.T, parentHash []byte) (*rctypes.QuorumCert, *storage.ExecutedBlock) {
	t.Helper()
	x := w.r.manager
	w.block.ShardState.Control = &evmroot.ControlState{Network: 5, Epoch: 2, Phase: "idle", VR: vrBytes(t, 2, 0), PredecessorBodyID: w.block.ShardState.Control.PredecessorBodyID}
	si := w.block.ShardState.States[w.key]
	si.IR.BlockHash = bytes.Clone(parentHash)
	// the committed root block is the one CommittedFrozenParent reads
	root, err := x.blockStore().Block(6)
	require.NoError(t, err)
	rootStates := root.ShardState.States
	require.NotNil(t, rootStates)
	if rs := rootStates[w.key]; rs != nil && rs.IR != nil {
		rs.IR.BlockHash = bytes.Clone(parentHash)
	}
	return &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7}}, w.block
}

// committedAt is the committed state the plan is derived from: the head block 7 of the replica's epoch with the same pending shard.
func (w *recoveryWorld) committedAt(t *testing.T, control *evmroot.ControlState, parentHash []byte) *abdrc.StateMsg {
	t.Helper()
	state, err := w.r.manager.blockStore().GetState()
	require.NoError(t, err)
	head := *state.CommittedHead
	blk := *head.Block
	blk.Round, blk.Epoch = 7, 2
	head.Block = &blk
	if head.CommitQc == nil || head.CommitQc.LedgerCommitInfo == nil {
		head.CommitQc = &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{}}
	}
	head.Control = control
	head.ShardInfo = append([]abdrc.ShardInfo(nil), head.ShardInfo...)
	require.Len(t, head.ShardInfo, 1)
	ir := *head.ShardInfo[0].IR
	ir.BlockHash, ir.Epoch = bytes.Clone(parentHash), 0
	head.ShardInfo[0].IR = &ir
	head.ShardInfo[0].IRTR.Epoch = 1
	state.CommittedHead = &head
	return state
}

// The whole proposal path on a VR chain: a request of the operator, the Prepare, the endorsements of J”s root quorum, the Freeze v3 companion
// the existing admission accepts, and H. Ordinary VR output is untouched (the VR path is not consulted).
func TestVRRecoveryLeaderOrdersPrepareFreezeAndH(t *testing.T) {
	ctx := context.Background()
	w := newRecoveryWorld(t)
	x := w.r.manager
	vrPathUsed := false
	x.vr = &vrHandoff{reject: func(context.Context, uint64, uint64, *rctypes.QuorumCert) bool { return false },
		leader: func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
			vrPathUsed = true
			return vrschedule.LeaderStep{}, nil
		}, svc: vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})}
	parentHash := bytes.Repeat([]byte{0x31}, 32)
	qc, parent := w.idleVRParent(t, parentHash)

	// the operator's request: K from the retained authorization, nothing chosen by the caller
	state := w.committedAt(t, parent.ShardState.Control, parentHash)
	plan, err := x.planVRRecoveryAt(state)
	require.NoError(t, err)
	c, ok := isRecoveryPlan(plan)
	require.True(t, ok)
	require.Empty(t, plan.Receipts, "no readiness receipts")
	require.Empty(t, plan.PrimaryPoPs, "no fresh proofs")
	require.NoError(t, w.r.manager.vrRecoveryEligibleAt(parent, c))
	require.Equal(t, w.candidate.ReplacedAssignment, c.ReplacedAssignment, "the superseded primary is named")
	require.NotNil(t, c.Supersedes)

	// Prepare
	records, err := x.handoffRecordsForRound(8, qc)
	require.NoError(t, err)
	require.False(t, vrPathUsed, "the recovery route does not consult the verified view certificate")
	require.Len(t, records, 1)
	prepare, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "prepare", prepare.Kind)
	body, err := x.decodePlanBody(plan.Body)
	require.NoError(t, err)
	require.Equal(t, body.id[:], prepare.NextBodyID)

	// the endorsement precondition is unchanged: before the Prepare is committed the endorsement is refused
	idle := w.committedAt(t, parent.ShardState.Control, parentHash)
	require.ErrorIs(t, x.endorseHandoffAtState(ctx, plan, idle), ErrEndorseBeforePrepare)

	// the committed Prepare, endorsed by J''s root quorum (this root and two others)
	control := *parent.ShardState.Control
	control.Phase, control.OrderedRound, control.RecordBytes, control.FrozenParent = "prepared", prepare.OrderedRound, records[0], bytes.Clone(parentHash)
	control.PreviousDigest = bytes.Repeat([]byte{9}, 32)
	prepared := w.committedAt(t, &control, parentHash)
	require.NoError(t, x.endorseHandoffAtState(ctx, plan, prepared))
	stored := x.handoffPlans[body.id]
	require.NotNil(t, stored)
	domain, err := storage.EndorsementBytes(stored.record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(stored.record)
	require.NoError(t, err)
	for _, other := range w.f.NewNodes[1:3] {
		signed := stored.plan
		signed.Signer = other.PeerConf.ID.String()
		signed.Signature, err = other.Signer.SignBytes(domain)
		require.NoError(t, err)
		signed.AbortSignature, err = other.Signer.SignBytes(abortDomain)
		require.NoError(t, err)
		require.NoError(t, x.onHandoffApprovalMsg(ctx, &signed))
	}

	// Freeze v3 (exact recovery), accepted by the existing admission
	parent.ShardState.Control = &control
	records, err = x.handoffRecordsForRound(control.OrderedRound+2, qc)
	require.NoError(t, err)
	require.False(t, vrPathUsed)
	require.Len(t, records, 2)
	freeze, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "freeze", freeze.Kind)
	companion, err := storage.ParseFreezeCompanion(records[1])
	require.NoError(t, err)
	require.EqualValues(t, 3, companion.Version, "a Freeze v3, not a v5")
	require.Empty(t, companion.Receipts)
	cand, err := evmassign.DecodeCandidate(companion.Preimage)
	require.NoError(t, err)
	require.Equal(t, evmassign.KindRecovery, cand.Kind)
	require.Equal(t, w.candidate.Identities, cand.Identities, "exactly K")
	got, err := x.blockStore().VerifyFreezeCompanion(freeze, records[1])
	require.NoError(t, err)
	require.Equal(t, parentHash, got)

	// H, once the Freeze is committed: the technical record the recovery installs
	endorsed := control
	endorsed.Phase, endorsed.OrderedRound, endorsed.RecordBytes = "endorsed", freeze.OrderedRound, records[0]
	parent.ShardState.Control = &endorsed
	x.vr.retained = func([]byte) ([]byte, error) { return nil, nil }
	records, err = x.handoffRecordsForRound(freeze.OrderedRound+2, qc)
	require.NoError(t, err)
	require.Empty(t, records, "no retained recovery candidate, a quorum-ready plan still cached: nothing is ordered")
	x.vr.retained = func([]byte) ([]byte, error) { return plan.CandidatePreimage, nil }
	records, err = x.handoffRecordsForRound(freeze.OrderedRound+2, qc)
	require.NoError(t, err)
	require.False(t, vrPathUsed)
	require.Len(t, records, 1)
	h, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	require.Equal(t, "commit", h.Kind)
	require.Equal(t, body.id[:], h.NextBodyID)
	require.NotEqual(t, make([]byte, 32), h.SuccessorTRHash)

	// a root that lost its plan (a restart, a leader change) orders the same H from the committed Freeze and the candidate it retained
	x.handoffMu.Lock()
	x.handoffPlans, x.handoffIntent = nil, nil
	x.handoffMu.Unlock()
	x.vr.retained = func(id []byte) ([]byte, error) {
		require.Equal(t, body.id[:], id)
		return plan.CandidatePreimage, nil
	}
	again, err := x.handoffRecordsForRound(freeze.OrderedRound+2, qc)
	require.NoError(t, err)
	require.Equal(t, records, again, "H without any volatile plan")
	x.vr.retained = func([]byte) ([]byte, error) { return nil, nil }
	none, err := x.handoffRecordsForRound(freeze.OrderedRound+2, qc)
	require.NoError(t, err)
	require.Empty(t, none, "no retained recovery candidate: nothing is invented")
}

// A plan distributed through the intent endpoint is judged against this root's own committed chain before a Prepare is spent on it.
func TestVRRecoveryRefusesASupersessionThatIsNotTheCommittedChain(t *testing.T) {
	w := newRecoveryWorld(t)
	x := w.r.manager
	require.NoError(t, x.vrRecoveryEligibleAt(w.block, w.candidate))
	bad := w.candidate
	sup := *w.candidate.Supersedes
	sup.ChainCommitment = bytes.Repeat([]byte{0xee}, 32)
	bad.Supersedes = &sup
	require.ErrorIs(t, x.vrRecoveryEligibleAt(w.block, bad), ErrVRRecoveryIneligible)
	bad = w.candidate
	bad.OldShardEpoch++
	require.ErrorIs(t, x.vrRecoveryEligibleAt(w.block, bad), ErrVRRecoveryIneligible, "it replaces another installed configuration")
	bad = w.candidate
	bad.Supersedes = nil
	require.ErrorIs(t, x.vrRecoveryEligibleAt(w.block, bad), ErrVRRecoveryIneligible)
}

// Endorsed plans of attempts the committed control state has moved past are forgotten, so repeated lapses cannot fill the cache.
func TestSpentRecoveryPlansArePruned(t *testing.T) {
	w := newRecoveryWorld(t)
	x := w.r.manager
	x.handoffPlans = map[[32]byte]*pendingHandoff{
		{1}: {plan: abdrc.HandoffApprovalMsg{Attempt: 0}, body: planBody{epoch: 1}}, // of an epoch already installed
		{2}: {plan: abdrc.HandoffApprovalMsg{Attempt: 0}, body: planBody{epoch: 3}}, // the next epoch's: kept
	}
	x.pruneSpentPlans()
	require.Len(t, x.handoffPlans, 1)
	require.Contains(t, x.handoffPlans, [32]byte{2})
}

// pendingPrimaryAs is pendingPrimary for root number index of the chain (a fixture given: that chain).
func pendingPrimaryAs(t *testing.T, f *q3fixture.Fixture, index int) (*q3Replica, *q3fixture.Fixture, types.PartitionShardID, *types.PartitionDescriptionRecord, *storage.ShardInfo, *evmassign.Supersession) {
	t.Helper()
	if f == nil {
		f = q3fixture.New(t, q3fixture.Options{Assignment: true})
	}
	r := newQ3Replica(t, f, f.NewNodes[index])
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(context.Background()))
	require.NoError(t, r.rt.Activate(context.Background(), r.bundle()))
	_, err := r.manager.blockStore().Add(&rctypes.BlockData{Version: 3, Round: 7, Epoch: 2, Payload: &rctypes.Payload{Version: 3}, Anchor: r.manager.epochAnchor}, nil)
	require.NoError(t, err)
	first, err := r.manager.blockStore().Block(7)
	require.NoError(t, err)
	key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
	configs, err := r.orchestration.ShardConfigs(7)
	require.NoError(t, err)
	chain, err := storage.CommittedChain(r.orchestration, key.PartitionID, types.ShardID{}, 0)
	require.NoError(t, err)
	binding, err := chain.Supersession()
	require.NoError(t, err)
	return r, f, key, configs[key], first.ShardState.States[key], binding
}

// J' acknowledged before the Prepare was ordered: the leader drops the request and orders no recovery; the VR path is consulted instead.
func TestVRRecoveryIsDroppedWhenThePrimaryAcknowledgesFirst(t *testing.T) {
	w := newRecoveryWorld(t)
	x := w.r.manager
	x.vr = &vrHandoff{reject: func(context.Context, uint64, uint64, *rctypes.QuorumCert) bool { return false },
		svc: vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})}
	parentHash := bytes.Repeat([]byte{0x31}, 32)
	qc, parent := w.idleVRParent(t, parentHash)
	_, err := x.planVRRecoveryAt(w.committedAt(t, parent.ShardState.Control, parentHash))
	require.NoError(t, err)
	require.NotNil(t, x.pendingIntent(0))

	// J''s first epoch-3 certificate lands: the installed and the acknowledged epoch agree
	si := parent.ShardState.States[w.key]
	si.TR.Epoch = si.IR.Epoch
	records, err := x.handoffRecordsForRound(8, qc)
	require.NoError(t, err)
	require.Empty(t, records, "no recovery Prepare is ordered")
	require.Nil(t, x.pendingIntent(0), "the request is dropped")

	// a new request is refused while nothing is pending
	acked := w.committedAt(t, parent.ShardState.Control, parentHash)
	acked.CommittedHead.ShardInfo[0].IRTR.Epoch = acked.CommittedHead.ShardInfo[0].IR.Epoch
	_, err = x.planVRRecoveryAt(acked)
	require.ErrorIs(t, err, ErrVRRecoveryIneligible)
}

// A restart in the middle: the plan and its endorsements are volatile, so a root that restarted after the Prepare orders no Freeze for it
// (the Prepare lapses and the operator requests again); the one-shot allowance is committed history, so it survives the restart.
func TestVRRecoveryAcrossARestart(t *testing.T) {
	ctx := context.Background()
	w := newRecoveryWorld(t)
	x := w.r.manager
	x.vr = &vrHandoff{reject: func(context.Context, uint64, uint64, *rctypes.QuorumCert) bool { return false },
		leader: func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
			return vrschedule.LeaderStep{}, nil
		}, svc: vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})}
	parentHash := bytes.Repeat([]byte{0x31}, 32)
	qc, parent := w.idleVRParent(t, parentHash)
	plan, err := x.planVRRecoveryAt(w.committedAt(t, parent.ShardState.Control, parentHash))
	require.NoError(t, err)
	records, err := x.handoffRecordsForRound(8, qc)
	require.NoError(t, err)
	require.Len(t, records, 1)
	prepare, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	control := *parent.ShardState.Control
	control.Phase, control.OrderedRound, control.RecordBytes, control.FrozenParent = "prepared", prepare.OrderedRound, records[0], bytes.Clone(parentHash)
	control.PreviousDigest = bytes.Repeat([]byte{9}, 32)
	require.NoError(t, x.endorseHandoffAtState(ctx, plan, w.committedAt(t, &control, parentHash)))
	parent.ShardState.Control = &control
	require.True(t, x.vrRecoveryRoute(parent, &control, control.OrderedRound+1), "premise: the plan is held")

	// the process restarts: nothing volatile is left
	x.handoffMu.Lock()
	x.handoffPlans, x.handoffIntent = nil, nil
	x.handoffMu.Unlock()
	require.False(t, x.vrRecoveryRoute(parent, &control, control.OrderedRound+1), "no plan: nothing is ordered for the old Prepare")
	records, err = x.handoffRecordsForRound(control.OrderedRound+2, qc)
	require.NoError(t, err)
	require.Empty(t, records)

	// the recovery commits, the root restarts: the allowance is not reset
	second := w.second
	require.NoError(t, w.r.rt.Activate(ctx, q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot, Candidate: second.Candidate}))
	w.r.close()
	w.r.mustOpen(true)
	lctx, err := storage.LifecycleFor(w.r.orchestration, w.key.PartitionID, types.ShardID{}, 0, w.installed)
	require.NoError(t, err)
	require.Equal(t, 1, lctx.CommittedRecoveries)
	require.ErrorIs(t, recoveryEligible(w.candidate, lctx, w.installed), evmassign.ErrRecoveryUsed)
}

// A leader change in the middle: another root of J' holds the same plan (the operator hands it to every root) and sees the same committed
// Prepare and the same endorsements, so it orders the same Freeze v3 and the existing admission accepts it.
func TestVRRecoveryLeaderChangeOrdersTheSameFreeze(t *testing.T) {
	ctx := context.Background()
	a := newRecoveryWorld(t)
	b := newRecoveryWorldAs(t, a.f, 1)
	parentHash := bytes.Repeat([]byte{0x31}, 32)
	worlds := []*recoveryWorld{a, b}
	var qcs []*rctypes.QuorumCert
	var parents []*storage.ExecutedBlock
	for _, w := range worlds {
		w.r.manager.vr = &vrHandoff{reject: func(context.Context, uint64, uint64, *rctypes.QuorumCert) bool { return false },
			leader: func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
				return vrschedule.LeaderStep{}, nil
			}, svc: vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})}
		qc, parent := w.idleVRParent(t, parentHash)
		qcs, parents = append(qcs, qc), append(parents, parent)
	}
	plan, err := a.r.manager.planVRRecoveryAt(a.committedAt(t, parents[0].ShardState.Control, parentHash))
	require.NoError(t, err)
	require.NoError(t, b.r.manager.acceptHandoffIntentAtState(plan, b.committedAt(t, parents[1].ShardState.Control, parentHash)))

	// the first leader orders the Prepare; both roots see it committed
	records, err := a.r.manager.handoffRecordsForRound(8, qcs[0])
	require.NoError(t, err)
	require.Len(t, records, 1)
	prepare, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	control := *parents[0].ShardState.Control
	control.Phase, control.OrderedRound, control.RecordBytes, control.FrozenParent = "prepared", prepare.OrderedRound, records[0], bytes.Clone(parentHash)
	control.PreviousDigest = bytes.Repeat([]byte{9}, 32)
	for i := range worlds {
		c := control
		parents[i].ShardState.Control = &c
	}
	// J''s root quorum endorses; every root learns every endorsement
	var endorsements []abdrc.HandoffApprovalMsg
	pb, err := a.r.manager.decodePlanBody(plan.Body)
	require.NoError(t, err)
	bodyID := pb.id
	for _, w := range worlds {
		require.NoError(t, w.r.manager.endorseHandoffAtState(ctx, plan, w.committedAt(t, &control, parentHash)))
		self := w.r.manager.id.String()
		mine := w.r.manager.handoffPlans[bodyID]
		require.NotNil(t, mine)
		msg := mine.plan
		msg.Signer, msg.Signature, msg.AbortSignature = self, mine.signatures[self], mine.abortSignatures[self]
		endorsements = append(endorsements, msg)
	}
	third := a.f.NewNodes[2]
	body, err := a.r.manager.decodePlanBody(plan.Body)
	require.NoError(t, err)
	stored := a.r.manager.handoffPlans[body.id]
	domain, err := storage.EndorsementBytes(stored.record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(stored.record)
	require.NoError(t, err)
	signed := stored.plan
	signed.Signer = third.PeerConf.ID.String()
	signed.Signature, err = third.Signer.SignBytes(domain)
	require.NoError(t, err)
	signed.AbortSignature, err = third.Signer.SignBytes(abortDomain)
	require.NoError(t, err)
	endorsements = append(endorsements, signed)
	for _, w := range worlds {
		for i := range endorsements {
			e := endorsements[i]
			require.NoError(t, w.r.manager.onHandoffApprovalMsg(ctx, &e))
		}
	}
	var freezes [][]byte
	for i, w := range worlds {
		recs, err := w.r.manager.handoffRecordsForRound(control.OrderedRound+2, qcs[i])
		require.NoError(t, err)
		require.Len(t, recs, 2, "root %d orders the Freeze", i)
		freeze, err := storage.DecodeOrderedHandoffRecord(recs[0])
		require.NoError(t, err)
		_, err = w.r.manager.blockStore().VerifyFreezeCompanion(freeze, recs[1])
		require.NoError(t, err)
		freezes = append(freezes, append(append([]byte{}, recs[0]...), recs[1]...))
	}
	require.Equal(t, freezes[0], freezes[1])
}
