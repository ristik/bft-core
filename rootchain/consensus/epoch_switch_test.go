package consensus

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3install"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The in-process epoch switch (#1086). The q3 fixture's replicas open on the old epoch's committed checkpoint: epoch 1 is installed and
// the committed root holds the commit of the handoff into epoch 2, which is exactly the state of a member right after the activation
// commit. The first three successor members are members of epoch 1 (they stay); the fourth is a joiner.

// ownSwitch is a stayer's switch: its own evidence is the fixture's bundle, installed through the replica's runtime.
func ownSwitch(r *q3Replica) EpochSwitch {
	return &Q3EpochSwitch{Runtime: r.rt, Bundle: func(context.Context, uint64) (q3active.Bundle, error) { return r.bundle(), nil }}
}

const joinerIndex = 3

// switchCluster is the live cluster in which the stayers switch in process and the joiner installs across a restart, as the drive
// installs a joiner before the commit's members move (#1082).
func switchCluster(t *testing.T, o q3fixture.Options) *q3Live {
	t.Helper()
	c := newQ3LiveWith(t, o, func(i int, r *q3Replica) {
		if i != joinerIndex {
			r.switchFor = ownSwitch
		}
	})
	ctx := context.Background()
	for i, r := range c.replicas {
		require.NoError(t, r.rt.Recover(ctx))
		if i == joinerIndex {
			require.NoError(t, r.rt.Activate(ctx, r.bundle()))
			r.close()
			r.mustOpen(true)
			require.NoError(t, r.rt.Recover(ctx))
		}
	}
	return c
}

// trafficLog records, per epoch, every consensus message the network delivers, with its time.
type trafficLog struct {
	mu       sync.Mutex
	timeouts map[uint64][]time.Time // epoch -> delivered timeout votes
	byAuthor map[string][]uint64    // author -> epochs of its delivered votes, timeouts and proposals, in order
}

func tapTraffic(c *q3Live) *trafficLog {
	l := &trafficLog{timeouts: map[uint64][]time.Time{}, byAuthor: map[string][]uint64{}}
	tap := func(_ peer.ID, msg any) {
		epoch, author, ok := futureEpochOf(msg)
		if !ok {
			return
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if _, timeout := msg.(*abdrc.TimeoutMsg); timeout {
			l.timeouts[epoch] = append(l.timeouts[epoch], time.Now())
		}
		l.byAuthor[author] = append(l.byAuthor[author], epoch)
	}
	c.tap.Store(&tap)
	return l
}

// anchorSlot is the replica's installed anchor slot once its successor is published, else the maximum round (nothing past it).
func anchorSlot(r *q3Replica) uint64 {
	if s := r.manager.SwitchState(); s.Epoch != 2 || s.Phase != SwitchRunning {
		return ^uint64(0)
	}
	return r.manager.epochAnchor.Slot
}

func committedEpoch(r *q3Replica) (epoch, round uint64) {
	state, err := r.manager.blockStore.GetState()
	if err != nil || state.CommittedHead == nil || state.CommittedHead.Block == nil {
		return 0, 0
	}
	return state.CommittedHead.Block.Epoch, state.CommittedHead.Block.Round
}

// awaitSuccessorCommit waits until every replica has committed a block of epoch 2 and returns how long that took.
func awaitSuccessorCommit(t *testing.T, c *q3Live, start time.Time, within time.Duration) time.Duration {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, r := range c.replicas {
			// past the synthetic anchor (which is the committed root of epoch 2 the install leaves): a block the successor certified
			if e, round := committedEpoch(r); e != 2 || round <= anchorSlot(r) {
				return false
			}
		}
		return true
	}, within, 10*time.Millisecond, "every member commits a block of the successor epoch")
	return time.Since(start)
}

// The staying members switch at the commit, inside their processes, and the successor commits its first blocks at round speed: no
// timeout vote of the successor epoch is ever sent (no hidden full timeout), and no member signs anything of the old epoch once it
// switched.
func TestInProcessSwitchStayersCommitTheSuccessorWithoutATimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    q3fixture.Options
		late []int // stayers that are online but whose process reaches the commit late (their queue holds the successor's first messages)
	}{
		{name: "root-only, unit weights", o: q3fixture.Options{}},
		{name: "coupled, weighted 6,1,1,1", o: q3fixture.Options{Assignment: true}},
		{name: "two stayers commit 600 ms after the first switched", o: q3fixture.Options{}, late: []int{1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := switchCluster(t, tc.o)
			traffic := tapTraffic(c)
			start := time.Now()
			for i := range c.replicas {
				if !slices.Contains(tc.late, i) {
					c.start(i)
				} else {
					c.offline.Delete(c.replicas[i].id()) // reachable: what is sent to it waits in its queue
				}
			}
			if len(tc.late) != 0 {
				time.Sleep(600 * time.Millisecond)
				for _, i := range tc.late {
					c.start(i)
				}
			}
			took := awaitSuccessorCommit(t, c, start, LocalTimeout*time.Millisecond)
			t.Logf("every member committed a successor block %v after the start", took)
			require.Less(t, took, LocalTimeout*time.Millisecond/2, "no round of the successor timed out on the way")

			traffic.mu.Lock()
			require.Empty(t, traffic.timeouts[2], "no timeout vote of the successor epoch")
			for i, r := range c.replicas {
				for _, e := range traffic.byAuthor[r.id().String()] {
					require.EqualValues(t, 2, e, "member %d signed nothing of the old epoch after the switch", i)
				}
			}
			traffic.mu.Unlock()
			for i, r := range c.replicas {
				s := r.manager.SwitchState()
				require.Equal(t, SwitchRunning, s.Phase, "member %d", i)
				require.EqualValues(t, 2, s.Epoch, "member %d", i)
				require.EqualValues(t, 2, r.manager.InstalledRootEpoch())
				if i != joinerIndex {
					require.EqualValues(t, 2, s.Target, "member %d switched in process", i)
					require.NotZero(t, s.Generation)
					t.Logf("member %d switched in %v", i, s.Took)
					require.Less(t, s.Took, time.Second, "the switch is one install, not a restart")
				}
				require.NoError(t, r.rt.Gate(context.Background(), c.f.Claim), "the journal admits the activation")
			}
		})
	}
}

// runAlone runs a replica's manager on its mock network and returns the channel Run's result arrives on.
func runAlone(t *testing.T, r *q3Replica) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cm := r.manager
	go func() { done <- cm.Run(ctx) }()
	r.stopRun = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("manager did not stop")
		}
	}
	return cancel, done
}

func openAlone(t *testing.T, f *q3fixture.Fixture, i int, prepare func(*q3Replica)) *q3Replica {
	t.Helper()
	r := newQ3Replica(t, f, f.NewNodes[i])
	if prepare != nil {
		prepare(r)
	}
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(context.Background()))
	return r
}

// A switch that completes on a lone member: the successor is installed by the journal, the context is published once, and the
// successor's worker started from durable state. Old-epoch work after it is refused at every fence.
func TestInProcessSwitchPublishesTheSuccessorAndFencesTheOldEpoch(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, func(r *q3Replica) { r.switchFor = ownSwitch })
	m := r.manager
	gen0 := m.contextGen()
	require.EqualValues(t, 1, m.InstalledRootEpoch())
	_, done := runAlone(t, r)
	require.Eventually(t, func() bool { return m.SwitchState().Epoch == 2 }, 5*time.Second, 5*time.Millisecond)
	s := m.SwitchState()
	require.Equal(t, SwitchRunning, s.Phase)
	require.EqualValues(t, gen0+2, s.Generation, "one generation for the barrier, one for the publication")
	require.Equal(t, s.Generation, m.contextGen())
	require.EqualValues(t, 2, m.InstalledRootEpoch())
	require.NotNil(t, m.epochAnchor)
	require.EqualValues(t, 2, m.epochAnchor.Epoch)
	require.NoError(t, r.rt.Gate(context.Background(), f.Claim))
	select {
	case err := <-done:
		t.Fatalf("Run ended after the switch: %v", err)
	default:
	}

	// the successor's worker started as at a process start: the round after the anchor, or later
	require.Eventually(t, func() bool { return m.pacemaker.GetCurrentRound() >= m.epochAnchor.Slot+1 }, time.Second, 5*time.Millisecond)

	// a signature of the old epoch is refused by the fence, whatever the caller
	err := m.safety.Sign(1, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 1}})
	require.ErrorIs(t, err, ErrStaleContext)
	_, err = m.safety.MakeVote(&drctypes.BlockData{Epoch: 1}, nil, nil, nil)
	require.ErrorIs(t, err, ErrStaleContext)
	require.ErrorIs(t, m.safety.SignTimeout(&abdrc.TimeoutMsg{Timeout: &drctypes.Timeout{Epoch: 1}}, nil), ErrStaleContext)
	// work started in the replaced context cannot complete in the successor's
	require.ErrorIs(t, m.contextOpen(gen0), ErrStaleContext)
	require.NoError(t, m.contextOpen(m.contextGen()))
}

// A member that does not stay (a leaver: a member of epoch 1 the successor does not name) and a joiner (not a member of epoch 1) do
// not switch in process in this slice: they stay in their epoch and the install restart is their path, as before.
func TestInProcessSwitchLeaverAndJoinerStayForTheRestart(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	leaver := newQ3Replica(t, f, f.OldNodes[3])
	require.NotContains(t, f.NewNodes, f.OldNodes[3], "the fixture's fourth old member leaves")
	leaver.switchFor = ownSwitch
	leaver.mustOpen(true)
	t.Cleanup(leaver.close)
	require.NoError(t, leaver.rt.Recover(context.Background()))
	joiner := openAlone(t, f, joinerIndex, func(r *q3Replica) { r.switchFor = ownSwitch })
	for name, r := range map[string]*q3Replica{"leaver": leaver, "joiner": joiner} {
		_, done := runAlone(t, r)
		require.Eventually(t, func() bool { return r.manager.pacemaker.GetCurrentRound() != 0 }, 2*time.Second, 5*time.Millisecond)
		time.Sleep(500 * time.Millisecond) // the loop evaluates the committed root at once
		s := r.manager.SwitchState()
		require.Equal(t, SwitchRunning, s.Phase, name)
		require.EqualValues(t, 1, s.Epoch, name)
		require.EqualValues(t, 1, r.manager.InstalledRootEpoch(), name)
		select {
		case err := <-done:
			t.Fatalf("%s: Run ended: %v", name, err)
		default:
		}
	}
}

// A capture that fails (this root holds no authenticated evidence of its own) is not a switch: nothing is fenced, the root stays in
// its epoch, and the install restart is the fallback.
func TestInProcessSwitchWithoutOwnEvidenceStaysInTheEpoch(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	forged := q3fixture.New(t, q3fixture.Options{Chain: f, SignedBy: 2}) // the commit below the old threshold: refused by Authenticate
	for name, bundle := range map[string]func(context.Context, uint64) (q3active.Bundle, error){
		"no evidence":     func(context.Context, uint64) (q3active.Bundle, error) { return q3active.Bundle{}, ErrNoQ3Evidence },
		"forged evidence": func(context.Context, uint64) (q3active.Bundle, error) { return secondBundle(forged), nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := openAlone(t, f, 0, func(r *q3Replica) {
				r.switchFor = func(r *q3Replica) EpochSwitch { return &Q3EpochSwitch{Runtime: r.rt, Bundle: bundle} }
			})
			_, done := runAlone(t, r)
			time.Sleep(500 * time.Millisecond) // the loop evaluates the committed root at once
			require.Equal(t, SwitchState{Phase: SwitchRunning, Epoch: 1}, r.manager.SwitchState())
			require.Nil(t, r.manager.switchCtx.Load(), "no barrier was raised")
			_, staged, err := r.rt.StagedBundleAt(context.Background(), 2)
			require.NoError(t, err)
			require.False(t, staged, "nothing was staged")
			select {
			case err := <-done:
				t.Fatalf("Run ended: %v", err)
			default:
			}
		})
	}
}

// A failure after the barrier never resumes the old epoch: signing stays fenced and Run returns the error, so that the process exits.
// Its restart recovers the exact activation through the journal (a failure after the bundle was staged) and runs the successor.
func TestInProcessSwitchFailureFencesAndTheRestartRecovers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(r *q3Replica) EpochSwitch
	}{
		{name: "a participant is not bound: the journal stops after the root installed", setup: func(r *q3Replica) EpochSwitch {
			r.authority.off.Store(true)
			return ownSwitch(r)
		}},
		{name: "the after-install derivation fails", setup: func(r *q3Replica) EpochSwitch {
			return &Q3EpochSwitch{Runtime: r.rt, Bundle: func(context.Context, uint64) (q3active.Bundle, error) { return r.bundle(), nil },
				After: func(context.Context, uint64) error { return errors.New("injected") }}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := q3fixture.New(t, q3fixture.Options{})
			r := openAlone(t, f, 0, func(rr *q3Replica) {
				rr.switchFor = func(rr *q3Replica) EpochSwitch { return &lateSwitch{make: func() EpochSwitch { return tc.setup(rr) }} }
			})
			m := r.manager
			_, done := runAlone(t, r)
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not end at the failed switch")
			}
			r.stopRun = nil
			require.Error(t, err)
			s := m.SwitchState()
			require.Equal(t, SwitchFaulted, s.Phase)
			require.EqualValues(t, 2, s.Target)
			require.ErrorIs(t, m.safety.Sign(2, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 2}}), ErrSwitching, "signing stays fenced")
			require.ErrorIs(t, m.safety.Sign(1, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 1}}), ErrSwitching, "the old epoch never resumes")
			require.ErrorIs(t, m.operator(func() error { return nil }), ErrSwitching)

			// the process restarts: the journal completes or checks the staged activation before anything is admitted
			r.authority.off.Store(false)
			r.close()
			r.switchFor = ownSwitch
			r.mustOpen(true)
			require.NoError(t, r.rt.Recover(context.Background()))
			require.EqualValues(t, 2, r.manager.InstalledRootEpoch())
			require.NoError(t, r.rt.Gate(context.Background(), f.Claim))
			_, done = runAlone(t, r)
			require.Eventually(t, func() bool { return r.manager.pacemaker.GetCurrentRound() >= r.manager.epochAnchor.Slot+1 }, 2*time.Second, 5*time.Millisecond)
			require.Equal(t, SwitchState{Phase: SwitchRunning, Epoch: 2}, r.manager.SwitchState(), "a restarted root in the successor does not switch again")
			select {
			case err := <-done:
				t.Fatalf("Run ended: %v", err)
			default:
			}
		})
	}
}

// lateSwitch builds the switch when it is first asked, after the replica is opened (its toggles are then in place).
type lateSwitch struct {
	once sync.Once
	make func() EpochSwitch
	s    EpochSwitch
}

func (l *lateSwitch) Capture(ctx context.Context, epoch uint64) (CapturedActivation, error) {
	l.once.Do(func() { l.s = l.make() })
	return l.s.Capture(ctx, epoch)
}

// fixedCapture is a captured activation that installs nothing.
type fixedCapture struct {
	members []string
	install func(context.Context) error
}

func (c fixedCapture) Members() []string { return c.members }
func (c fixedCapture) Install(ctx context.Context) error {
	if c.install != nil {
		return c.install(ctx)
	}
	return nil
}

// The barrier: an operator section in flight delays it, and while it is up nothing signs, no operator entry point runs, and the
// shard-facing entry points wait for the successor.
func TestInProcessSwitchBarrier(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, nil)
	m := r.manager

	inside, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = m.operator(func() error {
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	raised := make(chan *errEpochSwitch)
	go func() {
		err := m.enterSwitching(1, 2, evmroot.OrderedHandoffRecord{Epoch: 1, Kind: "commit"}, fixedCapture{})
		var sw *errEpochSwitch
		require.ErrorAs(t, err, &sw)
		raised <- sw
	}()
	select {
	case <-raised:
		t.Fatal("the barrier did not wait for the operator section in flight")
	case <-time.After(100 * time.Millisecond):
	}
	require.Nil(t, m.switchCtx.Load())
	close(release)
	sw := <-raised
	require.Equal(t, SwitchSwitching, m.SwitchState().Phase)

	require.ErrorIs(t, m.safety.Sign(1, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 1}}), ErrSwitching)
	require.ErrorIs(t, m.safety.Sign(2, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 2}}), ErrSwitching)
	require.ErrorIs(t, m.contextOpen(m.contextGen()), ErrSwitching)
	opRan := make(chan error, 1)
	go func() { opRan <- m.operator(func() error { return nil }) }()

	// a shard-facing caller waits for the successor context, then reads it
	waited := make(chan error, 1)
	go func() {
		_, err := m.ShardInfo(f.ShardConf.PartitionID, f.ShardConf.ShardID)
		waited <- err
	}()
	select {
	case <-waited:
		t.Fatal("a shard-facing read ran during the switch")
	case <-time.After(100 * time.Millisecond):
	}
	m.publishSwitch(sw, SwitchRunning)
	require.NoError(t, <-waited)
	require.NoError(t, <-opRan, "an operator call that waited on the barrier runs in the successor's context")
	require.NoError(t, m.operator(func() error { return nil }))
	require.Equal(t, SwitchRunning, m.SwitchState().Phase)
	require.EqualValues(t, 2, m.SwitchState().Epoch)
}

// Messages of the next epoch wait, bounded, for this root's own switch and are replayed only into that epoch.
func TestInProcessSwitchParksTheNextEpochsMessagesBounded(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, func(r *q3Replica) { r.switchFor = ownSwitch })
	m := r.manager
	require.EqualValues(t, 1, m.InstalledRootEpoch())
	proposal := func(epoch uint64, author string) *abdrc.ProposalMsg {
		return &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: epoch, Author: author}}
	}
	require.False(t, m.parkFuture(proposal(1, "a")), "the installed epoch is handled")
	require.False(t, m.parkFuture(proposal(3, "a")), "two epochs ahead is refused as before")
	require.False(t, m.parkFuture(&abdrc.StateMsg{}), "only proposals, votes and timeouts wait")
	for i := 0; i < 2*maxFutureMessagesPerAuthor; i++ {
		require.True(t, m.parkFuture(proposal(2, "a")))
	}
	require.Len(t, m.future.items, maxFutureMessagesPerAuthor, "per author")
	for i := 0; i < 2*maxFutureMessages; i++ {
		require.True(t, m.parkFuture(&abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{Epoch: 2}, Author: string(rune('A' + i%60))}))
	}
	require.Len(t, m.future.items, maxFutureMessages, "in all")
	m.replayFuture(context.Background()) // epoch 2 is not installed: dropped
	require.Empty(t, m.future.items)

	noSwitch := openAlone(t, f, 1, nil)
	require.False(t, noSwitch.manager.parkFuture(proposal(2, "a")), "a manager that never switches parks nothing")
}

// The successor's first certification requests are counted in its own context: a request of the replaced context is dropped by
// generation, and one made during the switch waits for the successor.
func TestInProcessSwitchCertificationRequestsAreOfOneContext(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, nil)
	m := r.manager
	sw := m.enterSwitching(1, 2, evmroot.OrderedHandoffRecord{Epoch: 1, Kind: "commit"}, fixedCapture{}).(*errEpochSwitch)
	sent := make(chan certRequest, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		go func() { sent <- <-m.certReqCh }()
		_ = m.RequestCertification(ctx, IRChangeRequest{})
	}()
	select {
	case <-sent:
		t.Fatal("a certification request went in during the switch")
	case <-time.After(100 * time.Millisecond):
	}
	m.publishSwitch(sw, SwitchRunning)
	req := <-sent
	require.Equal(t, m.contextGen(), req.gen, "made in the successor's context")
}

// InstallVerifiedEpoch refuses a manager whose worker runs, whatever its pacemaker says.
func TestInstallRefusesARunningWorker(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, nil)
	r.manager.workerRunning.Store(true)
	defer r.manager.workerRunning.Store(false)
	_, err := r.manager.InstallVerifiedEpoch(q3fixtureEntry(t, f), f.Proof, f.Snapshot, f.Candidate)
	require.ErrorIs(t, err, ErrNotStopped)
}

func q3fixtureEntry(t *testing.T, f *q3fixture.Fixture) q3format.Entry {
	t.Helper()
	require.NotNil(t, f.History)
	e, err := f.History.ForEpoch(2)
	require.NoError(t, err)
	return e
}

// Every field of the manager is accounted for by the switch: kept (a binding of the process, durable-backed, or the switch's own),
// reset by resetVolatile to what the constructor leaves, or replaced by the install. A field added without a decision fails here.
func TestInProcessSwitchAccountsForEveryManagerField(t *testing.T) {
	kept := []string{"timeoutVerify", "shadow", "backoff", "msgSeq", "profile", "certCacheStart", "certReqCh", "certResultCh", "ucSink", "params", "id", "net",
		"trustBaseStore", "safety", "blockStore", "orchestration", "viewResolver", "frontier", "recoveryProfile2", "utbPrevious", "utbStore", "evidence",
		"utbConfig", "recoveryHistory", "stageRecovery", "proposalRequestCheck", "posPrefetching", "witnesses", "q3", "primaryWitness",
		"approvalSink", "judgeHook", "handoffMu", "switcher", "ctxMu", "ctxGen", "switchCtx", "workerRunning", "future", "log", "tracer",
		"leaderCnt", "execMsgCnt", "execMsgDur", "voteCnt", "proposedCR", "qcSize", "qcVoters", "susVotes", "recoveryReq", "frontierFault", "addBlockDur"}
	reset := []string{"pacemaker", "voteBuffer", "recovery", "irReqBuffer", "retained", "leaderCheckedRound", "switchCheckedRound", "posQueue",
		"primaryCache", "v3Planned", "q3Staged", "q3StagedEVM"}
	installed := []string{"leaderSelector", "trustBase", "irReqVerifier", "t2Timeouts", "epochAnchor", "handoffPlans", "handoffIntent", "handoffAborts"}
	known := map[string]bool{}
	for _, set := range [][]string{kept, reset, installed} {
		for _, n := range set {
			require.False(t, known[n], "%s is classified twice", n)
			known[n] = true
		}
	}
	typ := reflect.TypeOf(ConsensusManager{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		require.True(t, known[name], "ConsensusManager.%s is not classified for the in-process epoch switch (#1086)", name)
		delete(known, name)
	}
	require.Empty(t, known, "classified fields the manager does not have")
	_ = q3install.ErrIncomplete
}
