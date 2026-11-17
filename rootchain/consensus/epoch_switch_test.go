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
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The in-process epoch switch (#1086). The q3 fixture's replicas open on the old epoch's committed checkpoint: epoch 1 is installed and
// the committed root holds the commit of the handoff into epoch 2, which is exactly the state of a member right after the activation
// commit. The first three successor members are members of epoch 1 (they stay); the fourth is a joiner.

// ownSwitch is a root's switch from its own evidence: the fixture's bundle, installed through the replica's runtime. It fetches from no
// peer (no Fetch): a root without the commit installs across a restart.
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
		{name: "root-only, weighted 6,1,1,1", o: q3fixture.Options{}},
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

// PR 2: a member that does not stay (a leaver: a member of epoch 1 the successor does not name) and a joiner that holds the commit (not a
// member of epoch 1) both switch in process at their own commit: the leaver into Following(2), where it signs nothing and still serves the
// activation from its journal, the joiner into Running(2).
func TestInProcessSwitchLeaverFollowsAndJoinerJoins(t *testing.T) {
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
		require.Eventually(t, func() bool { return r.manager.SwitchState().Epoch == 2 }, 5*time.Second, 5*time.Millisecond, name)
		s := r.manager.SwitchState()
		require.Equal(t, map[string]SwitchPhase{"leaver": SwitchFollowing, "joiner": SwitchRunning}[name], s.Phase, name)
		require.EqualValues(t, 2, s.Target, name)
		require.Zero(t, s.Declined, name)
		require.EqualValues(t, 2, r.manager.InstalledRootEpoch(), name)
		require.NoError(t, r.rt.Gate(context.Background(), f.Claim), name)
		_, staged, err := r.rt.StagedBundleAt(context.Background(), 2)
		require.NoError(t, err)
		require.True(t, staged, "%s serves the activation from its journal", name)
		select {
		case err := <-done:
			t.Fatalf("%s: Run ended: %v", name, err)
		default:
		}
	}
	// the leaver signs nothing of the successor, and nothing of the epoch it left
	m := leaver.manager
	require.ErrorIs(t, m.safety.Sign(2, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 2}}), ErrNotAMember)
	_, err := m.safety.MakeVote(&drctypes.BlockData{Epoch: 2}, nil, nil, nil)
	require.ErrorIs(t, err, ErrNotAMember)
	require.ErrorIs(t, m.safety.Sign(1, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 1}}), ErrStaleContext)
}

// PR 2: a successor that names a joiner is switched into in process by default: the staying member does not wait for a restart after the
// joiner (#1082 is kept by the joiner's own switch and its staged committee connections).
func TestInProcessSwitchIntoASuccessorWithAJoiner(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, func(r *q3Replica) {
		r.switchFor = func(r *q3Replica) EpochSwitch {
			return &Q3EpochSwitch{Runtime: r.rt, Bundle: func(context.Context, uint64) (q3active.Bundle, error) { return r.bundle(), nil }}
		}
	})
	require.Equal(t, []string{f.NewNodes[joinerIndex].PeerConf.ID.String()}, newcomers(nodeIDs(f), r.manager.trustBase.Load()))
	_, done := runAlone(t, r)
	require.Eventually(t, func() bool { return r.manager.SwitchState().Epoch == 2 }, 5*time.Second, 5*time.Millisecond)
	s := r.manager.SwitchState()
	require.Equal(t, SwitchRunning, s.Phase)
	require.EqualValues(t, 2, s.Target)
	require.Zero(t, s.Declined)
	select {
	case err := <-done:
		t.Fatalf("Run ended: %v", err)
	default:
	}
}

func nodeIDs(f *q3fixture.Fixture) (out []string) {
	for _, n := range f.NewNodes {
		out = append(out, n.PeerConf.ID.String())
	}
	return out
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
				r.switchFor = func(r *q3Replica) EpochSwitch {
					return &Q3EpochSwitch{Runtime: r.rt, Bundle: bundle}
				}
			})
			_, done := runAlone(t, r)
			time.Sleep(500 * time.Millisecond) // the loop evaluates the committed root at once
			require.Equal(t, SwitchState{Phase: SwitchRunning, Epoch: 1, Declined: 2, DeclinedReason: "no own evidence"}, r.manager.SwitchState())
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
		err := m.enterSwitching(1, 2, evmroot.OrderedHandoffRecord{Epoch: 1, Kind: "commit"}.ID(), fixedCapture{})
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

// Messages of the next epoch wait for this root's own switch only within the bounds of their authenticated sender (#1086 review): the
// transport's peer, not the claimed author; a root of the installed or staged committee; a per-message wire size; a per-sender count and
// byte allowance; an aggregate budget; a lifetime. They are replayed only into that epoch, and a declined switch drops them.
func TestInProcessSwitchParksTheNextEpochsMessagesWithinTheirSendersBounds(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, func(r *q3Replica) { r.switchFor = ownSwitch })
	m := r.manager
	require.EqualValues(t, 1, m.InstalledRootEpoch())
	now := time.Now()
	member := func(i int) peer.ID { return f.OldNodes[i].PeerConf.ID }
	proposal := func(epoch uint64, author peer.ID) *abdrc.ProposalMsg {
		return &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: epoch, Author: author.String()}}
	}
	from := func(id peer.ID, size uint64) messageOrigin { return messageOrigin{from: id, size: size, known: true} }
	parked := func() int { return len(m.future.items) }

	require.False(t, m.parkFuture(proposal(1, member(1)), from(member(1), 10), now), "the installed epoch is handled")
	require.False(t, m.parkFuture(proposal(3, member(1)), from(member(1), 10), now), "two epochs ahead is refused as before")
	require.False(t, m.parkFuture(&abdrc.StateMsg{}, from(member(1), 10), now), "only proposals, votes and timeouts wait")

	t.Run("not authenticated by the transport", func(t *testing.T) {
		require.True(t, m.parkFuture(proposal(2, member(1)), messageOrigin{}, now))
		require.Zero(t, parked())
	})
	t.Run("forged author: the claim is not the authenticated sender", func(t *testing.T) {
		require.True(t, m.parkFuture(proposal(2, member(2)), from(member(1), 10), now))
		require.Zero(t, parked())
	})
	t.Run("an outsider", func(t *testing.T) {
		outsider := testutilsNodeID(t)
		require.True(t, m.parkFuture(proposal(2, outsider), from(outsider, 10), now))
		require.Zero(t, parked())
	})
	t.Run("oversized", func(t *testing.T) {
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), maxFutureMessageBytes+1), now))
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 0), now))
		require.Zero(t, parked())
	})
	t.Run("a sender's allowance", func(t *testing.T) {
		for i := 0; i < 2*maxFutureMessagesPerPeer; i++ {
			require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 1), now))
		}
		require.Equal(t, maxFutureMessagesPerPeer, parked(), "per sender, by count")
		require.True(t, m.parkFuture(proposal(2, member(2)), from(member(2), maxFutureBytesPerPeer), now))
		require.True(t, m.parkFuture(proposal(2, member(2)), from(member(2), 1), now))
		require.Equal(t, maxFutureMessagesPerPeer+1, parked(), "per sender, by bytes")
		require.False(t, m.parkFuture(&abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{Epoch: 2}, Author: member(3).String()}, from(member(3), 1), now),
			"a vote without its commit info is malformed: not parked, refused by the handler as before")
		require.Equal(t, maxFutureMessagesPerPeer+1, parked())
	})
	t.Run("the aggregate budget", func(t *testing.T) {
		m.dropFuture()
		m.parkFuture(proposal(2, member(1)), from(member(1), 1), now) // the epoch's buffer
		m.future.bytes = maxFutureBytes - 1                           // as if the other senders had filled it
		require.True(t, m.parkFuture(proposal(2, member(2)), from(member(2), 2), now))
		require.Equal(t, 1, parked(), "a full budget takes nothing more")
		require.LessOrEqual(t, m.future.bytes, uint64(maxFutureBytes))
	})
	t.Run("a lifetime", func(t *testing.T) {
		m.dropFuture()
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 1000), now))
		require.True(t, m.parkFuture(proposal(2, member(2)), from(member(2), 1000), now.Add(futureMessageTTL+time.Second)))
		require.Equal(t, 1, parked(), "the expired one is gone")
		require.EqualValues(t, 1000, m.future.bytes)
		require.NotContains(t, m.future.byPeer, member(1))
	})
	t.Run("a declined switch drops them", func(t *testing.T) {
		require.NotZero(t, parked())
		m.declineSwitch(2, "joiners")
		require.Zero(t, parked())
		require.Zero(t, m.future.bytes)
		m.reconsiderSwitch(2)
	})
	t.Run("expired without another arrival", func(t *testing.T) {
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 10), now))
		require.NotZero(t, parked())
		m.sweepFuture(now.Add(futureMessageTTL + time.Second)) // the loop's periodic sweep
		require.Zero(t, parked())
		require.Zero(t, m.future.bytes)
		require.Empty(t, m.future.byPeer)
	})
	t.Run("an expired entry is not replayed", func(t *testing.T) {
		old := proposal(2, member(1))
		fresh := proposal(2, member(2))
		require.True(t, m.parkFuture(old, from(member(1), 10), now.Add(-futureMessageTTL-time.Second)))
		require.True(t, m.parkFuture(fresh, from(member(2), 10), now))
		installed := *m.trustBase.Load()
		installed.Epoch = 2 // as if the switch had installed epoch 2
		prev := m.trustBase.Swap(&installed)
		defer m.trustBase.Store(prev)
		require.Equal(t, []any{fresh}, m.replayable(now))
		require.Zero(t, parked())
	})
	t.Run("nothing parked after a decline until it is reconsidered", func(t *testing.T) {
		m.declineSwitch(2, "joiners")
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 10), now))
		require.Zero(t, parked(), "an arrival after the decline is refused")
		m.reconsiderSwitch(3)
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 10), now))
		require.Zero(t, parked(), "another target's reconsideration does not reset it")
		m.reconsiderSwitch(2)
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 10), now))
		require.Equal(t, 1, parked(), "a reconsidered activation parks again")
		m.dropFuture()
	})
	t.Run("replayed only into their epoch", func(t *testing.T) {
		require.True(t, m.parkFuture(proposal(2, member(1)), from(member(1), 1), now))
		m.replayFuture(context.Background()) // epoch 2 is not installed: dropped
		require.Zero(t, parked())
	})

	noSwitch := openAlone(t, f, 1, nil)
	require.False(t, noSwitch.manager.parkFuture(proposal(2, member(1)), from(member(1), 1), now), "a manager that never switches parks nothing")
}

func testutilsNodeID(t *testing.T) peer.ID {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{})
	return f.NewNodes[joinerIndex].PeerConf.ID
}

// The shard-facing barrier is a read-side critical section: a read already in flight holds the switch back, and the published
// successor is a started one (its pacemaker past the anchor, its leader and request context restored) before any worker runs in it.
func TestInProcessSwitchShardFacingReadsSeeOneStartedContext(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	t.Run("a read in flight holds the barrier", func(t *testing.T) {
		r := openAlone(t, f, 0, nil)
		m := r.manager
		inside, release := make(chan struct{}), make(chan struct{})
		m.SetViewResolver(blockingResolver{inside: inside, release: release})
		read := make(chan error, 1)
		go func() {
			_, _, err := m.RequestView(f.ShardConf.PartitionID, f.ShardConf.ShardID)
			read <- err
		}()
		<-inside
		raised := make(chan struct{})
		go func() {
			_ = m.enterSwitching(1, 2, evmroot.OrderedHandoffRecord{Epoch: 1, Kind: "commit"}.ID(), fixedCapture{})
			close(raised)
		}()
		select {
		case <-raised:
			t.Fatal("the switch raised its barrier under a shard-facing read in flight")
		case <-time.After(150 * time.Millisecond):
		}
		require.Nil(t, m.switchCtx.Load())
		close(release)
		require.NoError(t, <-read)
		<-raised
		require.Equal(t, SwitchSwitching, m.SwitchState().Phase)
		m.faultSwitch(&errEpochSwitch{from: 1, to: 2}, errors.New("test end"))
	})
	t.Run("published means started", func(t *testing.T) {
		paused, resume := make(chan struct{}), make(chan struct{})
		r := openAlone(t, f, 0, func(r *q3Replica) { r.switchFor = ownSwitch })
		m := r.manager
		m.switchPublished = func() {
			close(paused)
			<-resume
		}
		_, done := runAlone(t, r)
		<-paused // published, the successor's worker not running yet
		s := m.SwitchState()
		require.Equal(t, SwitchRunning, s.Phase)
		require.EqualValues(t, 2, s.Epoch)
		require.EqualValues(t, m.epochAnchor.Slot+1, m.pacemaker.GetCurrentRound(), "the pacemaker is restored before the publication")
		leader, err := m.leaderSelector.GetLeaderForRound(m.pacemaker.GetCurrentRound())
		require.NoError(t, err)
		require.NotEmpty(t, leader)
		si, err := m.ShardInfo(f.ShardConf.PartitionID, f.ShardConf.ShardID)
		require.NoError(t, err)
		require.NotNil(t, si)
		close(resume)
		select {
		case err := <-done:
			t.Fatalf("Run ended: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	})
}

// blockingResolver resolves nothing until released, signalling when a resolution is in flight.
type blockingResolver struct {
	inside, release chan struct{}
}

func (b blockingResolver) ResolveView(types.PartitionID, types.ShardID, uint64, storage.RequestPurpose) (*storage.RequestRoundView, error) {
	close(b.inside)
	<-b.release
	return nil, nil
}

// The successor's first certification requests are counted in its own context: a request of the replaced context is dropped by
// generation, and one made during the switch waits for the successor.
func TestInProcessSwitchCertificationRequestsAreOfOneContext(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, nil)
	m := r.manager
	sw := m.enterSwitching(1, 2, evmroot.OrderedHandoffRecord{Epoch: 1, Kind: "commit"}.ID(), fixedCapture{}).(*errEpochSwitch)
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
		"approvalSink", "judgeHook", "handoffMu", "switcher", "ctxMu", "ctxGen", "switchCtx", "workerRunning", "future", "switchDeclined", "origins", "acq",
		"switchPublished", "log", "tracer", "deferredReady", "vr",
		"leaderCnt", "execMsgCnt", "execMsgDur", "voteCnt", "proposedCR", "qcSize", "qcVoters", "susVotes", "recoveryReq", "frontierFault", "addBlockDur"}
	reset := []string{"pacemaker", "voteBuffer", "recovery", "irReqBuffer", "retained", "leaderCheckedRound", "switchCheckedRound", "posQueue",
		"primaryCache", "v3Planned", "q3Staged", "q3StagedEVM", "residence", "deferred"}
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

// The acceptance case of the default trigger (#1086 review): a re-weighting of the same committee (no joiner), every member with the
// production switch (joiners not allowed), and old-epoch work in flight across the switch on every member: shard-facing reads,
// certification requests counted in the old epoch, and operator calls. Every member switches in process, the successor commits at round
// speed with no timeout vote, nothing of the old epoch is signed after the switch, and nothing races (-race).
func TestInProcessSwitchDefaultTriggerWithOldEpochWorkInFlight(t *testing.T) {
	c := newQ3LiveWith(t, q3fixture.Options{NoJoiner: true, Weights: []uint64{3, 2, 2, 2}}, func(_ int, r *q3Replica) {
		r.switchFor = func(r *q3Replica) EpochSwitch {
			return &Q3EpochSwitch{Runtime: r.rt, Bundle: func(context.Context, uint64) (q3active.Bundle, error) { return r.bundle(), nil }}
		}
	})
	require.Len(t, c.replicas, 4)
	require.Empty(t, newcomers(nodeIDs(c.f), c.f.Old), "the successor has no joiner")
	ctx, stop := context.WithCancel(context.Background())
	var work sync.WaitGroup
	admitted := make([]int, len(c.replicas))
	for i, r := range c.replicas {
		require.NoError(t, r.rt.Recover(context.Background()))
		m := r.manager
		work.Add(1)
		go func() {
			defer work.Done()
			for ctx.Err() == nil {
				_, _ = m.ShardInfo(c.f.ShardConf.PartitionID, c.f.ShardConf.ShardID)
				_, _, _ = m.RequestView(c.f.ShardConf.PartitionID, c.f.ShardConf.ShardID)
				_, _ = m.Q3Status()
				_, _ = m.PlanV3Candidate(nil, nil)
				rctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
				if m.RequestCertification(rctx, IRChangeRequest{Partition: c.f.ShardConf.PartitionID, Shard: c.f.ShardConf.ShardID, Reason: Quorum, RootEpoch: 1}) == nil {
					admitted[i]++
				}
				cancel()
			}
		}()
	}
	traffic := tapTraffic(c)
	start := time.Now()
	for i := range c.replicas {
		c.start(i)
	}
	took := awaitSuccessorCommit(t, c, start, LocalTimeout*time.Millisecond)
	stop()
	work.Wait()
	t.Logf("every member committed a successor block %v after the start; old-epoch requests handed to the workers: %v", took, admitted)
	require.Less(t, took, LocalTimeout*time.Millisecond/2, "no round of the successor timed out on the way")
	traffic.mu.Lock()
	require.Empty(t, traffic.timeouts[2], "no timeout vote of the successor epoch")
	for _, epochs := range traffic.byAuthor {
		for _, e := range epochs {
			require.EqualValues(t, 2, e, "nothing of the old epoch is signed after the switch")
		}
	}
	traffic.mu.Unlock()
	for i, r := range c.replicas {
		s := r.manager.SwitchState()
		require.Equal(t, SwitchRunning, s.Phase, "member %d", i)
		require.EqualValues(t, 2, s.Epoch, "member %d", i)
		require.EqualValues(t, 2, s.Target, "member %d switched in process with the default switch", i)
		require.Zero(t, s.Declined, "member %d", i)
		t.Logf("member %d switched in %v", i, s.Took)
		require.NoError(t, r.rt.Gate(context.Background(), c.f.Claim))
	}
}

// A shard-facing admission that a switch overtakes between its wait and its read side waits no longer than its caller's context (#1086
// review, round 2): the read side is taken context-aware.
func TestInProcessSwitchShardFacingAdmissionHonoursItsContext(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, nil)
	m := r.manager
	m.ctxMu.Lock() // a switch that took the write side after the caller's awaitContext
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.RequestCertification(ctx, IRChangeRequest{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
	m.ctxMu.Unlock()
	require.NoError(t, m.shardFacing(context.Background(), func() error { return nil }), "a free barrier is taken at once")
}
