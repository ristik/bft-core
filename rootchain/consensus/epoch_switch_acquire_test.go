package consensus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// PR 2 of #1086: a root that does not hold the commit itself (a joiner, a follower, a member that lagged) acquires the activation from a
// root peer and switches into it in process, under the same barrier.

// peerFetch serves, for the replica asked, the bundle its journal staged (what q3delivery serves once a root has switched), after delay
// (a WAN round trip); a root that has not staged it yet refuses. It counts the requests.
type peerFetch struct {
	mu       sync.Mutex
	replicas map[peer.ID]*q3Replica
	delay    time.Duration
	asked    atomic.Int64
	serve    func(from peer.ID, epoch uint64) (q3active.Bundle, error) // replaces the journal lookup when set
}

func (p *peerFetch) fetch(ctx context.Context, from peer.ID, epoch uint64) (q3active.Bundle, error) {
	p.asked.Add(1)
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return q3active.Bundle{}, ctx.Err()
	}
	if p.serve != nil {
		return p.serve(from, epoch)
	}
	p.mu.Lock()
	r := p.replicas[from]
	p.mu.Unlock()
	if r == nil {
		return q3active.Bundle{}, errors.New("unknown root")
	}
	b, ok, err := r.rt.StagedBundleAt(ctx, epoch)
	if err != nil || !ok {
		return q3active.Bundle{}, fmt.Errorf("root %s does not serve epoch %d yet", from, epoch)
	}
	return b, nil
}

// acquiringSwitch is a root's production switch with both sources: its own evidence (none, for a root that does not hold the commit) and
// its peers'.
func acquiringSwitch(p *peerFetch) func(*q3Replica) EpochSwitch {
	return func(r *q3Replica) EpochSwitch {
		own := func(context.Context, uint64) (q3active.Bundle, error) { return r.bundle(), nil }
		if r.noCheckpoint {
			own = func(context.Context, uint64) (q3active.Bundle, error) { return q3active.Bundle{}, ErrNoQ3Evidence }
		}
		return &Q3EpochSwitch{Runtime: r.rt, Bundle: own, Fetch: p.fetch}
	}
}

// fixtureWhereJoinerLeads is a unit-weight fixture whose successor schedule gives the joiner round anchor.Slot+lead (lead 2 is what staging
// measured: the joiner's root led the round after the activation round). The schedule is read from a probe that installed the epoch.
func fixtureWhereJoinerLeads(t *testing.T, lead int) *q3fixture.Fixture {
	t.Helper()
	for range 32 {
		f := q3fixture.New(t, q3fixture.Options{Weights: []uint64{1, 1, 1, 1}})
		probe := newQ3Replica(t, f, f.NewNodes[0])
		probe.mustOpen(true)
		require.NoError(t, probe.rt.Recover(context.Background()))
		require.NoError(t, probe.rt.Activate(context.Background(), probe.bundle()))
		leader, err := probe.manager.leaderSelector.GetLeaderForRound(probe.manager.epochAnchor.Slot + uint64(lead))
		probe.close()
		require.NoError(t, err)
		if leader == f.NewNodes[joinerIndex].PeerConf.ID {
			return f
		}
	}
	t.Fatal("no fixture with the joiner in that slot")
	return nil
}

// The live latency test of PR 2: the stayers switch at their own commit, the joiner (which received no traffic of epoch 1 and does not hold
// the commit) acquires the activation from them when their first successor messages reach it, and the successor commits at round speed
// with no timeout vote at all: no full-timeout round, also when the joiner leads the first rounds.
func TestInProcessSwitchJoinerAcquiresAndTheSuccessorCommitsWithoutATimeout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lead   int           // the successor round, after the anchor, the joiner leads
		staged bool          // the joiner's staged candidate names it (it asks its peers before any successor message reaches it)
		delay  time.Duration // each fetch's round trip
	}{
		{name: "the joiner leads anchor+2 (staging k), a 50 ms WAN", lead: 2, delay: 50 * time.Millisecond},
		{name: "the joiner leads anchor+1 and has staged the candidate", lead: 1, staged: true, delay: 50 * time.Millisecond},
		{name: "a slow joiner: 1.5 s per fetch", lead: 2, delay: 1500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetch := &peerFetch{replicas: map[peer.ID]*q3Replica{}, delay: tc.delay}
			c := newQ3LiveFrom(t, fixtureWhereJoinerLeads(t, tc.lead), func(i int, r *q3Replica) {
				r.noCheckpoint = i == joinerIndex
				r.switchFor = acquiringSwitch(fetch)
				fetch.replicas[r.id()] = r
			})
			joiner := c.replicas[joinerIndex]
			for _, r := range c.replicas {
				require.NoError(t, r.rt.Recover(context.Background()))
			}
			require.EqualValues(t, 1, joiner.manager.InstalledRootEpoch())
			_, _, held := joiner.manager.blockStore().CommittedHandoff()
			require.False(t, held, "the joiner does not hold the commit")
			if tc.staged {
				joiner.manager.storeStagedEVM(2, evmassign.Candidate{}, c.f.Members)
				require.True(t, joiner.manager.IsStagedRoot(joiner.id().String()))
			}
			published := make([]atomic.Int64, len(c.replicas)) // when each member published its successor (unix ns)
			for i, r := range c.replicas {
				r.manager.switchPublished = func() { published[i].Store(time.Now().UnixNano()) }
			}
			traffic := tapTraffic(c)
			start := time.Now()
			for i := range c.replicas {
				c.start(i)
			}
			took := awaitSuccessorCommit(t, c, start, LocalTimeout*time.Millisecond)
			first := published[0].Load()
			for i := range c.replicas[:joinerIndex] {
				first = min(first, published[i].Load())
			}
			t.Logf("every member, the joiner included, committed a successor block %v after the start; the joiner switched %v after the first stayer",
				took, time.Duration(published[joinerIndex].Load()-first))
			require.Less(t, took, LocalTimeout*time.Millisecond/2, "no round of the successor timed out on the way")

			stayer := c.replicas[0].manager
			anchor := stayer.epochAnchor.Slot
			leader, err := stayer.leaderSelector.GetLeaderForRound(anchor + uint64(tc.lead))
			require.NoError(t, err)
			require.Equal(t, joiner.id(), leader, "the joiner leads round anchor+%d", tc.lead)

			traffic.mu.Lock()
			require.Empty(t, traffic.timeouts[2], "no timeout vote of the successor epoch: no full-timeout round")
			require.NotEmpty(t, traffic.byAuthor[joiner.id().String()], "the joiner takes part")
			for _, e := range traffic.byAuthor[joiner.id().String()] {
				require.EqualValues(t, 2, e, "the joiner signs only in the successor")
			}
			traffic.mu.Unlock()
			for i, r := range c.replicas {
				s := r.manager.SwitchState()
				require.Equal(t, SwitchRunning, s.Phase, "member %d", i)
				require.EqualValues(t, 2, s.Epoch, "member %d", i)
				require.EqualValues(t, 2, s.Target, "member %d switched in process", i)
				t.Logf("member %d switched in %v", i, s.Took)
				require.NoError(t, r.rt.Gate(context.Background(), c.f.Claim))
			}
			require.NotZero(t, fetch.asked.Load(), "the joiner asked its peers")
		})
	}
}

// A member that lagged behind the commit (online, but it never committed the handoff: once the others switched, nobody serves epoch 1's
// blocks) acquires the activation after its grace and switches in process instead of waiting for a restart.
func TestInProcessSwitchLaggardAcquiresTheActivation(t *testing.T) {
	fetch := &peerFetch{replicas: map[peer.ID]*q3Replica{}}
	const laggard = 1
	c := newQ3LiveWith(t, q3fixture.Options{}, func(i int, r *q3Replica) {
		r.noCheckpoint = i == laggard
		r.switchFor = acquiringSwitch(fetch)
		fetch.replicas[r.id()] = r
	})
	ctx := context.Background()
	for i, r := range c.replicas {
		require.NoError(t, r.rt.Recover(ctx))
		if i == joinerIndex { // the joiner installed first, as by its restart: this case is the laggard's
			require.NoError(t, r.rt.Activate(ctx, r.bundle()))
			r.close()
			r.mustOpen(true)
			require.NoError(t, r.rt.Recover(ctx))
		}
	}
	lag := c.replicas[laggard]
	require.NoError(t, lag.manager.safety.member(1), "the laggard is a member of epoch 1")
	start := time.Now()
	for i := range c.replicas {
		c.start(i)
	}
	awaitSuccessorCommit(t, c, start, LocalTimeout*time.Millisecond)
	s := lag.manager.SwitchState()
	require.Equal(t, SwitchRunning, s.Phase)
	require.EqualValues(t, 2, s.Target, "the laggard switched in process")
	took := time.Since(start)
	t.Logf("the laggard switched and committed a successor block %v after the start (grace %v)", took, laggardGrace)
	require.Greater(t, took, laggardGrace, "a member waits its grace for its own commit first")
}

// A root several epochs behind installs the lineage one epoch at a time, each a switch under the barrier: a joiner of epoch 3 that is at
// epoch 1 passes through epoch 2, which does not name it (Following(2): the same transition as a root that left earlier and re-enters),
// and ends Running(3). A peer whose bundle does not authenticate is not asked again, and the next peer's is installed.
func TestInProcessSwitchInstallsTheLineageSequentially(t *testing.T) {
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first, Weights: []uint64{1, 1, 6, 1}})
	forged := q3fixture.New(t, q3fixture.Options{Chain: first, SignedBy: 2})
	node := second.NewNodes[3]
	require.NotContains(t, first.NewNodes, node, "not a member of epoch 2")
	liar, honest := first.OldNodes[0].PeerConf.ID, first.OldNodes[1].PeerConf.ID
	var served sync.Map
	fetch := &peerFetch{serve: func(from peer.ID, epoch uint64) (q3active.Bundle, error) {
		served.Store(fmt.Sprintf("%s/%d", from, epoch), true)
		switch {
		case from == liar && epoch == 2:
			return secondBundle(forged), nil
		case epoch == 2:
			return q3active.Bundle{Envelope: first.EnvelopeBytes, Snapshot: first.Snapshot, Candidate: first.Candidate}, nil
		case epoch == 3:
			return secondBundle(second), nil
		}
		return q3active.Bundle{}, errors.New("no such epoch")
	}}
	r := newQ3Replica(t, first, node)
	r.noCheckpoint = true
	r.switchFor = acquiringSwitch(fetch)
	r.mustOpen(true)
	t.Cleanup(r.close)
	require.NoError(t, r.rt.Recover(context.Background()))
	m := r.manager
	// an authenticated root of epoch 1 sent this root a message of epoch 3 (loop-owned state, set before the loop runs)
	m.acq.note(3, 1, liar, time.Now())
	m.acq.note(3, 1, honest, time.Now())
	m.acq.senders = []peer.ID{liar, honest}
	_, done := runAlone(t, r)
	require.Eventually(t, func() bool { return m.SwitchState().Epoch == 3 }, 10*time.Second, 10*time.Millisecond)
	s := m.SwitchState()
	require.Equal(t, SwitchRunning, s.Phase, "a member of epoch 3")
	require.EqualValues(t, 3, m.InstalledRootEpoch())
	_, liarAsked := served.Load(fmt.Sprintf("%s/2", liar))
	require.True(t, liarAsked)
	for _, e := range []uint64{2, 3} {
		_, staged, err := r.rt.StagedBundleAt(context.Background(), e)
		require.NoError(t, err)
		require.True(t, staged, "epoch %d installed through the journal", e)
	}
	require.NoError(t, r.rt.Gate(context.Background(), second.Claim))
	// old-epoch work after the switch is refused
	require.ErrorIs(t, m.safety.Sign(2, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 2}}), ErrStaleContext)
	require.ErrorIs(t, m.safety.Sign(1, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 1}}), ErrStaleContext)
	select {
	case err := <-done:
		t.Fatalf("Run ended: %v", err)
	default:
	}
}

func TestJoiningLeaderUsesInstalledActivationForClosure(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, joinerIndex, func(r *q3Replica) { r.noCheckpoint = true })
	_, err := r.manager.ClosureWitness(ctx, 2)
	require.ErrorIs(t, err, ErrNoQ3Evidence)

	require.NoError(t, r.rt.Activate(ctx, r.bundle()))
	_, _, _, err = r.manager.Q3ActivationEvidence(2)
	require.ErrorIs(t, err, ErrNoQ3Evidence)

	want, err := handoffdelivery.EncodeWitnessV3(handoffdelivery.WitnessV3{
		Proof: f.Proof, Body: f.Body.Encode(), Snapshot: f.Snapshot, Candidate: f.Candidate,
	})
	require.NoError(t, err)
	got, err := r.manager.ClosureWitness(ctx, 2)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// A joiner without evidence: no peer serves the activation (or every one serves a forgery). It stays in its epoch, raises no barrier,
// stages nothing, and asks at a bounded, backed-off rate; the restart is its fallback.
func TestInProcessSwitchJoinerWithoutEvidenceStaysAndBacksOff(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	forged := q3fixture.New(t, q3fixture.Options{Chain: f, SignedBy: 2})
	for name, serve := range map[string]func(peer.ID, uint64) (q3active.Bundle, error){
		"nobody serves it": func(peer.ID, uint64) (q3active.Bundle, error) { return q3active.Bundle{}, errors.New("not found") },
		"forgeries only":   func(peer.ID, uint64) (q3active.Bundle, error) { return secondBundle(forged), nil },
	} {
		t.Run(name, func(t *testing.T) {
			fetch := &peerFetch{serve: serve}
			r := openAlone(t, f, joinerIndex, func(r *q3Replica) {
				r.noCheckpoint = true
				r.switchFor = acquiringSwitch(fetch)
			})
			m := r.manager
			m.acq.note(2, 1, f.OldNodes[0].PeerConf.ID, time.Now())
			_, done := runAlone(t, r)
			time.Sleep(2 * time.Second)
			require.Equal(t, SwitchState{Phase: SwitchRunning, Epoch: 1}, m.SwitchState())
			require.Nil(t, m.switchCtx.Load(), "no barrier was raised")
			_, staged, err := r.rt.StagedBundleAt(context.Background(), 2)
			require.NoError(t, err)
			require.False(t, staged, "nothing was staged")
			// 4 peers per round, rounds after 0, 250, 750, 1750 ms (doubling) at most; a forging peer is asked once per epoch
			asked := fetch.asked.Load()
			t.Logf("asked %d times in 2 s", asked)
			require.LessOrEqual(t, asked, int64(16))
			require.NotZero(t, asked)
			select {
			case err := <-done:
				t.Fatalf("Run ended: %v", err)
			default:
			}
		})
	}
}

// A failure after the barrier of an acquired switch is a failure like any other: signing stays fenced, Run ends, and the restart recovers
// the exact activation through the journal.
func TestInProcessSwitchAcquiredFailureFencesAndTheRestartRecovers(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	fetch := &peerFetch{serve: func(peer.ID, uint64) (q3active.Bundle, error) {
		return q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate}, nil
	}}
	r := openAlone(t, f, joinerIndex, func(r *q3Replica) {
		r.noCheckpoint = true
		r.switchFor = func(r *q3Replica) EpochSwitch {
			return &Q3EpochSwitch{Runtime: r.rt, Fetch: fetch.fetch, After: func(context.Context, uint64) error { return errors.New("injected") }}
		}
	})
	m := r.manager
	m.acq.note(2, 1, f.OldNodes[0].PeerConf.ID, time.Now())
	_, done := runAlone(t, r)
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end at the failed switch")
	}
	r.stopRun = nil
	require.Equal(t, SwitchFaulted, m.SwitchState().Phase)
	require.ErrorIs(t, m.safety.Sign(2, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 2}}), ErrSwitching)
	r.close()
	r.switchFor = acquiringSwitch(fetch)
	r.mustOpen(true)
	require.NoError(t, r.rt.Recover(context.Background()))
	require.EqualValues(t, 2, r.manager.InstalledRootEpoch(), "the journal completed the staged activation")
	require.NoError(t, r.rt.Gate(context.Background(), f.Claim))
}

// The trigger's bounds: only an authenticated sender that is a root of the installed committee and authored the message counts, a member
// of the installed epoch waits its grace, and a root that committed the handoff without its own evidence asks at once.
func TestInProcessSwitchAcquisitionTrigger(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	r := openAlone(t, f, 0, func(r *q3Replica) { r.noCheckpoint = true; r.switchFor = acquiringSwitch(&peerFetch{}) })
	m := r.manager
	now := time.Now()
	member, outsider := f.OldNodes[1].PeerConf.ID, f.NewNodes[joinerIndex].PeerConf.ID
	timeout := func(epoch uint64, author peer.ID) any {
		return &abdrc.TimeoutMsg{Timeout: &drctypes.Timeout{Epoch: epoch}, Author: author.String()}
	}
	m.noteAhead(timeout(2, member), messageOrigin{}, now)
	require.Zero(t, m.acq.ahead, "not authenticated by the transport")
	m.noteAhead(timeout(2, member), messageOrigin{from: outsider, size: 10, known: true}, now)
	require.Zero(t, m.acq.ahead, "a message its sender did not author")
	m.noteAhead(timeout(2, outsider), messageOrigin{from: outsider, size: 10, known: true}, now)
	require.Zero(t, m.acq.ahead, "a sender that is no root of the installed or staged committee")
	m.noteAhead(timeout(1, member), messageOrigin{from: member, size: 10, known: true}, now)
	require.Zero(t, m.acq.ahead, "the installed epoch is no sign")
	m.noteAhead(timeout(2, member), messageOrigin{from: member, size: 10, known: true}, now)
	require.EqualValues(t, 2, m.acq.ahead)
	require.Equal(t, []peer.ID{member}, m.acq.senders)

	due, _ := m.acquireWanted(1, now)
	require.False(t, due, "a member of the installed epoch waits for its own commit first")
	due, _ = m.acquireWanted(1, now.Add(laggardGrace))
	require.True(t, due, "then it acquires")
	due, _ = m.acquireWanted(1, now.Add(futureMessageTTL+time.Second))
	require.False(t, due, "a sign older than the parking lifetime is stale")
	m.acq.committed = 2
	due, poll := m.acquireWanted(1, now.Add(futureMessageTTL+time.Second))
	require.True(t, due, "a commit without own evidence is acquired at once")
	require.False(t, poll)
	require.Equal(t, member, m.acquirePeersFor(2)[0], "the sender is asked first")
	require.NotContains(t, m.acquirePeersFor(2), r.id(), "never this root")
	m.acq.refused = map[peer.ID]uint64{member: 2}
	require.NotContains(t, m.acquirePeersFor(2), member, "a peer whose bundle did not authenticate is not asked again for the epoch")
	require.Contains(t, m.acquirePeersFor(3), member)
}

// A leaver that stays reachable switches at its own commit into Following(2): it signs nothing of either epoch from then on, serves the
// activation from its journal, and the successor commits at round speed without it. A leaver that crashes at the commit costs the
// successor nothing either.
func TestInProcessSwitchLeaverFollowsInTheLiveCluster(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "reachable", true: "crashes right after its commit"}[crash], func(t *testing.T) {
			c := newQ3LiveWith(t, q3fixture.Options{}, func(i int, r *q3Replica) { r.switchFor = ownSwitch })
			leaver := newQ3Replica(t, c.f, c.f.OldNodes[3])
			leaver.link, leaver.durable = c.net.connect(leaver.id()), true
			leaver.switchFor = ownSwitch
			leaver.mustOpen(true)
			t.Cleanup(leaver.close)
			c.offline.Store(leaver.id(), struct{}{})
			members := c.replicas
			c.replicas = append(append([]*q3Replica(nil), members...), leaver)
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
			traffic := tapTraffic(c)
			start := time.Now()
			for i := range c.replicas {
				c.start(i)
			}
			if crash {
				c.stop(len(c.replicas) - 1)
			}
			require.Eventually(t, func() bool {
				for _, r := range members {
					if e, round := committedEpoch(r); e != 2 || round <= anchorSlot(r) {
						return false
					}
				}
				return true
			}, LocalTimeout*time.Millisecond, 10*time.Millisecond)
			took := time.Since(start)
			t.Logf("the successor committed %v after the start", took)
			require.Less(t, took, LocalTimeout*time.Millisecond/2)
			traffic.mu.Lock()
			require.Empty(t, traffic.timeouts[2], "no timeout vote of the successor epoch")
			for _, e := range traffic.byAuthor[leaver.id().String()] {
				require.NotEqualValues(t, 2, e, "the leaver signs nothing of the successor")
			}
			traffic.mu.Unlock()
			if crash {
				return
			}
			require.Eventually(t, func() bool { return leaver.manager.SwitchState().Phase == SwitchFollowing }, 5*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, leaver.manager.SwitchState().Epoch)
			_, staged, err := leaver.rt.StagedBundleAt(ctx, 2)
			require.NoError(t, err)
			require.True(t, staged, "the leaver serves the activation as a follower")
			require.ErrorIs(t, leaver.manager.safety.Sign(1, &abdrc.ProposalMsg{Block: &drctypes.BlockData{Epoch: 1}}), ErrStaleContext)
		})
	}
}

// An abort of the committed handoff after an in-process switch is refused as too late, as before the switch, on every root that switched:
// a stayer, a leaver (Following) and a joiner that acquired the activation from a peer. Their committed head is the successor's anchor and
// carries no control state any more; the verified activation in their history answers. A target that is not the committed record stays a
// mismatch, and a joiner that has not installed the activation does not answer for it.
func TestInProcessSwitchAbortAfterTheSwitchIsTooLate(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	fetch := &peerFetch{serve: func(peer.ID, uint64) (q3active.Bundle, error) {
		return q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate}, nil
	}}
	stayer := openAlone(t, f, 0, func(r *q3Replica) { r.switchFor = ownSwitch })
	leaver := newQ3Replica(t, f, f.OldNodes[3])
	leaver.switchFor = ownSwitch
	leaver.mustOpen(true)
	t.Cleanup(leaver.close)
	require.NoError(t, leaver.rt.Recover(context.Background()))
	joiner := openAlone(t, f, joinerIndex, func(r *q3Replica) { r.noCheckpoint = true; r.switchFor = acquiringSwitch(fetch) })

	_, ok := stayer.rt.Activated(2)
	require.False(t, ok, "not installed yet")
	committed, err := stayer.manager.HandoffAbortStatus(abortTargetOf(t, stayer))
	require.NoError(t, err)
	require.Equal(t, "too_late", committed.State, "before the switch: the committed head's control state")
	target := abortTargetOf(t, stayer)
	_, err = joiner.manager.HandoffAbortStatus(target)
	require.ErrorIs(t, err, ErrHandoffAbortTarget, "a joiner that holds neither the commit nor the activation does not answer for it")

	joiner.manager.acq.note(2, 1, f.OldNodes[0].PeerConf.ID, time.Now())
	for name, r := range map[string]*q3Replica{"stayer": stayer, "leaver": leaver, "joiner": joiner} {
		runAlone(t, r)
		require.Eventually(t, func() bool { return r.manager.SwitchState().Epoch == 2 }, 5*time.Second, 5*time.Millisecond, name)
		status, err := r.manager.HandoffAbortStatus(target)
		require.NoError(t, err, name)
		require.Equal(t, "too_late", status.State, name)
		require.Equal(t, committed.RecordID, status.RecordID, name)
		require.Equal(t, committed.OrderedRound, status.OrderedRound, name)
		_, err = r.manager.SubmitHandoffAbort(context.Background(), target)
		require.ErrorIs(t, err, ErrHandoffAbortTarget, "%s: nothing is signed; the operator reads too_late from the status", name)
		other := target
		other.Attempt++
		_, err = r.manager.HandoffAbortStatus(other)
		require.ErrorIs(t, err, ErrHandoffAbortTarget, "%s: another target is still a mismatch", name)
	}
}

// abortTargetOf is the abort target of the handoff the replica's committed head holds.
func abortTargetOf(t *testing.T, r *q3Replica) abdrc.HandoffAbortTarget {
	t.Helper()
	state, err := r.manager.blockStore().GetState()
	require.NoError(t, err)
	require.NotNil(t, state.CommittedHead.Control)
	record, err := storage.DecodeOrderedHandoffRecord(state.CommittedHead.Control.RecordBytes)
	require.NoError(t, err)
	return abdrc.HandoffAbortTarget{Network: record.Network, OldEpoch: record.Epoch, PredecessorBodyID: record.PredecessorBodyID,
		Attempt: record.Attempt, NextBodyID: record.NextBodyID}
}
