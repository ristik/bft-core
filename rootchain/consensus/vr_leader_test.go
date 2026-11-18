package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The manager's VR leader paths (review #1188 test gaps): orderHandoffViewWith, vrRecordsForRound with its intent-at-parent, time-gate,
// rejection and witness branches, the witness and output prefetch, and the stage pull of a (re)started root.

type vrWorld struct {
	*vrhandofffix.Fixture
	in  vrhandoff.Intent
	d   [32]byte
	ids []string
}

func newVRWorld(t *testing.T) *vrWorld {
	f := vrhandofffix.New(t)
	in, d := f.Intent()
	_, ids := f.Incumbents()
	return &vrWorld{Fixture: f, in: in, d: d, ids: ids}
}

func (w *vrWorld) committed(view uint64) vrschedule.Committed {
	keys, _ := w.Incumbents()
	return vrschedule.Committed{Derived: vrschedule.Derived{VRIntent: storage.VRIntent{Digest: w.d, AnchorRound: w.in.AnchorRound}, Intent: w.in,
		RootEpoch: w.RC.RootEpoch, Body: w.BC}, Derivable: true, CommittedView: view, Incumbents: keys, K: w.K}
}

// messages are every message of a complete view.
func (w *vrWorld) messages(view uint64) []vrschedule.Message {
	pops := w.PoPs(w.in)
	a := w.Assembly(w.in, w.d, view, pops)
	body, err := vrhandoff.DeriveBody(w.in, w.RC.RootEpoch, sha256.Sum256(a.Candidate), w.BC)
	require.NoError(w.T, err)
	_, tb, err := vrhandoff.TrustBase(w.in, w.RC.RootEpoch)
	require.NoError(w.T, err)
	var out []vrschedule.Message
	for i := range pops {
		out = append(out, vrschedule.Message{PoP: &pops[i]})
	}
	out = append(out, vrschedule.Message{Assembly: &a})
	for _, m := range w.J {
		r, err := vrhandoff.SignReadiness(w.in, a, body, m.RootNodeID, tb, nil, w.ByStaking(m.StakingID).RK.Signer)
		require.NoError(w.T, err)
		out = append(out, vrschedule.Message{Readiness: &r})
	}
	return out
}

// planned is a service whose intent holds a complete verified certificate of view 0.
func (w *vrWorld) planned() *vrschedule.Service {
	s := vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})
	s.Update(w.committed(0))
	for _, m := range w.messages(0) {
		_, _, _ = s.Offer("peer", m)
	}
	_, ok := s.Plan()
	require.True(w.T, ok)
	return s
}

func vrManager(v *vrHandoff) *ConsensusManager {
	if v.cfg.Log == nil {
		v.cfg.Log = slog.New(slog.DiscardHandler)
	}
	if v.cfg.Intents == nil {
		v.cfg.Intents = &vrschedule.Intents{}
	}
	return &ConsensusManager{vr: v, log: slog.New(slog.DiscardHandler), params: &Parameters{HashAlgorithm: crypto.SHA256}}
}

func idleParent(epoch uint64) *storage.ExecutedBlock {
	return &storage.ExecutedBlock{BlockData: &rctypes.BlockData{Round: 9}, ShardState: storage.ShardStates{Control: &evmroot.ControlState{Epoch: epoch, Phase: "idle"}}}
}

func TestVRRecordsForRoundOrdersThePrepareOnlyWhenItsChecksHold(t *testing.T) {
	w := newVRWorld(t)
	svc := w.planned()
	plan, _ := svc.Plan()
	derived := vrschedule.Derived{VRIntent: storage.VRIntent{Digest: plan.Intent}}
	var schedule []vrschema.Activation
	rejecting := false
	v := &vrHandoff{svc: svc,
		leader: func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
			return vrschedule.LeaderStep{Kind: "prepare", Records: [][]byte{{1}}}, nil
		},
		queryAt: func(*storage.ExecutedBlock) (storage.VRIntentQuery, bool, error) {
			return storage.VRIntentQuery{Root: func() (storage.VRRootFacts, error) {
				return storage.VRRootFacts{Fold: vrschema.FoldInput{Schedule: schedule}}, nil
			}}, true, nil
		},
		derive: func(storage.VRIntentQuery) (vrschedule.Derived, bool, error) { return derived, true, nil },
		reject: func(context.Context, uint64, uint64, *rctypes.QuorumCert) bool { return rejecting },
	}
	x := vrManager(v)
	parent := idleParent(plan.Epoch)
	qc := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 9}}

	recs, err := x.vrRecordsForRound(10, parent, qc)
	require.NoError(t, err)
	require.Len(t, recs, 1, "every check holds: the Prepare is ordered")

	derived.Digest = [32]byte{0xdd}
	recs, _ = x.vrRecordsForRound(10, parent, qc)
	require.Empty(t, recs, "the planned intent is not the one derivable at this parent")
	derived.Digest = plan.Intent
	v.derive = func(storage.VRIntentQuery) (vrschedule.Derived, bool, error) {
		return vrschedule.Derived{}, false, vrschedule.ErrUnavailable
	}
	recs, _ = x.vrRecordsForRound(10, parent, qc)
	require.Empty(t, recs, "an uncached output at the parent: not this round")
	v.derive = func(storage.VRIntentQuery) (vrschedule.Derived, bool, error) { return derived, true, nil }

	schedule = []vrschema.Activation{{RuleID: vrschema.Word{1}, RootEpoch: plan.Epoch, NotBeforeUcTime: ^uint64(0) >> 1, State: vrschema.ActActive, ChangeID: 1}}
	recs, _ = x.vrRecordsForRound(10, parent, qc)
	require.Empty(t, recs, "the activation time gate does not hold yet")
	schedule = nil

	rejecting = true
	recs, _ = x.vrRecordsForRound(10, parent, qc)
	require.Empty(t, recs, "a due rejection comes first")
	rejecting = false

	v.leader = func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error) {
		return vrschedule.LeaderStep{Reason: vrschedule.ReasonOtherBody}, nil
	}
	recs, _ = x.vrRecordsForRound(10, parent, qc)
	require.Empty(t, recs)
}

// The Freeze's witness is read from the cache only: a miss orders nothing this round and fetches it once in the background; the next round
// orders the Freeze from the cache.
func TestVRRecordsForRoundReadsTheWitnessFromTheCache(t *testing.T) {
	w := newVRWorld(t)
	svc := w.planned()
	plan, _ := svc.Plan()
	var mu sync.Mutex
	fetches := 0
	v := &vrHandoff{svc: svc, cfg: VRHandoffConfig{Witness: func(context.Context, [32]byte, [32]byte, vrschema.Word) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		return []byte("witness"), nil
	}}}
	v.leader = func(_ vrschedule.PreparePlan, _ *storage.ExecutedBlock, _ uint64, _ types.PartitionShardID, witness func(p, root [32]byte) ([]byte, error), _ crypto.Hash) (vrschedule.LeaderStep, error) {
		wt, err := witness([32]byte{1}, [32]byte{2})
		if err != nil {
			return vrschedule.LeaderStep{}, err
		}
		return vrschedule.LeaderStep{Kind: "freeze", Records: [][]byte{wt}}, nil
	}
	x := vrManager(v)
	parent := idleParent(plan.Epoch)
	parent.ShardState.Control.Phase = "prepared"
	recs, _ := x.vrRecordsForRound(10, parent, nil)
	require.Empty(t, recs, "a cache miss orders nothing")
	require.Eventually(t, func() bool {
		recs, _ = x.vrRecordsForRound(11, parent, nil)
		return len(recs) == 1
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []byte("witness"), recs[0])
	mu.Lock()
	require.Equal(t, 1, fetches, "fetched once")
	mu.Unlock()
}

func TestOrderHandoffViewWith(t *testing.T) {
	w := newVRWorld(t)
	intent := w.d
	now := time.Now()
	idle := vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})
	idle.Update(w.committed(0))
	o := opening(intent, 1, 30, 20, true)
	v := &vrHandoff{svc: idle, opening: func() (storage.VROpening, bool, error) { return o, true, nil }}
	x := vrManager(v)
	x.residence = &vrResidence{base: now, clock: func() time.Time { return now }}
	trialErr := error(nil)
	trials := 0
	trial := func(*rctypes.BlockData) error { trials++; return trialErr }
	block := func() *rctypes.BlockData {
		return &rctypes.BlockData{Epoch: 1, Round: 40, Payload: &rctypes.Payload{}}
	}
	views := func(b *rctypes.BlockData) []uint64 {
		var out []uint64
		for _, c := range b.Payload.PosControls {
			if c.Op == rctypes.OpHandoffView {
				out = append(out, c.View.View)
			}
		}
		return out
	}

	b := block()
	x.orderHandoffViewWith(context.Background(), b, trial)
	require.Empty(t, views(b), "the residence wait from the first held opening has not passed")
	require.Zero(t, trials)
	wait, ok := vradmit.ResidenceWaitMillis(0, 1, 4)
	require.True(t, ok)
	now = now.Add(time.Duration(wait) * time.Millisecond)

	b = block()
	x.orderHandoffViewWith(context.Background(), b, trial)
	require.Equal(t, []uint64{2}, views(b), "the next view, after the trial execution admits it")

	trialErr = errors.New("not due at this parent")
	b = block()
	x.orderHandoffViewWith(context.Background(), b, trial)
	require.Empty(t, views(b), "a refused trial orders nothing")
	trialErr = nil

	b = block()
	b.Payload.PosControls = make([]rctypes.PosControl, rctypes.MaxPosControls)
	x.orderHandoffViewWith(context.Background(), b, trial)
	require.Len(t, b.Payload.PosControls, rctypes.MaxPosControls, "no room for another control")

	b = block()
	b.Payload.HandoffRecords = [][]byte{{1}}
	x.orderHandoffViewWith(context.Background(), b, trial)
	require.Empty(t, views(b), "a handoff record is ordered")

	for _, set := range []func(*storage.VROpening){
		func(o *storage.VROpening) { o.State.Backoff.Prepared = true },
		func(o *storage.VROpening) { o.State.Backoff.Settled = true },
	} {
		o = opening(intent, 1, 30, 20, true)
		set(&o)
		b = block()
		x.orderHandoffViewWith(context.Background(), b, trial)
		require.Empty(t, views(b), "a prepared or settled attempt takes no view")
	}
	o = opening(intent, 1, 30, 20, true)

	v.svc = w.planned()
	b = block()
	x.orderHandoffViewWith(context.Background(), b, trial)
	require.Empty(t, views(b), "a complete verified certificate: the Prepare comes first")
}

// An executed block's certified EVM state is prefetched into the output cache, once.
func TestVROutputsArePrefetchedAtExecution(t *testing.T) {
	evm := types.PartitionShardID{PartitionID: 8, ShardID: types.ShardID{}.Key()}
	r := vrschema.Word{0x52}
	out := &vrhandoff.Output{State: vradmit.OutputState{ResultID: r}}
	reads := make(chan [32]byte, 4)
	outputs := vrschedule.NewOutputs()
	v := &vrHandoff{cfg: VRHandoffConfig{EVM: evm, Intents: &vrschedule.Intents{Outputs: outputs}, Reader: readerFunc(func(root [32]byte) (*vrhandoff.Output, error) {
		reads <- root
		return out, nil
	})}, prefetch: make(chan vrschedule.CertifiedEVM, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.prefetchRun(ctx)
	root := [32]byte{7}
	b := &storage.ExecutedBlock{BlockData: &rctypes.BlockData{Round: 5}, ShardState: storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{
		evm: {IR: &types.InputRecord{BlockHash: make([]byte, 32), Hash: root[:]}}}}}
	v.onExecuted(b)
	require.Eventually(t, func() bool { _, ok := outputs.At(root); return ok }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, root, <-reads)
	v.onExecuted(b)
	select {
	case <-reads:
		t.Fatal("a cached state is not read again")
	case <-time.After(100 * time.Millisecond):
	}
}

func newPipe() (pipeStream, pipeStream) { a, b := net.Pipe(); return pipeStream{a}, pipeStream{b} }

type readerFunc func(root [32]byte) (*vrhandoff.Output, error)

func (f readerFunc) OpenOutput(_ context.Context, _, root [32]byte) (*vrhandoff.Output, error) {
	return f(root)
}

// stageOpener serves GetStage from a set of services by peer, failing for the peers it has none of.
type stageOpener struct {
	mu    sync.Mutex
	peers map[peer.ID]*vrschedule.Service
	asked []peer.ID
}

func (o *stageOpener) CreateStream(_ context.Context, to peer.ID, _ string) (vrschedule.Stream, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.asked = append(o.asked, to)
	s, ok := o.peers[to]
	if !ok {
		return nil, errors.New("unreachable")
	}
	a, b := newPipe()
	srv := vrschedule.NewServer(s, vrschedule.NewQueue(s, 0), func(peer.ID) bool { return true })
	go srv.Serve("self", b)
	return a, nil
}

// A (re)started root rebuilds its view state from its peers: a pull no peer answers does not count, the next one does, and a root whose
// intent holds no complete certificate pulls one peer at a time every PullInterval.
func TestVRStagePullRebuildsARestartedRoot(t *testing.T) {
	w := newVRWorld(t)
	holder := w.planned()
	p1, p2 := peer.ID("peer-1"), peer.ID("peer-2")
	opener := &stageOpener{peers: map[peer.ID]*vrschedule.Service{}}
	restarted := vrschedule.NewService(vrschedule.ServiceConfig{Self: "y"})
	restarted.Update(w.committed(0))
	now := time.Now()
	var mu sync.Mutex
	v := &vrHandoff{svc: restarted, cfg: VRHandoffConfig{Opener: opener, Log: slog.New(slog.DiscardHandler)}, peers: func() []peer.ID { return []peer.ID{p1, p2} },
		now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	idleWait := func() {
		require.Eventually(t, func() bool { v.pmu.Lock(); defer v.pmu.Unlock(); return !v.pulling }, 5*time.Second, 5*time.Millisecond)
	}
	v.pull(context.Background())
	idleWait()
	require.False(t, v.restored, "no peer answered: not rebuilt")
	opener.mu.Lock()
	opener.peers[p2] = holder
	opener.mu.Unlock()
	v.pull(context.Background())
	idleWait()
	require.True(t, v.restored)
	_, _, complete, _ := restarted.Current()
	require.True(t, complete, "the peer's stage set rebuilt the certificate")

	// an incomplete root pulls one peer per PullInterval
	lagging := vrschedule.NewService(vrschedule.ServiceConfig{Self: "z"})
	lagging.Update(w.committed(0))
	opener.mu.Lock()
	opener.asked = nil
	opener.mu.Unlock()
	v2 := &vrHandoff{svc: lagging, cfg: VRHandoffConfig{Opener: opener, Log: slog.New(slog.DiscardHandler)}, peers: v.peers, now: v.now, restored: true}
	v2.pull(context.Background())
	require.Eventually(t, func() bool { v2.pmu.Lock(); defer v2.pmu.Unlock(); return !v2.pulling }, 5*time.Second, 5*time.Millisecond)
	v2.pull(context.Background())
	opener.mu.Lock()
	require.Len(t, opener.asked, 1, "one peer per interval")
	opener.mu.Unlock()
	mu.Lock()
	now = now.Add(PullInterval)
	mu.Unlock()
	v2.pull(context.Background())
	require.Eventually(t, func() bool {
		_, _, complete, _ := lagging.Current()
		return complete
	}, 5*time.Second, 5*time.Millisecond, "the second peer's set completes the view")
}

// wireStageSet is the stage set's wire form (vrschedule's GetStage answer).
type wireStageSet struct {
	_          struct{} `cbor:",toarray"`
	PoPs       []vrhandoff.PoPOffer
	Assemblies []vrhandoff.Assembly
	Readiness  []vrhandoff.Readiness
}

// cannedStream answers any request with one fixed frame.
type cannedStream struct {
	r io.Reader
}

func (s *cannedStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *cannedStream) Write(p []byte) (int, error) { return len(p), nil }
func (*cannedStream) SetDeadline(time.Time) error   { return nil }
func (*cannedStream) CloseWrite() error             { return nil }
func (*cannedStream) Close() error                  { return nil }
func (*cannedStream) Reset() error                  { return nil }

type cannedOpener map[peer.ID][]byte

func (o cannedOpener) CreateStream(_ context.Context, to peer.ID, _ string) (vrschedule.Stream, error) {
	frame, ok := o[to]
	if !ok {
		return nil, errors.New("unreachable")
	}
	return &cannedStream{r: bytes.NewReader(frame)}, nil
}

func stageFrame(t *testing.T, set wireStageSet) []byte {
	b, err := types.Cbor.Marshal(set)
	require.NoError(t, err)
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(len(b)))
	return append(p[:], b...)
}

// A Byzantine peer's pulled stage set (review #1188 r2): a set that opens with a refused message is abandoned there, nothing after it is
// judged; a set of 10,000 copies of valid proofs costs nothing beyond duplicates; an honest peer's set then completes the view.
func TestVRAByzantinePulledSet(t *testing.T) {
	w := newVRWorld(t)
	pops := w.PoPs(w.in)
	bad := pops[0]
	bad.PoP.Signature = append([]byte(nil), bad.PoP.Signature...)
	bad.PoP.Signature[3] ^= 1
	var dup []vrhandoff.PoPOffer
	for i := 0; i < 10_000; i++ {
		dup = append(dup, pops[i%len(pops)])
	}
	holder := w.planned()
	honest, _ := holder.Stage(w.d, 0)
	byzA, byzB, good := peer.ID("byz-a"), peer.ID("byz-b"), peer.ID("honest")
	opener := cannedOpener{
		byzA: stageFrame(t, wireStageSet{PoPs: append([]vrhandoff.PoPOffer{bad}, pops[1:]...)}),
		byzB: stageFrame(t, wireStageSet{PoPs: dup}),
		good: stageFrame(t, wireStageSet{PoPs: honest.PoPs, Assemblies: honest.Assemblies, Readiness: honest.Readiness}),
	}
	s := vrschedule.NewService(vrschedule.ServiceConfig{Self: "y"})
	s.Update(w.committed(0))
	v := &vrHandoff{svc: s, cfg: VRHandoffConfig{Opener: opener, Log: slog.New(slog.DiscardHandler)}}

	require.True(t, v.pullFrom(context.Background(), []peer.ID{byzA}, w.d, 0))
	set, _ := s.Stage(w.d, 0)
	require.Empty(t, set.PoPs, "abandoned at the refused first message: nothing after it was judged")

	start := time.Now()
	require.True(t, v.pullFrom(context.Background(), []peer.ID{byzB}, w.d, 0))
	set, _ = s.Stage(w.d, 0)
	require.Len(t, set.PoPs, len(pops), "each proof once; the copies are duplicates")
	t.Logf("10,000 pulled copies judged in %s", time.Since(start))

	require.True(t, v.pullFrom(context.Background(), []peer.ID{good}, w.d, 0))
	_, _, complete, _ := s.Current()
	require.True(t, complete, "the honest peer's set completes the view")
}

type trustBaseMap map[uint64]*types.RootTrustBaseV1

func (m trustBaseMap) GetByEpoch(e uint64) (*types.RootTrustBaseV1, error) {
	if tb, ok := m[e]; ok {
		return tb, nil
	}
	return nil, errors.New("no trust base of that epoch")
}

// astra's review of #1188, r5: the membership a committed state names is the committee of that state's epoch with its root facts; a
// committee of another epoch or missing facts publish nothing (the service keeps its last good membership).
func TestVRMembershipIsOfTheStatesEpochWithItsFacts(t *testing.T) {
	tb := func(epoch uint64, ids ...string) *types.RootTrustBaseV1 {
		out := &types.RootTrustBaseV1{Epoch: epoch}
		for _, id := range ids {
			out.RootNodes = append(out.RootNodes, &types.NodeInfo{NodeID: id, SigKey: []byte{1}})
		}
		return out
	}
	k := []evmassign.Identity{{RootNodeID: "k1"}}
	facts := func() (storage.VRRootFacts, error) {
		return storage.VRRootFacts{Lifecycle: evmassign.LifecycleContext{Incumbent: k}}, nil
	}
	q := storage.VRIntentQuery{Epoch: 3, Root: facts}

	inc, f, err := vrMembership(q, tb(4, "live"), trustBaseMap{3: tb(3, "e3a", "e3b")})
	require.NoError(t, err)
	require.Len(t, inc, 2, "the stored committee of the state's epoch, not the live one")
	require.Contains(t, inc, "e3a")
	require.Equal(t, k, f.Lifecycle.Incumbent)

	inc, _, err = vrMembership(q, tb(3, "live3"), trustBaseMap{})
	require.NoError(t, err)
	require.Contains(t, inc, "live3", "the live trust base only when it is of the state's epoch")

	_, _, err = vrMembership(q, tb(4, "live4"), trustBaseMap{})
	require.ErrorIs(t, err, ErrVRHandoff, "another epoch's committee is never used")
	_, _, err = vrMembership(q, tb(4, "live4"), nil)
	require.ErrorIs(t, err, ErrVRHandoff)

	q.Root = nil
	_, _, err = vrMembership(q, tb(3, "live3"), nil)
	require.ErrorIs(t, err, ErrVRHandoff, "no facts: no membership")
	q.Root = func() (storage.VRRootFacts, error) { return storage.VRRootFacts{}, errors.New("authority unavailable") }
	_, _, err = vrMembership(q, tb(3, "live3"), nil)
	require.ErrorIs(t, err, ErrVRHandoff, "a facts error is not an empty K")
}

// A refresh whose committed membership is not available keeps the service's last good membership.
func TestVRRefreshKeepsTheLastGoodMembership(t *testing.T) {
	w := newVRWorld(t)
	svc := vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})
	_, known := svc.Membership()
	require.False(t, known, "no committed membership before the first refresh")
	good := w.committed(0)
	fail := false
	v := &vrHandoff{svc: svc, cfg: VRHandoffConfig{Log: slog.New(slog.DiscardHandler)}, update: func() (vrschedule.Committed, error) {
		if fail {
			return vrschedule.Committed{}, ErrVRHandoff
		}
		return good, nil
	}}
	v.refresh(context.Background())
	before, known := svc.Membership()
	require.True(t, known)
	require.NotEmpty(t, before)
	fail = true
	v.refresh(context.Background())
	after, _ := svc.Membership()
	require.Equal(t, before, after, "kept")
}
