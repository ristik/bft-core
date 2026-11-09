package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// #976 part 2: the REAL shard driver (the production shardnode.Node: BFTClient, round driver, net disseminator; a deterministic fake executor that keeps its
// pending work until a block carrying it is committed, as a mempool does) for the fixture's EVM validators, on the same libp2p transport as the roots. The
// roots' ingress is the drop and observation point: requests the shards send are dropped there on purpose, so no root holds them. Nothing here replaces
// a request the shard built: every request the roots accept is one a validator signed and sent.

// managerTrust serves the trust bases the shard's certificates name: the live epoch of the manager, and the fixture's earlier one (the genesis certificate of
// the shard is from it).
// liveShardEpoch is the shard epoch the fixture's live certificates name.
const liveShardEpoch = 1

type managerTrust struct {
	m   *ConsensusManager
	old *types.RootTrustBaseV1
}

func (s managerTrust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if tb := s.m.trustBase.Load(); tb.Epoch == epoch {
		return tb, nil
	}
	if s.old != nil && s.old.Epoch == epoch {
		return s.old, nil
	}
	return nil, fmt.Errorf("trust base epoch %d unavailable", epoch)
}

// retainingExecutor is the fake executor with a pool of pending entries: every Build takes them again, and they leave only when a Commit moves the head (a
// block carrying them is final). The plain fake forgets entries once built, which would lose the work together with an attempt the roots did not certify.
type retainingExecutor struct {
	*executortest.Fake
	mu      sync.Mutex
	pending [][]byte
}

func (e *retainingExecutor) add(entries ...[]byte) {
	e.mu.Lock()
	e.pending = append(e.pending, entries...)
	e.mu.Unlock()
}

func (e *retainingExecutor) poolSize() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pending)
}

func (e *retainingExecutor) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	e.mu.Lock()
	entries := slices.Clone(e.pending)
	e.mu.Unlock()
	e.Fake.AddEntries(entries...)
	return e.Fake.Build(ctx, p)
}

func (e *retainingExecutor) Commit(ctx context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	before, _ := e.Fake.Head(ctx)
	st, err := e.Fake.Commit(ctx, hash)
	if after, herr := e.Fake.Head(ctx); herr == nil && after.Number > before.Number {
		e.mu.Lock()
		e.pending = nil
		e.mu.Unlock()
	}
	return st, err
}

type requestEvent struct {
	at        time.Time
	root      string
	node      string
	round     uint64
	blockHash []byte
	fp        [32]byte // of the signed bytes: a byte-identical re-send has the same
	dropped   bool
}

// lossyNet is the partition network a root node is given: it forwards what arrives, except the requests the world decides to drop.
type lossyNet struct {
	*network.LibP2PNetwork
	name string
	out  chan any
	w    *shardWorld
}

func (n *lossyNet) ReceivedChannel() <-chan any { return n.out }

func (n *lossyNet) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-n.LibP2PNetwork.ReceivedChannel():
			if hs, ok := m.(*handshake.Handshake); ok && hs.PartitionID == q3fixture.PartitionID {
				n.w.noteHandshake(n.name, hs.NodeID)
			}
			if req, ok := m.(*certification.BlockCertificationRequest); ok && n.w.judge(n.name, req) {
				continue
			}
			select {
			case n.out <- m:
			case <-ctx.Done():
				return
			}
		}
	}
}

type certSample struct {
	at     time.Time
	seal   uint64
	ir     *types.InputRecord
	leader string
}

type handshakeEvent struct {
	at   time.Time
	root string
	node string
}

type proposalSample struct {
	at    time.Time
	round uint64
}

type shardWorld struct {
	t         *testing.T
	c         *q4bLive
	transport *liveTransport
	shards    map[string]*realShard
	ids       []string
	h         *ConsensusManager // the watched root's manager

	mu        sync.Mutex
	dropFn    func(*certification.BlockCertificationRequest) bool
	events    []requestEvent
	certs     []certSample
	t2Props   []proposalSample
	hands     []handshakeEvent
	sight     map[string]map[uint64]time.Time // per root: when it first showed each certificate of the shard
	cancelAll context.CancelFunc
}

func (w *shardWorld) judge(root string, req *certification.BlockCertificationRequest) bool {
	raw, _ := types.Cbor.Marshal(req)
	ev := requestEvent{at: time.Now(), root: root, node: req.NodeID, fp: sha256.Sum256(raw)}
	if req.InputRecord != nil {
		ev.round, ev.blockHash = req.InputRecord.RoundNumber, bytes.Clone(req.InputRecord.BlockHash)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dropFn != nil && w.dropFn(req) {
		ev.dropped = true
	}
	w.events = append(w.events, ev)
	return ev.dropped
}

func (w *shardWorld) noteHandshake(root, node string) {
	w.mu.Lock()
	w.hands = append(w.hands, handshakeEvent{at: time.Now(), root: root, node: node})
	w.mu.Unlock()
}

func (w *shardWorld) handshakesSince(from time.Time) (out []handshakeEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, h := range w.hands {
		if !h.at.Before(from) {
			out = append(out, h)
		}
	}
	return out
}

func (w *shardWorld) setDrop(f func(*certification.BlockCertificationRequest) bool) {
	w.mu.Lock()
	w.dropFn = f
	w.mu.Unlock()
}

func (w *shardWorld) requestsSince(from time.Time) (out []requestEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.events {
		if !e.at.Before(from) {
			out = append(out, e)
		}
	}
	return out
}

func (w *shardWorld) lastCert() certSample {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.certs) == 0 {
		return certSample{}
	}
	return w.certs[len(w.certs)-1]
}

func (w *shardWorld) certCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.certs)
}

func (w *shardWorld) certsSince(seal uint64) (out []certSample) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.certs {
		if s.seal > seal {
			out = append(out, s)
		}
	}
	return out
}

func (w *shardWorld) firstT2Proposal(after time.Time) (proposalSample, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range w.t2Props {
		if !p.at.Before(after) {
			return p, true
		}
	}
	return proposalSample{}, false
}

type shardWorldConfig struct {
	names      []string
	options    q3fixture.Options
	timeout    time.Duration
	blockRate  time.Duration
	shardOpts  shardnode.BFTClientOptions
	silent     map[string]bool // shard validators that are not started (by index in id order)
	silentLast int             // how many of the validators, from the end of the id order, are not started
}

func newShardWorld(t *testing.T, cfg shardWorldConfig) *shardWorld {
	t.Helper()
	w := &shardWorld{t: t}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancelAll = cancel
	t.Cleanup(cancel)
	w.transport = newLiveTransport(t)
	w.transport.wrap = func(name string, n *network.LibP2PNetwork) RootPartitionNet {
		l := &lossyNet{LibP2PNetwork: n, name: name, out: make(chan any, 1024), w: w}
		go l.run(ctx)
		return l
	}
	w.transport.tap = func(msg any) {
		pm, ok := msg.(*abdrc.ProposalMsg)
		if !ok || pm.Block == nil || pm.Block.Payload == nil {
			return
		}
		for _, r := range pm.Block.Payload.Requests {
			if r.Partition == q3fixture.PartitionID && r.CertReason == drctypes.T2Timeout {
				w.mu.Lock()
				w.t2Props = append(w.t2Props, proposalSample{at: time.Now(), round: pm.Block.Round})
				w.mu.Unlock()
			}
		}
	}
	w.c = newEqualLiveRate(t, cfg.timeout, cfg.blockRate, cfg.options, w.transport.install, cfg.names...)
	w.h = w.c.nodes[w.c.idx(cfg.names[0])].r.manager
	w.transport.up(w.c, w.c.all()...)
	w.c.start(w.c.all()...)
	w.c.warm(8, w.c.all()...)
	// the shards are built on the LIVE shard configuration (the assignment changes its hash after the first live round), then introduced to the roots
	w.shards = addRealShards(t, w.transport, w.c, cfg.shardOpts)
	for id := range w.shards {
		w.ids = append(w.ids, id)
	}
	slices.Sort(w.ids)
	w.transport.introduceShards()
	if si := w.h.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{}); si != nil && si.LastCR != nil {
		require.EqualValues(t, liveShardEpoch, si.LastCR.Technical.Epoch, "the live certificates name the shard epoch the shards have a configuration for")
	}
	// sample the shard's certificate at the watched root
	// the earliest sighting of each new certificate of the shard at ANY root (the shards get it from whichever root sends it first)
	sampled := make(chan struct{})
	t.Cleanup(func() { cancel(); <-sampled }) // registered after the cluster's own cleanup, so it runs before it: the sampler never reads a closed manager
	go func() {
		defer close(sampled)
		var last uint64
		for ctx.Err() == nil {
			for _, n := range w.c.nodes {
				if s := shardCertOf(n.r.manager); s != nil {
					w.mu.Lock()
					if w.sight == nil {
						w.sight = map[string]map[uint64]time.Time{}
					}
					if w.sight[n.name] == nil {
						w.sight[n.name] = map[uint64]time.Time{}
					}
					if _, seen := w.sight[n.name][s.seal]; !seen {
						w.sight[n.name][s.seal] = time.Now()
					}
					w.mu.Unlock()
				}
				if s := shardCertOf(n.r.manager); s != nil && s.seal > last {
					last = s.seal
					w.mu.Lock()
					w.certs = append(w.certs, certSample{at: time.Now(), seal: s.seal, ir: s.ir, leader: s.leader})
					w.mu.Unlock()
				}
			}
			time.Sleep(3 * time.Millisecond)
		}
	}()
	for i, id := range w.ids {
		if i >= len(w.ids)-cfg.silentLast {
			t.Logf("shard validator %s is NOT started (the paused-leader variant)", id[len(id)-6:])
			continue
		}
		w.shards[id].start()
	}
	t.Cleanup(func() {
		for _, s := range w.shards {
			if s.cancel != nil {
				s.cancel()
				select {
				case <-s.done:
				case <-time.After(10 * time.Second):
				}
			}
		}
	})
	return w
}

func (w *shardWorld) executors() (out []*retainingExecutor) {
	for _, id := range w.ids {
		out = append(out, w.shards[id].exec)
	}
	return out
}

// addPending queues the same entry at every validator, as every validator's mempool would hold a transaction it was sent.
func (w *shardWorld) addPending(entry []byte) {
	for _, e := range w.executors() {
		e.add(entry)
	}
}

type realShard struct {
	t      *testing.T
	id     string
	node   *shardnode.Node
	exec   *retainingExecutor
	cancel context.CancelFunc
	done   chan error
}

func (s *realShard) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done = cancel, make(chan error, 1)
	go func() {
		err := s.node.Run(ctx)
		if ctx.Err() == nil {
			s.t.Logf("shard %s: Run returned: %v", shortID(s.id), err)
		}
		s.done <- err
	}()
}

type testLogWriter struct {
	t      *testing.T
	prefix string
	mu     sync.Mutex
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "level=ERROR") || strings.Contains(line, "level=WARN") || os.Getenv("SHARD_LOG_ALL") != "" {
		w.t.Logf("shard %s: %s", w.prefix, line)
	}
	return len(p), nil
}

// addRealShards is liveTransport.addShards with a production shard node behind each validator's shard network instead of a receipt goroutine.
func addRealShards(t *testing.T, x *liveTransport, c *q4bLive, opts shardnode.BFTClientOptions) map[string]*realShard {
	t.Helper()
	f := c.nodes[0].r.f
	m := c.nodes[0].r.manager
	si := m.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	require.NotNil(t, si)
	luc := si.LastCR.UC
	genesis := shardnode.BlockRef{Number: 0, Hash: shardnode.Hash(luc.InputRecord.BlockHash), StateRoot: shardnode.Hash(luc.InputRecord.Hash)}
	// The fixture runs with an assignment (Options.Assignment, newEqualLiveRate): its live certificates name shard epoch liveShardEpoch, whose configuration is the
	// shard's only one. newShardWorld asserts the live certificates really name it.
	opts.InstalledShardConfs = map[uint64][]byte{liveShardEpoch: bytes.Clone(si.ShardConfHash)}
	ids := make([]string, 0, len(f.ShardNodes))
	for id := range f.ShardNodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	peers := make([]peer.ID, 0, len(ids))
	hosts := map[string]*shardHost{}
	for _, id := range ids {
		p := x.newPeer(f.ShardNodes[id].PeerConf)
		t.Cleanup(func() { _ = p.Close() })
		n, err := network.NewShardNetwork(p, x.obs, network.DefaultShardNetworkOptions)
		require.NoError(t, err)
		h := &shardHost{peer: p, net: n}
		x.shards[id] = h
		hosts[id] = h
		peers = append(peers, p.ID())
	}
	out := map[string]*realShard{}
	for _, id := range ids {
		h := hosts[id]
		diss, err := shardnode.NewNetDisseminator(h.peer, x.obs, peers)
		require.NoError(t, err)
		exec := &retainingExecutor{Fake: executortest.NewAt(genesis)}
		node, err := shardnode.New(h.peer, h.net, f.EVMSigners[id], q3fixture.PartitionID, types.ShardID{}, si.ShardConfHash, managerTrust{m: m, old: f.Old}, exec, diss, nil,
			slog.New(slog.NewTextHandler(&testLogWriter{t: t, prefix: id[len(id)-6:]}, &slog.HandlerOptions{Level: slog.LevelInfo})), opts)
		require.NoError(t, err)
		out[id] = &realShard{t: t, id: id, node: node, exec: exec}
	}
	return out
}

func (w *shardWorld) waitFor(what string, d time.Duration, f func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	w.dump(what)
	require.Fail(w.t, "condition never satisfied", what)
}

// dump is the state a failed wait leaves behind: the retained failure to investigate, not a summary.
func (w *shardWorld) dump(what string) {
	t := w.t
	t.Logf("=== STATE AT FAILURE (%s) ===", what)
	for _, id := range w.ids {
		e := w.shards[id].exec
		h, _ := e.Head(context.Background())
		t.Logf("validator %s: head number %d hash %x, pool %d", shortID(id), h.Number, h.Hash, e.poolSize())
	}
	cs := w.certsSince(0)
	for _, c := range cs[max(0, len(cs)-10):] {
		t.Logf("cert seal %d block=%x leader %s", c.seal, c.ir.BlockHash, shortID(c.leader))
	}
	evs := w.requestsSince(time.Time{})
	for _, e := range evs[max(0, len(evs)-24):] {
		t.Logf("request at %s from %s at %s: shard round %d block=%x dropped=%v", e.at.Format("15:04:05.000"), shortID(e.node), e.root, e.round, e.blockHash, e.dropped)
	}
	for _, n := range w.c.nodes {
		si := n.r.manager.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
		if si != nil && si.LastCR != nil {
			t.Logf("root %s: root round %d, shard LastCR seal %d, technical round %d epoch %d leader %s, IR round %d", n.name, w.c.state(n.name).Round, si.LastCR.UC.UnicitySeal.RootChainRoundNumber, si.LastCR.Technical.Round, si.LastCR.Technical.Epoch, shortID(si.LastCR.Technical.Leader), si.LastCR.UC.InputRecord.RoundNumber)
		}
	}
}

// stallAfterLoss arms the drop (every request any validator sends is dropped at every root), queues the identifiable pending work, and waits until the
// shard has been without a certificate for more root rounds than a committed request needs: whatever the roots held has certified or gone, the rest was
// dropped. It returns the last certificate u and the time the drop was armed.
func (w *shardWorld) stallAfterLoss(marker []byte) (u certSample, armed time.Time) {
	w.t.Helper()
	w.setDrop(func(*certification.BlockCertificationRequest) bool { return true })
	armed = time.Now()
	w.addPending(marker)
	w.waitFor("the shard stalls with every request dropped", 3*time.Minute, func() bool {
		u = w.lastCert()
		return w.c.state("H").Round >= u.seal+ingressLossBudget(w.c)+2 && time.Since(u.at) > 3*time.Second
	})
	return u, armed
}

func shortID(id string) string { return id[len(id)-6:] }

// T2 window: the duplicate-triggered retry is withheld (MaxResubmits -1, the test-only control), the repeat reaches the shard, and everything after is the
// shard's own work: its round driver builds a new attempt from the pending entry its executor still holds, signs it, sends it, and the roots accept it.
func TestIngressLossWithRealShardsRecoversThroughTheT2Repeat(t *testing.T) {
	if testing.Short() {
		t.Skip("a live four-root cluster with four real shard nodes")
	}
	opts := shardnode.DefaultBFTClientOptions
	opts.MaxResubmits = -1
	w := newShardWorld(t, shardWorldConfig{names: []string{"H", "a", "b", "c"}, options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: opts})
	w.waitFor("the real shard certifies", 2*time.Minute, func() bool { return w.certCount() >= 4 })

	t.Logf("before the drop: %d certificates sampled, %d requests seen at the roots", w.certCount(), len(w.requestsSince(time.Time{})))
	for i, cs := range w.certsSince(0) {
		t.Logf("  cert %d: seal %d round %d hash %x block %x at +%s", i, cs.seal, cs.ir.RoundNumber, cs.ir.Hash[:4], cs.ir.BlockHash, cs.at.Sub(w.certsSince(0)[0].at).Round(time.Millisecond))
	}
	marker := []byte("pending-976-t2")
	u, armed := w.stallAfterLoss(marker)
	head, err := w.shards[w.ids[0]].exec.Head(context.Background())
	require.NoError(t, err)
	expected := executortest.ExpectedBlock(head, marker)
	for _, e := range w.executors() {
		require.Equal(t, 1, e.poolSize(), "every validator still holds the pending entry")
		h, _ := e.Head(context.Background())
		require.Equal(t, head.Hash, h.Hash, "and none has applied it")
	}
	// the loss boundary: nothing the shards sent since the drop was armed was accepted, and no root has the shard's change in a proposal
	dropped := map[string]int{}
	lost := map[[32]byte]bool{}
	for _, e := range w.requestsSince(armed) {
		require.True(t, e.dropped, "a request reached a root after the drop was armed (%s from %s)", e.root, shortID(e.node))
		dropped[e.root]++
		lost[e.fp] = true
	}
	require.NotEmpty(t, lost, "premise: the shard's attempt was sent and dropped")
	for _, name := range w.c.all() {
		require.Nil(t, w.c.nodes[w.c.idx(name)].r.manager.blockStore.IsChangeInProgress(w.c.state(name).Round, q3fixture.PartitionID, types.ShardID{}), "%s has no change of the shard in a proposal", name)
	}
	eligible := u.seal + t2Rounds(w.h)
	t.Logf("last certificate u: root round %d; a repeat is eligible from round %d; dropped requests per root %v (%d distinct signed requests); pending entry held by %d validators; expected block %x", u.seal, eligible, dropped, len(lost), len(w.ids), expected.Hash[:6])

	var prop proposalSample
	w.waitFor("the roots propose the T2 repeat", 3*time.Minute, func() bool { p, ok := w.firstT2Proposal(armed); prop = p; return ok })
	w.setDrop(nil) // the drop ends with the repeat proposal: from here the shard's own new request is accepted
	opened := time.Now()
	var repeat certSample
	w.waitFor("the repeat is certified", 2*time.Minute, func() bool {
		if cs := w.certsSince(u.seal); len(cs) > 0 {
			repeat = cs[0]
			return true
		}
		return false
	})
	same, err := types.EqualIR(u.ir, repeat.ir)
	require.NoError(t, err)
	require.True(t, same, "the first new certificate is a repeat of u")
	require.GreaterOrEqual(t, repeat.seal, eligible)
	require.LessOrEqual(t, repeat.seal, eligible+ingressLossBudget(w.c))

	var fresh certSample
	w.waitFor("the roots certify the shard's new attempt", 3*time.Minute, func() bool {
		for _, s := range w.certsSince(repeat.seal) {
			if bytes.Equal(s.ir.BlockHash, expected.Hash) {
				fresh = s
				return true
			}
		}
		return false
	})
	accepted := []requestEvent{}
	for _, e := range w.requestsSince(opened) {
		if !e.dropped {
			accepted = append(accepted, e)
		}
	}
	require.NotEmpty(t, accepted)
	for _, e := range accepted {
		require.False(t, lost[e.fp], "no byte-identical re-send: %s from %s", e.root, shortID(e.node))
	}
	acceptedBy := map[string]bool{}
	for _, e := range accepted {
		if bytes.Equal(e.blockHash, expected.Hash) {
			acceptedBy[e.node] = true
		}
	}
	require.GreaterOrEqual(t, len(acceptedBy), 3, "a quorum of the validators sent the new attempt for the pending block")
	same, err = types.EqualIR(repeat.ir, fresh.ir)
	require.NoError(t, err)
	require.False(t, same, "the new attempt certified as new work, not another repeat")
	extra := 0
	for _, c := range w.certsSince(repeat.seal) {
		if c.seal < fresh.seal {
			extra++ // a further repeat before the block certified: the first attempt after the first repeat did not certify (see TestIngressLossWithRealShardsFirstAttemptRate)
		}
	}
	if extra == 0 {
		require.LessOrEqual(t, fresh.seal, repeat.seal+ingressLossBudget(w.c), "certified on the first attempt, within the premise budget")
	} else {
		t.Logf("NOTE: %d further repeat(s) came before the block certified: the first attempt after the first repeat did not certify; the stage is accounted, not hidden", extra)
		require.LessOrEqual(t, fresh.seal, repeat.seal+uint64(extra+1)*(t2Rounds(w.h)+ingressLossBudget(w.c)))
	}
	var applied time.Time
	w.waitFor("every validator applies the certified block", time.Minute, func() bool {
		for _, e := range w.executors() {
			if h, _ := e.Head(context.Background()); !bytes.Equal(h.Hash, expected.Hash) || e.poolSize() != 0 {
				return false
			}
		}
		applied = time.Now()
		return true
	})
	t.Logf("T=%s, block rate %s, T2=%d root rounds, shard: 1 (EVM, 4 validators, fake executor), no other shard load; four non-overlapping terms from the last certificate:", 2*time.Second, phaseLockBlockRate, t2Rounds(w.h))
	t.Logf("  L_eligible: u -> first T2 proposal            %s", prop.at.Sub(u.at).Round(time.Millisecond))
	t.Logf("  C_repeat:   proposal -> repeat certified      %s (root round %d, %d after eligibility)", repeat.at.Sub(prop.at).Round(time.Millisecond), repeat.seal, repeat.seal-eligible)
	first := accepted[0].at
	t.Logf("  R:          repeat certified -> first fresh request accepted at a root   %s (observation resolution ~5 ms; negative means the request preceded the poll)", first.Sub(repeat.at).Round(time.Millisecond))
	t.Logf("  C_fresh:    first accepted -> certified       %s (root round %d, %d after the repeat)", fresh.at.Sub(first).Round(time.Millisecond), fresh.seal, fresh.seal-repeat.seal)
	t.Logf("  applied at all four validators %s after certification", applied.Sub(fresh.at).Round(time.Millisecond))
}

// introduceShards gives every root and every shard validator the others' addresses (liveTransport.up does it for shards that exist when the roots come up).
func (x *liveTransport) introduceShards() {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, r := range x.online {
		for _, sh := range x.shards {
			r.peer.Network().Peerstore().AddAddrs(sh.peer.ID(), sh.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
			sh.peer.Network().Peerstore().AddAddrs(r.peer.ID(), r.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
		}
	}
	for _, a := range x.shards {
		for _, b := range x.shards {
			if a != b {
				a.peer.Network().Peerstore().AddAddrs(b.peer.ID(), b.peer.MultiAddresses(), peerstore.PermanentAddrTTL)
			}
		}
	}
}

// retryOptions are the shard client's options for the windows that exercise the duplicate-triggered re-send: short inactivity and spacing, so the re-send path
// is tried well inside the roots' T2 (12 root rounds), a repeat cannot win the race, and the budget can be exhausted in a short window.
func retryOptions(maxResubmits int) shardnode.BFTClientOptions {
	o := shardnode.DefaultBFTClientOptions
	o.HeartbeatInterval = 200 * time.Millisecond
	o.InactivityTimeout = time.Second
	o.ResubmitMinInterval = 400 * time.Millisecond
	o.MaxResubmits = maxResubmits
	return o
}

func (w *shardWorld) distinctNodes(evs []requestEvent) map[string]bool {
	out := map[string]bool{}
	for _, e := range evs {
		out[e.node] = true
	}
	return out
}

// Inactivity / duplicate window: the first attempt of every validator is lost (dropped at both ingress roots, then the drop ends), no repeat can come before
// the re-send, and the shard's own path recovers it: its inactivity handshake, the root's authenticated answer with the certificate it already holds, and the
// byte-identical re-send of the signed request.
func TestIngressLossWithRealShardsRecoversThroughTheDuplicateResend(t *testing.T) {
	if testing.Short() {
		t.Skip("a live four-root cluster with four real shard nodes")
	}
	w := newShardWorld(t, shardWorldConfig{names: []string{"H", "a", "b", "c"}, options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: retryOptions(10)})
	w.waitFor("the real shard certifies", 2*time.Minute, func() bool { return w.certCount() >= 4 })

	marker := []byte("pending-976-dup")
	w.setDrop(func(*certification.BlockCertificationRequest) bool { return true })
	armed := time.Now()
	w.addPending(marker)
	var lostEvents []requestEvent
	w.waitFor("every validator's attempt is dropped", 2*time.Minute, func() bool {
		lostEvents = w.requestsSince(armed)
		return len(w.distinctNodes(lostEvents)) == len(w.ids)
	})
	w.setDrop(nil) // lost on the way: the drop ends, nothing is replayed
	opened := time.Now()
	u := w.lastCert()
	lost := map[[32]byte]bool{}
	for _, e := range lostEvents {
		require.True(t, e.dropped)
		lost[e.fp] = true
	}
	head, _ := w.shards[w.ids[0]].exec.Head(context.Background())
	expected := executortest.ExpectedBlock(head, marker)
	eligible := u.seal + t2Rounds(w.h)

	var fresh certSample
	w.waitFor("the roots certify the pending block", 3*time.Minute, func() bool {
		for _, s := range w.certsSince(u.seal) {
			if bytes.Equal(s.ir.BlockHash, expected.Hash) {
				fresh = s
				return true
			}
		}
		return false
	})
	for _, s := range w.certsSince(u.seal) {
		same, err := types.EqualIR(u.ir, s.ir)
		require.NoError(t, err)
		require.False(t, same && s.seal <= fresh.seal, "no repeat won the race: the first new certificate is the pending block's")
	}
	require.Less(t, fresh.seal, eligible, "it certified before a T2 repeat was even eligible (u=%d, eligible from %d)", u.seal, eligible)
	var resent []requestEvent
	for _, e := range w.requestsSince(opened) {
		if !e.dropped && lost[e.fp] {
			resent = append(resent, e)
		}
	}
	nodes := w.distinctNodes(resent)
	require.GreaterOrEqual(t, len(nodes), 3, "a quorum of the validators re-sent their lost request, byte-identical")
	for node := range nodes {
		var firstResend time.Time
		for _, e := range resent {
			if e.node == node && (firstResend.IsZero() || e.at.Before(firstResend)) {
				firstResend = e.at
			}
		}
		// the trigger is an authenticated duplicate of the held certificate: any validator's handshake makes a root answer with it (a root also
		// answers the others it serves), so the check is that SOME handshake of the shard preceded this validator's re-send, and its own is logged
		own, any := false, false
		for _, h := range w.handshakesSince(armed) {
			if h.at.Before(firstResend) {
				any = true
				own = own || h.node == node
			}
		}
		require.True(t, any, "validator %s re-sent without any handshake of the shard before it", shortID(node))
		t.Logf("  validator %s: first re-send preceded by its own handshake: %v", shortID(node), own)
	}
	var applied time.Time
	w.waitFor("every validator applies the certified block", time.Minute, func() bool {
		for _, e := range w.executors() {
			if h, _ := e.Head(context.Background()); !bytes.Equal(h.Hash, expected.Hash) || e.poolSize() != 0 {
				return false
			}
		}
		applied = time.Now()
		return true
	})
	hs0 := w.handshakesSince(armed)[0]
	t.Logf("inactivity %s, spacing %s, re-send budget 10, T2=%d root rounds; u=%d, T2 eligible from %d, certified at %d", time.Second, 400*time.Millisecond, t2Rounds(w.h), u.seal, eligible, fresh.seal)
	t.Logf("  last certificate -> first handshake after the loss   %s", hs0.at.Sub(u.at).Round(time.Millisecond))
	t.Logf("  first handshake -> first byte-identical re-send accepted   %s", resent[0].at.Sub(hs0.at).Round(time.Millisecond))
	t.Logf("  first re-send accepted -> certified   %s; applied at all validators %s later; %d validators re-sent", fresh.at.Sub(resent[0].at).Round(time.Millisecond), applied.Sub(fresh.at).Round(time.Millisecond), len(nodes))
}

// Exhausted-retry control: the same loss, but the drop lasts until every validator has used its whole re-send budget (2) against it. Nothing re-sends after
// that (the limitation stays as designed); only the roots' T2 repeat and the shard's new attempt recover the work, and that is reported as such.
func TestIngressLossWithRealShardsAfterTheResendBudgetIsExhausted(t *testing.T) {
	if testing.Short() {
		t.Skip("a live four-root cluster with four real shard nodes")
	}
	const budget = 2
	w := newShardWorld(t, shardWorldConfig{names: []string{"H", "a", "b", "c"}, options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: retryOptions(budget)})
	w.waitFor("the real shard certifies", 2*time.Minute, func() bool { return w.certCount() >= 4 })

	marker := []byte("pending-976-exhausted")
	w.setDrop(func(*certification.BlockCertificationRequest) bool { return true })
	armed := time.Now()
	w.addPending(marker)
	// every validator's signed request arrives 1+budget times (the original and its re-sends), at each ingress root that gets it
	var lostFP = map[[32]byte]string{}
	w.waitFor("every validator has used its re-send budget against the drop", 2*time.Minute, func() bool {
		per := map[[32]byte]int{}
		roots := map[[32]byte]map[string]bool{}
		for _, e := range w.requestsSince(armed) {
			per[e.fp]++
			if roots[e.fp] == nil {
				roots[e.fp] = map[string]bool{}
			}
			roots[e.fp][e.root] = true
			lostFP[e.fp] = e.node
		}
		done := map[string]bool{}
		for fp, n := range per {
			if n >= (1+budget)*len(roots[fp]) {
				done[lostFP[fp]] = true
			}
		}
		return len(done) == len(w.ids)
	})
	w.setDrop(nil)
	opened := time.Now()
	u := w.lastCert()
	head, _ := w.shards[w.ids[0]].exec.Head(context.Background())
	expected := executortest.ExpectedBlock(head, marker)
	eligible := u.seal + t2Rounds(w.h)
	quiet := 2 * time.Second
	time.Sleep(quiet)
	for _, e := range w.requestsSince(opened) {
		_, was := lostFP[e.fp]
		require.False(t, was, "after the budget is spent nothing re-sends the lost request (%s from %s, %s after the drop ended)", e.root, shortID(e.node), e.at.Sub(opened))
	}
	require.Empty(t, w.certsSince(u.seal), "and no certificate came in that time: the work is still outstanding")
	require.Less(t, w.c.state("H").Round, eligible, "premise: a T2 repeat was not yet eligible, so the silence is the exhausted budget")

	var fresh certSample
	w.waitFor("the roots certify the pending block after the T2 repeat", 3*time.Minute, func() bool {
		for _, s := range w.certsSince(u.seal) {
			if bytes.Equal(s.ir.BlockHash, expected.Hash) {
				fresh = s
				return true
			}
		}
		return false
	})
	repeats := 0
	for _, s := range w.certsSince(u.seal) {
		if same, _ := types.EqualIR(u.ir, s.ir); same {
			repeats++
		}
	}
	require.Positive(t, repeats, "the recovery went through a T2 repeat")
	for _, e := range w.requestsSince(opened) {
		_, was := lostFP[e.fp]
		require.False(t, was, "the request that certified is a new attempt, not a re-send")
	}
	t.Logf("re-send budget %d (spent against the drop), inactivity %s; u=%d, T2 eligible from %d; the pending block certified at root round %d, %s after the last certificate (%d repeat(s) first)", budget, time.Second, u.seal, eligible, fresh.seal, fresh.at.Sub(u.at).Round(time.Millisecond), repeats)
}

type cycleRow struct {
	cycle        int
	leader       string
	pausedLeader bool
	fresh        bool          // a quorum of validators' requests for the pending block reached the ingress roots within the budget of the repeat
	firstTry     bool          // ... and that attempt certified: no further repeat was needed
	toApplied    time.Duration // from the first repeat to the block applied at every live validator
	repeats      int           // repeats of the last certificate before the block certified
	behind       int           // requests of the first fresh wave that reached a root that had not yet shown the repeat
	waveRequests int
}

// runLossCycles repeats the T2 window (drop every request, wait for the repeat, let the shard's own new attempt through) on one cluster. A cycle's first fresh
// wave is classified against what each receiving root had shown when the request arrived.
func runLossCycles(t *testing.T, w *shardWorld, cycles int, silent string, rBudget time.Duration) []cycleRow {
	var rows []cycleRow
	live := func(f func(id string, e *retainingExecutor) bool) bool {
		for _, id := range w.ids {
			if id != silent && !f(id, w.shards[id].exec) {
				return false
			}
		}
		return true
	}
	w.waitFor("the live validators certify", 3*time.Minute, func() bool { return w.certCount() >= 3 })
	for k := 1; k <= cycles; k++ {
		w.waitFor("the previous marker is applied everywhere live", 5*time.Minute, func() bool { return live(func(_ string, e *retainingExecutor) bool { return e.poolSize() == 0 }) })
		marker := []byte(fmt.Sprintf("pending-976-cycle-%d", k))
		u, armed := w.stallAfterLoss(marker)
		head, _ := w.shards[w.ids[0]].exec.Head(context.Background())
		expected := executortest.ExpectedBlock(head, marker)
		w.waitFor("the roots propose the T2 repeat", 3*time.Minute, func() bool { _, ok := w.firstT2Proposal(armed); return ok })
		w.setDrop(nil)
		var repeat certSample
		w.waitFor("the repeat is certified", 2*time.Minute, func() bool {
			if cs := w.certsSince(u.seal); len(cs) > 0 {
				repeat = cs[0]
				return true
			}
			return false
		})
		r := cycleRow{cycle: k, leader: shortID(repeat.leader), pausedLeader: silent != "" && repeat.leader == silent}
		for time.Now().Before(repeat.at.Add(rBudget)) && !r.fresh {
			by := map[string]bool{}
			for _, e := range w.requestsSince(repeat.at) {
				if !e.dropped && bytes.Equal(e.blockHash, expected.Hash) {
					by[e.node] = true
				}
			}
			r.fresh = len(by) >= 3
			time.Sleep(20 * time.Millisecond)
		}
		// the first wave: requests for the pending block that arrived within the first 2 s after the repeat, against what the receiving root had shown
		w.mu.Lock()
		for _, e := range w.events {
			if e.dropped || e.at.Before(repeat.at) || e.at.After(repeat.at.Add(2*time.Second)) || !bytes.Equal(e.blockHash, expected.Hash) {
				continue
			}
			r.waveRequests++
			if at, ok := w.sight[e.root][repeat.seal]; !ok || at.After(e.at) {
				r.behind++
			}
		}
		w.mu.Unlock()
		w.waitFor("the pending block is applied at the live validators", 6*time.Minute, func() bool {
			return live(func(_ string, e *retainingExecutor) bool {
				h, _ := e.Head(context.Background())
				return bytes.Equal(h.Hash, expected.Hash)
			})
		})
		r.toApplied = time.Since(repeat.at)
		for _, s := range w.certsSince(u.seal) {
			if same, _ := types.EqualIR(u.ir, s.ir); same {
				r.repeats++
			}
		}
		r.firstTry = r.repeats == 1
		rows = append(rows, r)
		t.Logf("cycle %d: repeat names leader %s (paused: %v); a quorum's requests reached the roots within %s: %v; certified on that attempt: %v (repeats before the block certified: %d); first wave %d requests, %d at a root that had not yet shown the repeat; repeat -> applied %s",
			k, r.leader, r.pausedLeader, rBudget, r.fresh, r.firstTry, r.repeats, r.waveRequests, r.behind, r.toApplied.Round(time.Millisecond))
		w.waitFor("the live pools are empty", time.Minute, func() bool { return live(func(_ string, e *retainingExecutor) bool { return e.poolSize() == 0 }) })
	}
	return rows
}

// Paused-next-leader cases: the shard's last validator (in id order) is never started. A repeat names the next shard leader; when that is the paused validator
// no block is built and no fresh request exists, so R has no finite value for that cycle. Every cycle is reported, the unsuccessful ones included, and the
// assertion is per kind: a live named leader produces its fresh request within the budget, the paused one does not.
func TestIngressLossWithRealShardsPausedNextLeaderHasNoFiniteR(t *testing.T) {
	if testing.Short() {
		t.Skip("a live four-root cluster with three real shard nodes; minutes")
	}
	opts := shardnode.DefaultBFTClientOptions
	opts.MaxResubmits = -1
	w := newShardWorld(t, shardWorldConfig{names: []string{"H", "a", "b", "c"}, options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: opts, silentLast: 1})
	cycles := traceEnvInt(t, "BFT_976_CYCLES", 8)
	rows := runLossCycles(t, w, cycles, w.ids[len(w.ids)-1], 8*time.Second)
	live, pausedN, liveFresh, pausedFresh := 0, 0, 0, 0
	for _, r := range rows {
		if r.pausedLeader {
			pausedN++
			if r.fresh {
				pausedFresh++
			}
		} else {
			live++
			if r.fresh {
				liveFresh++
			}
		}
	}
	t.Logf("summary over %d cycles: live named leader %d (fresh request within the budget: %d); paused named leader %d (fresh request within the budget: %d)", len(rows), live, liveFresh, pausedN, pausedFresh)
	require.Positive(t, pausedN, "premise: at least one repeat named the paused validator as the next leader")
	require.Equal(t, live, liveFresh, "a live named leader produced its fresh request within the budget every time")
	require.Zero(t, pausedFresh, "a paused named leader produced none: R has no finite value for those cycles")
}

// All four validators live and the re-send withheld: how often does the shard's first new attempt after a repeat certify without another repeat? Not an
// assertion on the rate: the attempt can reach an ingress root that has not yet shown the repeat, is refused there ("another request context"), and is not
// retained, so the next recovery is the next T2 (or the duplicate re-send, which this control withholds). The test asserts eventual certification and
// reports the rate, the extra stages, and the evidence for the cause of each failed first attempt.
func TestIngressLossWithRealShardsFirstAttemptRate(t *testing.T) {
	if testing.Short() {
		t.Skip("a live four-root cluster with four real shard nodes; minutes")
	}
	opts := shardnode.DefaultBFTClientOptions
	opts.MaxResubmits = -1
	w := newShardWorld(t, shardWorldConfig{names: []string{"H", "a", "b", "c"}, options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: opts})
	rows := runLossCycles(t, w, traceEnvInt(t, "BFT_976_CYCLES", 8), "", 8*time.Second)
	first, behindFail := 0, 0
	for _, r := range rows {
		if r.firstTry {
			first++
		} else if r.behind > 0 {
			behindFail++
		}
	}
	t.Logf("summary over %d cycles: certified on the first attempt after the repeat %d; needed another repeat %d (of which %d had first-wave requests at a root that had not yet shown the repeat)", len(rows), first, len(rows)-first, behindFail)
}
