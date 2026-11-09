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

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
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
// a request the shard built: every request delivered to a root is one a validator signed and sent. "Delivered" is the wrapper's view, before the root validates
// it; see requestEvent.
//
// STAND-INS AND LIMITS (read before quoting any number from these tests):
//   - Executor: a deterministic FAKE (no EVM, no reth). Its sync is replaced by blockPool, an OPTIMISTIC availability model: it holds only blocks a fixture
//     validator's executor itself built (Seal) or verified valid (Verify), by hash, and importFromPeers verifies each against the importing head and commits it
//     directly. It does not model reth sync, its deadlines, or unavailable peers; it never creates or replaces a request, and the certificate / evidence admission
//     path is the production one. No claim about execution-sync safety or latency follows from a pass.
//   - Authenticated-evidence recovery is ENABLED (Recover, providers = the other validators, DefaultRecoveryOptions otherwise): an enabled premise.
//   - The follower's await timeout is AwaitTimeoutForT2(T2), as the CLI sets it.
//   - MaxResubmits = -1 is the TEST-ONLY control that withholds the duplicate-triggered re-send, to isolate the T2 path.
//   - One shard (EVM, 4 or 5 validators), no f8batch proof load (no RSMT shards, no ~212 KB batches), no other shard traffic. One host, loopback libp2p.
//   - Root rounds and shard rounds share the host with whatever else runs on it; the figures are observations of this profile, not bounds.

// requireLive976 gates every live real-shard test: they take minutes each on a quiet host, so they run only when asked (BFT_976_LIVE=1), in the separate
// workflow .github/workflows/976-live.yml, and never in the default `go test ./...` of go-ci (which runs without -short and has a 30 minute budget per shard).
func requireLive976(t *testing.T) {
	t.Helper()
	if testing.Short() || os.Getenv("BFT_976_LIVE") != "1" {
		t.Skip("live real-shard test (minutes): set BFT_976_LIVE=1; run by .github/workflows/976-live.yml")
	}
}

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
	pool    *blockPool
}

// blockPool is what a real execution client's own peer-to-peer block sync is to the shard node: every block any validator's executor built or verified, by
// hash, so an executor that did not receive a disseminated block (a late leader under this host's load) can still import it when the roots certify it. The
// plain fake answers SYNCING for ever, because nothing supplies the block; reth does not.
type blockPool struct {
	mu     sync.Mutex
	blocks map[string]shardnode.Block
}

func (p *blockPool) put(b shardnode.Block) {
	if len(b.Raw) == 0 {
		return
	}
	p.mu.Lock()
	p.blocks[string(b.Hash)] = b
	p.mu.Unlock()
}

func (p *blockPool) get(hash []byte) (shardnode.Block, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.blocks[string(hash)]
	return b, ok
}

func (e *retainingExecutor) Seal(ctx context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	b, err := e.Fake.Seal(ctx, id)
	if err == nil {
		e.pool.put(b)
	}
	return b, err
}

func (e *retainingExecutor) Verify(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	st, err := e.Fake.Verify(ctx, b, p)
	if err == nil && st == shardnode.StatusValid {
		e.pool.put(b)
	}
	return st, err
}

// importFromPeers imports the chain from the executor's head up to hash out of the pool, oldest first, each block verified against the then-current head.
func (e *retainingExecutor) importFromPeers(ctx context.Context, hash shardnode.Hash) {
	var chain []shardnode.Block
	want := hash
	head, _ := e.Fake.Head(ctx)
	for len(chain) < 64 {
		b, ok := e.pool.get(want)
		if !ok {
			return
		}
		chain = append([]shardnode.Block{b}, chain...)
		if bytes.Equal(b.ParentHash, head.Hash) {
			break
		}
		want = b.ParentHash
	}
	for _, b := range chain {
		if st, err := e.Fake.Verify(ctx, b, shardnode.RoundParams{}); err != nil || st != shardnode.StatusValid {
			return
		}
		if _, err := e.Fake.Commit(ctx, b.Hash); err != nil {
			return
		}
	}
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
	if err == nil && st == shardnode.StatusSyncing {
		e.importFromPeers(ctx, hash)
		st, err = e.Fake.Commit(ctx, hash)
	}
	if after, herr := e.Fake.Head(ctx); herr == nil && after.Number > before.Number {
		e.mu.Lock()
		e.pending = nil
		e.mu.Unlock()
	}
	return st, err
}

// requestEvent is one request DELIVERED to a root's transport wrapper (lossyNet), before rootchain.Node validates, buffers or counts it. A non-dropped event
// therefore means "the network handed it to the root node", not "the root admitted it"; admission is observed only through what the roots go on to certify.
type requestEvent struct {
	at        time.Time
	root      string
	node      string
	round     uint64
	epoch     uint64
	prev      []byte
	blockHash []byte
	fp        [32]byte // of the signed bytes: a byte-identical re-send has the same
	dropped   bool
}

// attemptKey identifies one logical attempt of the shard: the request context its validators sign (shard round, epoch and the previous certified state). A
// later attempt, built after a later repeat, has another round, so retries cannot be counted into an earlier attempt.
type attemptKey struct {
	round, epoch uint64
	prev         string
}

func (e requestEvent) attempt() attemptKey { return attemptKey{e.round, e.epoch, string(e.prev)} }

func keyOfIR(ir *types.InputRecord) attemptKey {
	return attemptKey{ir.RoundNumber, ir.Epoch, string(ir.PreviousHash)}
}

// certSampleResolution is the uncertainty of every time taken from the certificate sampler (it polls the roots every few ms). Latencies that involve a
// certificate time are reported with it; request times are the wrapper's own clock and carry no such error.
const certSampleResolution = 10 * time.Millisecond

// span reports a latency taken against a sampled certificate time as an interval, never a point and never a negative number.
func span(d time.Duration) string {
	lo, hi := d-certSampleResolution, d+certSampleResolution
	if hi < 0 {
		return fmt.Sprintf("the request preceded the first sighting by %s (resolution %s)", (-d).Round(time.Millisecond), certSampleResolution)
	}
	return fmt.Sprintf("[%s, %s]", max(lo, 0).Round(time.Millisecond), hi.Round(time.Millisecond))
}

// attemptStats is what the wrappers saw of one attempt's non-dropped requests for a block.
type attemptStats struct {
	key        attemptKey
	first      time.Time       // the first request of the attempt delivered to any root
	nodes      map[string]bool // distinct validators whose request for the attempt was delivered to any root
	quorumAt   time.Time       // the time a single root had threshold distinct validators' requests delivered (zero: never); still before validation
	quorumRoot string
}

// attemptsOf groups the non-dropped requests for block by attempt. threshold is the shard's request threshold.
func attemptsOf(evs []requestEvent, block []byte, threshold int) map[attemptKey]*attemptStats {
	out := map[attemptKey]*attemptStats{}
	perRoot := map[attemptKey]map[string]map[string]bool{}
	sorted := slices.Clone(evs)
	slices.SortFunc(sorted, func(a, b requestEvent) int { return a.at.Compare(b.at) })
	for _, e := range sorted {
		if e.dropped || !bytes.Equal(e.blockHash, block) {
			continue
		}
		k := e.attempt()
		st := out[k]
		if st == nil {
			st = &attemptStats{key: k, first: e.at, nodes: map[string]bool{}}
			out[k] = st
			perRoot[k] = map[string]map[string]bool{}
		}
		st.nodes[e.node] = true
		if perRoot[k][e.root] == nil {
			perRoot[k][e.root] = map[string]bool{}
		}
		perRoot[k][e.root][e.node] = true
		if st.quorumAt.IsZero() && len(perRoot[k][e.root]) >= threshold {
			st.quorumAt, st.quorumRoot = e.at, e.root
		}
	}
	return out
}

// threshold is the shard's request threshold for its validators (unit weights): the majority the production quorum arithmetic computes, not a constant. It is
// the shard's request majority, not the roots' consensus threshold.
func (w *shardWorld) threshold() int {
	q, err := quorumweight.MajorityThreshold(uint64(len(w.ids)))
	require.NoError(w.t, err)
	return int(q)
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
		ev.round, ev.epoch, ev.prev, ev.blockHash = req.InputRecord.RoundNumber, req.InputRecord.Epoch, bytes.Clone(req.InputRecord.PreviousHash), bytes.Clone(req.InputRecord.BlockHash)
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
	pool := &blockPool{blocks: map[string]shardnode.Block{}}
	for _, id := range ids {
		h := hosts[id]
		diss, err := shardnode.NewNetDisseminator(h.peer, x.obs, peers)
		require.NoError(t, err)
		exec := &retainingExecutor{Fake: executortest.NewAt(genesis), pool: pool}
		node, err := shardnode.New(h.peer, h.net, f.EVMSigners[id], q3fixture.PartitionID, types.ShardID{}, si.ShardConfHash, managerTrust{m: m, old: f.Old}, exec, diss, nil,
			slog.New(slog.NewTextHandler(&testLogWriter{t: t, prefix: id[len(id)-6:]}, &slog.HandlerOptions{Level: slog.LevelInfo})), opts)
		require.NoError(t, err)
		// as the production shard node is configured: the follower's wait for the leader's block follows the shard's own T2, and certificates are served
		node.SetAwaitTimeout(shardnode.AwaitTimeoutForT2(f.ShardConf.T2Timeout))
		// A validator that misses a block (a late leader under this host's load) cannot continue without a catch-up (docs/troubleshooting.md: it must resync), which
		// this package does not model; the authenticated-evidence recovery is the production mechanism for it, switched on here with the other validators as providers.
		recovery := shardnode.DefaultRecoveryOptions()
		recovery.Recover = true
		for _, p := range peers {
			if p != h.peer.ID() {
				recovery.Providers = append(recovery.Providers, p)
			}
		}
		require.NoError(t, node.EnableRecovery(recovery))
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
		// Pace-independent: in root rounds (a round is about BlockRate/2, anywhere from ~230 ms on a CI runner to far more on a loaded host), with a short floor for
		// deliveries in flight, and only once no root has a change of the shard in a proposal. A T2 repeat of u that is itself in flight is waited out, not mistaken
		// for a lost request; the next repeat is 12 rounds later, the window between is wide enough at every pace seen.
		if w.c.state("H").Round < u.seal+ingressLossBudget(w.c)+2 || time.Since(u.at) < 500*time.Millisecond {
			return false
		}
		for _, name := range w.c.all() {
			if w.c.nodes[w.c.idx(name)].r.manager.blockStore.IsChangeInProgress(w.c.state(name).Round, q3fixture.PartitionID, types.ShardID{}) != nil {
				return false
			}
		}
		return true
	})
	return u, armed
}

func shortID(id string) string { return id[len(id)-6:] }

// T2 window: the duplicate-triggered retry is withheld (MaxResubmits -1, the test-only control), the repeat reaches the shard, and everything after is the
// shard's own work: its round driver builds a new attempt from the pending entry its executor still holds, signs it, sends it, and the roots accept it.
func TestIngressLossWithRealShardsRecoversThroughTheT2Repeat(t *testing.T) {
	requireLive976(t)
	opts := shardnode.DefaultBFTClientOptions
	opts.MaxResubmits = -1
	w := newShardWorld(t, shardWorldConfig{names: liveRootNames(), options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: opts})
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
		if ch := w.c.nodes[w.c.idx(name)].r.manager.blockStore.IsChangeInProgress(w.c.state(name).Round, q3fixture.PartitionID, types.ShardID{}); ch != nil {
			// the only change that may be in flight is the roots' own T2 repeat of u (it needs no request); anything else is a request that got into a proposal
			same, err := types.EqualIR(u.ir, ch)
			require.NoError(t, err)
			require.True(t, same, "%s has no change of the shard in a proposal other than a repeat of u", name)
		}
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
	// The attempt that certified, and only its requests: a later retry cannot satisfy an earlier attempt's condition.
	key := keyOfIR(fresh.ir)
	attempts := attemptsOf(w.requestsSince(opened), expected.Hash, w.threshold())
	for _, e := range w.requestsSince(opened) {
		require.False(t, !e.dropped && lost[e.fp], "no byte-identical re-send: %s from %s", e.root, shortID(e.node))
	}
	st := attempts[key]
	require.NotNil(t, st, "requests of the attempt that certified were delivered to the roots")
	require.GreaterOrEqual(t, len(st.nodes), w.threshold(), "the certified attempt was signed and sent by at least the shard's request threshold of validators")
	require.False(t, st.quorumAt.IsZero(), "a threshold of distinct validators' requests of that attempt reached a common root (delivered to its ingress; the root's own admission is shown by the certification that followed)")
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
	t.Logf("T=%s, block rate %s, T2=%d root rounds, %d roots, shard: 1 (EVM, %d validators, fake executor, shared block pool), request threshold %d, no other shard load; non-overlapping terms from the last certificate:", 2*time.Second, phaseLockBlockRate, t2Rounds(w.h), len(w.c.nodes), len(w.ids), w.threshold())
	t.Logf("  L_eligible: u -> first T2 proposal            %s", prop.at.Sub(u.at).Round(time.Millisecond))
	t.Logf("  C_repeat:   proposal -> repeat certified      %s (root round %d, %d after eligibility)", repeat.at.Sub(prop.at).Round(time.Millisecond), repeat.seal, repeat.seal-eligible)
	t.Logf("  R (first arrival):  repeat certified -> first request of the certified attempt delivered to a root   %s", span(st.first.Sub(repeat.at)))
	t.Logf("  R (quorum delivered): repeat certified -> %d distinct validators' requests of that attempt delivered to common root %s   %s (delivery, before the root validates)", w.threshold(), st.quorumRoot, span(st.quorumAt.Sub(repeat.at)))
	t.Logf("  C_fresh:    quorum delivered -> certified     %s (root round %d, %d after the repeat)", span(fresh.at.Sub(st.quorumAt)), fresh.seal, fresh.seal-repeat.seal)
	t.Logf("  tail: certified -> applied at all %d validators %s (end to end; not attributed to a cause: it includes the slowest validator's receipt, import and apply)", len(w.ids), applied.Sub(fresh.at).Round(time.Millisecond))
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

// wideT2 is the shard's T2 in the windows that must show a re-send winning the race against a repeat: about 44 root rounds instead of the fixture's 12, so the
// outcome does not depend on how fast the host happens to run the handshake and re-send path (a runner and a loaded laptop differ by several times). The T2
// window itself keeps the fixture's T2.
const wideT2 = 10 * time.Second

// retryOptions are the shard client's options for the windows that exercise the duplicate-triggered re-send: short inactivity and spacing, so the re-send path
// is tried well inside the roots' T2 (12 root rounds), a repeat cannot win the race, and the budget can be exhausted in a short window.
func retryOptions(maxResubmits int) shardnode.BFTClientOptions {
	o := shardnode.DefaultBFTClientOptions
	o.HeartbeatInterval = 100 * time.Millisecond
	o.InactivityTimeout = 400 * time.Millisecond
	o.ResubmitMinInterval = 150 * time.Millisecond
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
	requireLive976(t)
	w := newShardWorld(t, shardWorldConfig{names: liveRootNames(), options: q3fixture.Options{PeerEVM: true, EVMT2: wideT2}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: retryOptions(10)})
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
	opened := time.Now() // before the drop ends: a re-send delivered the instant it lifts must not fall between the two
	w.setDrop(nil)       // lost on the way: the drop ends, nothing is replayed
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
	if len(nodes) < w.threshold() {
		for _, e := range w.requestsSince(armed) {
			t.Logf("  DIAG request %s from %s at %s: round %d block %x lost-fp %v dropped %v", e.at.Format("15:04:05.000"), shortID(e.node), e.root, e.round, e.blockHash[:min(4, len(e.blockHash))], lost[e.fp], e.dropped)
		}
	}
	require.GreaterOrEqual(t, len(nodes), w.threshold(), "at least the request threshold of validators re-sent their lost request, byte-identical (delivered to a root; admission is shown by the certification)")
	// The trigger is an authenticated duplicate of the held certificate, not necessarily the answer to the shard's own handshake: the roots also deliver the held
	// certificate on their own, and on a loaded host every re-send can come that way. So no handshake is required; for each validator whether one of the
	// shard's handshakes (its own or another's) preceded its first re-send is reported.
	for node := range nodes {
		var firstResend time.Time
		for _, e := range resent {
			if e.node == node && (firstResend.IsZero() || e.at.Before(firstResend)) {
				firstResend = e.at
			}
		}
		own, any := false, false
		for _, h := range w.handshakesSince(armed) {
			if h.at.Before(firstResend) {
				any = true
				own = own || h.node == node
			}
		}
		t.Logf("  validator %s: first re-send preceded by a handshake of the shard: %v, by its own: %v", shortID(node), any, own)
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
	t.Logf("inactivity %s, spacing %s, re-send budget 10, T2=%d root rounds; u=%d, T2 eligible from %d, certified at %d", retryOptions(10).InactivityTimeout, retryOptions(10).ResubmitMinInterval, t2Rounds(w.h), u.seal, eligible, fresh.seal)
	t.Logf("  last certificate -> first handshake after the loss   %s", hs0.at.Sub(u.at).Round(time.Millisecond))
	t.Logf("  first handshake -> first byte-identical re-send delivered   %s", resent[0].at.Sub(hs0.at).Round(time.Millisecond))
	t.Logf("  first re-send delivered -> certified   %s; applied at all validators %s later; %d validators re-sent", fresh.at.Sub(resent[0].at).Round(time.Millisecond), applied.Sub(fresh.at).Round(time.Millisecond), len(nodes))
}

// Exhausted-retry control: the same loss, but the drop lasts until every validator has used its whole re-send budget (2) against it. Nothing re-sends after
// that (the limitation stays as designed); only the roots' T2 repeat and the shard's new attempt recover the work, and that is reported as such.
func TestIngressLossWithRealShardsAfterTheResendBudgetIsExhausted(t *testing.T) {
	requireLive976(t)
	const budget = 2
	w := newShardWorld(t, shardWorldConfig{names: liveRootNames(), options: q3fixture.Options{PeerEVM: true, EVMT2: wideT2}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: retryOptions(budget)})
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
	// Keep dropping until nothing has been delivered for longer than the re-send spacing: a re-send in flight when the drop lifts would be a delivery of a
	// lost request that is not a re-send after the budget was spent.
	spacing := retryOptions(budget).ResubmitMinInterval
	w.waitFor("the drop has been quiet for longer than the re-send spacing", time.Minute, func() bool {
		evs := w.requestsSince(armed)
		return len(evs) > 0 && time.Since(evs[len(evs)-1].at) > spacing+200*time.Millisecond
	})
	w.setDrop(nil)
	opened := time.Now()
	u := w.lastCert()
	head, _ := w.shards[w.ids[0]].exec.Head(context.Background())
	expected := executortest.ExpectedBlock(head, marker)
	eligible := u.seal + t2Rounds(w.h)
	quiet := 3 * spacing // three re-send periods without a single delivery of a lost request
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
	t.Logf("re-send budget %d (spent against the drop), inactivity %s; u=%d, T2 eligible from %d; the pending block certified at root round %d, %s after the last certificate (%d repeat(s) first)", budget, retryOptions(budget).InactivityTimeout, u.seal, eligible, fresh.seal, fresh.at.Sub(u.at).Round(time.Millisecond), repeats)
}

// attemptReport is what the roots' wrappers saw of ONE attempt (the one built after one particular repeat), measured from that repeat's certificate.
type attemptReport struct {
	exists   bool          // any request of the attempt was delivered to a root
	nodes    int           // distinct validators whose request of the attempt was delivered
	arrival  time.Duration // repeat certificate -> first request of the attempt delivered (certificate-sample resolution applies)
	quorumOK bool          // a threshold of distinct validators' requests reached ONE root (delivery; the root's validation comes after)
	quorum   time.Duration // repeat certificate -> that moment
	behind   int           // requests of the first 2 s that reached a root which had not yet shown the repeat
	wave     int
}

type cycleRow struct {
	cycle        int
	leader       string // named by the FIRST repeat
	pausedLeader bool
	repeats      int // repeats of the last certificate before the block certified
	first        attemptReport
	final        attemptReport // the attempt that certified (the same as first when repeats == 1)
	finalLeader  string        // named by the last repeat
	finalPaused  bool
	toFinalReq   time.Duration // first repeat -> first request of the certified attempt delivered
	toCertified  time.Duration // first repeat -> the block certified
	toApplied    time.Duration // first repeat -> applied at every live validator
	certifiedKey attemptKey
}

func (r cycleRow) firstTry() bool { return r.repeats == 1 }

// runLossCycles repeats the T2 window (drop every request, wait for the repeat, let the shard's own new attempt through) on one cluster. Everything is per
// attempt: the attempt after repeat k is the earliest not-yet-assigned attempt whose first request was delivered after repeat k's certificate (and before repeat
// k+1's), so a later retry cannot satisfy an earlier attempt's condition. Times from a repeat carry the certificate-sampling resolution.
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
	pausedSeen := 0
	for k := 1; k <= cycles || (silent != "" && pausedSeen == 0 && k <= 4*cycles); k++ { // with a paused validator, run on until a repeat has named it (the premise of the test)
		w.waitFor("the previous marker is applied everywhere live", 5*time.Minute, func() bool { return live(func(_ string, e *retainingExecutor) bool { return e.poolSize() == 0 }) })
		// every cycle starts from a common checkpoint: all live validators on the same executor head (a validator still catching up from the previous cycle would
		// make this cycle's outcome the previous one's)
		w.waitFor("the live validators are on one executor head", 5*time.Minute, func() bool {
			var first []byte
			return live(func(_ string, e *retainingExecutor) bool {
				h, _ := e.Head(context.Background())
				if first == nil {
					first = h.Hash
				}
				return bytes.Equal(first, h.Hash)
			})
		})
		marker := []byte(fmt.Sprintf("pending-976-cycle-%d", k))
		u, armed := w.stallAfterLoss(marker)
		head, _ := w.shards[w.ids[0]].exec.Head(context.Background())
		expected := executortest.ExpectedBlock(head, marker)
		w.waitFor("the roots propose the T2 repeat", 3*time.Minute, func() bool { _, ok := w.firstT2Proposal(armed); return ok })
		w.setDrop(nil)
		w.waitFor("the repeat is certified", 2*time.Minute, func() bool { return len(w.certsSince(u.seal)) > 0 })
		var certified certSample
		w.waitFor("the block certifies", 6*time.Minute, func() bool {
			for _, s := range w.certsSince(u.seal) {
				if bytes.Equal(s.ir.BlockHash, expected.Hash) {
					certified = s
					return true
				}
			}
			return false
		})
		w.waitFor("the pending block is applied at the live validators", 6*time.Minute, func() bool {
			return live(func(_ string, e *retainingExecutor) bool {
				h, _ := e.Head(context.Background())
				return bytes.Equal(h.Hash, expected.Hash)
			})
		})
		applied := time.Now()
		var repeats []certSample
		for _, s := range w.certsSince(u.seal) {
			if same, _ := types.EqualIR(u.ir, s.ir); same && s.seal < certified.seal {
				repeats = append(repeats, s)
			}
		}
		if len(repeats) == 0 {
			w.dump("cycle premise violated: the pending block certified with no T2 repeat of u first, so the loss was not total")
		}
		require.NotEmpty(t, repeats, "cycle %d: the pending block certified without a T2 repeat of u first (premise: every request was lost)", k)
		attempts := attemptsOf(w.requestsSince(armed), expected.Hash, w.threshold())
		assigned := map[attemptKey]bool{}
		const margin = 100 * time.Millisecond // a request can precede the sampler's first sighting of the certificate it answers
		report := func(i int) attemptReport {
			from := repeats[i].at.Add(-margin)
			to := applied.Add(time.Hour)
			if i+1 < len(repeats) {
				to = repeats[i+1].at.Add(-margin)
			}
			var best *attemptStats
			for key, st := range attempts {
				if assigned[key] || st.first.Before(from) || !st.first.Before(to) {
					continue
				}
				if best == nil || st.first.Before(best.first) {
					best = st
				}
			}
			if best == nil {
				return attemptReport{}
			}
			assigned[best.key] = true
			r := attemptReport{exists: true, nodes: len(best.nodes), arrival: best.first.Sub(repeats[i].at), quorumOK: !best.quorumAt.IsZero()}
			if r.quorumOK {
				r.quorum = best.quorumAt.Sub(repeats[i].at)
			}
			w.mu.Lock()
			for _, e := range w.events {
				if e.dropped || e.attempt() != best.key || e.at.After(repeats[i].at.Add(2*time.Second)) {
					continue
				}
				r.wave++
				if at, ok := w.sight[e.root][repeats[i].seal]; !ok || at.After(e.at) {
					r.behind++
				}
			}
			w.mu.Unlock()
			return r
		}
		row := cycleRow{cycle: k, leader: shortID(repeats[0].leader), pausedLeader: silent != "" && repeats[0].leader == silent, repeats: len(repeats), certifiedKey: keyOfIR(certified.ir)}
		for i := range repeats {
			r := report(i)
			if i == 0 {
				row.first = r
			}
			if i == len(repeats)-1 {
				row.final = r
			}
		}
		last := repeats[len(repeats)-1]
		row.finalLeader, row.finalPaused = shortID(last.leader), silent != "" && last.leader == silent
		row.toFinalReq = last.at.Sub(repeats[0].at) + row.final.arrival
		row.toCertified = certified.at.Sub(repeats[0].at)
		row.toApplied = applied.Sub(repeats[0].at)
		rows = append(rows, row)
		if row.pausedLeader {
			pausedSeen++
		}
		desc := func(r attemptReport) string {
			if !r.exists {
				return "no request of the attempt was delivered"
			}
			q := "threshold NOT reached at any single root"
			if r.quorumOK {
				q = fmt.Sprintf("threshold at one root after %s", span(r.quorum))
			}
			return fmt.Sprintf("first request after %s, %d validators, %s; first 2 s: %d requests, %d at a root that had not yet shown the repeat", span(r.arrival), r.nodes, q, r.wave, r.behind)
		}
		t.Logf("cycle %d: %d repeat(s) before the block certified. FIRST repeat names %s (paused: %v): %s.", k, row.repeats, row.leader, row.pausedLeader, desc(row.first))
		if row.repeats > 1 {
			t.Logf("cycle %d:   CERTIFIED attempt followed the last repeat (names %s, paused: %v): %s; first repeat -> that attempt's first request %s; -> certified %s; -> applied %s (all from the first repeat's certificate)",
				k, row.finalLeader, row.finalPaused, desc(row.final), row.toFinalReq.Round(time.Millisecond), row.toCertified.Round(time.Millisecond), row.toApplied.Round(time.Millisecond))
		} else {
			t.Logf("cycle %d:   certified on that attempt; first repeat -> certified %s; -> applied %s", k, row.toCertified.Round(time.Millisecond), row.toApplied.Round(time.Millisecond))
		}
		w.waitFor("the live pools are empty", time.Minute, func() bool { return live(func(_ string, e *retainingExecutor) bool { return e.poolSize() == 0 }) })
	}
	return rows
}

// Paused-next-leader cases: the shard's last validator (in id order) is never started. A repeat names the next shard leader; when that is the paused validator
// the followers abstain (no block from the named leader) and NO request exists for THAT attempt, so the first-attempt R is unavailable. That is not a
// finite-or-infinite statement about the work: the technical round advances on the timeout, a later repeat can name a live leader, and that attempt's request,
// its non-repeat certificate and the application are reported per cycle, with the time from the first repeat. The assertions are per kind and per attempt, and
// the eventual chain is asserted for every cycle, so a paused leader cannot be averaged away and a stuck chain is a failure, not an expected negative.
func TestIngressLossWithRealShardsPausedNextLeaderHasNoFiniteR(t *testing.T) {
	requireLive976(t)
	opts := shardnode.DefaultBFTClientOptions
	opts.MaxResubmits = -1
	w := newShardWorld(t, shardWorldConfig{names: liveRootNames(), options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: opts, silentLast: 1})
	cycles := traceEnvInt(t, "BFT_976_CYCLES", 8)
	rows := runLossCycles(t, w, cycles, w.ids[len(w.ids)-1], 8*time.Second)
	live, pausedN, liveReq, pausedReq := 0, 0, 0, 0
	var evTimes []string
	for _, r := range rows {
		// the eventual chain, for every cycle: a later attempt named a live leader, its requests reached the roots, the block certified (not a repeat) and applied
		require.False(t, r.finalPaused, "cycle %d: the attempt that certified followed a repeat naming a live leader", r.cycle)
		require.True(t, r.final.exists, "cycle %d: requests of the certified attempt were delivered to the roots", r.cycle)
		if r.pausedLeader {
			pausedN++
			if r.first.exists {
				pausedReq++
			}
			require.Greater(t, r.repeats, 1, "cycle %d: the first repeat named the paused validator; a later repeat is what started the attempt that certified", r.cycle)
			evTimes = append(evTimes, fmt.Sprintf("cycle %d: first repeat -> certified attempt's first request %s, -> certified %s, -> applied %s", r.cycle, r.toFinalReq.Round(time.Millisecond), r.toCertified.Round(time.Millisecond), r.toApplied.Round(time.Millisecond)))
		} else {
			live++
			if r.first.exists {
				liveReq++
			}
		}
	}
	t.Logf("summary over %d cycles: live named leader %d (an attempt followed with requests delivered: %d); paused named leader %d (requests of that attempt: %d). For the paused cycles the first-attempt R is UNAVAILABLE (no request for that attempt); time from the first repeat through the later repeat(s) to the eventual live-leader request, and on to application:", len(rows), live, liveReq, pausedN, pausedReq)
	for _, s := range evTimes {
		t.Logf("  %s", s)
	}
	require.Positive(t, pausedN, "premise: at least one repeat named the paused validator as the next leader")
	// A live named leader whose attempt has no request at all is a liveness question, not an expected negative (arch). It is NOT averaged away and NOT asserted
	// away: it is reported as OPEN with the cycle numbers, kept in the trace, and tracked in the #976 follow-up issue; the eventual chain above is still asserted.
	if liveReq != live {
		var missing []int
		for _, r := range rows {
			if !r.pausedLeader && !r.first.exists {
				missing = append(missing, r.cycle)
			}
		}
		t.Logf("OPEN: a live named leader's first attempt had NO request delivered in %d of %d such cycles (cycles %v); each recovered through a later repeat. Cause not established (a leader that did not build, or a block the followers did not receive in time, are both possible); see the follow-up issue.", live-liveReq, live, missing)
	}
	require.Zero(t, pausedReq, "no request exists for an attempt whose named leader is paused: the first-attempt R is unavailable for those cycles")
}

// All validators live and the re-send withheld: how often does the shard's first new attempt after a repeat certify without another repeat? Not an assertion on
// the rate (arch: retain the misses, do not change deadlines to pass them, cause open). The test asserts that every cycle's pending block eventually certifies
// and applies, and reports per attempt: arrival, quorum delivered at a common root, and the evidence for each missed first attempt as it can be known from the
// wrappers: requests delivered, at which roots, and whether those roots had shown the repeat. Their cause (admission, quorum assembly, forwarding, proposal
// inclusion, supersession by the next repeat) is NOT established here.
func TestIngressLossWithRealShardsFirstAttemptRate(t *testing.T) {
	requireLive976(t)
	opts := shardnode.DefaultBFTClientOptions
	opts.MaxResubmits = -1
	w := newShardWorld(t, shardWorldConfig{names: liveRootNames(), options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: opts})
	rows := runLossCycles(t, w, traceEnvInt(t, "BFT_976_CYCLES", 8), "", 8*time.Second)
	first, noQuorum, behindFail := 0, 0, 0
	for _, r := range rows {
		if r.firstTry() {
			first++
			continue
		}
		if !r.first.quorumOK {
			noQuorum++
		}
		if r.first.behind > 0 {
			behindFail++
		}
	}
	t.Logf("summary over %d cycles: certified on the first attempt after the repeat %d; needed another repeat %d (of which: threshold never delivered to a single root %d; had first-wave requests at a root that had not yet shown the repeat %d). Causes not established.", len(rows), first, len(rows)-first, noQuorum, behindFail)
}

// Control for the loss cycles: the same shards, executors and roots, no request is ever dropped. Entries are queued one after another; every one must be
// applied at every validator with all heads equal. A divergence here is not the loss path's.
func TestRealShardsWithoutLossApplyEveryEntry(t *testing.T) {
	requireLive976(t)
	w := newShardWorld(t, shardWorldConfig{names: liveRootNames(), options: q3fixture.Options{PeerEVM: true}, timeout: 2 * time.Second, blockRate: phaseLockBlockRate, shardOpts: shardnode.DefaultBFTClientOptions})
	w.waitFor("the real shard certifies", 2*time.Minute, func() bool { return w.certCount() >= 4 })
	n := traceEnvInt(t, "BFT_976_ENTRIES", 20)
	for k := 1; k <= n; k++ {
		marker := []byte(fmt.Sprintf("pending-976-control-%d", k))
		w.addPending(marker)
		start := time.Now()
		w.waitFor("the entry is applied at every validator", 3*time.Minute, func() bool {
			var first []byte
			for _, e := range w.executors() {
				if e.poolSize() != 0 {
					return false
				}
				h, _ := e.Head(context.Background())
				if first == nil {
					first = h.Hash
				} else if !bytes.Equal(first, h.Hash) {
					return false
				}
			}
			return true
		})
		t.Logf("entry %d applied at all validators after %s", k, time.Since(start).Round(time.Millisecond))
	}
}

// liveRootNames is the roots of these windows: four, or five with BFT_976_ROOTS=5 (the gate 9 committee size).
func liveRootNames() []string {
	if os.Getenv("BFT_976_ROOTS") == "5" {
		return []string{"H", "a", "b", "c", "d"}
	}
	return []string{"H", "a", "b", "c"}
}
