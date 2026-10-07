package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// Slice D of the Q1 #48 design: real, in-process root consensus (the ConsensusManager run loop, handoff profile so the votes are
// weighed by stake) with the committee 6,1,1,1 and the domain-bound scheme enabled in the test only, through the per-epoch
// activation of the trust base store. Nothing here changes production code; no production start-up installs an activation.
//
// Delivery is controlled: skewedNet is lossless and keeps the order of each sender's messages, so a message is delayed by
// scheduling only, never dropped (the mock network of the other consensus tests drops a message whose receiver does not read it
// within 70 ms, and delivers every send on its own goroutine). The leader schedule outcomes asserted below depend on the first
// rounds, where one lost message misses the bootstrap for good; rounds still end by the manager's own wall-clock local timeout.

// skewedNet is an in-process root network: per receiver a FIFO queue that is only ever emptied into the receiver's channel,
// and a filter that decides, at send time and in the sender's goroutine, whether the message is dropped.
type skewedNet struct {
	mu     sync.Mutex
	boxes  map[peer.ID]*skewedBox
	filter func(from, to peer.ID, msg any) (drop bool)
	sched  *q4Sched // optional Q4 fault adapter (q4_delivery_test.go); nil: every send is delivered, as before
	done   chan struct{}
}

type skewedBox struct {
	mu   sync.Mutex
	q    []any
	wake chan struct{}
	rcv  chan any
}

type skewedConn struct {
	net *skewedNet
	id  peer.ID
	box *skewedBox
}

func newSkewedNet(t *testing.T) *skewedNet {
	n := &skewedNet{boxes: map[peer.ID]*skewedBox{}, done: make(chan struct{})}
	t.Cleanup(func() { close(n.done) })
	return n
}

func (n *skewedNet) connect(id peer.ID) *skewedConn {
	box := &skewedBox{wake: make(chan struct{}, 1), rcv: make(chan any)}
	n.mu.Lock()
	n.boxes[id] = box
	n.mu.Unlock()
	go func() {
		for {
			box.mu.Lock()
			if len(box.q) == 0 {
				box.mu.Unlock()
				select {
				case <-box.wake:
					continue
				case <-n.done:
					return
				}
			}
			msg := box.q[0]
			box.q = box.q[1:]
			box.mu.Unlock()
			select {
			case box.rcv <- msg:
			case <-n.done:
				return
			}
		}
	}()
	return &skewedConn{net: n, id: id, box: box}
}

func (c *skewedConn) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	for _, to := range receivers {
		if c.net.sched != nil {
			if err := c.net.sched.send(c.net, c.id, to, msg); err != nil {
				return err
			}
			continue
		}
		if _, err := c.net.deliver(c.id, to, msg); err != nil {
			return err
		}
	}
	return nil
}

// deliver applies the send-time filter and, when the message passes, queues it at the receiver. It reports whether the message was
// queued: the filter dropping it (an offline party) is not an error.
func (n *skewedNet) deliver(from, to peer.ID, msg any) (bool, error) {
	if n.filter != nil && n.filter(from, to, msg) {
		return false, nil
	}
	n.mu.Lock()
	box := n.boxes[to]
	n.mu.Unlock()
	if box == nil {
		return false, fmt.Errorf("unknown receiver %s", to)
	}
	box.mu.Lock()
	box.q = append(box.q, msg)
	box.mu.Unlock()
	select {
	case box.wake <- struct{}{}:
	default:
	}
	return true, nil
}

func (c *skewedConn) ReceivedChannel() <-chan any { return c.box.rcv }

// skewedStakes: node 0 is the heavy node. The quorum threshold of 9 in total is 7, so the heavy node needs one light node and
// the three light nodes (3) never reach it.
var skewedStakes = []uint64{6, 1, 1, 1}

const skewedThreshold = 7

func skewedConfig() votesig.Config {
	return votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("skewed-weight-integration-genesis"))}
}

type skewedNode struct {
	id      peer.ID
	signer  abcrypto.Signer
	conn    *skewedConn
	dir     string
	synced  bool // the stores are opened with fsync on: the node whose durable restart is claimed
	db      PersistentStore
	orch    *partitions.Orchestration
	tbStore *tbstore.TrustBaseStore

	mu     sync.Mutex
	cm     *ConsensusManager
	cancel context.CancelFunc
	done   chan error
}

type skewedCluster struct {
	t       *testing.T
	nodes   []*skewedNode
	net     *skewedNet
	trust   *types.RootTrustBaseV1
	params  Parameters
	offline sync.Map // peer.ID -> struct{}: the firewall drops everything from and to an offline node
	signing bool
	roster  *q4Roster    // Q4 clusters: the canonical vector the nodes were built from; c.nodes follows its order
	cutOn   atomic.Value // string: the author whose next delivered vote cuts that node off the network (a crash at an observed vote)

	obsMu    sync.Mutex
	observed map[observedKey]map[string]struct{} // every distinct signed statement seen on the wire per (author, round, kind)
}

type observedKey struct {
	author string
	round  uint64
	kind   string
}

// observe records the signed statement of every vote and timeout that is delivered, as the canonical bytes the signature covers:
// the native seal bytes of a legacy vote (its vote-info hash, committed round, epoch, timestamp and root hash) and the timeout
// bytes (round, epoch, high QC round, anchor identity, author). Scheme 2 messages are not expected in the live cluster.
func (c *skewedCluster) observe(msg any) {
	var key observedKey
	var statement []byte
	var err error
	switch m := msg.(type) {
	case *abdrc.VoteMsg:
		if m.Scheme == votesig.SchemeDomainBound {
			c.t.Errorf("unexpected scheme 2 vote from %s in the live cluster", m.Author)
			return
		}
		key = observedKey{m.Author, m.VoteInfo.RoundNumber, "vote"}
		statement, err = m.LedgerCommitInfo.SigBytes()
	case *abdrc.TimeoutMsg:
		if m.Scheme == votesig.SchemeDomainBound {
			c.t.Errorf("unexpected scheme 2 timeout from %s in the live cluster", m.Author)
			return
		}
		key = observedKey{m.Author, m.Timeout.Round, "timeout"}
		statement = m.Bytes()
	default:
		return
	}
	if err != nil {
		c.t.Errorf("signing bytes of %v: %v", key, err)
		return
	}
	c.obsMu.Lock()
	defer c.obsMu.Unlock()
	if c.observed == nil {
		c.observed = map[observedKey]map[string]struct{}{}
	}
	if c.observed[key] == nil {
		c.observed[key] = map[string]struct{}{}
	}
	c.observed[key][string(statement)] = struct{}{}
}

// signedRounds are the rounds in which the node (by index) was seen to sign the kind of message.
func (c *skewedCluster) signedRounds(i int, kind string) []uint64 {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()
	var rounds []uint64
	for k := range c.observed {
		if k.author == c.nodes[i].id.String() && k.kind == kind {
			rounds = append(rounds, k.round)
		}
	}
	return rounds
}

// doubleSigned are the (author, round, kind) for which two different signed statements were delivered.
func (c *skewedCluster) doubleSigned() []observedKey {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()
	var keys []observedKey
	for k, statements := range c.observed {
		if len(statements) != 1 {
			keys = append(keys, k)
		}
	}
	return keys
}

// requireNoDoubleSign: no author signed two different statements for the same round and kind.
func (c *skewedCluster) requireNoDoubleSign() {
	c.t.Helper()
	c.obsMu.Lock()
	n := len(c.observed)
	c.obsMu.Unlock()
	require.NotZero(c.t, n, "premise: messages were observed")
	require.Empty(c.t, c.doubleSigned())
}

// The observer compares the canonical signing bytes, so two statements that differ in a single signed byte are two
// statements: a vote differing only in the seal timestamp or committed round, a timeout differing only in its anchor.
func TestSkewedWeightObserverSeesStatementsThatDifferInOneSignedField(t *testing.T) {
	vote := func(mutate func(*abdrc.VoteMsg)) *abdrc.VoteMsg {
		v := NewDummyVote(t, "author", 9, hash32(1))
		v.LedgerCommitInfo = &types.UnicitySeal{Version: 1, NetworkID: 5, PreviousHash: hash32(2), RootChainRoundNumber: 8, Epoch: 1, Timestamp: 1000, Hash: hash32(3)}
		mutate(v)
		return v
	}
	timeout := func(mutate func(*abdrc.TimeoutMsg)) *abdrc.TimeoutMsg {
		anchor := &drctypes.EpochAnchor{GenesisID: hash32(4), Epoch: 2, Slot: 6, StateRoot: hash32(5)}
		m := abdrc.NewTimeoutMsg(drctypes.NewAnchorTimeout(7, anchor), "author", nil)
		mutate(m)
		return m
	}
	cases := map[string][2]any{
		"seal timestamp":    {vote(func(*abdrc.VoteMsg) {}), vote(func(v *abdrc.VoteMsg) { v.LedgerCommitInfo.Timestamp++ })},
		"committed round":   {vote(func(*abdrc.VoteMsg) {}), vote(func(v *abdrc.VoteMsg) { v.LedgerCommitInfo.RootChainRoundNumber++ })},
		"committed hash":    {vote(func(*abdrc.VoteMsg) {}), vote(func(v *abdrc.VoteMsg) { v.LedgerCommitInfo.Hash = hash32(9) })},
		"anchor genesis id": {timeout(func(*abdrc.TimeoutMsg) {}), timeout(func(m *abdrc.TimeoutMsg) { m.Timeout.Anchor.GenesisID = hash32(9) })},
		"anchor slot":       {timeout(func(*abdrc.TimeoutMsg) {}), timeout(func(m *abdrc.TimeoutMsg) { m.Timeout.Anchor.Slot++ })},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			c := &skewedCluster{t: t}
			c.observe(pair[0])
			c.observe(pair[0]) // the same statement again is not a second one
			require.Empty(t, c.doubleSigned())
			c.observe(pair[1])
			require.Len(t, c.doubleSigned(), 1)
		})
	}
}

// newSkewedCluster builds the four managers (none running). With domainBound the epoch-1 trust base of every node carries the scheme 2
// activation, so every vote, timeout, QC and TC of the epoch is the paired-signature form.
//
// heavyPos is the heavy node's place in the sorted committee, which is the order the leader schedule walks: the leader of round r
// is member r mod 4, so the place decides which rounds the heavy node leads. c.nodes[0] is the heavy node, the others follow in
// committee order. The nodes named in syncNodes (indices into c.nodes) keep their stores on disk with fsync on, the others
// without (their durability is not claimed).
func newSkewedCluster(t *testing.T, domainBound bool, heavyPos int, syncNodes ...int) *skewedCluster {
	t.Helper()
	return newClusterOf(t, clusterSpec{heavy: skewedStakes[0], light: 1, n: len(skewedStakes), heavyPos: heavyPos, domainBound: domainBound}, syncNodes...)
}

// clusterSpec is a committee of n members with one heavy member (at heavyPos in the sorted committee) and n-1 equal light ones.
// weightedLeader activates the root-wrr-v1 leader policy for the genesis epoch in every node's trust base store, so the real
// manager constructor builds the weighted selector.
type clusterSpec struct {
	heavy, light   uint64
	n, heavyPos    int
	domainBound    bool
	weightedLeader bool
	// roster, when set, replaces heavy/light/n/heavyPos by an explicit canonical vector (Q4): c.nodes follows the roster's canonical
	// order and faults are addressed by identity name (c.at).
	roster *q4Roster
}

func newClusterOf(t *testing.T, spec clusterSpec, syncNodes ...int) *skewedCluster {
	t.Helper()
	heavyPos, domainBound := spec.heavyPos, spec.domainBound
	observe := testobservability.Default(t)
	var sorted, testNodes []*testutils.TestNode
	var stakes []uint64
	var total uint64
	if spec.roster != nil {
		for _, e := range spec.roster.Entities {
			sorted = append(sorted, &testutils.TestNode{Signer: e.Signer, Verifier: e.Verifier, PeerConf: &network.PeerConfiguration{ID: e.ID}})
		}
		testNodes, stakes, total = sorted, spec.roster.Weights, spec.roster.Total()
	} else {
		sorted, _ = testutils.CreateTestNodes(t, spec.n)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].PeerConf.ID.String() < sorted[j].PeerConf.ID.String() })
		for i := range sorted {
			stakes = append(stakes, spec.light)
			if i == heavyPos {
				stakes[i] = spec.heavy
			}
		}
		testNodes = append([]*testutils.TestNode{sorted[heavyPos]}, append(append([]*testutils.TestNode{}, sorted[:heavyPos]...), sorted[heavyPos+1:]...)...)
		total = spec.heavy + uint64(spec.n-1)*spec.light
	}
	infos := make([]*types.NodeInfo, len(sorted))
	for i, n := range sorted {
		infos[i] = n.NodeInfo(t)
		infos[i].Stake = stakes[i]
	}
	trust, err := quorumweight.NewTrustBase(5, infos)
	require.NoError(t, err)
	for _, n := range testNodes {
		require.NoError(t, trust.Sign(n.PeerConf.ID.String(), n.Signer))
	}
	require.EqualValues(t, 2*total/3+1, trust.QuorumThreshold, "premise: the root threshold is floor(2W/3)+1")
	if spec.roster == nil {
		require.Equal(t, sorted[heavyPos].PeerConf.ID.String(), trust.RootNodes[heavyPos].NodeID, "premise: the trust base lists the members in sorted order")
		require.EqualValues(t, spec.heavy, trust.RootNodes[heavyPos].Stake)
	}

	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff // stake-weighted voting is a handoff-profile rule
	params.BlockRate = 90 * time.Millisecond
	params.LocalTimeout = 1000 * time.Millisecond

	c := &skewedCluster{t: t, net: newSkewedNet(t), trust: trust, params: params, signing: domainBound, roster: spec.roster}
	for _, n := range testNodes {
		node := &skewedNode{id: n.PeerConf.ID, signer: n.Signer, dir: t.TempDir(), conn: c.net.connect(n.PeerConf.ID)}
		for _, i := range syncNodes {
			node.synced = node.synced || testNodes[i] == n
		}
		c.openStores(node)
		store, err := tbstore.NewTrustBaseStore(memorydb.New(), observe.Logger())
		require.NoError(t, err)
		require.NoError(t, store.Store(trust))
		if domainBound {
			require.NoError(t, store.ActivateSigning(1, skewedConfig()))
		}
		if spec.weightedLeader {
			require.NoError(t, store.ActivateLeaderPolicy(1, tbstore.LeaderPolicyWeightedV1))
		}
		node.tbStore = store
		c.nodes = append(c.nodes, node)
		t.Cleanup(func() { c.closeStores(node) })
	}
	c.net.filter = func(from, to peer.ID, msg any) bool {
		_, f := c.offline.Load(from)
		_, o := c.offline.Load(to)
		if f || o {
			return true
		}
		c.observe(msg)
		// a crash pinned to an observed vote: the vote that is delivered is the node's last message
		if v, ok := msg.(*abdrc.VoteMsg); ok {
			if author, _ := c.cutOn.Load().(string); author != "" && author == v.Author {
				c.offline.Store(from, struct{}{})
			}
		}
		return false
	}
	for _, n := range c.nodes {
		c.offline.Store(n.id, struct{}{}) // nobody is online until started
	}
	t.Cleanup(c.stopAll)
	return c
}

// openStores opens the node's stores from its directory; closeStores closes them. Reopening is what a restarted process does.
func (c *skewedCluster) openStores(n *skewedNode) {
	c.t.Helper()
	var dbOpts []storage.BoltOption
	var orchOpts []partitions.StoreOption
	if !n.synced {
		dbOpts, orchOpts = []storage.BoltOption{storage.WithNoSync()}, []partitions.StoreOption{partitions.WithNoSync()}
	}
	db, err := storage.NewBoltStorage(filepath.Join(n.dir, "root.db"), dbOpts...)
	require.NoError(c.t, err)
	orch, err := partitions.NewOrchestration(5, filepath.Join(n.dir, "orchestration.db"), testobservability.Default(c.t).Logger(), orchOpts...)
	require.NoError(c.t, err)
	n.db, n.orch = db, orch
}

func (c *skewedCluster) closeStores(n *skewedNode) {
	if db, ok := n.db.(interface{ Close() error }); ok {
		_ = db.Close()
	}
	if n.orch != nil {
		_ = n.orch.Close()
	}
}

// build constructs a fresh manager over the node's durable stores, the way a restarted process does.
func (c *skewedCluster) build(n *skewedNode) *ConsensusManager {
	c.t.Helper()
	cm, err := NewConsensusManager(n.id, n.tbStore, n.orch, n.conn, n.signer, n.db, testobservability.Default(c.t), WithConsensusParams(c.params))
	require.NoError(c.t, err)
	return cm
}

// start builds every named manager first, puts them all on the network, then runs them, so that no first-round message is sent
// to a node that is not yet there.
func (c *skewedCluster) start(indices ...int) {
	c.t.Helper()
	cms := make([]*ConsensusManager, len(indices))
	for k, i := range indices {
		cms[k] = c.build(c.nodes[i])
	}
	for _, i := range indices {
		c.offline.Delete(c.nodes[i].id)
	}
	for k, i := range indices {
		n, cm := c.nodes[i], cms[k]
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		n.mu.Lock()
		n.cm, n.cancel, n.done = cm, cancel, done
		n.mu.Unlock()
		go func() { done <- cm.Run(ctx) }()
	}
}

// reopen stops the node, closes its stores and opens them again from disk; the caller starts a new manager over them.
func (c *skewedCluster) reopen(i int) {
	c.t.Helper()
	c.stop(i)
	n := c.nodes[i]
	c.closeStores(n)
	c.openStores(n)
}

func (c *skewedCluster) stop(i int) {
	n := c.nodes[i]
	c.offline.Store(n.id, struct{}{})
	n.mu.Lock()
	cancel, done := n.cancel, n.done
	n.cancel, n.done = nil, nil
	n.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(c.t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		c.t.Fatalf("node %d did not stop", i)
	}
}

func (c *skewedCluster) stopAll() {
	for i := range c.nodes {
		c.stop(i)
	}
}

func (c *skewedCluster) manager(i int) *ConsensusManager {
	n := c.nodes[i]
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cm
}

// highQCRound is the round of the highest QC the node has formed or received.
func (c *skewedCluster) highQCRound(i int) uint64 {
	return c.manager(i).blockStore.GetHighQc().GetRound()
}

// committedRound is the round of the node's latest committed block.
func (c *skewedCluster) committedRound(i int) uint64 {
	state, err := c.manager(i).blockStore.GetState()
	if err != nil {
		return 0
	}
	return state.CommittedHead.Block.Round
}

// signedStake is the stake of the given signers in the trust base.
func (c *skewedCluster) signedStake(signers func(yield func(string))) uint64 {
	stake := map[string]uint64{}
	for _, n := range c.trust.RootNodes {
		stake[n.NodeID] = n.Stake
	}
	var total uint64
	signers(func(id string) { total += stake[id] })
	return total
}

// lightAt is the index (into c.nodes) of the light node that sits `offset` places after the heavy node in the sorted committee,
// the order the round-robin leader schedule walks (leader of round r is member r mod 4).
func (c *skewedCluster) lightAt(offset int) int {
	pos := map[string]int{}
	for i, n := range c.trust.RootNodes {
		pos[n.NodeID] = i
	}
	heavy := pos[c.nodes[0].id.String()]
	for i, n := range c.nodes {
		if pos[n.id.String()] == (heavy+offset)%len(c.nodes) {
			return i
		}
	}
	panic("no such member")
}

// Heavy node plus ONE light node: weight 6+1 = 7, exactly the threshold, with a count of 2 of 4 members. QCs and TCs form by
// weight; whether a QC forms and whether anything ever commits depends on WHERE the two online members sit in the sorted
// committee, because the leader schedule ignores the weights. The leader of round r is the r-th member of the sorted committee,
// round robin (leader/reputation.go pickLeader). A QC for round r is formed by the leader of r+1 over the votes for the block
// the leader of r proposed, so it needs two consecutive online leaders; a commit needs a QC for r+1 on top of it, three. The
// reputation election replaces the round robin only after a QC whose block extends the QC of the previous round
// (reputation.go Update), which two online members get only if they lead rounds 2 and 3 (the genesis QC is the first parent):
// then the election picks among the online signers and the pair carries on alone, committing. Anywhere else the schedule stays
// round robin for good: online neighbours form QCs but never commit, and online members that are not neighbours form no QC.
func TestSkewedWeightHeavyPlusOneLightDependsOnThePlaceInTheSchedule(t *testing.T) {
	t.Run("the two online members are neighbours that do not lead rounds 2 and 3: QCs and TCs by weight, no commit", func(t *testing.T) {
		c := newSkewedCluster(t, false, 0)
		light := c.lightAt(1)
		c.start(0, light)
		require.Eventually(t, func() bool { return c.highQCRound(0) >= 8 }, 40*time.Second, 100*time.Millisecond,
			"QCs form with the heavy node and one light node (weight 7 of 9, 2 of 4 members)")

		// (c) a TC formed by weight: two signers, below any count quorum of the four
		var tc *drctypes.TimeoutCert
		require.Eventually(t, func() bool {
			var err error
			tc, err = c.manager(0).blockStore.GetLastTC()
			return err == nil && tc != nil
		}, 10*time.Second, 100*time.Millisecond, "a timeout certificate formed (the offline members' rounds time out)")
		require.Len(t, tc.Signatures, 2, "the TC is signed by exactly the two online members")
		require.Contains(t, tc.Signatures, c.nodes[0].id.String())
		weight := c.signedStake(func(yield func(string)) {
			for id := range tc.Signatures {
				yield(id)
			}
		})
		require.GreaterOrEqual(t, weight, uint64(skewedThreshold))
		require.NoError(t, tc.Verify(c.nodes[0].tbStore), "the TC verifies under the weighted trust base")

		// the commit rule: the committed head is at most the genesis block however many QCs formed
		require.LessOrEqual(t, c.committedRound(0), uint64(1), "no block beyond genesis commits: three consecutive online leaders never occur")
		c.requireNoDoubleSign()
	})

	t.Run("the two online members are not neighbours: TCs by weight, no QC ever forms", func(t *testing.T) {
		c := newSkewedCluster(t, false, 0)
		c.start(0, c.lightAt(2))
		require.Eventually(t, func() bool { return c.manager(0).pacemaker.GetCurrentRound() >= 6 }, 30*time.Second, 100*time.Millisecond,
			"the pacemaker advances on TCs formed by weight 7")
		require.LessOrEqual(t, c.highQCRound(0), uint64(1), "no QC beyond genesis: the leaders of two consecutive rounds are never both online")
		tc, err := c.manager(0).blockStore.GetLastTC()
		require.NoError(t, err)
		require.NotNil(t, tc)
		require.Len(t, tc.Signatures, 2)
		c.requireNoDoubleSign()
	})

	t.Run("the two online members lead rounds 2 and 3: the reputation election bootstraps and they commit alone", func(t *testing.T) {
		c := newSkewedCluster(t, false, 2)
		c.start(0, c.lightAt(1)) // committee places 2 and 3
		require.Eventually(t, func() bool { return c.highQCRound(0) >= 8 && c.committedRound(0) >= 6 }, 40*time.Second, 100*time.Millisecond,
			"QCs and commits with the heavy node and one light node, weight 7 of 9, 2 of 4 members")
		c.requireNoDoubleSign()
	})
}

// Heavy node plus TWO light nodes (weight 8, 3 of 4 members): the leaders of three consecutive rounds are online, so QCs
// commit. This is the commit evidence for the skewed committee, with the same code and committee as the test above.
func TestSkewedWeightHeavyPlusTwoLightNodesCommit(t *testing.T) {
	c := newSkewedCluster(t, false, 0)
	c.start(0, 1, 2)
	require.Eventually(t, func() bool { return c.highQCRound(0) >= 8 && c.committedRound(0) >= 6 }, 40*time.Second, 100*time.Millisecond,
		"QCs and commits with the heavy node and two light nodes")
	c.requireNoDoubleSign()
}

// Weight below the threshold never progresses, whatever the count: the three light nodes (3 of 9, count 3 of 4) and the
// heavy node alone (6 of 9).
func TestSkewedWeightBelowThresholdMakesNoProgress(t *testing.T) {
	for name, online := range map[string][]int{"three light nodes": {1, 2, 3}, "heavy node alone": {0}} {
		t.Run(name, func(t *testing.T) {
			c := newSkewedCluster(t, false, 0)
			c.start(online...)
			// 3.5 local timeouts of a second: every online node has timed out in round 2 repeatedly and re-broadcast
			time.Sleep(3500 * time.Millisecond)
			for _, i := range online {
				require.LessOrEqual(t, c.highQCRound(i), uint64(1), "no QC beyond the genesis QC")
				require.EqualValues(t, 2, c.manager(i).pacemaker.GetCurrentRound(), "the round never advances: no QC and no TC")
				tc, err := c.manager(i).blockStore.GetLastTC()
				require.NoError(t, err)
				require.Nil(t, tc, "no timeout certificate forms below the threshold weight")
				require.LessOrEqual(t, c.committedRound(i), uint64(1))
			}
			// the timeouts themselves were signed and sent, once per statement
			for _, i := range online {
				require.Contains(t, c.signedRounds(i, "timeout"), uint64(2))
			}
			c.requireNoDoubleSign()
		})
	}
}

// A node that crashes right after one of its votes was delivered keeps its durable safety state and does not sign a second
// statement. The cluster is heavy plus two light nodes (it commits); the victim, a light node whose stores are on disk with fsync
// on, is cut off the network at the first vote of it that is delivered after the arming (nothing it signs afterwards leaves it),
// stopped, its stores closed and opened again from disk, and a new manager started over them. The restarted node must vote
// again at a round above the high-water mark that was on disk, and no author may ever have signed two different statements.
// Scheme 1, live: the legacy safety module persists the highest voted round before signing; the scheme 2 decision record has the
// same close/reopen test on the epoch-2 anchor cluster (TestSkewedWeightScheme2DecisionSurvivesRestart).
func TestSkewedWeightRestartMidRoundKeepsOneDecisionAndNeverDoubleSigns(t *testing.T) {
	const victim = 2
	// Every node syncs its stores to disk, not only the victim. With the victim the only fsyncing node, the other three run
	// unsynced rounds ahead of it: the rounds it leads time out, three consecutive QCs never form and nothing commits within
	// the wait below (observed on an unloaded machine, with and without #398). Equal per-round cost keeps the schedule the one
	// the test describes; the durability under test is still the victim's.
	c := newSkewedCluster(t, false, 0, 0, 1, victim)
	c.start(0, 1, 2)
	require.Eventually(t, func() bool { return c.committedRound(0) >= 3 && len(c.signedRounds(victim, "vote")) > 0 }, 30*time.Second, 20*time.Millisecond)

	// the crash, pinned to the next delivered vote of the victim
	id := c.nodes[victim].id
	c.cutOn.Store(id.String())
	require.Eventually(t, func() bool { _, cut := c.offline.Load(id); return cut }, 30*time.Second, time.Millisecond, "the victim's next vote was delivered and cut it off")
	c.cutOn.Store("")
	var lastVoted uint64
	for _, r := range c.signedRounds(victim, "vote") {
		lastVoted = max(lastVoted, r)
	}

	c.reopen(victim)
	n := c.nodes[victim]
	highWater := n.db.GetHighestVotedRound()
	require.GreaterOrEqual(t, highWater, lastVoted, "the highest voted round read back from disk covers the last delivered vote")

	c.start(victim)
	restarted := c.manager(victim)
	require.GreaterOrEqual(t, restarted.safety.storage.GetHighestVotedRound(), highWater, "the restarted node reads the durable decision")
	// a second statement for a round already voted is refused by the restarted safety module
	conflicting := &drctypes.BlockData{Round: highWater, Epoch: 1, Qc: &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: highWater - 1}}}
	_, err := restarted.safety.MakeVote(conflicting, bytes.Repeat([]byte{0xee}, 32), nil, nil)
	require.ErrorIs(t, err, ErrAlreadyVotedForRound)

	// the cluster, with the restarted node, goes on, and the restarted node itself votes above the stopped store's high-water mark
	target := c.committedRound(0) + 4
	require.Eventually(t, func() bool { return c.committedRound(0) >= target }, 40*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool {
		for _, r := range c.signedRounds(victim, "vote") {
			if r > highWater {
				return true
			}
		}
		return false
	}, 40*time.Second, 100*time.Millisecond, "the restarted node votes at a round above the stopped store's high-water mark")
	c.requireNoDoubleSign()
}

// ---- scheme 2 and the epoch boundary: the anchor cluster ----
//
// A live cluster cannot run scheme 2 from genesis (the genesis QC is a legacy-form certificate of epoch 1) and the only
// fixture that reaches epoch 2 is the hand-driven anchor cluster: four replicas that installed the epoch-2 trust base from a
// verified handoff, with the proposals and votes delivered by the test (no run loops). The tests below are therefore anchor
// cluster evidence, not live-cluster evidence: real managers, real safety modules, real bolt stores and the real QC
// formation and handlers, with message delivery driven by the test.
//
// The skew is in epoch 1 (stakes 6,1,1,1, threshold 7, scheme 1). Epoch 2 keeps three of the four epoch-1 identities, replaces the fourth, and is unit weight
// (threshold 3) with the domain-bound scheme from its first round: the verified trust-history lineage refuses a non-unit
// weight in any successor body (m2contract/contract.go ErrNonUnitWeight), so a skewed epoch 2 cannot be installed without a
// production change, and scheme 2 on a skewed committee is only exercised by the unit-level tests (paired_qc_test.go).

// skewedAnchorCluster is the anchor cluster whose epoch-1 committee is 6,1,1,1 and that signs epoch 2 with scheme 2.
func skewedAnchorCluster(t *testing.T) (c *anchorCluster, heavy string) {
	t.Helper()
	replicas, anchor, _ := newAnchorReplicasWith(t, anchorOptions{weights: skewedStakes, syncDB: true}, 4)
	for _, r := range replicas {
		require.NoError(t, r.store.ActivateSigning(2, domainBoundConfig()))
	}
	old, err := firstReplica(replicas).store.GetByEpoch(1)
	require.NoError(t, err)
	for _, n := range old.RootNodes {
		if n.Stake == 6 {
			heavy = n.NodeID
		}
	}
	require.NotEmpty(t, heavy, "premise: the epoch-1 trust base carries the stakes 6,1,1,1")
	require.EqualValues(t, skewedThreshold, old.QuorumThreshold)
	require.EqualValues(t, 3, firstReplica(replicas).manager.trustBase.Load().QuorumThreshold, "premise: epoch 2 is unit weight")
	return startAnchorCluster(t, replicas, anchor), heavy
}

func stakeOf(tb *types.RootTrustBaseV1, ids []string) uint64 {
	var total uint64
	for _, id := range ids {
		for _, n := range tb.RootNodes {
			if n.NodeID == id {
				total += n.Stake
			}
		}
	}
	return total
}

func signerIDs[V any](m map[string]V) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	return ids
}

// (e) The epoch boundary from scheme 1 (epoch 1, stakes 6,1,1,1) to scheme 2 (epoch 2, unit weights). Every certificate and
// message is verified under the rule of its own epoch: the epoch-2 QCs the cluster forms are paired-signature QCs counted at
// unit weight; the epoch-1 certificates are legacy-form and counted with the epoch-1 stakes (heavy plus one light, two
// signers, is a quorum there although two of the four is no quorum at unit weight, and the three light nodes are not
// although three of the four is a quorum at unit weight); neither wire form verifies under the other epoch's rule; and the
// old epoch's authentic messages of the heavy identity are refused by the live handlers, never buffered and never counted.
func TestSkewedWeightEpochBoundaryScheme1To2(t *testing.T) {
	c, heavy := skewedAnchorCluster(t)
	for i := 0; i < 4; i++ {
		c.advance()
	}
	var hr, source *anchorReplica
	for id, r := range c.replicas {
		if id.String() == heavy {
			hr = r
		}
		if source == nil && r.oldSigners[id.String()] != nil {
			source = r
		}
	}
	require.NotNil(t, hr)
	require.NotNil(t, source)
	store := source.store
	newTB, err := store.GetByEpoch(2)
	require.NoError(t, err)

	t.Run("epoch 2 QCs are paired-signature QCs counted at unit weight", func(t *testing.T) {
		qc := hr.manager.blockStore.GetHighQc()
		require.EqualValues(t, 2, qc.VoteInfo.Epoch)
		require.EqualValues(t, votesig.SchemeDomainBound, qc.Scheme)
		require.NoError(t, qc.VerifyWith(store))
		require.GreaterOrEqual(t, stakeOf(newTB, signerIDs(qc.Signatures)), uint64(3))

		legacyForm := *qc
		legacyForm.Scheme = votesig.SchemeLegacy
		require.ErrorIs(t, legacyForm.VerifyWith(store), votesig.ErrScheme, "the legacy form of an epoch that signs with scheme 2 is refused")
	})

	t.Run("epoch 1 certificates are verified by their own rule and stakes", func(t *testing.T) {
		old := source.proof.CommitQC
		require.NoError(t, old.VerifyWith(store), "the epoch-1 commit proof verifies under epoch 1's rule")
		wrongForm := *old
		wrongForm.Scheme = votesig.SchemeDomainBound
		require.ErrorIs(t, wrongForm.VerifyWith(store), votesig.ErrScheme, "the scheme 2 form of an epoch that signs with scheme 1 is refused")

		var lights []string
		for id := range source.oldSigners {
			if id != heavy {
				lights = append(lights, id)
			}
		}
		sort.Strings(lights)
		sign := func(ids ...string) map[string]abcrypto.Signer {
			m := map[string]abcrypto.Signer{}
			for _, id := range ids {
				m[id] = source.oldSigners[id]
			}
			return m
		}
		round := old.GetRound() + 1
		pair := epochQC(t, old, sign(heavy, lights[0]), round)
		require.NoError(t, pair.VerifyWith(store), "heavy plus one light is 7 of 9 in epoch 1")
		require.Less(t, stakeOf(newTB, []string{heavy, lights[0]}), newTB.QuorumThreshold, "premise: the same pair is no quorum at epoch-2 unit weight")
		threeLights := epochQC(t, old, sign(lights...), round)
		require.ErrorIs(t, threeLights.VerifyWith(store), quorumweight.ErrQuorumNotReached, "the three light nodes are 3 of the epoch-1 threshold 7")
	})

	t.Run("old-epoch messages of the heavy identity are refused by the live handlers and never weighed", func(t *testing.T) {
		ctx := context.Background()
		cm := hr.manager
		round := cm.pacemaker.GetCurrentRound() + 1
		vote, timeout := oldEpochMessages(t, source, heavy, round)
		require.NoError(t, vote.Verify(store), "authentic under its own epoch's rule")
		require.NoError(t, timeout.Verify(store))
		before := len(cm.voteBuffer)
		weightBefore, err := cm.bufferedWeight()
		require.NoError(t, err)
		require.ErrorIs(t, cm.onVoteMsg(ctx, vote), ErrVoteEpoch)
		require.ErrorIs(t, cm.onTimeoutMsg(ctx, timeout), ErrVoteEpoch)
		require.Len(t, cm.voteBuffer, before)
		weightAfter, err := cm.bufferedWeight()
		require.NoError(t, err)
		require.Equal(t, weightBefore, weightAfter, "the old-epoch vote of the identity that weighed 6 adds no weight")
	})

	t.Run("the epoch-2 vote verifies under scheme 2 and its legacy form is refused", func(t *testing.T) {
		votes := hr.net.SentMessages(network.ProtocolRootVote)
		require.NotEmpty(t, votes)
		vote := votes[0].Message.(*abdrc.VoteMsg)
		require.EqualValues(t, 2, vote.VoteInfo.Epoch)
		require.EqualValues(t, votesig.SchemeDomainBound, vote.Scheme)
		require.NoError(t, vote.Verify(store))
		legacy := *vote
		legacy.Scheme, legacy.SealSignature = votesig.SchemeLegacy, nil
		require.ErrorIs(t, legacy.Verify(store), votesig.ErrScheme)
	})
}

// (d), scheme 2: the safety module of the node that was the heavy one in epoch 1 keeps one durable decision per (epoch,
// round, kind), with the complete signed vote. The vote it made in the anchor cluster is recorded in its bolt file (fsync on);
// the file is closed and opened again from disk, and a safety module built over the reopened file reproduces exactly that
// recorded message and can never sign another statement for the same round.
func TestSkewedWeightScheme2DecisionSurvivesRestart(t *testing.T) {
	c, heavy := skewedAnchorCluster(t)
	for i := 0; i < 3; i++ {
		c.advance()
	}
	var hr *anchorReplica
	for id, r := range c.replicas {
		if id.String() == heavy {
			hr = r
		}
	}
	// the votes the replicas sent were for the proposal before the latest one
	block := c.proposals[len(c.proposals)-2].Block
	votes := hr.net.SentMessages(network.ProtocolRootVote)
	require.Len(t, votes, 1)
	vote := votes[0].Message.(*abdrc.VoteMsg)
	require.EqualValues(t, block.Round, vote.VoteInfo.RoundNumber)
	require.EqualValues(t, votesig.SchemeDomainBound, vote.Scheme)
	sent, err := types.Cbor.Marshal(vote)
	require.NoError(t, err)

	old := hr.manager.safety
	require.NoError(t, hr.db.Close())
	reopened, err := storage.NewBoltStorage(hr.dbPath) // from disk, fsync on
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	_, recorded, err := reopened.SignedDecision(storage.DecisionVote, block.Epoch, block.Round)
	require.NoError(t, err)
	require.Equal(t, sent, recorded, "the file holds the complete vote that was sent, byte for byte")

	restarted, err := NewSafetyModule(old.network, old.peerID, old.signer, reopened, WithDomainBoundSigning(hr.store, old.committed))
	require.NoError(t, err)
	again, err := restarted.MakeVote(block, vote.VoteInfo.CurrentRootHash, nil, nil)
	require.NoError(t, err, "the recorded vote is reproduced after the restart")
	resent, err := types.Cbor.Marshal(again)
	require.NoError(t, err)
	require.Equal(t, sent, resent, "the very message that was recorded, high QC included")
	require.NoError(t, again.Verify(hr.store))

	_, err = restarted.MakeVote(block, bytes.Repeat([]byte{0xee}, 32), vote.HighQc, nil)
	require.ErrorIs(t, err, storage.ErrDecisionConflict, "a second statement for the same (epoch, round) is refused")
	_, unchanged, err := reopened.SignedDecision(storage.DecisionVote, block.Epoch, block.Round)
	require.NoError(t, err)
	require.Equal(t, recorded, unchanged, "the refusal left the record untouched")
}

// Two nodes of four restart after they signed and recorded their timeout of the epoch's first round and before the timeout left
// them (their messages are discarded). Their bolt files (fsync on) are closed and opened again from disk, new safety modules are
// built over them, and the HighQC situation has moved on, so that a timeout built now would be a different statement (the
// recorded decision refuses it). The restarted managers send the recorded timeouts, and the other two nodes, which have two
// timeouts only against the quorum of three, form the TC and move to the next round. Without the recorded messages the two
// restarts would leave the quorum at weight 2 for good (the review of #398).
func TestSkewedWeightScheme2TCFormsAfterTwoRestarts(t *testing.T) {
	c, _ := skewedAnchorCluster(t)
	ctx := context.Background()
	var replicas []*anchorReplica
	for _, r := range c.replicas {
		replicas = append(replicas, r)
	}
	crashed, alive := replicas[:2], replicas[2:]
	first := map[*anchorReplica]*abdrc.TimeoutMsg{}
	for _, r := range replicas {
		r.net.ResetSentMessages(network.ProtocolRootTimeout)
		r.manager.onLocalTimeout(ctx)
		sent := r.net.SentMessages(network.ProtocolRootTimeout)
		require.NotEmpty(t, sent)
		msg := sent[0].Message.(*abdrc.TimeoutMsg)
		require.EqualValues(t, votesig.SchemeDomainBound, msg.Scheme)
		require.NotNil(t, msg.Timeout.Anchor, "premise: the first timeout of the epoch carries the anchor")
		first[r] = msg
	}
	round := first[alive[0]].Timeout.Round

	// the restarts: the stores are closed and opened again from disk, the pacemaker starts the round without its timeout vote
	for _, r := range crashed {
		require.NoError(t, r.db.Close())
		reopened, err := storage.NewBoltStorage(r.dbPath)
		require.NoError(t, err)
		t.Cleanup(func() { _ = reopened.Close() })
		old := r.manager.safety
		restarted, err := NewSafetyModule(old.network, old.peerID, old.signer, reopened, WithDomainBoundSigning(r.store, old.committed))
		require.NoError(t, err)
		r.manager.safety = restarted
		r.manager.pacemaker.timeoutVote = nil
		r.manager.epochAnchor = nil // what it would build now is not the statement it recorded
		r.net.ResetSentMessages(network.ProtocolRootTimeout)
		r.manager.onLocalTimeout(ctx)
		sent := r.net.SentMessages(network.ProtocolRootTimeout)
		require.NotEmpty(t, sent, "the restarted node sends its recorded timeout")
		again := sent[0].Message.(*abdrc.TimeoutMsg)
		require.Equal(t, first[r].Signature, again.Signature, "the recorded message, not a new signature")
		first[r] = again
	}

	receiver := alive[1].manager
	require.EqualValues(t, round, receiver.pacemaker.GetCurrentRound())
	for _, r := range alive { // the two timeouts that were never lost
		require.NoError(t, receiver.onTimeoutMsg(ctx, first[r]))
	}
	require.EqualValues(t, round, receiver.pacemaker.GetCurrentRound(), "two timeouts are below the quorum of three: no TC")
	// either restarted node's recorded timeout completes the quorum of three (before the fix neither could contribute any)
	require.NoError(t, receiver.onTimeoutMsg(ctx, first[crashed[0]]))
	require.EqualValues(t, round+1, receiver.pacemaker.GetCurrentRound(), "with a restarted node's recorded timeout the TC forms and the round advances")
	tc := receiver.pacemaker.LastRoundTC()
	require.NotNil(t, tc)
	require.EqualValues(t, votesig.SchemeDomainBound, tc.Scheme)
	require.GreaterOrEqual(t, len(tc.Signatures), 3)
	require.NoError(t, tc.Verify(alive[1].store))
}
