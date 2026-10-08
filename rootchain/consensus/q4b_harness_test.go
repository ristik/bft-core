package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4shim"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// Q4 #51 (B) in-process live harness: the validators of a REAL Q3 activation (scheme 2, weighted, root-wrr-v1 chosen by the
// committed tuple), each behind the q4shim fault shim that the live lane wires into the process, each with fsynced stores and a
// crash-cut capable signer and store. A->B is two real activations in a row (the second verified under the first's weighted scheme 2
// quorum). Coverage label: IN-PROCESS, root consensus only (no EVM, no aggregator shard, in-process close/reopen is not a SIGKILL).

var (
	errQ4BCrashed    = errors.New("q4b: the node crashed at its cut")
	errQ4BChain      = errors.New("q4b finality: conflicting committed history")
	errQ4BRecovery   = errors.New("q4b recovery: insufficient post-fault commits")
	errQ4BCutMissing = errors.New("q4b: the crash cut never fired")
)

const (
	q4bDeadline = 120 * time.Second // frozen before every run
	q4bStall    = 3500 * time.Millisecond
)

// cut points of a signing decision, in the order the safety module performs them
const (
	cutBeforeSign   = "before-sign"            // nothing signed yet
	cutBetweenPair  = "between-paired"         // PV signed in memory, the seal signature not made
	cutBeforeRecord = "after-sign-before-save" // every signature made, the decision not on disk
	cutBeforeSend   = "after-save-before-send" // the decision is on disk, the message never left
)

type q4bCutSpec struct {
	Point string
	Kind  storage.DecisionKind
}

// q4bCrash is the crash state of one node: an armed cut, and once it fired the node is dead: its signer and its store refuse
// everything, which is the node having lost power at that instant.
type q4bCrash struct {
	mu    sync.Mutex
	armed *q4bCutSpec
	dead  atomic.Bool
	fired chan struct{}
	// what the node had decided when it died
	recorded       bool
	epoch, round   uint64
	statement, msg []byte
	signed         []byte // the statement being signed at a signer cut
	lastPV         bool
	onCrash        func()
}

func newQ4BCrash() *q4bCrash { return &q4bCrash{fired: make(chan struct{})} }

func (c *q4bCrash) arm(spec q4bCutSpec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = &spec
}

func (c *q4bCrash) crash() {
	if c.dead.CompareAndSwap(false, true) {
		close(c.fired)
		if c.onCrash != nil {
			go c.onCrash()
		}
	}
}

// signer cut: decides on the statement kind from its canonical tag.
type q4bSigner struct {
	abcrypto.Signer
	c *q4bCrash
}

func q4bKindOf(data []byte) (storage.DecisionKind, bool) {
	v, err := votesig.Decode(data)
	if err != nil {
		return 0, false
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return 0, false
	}
	switch arr[0] {
	case votesig.VoteTag:
		return storage.DecisionVote, true
	case votesig.TimeoutTag:
		return storage.DecisionTimeout, true
	}
	return 0, false
}

func q4bIsSeal(data []byte) bool {
	var s types.UnicitySeal
	return types.Cbor.Unmarshal(data, &s) == nil && s.Version == 1 && s.RootChainRoundNumber != 0
}

func (s *q4bSigner) SignBytes(data []byte) ([]byte, error) {
	c := s.c
	if c.dead.Load() {
		return nil, errQ4BCrashed
	}
	kind, tagged := q4bKindOf(data)
	c.mu.Lock()
	spec := c.armed
	pair := c.lastPV
	c.lastPV = tagged && kind == storage.DecisionVote
	hit := false
	if spec != nil {
		switch {
		case spec.Point == cutBeforeSign && tagged && kind == spec.Kind:
			hit = true
		case spec.Point == cutBetweenPair && pair && !tagged && q4bIsSeal(data):
			hit = true
		}
	}
	if hit {
		c.armed = nil
		c.signed = bytes.Clone(data)
	}
	c.mu.Unlock()
	if hit {
		c.crash()
		return nil, errQ4BCrashed
	}
	return s.Signer.SignBytes(data)
}

// q4bStore observes committed roots (finality) and carries the store cuts. It embeds the bolt store so every optional capability of
// the manager's store survives.
type q4bStore struct {
	storage.BoltDB
	live  *q4bLive
	index int
	c     *q4bCrash
}

func (s *q4bStore) dead() error {
	if s.c.dead.Load() {
		return errQ4BCrashed
	}
	return nil
}

func (s *q4bStore) WriteBlock(b *storage.ExecutedBlock, root bool) error {
	return s.observed(b, root, func() error { return s.BoltDB.WriteBlock(b, root) })
}

func (s *q4bStore) CommitBlock(b *storage.ExecutedBlock, recs []rootrecords.Record, cut *storage.CutEntry) error {
	return s.observed(b, true, func() error { return s.BoltDB.CommitBlock(b, recs, cut) })
}

func (s *q4bStore) observed(b *storage.ExecutedBlock, root bool, write func() error) error {
	if err := s.dead(); err != nil {
		return err
	}
	hash, err := b.BlockData.Hash(crypto.SHA256)
	if err != nil {
		return err
	}
	blk := q4Block{Hash: slices.Clone(hash), Parent: b.GetParentRound()}
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if err := write(); err != nil {
		return err
	}
	s.live.recordBlock(s.index, b.GetRound(), blk, root)
	return nil
}

func (s *q4bStore) WriteVote(v any) error {
	if err := s.dead(); err != nil {
		return err
	}
	return s.BoltDB.WriteVote(v)
}

func (s *q4bStore) WriteTC(tc *rctypes.TimeoutCert) error {
	if err := s.dead(); err != nil {
		return err
	}
	return s.BoltDB.WriteTC(tc)
}

func (s *q4bStore) SetHighestVotedRound(r uint64) error {
	if err := s.dead(); err != nil {
		return err
	}
	return s.BoltDB.SetHighestVotedRound(r)
}

func (s *q4bStore) SetHighestQcRound(q, v uint64) error {
	if err := s.dead(); err != nil {
		return err
	}
	return s.BoltDB.SetHighestQcRound(q, v)
}

func (s *q4bStore) RecordSignedDecision(kind storage.DecisionKind, epoch, round uint64, statement, message []byte) error {
	if err := s.dead(); err != nil {
		return err
	}
	c := s.c
	c.mu.Lock()
	spec := c.armed
	hit := spec != nil && spec.Kind == kind && (spec.Point == cutBeforeRecord || spec.Point == cutBeforeSend)
	if hit {
		c.armed = nil
		c.epoch, c.round, c.statement, c.msg = epoch, round, bytes.Clone(statement), bytes.Clone(message)
	}
	c.mu.Unlock()
	if hit && spec.Point == cutBeforeRecord {
		c.crash()
		return errQ4BCrashed
	}
	if err := s.BoltDB.RecordSignedDecision(kind, epoch, round, statement, message); err != nil {
		return err
	}
	if hit { // cutBeforeSend: it is on disk, the node dies before it can say so
		c.mu.Lock()
		c.recorded = true
		c.mu.Unlock()
		c.crash()
		return errQ4BCrashed
	}
	return nil
}

// ---- the live cluster ----

type q4bNode struct {
	name   string
	weight uint64
	r      *q3Replica
	shim   *q4shim.Net
	crash  *q4bCrash
}

type q4bLive struct {
	t       *testing.T
	epoch   uint64
	net     *skewedNet
	nodes   []*q4bNode
	cfg     votesig.Config
	offline sync.Map

	mu     sync.Mutex
	cancel map[int]context.CancelFunc
	done   map[int]chan error
	seen   map[int][]q4Commit
	chains map[int]map[uint64]q4Block
	blocks map[int]map[uint64]q4Block
	faults []error
	// the shim traces of nodes that were closed (a restart makes a new shim; the earlier one's trace stays evidence)
	retired [][]q4shim.Event
	retIdx  []int
}

func (c *q4bLive) signing(epoch uint64) (votesig.Config, error) {
	if epoch < 2 {
		return votesig.Config{Scheme: votesig.SchemeLegacy}, nil
	}
	return c.cfg, nil
}

// attach puts a shim, the crash state and the observing wrappers on a replica.
func (c *q4bLive) attach(i int, n *q4bNode) {
	r := n.r
	conn := c.net.connect(r.id())
	n.crash = newQ4BCrash()
	n.shim = q4shim.New(conn, q4shim.Config{Self: r.id(), Signing: c.signing, Signer: r.node.Signer, KeepRaw: true})
	r.link, r.durable = n.shim, true
	r.wrapStore = func(db storage.BoltDB) PersistentStore { return &q4bStore{BoltDB: db, live: c, index: i, c: n.crash} }
	r.wrapSigner = func(s abcrypto.Signer) abcrypto.Signer { return &q4bSigner{Signer: s, c: n.crash} }
	n.crash.onCrash = func() { c.offline.Store(r.id(), struct{}{}) }
	c.offline.Store(r.id(), struct{}{}) // nobody is online until started
}

func newQ4BBase(t *testing.T, epoch uint64, f *q3fixture.Fixture) *q4bLive {
	c := &q4bLive{t: t, epoch: epoch, net: newSkewedNet(t), cancel: map[int]context.CancelFunc{}, done: map[int]chan error{},
		seen: map[int][]q4Commit{}, chains: map[int]map[uint64]q4Block{}, blocks: map[int]map[uint64]q4Block{}}
	c.cfg = votesig.Config{Scheme: votesig.SchemeDomainBound, Network: q3fixture.Network, Genesis: f.Genesis}
	c.net.filter = func(from, to peer.ID, msg any) bool {
		_, a := c.offline.Load(from)
		_, b := c.offline.Load(to)
		return a || b
	}
	t.Cleanup(c.stopAll)
	return c
}

// newQ4BLiveA is the first activation, live: 6,1,1,1 (W=9, Q=7) over scheme 2 with a coupled EVM assignment. Nodes H, a, b, c.
func newQ4BLiveA(t *testing.T) *q4bLive {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	c := newQ4BBase(t, 2, f)
	for i, name := range []string{"H", "a", "b", "c"} {
		r := newQ3Replica(t, f, f.NewNodes[i])
		n := &q4bNode{name: name, weight: f.Members[i].Weight, r: r}
		c.nodes = append(c.nodes, n)
		c.attach(i, n)
		r.mustOpen(true)
		t.Cleanup(r.close)
	}
	ctx := context.Background()
	for _, n := range c.nodes {
		require.NoError(t, n.r.rt.Recover(ctx))
		require.NoError(t, n.r.rt.Activate(ctx, n.r.bundle()))
	}
	for _, n := range c.nodes {
		n.r.close()
		n.r.mustOpen(true)
		require.NoError(t, n.r.rt.Recover(ctx))
	}
	return c
}

// newQ4BLiveB is A then the handoff to B: the old committee (H and a, weight 7 of 9) commits the second body, three members are
// retained with new weights 3,3,2 and the fourth is replaced by a new entity d of weight 1 (one of four identities changed; the
// retained weight is 8 of 9 in the old map and 8 of 9 in the new). Both activations are verified under the weighted scheme 2 rule of
// the epoch that commits them. Nodes h1, h2, n2, d.
func newQ4BLiveB(t *testing.T) *q4bLive {
	t.Helper()
	f1 := q3fixture.New(t, q3fixture.Options{})
	f2 := q3fixture.New(t, q3fixture.Options{After: f1, Weights: []uint64{3, 3, 2, 1}})
	c := newQ4BBase(t, 3, f1)
	ctx := context.Background()
	for i, name := range []string{"h1", "h2", "n2", "d"} {
		r := newQ3Replica(t, f1, f2.NewNodes[i])
		n := &q4bNode{name: name, weight: f2.Members[i].Weight, r: r}
		c.nodes = append(c.nodes, n)
		c.attach(i, n)
		r.mustOpen(true)
		t.Cleanup(r.close)
	}
	for _, n := range c.nodes {
		require.NoError(t, n.r.rt.Recover(ctx))
		require.NoError(t, n.r.rt.Activate(ctx, q3active.Bundle{Envelope: f1.EnvelopeBytes, Snapshot: f1.Snapshot}))
		n.r.restart()
		require.NoError(t, n.r.rt.Activate(ctx, q3active.Bundle{Envelope: f2.EnvelopeBytes, Snapshot: f2.Snapshot}))
	}
	for _, n := range c.nodes {
		n.r.close()
		n.r.mustOpen(true)
		require.NoError(t, n.r.rt.Recover(ctx))
	}
	return c
}

func (c *q4bLive) idx(name string) int {
	for i, n := range c.nodes {
		if n.name == name {
			return i
		}
	}
	c.t.Fatalf("no node %q", name)
	return -1
}

func (c *q4bLive) id(name string) peer.ID { return c.nodes[c.idx(name)].r.id() }

func (c *q4bLive) ids(names ...string) (out []string) {
	for _, n := range names {
		out = append(out, c.id(n).String())
	}
	return out
}

func (c *q4bLive) weight(names ...string) (w uint64) {
	for _, n := range names {
		w += c.nodes[c.idx(n)].weight
	}
	return w
}

func (c *q4bLive) all() (out []string) {
	for _, n := range c.nodes {
		out = append(out, n.name)
	}
	return out
}

func (c *q4bLive) except(names ...string) (out []string) {
	for _, n := range c.all() {
		if !slices.Contains(names, n) {
			out = append(out, n)
		}
	}
	return out
}

// apply gives every named node's shim a control document.
func (c *q4bLive) apply(ctl q4shim.Control, names ...string) {
	c.t.Helper()
	for _, n := range names {
		require.NoError(c.t, c.nodes[c.idx(n)].shim.Apply(context.Background(), ctl))
	}
}

func (c *q4bLive) start(names ...string) {
	c.t.Helper()
	for _, name := range names {
		i := c.idx(name)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		cm := c.nodes[i].r.manager
		c.mu.Lock()
		c.cancel[i], c.done[i] = cancel, done
		c.mu.Unlock()
		c.offline.Delete(c.nodes[i].r.id())
		go func() { done <- cm.Run(ctx) }()
	}
}

func (c *q4bLive) stop(name string) {
	i := c.idx(name)
	c.offline.Store(c.nodes[i].r.id(), struct{}{})
	c.mu.Lock()
	cancel, done := c.cancel[i], c.done[i]
	delete(c.cancel, i)
	delete(c.done, i)
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(c.t, err, context.Canceled)
	case <-time.After(15 * time.Second):
		c.t.Fatalf("node %s did not stop", name)
	}
}

func (c *q4bLive) stopAll() {
	for _, n := range c.nodes {
		c.stop(n.name)
	}
}

// restart is a process restart of one node: loop ended, stores released and reopened from disk (fsync on), the verified history
// rebuilt from the journal, a fresh shim and a fresh crash state (the earlier shim's trace stays in the evidence). In-process close
// and reopen is not a SIGKILL and not a power loss.
func (c *q4bLive) restart(name string) {
	c.t.Helper()
	c.stop(name)
	i := c.idx(name)
	n := c.nodes[i]
	c.mu.Lock()
	c.retired, c.retIdx = append(c.retired, n.shim.Trace()), append(c.retIdx, i)
	c.mu.Unlock()
	n.shim.Close()
	n.r.close()
	c.attach(i, n)
	n.r.mustOpen(true)
	require.NoError(c.t, n.r.rt.Recover(context.Background()))
	c.start(name)
}

// ---- observation ----

func (c *q4bLive) recordBlock(i int, round uint64, b q4Block, root bool) {
	if c.blocks[i] == nil {
		c.blocks[i] = map[uint64]q4Block{}
	}
	if c.chains[i] == nil {
		c.chains[i] = map[uint64]q4Block{}
	}
	c.blocks[i][round] = b
	if !root {
		return
	}
	for at := round; at > 1; {
		block, ok := c.blocks[i][at]
		if !ok {
			break
		}
		if old, exists := c.chains[i][at]; exists {
			if !bytes.Equal(old.Hash, block.Hash) {
				c.faults = append(c.faults, fmt.Errorf("%w: node %d round %d", errQ4BChain, i, at))
			}
			break
		}
		c.chains[i][at] = block
		if block.Parent >= at {
			break
		}
		at = block.Parent
	}
	obs := c.seen[i]
	if round > 1 && (len(obs) == 0 || round > obs[len(obs)-1].Round) {
		c.seen[i] = append(obs, q4Commit{round, time.Now()})
	}
}

type q4bMark struct {
	At     time.Time
	Counts map[int]int
}

func (c *q4bLive) mark() q4bMark {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := q4bMark{At: time.Now(), Counts: map[int]int{}}
	for i := range c.nodes {
		m.Counts[i] = len(c.seen[i])
	}
	return m
}

func (c *q4bLive) commitsSince(i int, m q4bMark) []q4Commit {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.seen[i][m.Counts[i]:])
}

// requireRecovery: every named node has n new ordinary commits (never a TC or a round advance) within the frozen deadline.
func (c *q4bLive) requireRecovery(m q4bMark, n int, names ...string) (first, nth time.Duration) {
	c.t.Helper()
	deadline := m.At.Add(q4bDeadline)
	require.Eventually(c.t, func() bool {
		for _, name := range names {
			if len(c.commitsSince(c.idx(name), m)) < n {
				return false
			}
		}
		return true
	}, time.Until(deadline), 20*time.Millisecond, "%v need %d new commits within %s", names, n, q4bDeadline)
	for _, name := range names {
		obs := c.commitsSince(c.idx(name), m)
		first, nth = max(first, obs[0].At.Sub(m.At)), max(nth, obs[n-1].At.Sub(m.At))
	}
	return first, nth
}

type q4bState struct{ Round, HighQC, Committed uint64 }

func (c *q4bLive) state(name string) q4bState {
	m := c.nodes[c.idx(name)].r.manager
	var s q4bState
	s.Round = m.pacemaker.GetCurrentRound()
	s.HighQC = m.blockStore.GetHighQc().GetRound()
	if st, err := m.blockStore.GetState(); err == nil {
		s.Committed = st.CommittedHead.Block.Round
	}
	return s
}

// requireStalled: after the pre-issued evidence drains, no QC and no commit for the window. TC and round advance are not
// counted as progress but a stall also needs no new QC.
func (c *q4bLive) requireStalled(names ...string) {
	c.t.Helper()
	time.Sleep(q4Quiesce) // pre-issued messages drain
	before := map[string]q4bState{}
	for _, n := range names {
		before[n] = c.state(n)
	}
	time.Sleep(q4bStall)
	for _, n := range names {
		after := c.state(n)
		require.Equal(c.t, before[n].Committed, after.Committed, "%s committed during the stall", n)
		require.Equal(c.t, before[n].HighQC, after.HighQC, "%s formed or adopted a QC during the stall", n)
	}
}

// requireChainsAgree: no two nodes committed different blocks for a common round, and the observer itself saw no conflict.
func (c *q4bLive) requireChainsAgree(names ...string) {
	c.t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NoError(c.t, errors.Join(c.faults...))
	for x, a := range names {
		for _, b := range names[x+1:] {
			ca, cb := c.chains[c.idx(a)], c.chains[c.idx(b)]
			require.NotEmpty(c.t, ca, a)
			require.NotEmpty(c.t, cb, b)
			shared := 0
			for round, blk := range ca {
				if other, ok := cb[round]; ok {
					shared++
					require.Truef(c.t, bytes.Equal(blk.Hash, other.Hash), "%w: round %d, %s and %s", errQ4BChain, round, a, b)
				}
			}
			require.NotZero(c.t, shared, "%s and %s share committed rounds", a, b)
		}
	}
}

func pid(s string) peer.ID {
	id, err := peer.Decode(s)
	if err != nil {
		return ""
	}
	return id
}

// views are the oracle's epoch views of the cluster: weights and verification keys by peer id, with the epoch's signing config.
func (c *q4bLive) views() map[uint64]q4EpochView {
	v := q4EpochView{Epoch: c.epoch, Weights: map[string]uint64{}, Verifiers: map[string]abcrypto.Verifier{}, Cfg: &c.cfg}
	for _, n := range c.nodes {
		ver, err := n.r.node.Signer.Verifier()
		require.NoError(c.t, err)
		v.Weights[n.r.id().String()] = n.weight
		v.Verifiers[n.r.id().String()] = ver
	}
	return map[uint64]q4EpochView{c.epoch: v}
}

// trace is the merged trace of every shim (live and retired) in the oracle's form, with node-unique send ids. Byzantine sends are
// attempts with a delivery, so the oracle classifies them like any other signed statement.
func (c *q4bLive) trace() q4Trace {
	type src struct {
		idx int
		evs []q4shim.Event
	}
	var srcs []src
	for i, n := range c.nodes {
		srcs = append(srcs, src{i, n.shim.Trace()})
	}
	c.mu.Lock()
	for k, evs := range c.retired {
		srcs = append(srcs, src{c.retIdx[k], evs})
	}
	c.mu.Unlock()
	type row struct {
		t   time.Time
		seq int
		ev  q4Event
	}
	var rows []row
	extra := uint64(1 << 40)
	for si, s := range srcs {
		base := uint64(si+1) << 32
		for _, e := range s.evs {
			m := e.Msg()
			qm := q4Msg{Class: q4Class(m.Class), Epoch: m.Epoch, Round: m.Round, Author: m.Author, Statement: m.Statement, Raw: m.Raw}
			ev := q4Event{Seq: e.Seq, SendID: base + e.SendID, From: pid(e.From), To: pid(e.To), Msg: qm, Rule: e.Rule}
			switch e.Kind {
			case "attempt", "drop", "hold", "deliver":
				ev.Kind = e.Kind
				if e.Kind == "deliver" {
					ev.DeliveryID = base + e.DeliveryID
				}
				rows = append(rows, row{e.Time, si, ev})
			case "equivocate":
				extra++
				at, dl := ev, ev
				at.Kind, at.SendID, at.From = "attempt", extra, pid(m.Author)
				dl.Kind, dl.SendID, dl.From, dl.DeliveryID = "deliver", extra, pid(m.Author), extra
				rows = append(rows, row{e.Time, si, at}, row{e.Time, si, dl})
			}
		}
	}
	slices.SortStableFunc(rows, func(a, b row) int {
		if d := a.t.Compare(b.t); d != 0 {
			return d
		}
		return a.seq - b.seq
	})
	var tr q4Trace
	for _, r := range rows {
		tr = append(tr, r.ev)
	}
	return tr
}

// finish checks every shim for harness faults and unmet requirements and verifies the whole trace offline.
func (c *q4bLive) finish(malformed ...uint64) q4Trace {
	c.t.Helper()
	for _, n := range c.nodes {
		require.NoError(c.t, n.shim.Finish(), n.name)
	}
	tr := c.trace()
	views := c.views()
	require.NotEmpty(c.t, tr)
	got := tr.Malformed(views)
	require.ElementsMatch(c.t, malformed, got, "the oracle flags exactly the injected malformed sends")
	return tr
}

// committedRound is the node's committed head round.
func (c *q4bLive) committedRound(name string) uint64 { return c.state(name).Committed }

// warm waits until every named node committed at least n rounds beyond the epoch's anchor.
func (c *q4bLive) warm(n uint64, names ...string) {
	c.t.Helper()
	slot := c.nodes[0].r.manager.epochAnchor.Slot
	require.Eventually(c.t, func() bool {
		for _, name := range names {
			if c.committedRound(name) < slot+n {
				return false
			}
		}
		return true
	}, q4bDeadline, 50*time.Millisecond, "the cluster commits live in the activated epoch")
}
