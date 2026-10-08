package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4replay"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// Q4 #51 (A) fault rows. Coverage label: IN-PROCESS, root only (no EVM, no aggregator shards). Real ConsensusManager run loops, the
// production selector (root-wrr-v1 activated in the test only), real bolt stores and the production verifiers for the honest
// members; scheme 1, the supported live path (a live scheme 2 cluster from genesis needs the Q3 activation work and is NOT claimed
// here). Setup is test-local: the weighted policy activation and the fixed keys are fixtures, not evidence of Q3 coupled activation.
// A row's outcome (PASS/FAIL) is reported separately from its assumption class (IN-BOUND / OUTSIDE-ASSUMPTIONS).

// q4Slots bounds how many live clusters run at once, so that the frozen deadlines hold under the load the rows themselves create.
var q4Slots = make(chan struct{}, 3)

const (
	q4Deadline     = 120 * time.Second // frozen: recovery of an in-bound row, never widened after a stall
	q4Delta        = 5 * time.Second   // post-release delivery bound
	q4StallWindow  = 3500 * time.Millisecond
	q4Quiesce      = 2500 * time.Millisecond
	q4RecoverRound = 3 // ordinary root commits and, in a coupled lane, paid EVM blocks required after a fault
)

type q4Run struct {
	t     *testing.T
	r     *q4Roster
	c     *skewedCluster
	s     *q4Sched
	man   *q4Manifest
	byz   map[string]bool // peer ID string of the Byzantine identities
	start time.Time

	mu     sync.Mutex
	seen   map[int][]q4Commit
	blocks map[int]map[uint64]q4Block
	chains map[int]map[uint64]q4Block
	faults []error
	// windows are the progress and stall expectations of the run, judged offline by the replay checker against the frozen deadline.
	windows []q4replay.Window
	// report is the replay checker's verdict on the exported run, set by finish.
	report *q4replay.Report
}

var (
	errQ4ChainConflict = errors.New("q4 finality: conflicting committed history")
	errQ4ChainMissing  = errors.New("q4 finality: missing committed ancestry")
	errQ4Recovery      = errors.New("q4 recovery: insufficient post-fault commits")
)

// q4Block owns its hash; no pointer into the mutable, pruning block store is retained.
type q4Block struct {
	Hash   []byte
	Parent uint64
}

type q4Commit struct {
	Round uint64
	At    time.Time
}

// newQ4Run builds a cluster over the roster with the manifest's unavailable and Byzantine identities not running a manager. The
// Byzantine identities are on the network (they can speak through Inject) but run no consensus loop: they withhold unless told to speak.
func newQ4Run(t *testing.T, r *q4Roster, man q4Manifest, rules []*q4Rule, triggers []*q4Trigger, syncAll bool) *q4Run {
	t.Helper()
	man.Seed, man.Set, man.Coverage, man.Deadline, man.Delta = r.Seed, r.Set.Name, "IN-PROCESS", q4Deadline, q4Delta
	require.NoError(t, man.Validate(r))
	var sync []int
	if syncAll {
		for i := range r.Entities {
			sync = append(sync, i)
		}
	}
	c := newClusterOf(t, clusterSpec{roster: r, weightedLeader: true}, sync...)
	run := &q4Run{t: t, r: r, c: c, man: &man, byz: map[string]bool{}, seen: map[int][]q4Commit{}, blocks: map[int]map[uint64]q4Block{}, chains: map[int]map[uint64]q4Block{}, start: time.Now()}
	for _, n := range q4Names(man.Byzantine, "root") {
		run.byz[r.Entities[r.Index(n)].ID.String()] = true
	}
	run.s = newQ4Sched(rules, triggers)
	c.net.sched = run.s
	t.Logf("manifest: set=%s seed=%s coverage=%s class=%s weights=%v W=%d Q=%d F=%d byzantine=%v unavailable=%v responsive=%d deadline=%s delta=%s",
		r.Set.Name, r.Seed, man.Coverage, man.Class(r), r.Weights, r.Total(), r.Quorum(), r.Faulty(), man.Byzantine, man.Unavailable, man.Responsive(r), man.Deadline, man.Delta)
	for i := range c.nodes {
		run.observeStore(i)
	}
	return run
}

// idx resolves identity names to cluster indices; fault targets are never positional.
func (run *q4Run) idx(names ...string) []int {
	out := make([]int, len(names))
	for i, n := range names {
		out[i] = run.r.Index(n)
		require.GreaterOrEqual(run.t, out[i], 0, n)
	}
	return out
}

func (run *q4Run) ids(names ...string) []peer.ID {
	var out []peer.ID
	for _, i := range run.idx(names...) {
		out = append(out, run.r.Entities[i].ID)
	}
	return out
}

// running are the names that run a manager: neither unavailable nor Byzantine.
func (run *q4Run) running() []string {
	var out []string
	for _, n := range run.r.Names() {
		skip := false
		for _, tg := range append(slices.Clone(run.man.Byzantine), run.man.Unavailable...) {
			skip = skip || (tg.Name == n && tg.Role == "root")
		}
		if !skip {
			out = append(out, n)
		}
	}
	return out
}

func (run *q4Run) startNodes(names ...string) {
	run.t.Helper()
	indices := run.idx(names...)
	run.c.start(indices...)
}

// startAll starts every running identity and puts the Byzantine identities on the network.
func (run *q4Run) startAll() {
	run.t.Helper()
	for _, n := range q4Names(run.man.Byzantine, "root") {
		run.c.offline.Delete(run.r.Entities[run.r.Index(n)].ID)
	}
	run.startNodes(run.running()...)
}

func (run *q4Run) stopNode(name string) {
	i := run.idx(name)[0]
	run.c.stop(i)
}

// q4HistoryStore observes successful writes synchronously. Snapshot the block before the
// root write prunes durable history; record a commit only after that write succeeds.
// Embedding BoltDB preserves all optional storage capabilities (including Close).
type q4HistoryStore struct {
	storage.BoltDB
	run   *q4Run
	index int
}

func (run *q4Run) observeStore(i int) {
	db, ok := run.c.nodes[i].db.(storage.BoltDB)
	require.True(run.t, ok)
	run.c.nodes[i].db = &q4HistoryStore{BoltDB: db, run: run, index: i}
}

func (s *q4HistoryStore) WriteBlock(b *storage.ExecutedBlock, root bool) error {
	return s.observed(b, root, func() error { return s.BoltDB.WriteBlock(b, root) })
}

// CommitBlock is the atomic commit of a block with its records and cut; the observation is the same as for the plain root write.
func (s *q4HistoryStore) CommitBlock(b *storage.ExecutedBlock, recs []rootrecords.Record, cut *storage.CutEntry) error {
	return s.observed(b, true, func() error { return s.BoltDB.CommitBlock(b, recs, cut) })
}

func (s *q4HistoryStore) observed(b *storage.ExecutedBlock, root bool, write func() error) error {
	hash, err := b.BlockData.Hash(crypto.SHA256)
	if err != nil {
		return err
	}
	block := q4Block{Hash: slices.Clone(hash), Parent: b.GetParentRound()}
	// Serialize the write and observation with mark: a completed pre-mark root write
	// can never appear later as a post-mark commit, even if the head was not sampled.
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	if err := write(); err != nil {
		return err
	}
	s.run.recordBlock(s.index, b.GetRound(), block, root)
	return nil
}

// recordBlock is called with run.mu held. Retain locally executed ancestry too:
// a commit may finalize several pending ancestors at once. Recovery may install a
// checkpoint whose earlier blocks this node never executed; it remains a boundary,
// and chainsAgree refuses to skip an older head beyond that boundary.
func (run *q4Run) recordBlock(i int, round uint64, b q4Block, root bool) {
	if run.blocks[i] == nil {
		run.blocks[i] = map[uint64]q4Block{}
	}
	if run.chains[i] == nil {
		run.chains[i] = map[uint64]q4Block{}
	}
	b.Hash = slices.Clone(b.Hash)
	run.blocks[i][round] = b
	if !root {
		return
	}
	for at := round; at > 1; {
		block, ok := run.blocks[i][at]
		if !ok {
			break
		} // a recovery checkpoint boundary, not a skipped comparison
		if old, exists := run.chains[i][at]; exists {
			if !bytes.Equal(old.Hash, block.Hash) {
				run.faults = append(run.faults, fmt.Errorf("%w: node %d round %d", errQ4ChainConflict, i, at))
			}
			break
		}
		run.chains[i][at] = block
		if block.Parent >= at {
			run.faults = append(run.faults, errQ4ChainMissing)
			break
		}
		at = block.Parent
	}
	obs := run.seen[i]
	if round > 1 && (len(obs) == 0 || round > obs[len(obs)-1].Round) {
		run.seen[i] = append(obs, q4Commit{round, time.Now()})
	}
}

// q4Mark freezes both the observation counts and the start of the recovery deadline.
type q4Mark struct {
	At     time.Time
	Counts map[int]int
}

func (run *q4Run) mark() q4Mark {
	run.mu.Lock()
	defer run.mu.Unlock()
	m := q4Mark{At: time.Now(), Counts: map[int]int{}}
	for i := range run.r.Entities {
		m.Counts[i] = len(run.seen[i])
	}
	return m
}

// commitsSince counts distinct successful ordinary committed-root writes. A QC,
// TC, round advance, or reinstall of the same root never counts as a new commit.
func (run *q4Run) commitsSince(i int, m q4Mark) []q4Commit {
	run.mu.Lock()
	defer run.mu.Unlock()
	return slices.Clone(run.seen[i][m.Counts[i]:])
}

func (run *q4Run) recovery(m q4Mark, n int, names ...string) error {
	for _, i := range run.idx(names...) {
		obs := run.commitsSince(i, m)
		if len(obs) < n || obs[n-1].At.After(m.At.Add(run.man.Deadline)) {
			return fmt.Errorf("%w: %s needs %d", errQ4Recovery, run.r.Entities[i].Name, n)
		}
	}
	return nil
}

// waitRecovery uses the same predicate and frozen post-mark deadline for live rows
// and the early-stop regression. It returns a sentinel refusal for negative tests.
func (run *q4Run) waitRecovery(ctx context.Context, m q4Mark, n int, names ...string) error {
	timer := time.NewTimer(max(time.Until(m.At.Add(run.man.Deadline)), 0))
	defer timer.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := run.recovery(m, n, names...); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", run.recovery(m, n, names...), ctx.Err())
		case <-timer.C:
			return run.recovery(m, n, names...)
		case <-tick.C:
		}
	}
}

// requireRecovery waits until every named node has n new ordinary commits.
func (run *q4Run) requireRecovery(m q4Mark, n int, names ...string) (first, nth time.Duration) {
	run.t.Helper()
	require.NoError(run.t, run.waitRecovery(context.Background(), m, n, names...), "post-fault recovery within %s", run.man.Deadline)
	run.recordWindow(q4replay.Window{Name: "recovery", Expect: "progress", Nodes: names, StartMs: m.At.UnixMilli(), MinCommits: n})
	for _, i := range run.idx(names...) {
		obs := run.commitsSince(i, m)
		first, nth = max(first, obs[0].At.Sub(m.At)), max(nth, obs[n-1].At.Sub(m.At))
	}
	return first, nth
}

type q4State struct{ Round, HighQC, Committed uint64 }

func (run *q4Run) state(i int) q4State {
	return q4State{run.c.manager(i).pacemaker.GetCurrentRound(), run.c.highQCRound(i), run.c.committedRound(i)}
}

// requireStalled is the explicit stall assertion: pre-issued evidence is drained (no change for q4Quiesce), then nothing moves for
// q4StallWindow, which is more than three local timeouts: no new QC, no round advance by a TC, no commit. It returns the state.
func (run *q4Run) requireStalled(names ...string) map[int]q4State {
	run.t.Helper()
	indices := run.idx(names...)
	snap := func() map[int]q4State {
		out := map[int]q4State{}
		for _, i := range indices {
			out[i] = run.state(i)
		}
		return out
	}
	last, stableSince := snap(), time.Now()
	require.Eventually(run.t, func() bool {
		if now := snap(); fmt.Sprint(now) != fmt.Sprint(last) {
			last, stableSince = now, time.Now()
		}
		return time.Since(stableSince) >= q4Quiesce
	}, 60*time.Second, 50*time.Millisecond, "pre-issued evidence drains")
	from := time.Now()
	time.Sleep(q4StallWindow)
	for _, i := range indices {
		require.Equal(run.t, last[i], run.state(i), "%s: no fresh QC, TC advance or commit below the quorum", run.r.Entities[i].Name)
	}
	run.recordWindow(q4replay.Window{Name: "stall", Expect: "stall", Nodes: names, StartMs: from.UnixMilli(), EndMs: time.Now().UnixMilli()})
	return last
}

// chainsAgree compares immutable finalized history, including blocks already
// pruned by either store. It also requires the lower committed head to occur in
// the higher node's recorded ancestry, so an empty intersection cannot pass.
func (run *q4Run) chainsAgree(names ...string) error {
	indices := run.idx(names...)
	// Check the current stores against their immutable observations as well. A
	// deliberately corrupted retained head must not be hidden by its earlier copy.
	heads := map[int]q4Block{}
	rounds := map[int]uint64{}
	for _, i := range indices {
		state, err := run.c.manager(i).blockStore.GetState()
		if err != nil {
			return fmt.Errorf("%w: %v", errQ4ChainMissing, err)
		}
		b := state.CommittedHead.Block
		hash, err := b.Hash(crypto.SHA256)
		if err != nil {
			return err
		}
		heads[i], rounds[i] = q4Block{Hash: hash, Parent: b.GetParentRound()}, b.Round
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	for i, b := range heads {
		if rounds[i] <= 1 {
			return errQ4ChainMissing
		}
		old, ok := run.chains[i][rounds[i]]
		if !ok {
			return errQ4ChainMissing
		}
		if !bytes.Equal(old.Hash, b.Hash) || old.Parent != b.Parent {
			return fmt.Errorf("%w: %s's stored head at round %d changed", errQ4ChainConflict, run.r.Entities[i].Name, rounds[i])
		}
	}
	if err := errors.Join(run.faults...); err != nil {
		return err
	}
	for x, i := range indices {
		for _, j := range indices[x+1:] {
			if len(run.seen[i]) == 0 || len(run.seen[j]) == 0 {
				return errQ4ChainMissing
			}
			left, right := i, j
			ri := run.seen[i][len(run.seen[i])-1].Round
			rj := run.seen[j][len(run.seen[j])-1].Round
			if ri > rj {
				left, right = j, i
			}
			lower := min(ri, rj)
			if _, ok := run.chains[right][lower]; !ok {
				return fmt.Errorf("%w: %s lacks %s's committed round %d", errQ4ChainMissing, run.r.Entities[right].Name, run.r.Entities[left].Name, lower)
			}
			for round, a := range run.chains[i] {
				if b, ok := run.chains[j][round]; ok && (!bytes.Equal(a.Hash, b.Hash) || a.Parent != b.Parent) {
					return fmt.Errorf("%w: round %d, %s and %s", errQ4ChainConflict, round, run.r.Entities[i].Name, run.r.Entities[j].Name)
				}
			}
		}
	}
	return nil
}

func (run *q4Run) requireChainsAgree(names ...string) {
	run.t.Helper()
	require.NoError(run.t, run.chainsAgree(names...))
}

// requireQCWeight checks the node's highest QC with the oracle: signers are members, each signature verifies over the seal bytes with
// the fixture key, the vote info hash matches, and the signed weight reaches the independently computed quorum.
func (run *q4Run) requireQCWeight(name string) uint64 {
	run.t.Helper()
	qc := run.c.manager(run.idx(name)[0]).blockStore.GetHighQc()
	require.NotNil(run.t, qc)
	view := q4View(run.r, qc.VoteInfo.Epoch)
	seal, err := qc.LedgerCommitInfo.SigBytes()
	require.NoError(run.t, err)
	hash, err := qc.VoteInfo.Hash(crypto.SHA256)
	require.NoError(run.t, err)
	require.Equal(run.t, hash, []byte(qc.LedgerCommitInfo.PreviousHash), "the seal signs the vote info")
	var weight uint64
	for id, sig := range qc.Signatures {
		v, ok := view.Verifiers[id]
		require.True(run.t, ok, "signer %s is a member", id)
		require.NoError(run.t, v.VerifyBytes(sig, seal), "signer %s signed the seal", id)
		weight += view.Weights[id]
	}
	require.GreaterOrEqual(run.t, weight, view.Quorum(), "the QC of round %d carries the quorum weight", qc.GetRound())
	return weight
}

// finish closes the adapter, reports required triggers and rules that did not fire, and applies the trace oracle: the trace
// accounts for every attempt, the malformed messages are exactly the injected ones (bad), and no honest identity signed two
// statements. A Byzantine author's equivocation is classified, not counted against the honest set.
func (run *q4Run) finish(bad ...uint64) q4Trace {
	run.t.Helper()
	require.NoError(run.t, run.s.Finish(), "every required injection happened")
	tr := run.s.Trace()
	require.Empty(run.t, tr.Unaccounted(), "no silent loss")
	require.NotEmpty(run.t, tr.Statements(), "premise: signed votes or timeouts were traced")
	views := map[uint64]q4EpochView{1: q4View(run.r, 1)}
	require.ElementsMatch(run.t, bad, tr.Malformed(views), "the malformed messages are exactly the injected ones")
	if len(bad) == 0 {
		require.NoError(run.t, tr.Verify(views))
	}
	require.Empty(run.t, tr.HonestDoubleSigns(views, run.byz), "no honest double signing")
	if len(run.byz) == 0 { // the harness's wire observer does not check signatures: with injected forgeries only the oracle above decides
		run.c.requireNoDoubleSign()
	}
	run.report = run.export(tr, len(bad))
	if len(run.man.Byzantine) == 0 {
		require.NoError(run.t, run.report.ExpectEquivocators(), "the checker finds no equivocator in a run with no Byzantine identity")
	}
	return tr
}

func q4Slot(t *testing.T) {
	q4Slots <- struct{}{}
	t.Cleanup(func() { <-q4Slots })
}

// ---- rows ----

type q4Row struct {
	Name        string
	Set         q4Set
	Arrangement []uint64
	Offline     []string // unavailable: no manager
	Cut         []string // isolated by hold rules, then released
	CutDir      string   // "both" or "out" (delay only the cut identities' own traffic)
	Byzantine   []string // silent Byzantine identities (equivocation rows add injection)
	Heal        bool     // after a stall: start/release the missing identities and require recovery
}

func (row q4Row) manifest() q4Manifest {
	var m q4Manifest
	for _, n := range row.Offline {
		m.Unavailable = append(m.Unavailable, q4Target{n, "root"})
	}
	for _, n := range row.Byzantine {
		m.Byzantine = append(m.Byzantine, q4Target{n, "root"})
	}
	return m
}

func (run *q4Run) cutRules(names []string, dir string) []*q4Rule {
	if len(names) == 0 {
		return nil
	}
	var inside, outside []peer.ID
	for _, e := range run.r.Entities {
		if slices.Contains(names, e.Name) {
			inside = append(inside, e.ID)
		} else {
			outside = append(outside, e.ID)
		}
	}
	rules := []*q4Rule{{Name: "cut-out", Match: q4Match{From: inside, To: outside}, Action: q4Hold, Require: true}}
	if dir == "both" {
		rules = append(rules, &q4Rule{Name: "cut-in", Match: q4Match{From: outside, To: inside}, Action: q4Hold, Require: true})
	}
	return rules
}

// runRow executes one row. Progress is expected exactly when the responsive weight (not Byzantine, not offline, not cut) is at least
// the quorum: then the row requires q4RecoverRound commits within the frozen deadline; otherwise it requires an explicit stall,
// and after Heal the recovery with the restored identities.
func runQ4Row(t *testing.T, row q4Row) {
	r := q4NewRoster(t, row.Set, "q4-"+row.Set.Name, row.Arrangement)
	man := row.manifest()
	run := newQ4Run(t, r, man, nil, nil, false)
	run.s.mu.Lock()
	run.s.rules = run.cutRules(row.Cut, row.CutDir)
	run.s.mu.Unlock()
	responsive := r.Total() - r.Weight(append(slices.Clone(row.Offline), append(slices.Clone(row.Cut), row.Byzantine...)...)...)
	expectProgress := responsive >= r.Quorum()
	t.Logf("row %q: responsive weight %d, quorum %d, progress expected: %v", row.Name, responsive, r.Quorum(), expectProgress)

	base := run.mark()
	run.startAll()
	online := run.running()
	if expectProgress {
		// responsive identities: the running ones that are not cut
		var live []string
		for _, n := range online {
			if !slices.Contains(row.Cut, n) {
				live = append(live, n)
			}
		}
		first, third := run.requireRecovery(base, q4RecoverRound, live...)
		t.Logf("row %q: first commit %s, third commit %s", row.Name, first, third)
		run.requireQCWeight(live[0])
		run.requireChainsAgree(live...)
	} else {
		run.requireStalled(online...)
		for _, n := range online {
			require.Zero(t, len(run.commitsSince(run.idx(n)[0], base)), "no ordinary commit below the quorum")
		}
	}
	if len(row.Cut) > 0 {
		require.NoError(t, run.s.requireHits("cut-out"))
		if row.CutDir == "both" {
			require.NoError(t, run.s.requireHits("cut-in"))
		}
		require.Positive(t, run.s.Held(""), "premise: the isolation held traffic")
		before := run.state(run.idx(online[0])[0]).Committed
		released, err := run.s.release(run.c.net, "", q4FIFO)
		require.NoError(t, err)
		run.s.RemoveRule("cut-out")
		run.s.RemoveRule("cut-in")
		t.Logf("row %q: released %d stale messages", row.Name, released)
		heal := run.mark()
		run.requireRecovery(heal, q4RecoverRound, online...)
		require.GreaterOrEqual(t, run.state(run.idx(online[0])[0]).Committed, before, "the release does not roll the committed head back")
		run.requireChainsAgree(online...)
	}
	if row.Heal && len(row.Offline) > 0 {
		heal := run.mark()
		run.startNodes(row.Offline...)
		run.requireRecovery(heal, q4RecoverRound, append(slices.Clone(online), row.Offline...)...)
		run.requireChainsAgree(append(slices.Clone(online), row.Offline...)...)
	}
	run.finish()
}

func TestQ4Fault(t *testing.T) {
	a, b := q4SetA, q4SetB
	row := func(name string, set q4Set, arr []uint64, f func(*q4Row)) q4Row {
		rw := q4Row{Name: name, Set: set, Arrangement: arr, CutDir: "both"}
		if f != nil {
			f(&rw)
		}
		return rw
	}
	// role names depend on the arrangement: they are assigned by weight class and canonical position, so a row is written in
	// role names and holds for every placement of the heavy identity
	all := func(t *testing.T, rows []q4Row) {
		for _, rw := range rows {
			t.Run(rw.Name, func(t *testing.T) {
				t.Parallel()
				q4Slot(t)
				runQ4Row(t, rw)
			})
		}
	}

	t.Run("no-fault controls at the same load", func(t *testing.T) {
		var rows []q4Row
		rows = append(rows, row("A", a, a.Weights, nil), row("B", b, b.Weights, nil), row("many-small", q4SetManySmall, q4SetManySmall.Weights, nil))
		all(t, rows)
	})

	t.Run("A: heavy plus one light, all four heavy placements and three light choices", func(t *testing.T) {
		var rows []q4Row
		for _, arr := range q4Arrangements(a.Weights) {
			for _, keep := range []string{"a", "b", "c"} {
				var off []string
				for _, l := range []string{"a", "b", "c"} {
					if l != keep {
						off = append(off, l)
					}
				}
				rows = append(rows, row(fmt.Sprintf("%v keep %s", arr, keep), a, arr, func(rw *q4Row) { rw.Offline = off }))
			}
		}
		all(t, rows)
	})

	t.Run("A: heavy offline and heavy alone stall, then recover when the missing identities return", func(t *testing.T) {
		var rows []q4Row
		for _, arr := range q4Arrangements(a.Weights) {
			rows = append(rows, row(fmt.Sprintf("%v heavy offline", arr), a, arr, func(rw *q4Row) { rw.Offline, rw.Heal = []string{"H"}, true }),
				row(fmt.Sprintf("%v heavy alone", arr), a, arr, func(rw *q4Row) { rw.Offline, rw.Heal = []string{"a", "b", "c"}, true }))
		}
		all(t, rows)
	})

	t.Run("B: honest 3+3+1 progresses for every canonical arrangement", func(t *testing.T) {
		var rows []q4Row
		for _, arr := range q4Arrangements(b.Weights) {
			rows = append(rows, row(fmt.Sprintf("%v n2 offline", arr), b, arr, func(rw *q4Row) { rw.Offline = []string{"n2"} }))
		}
		all(t, rows)
	})

	t.Run("B: the other light subset progresses, either heavy offline stalls and recovers", func(t *testing.T) {
		var rows []q4Row
		for _, arr := range [][]uint64{{3, 3, 2, 1}, {1, 2, 3, 3}, {3, 2, 1, 3}, {2, 3, 3, 1}} {
			rows = append(rows,
				row(fmt.Sprintf("%v n1 offline", arr), b, arr, func(rw *q4Row) { rw.Offline = []string{"n1"} }),
				row(fmt.Sprintf("%v H1 offline", arr), b, arr, func(rw *q4Row) { rw.Offline, rw.Heal = []string{"H1"}, true }),
				row(fmt.Sprintf("%v H2 offline", arr), b, arr, func(rw *q4Row) { rw.Offline, rw.Heal = []string{"H2"}, true }))
		}
		all(t, rows)
	})

	t.Run("light partitions and delays, then heal by releasing the stale traffic", func(t *testing.T) {
		rows := []q4Row{
			// A: two isolated lights leave 7; all three give 6|3 and stall
			row("A two lights isolated", a, a.Weights, func(rw *q4Row) { rw.Cut = []string{"a", "b"} }),
			row("A three lights isolated", a, a.Weights, func(rw *q4Row) { rw.Cut = []string{"a", "b", "c"} }),
			// B: one light isolated leaves 8, two leave 7 ... both lights isolated (3) leaves 6 on one side
			row("B n1 isolated", b, b.Weights, func(rw *q4Row) { rw.Cut = []string{"n1"} }),
			row("B n2 isolated", b, b.Weights, func(rw *q4Row) { rw.Cut = []string{"n2"} }),
			row("B both lights isolated", b, b.Weights, func(rw *q4Row) { rw.Cut = []string{"n1", "n2"} }),
			// delays: only the delayed identities' own traffic is held, they still hear the others
			row("A two lights delayed", a, a.Weights, func(rw *q4Row) { rw.Cut, rw.CutDir = []string{"a", "b"}, "out" }),
			row("A heavy delayed", a, a.Weights, func(rw *q4Row) { rw.Cut, rw.CutDir = []string{"H"}, "out" }),
			row("B weight 2 delayed", b, b.Weights, func(rw *q4Row) { rw.Cut, rw.CutDir = []string{"n2"}, "out" }),
			row("B one heavy delayed", b, b.Weights, func(rw *q4Row) { rw.Cut, rw.CutDir = []string{"H1"}, "out" }),
		}
		all(t, rows)
	})

	t.Run("#399 outage control: heavy offline with exactly the quorum left", func(t *testing.T) {
		t.Parallel()
		q4Slot(t)
		r := q4DefaultRoster(t, q4SetOutageCtrl)
		run := newQ4Run(t, r, q4Manifest{Unavailable: []q4Target{{"H", "root"}}}, nil, nil, false)
		require.EqualValues(t, r.Quorum(), r.Weight("l1", "l2", "l3", "l4"), "premise: the four lights weigh exactly 8")
		base := run.mark()
		run.startAll()
		run.requireRecovery(base, q4RecoverRound, "l1", "l2", "l3", "l4")
		tc, err := run.c.manager(run.idx("l1")[0]).blockStore.GetLastTC()
		require.NoError(t, err)
		require.NotNil(t, tc, "the heavy identity's rounds are left by actual timeout certificates")
		var weight uint64
		for id := range tc.Signatures {
			w, ok := q4View(r, 1).Weights[id]
			require.True(t, ok)
			weight += w
		}
		require.GreaterOrEqual(t, weight, r.Quorum(), "the TC is signed by at least weight 8")
		require.NoError(t, tc.Verify(run.c.nodes[run.idx("l1")[0]].tbStore))
		run.requireQCWeight("l1")
		run.finish()
	})

	t.Run("restarts: heavy, then the whole quorum, over the same fsynced stores", func(t *testing.T) {
		t.Parallel()
		q4Slot(t)
		r := q4DefaultRoster(t, q4SetA)
		run := newQ4Run(t, r, q4Manifest{}, nil, nil, true)
		base := run.mark()
		run.startAll()
		run.requireRecovery(base, q4RecoverRound, r.Names()...)

		// the heavy identity restarts: 3 of 9 remain, an explicit stall; the stores reopen and the cluster recovers
		hi := run.idx("H")[0]
		votedBefore := run.c.nodes[hi].db.GetHighestVotedRound()
		run.stopNode("H")
		run.requireStalled("a", "b", "c")
		run.c.reopen(hi)
		run.observeStore(hi)
		heal := run.mark()
		run.startNodes("H")
		run.requireRecovery(heal, q4RecoverRound, r.Names()...)
		require.GreaterOrEqual(t, run.c.manager(hi).safety.storage.GetHighestVotedRound(), votedBefore, "the restarted heavy identity reads its durable decisions")
		run.requireChainsAgree(r.Names()...)

		// every identity restarts together
		committed := run.state(hi).Committed
		for _, n := range r.Names() {
			run.stopNode(n)
		}
		for _, n := range r.Names() {
			run.c.reopen(run.idx(n)[0])
			run.observeStore(run.idx(n)[0])
		}
		heal = run.mark()
		run.startNodes(r.Names()...)
		run.requireRecovery(heal, q4RecoverRound, r.Names()...)
		require.Greater(t, run.state(hi).Committed, committed, "the quorum-wide restart continues above the committed head")
		run.requireChainsAgree(r.Names()...)
		run.finish()
	})
}

// ---- Byzantine signer rows ----

// q4Equivocation are the send IDs (one per honest receiver) of what the isolated Byzantine fixture signer sent. The signer holds only
// the keys of identities the manifest declares Byzantine and never touches an honest identity's SafetyModule.
type q4Equivocation struct {
	V1, V2, Forged, Mixed, Dup []uint64 // send IDs, one per honest receiver
}

// equivocate makes the declared Byzantine identity speak: a well formed vote for the observed round, a second vote that differs in
// the signed state (equivocation), the first again (a rebroadcast), a vote signed by a key that is not the claimed author's (forged)
// and a vote whose seal does not match its vote info (mixed statement), each to every honest identity through the adapter.
func (run *q4Run) equivocate(byz string, template *abdrc.VoteMsg, honest []string) q4Equivocation {
	run.t.Helper()
	e := run.r.Entities[run.r.Index(byz)]
	other := run.r.Entities[run.r.Index(honest[0])] // the honest identity the forgery claims to be
	clone := func() *abdrc.VoteMsg {
		var v abdrc.VoteMsg
		raw, err := types.Cbor.Marshal(template)
		require.NoError(run.t, err)
		require.NoError(run.t, types.Cbor.Unmarshal(raw, &v))
		v.Author, v.Signature = e.ID.String(), nil
		return &v
	}
	seal := func(v *abdrc.VoteMsg) {
		h, err := v.VoteInfo.Hash(crypto.SHA256)
		require.NoError(run.t, err)
		v.LedgerCommitInfo.PreviousHash = h
	}
	v1 := clone()
	require.NoError(run.t, v1.Sign(e.Signer))
	v2 := clone()
	v2.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{0xbb}, 32)
	seal(v2)
	require.NoError(run.t, v2.Sign(e.Signer))
	forged := clone()
	forged.Author = other.ID.String() // frames an honest identity ...
	forged.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{0xcc}, 32)
	seal(forged)
	require.NoError(run.t, forged.Sign(e.Signer)) // ... but is signed by the Byzantine key
	mixed := clone()
	mixed.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{0xdd}, 32) // the seal still signs the old vote info
	require.NoError(run.t, mixed.Sign(e.Signer))

	var out q4Equivocation
	send := func(v *abdrc.VoteMsg) (ids []uint64) {
		for _, h := range honest {
			id, err := run.s.Inject(run.c.net, e.ID, run.r.Entities[run.r.Index(h)].ID, v)
			require.NoError(run.t, err)
			ids = append(ids, id)
		}
		return ids
	}
	out.V1, out.V2, out.Dup, out.Forged, out.Mixed = send(v1), send(v2), send(clonedVote(run.t, v1)), send(forged), send(mixed)
	return out
}

func clonedVote(t *testing.T, v *abdrc.VoteMsg) *abdrc.VoteMsg {
	var out abdrc.VoteMsg
	raw, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, types.Cbor.Unmarshal(raw, &out))
	return &out
}

func TestQ4FaultByzantine(t *testing.T) {
	type byzRow struct {
		name    string
		set     q4Set
		byz     []string
		inBound bool
	}
	rows := []byzRow{
		{"A: two Byzantine lights equivocate, honest H+light progress", q4SetA, []string{"b", "c"}, true},
		{"B: Byzantine weight 2 equivocates, honest 3+3+1 progress", q4SetB, []string{"n2"}, true},
		{"many-small: eight Byzantine lights equivocate, honest H+light progress", q4SetManySmall, q4Lights("l", 8), true},
		{"A: Byzantine heavy equivocates and withholds, outside the assumptions: quorum lost", q4SetA, []string{"H"}, false},
		{"B: Byzantine heavy equivocates and withholds, outside the assumptions: quorum lost", q4SetB, []string{"H1"}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			q4Slot(t)
			r := q4DefaultRoster(t, row.set)
			var targets []q4Target
			for _, n := range row.byz {
				targets = append(targets, q4Target{n, "root"})
			}
			// the trigger is an observed signed event of an honest identity: a vote of round 4 when the honest weight can progress, a
			// timeout when it cannot (a stalled cluster never votes)
			trig := &q4Trigger{Name: "honest-event", Match: q4Match{Class: q4Vote, RoundMin: 4}}
			if !row.inBound {
				trig.Match = q4Match{Class: q4Timeout, RoundMin: 2}
			}
			run := newQ4Run(t, r, q4Manifest{Byzantine: targets}, nil, []*q4Trigger{trig}, false)
			require.Equal(t, map[bool]string{true: "IN-BOUND", false: "OUTSIDE-ASSUMPTIONS"}[row.inBound], run.man.Class(r))
			honest := run.running()
			run.startAll()
			require.Eventually(t, func() bool { return run.s.Fired(trig.Name) > 0 }, run.man.Deadline, 10*time.Millisecond, "the honest event that triggers the injection was observed")
			bad, postFault := run.injectAndMark(row.byz, honest)
			if row.inBound {
				run.requireRecovery(postFault, q4RecoverRound, honest...) // strictly after all injections
				run.requireQCWeight(honest[0])
				run.requireChainsAgree(honest...)
			} else {
				// the honest remainder (3 of 9, 6 of 9) is below 7: after the pre-issued evidence drains nothing moves
				run.requireStalled(honest...)
			}
			tr := run.finish(bad...)
			equivocators := tr.Equivocators(map[uint64]q4EpochView{1: q4View(r, 1)})
			require.NoError(t, run.report.ExpectEquivocators(row.byz...), "the offline checker, from the bytes, finds exactly the declared Byzantine members equivocating")
			require.Len(t, equivocators, len(row.byz), "exactly the declared Byzantine authors equivocated")
			for _, n := range row.byz {
				require.Contains(t, equivocators, r.Entities[r.Index(n)].ID.String())
			}
		})
	}
}

// injectAndMark is shared with the early-stop control: only successful committed
// roots written strictly after the final Byzantine send can satisfy recovery.
func (run *q4Run) injectAndMark(byzantine, honest []string) ([]uint64, q4Mark) {
	template := run.honestVote(honest)
	var bad []uint64
	for _, n := range byzantine {
		sent := run.equivocate(n, template, honest)
		bad = append(append(bad, sent.Forged...), sent.Mixed...)
	}
	return bad, run.mark()
}

// TestQ4FaultControls commits the reviewer's deliberately corrupted-evidence and
// early-stop controls. They test the exact checkers used by the live fault rows.
func TestQ4FaultControls(t *testing.T) {
	t.Run("historical hash conflict after pruning", func(t *testing.T) {
		r := q4DefaultRoster(t, q4SetA)
		run := newQ4Run(t, r, q4Manifest{}, nil, nil, false)
		base := run.mark()
		run.startNodes("H", "a")
		run.requireRecovery(base, 4, "H", "a")
		run.stopNode("a")
		ai, hi := run.idx("a")[0], run.idx("H")[0]
		round := run.c.committedRound(ai)
		b, err := run.c.manager(ai).blockStore.Block(round)
		require.NoError(t, err)
		before := slices.Clone(run.chains[ai][round].Hash)
		base = run.mark()
		run.startNodes("b")
		run.requireRecovery(base, 5, "H", "b")
		run.stopNode("H")
		run.stopNode("b")
		_, err = run.c.manager(hi).blockStore.Block(round)
		require.ErrorContains(t, err, "not found", "premise only: the other store really pruned the old round")
		require.NoError(t, run.chainsAgree("H", "a"), "control: different heads share finalized history")

		// The reviewer's corruption: change only the stopped node's older head.
		b.BlockData.Timestamp++
		require.Equal(t, before, run.chains[ai][round].Hash, "retained history owns its hash")
		require.ErrorIs(t, run.chainsAgree("H", "a"), errQ4ChainConflict)
		b.BlockData.Timestamp--
		require.NoError(t, run.chainsAgree("H", "a"))

		// Isolate the historical comparison from the current-head integrity guard:
		// corrupt only the advanced node's retained copy of the now-pruned round.
		saved := run.chains[hi][round]
		bad := saved
		bad.Hash = slices.Clone(saved.Hash)
		bad.Hash[0] ^= 1
		run.chains[hi][round] = bad
		require.ErrorIs(t, run.chainsAgree("H", "a"), errQ4ChainConflict)
		run.chains[hi][round] = saved
		require.NoError(t, run.chainsAgree("H", "a"))

		delete(run.chains[hi], round)
		require.ErrorIs(t, run.chainsAgree("H", "a"), errQ4ChainMissing, "missing ancestry cannot silently skip the lower head")
		run.chains[hi][round] = saved
		require.NoError(t, run.chainsAgree("H", "a"))
	})

	t.Run("early stop cannot count four pre-injection commits", func(t *testing.T) {
		r := q4DefaultRoster(t, q4SetA)
		run := newQ4Run(t, r, q4Manifest{Byzantine: []q4Target{{"b", "root"}, {"c", "root"}}}, nil, nil, false)
		base := run.mark()
		run.startAll()
		honest := run.running()
		run.requireRecovery(base, 4, honest...)
		bad, postFault := run.injectAndMark([]string{"b", "c"}, honest)
		for _, n := range honest {
			run.stopNode(n)
		}
		require.NoError(t, run.recovery(base, 4, honest...), "premise: the old pre-start mark falsely satisfies recovery")
		require.ErrorIs(t, run.recovery(postFault, q4RecoverRound, honest...), errQ4Recovery)
		// Cancel the negative control promptly; the live row keeps its frozen
		// 120 s post-injection deadline and uses the same wait and predicate.
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, run.waitRecovery(ctx, postFault, q4RecoverRound, honest...), errQ4Recovery)
		run.finish(bad...)
	})

	t.Run("a completed unsampled root is excluded by the mark", func(t *testing.T) {
		r := q4DefaultRoster(t, q4SetA)
		run := newQ4Run(t, r, q4Manifest{}, nil, nil, false)
		base := run.mark()
		run.startAll()
		run.requireRecovery(base, 4, r.Names()...)
		for _, n := range r.Names() {
			run.stopNode(n)
		}
		mark := run.mark()
		for _, i := range run.idx(r.Names()...) {
			require.Equal(t, run.c.committedRound(i), run.seen[i][mark.Counts[i]-1].Round, "every completed root write was observed synchronously")
			require.Empty(t, run.commitsSince(i, mark), "no late sampler may credit a pre-mark commit")
		}
		require.ErrorIs(t, run.recovery(mark, 1, r.Names()...), errQ4Recovery)
	})
}

// honestVote is the template of the Byzantine votes: an honest identity's traced vote of a round of at least 4 when there is one,
// otherwise (a cluster below the quorum never votes) a synthetic vote of round 2 of the same epoch.
func (run *q4Run) honestVote(honest []string) *abdrc.VoteMsg {
	run.t.Helper()
	for _, ev := range run.s.Trace() {
		if ev.Kind == "attempt" && ev.Msg.Class == q4Vote && ev.Msg.Round >= 4 && slices.ContainsFunc(honest, func(n string) bool {
			return run.r.Entities[run.r.Index(n)].ID.String() == ev.Msg.Author
		}) {
			var v abdrc.VoteMsg
			require.NoError(run.t, types.Cbor.Unmarshal(ev.Msg.Raw, &v))
			return &v
		}
	}
	v := NewDummyVote(run.t, run.r.Entities[0].ID.String(), 2, bytes.Repeat([]byte{0xaa}, 32))
	v.VoteInfo.Epoch = 1
	return v
}

// q4LookupProbe wraps a manager's selector and records the farthest round, relative to the pacemaker's current round, that any route
// asked it about. The selector replays every intervening round under a mutex, so this distance is the cost a route can be made to pay.
type q4LookupProbe struct {
	Leader
	current func() uint64
	mu      sync.Mutex
	maxDist uint64
	calls   int
}

func (p *q4LookupProbe) GetLeaderForRound(round uint64) (peer.ID, error) {
	p.mu.Lock()
	p.calls++
	if cur := p.current(); round > cur {
		p.maxDist = max(p.maxDist, round-cur)
	}
	p.mu.Unlock()
	return p.Leader.GetLeaderForRound(round)
}

func (p *q4LookupProbe) reset() {
	p.mu.Lock()
	p.maxDist, p.calls = 0, 0
	p.mu.Unlock()
}

// TestQ4AdmissionAudit is the audit of the #399 admission-order gate for the routes a single authenticated member can reach on an
// unstarted manager: it sends one validly signed message for a round 2^30 ahead and records how far the selector was asked to
// replay. It is an AUDIT, not a passed production gate: it covers three routes with one signer, not startup, recovery or routing, and
// the table it logs is the finding record. A route that reaches the selector with a far-future round before the round-advancement
// evidence is authenticated is a release blocker for the query-cost gate, to be fixed outside this slice.
func TestQ4AdmissionAudit(t *testing.T) {
	r := q4DefaultRoster(t, q4SetA)
	c := newClusterOf(t, clusterSpec{roster: r, weightedLeader: true})
	cm := c.build(c.nodes[0])
	t.Cleanup(cm.pacemaker.Stop)
	probe := &q4LookupProbe{Leader: cm.leaderSelector, current: cm.pacemaker.GetCurrentRound}
	cm.leaderSelector = probe
	require.IsType(t, &leader.Weighted{}, probe.Leader)
	signer := c.nodes[1]
	const far = uint64(1) << 30
	ctx := context.Background()
	hqc := cm.blockStore.GetHighQc()

	routes := map[string]func() error{
		"vote for a far round": func() error {
			v := NewDummyVote(t, signer.id.String(), far, bytes.Repeat([]byte{1}, 32))
			v.VoteInfo.Epoch, v.HighQc = 1, hqc
			require.NoError(t, v.Sign(signer.signer))
			return cm.onVoteMsg(ctx, v)
		},
		"timeout for a far round": func() error {
			m := abdrc.NewTimeoutMsg(drctypes.NewTimeout(far, 1, hqc), signer.id.String(), nil)
			sig, err := signer.signer.SignBytes(m.Bytes()) // TimeoutMsg.Sign refuses a gap round without its TC; sign the bytes directly
			require.NoError(t, err)
			m.Signature = sig
			return cm.onTimeoutMsg(ctx, m)
		},
		"proposal for a far round on the current QC": func() error {
			p := &abdrc.ProposalMsg{Block: &drctypes.BlockData{Version: 1, Author: signer.id.String(), Round: far, Epoch: 1, Timestamp: 1, Payload: &drctypes.Payload{}, Qc: hqc}}
			if err := p.Sign(signer.signer); err != nil {
				return err
			}
			return cm.onProposalMsg(ctx, p)
		},
	}
	for name, send := range routes {
		probe.reset()
		start := time.Now()
		err := send()
		probe.mu.Lock()
		t.Logf("AUDIT %-45s -> max lookup distance %d over %d selector calls, %s, result: %v", name, probe.maxDist, probe.calls, time.Since(start).Round(time.Millisecond), err)
		dist := probe.maxDist
		probe.mu.Unlock()
		require.Zero(t, dist, "%s: a single member's far-future message must not make the selector replay", name)
	}
}
