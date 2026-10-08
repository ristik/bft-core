package consensus

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4replay"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Q4 #51 (C) export: every deterministic Q4-A and Q4-B row ends by exporting its run as a q4replay bundle and handing the bundle to
// the independent checker, which re-derives the verdicts from the bytes (class, epoch, round, author and signed statement of every
// message, every signature, equivocator set, committed-chain agreement, progress and stall windows against the frozen deadline).
// Set Q4_EXPORT_DIR to keep the bundles; the q4replay command and the acceptance report read them back.

const q4ExportEnv = "Q4_EXPORT_DIR"

type q4ExportIn struct {
	Scenario  string
	Scope     string
	Seed      string
	Epochs    []q4replay.Epoch
	Byzantine []string
	Trace     q4Trace
	Chains    []q4replay.Chain
	Windows   []q4replay.Window
	Deadline  time.Duration
	Class     string // claimed from the declared Byzantine weight against the faulty bound; the checker recomputes it
}

func q4Epoch(t testing.TB, epoch uint64, cfg *votesig.Config, names []string, ids []string, verifiers []abcrypto.Verifier, weights []uint64) q4replay.Epoch {
	t.Helper()
	e := q4replay.Epoch{Epoch: epoch, Scheme: votesig.SchemeLegacy}
	if cfg != nil {
		e.Scheme, e.Network, e.Genesis = cfg.Scheme, cfg.Network, cfg.Genesis[:]
	}
	var total uint64
	for i, n := range names {
		pub, err := verifiers[i].MarshalPublicKey()
		require.NoError(t, err)
		e.Members = append(e.Members, q4replay.Member{Name: n, ID: ids[i], PubKey: pub, Weight: weights[i]})
		total += weights[i]
	}
	e.Total, e.Quorum = total, q4Threshold(total)
	e.Faulty = e.Total - e.Quorum
	return e
}

// q4ClassOf claims the class from the declared Byzantine weight against the epoch's faulty bound.
func q4ClassOf(e q4replay.Epoch, byz []string) string {
	var w uint64
	for _, m := range e.Members {
		if slices.Contains(byz, m.Name) {
			w += m.Weight
		}
	}
	if w <= e.Faulty {
		return q4replay.InBound
	}
	return q4replay.OutsideAssumptions
}

func q4EventsOf(tr q4Trace) []q4replay.Event {
	out := make([]q4replay.Event, 0, len(tr))
	for _, ev := range tr {
		out = append(out, q4replay.Event{Seq: ev.Seq, Kind: ev.Kind, SendID: ev.SendID, DeliveryID: ev.DeliveryID, From: ev.From.String(), To: ev.To.String(), Rule: ev.Rule,
			Class: string(ev.Msg.Class), Epoch: ev.Msg.Epoch, Round: ev.Msg.Round, Author: ev.Msg.Author, Raw: ev.Msg.Raw})
	}
	return out
}

func q4ChainOf(node string, blocks map[uint64]q4Block, seen []q4Commit) q4replay.Chain {
	c := q4replay.Chain{Node: node}
	rounds := make([]uint64, 0, len(blocks))
	for r := range blocks {
		rounds = append(rounds, r)
	}
	slices.Sort(rounds)
	for _, r := range rounds {
		c.Blocks = append(c.Blocks, q4replay.Block{Round: r, Hash: blocks[r].Hash, Parent: blocks[r].Parent})
	}
	for _, s := range seen {
		c.Observed = append(c.Observed, q4replay.Observe{Round: s.Round, AtMs: s.At.UnixMilli()})
	}
	return c
}

func q4Bundle(in q4ExportIn) *q4replay.Bundle {
	return &q4replay.Bundle{Version: q4replay.Version, Scenario: in.Scenario, Coverage: "IN-PROCESS", Scope: in.Scope, Seed: in.Seed, Class: in.Class,
		Epochs: in.Epochs, Byzantine: in.Byzantine, Frozen: q4replay.Frozen{DeadlineMs: in.Deadline.Milliseconds()},
		Events: q4EventsOf(in.Trace), Chains: in.Chains, Windows: in.Windows}
}

var q4ExportName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// q4ReplayCheck hands the bundle to the independent checker through its file form (so what is checked is what is exported) and
// requires a clean verdict. injected is the number of deliberately forged or mixed messages the row sent: the checker must flag
// exactly that many sends, each by its own reason, and nothing else.
func q4ReplayCheck(t *testing.T, b *q4replay.Bundle, injected int) *q4replay.Report {
	t.Helper()
	b.Injected = injected
	dir := os.Getenv(q4ExportEnv)
	if dir == "" {
		dir = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, strings.Trim(q4ExportName.ReplaceAllString(b.Scenario, "_"), "_")+".json")
	require.NoError(t, b.Save(path))
	loaded, err := q4replay.Load(path)
	require.NoError(t, err)
	rep := q4replay.Check(loaded)
	require.NoError(t, rep.Err())
	require.Len(t, rep.Malformed, injected)
	require.Equal(t, b.Class, rep.ComputedClass, "the class the row claims is the class the checker recomputes")
	require.NotZero(t, rep.Signed, "premise: the checker verified signatures")
	return rep
}

// ---- Q4-A (the skewedNet cluster) ----

func (run *q4Run) epochs(t testing.TB) []q4replay.Epoch {
	var names, ids []string
	var vs []abcrypto.Verifier
	for _, e := range run.r.Entities {
		names, ids, vs = append(names, e.Name), append(ids, e.ID.String()), append(vs, e.Verifier)
	}
	return []q4replay.Epoch{q4Epoch(t, 1, nil, names, ids, vs, run.r.Weights)}
}

func (run *q4Run) export(tr q4Trace, bad int) *q4replay.Report {
	run.t.Helper()
	run.mu.Lock()
	var chains []q4replay.Chain
	for i, e := range run.r.Entities {
		if len(run.chains[i]) > 0 {
			chains = append(chains, q4ChainOf(e.Name, run.chains[i], run.seen[i]))
		}
	}
	windows := slices.Clone(run.windows)
	run.mu.Unlock()
	epochs := run.epochs(run.t)
	var byz []string
	for _, tg := range run.man.Byzantine {
		byz = append(byz, tg.Name)
	}
	b := q4Bundle(q4ExportIn{Scenario: run.t.Name(), Seed: run.r.Seed, Epochs: epochs, Byzantine: byz, Trace: tr, Chains: chains, Windows: windows,
		Deadline: run.man.Deadline, Class: run.man.Class(run.r),
		Scope: "root consensus only, legacy scheme 1, test-local weighted leader; no EVM, no aggregator shard; restarts are in-process close/reopen"})
	return q4ReplayCheck(run.t, b, bad)
}

// recordWindow records an expectation window of the run for the offline timing gate.
func (run *q4Run) recordWindow(w q4replay.Window) {
	run.mu.Lock()
	run.windows = append(run.windows, w)
	run.mu.Unlock()
}

// ---- Q4-B (the live harness) ----

func (c *q4bLive) epochs(t testing.TB) []q4replay.Epoch {
	var names, ids []string
	var vs []abcrypto.Verifier
	for _, n := range c.nodes {
		ver, err := n.r.node.Signer.Verifier()
		require.NoError(t, err)
		names, ids, vs = append(names, n.name), append(ids, n.r.id().String()), append(vs, ver)
	}
	cfg := c.cfg
	return []q4replay.Epoch{q4Epoch(t, c.epoch, &cfg, names, ids, vs, c.weights())}
}

func (c *q4bLive) export(tr q4Trace, bad int) *q4replay.Report {
	c.t.Helper()
	c.mu.Lock()
	var chains []q4replay.Chain
	for i, n := range c.nodes {
		if len(c.chains[i]) > 0 {
			chains = append(chains, q4ChainOf(n.name, c.chains[i], c.seen[i]))
		}
	}
	windows := slices.Clone(c.windows)
	declared := slices.Clone(c.declared)
	c.mu.Unlock()
	epochs := c.epochs(c.t)
	b := q4Bundle(q4ExportIn{Scenario: c.t.Name(), Epochs: epochs, Byzantine: declared, Trace: tr, Chains: chains, Windows: windows, Deadline: q4bDeadline,
		Class: q4ClassOf(epochs[0], declared),
		Scope: "root consensus only, scheme 2, real Q3 activation, root-wrr-v1 from the committed tuple; no EVM, no aggregator shard; restarts are in-process close/reopen of fsynced stores"})
	return q4ReplayCheck(c.t, b, bad)
}
