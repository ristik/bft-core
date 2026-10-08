package consensus

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4shim"
)

var q4bHealSeq atomic.Uint64

// holdBetween is a bidirectional partition by holding: each side holds what it sends to the other, so a heal delivers the stale
// traffic in order and nothing honest is altered or lost.
func (c *q4bLive) holdBetween(rule string, left, right []string) {
	c.t.Helper()
	cut := func(from, to []string) {
		c.apply(q4shim.Control{Rules: []q4shim.Rule{{Name: rule, To: c.ids(to...), Action: q4shim.Hold, Require: true}}}, from...)
	}
	cut(left, right)
	cut(right, left)
}

// hold makes the named nodes hold everything they send to anyone else (a delayed validator).
func (c *q4bLive) hold(rule string, names ...string) {
	c.t.Helper()
	c.apply(q4shim.Control{Rules: []q4shim.Rule{{Name: rule, Action: q4shim.Hold, Require: true}}}, names...)
}

// heal releases every message the rule held, in arrival order, and lets the rule pass what it matches from then on.
func (c *q4bLive) heal(rule string, names ...string) {
	c.t.Helper()
	id := fmt.Sprintf("%s-%d", rule, q4bHealSeq.Add(1))
	c.apply(q4shim.Control{Rules: []q4shim.Rule{{Name: rule, Action: q4shim.Pass}}, Releases: []q4shim.Release{{ID: id, Rule: rule, Order: q4shim.FIFO}}}, names...)
}

func (c *q4bLive) byzantine(variant string, byz []string, recipients []string) {
	c.t.Helper()
	c.mu.Lock()
	c.declared = append(c.declared, byz...)
	c.mu.Unlock()
	for _, b := range byz {
		require.NoError(c.t, c.nodes[c.idx(b)].shim.SetEquivocations([]q4shim.Equivocation{{Name: "byz", Recipients: c.ids(recipients...), Variant: variant, Require: true}}))
	}
}

func (c *q4bLive) requireByzantineSent(byz ...string) {
	c.t.Helper()
	require.Eventually(c.t, func() bool {
		for _, b := range byz {
			if c.nodes[c.idx(b)].shim.Sent("byz") == 0 {
				return false
			}
		}
		return true
	}, q4bDeadline, 20*time.Millisecond, "the Byzantine adapter sent its second statement")
}

// requireNoHonestDoubleSign: the oracle finds no author outside byz with two different validly signed statements for one decision.
func (c *q4bLive) requireNoHonestDoubleSign(tr q4Trace, byz ...string) {
	c.t.Helper()
	bad := map[string]bool{}
	for _, b := range byz {
		bad[c.id(b).String()] = true
	}
	require.Empty(c.t, tr.HonestDoubleSigns(c.views(), bad))
}

func (c *q4bLive) requireEquivocators(tr q4Trace, names ...string) {
	c.t.Helper()
	got := tr.Equivocators(c.views())
	var want []string
	for _, n := range names {
		want = append(want, c.id(n).String())
	}
	var have []string
	for a := range got {
		have = append(have, a)
	}
	require.ElementsMatch(c.t, want, have, "exactly the declared Byzantine authors equivocated")
	require.NoError(c.t, c.report.ExpectEquivocators(names...), "the offline checker, from the bytes, finds the same equivocators")
}

type q4bRow struct {
	name string
	// class is IN-BOUND or OUTSIDE-ASSUMPTIONS (computed here from the declared Byzantine weight against F=2)
	run func(t *testing.T, c *q4bLive)
}

func q4bRun(t *testing.T, mk func(*testing.T) *q4bLive, row q4bRow) {
	t.Run(row.name, func(t *testing.T) {
		t.Parallel()
		q4Slot(t)
		c := mk(t)
		t.Logf("manifest: epoch=%d nodes=%v weights=%v coverage=IN-PROCESS(root consensus, real Q3 activation, scheme 2, root-wrr-v1) deadline=%s", c.epoch, c.all(), c.weights(), q4bDeadline)
		row.run(t, c)
	})
}

func (c *q4bLive) weights() (out []uint64) {
	for _, n := range c.nodes {
		out = append(out, n.weight)
	}
	return out
}

// progressRow: start everything, fault, the responsive set recovers, heal, everyone recovers.
func progressRow(fault func(c *q4bLive), responsive func(c *q4bLive) []string, heal func(c *q4bLive)) func(*testing.T, *q4bLive) {
	return func(t *testing.T, c *q4bLive) {
		c.start(c.all()...)
		c.warm(3, c.all()...)
		fault(c)
		up := responsive(c)
		c.requireRecovery(c.mark(), q4RecoverRound, up...)
		c.requireChainsAgree(up...)
		heal(c)
		c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
		c.requireChainsAgree(c.all()...)
		tr := c.finish()
		require.NoError(t, tr.Verify(c.views()))
		c.requireNoHonestDoubleSign(tr)
		require.Empty(t, tr.Equivocators(c.views()))
	}
}

// stallRow: the fault leaves the responsive weight below Q: after the pre-issued evidence drains nothing moves, then it heals.
func stallRow(fault func(c *q4bLive), stalled func(c *q4bLive) []string, heal func(c *q4bLive)) func(*testing.T, *q4bLive) {
	return func(t *testing.T, c *q4bLive) {
		c.start(c.all()...)
		c.warm(3, c.all()...)
		fault(c)
		c.requireStalled(stalled(c)...)
		heal(c)
		c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
		c.requireChainsAgree(c.all()...)
		tr := c.finish()
		require.NoError(t, tr.Verify(c.views()))
		c.requireNoHonestDoubleSign(tr)
	}
}

func TestQ4BLiveA(t *testing.T) {
	rows := []q4bRow{
		{"no-fault control", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
			require.Empty(t, tr.Equivocators(c.views()))
		}},
		{"two isolated lights: H+a (weight 7) progress, heal", progressRow(
			func(c *q4bLive) { c.holdBetween("cut", []string{"b", "c"}, []string{"H", "a"}) },
			func(c *q4bLive) []string { return []string{"H", "a"} },
			func(c *q4bLive) { c.heal("cut", c.all()...) })},
		{"all three lights isolated: 6|3 stalled, heal", stallRow(
			func(c *q4bLive) { c.holdBetween("cut", []string{"a", "b", "c"}, []string{"H"}) },
			func(c *q4bLive) []string { return c.all() },
			func(c *q4bLive) { c.heal("cut", c.all()...) })},
		{"heavy delayed: quorum lost until release", stallRow(
			func(c *q4bLive) { c.hold("delay", "H") },
			func(c *q4bLive) []string { return []string{"a", "b", "c"} },
			func(c *q4bLive) { c.heal("delay", "H") })},
		{"lights delayed (weight 3): H alone (6) stalls, release", stallRow(
			func(c *q4bLive) { c.hold("delay", "a", "b", "c") },
			func(c *q4bLive) []string { return []string{"H"} },
			func(c *q4bLive) { c.heal("delay", "a", "b", "c") })},
		{"heavy offline then restart", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.stop("H")
			c.requireStalled("a", "b", "c")
			c.restart("H")
			c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
		{"two Byzantine lights (weight 2, in bound) equivocate: honest H+a progress", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			require.EqualValues(t, 2, c.weight("b", "c"))
			c.byzantine("state", []string{"b", "c"}, []string{"H", "a"})
			c.requireByzantineSent("b", "c")
			m := c.mark()
			c.requireRecovery(m, q4RecoverRound, "H", "a")
			c.requireChainsAgree("H", "a")
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireEquivocators(tr, "b", "c")
			c.requireNoHonestDoubleSign(tr, "b", "c")
		}},
		{"Byzantine heavy (weight 6, OUTSIDE the assumptions) equivocates: classification only", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.byzantine("state", []string{"H"}, []string{"a", "b", "c"})
			c.requireByzantineSent("H")
			time.Sleep(2 * time.Second)
			c.requireChainsAgree(c.all()...) // no conflicting finality among the nodes even here; absence of one proves no guarantee
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireEquivocators(tr, "H")
			c.requireNoHonestDoubleSign(tr, "H")
		}},
	}
	for _, row := range rows {
		q4bRun(t, newQ4BLiveA, row)
	}
}

// B is the successor of the handoff: h1,h2 weight 3 each, n2 weight 2, the new entity d weight 1 (W=9, Q=7, F=2).
func TestQ4BLiveB(t *testing.T) {
	rows := []q4bRow{
		{"no-fault control, schedule is root-wrr-v1 from A*", func(t *testing.T, c *q4bLive) {
			for _, n := range c.nodes {
				requireWeightedEpoch(t, n.r, 3, n.r.manager.epochAnchor.Slot+1)
			}
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
		{"the carried identities alone (d never started) are a quorum: 3+3+2=8", func(t *testing.T, c *q4bLive) {
			c.start("h1", "h2", "n2")
			c.warm(3, "h1", "h2", "n2")
			c.requireRecovery(c.mark(), q4RecoverRound, "h1", "h2", "n2")
			c.start("d") // the new entity joins and catches up
			c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
		{"weight 2 offline (n2): 3+3+1=7 progresses", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.stop("n2")
			c.requireRecovery(c.mark(), q4RecoverRound, "h1", "h2", "d")
			c.restart("n2")
			c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
		{"either weight-3 identity offline leaves 6: stalled, then back", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			for _, h := range []string{"h1", "h2"} {
				c.stop(h)
				c.requireStalled(c.except(h)...)
				c.restart(h)
				c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			}
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
		{"one heavy delayed: 6 until release", stallRow(
			func(c *q4bLive) { c.hold("delay", "h1") },
			func(c *q4bLive) []string { return []string{"h2", "n2", "d"} },
			func(c *q4bLive) { c.heal("delay", "h1") })},
		{"n2+d isolated (weight 3): h1+h2 (6) stalled, heal", stallRow(
			func(c *q4bLive) { c.holdBetween("cut", []string{"n2", "d"}, []string{"h1", "h2"}) },
			func(c *q4bLive) []string { return c.all() },
			func(c *q4bLive) { c.heal("cut", c.all()...) })},
		{"d isolated (weight 1): 8 progresses, heal", progressRow(
			func(c *q4bLive) { c.holdBetween("cut", []string{"d"}, []string{"h1", "h2", "n2"}) },
			func(c *q4bLive) []string { return []string{"h1", "h2", "n2"} },
			func(c *q4bLive) { c.heal("cut", c.all()...) })},
		{"first successor proposal held: release, commits resume", func(t *testing.T, c *q4bLive) {
			start := c.nodes[0].r.manager.epochAnchor.Slot + 1
			c.apply(q4shim.Control{Rules: []q4shim.Rule{{Name: "first", Class: q4shim.Proposal, Epoch: 3, RoundMax: start + 1, Action: q4shim.Hold, Require: true}}}, c.all()...)
			c.start(c.all()...)
			require.Eventually(t, func() bool {
				for _, n := range c.nodes {
					if n.shim.Held("first") > 0 {
						return true
					}
				}
				return false
			}, q4bDeadline, 20*time.Millisecond, "the first successor proposal was held")
			time.Sleep(2 * time.Second)
			c.heal("first", c.all()...)
			c.requireRecovery(c.mark(), q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
		{"Byzantine weight 2 (n2, in bound) equivocates: honest 3+3+1 progress", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.byzantine("state", []string{"n2"}, []string{"h1", "h2", "d"})
			c.requireByzantineSent("n2")
			c.requireRecovery(c.mark(), q4RecoverRound, "h1", "h2", "d")
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireEquivocators(tr, "n2")
			c.requireNoHonestDoubleSign(tr, "n2")
		}},
		{"Byzantine heavy (weight 3, OUTSIDE the assumptions): classification, no single-heavy conflict claim", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			c.byzantine("state", []string{"h1"}, []string{"h2", "n2", "d"})
			c.requireByzantineSent("h1")
			time.Sleep(2 * time.Second)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireEquivocators(tr, "h1")
			c.requireNoHonestDoubleSign(tr, "h1")
		}},
		{"quorum-wide restart recovers from the retained stores", func(t *testing.T, c *q4bLive) {
			c.start(c.all()...)
			c.warm(3, c.all()...)
			for _, n := range c.all() {
				c.stop(n)
			}
			m := c.mark()
			for _, n := range c.all() {
				c.restart(n)
			}
			c.requireRecovery(m, q4RecoverRound, c.all()...)
			c.requireChainsAgree(c.all()...)
			tr := c.finish()
			require.NoError(t, tr.Verify(c.views()))
			c.requireNoHonestDoubleSign(tr)
		}},
	}
	for _, row := range rows {
		q4bRun(t, newQ4BLiveB, row)
	}
}
