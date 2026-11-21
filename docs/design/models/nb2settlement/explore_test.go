package nb2settlement

import (
	"fmt"
	"strings"
	"testing"
)

type edge struct {
	description string
	next        state
	// A stable step leaves the recipient and background payment stream alone.
	stable bool
}

type coverage struct {
	ordinaryPaid, recoveredPaid, reverted, sealReverted, retryPaid bool
	ordinarySawRecovered, recoveredSawOrdinary                     bool
	previousPaid, stale, recentDuplicate, archivedDuplicate        bool
	longLineageRefused, longGapRefused, chunkAndLineagePaid        bool
}

func (s state) moves(c claim, seen *coverage, visit func(edge)) {
	if s.traffic < trafficLimit {
		visit(edge{"settle unrelated burn", s.payTraffic(), false})
	}
	next := s
	next.accepts = !s.accepts
	visit(edge{"toggle recipient availability", next, false})

	try := func(tx call) {
		next, result := s.settle(c, tx)
		if result != settled && next != s {
			panic(fmt.Sprintf("rejected transaction mutated state: %+v", tx))
		}
		switch result {
		case settled:
			seen.ordinaryPaid = seen.ordinaryPaid || tx.route == ordinary
			seen.recoveredPaid = seen.recoveredPaid || tx.route == recovered
			seen.previousPaid = seen.previousPaid || tx.suffix.to < s.segment
			seen.chunkAndLineagePaid = seen.chunkAndLineagePaid ||
				(tx.event.kind == absenceProgress && c.lineageSteps > lineageLimit &&
					tx.suffix.to-c.burn.start > gapsPerCall)
			visit(edge{fmt.Sprintf("settle route=%d session=%d suffix=%d..%d",
				tx.route, tx.identity.session, tx.suffix.from, tx.suffix.to), next, true})
		case oversized:
			seen.longLineageRefused = seen.longLineageRefused ||
				(tx.route == ordinary && c.lineageSteps > lineageLimit && tx.suffix.to-tx.suffix.from <= gapsPerCall)
			seen.longGapRefused = seen.longGapRefused ||
				(tx.route == ordinary && tx.suffix.to-tx.suffix.from > gapsPerCall && s.segment-tx.suffix.to <= 1)
		case staleEndpoint:
			seen.stale = true
		case recentReplay, wrongHead:
			if s.targetPayments == 1 && s.segment-tx.suffix.to <= 1 {
				seen.ordinarySawRecovered = seen.ordinarySawRecovered ||
					(tx.route == ordinary && s.paidBy == recovered)
				seen.recoveredSawOrdinary = seen.recoveredSawOrdinary ||
					(tx.route == recovered && s.paidBy == ordinary)
				seen.recentDuplicate = seen.recentDuplicate || result == recentReplay
				seen.archivedDuplicate = seen.archivedDuplicate || result == wrongHead
			}
		case recipientReverted:
			seen.reverted = true
			seen.sealReverted = seen.sealReverted || s.count == segmentSize-1
			// Retry the same prepared transaction after the recipient is payable.
			ready := s
			ready.accepts = true
			paid, retry := ready.settle(c, tx)
			if retry != settled || paid.targetPayments != ready.targetPayments+1 {
				panic("recipient recovery did not permit the same transaction to settle")
			}
			seen.retryPaid = true
		}
	}
	start := c.burn.start
	// Endpoints below current model delayed preparations. Both current and
	// previous remain admissible and all earlier endpoints must be rejected.
	for end := start; end <= s.segment; end++ {
		p := suffix{from: start, to: end}
		if end > start {
			p.start = s.archiveAt(start)
		}
		try(call{route: ordinary, claimed: c.burn, suffix: p})
	}

	for session := uint8(0); session < sessions; session++ {
		id := c.identity(session)
		cursor := s.lineage[session]
		if cursor < c.lineageSteps {
			var before receipt
			if cursor > 0 {
				before = lineageReceipt(c, id, cursor)
			}
			event, ok := lineageStep(c, id, before, cursor)
			if !ok {
				panic("reachable lineage did not advance")
			}
			next := s
			next.lineage[session] = event.cursor
			visit(edge{fmt.Sprintf("verify lineage session=%d cursor=%d", session, event.cursor), next, true})
			continue
		}
		complete := lineageReceipt(c, id, cursor)
		prefix := s.prefix[session]
		if prefix < s.segment {
			from := s.archiveAt(prefix)
			before := complete
			if prefix > start {
				before = receipt{true, absenceProgress, id, prefix, from}
			}
			event, ok := advanceAbsence(c, id, before, suffix{prefix, prefix + 1, from})
			if !ok {
				panic("reachable prefix did not advance")
			}
			// A prefix can advance along the authentic head only if its next
			// segment has a valid gap. A false head can never rejoin this branch.
			if event.folded == s.archiveAt(prefix+1) {
				next := s
				next.prefix[session] = event.cursor
				visit(edge{fmt.Sprintf("verify gap session=%d end=%d", session, event.cursor), next, true})
			}
		}
		for from := start; from <= prefix; from++ {
			before := complete
			base := s.archiveAt(from)
			if from > start {
				before = receipt{true, absenceProgress, id, from, base}
			}
			for end := from; end <= s.segment && end-from <= gapsPerCall; end++ {
				p := suffix{from, end, base}
				if from == start && end == from {
					p.start = 0
				}
				try(call{recovered, c.burn, id, before, p})
			}
		}
	}
}

type node struct {
	state
	parent int
	action string
}

func trace(nodes []node, at int) string {
	var steps []string
	for nodes[at].parent >= 0 {
		steps = append(steps, nodes[at].action)
		at = nodes[at].parent
	}
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}
	return strings.Join(steps, " -> ")
}

func (s state) progress() int {
	rank := int(s.targetPayments)
	for session := range s.lineage {
		rank += int(s.lineage[session]) + int(s.prefix[session])
	}
	return rank
}

func explore(t *testing.T, c claim) coverage {
	t.Helper()
	start := initial(c)
	nodes := []node{{state: start, parent: -1}}
	index := map[state]int{start: 0}
	// Reverse graph of stable execution, for the conditional progress check.
	predecessors := [][]int{nil}
	var seen coverage
	edges := 0
	for i := 0; i < len(nodes); i++ {
		s := nodes[i].state
		if err := s.check(c); err != nil {
			t.Fatalf("%v after %s: %+v", err, trace(nodes, i), s)
		}
		s.moves(c, &seen, func(e edge) {
			edges++
			j, ok := index[e.next]
			if !ok {
				j = len(nodes)
				index[e.next] = j
				nodes = append(nodes, node{e.next, i, e.description})
				predecessors = append(predecessors, nil)
			}
			if e.stable {
				if e.next.progress() <= s.progress() {
					t.Fatalf("stable transition %q failed to advance after %s", e.description, trace(nodes, i))
				}
				predecessors[j] = append(predecessors[j], i)
			}
		})
	}

	// Distance to payment under a stable, payable execution with archive and
	// receipt access. The bounded progress rank above excludes cycles and
	// distance excludes unpaid dead ends. Every maximal stable path pays if
	// effective calls continue to be included. Distance also measures the
	// shortest completion path available to a claimant from each state.
	distance := make([]int, len(nodes))
	var queue []int
	for i, n := range nodes {
		if n.targetPayments == 1 {
			distance[i] = 1
			queue = append(queue, i)
		}
	}
	maxSteps, checked := 0, 0
	for i := 0; i < len(queue); i++ {
		j := queue[i]
		for _, prev := range predecessors[j] {
			if distance[prev] == 0 {
				distance[prev] = distance[j] + 1
				queue = append(queue, prev)
			}
		}
	}
	for i, n := range nodes {
		if n.targetPayments == 0 && n.accepts {
			checked++
			if distance[i] == 0 {
				t.Fatalf("no stable path to payment after %s: %+v", trace(nodes, i), n.state)
			}
			maxSteps = max(maxSteps, distance[i]-1)
		}
	}
	t.Logf("%d states, %d transitions, %d eligible unpaid states reach exactly one payment within %d steps",
		len(nodes), edges, checked, maxSteps)
	return seen
}

func TestSettlementInterleavings(t *testing.T) {
	for _, test := range []struct {
		name string
		claim
	}{
		{"race", claim{verdict{1, 1, 0, 1, 1, targetAmount}, 1, 0}},
		{"anchoredRace", claim{verdict{1, 1, 1, 1, 1, targetAmount}, 1, 2}},
		{"absenceOversized", claim{verdict{1, 1, 0, 1, 1, targetAmount}, 1, 6}},
		{"lineageOversized", claim{verdict{1, 1, 0, 1, 1, targetAmount}, 3, 0}},
		{"bothOversized", claim{verdict{1, 1, 0, 1, 1, targetAmount}, 3, 6}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := explore(t, test.claim)
			if !got.recoveredPaid || !got.reverted || !got.sealReverted || !got.retryPaid ||
				!got.previousPaid || !got.stale || !got.recentDuplicate || !got.archivedDuplicate {
				t.Fatalf("missing recovery or replay coverage: %+v", got)
			}
			switch test.name {
			case "race", "anchoredRace":
				if !got.ordinaryPaid || !got.ordinarySawRecovered || !got.recoveredSawOrdinary {
					t.Fatalf("missing an ordering of the payout race: %+v", got)
				}
			case "absenceOversized":
				if got.ordinaryPaid || !got.longGapRefused {
					t.Fatalf("expected the gap envelope alone to block ordinary payment: %+v", got)
				}
			case "lineageOversized":
				if got.ordinaryPaid || !got.longLineageRefused {
					t.Fatalf("expected lineage alone to block ordinary payment: %+v", got)
				}
			case "bothOversized":
				if got.ordinaryPaid || !got.longGapRefused || !got.longLineageRefused || !got.chunkAndLineagePaid {
					t.Fatalf("missing joint oversize recovery: %+v", got)
				}
			}
		})
	}
}
