package nb2settlement

import (
	"fmt"
	"math/bits"
)

// A head encodes the chain of sealed roots projected onto presence of the
// target ID. Each step is injective in the prior head and presence bit. The
// fixed-length projection omits unrelated IDs, which cannot affect this proof.
// Distinct genesis values allow tests to supply a different unsigned start.
type head uint16

func (h head) next(containsTarget bool) head {
	if containsTarget {
		return h<<1 | 1
	}
	return h << 1
}

const (
	segmentSize  = 2
	trafficLimit = 9
	sessions     = 2
	gapsPerCall  = 1
	lineageLimit = 1
	targetAmount = 2
	deposit      = targetAmount + trafficLimit
)

type verdict struct {
	domain, id, start, asset, recipient, amount uint8
}

type claim struct {
	burn         verdict
	lineageSteps uint8
	traffic      uint8
}

type route uint8

const (
	ordinary route = iota + 1
	recovered
)

type state struct {
	segment, count     uint8
	recent, previous   bool
	archive            head
	headBeforeLast     head
	traffic            uint8
	accepts            bool
	liability, custody int
	// Ghost accounting. Neither replay nor receipt verification reads this.
	targetPayments, targetReceived, trafficReceived uint8
	paidBy                                          route
	// Reachable, immutable public receipts. Each maximum implies that all
	// preceding receipts on that session's canonical branch remain available.
	lineage, prefix [sessions]uint8
}

func initial(c claim) state {
	s := state{archive: 1, liability: deposit, custody: deposit, accepts: true}
	for i := uint8(0); i < c.traffic; i++ {
		s = s.payTraffic()
	}
	s.prefix = [sessions]uint8{c.burn.start, c.burn.start}
	return s
}

func (s state) insert(target bool, amount int) state {
	s.recent = s.recent || target
	s.count++
	s.liability -= amount
	s.custody -= amount
	if s.count == segmentSize {
		s.headBeforeLast = s.archive
		s.archive = s.archive.next(s.recent)
		s.previous, s.recent = s.recent, false
		s.segment++
		s.count = 0
	}
	return s
}

func (s state) payTraffic() state {
	s.traffic++
	s.trafficReceived++
	return s.insert(false, 1)
}

type eventKind uint8

const (
	lineageProgress eventKind = iota + 1
	lineageComplete
	absenceProgress
)

type identity struct {
	session, evidence, generation, version uint8
	burn                                   verdict
}

func (c claim) identity(session uint8) identity {
	return identity{session: session, evidence: c.burn.id, generation: 1, version: 1, burn: c.burn}
}

// certified abstracts authenticated historical authority, domain, emitter and
// receipt-trie inclusion. The other fields are authenticated event contents.
type receipt struct {
	certified bool
	kind      eventKind
	identity  identity
	cursor    uint8
	folded    head
}

func lineageStep(c claim, id identity, before receipt, offset uint8) (receipt, bool) {
	if id.session >= sessions || id != c.identity(id.session) || offset >= c.lineageSteps {
		return receipt{}, false
	}
	if offset == 0 {
		if before != (receipt{}) {
			return receipt{}, false
		}
	} else if before != (receipt{true, lineageProgress, id, offset, 0}) {
		return receipt{}, false
	}
	return lineageReceipt(c, id, offset+1), true
}

func lineageReceipt(c claim, id identity, cursor uint8) receipt {
	kind := lineageProgress
	if cursor == c.lineageSteps {
		kind = lineageComplete
	}
	return receipt{true, kind, id, cursor, 0}
}

func completed(c claim, id identity, event receipt) bool {
	return id.session < sessions && id == c.identity(id.session) &&
		event == (receipt{true, lineageComplete, id, c.lineageSteps, 0})
}

type suffix struct {
	from, to uint8
	start    head
}

func (p suffix) fold() head {
	// Every supplied gap asserts absence of this burn ID. In the projection,
	// the only compatible root at each step has a zero presence bit.
	steps := p.to - p.from
	// A symbolic fold must never truncate the caller-supplied starting head.
	if p.start > ^head(0)>>steps {
		return 0
	}
	return p.start << steps
}

func advanceAbsence(c claim, id identity, before receipt, p suffix) (receipt, bool) {
	if p.to <= p.from || p.to-p.from > gapsPerCall || p.start == 0 {
		return receipt{}, false
	}
	if completed(c, id, before) {
		if p.from != c.burn.start {
			return receipt{}, false
		}
	} else if id.session >= sessions || id != c.identity(id.session) || p.from <= c.burn.start ||
		before != (receipt{true, absenceProgress, id, p.from, p.start}) {
		return receipt{}, false
	}
	folded := p.fold()
	if folded == 0 {
		return receipt{}, false
	}
	return receipt{true, absenceProgress, id, p.to, folded}, true
}

func (s state) archiveAt(index uint8) head {
	return s.archive >> (s.segment - index)
}

type outcome uint8

const (
	settled outcome = iota
	badReceipt
	oversized
	staleEndpoint
	recentReplay
	wrongHead
	recipientReverted
	insufficientBacking
)

type call struct {
	route    route
	claimed  verdict
	identity identity
	event    receipt
	suffix   suffix
}

func (s state) settle(c claim, tx call) (state, outcome) {
	if tx.claimed != c.burn {
		return s, badReceipt
	}
	p := tx.suffix
	if p.to < p.from || p.to-p.from > gapsPerCall {
		return s, oversized
	}
	receiptedPrefix := false
	switch tx.route {
	case ordinary:
		if c.lineageSteps > lineageLimit {
			return s, oversized
		}
		if p.from != c.burn.start {
			return s, badReceipt
		}
	case recovered:
		id := tx.identity
		if completed(c, id, tx.event) {
			if p.from != c.burn.start {
				return s, badReceipt
			}
		} else {
			if id.session >= sessions || id != c.identity(id.session) || p.from <= c.burn.start ||
				p.start == 0 || tx.event != (receipt{true, absenceProgress, id, p.from, p.start}) {
				return s, badReceipt
			}
			receiptedPrefix = true
		}
	default:
		return s, badReceipt
	}

	if p.to > s.segment || s.segment-p.to > 1 {
		return s, staleEndpoint
	}
	if (receiptedPrefix || p.to != p.from) && p.start == 0 {
		return s, wrongHead
	}
	if s.recent || (p.to < s.segment && s.previous) {
		return s, recentReplay
	}
	if receiptedPrefix || p.to != p.from {
		retained := s.archive
		if p.to < s.segment {
			retained = s.headBeforeLast
		}
		if p.fold() != retained {
			return s, wrongHead
		}
	} else if p.start != 0 {
		return s, wrongHead
	}
	if s.liability < int(c.burn.amount) {
		return s, insufficientBacking
	}
	next := s.insert(true, int(c.burn.amount))
	if !s.accepts {
		return s, recipientReverted
	}
	next.targetPayments++
	next.targetReceived += c.burn.amount
	next.paidBy = tx.route
	return next, settled
}

func (s state) check(c claim) error {
	if s.targetPayments > 1 {
		return fmt.Errorf("burn %d paid %d times", c.burn.id, s.targetPayments)
	}
	if s.targetReceived != s.targetPayments*c.burn.amount || s.trafficReceived != s.traffic ||
		s.liability != deposit-int(s.targetReceived)-int(s.trafficReceived) ||
		s.custody != s.liability || s.liability < 0 {
		return fmt.Errorf("payout and custody do not conserve the funded amounts")
	}
	recorded := bits.OnesCount16(uint16(s.archive) & ((1 << s.segment) - 1))
	if s.recent {
		recorded++
	}
	if recorded != int(s.targetPayments) ||
		(s.segment > 0 && (s.headBeforeLast != s.archive>>1 || s.previous != (s.archive&1 == 1))) ||
		int(s.segment)*segmentSize+int(s.count) != int(s.traffic)+int(s.targetPayments) {
		return fmt.Errorf("replay records diverge from successful payments or seal position")
	}
	return nil
}
