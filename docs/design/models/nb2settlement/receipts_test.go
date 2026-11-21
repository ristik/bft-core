package nb2settlement

import "testing"

func TestReceiptBoundaries(t *testing.T) {
	c := claim{verdict{1, 1, 0, 1, 1, targetAmount}, 3, 6}
	s := initial(c)
	id := c.identity(0)
	other := c.identity(1)
	progress, ok := lineageStep(c, id, receipt{}, 0)
	if !ok {
		t.Fatal("could not start lineage")
	}
	if _, ok := lineageStep(c, id, progress, 1); !ok {
		t.Fatal("exact predecessor did not advance")
	}
	for offset := uint8(0); offset <= c.lineageSteps; offset++ {
		for _, session := range []identity{id, other} {
			_, ok := lineageStep(c, session, progress, offset)
			if ok != (session == id && offset == 1) {
				t.Fatalf("incorrect progress authentication for session=%d offset=%d", session.session, offset)
			}
		}
	}

	complete := lineageReceipt(c, id, c.lineageSteps)
	first := suffix{0, 1, s.archiveAt(0)}
	second := suffix{1, 2, s.archiveAt(1)}
	prefix, ok := advanceAbsence(c, id, complete, first)
	if !ok {
		t.Fatal("completed lineage did not authorize the first gap")
	}
	aliased := first
	aliased.start |= 1 << 15
	if _, ok := advanceAbsence(c, id, complete, aliased); ok {
		t.Fatal("symbolic chain accepted a starting head that would truncate")
	}
	secondPrefix, ok := advanceAbsence(c, id, prefix, second)
	if !ok {
		t.Fatal("exact absence predecessor did not advance")
	}
	tx := call{recovered, c.burn, id, secondPrefix, suffix{2, 2, s.archiveAt(2)}}
	if _, result := s.settle(c, tx); result != settled {
		t.Fatalf("certified exact prefix must settle at a retained head with zero new gaps, got %d", result)
	}
	if _, ok := advanceAbsence(c, id, complete, second); ok {
		t.Fatal("new absence session skipped the signed start")
	}
	if _, ok := advanceAbsence(c, id, prefix, first); ok {
		t.Fatal("absence continuation accepted an offset rewind")
	}
	skipped := suffix{2, 3, s.archiveAt(2)}
	if _, ok := advanceAbsence(c, id, prefix, skipped); ok {
		t.Fatal("absence continuation skipped a segment")
	}
	wrongStart := second
	wrongStart.start++
	if _, ok := advanceAbsence(c, id, prefix, wrongStart); ok {
		t.Fatal("absence continuation changed the authenticated starting head")
	}

	for _, test := range []struct {
		name  string
		alter func(*receipt)
	}{
		{"uncertified", func(r *receipt) { r.certified = false }},
		{"session", func(r *receipt) { r.identity.session = 1 }},
		{"evidence", func(r *receipt) { r.identity.evidence++ }},
		{"generation", func(r *receipt) { r.identity.generation++ }},
		{"version", func(r *receipt) { r.identity.version++ }},
		{"deployment", func(r *receipt) { r.identity.burn.domain++ }},
		{"burn ID", func(r *receipt) { r.identity.burn.id++ }},
		{"signed start", func(r *receipt) { r.identity.burn.start++ }},
		{"asset", func(r *receipt) { r.identity.burn.asset++ }},
		{"recipient", func(r *receipt) { r.identity.burn.recipient++ }},
		{"amount", func(r *receipt) { r.identity.burn.amount++ }},
		{"cursor", func(r *receipt) { r.cursor++ }},
		{"kind only", func(r *receipt) {
			if r.kind == lineageProgress {
				r.kind = lineageComplete
			} else {
				r.kind = lineageProgress
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, boundary := range []struct {
				event  receipt
				accept func(receipt) bool
			}{
				{progress, func(r receipt) bool { _, ok := lineageStep(c, id, r, 1); return ok }},
				{complete, func(r receipt) bool { _, ok := advanceAbsence(c, id, r, first); return ok }},
				{prefix, func(r receipt) bool { _, ok := advanceAbsence(c, id, r, second); return ok }},
				{secondPrefix, func(r receipt) bool {
					call := tx
					call.event = r
					next, result := s.settle(c, call)
					return next != s || result != badReceipt
				}},
			} {
				event := boundary.event
				test.alter(&event)
				if boundary.accept(event) {
					t.Fatalf("wrong predecessor accepted at boundary %d: %+v", boundary.event.kind, event)
				}
			}
		})
	}
	invalidCaller := tx
	invalidCaller.claimed.recipient++
	if next, result := s.settle(c, invalidCaller); result != badReceipt || next != s {
		t.Fatal("settlement accepted a caller-selected recipient")
	}
}

func TestRecoveredSettlementRequiresSignedStart(t *testing.T) {
	c := claim{verdict{1, 1, 1, 1, 1, targetAmount}, 3, 4}
	s := initial(c)
	id := c.identity(0)
	tx := call{
		route:    recovered,
		claimed:  c.burn,
		identity: id,
		event:    lineageReceipt(c, id, c.lineageSteps),
		suffix:   suffix{from: c.burn.start, to: s.segment, start: s.archiveAt(c.burn.start)},
	}
	if _, result := s.settle(c, tx); result != settled {
		t.Fatalf("completed receipt and proof from the signed start must settle, got %d", result)
	}

	// Keep the same receipt and retained endpoint. The empty suffix is valid
	// at that endpoint, but it skips the interval starting at the signed index.
	tx.suffix = suffix{from: s.segment, to: s.segment}
	if next, result := s.settle(c, tx); result != badReceipt || next != s {
		t.Fatalf("suffix skipped signed start %d: outcome %d, state changed %t",
			c.burn.start, result, next != s)
	}
}

func TestCertifiedAbsenceStillNeedsRetainedHead(t *testing.T) {
	c := claim{verdict{1, 1, 0, 1, 1, targetAmount}, 1, 0}
	s := initial(c)
	first, result := s.settle(c, call{route: ordinary, claimed: c.burn})
	if result != settled {
		t.Fatal("first payout failed")
	}
	s = first.payTraffic().payTraffic().payTraffic()
	if s.segment != 2 || s.recent || s.previous {
		t.Fatal("paid ID should be covered only by the historical proof")
	}
	id := c.identity(0)
	complete := lineageReceipt(c, id, c.lineageSteps)
	for _, start := range []head{s.archiveAt(0), 2} {
		// The verifier can certify an absence fold on a hypothetical chain.
		// For start=1, the first gap omits the real payout. For start=2,
		// the fold also starts from a substituted unsigned head.
		event, ok := advanceAbsence(c, id, complete, suffix{0, 1, start})
		if !ok {
			t.Fatalf("could not generate a certified branch from start head %d", start)
		}
		for end := uint8(1); end <= s.segment; end++ {
			tx := call{recovered, c.burn, id, event, suffix{1, end, event.folded}}
			if next, result := s.settle(c, tx); result != wrongHead || next != s {
				t.Fatalf("start %d, end %d: false absence prefix changed state or bypassed head check (%d)", start, end, result)
			}
		}
	}

	// An authentic endpoint prepared before later traffic survives one seal.
	// After the next seal, the same call must be refreshed.
	initial := initial(c)
	tx := call{recovered, c.burn, id, complete, suffix{}}
	if _, result := initial.payTraffic().payTraffic().settle(c, tx); result != settled {
		t.Fatalf("previous endpoint rejected, result %d", result)
	}
	later := initial.payTraffic().payTraffic().payTraffic().payTraffic()
	if next, result := later.settle(c, tx); result != staleEndpoint || next != later {
		t.Fatalf("endpoint survived two seal rollovers, result %d", result)
	}
}
