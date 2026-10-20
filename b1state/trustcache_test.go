package b1state

import (
	"errors"
	"testing"
)

// A span-2 import writes each new entry's C_e at field 11 and never touches the closed tip's cache; the view serves the cached
// value with the closure words, in the caller's order, and refuses an empty, oversized or missing request.
func TestTheTrustCacheIsWrittenWithEachEntryAndServedByTheBoundedView(t *testing.T) {
	r := chain(t, 0)
	next, w, err := r.Apply(Update{PriorTipEpoch: 0, NewEntries: []Entry{fixtureEntry(1, 8), fixtureEntry(2, 9)}, OriginEpoch: 2, OriginRound: 10}, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []uint64{1, 2} {
		entry, _ := next.Entry(e)
		want, err := fixtureDeployment.EpochCommitment(entry)
		if err != nil {
			t.Fatal(err)
		}
		if w.Final[EntrySlot(e, CommitmentField)] != want {
			t.Fatalf("epoch %d: the cache word is C_e", e)
		}
	}
	for _, x := range w.Trace {
		if x.Slot == EntrySlot(0, CommitmentField) {
			t.Fatal("closing the old tip rewrote its cache")
		}
	}
	genesis, _ := next.Entry(0)
	if genesis.End == nil || *genesis.End != 8 {
		t.Fatal("premise: the genesis epoch is closed at 8")
	}

	got, err := next.EpochCommitments([]uint64{2, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range []uint64{2, 0, 1} {
		entry, _ := next.Entry(e)
		want, _ := fixtureDeployment.EpochCommitment(entry)
		if got[i].Commitment != want {
			t.Fatalf("epoch %d: the view serves C_e", e)
		}
	}
	if got[0].HasEnd || got[1].End != 8 || !got[1].HasEnd || got[2].End != 9 || !got[2].HasEnd {
		t.Fatalf("closure words: %+v", got)
	}
	// closing does not change C_e: the closed genesis entry's commitment is the open one's
	open := genesis
	open.End = nil
	if c, _ := fixtureDeployment.EpochCommitment(open); c != got[1].Commitment {
		t.Fatal("closure changed C_e")
	}

	full := make([]uint64, MaxCommitmentView)
	if _, err := next.EpochCommitments(full); err != nil {
		t.Fatal("exactly the bound is served", err)
	}
	for name, epochs := range map[string][]uint64{"none": nil, "over the bound": make([]uint64, MaxCommitmentView+1), "missing": {3}} {
		if _, err := next.EpochCommitments(epochs); !errors.Is(err, ErrCommitmentView) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
