package b1state

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

// chain builds a registry at genesis epoch g (start 7), then appends the given successor starts with no origin change (what a preload does).
func chain(t *testing.T, g uint64, starts ...uint64) *Registry {
	t.Helper()
	gen := fixtureEntry(0, 7)
	gen.Epoch, gen.BodyID = g, [32]byte{1}
	r, err := NewRegistry(gen)
	if err != nil {
		t.Fatal(err)
	}
	w := &Changes{Final: map[[32]byte][32]byte{}}
	for i, s := range starts {
		e := fixtureEntry(g+uint64(i)+1, s)
		if _, err := r.append(e, w); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// ready makes (u, o) the usable origin of r through the guarded path.
func ready(t *testing.T, r *Registry, u, o uint64) *Registry {
	t.Helper()
	if err := r.advance(u, o, &Changes{Final: map[[32]byte][32]byte{}}); err != nil {
		t.Fatal(err)
	}
	return r
}

func update(r *Registry, originEpoch, originRound uint64, add ...Entry) Update {
	return Update{PriorTipEpoch: r.Tip, OriginEpoch: originEpoch, OriginRound: originRound, NewEntries: add}
}

// refused asserts one named guard fires and that the registry and its writes are untouched.
func refused(t *testing.T, r *Registry, u Update, b uint64, want error) {
	t.Helper()
	before := r.copy()
	out, w, err := r.Apply(u, b)
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	if out != nil || w != nil || !reflect.DeepEqual(before, r) {
		t.Fatal("a refused update left an effect")
	}
}

func TestGenesisZeroIsAnOccupiedEpochAndNoOriginIsReadyYet(t *testing.T) {
	r := chain(t, 0)
	if r.Genesis != 0 || r.Tip != 0 || r.Ready || r.Len() != 1 {
		t.Fatal(r)
	}
	if e, ok := r.Entry(0); !ok || e.End != nil {
		t.Fatal("genesis entry is present and open")
	}
	if _, ok := r.Entry(1); ok {
		t.Fatal("an absent epoch is absent")
	}
	if _, err := NewRegistry(func() Entry { e := fixtureEntry(1, 7); return e }()); !errors.Is(err, ErrHistory) {
		t.Fatalf("a non-genesis body cannot start a registry: %v", err)
	}
}

func TestAppendAndOriginAdvanceAreOneAtomicUpdate(t *testing.T) {
	r := chain(t, 0)
	e1 := fixtureEntry(1, 8)
	out, w, err := r.Apply(update(r, 1, 10, e1), 1)
	if err != nil {
		t.Fatal(err)
	}
	if out.Tip != 1 || !out.Ready || out.U != 1 || out.O != 10 || out.Len() != 2 {
		t.Fatal(out)
	}
	old, _ := out.Entry(0)
	if old.End == nil || *old.End != 8 {
		t.Fatal("the old tip is closed once at the successor's start")
	}
	for _, name := range []string{"b1.importedTipEpoch", "b1.originReady", "origin.rootEpoch", "clock.rootRound"} {
		if _, ok := w.Final[FixedSlot(name)]; !ok {
			t.Fatal("missing write", name)
		}
	}
	// nothing is deleted and no installed entry is rewritten except the one-time closure of the old tip (end word and hasEnd flag)
	genesisWords, _ := EntryStorage(old0(r))
	for _, x := range w.Trace {
		_, touchesGenesis := genesisWords[x.Slot]
		if x.Clear || (touchesGenesis && x.Slot != EntrySlot(0, 5) && x.Slot != EntrySlot(0, 6)) {
			t.Fatal("a write cleared or rewrote an installed entry", x)
		}
	}
	if !reflect.DeepEqual(r.Entries(), []uint64{0}) {
		t.Fatal("the receiver changed")
	}
}

// Entries lists installed epochs in order (test helper on the model).
func (r *Registry) Entries() []uint64 {
	var out []uint64
	for e := r.Genesis; ; e++ {
		if _, ok := r.entries[e]; !ok {
			return out
		}
		out = append(out, e)
		if e == math.MaxUint64 {
			return out
		}
	}
}

func TestWriteSideGuardsEachFireAlone(t *testing.T) {
	// base: epochs 0..3 installed (starts 7, 20, 30, 40), usable origin (1, 25): epoch 1 is closed at 30 once 2 is installed.
	base := func() *Registry { return ready(t, chain(t, 0, 20, 30, 40), 1, 25) }
	for _, tc := range []struct {
		name string
		r    *Registry
		u    func(*Registry) Update
		want error
	}{
		{"origin epoch regression", base(), func(r *Registry) Update { return update(r, 0, 25) }, ErrOriginEpochRegression},
		{"origin round regression", base(), func(r *Registry) Update { return update(r, 1, 24) }, ErrOriginRoundRegression},
		{"origin beyond the imported tip", base(), func(r *Registry) Update { return update(r, 4, 50) }, ErrOriginBeyondImportedTip},
		{"origin before the epoch's start", base(), func(r *Registry) Update { return update(r, 2, 29+0) }, ErrOriginBeforeStart},
		{"origin at the closed epoch's end", base(), func(r *Registry) Update { return update(r, 1, 30) }, ErrOriginAtOrAfterEnd},
		{"origin past the closed epoch's end", base(), func(r *Registry) Update { return update(r, 1, 31) }, ErrOriginAtOrAfterEnd},
		{"first origin before genesis", chain(t, 5), func(r *Registry) Update { return update(r, 4, 9) }, ErrFirstOriginBeforeGenesis},
		{"first origin beyond the tip", chain(t, 0), func(r *Registry) Update { return update(r, 1, 9) }, ErrOriginBeyondImportedTip},
		{"first origin before the start", chain(t, 0), func(r *Registry) Update { return update(r, 0, 6) }, ErrOriginBeforeStart},
	} {
		t.Run(tc.name, func(t *testing.T) { refused(t, tc.r, tc.u(tc.r), 1, tc.want) })
	}
	// There is no preload: an update that leaves the imported tip ahead of the usable epoch is refused, whatever the round (these were lawful
	// under the withdrawn preload semantics).
	refused(t, base(), update(base(), 2, 30), 1, ErrImportedUsableMismatch) // round = start of an already-installed, not-last epoch
	refused(t, base(), update(base(), 1, 29), 1, ErrImportedUsableMismatch) // round = end-1 of a closed epoch
	// the lawful boundaries sit on the tip: O_new = O, and O_new = the new tip's start (successor start above O)
	tip := func() *Registry { return ready(t, chain(t, 0, 20), 1, 25) }
	if _, _, err := tip().Apply(update(tip(), 1, 25), 1); err != nil {
		t.Fatal("same epoch, same round:", err)
	}
	if _, _, err := tip().Apply(update(tip(), 2, 26, fixtureEntry(2, 26)), 1); err != nil {
		t.Fatal("round = the new tip's start:", err)
	}
}

func TestAppendGuards(t *testing.T) {
	// ready at (0, 10) with I = U = 0: the successor may not close the usable epoch at or below O
	rd := func() *Registry { return ready(t, chain(t, 0), 0, 10) }
	refused(t, rd(), update(rd(), 1, 12, fixtureEntry(1, 7)), 1, ErrAppendStartNotIncreasing)
	refused(t, rd(), update(rd(), 1, 12, fixtureEntry(1, 6)), 1, ErrAppendStartNotIncreasing)
	refused(t, rd(), update(rd(), 1, 12, fixtureEntry(1, 10)), 1, ErrAppendClosesUsableOrigin)
	refused(t, rd(), update(rd(), 1, 12, fixtureEntry(1, 9)), 1, ErrAppendClosesUsableOrigin)
	if _, _, err := rd().Apply(update(rd(), 1, 12, fixtureEntry(1, 11)), 1); err != nil {
		t.Fatal("start above O is lawful:", err)
	}
	// a tip ahead of the usable epoch is not a state this registry reaches: appending past it while the origin stays behind is refused
	pre := ready(t, chain(t, 0, 20), 0, 10)
	refused(t, pre, update(pre, 0, 11, fixtureEntry(2, 25)), 1, ErrImportedUsableMismatch)
	// gaps, wrong parent, overflow, B
	g := chain(t, 0)
	refused(t, g, update(g, 1, 9, fixtureEntry(2, 8)), 1, ErrAppendGap)
	bad := update(g, 1, 9, fixtureEntry(1, 8))
	bad.PriorTipEpoch = 3
	refused(t, g, bad, 1, ErrHistory)
	refused(t, g, update(g, 2, 12, fixtureEntry(1, 8), fixtureEntry(2, 9)), 1, ErrTooManyEpochs)
	if _, _, err := g.Apply(update(g, 2, 12, fixtureEntry(1, 8), fixtureEntry(2, 9)), 2); err != nil {
		t.Fatal("B = 2 admits two:", err)
	}
	top := chain(t, 0)
	top.Tip = math.MaxUint64
	top.entries[math.MaxUint64] = top.entries[0]
	if _, err := top.append(fixtureEntry(0, 99), &Changes{Final: map[[32]byte][32]byte{}}); !errors.Is(err, ErrImmutable) {
		t.Fatal(err)
	}
	if _, err := top.append(Entry{Epoch: 0}, &Changes{Final: map[[32]byte][32]byte{}}); err == nil {
		t.Fatal("a successor of u64::MAX must be refused")
	}
	// an atomic failure: the append is lawful but the origin advance is not, so nothing is installed
	refused(t, g, update(g, 1, 7, fixtureEntry(1, 8)), 1, ErrOriginBeforeStart)
}

func TestReplayIsIdempotentAndImmutable(t *testing.T) {
	r := ready(t, chain(t, 0, 20, 30), 0, 10)
	closed, _ := r.Entry(1)
	if closed.End == nil || *closed.End != 30 {
		t.Fatal("epoch 1 is closed by epoch 2")
	}
	w := &Changes{Final: map[[32]byte][32]byte{}}
	// the original open append, replayed after its closure: a no-op that preserves the stored end
	ok, err := r.append(fixtureEntry(1, 20), w)
	if err != nil || ok || len(w.Trace) != 0 {
		t.Fatal(ok, err, len(w.Trace))
	}
	if e, _ := r.Entry(1); e.End == nil || *e.End != 30 {
		t.Fatal("replay reopened or changed the end")
	}
	// a replay asserting the matching end is fine; a different one, or a changed field, is refused
	same := fixtureEntry(1, 20)
	end := uint64(30)
	same.End = &end
	if _, err := r.append(same, w); err != nil {
		t.Fatal(err)
	}
	wrong := fixtureEntry(1, 20)
	other := uint64(31)
	wrong.End = &other
	if _, err := r.append(wrong, w); !errors.Is(err, ErrImmutable) {
		t.Fatal(err)
	}
	for _, change := range []func(*Entry){func(e *Entry) { e.Start++ }, func(e *Entry) { e.BodyID[0] ^= 1 }, func(e *Entry) { e.Members[0].Weight++ }, func(e *Entry) { e.SigningConfigHash[0] ^= 1 }} {
		e := fixtureEntry(1, 20)
		change(&e)
		if _, err := r.append(e, w); !errors.Is(err, ErrImmutable) {
			t.Fatal(err)
		}
	}
	if r.Tip != 2 || r.Len() != 3 {
		t.Fatal("replay moved a cursor")
	}
	// an epoch below the genesis was never installed
	if _, err := chain(t, 5).append(fixtureEntry(4, 1), w); !errors.Is(err, ErrImmutable) {
		t.Fatal(err)
	}
}

func TestNextEntriesAreTheBoundedMissingSuffix(t *testing.T) {
	history := []Entry{fixtureEntry(0, 7), fixtureEntry(1, 8), fixtureEntry(2, 9), fixtureEntry(3, 10)}
	for _, tc := range []struct {
		tip, upTo, b uint64
		want         []uint64
	}{{0, 3, 1, []uint64{1}}, {1, 3, 1, []uint64{2}}, {0, 3, 2, []uint64{1, 2}}, {0, 3, 9, []uint64{1, 2, 3}}, {3, 3, 1, nil}, {0, 1, 5, []uint64{1}}} {
		var got []uint64
		for _, e := range NextEntries(history, tc.tip, tc.upTo, tc.b) {
			got = append(got, e.Epoch)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}

func old0(r *Registry) Entry { e, _ := r.Entry(0); return e }

// A span-2 acknowledgement installs two consecutive epochs in one update. Every section 1 guard is checked against each of the two entries
// and the whole update is all-or-nothing; the second entry may repeat the first's membership exactly (a root-only step).
func TestSpanTwoUpdateInstallsBothOrNeither(t *testing.T) {
	const b = MinEpochsPerUpdate
	base := func() *Registry { return ready(t, chain(t, 0, 20), 1, 25) } // epochs 0, 1 installed; usable origin (1, 25)
	e2, e3 := fixtureEntry(2, 30), fixtureEntry(3, 40)
	e3.Members = e2.Members // same membership, new epoch and body

	// lawful: both entries, then the origin on the last; the old tip closes at the first start and the first new entry at the second
	r := base()
	out, w, err := r.Apply(update(r, 3, 45, e2, e3), b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Tip != 3 || out.U != 3 || out.O != 45 || out.Len() != 4 {
		t.Fatal(out)
	}
	for epoch, end := range map[uint64]uint64{1: 30, 2: 40} {
		if e, _ := out.Entry(epoch); e.End == nil || *e.End != end {
			t.Fatalf("epoch %d closed at %v", epoch, e.End)
		}
	}
	if e, _ := out.Entry(3); e.End != nil {
		t.Fatal("the new tip is open")
	}
	if !reflect.DeepEqual(w.Final[FixedSlot("b1.importedTipEpoch")], Word(3)) {
		t.Fatal("one tip write, to the last epoch")
	}
	// the origin cannot stay behind: installing both entries while the usable epoch remains the old one is refused (no preload)
	refused(t, base(), update(base(), 1, 25, e2, e3), b, ErrImportedUsableMismatch)
	refused(t, base(), update(base(), 2, 35, e2, e3), b, ErrImportedUsableMismatch)

	// each guard, against the first and against the second entry; the registry is unchanged every time
	cases := []struct {
		name string
		u    func(r *Registry) Update
		want error
	}{
		{"first start not increasing", func(r *Registry) Update { x := e2; x.Start = 20; return update(r, 3, 45, x, e3) }, ErrAppendStartNotIncreasing},
		{"first closes the usable origin", func(r *Registry) Update { x := e2; x.Start = 25; return update(r, 1, 25, x, e3) }, ErrAppendClosesUsableOrigin},
		{"second start not increasing", func(r *Registry) Update { x := e3; x.Start = 30; return update(r, 3, 45, e2, x) }, ErrAppendStartNotIncreasing},
		{"second start below the first", func(r *Registry) Update { x := e3; x.Start = 29; return update(r, 3, 45, e2, x) }, ErrAppendStartNotIncreasing},
		{"first leaves a gap", func(r *Registry) Update { return update(r, 3, 45, e3, e3) }, ErrAppendGap},
		{"second leaves a gap", func(r *Registry) Update { x := fixtureEntry(4, 50); return update(r, 4, 55, e2, x) }, ErrAppendGap},
		{"first is invalid", func(r *Registry) Update { x := e2; x.Members = nil; return update(r, 3, 45, x, e3) }, ErrMembers},
		{"second is invalid", func(r *Registry) Update { x := e3; x.SigningConfigHash = [32]byte{}; return update(r, 3, 45, e2, x) }, ErrHistory},
		{"second is a genesis body", func(r *Registry) Update {
			x := e3
			x.BodyKind = 1
			x.ActivationCommitID = [32]byte{}
			return update(r, 3, 45, e2, x)
		}, ErrHistory},
		{"origin beyond the second", func(r *Registry) Update { return update(r, 4, 45, e2, e3) }, ErrOriginBeyondImportedTip},
		{"origin before the second's start", func(r *Registry) Update { return update(r, 3, 39, e2, e3) }, ErrOriginBeforeStart},
		{"origin regresses", func(r *Registry) Update { return update(r, 0, 45, e2, e3) }, ErrOriginEpochRegression},
		{"origin round regresses", func(r *Registry) Update { return update(r, 3, 24, e2, e3) }, ErrOriginRoundRegression},
		{"origin at the first new entry's end", func(r *Registry) Update { return update(r, 2, 40, e2, e3) }, ErrOriginAtOrAfterEnd},
		{"three entries at B = 2", func(r *Registry) Update { return update(r, 4, 55, e2, e3, fixtureEntry(4, 50)) }, ErrTooManyEpochs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { r := base(); refused(t, r, tc.u(r), b, tc.want) })
	}
}

func TestParentRegistryRefusesAReadyParentBehindItsTip(t *testing.T) {
	g, e1 := fixtureEntry(0, 7), fixtureEntry(1, 20)
	end := uint64(20)
	g.End = &end
	if _, err := ParentRegistry(0, 1, true, 0, 10, g, e1); !errors.Is(err, ErrImportedUsableMismatch) {
		t.Fatalf("U < I on a ready parent: %v", err)
	}
	if r, err := ParentRegistry(0, 1, true, 1, 25, e1); err != nil || r.U != 1 {
		t.Fatalf("U = I is lawful: %v", err)
	}
	if r, err := ParentRegistry(0, 0, false, 0, 0, g0()); err != nil || r.Ready {
		t.Fatalf("not ready: any U/O is ignored: %v", err)
	}
}

func g0() Entry { return fixtureEntry(0, 7) }
