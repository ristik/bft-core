package b1state

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func fixtureEntry(epoch, start uint64) Entry {
	var scalar [32]byte
	scalar[31] = 1
	key, _ := ethcrypto.ToECDSA(scalar[:])
	var pub [33]byte
	copy(pub[:], ethcrypto.CompressPubkey(&key.PublicKey))
	kind := uint64(2)
	commit := [32]byte{byte(epoch + 10)}
	if epoch == 0 {
		kind = 1
		commit = [32]byte{}
	}
	return Entry{Epoch: epoch, Start: start, BodyKind: kind, BodyID: [32]byte{byte(epoch + 1)}, ActivationCommitID: commit, SigningScheme: 1, SigningConfigHash: [32]byte{9}, Members: []Member{{NodeID: "root", Key: pub, Weight: 1}}}
}

// All pins here identify synthetic fixtures, not a PR3 runtime or production profile.
func fixtureProfile(w uint64) Profile {
	p := Profile{Network: 3, RootGenesisID: [32]byte{1}, ExecutionChainID: 2, RuntimeHash: [32]byte{3}, CompilerHash: [32]byte{4}, WCert: w, DeltaEV: w + 1, DeltaHold: w + 2, RestGas: 100, CompanionBytes: 1000000, OtherCompanionBytes: 1024, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
	p.SystemGas, _ = p.RequiredSystemGas()
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	return p
}
func fixtureUpdate(p Profile) Update {
	h, _ := p.Hash()
	end := uint64(20)
	return Update{Network: p.Network, RootGenesisID: p.RootGenesisID, ExecutionChainID: p.ExecutionChainID, ProfileHash: h, ParentHash: [32]byte{5}, BlockNumber: 1, OriginEpoch: 1, OriginRound: 20, OriginIdentity: [32]byte{6}, PriorTipEpoch: 0, OldTipEnd: &end, NewEntries: []Entry{fixtureEntry(1, 20)}}
}
func TestMembersIsolatedRefusals(t *testing.T) {
	base := fixtureEntry(0, 0)
	for _, tc := range []struct {
		name   string
		change func(*Entry)
		want   error
	}{
		{"empty", func(e *Entry) { e.Members = nil }, ErrMembers},
		{"too-many", func(e *Entry) { e.Members = make([]Member, 65) }, ErrMembers},
		{"empty-ID", func(e *Entry) { e.Members[0].NodeID = "" }, ErrMembers},
		{"long-ID", func(e *Entry) { e.Members[0].NodeID = string(bytes.Repeat([]byte{'a'}, 129)) }, ErrMembers},
		{"utf8", func(e *Entry) { e.Members[0].NodeID = "\xff" }, ErrMembers},
		{"zero-weight", func(e *Entry) { e.Members[0].Weight = 0 }, ErrMembers},
		{"invalid-point", func(e *Entry) { e.Members[0].Key = [33]byte{} }, ErrMembers},
		{"duplicate-ID", func(e *Entry) { m := e.Members[0]; m.Key[0] ^= 1; e.Members = append(e.Members, m) }, ErrMembers},
		{"duplicate-key", func(e *Entry) { m := e.Members[0]; m.NodeID = "z"; e.Members = append(e.Members, m) }, ErrMembers},
		{"order", func(e *Entry) { m := e.Members[0]; m.NodeID = "a"; m.Key[0] ^= 1; e.Members = append(e.Members, m) }, ErrMembers},
		{"weight-overflow", func(e *Entry) {
			e.Members[0].Weight = math.MaxUint64
			m := e.Members[0]
			m.NodeID = "z"
			m.Key[0] ^= 1
			m.Weight = 1
			e.Members = append(e.Members, m)
		}, ErrOverflow},
		{"missing-config", func(e *Entry) { e.SigningConfigHash = [32]byte{} }, ErrHistory},
		{"missing-body", func(e *Entry) { e.BodyID = [32]byte{} }, ErrHistory},
		{"unknown-scheme", func(e *Entry) { e.SigningScheme = 0 }, ErrHistory},
		{"genesis-commit", func(e *Entry) { e.ActivationCommitID = [32]byte{1} }, ErrHistory},
		{"empty-interval", func(e *Entry) { end := e.Start; e.End = &end }, ErrInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := clone(base)
			tc.change(&e)
			if err := e.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	for _, total := range []uint64{1, 2, 3, 4, 5, 6, math.MaxUint64 - 1, math.MaxUint64} {
		threshold, err := Threshold(total)
		if err != nil || threshold != total/3*2+(total%3*2)/3+1 {
			t.Fatalf("threshold(%d)=%d %v", total, threshold, err)
		}
	}
	if _, err := Threshold(0); !errors.Is(err, ErrMembers) {
		t.Fatal(err)
	}
}
func TestProfileRefusalsAndCapacity(t *testing.T) {
	p := fixtureProfile(5)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	k, c, tokens, _ := p.Bounds()
	if k != 6 || c != 102400 || tokens != 1628 {
		t.Fatal(k, c, tokens)
	}
	if gas, _ := p.RequiredSystemGas(); gas != 112213844 {
		t.Fatal(gas)
	}
	for _, tc := range []struct {
		name   string
		change func(*Profile)
		want   error
	}{
		{"W-overflow", func(p *Profile) { p.WCert = math.MaxUint64; p.DeltaEV = math.MaxUint64; p.DeltaHold = math.MaxUint64 }, ErrProfile},
		{"no-runtime", func(p *Profile) { p.RuntimeHash = [32]byte{} }, ErrProfile},
		{"no-rest", func(p *Profile) { p.RestGas = 0 }, ErrProfile},
		{"window", func(p *Profile) { p.WCert = p.DeltaEV + 1 }, ErrProfile},
		{"hold", func(p *Profile) { p.DeltaHold = p.DeltaEV }, ErrProfile},
		{"system-small", func(p *Profile) { p.SystemGas-- }, ErrProfile},
		{"ordinary-small", func(p *Profile) { p.OrdinaryCapacity = 0 }, ErrProfile},
		{"partition-sum", func(p *Profile) { p.ForcedGas = 1 }, ErrProfile},
		{"transport-small", func(p *Profile) { p.CompanionBytes = 102400 }, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := p
			tc.change(&x)
			if err := x.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("%v", err)
			}
		})
	}
	p.WCert = math.MaxUint64
	if _, _, _, err := p.Bounds(); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
	p = fixtureProfile(0)
	p.RestGas = math.MaxUint64
	if _, err := p.RequiredSystemGas(); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
}
func TestUpdateStagedDebitAndCanonical(t *testing.T) {
	p := fixtureProfile(5)
	u := fixtureUpdate(p)
	raw := u.Bytes()
	scan := uint64(2000 + 16*len(raw))
	gas := scan + 1000
	got, used, err := Admit(raw, p, gas)
	if err != nil || used != gas || !reflect.DeepEqual(got, u) {
		t.Fatalf("%v %d", err, used)
	}
	for _, budget := range []uint64{scan - 1, scan, gas - 1} {
		if _, _, err := Admit(raw, p, budget); !errors.Is(err, ErrBudget) {
			t.Fatalf("budget %d: %v", budget, err)
		}
	}
	if _, _, err := Admit(append(raw, 0), p, gas+16); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
	if _, _, err := Admit(append([]byte{0x98, 13}, raw[1:]...), p, gas+16); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
	if _, _, err := Admit(bytes.Repeat([]byte{0}, 102401), p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
	// The first pass never allocates, including malformed input.
	_, _, tokens, _ := p.Bounds()
	k, _, _, _ := p.Bounds()
	if alloc := testing.AllocsPerRun(100, func() { r := wireReader{b: raw, limit: tokens}; r.parse(k, false) }); alloc != 0 {
		t.Fatalf("scan allocated %g", alloc)
	}
	for _, tc := range []struct {
		name   string
		change func(*Update)
		want   error
	}{
		{"network", func(u *Update) { u.Network++ }, ErrBinding}, {"genesis", func(u *Update) { u.RootGenesisID[0] ^= 1 }, ErrBinding},
		{"profile", func(u *Update) { u.ProfileHash[0] ^= 1 }, ErrBinding}, {"parent-zero", func(u *Update) { u.ParentHash = [32]byte{} }, ErrBinding},
		{"height-zero", func(u *Update) { u.BlockNumber = 0 }, ErrBinding}, {"origin-zero", func(u *Update) { u.OriginIdentity = [32]byte{} }, ErrBinding},
		{"wrong-tail", func(u *Update) { u.OriginEpoch++ }, ErrInterval}, {"future-start", func(u *Update) { u.NewEntries[0].Start++ }, ErrInterval},
		{"bad-weight", func(u *Update) { u.NewEntries[0].Members[0].Weight = 0 }, ErrMembers},
		{"no-closure", func(u *Update) { u.OldTipEnd = nil }, ErrInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := fixtureUpdate(p)
			tc.change(&x)
			if _, _, err := Admit(x.Bytes(), p, math.MaxUint64); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
	if used, err := SystemGas(100, 20, 30, 10, 40); err != nil || used != 100 {
		t.Fatal(used, err)
	}
	for _, gs := range [][4]uint64{{101, 0, 0, 0}, {20, 81, 0, 0}, {20, 30, 51, 0}, {20, 30, 10, 41}, {math.MaxUint64, 1, 0, 0}} {
		if _, err := SystemGas(100, gs[0], gs[1], gs[2], gs[3]); !errors.Is(err, ErrBudget) {
			t.Fatal(err)
		}
	}
}

func TestProjectionExhaustive(t *testing.T) {
	// Every integer partition of [0,6], every window and monotone origin pair.
	// The independent model enumerates intervals then filters by intersection.
	cases := 0
	for mask := 0; mask < 64; mask++ {
		starts := []uint64{0}
		for i := uint64(1); i <= 6; i++ {
			if mask&(1<<(i-1)) != 0 {
				starts = append(starts, i)
			}
		}
		history := make([]Entry, len(starts))
		for i, s := range starts {
			history[i] = fixtureEntry(uint64(i), s)
		}
		for w := uint64(0); w <= 6; w++ {
			for parentOrigin := uint64(0); parentOrigin <= 6; parentOrigin++ {
				for origin := parentOrigin; origin <= 6; origin++ {
					model := func(o uint64) []Entry {
						var result []Entry
						for i, s := range starts {
							if s > o {
								break
							}
							e := clone(history[i])
							if i+1 < len(starts) && starts[i+1] <= o {
								end := starts[i+1]
								e.End = &end
							}
							L := uint64(0)
							if o > w {
								L = o - w
							}
							if e.End == nil || *e.End > L {
								result = append(result, e)
							}
						}
						return result
					}
					parent := model(parentOrigin)
					end, added, err := Delta(history, parent, parentOrigin, origin, w)
					if err != nil {
						t.Fatal(err)
					}
					for _, head := range []uint64{0, w} {
						r := Ring{Head: head, OriginRound: parentOrigin, Entries: parent}
						u := Update{PriorTipEpoch: parent[len(parent)-1].Epoch, OldTipEnd: end, NewEntries: added, OriginRound: origin, OriginEpoch: model(origin)[len(model(origin))-1].Epoch}
						out, _, err := r.Apply(u, w)
						if err != nil || !reflect.DeepEqual(out.Entries, model(origin)) {
							t.Fatalf("mask=%d W=%d parent=%d O=%d head=%d err=%v", mask, w, parentOrigin, origin, head, err)
						}
						cases++
					}
				}
			}
		}
	}
	if cases != 25088 {
		t.Fatal(cases)
	}
}
func TestProjectionBoundaryAndIdentity(t *testing.T) {
	history := []Entry{fixtureEntry(0, 7), fixtureEntry(1, 1000), fixtureEntry(2, 1001), fixtureEntry(3, 1002)}
	live, err := Select(history, 1000, 2)
	if err != nil || len(live) != 2 || live[0].Start != 7 || live[1].End != nil {
		t.Fatal(live, err)
	}
	// Future-known activation does not close epoch 1 at O=1000.
	parent, _ := Select(history, 999, 2)
	end, added, err := Delta(history, parent, 999, 1002, 1)
	if err != nil || *end != 1000 || len(added) != 2 || added[0].Epoch != 2 {
		t.Fatal(end, added, err)
	}
	// Expired intermediate epoch 1 was omitted from materialization, not history.
	changed := append([]Entry(nil), parent...)
	changed[0] = clone(changed[0])
	changed[0].Members[0].Weight++
	if _, _, err := Delta(history, changed, 999, 1002, 1); !errors.Is(err, ErrHistory) {
		t.Fatal(err)
	}
	if _, _, err := Delta(history, parent, 999, 998, 1); !errors.Is(err, ErrClock) {
		t.Fatal(err)
	}
	skipped := []Entry{history[0], history[2]}
	if _, err := Select(skipped, 1002, 1); !errors.Is(err, ErrHistory) {
		t.Fatal(err)
	}
	bad := append([]Entry(nil), history...)
	bad[1].Start = 7
	if _, err := Select(bad, 1002, 1); !errors.Is(err, ErrHistory) {
		t.Fatal(err)
	}
	live, err = Select(history, 8, 0)
	if err != nil || len(live) != 1 || live[0].Epoch != 0 {
		t.Fatal(live, err)
	}
}
func TestStorageClearsAndBootstrap(t *testing.T) {
	p := fixtureProfile(1)
	g := fixtureEntry(0, 7)
	g.Members[0].NodeID = string(bytes.Repeat([]byte{'a'}, 128))
	words, err := GenesisWords(p, g)
	if err != nil {
		t.Fatal(err)
	}
	if words[FixedSlot("b1.count")] != Word(1) || words[QueueSlot(0)] != Word(0) || words[FixedSlot("clock.rootRound")] != Word(0) || words[FixedSlot("origin.rootEpoch")] != Word(0) {
		t.Fatal("bootstrap")
	}
	idword := words[MemberSlot(0, 0, 1)]
	if words[MemberSlot(0, 0, 6)][0] != g.Members[0].Key[32] || !bytes.Equal(idword[:], bytes.Repeat([]byte{'a'}, 32)) {
		t.Fatal("padding")
	}
	history := []Entry{g, fixtureEntry(1, 8), fixtureEntry(2, 9)}
	parent, _ := Select(history, 7, 1)
	end, added, _ := Delta(history, parent, 7, 10, 1)
	out, writes, err := (Ring{Head: 1, OriginRound: 7, GenesisStart: 7, Entries: parent}).Apply(Update{PriorTipEpoch: 0, OldTipEnd: end, NewEntries: added, OriginRound: 10, OriginEpoch: 2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if out.Head != 0 || len(out.Entries) != 1 {
		t.Fatal(out)
	}
	for i := uint64(0); i < 11; i++ {
		if w, ok := writes.Final[EntrySlot(0, i)]; !ok || w != ([32]byte{}) {
			t.Fatal("metadata not cleared", i)
		}
	}
	for i := uint64(0); i < 8; i++ {
		if w, ok := writes.Final[MemberSlot(0, 0, i)]; !ok || w != ([32]byte{}) {
			t.Fatal("member not cleared", i)
		}
	}
	if _, ok := writes.Final[EntrySlot(1, 0)]; ok {
		t.Fatal("expired intermediate materialized")
	}
}

func TestRingIsolatedRefusals(t *testing.T) {
	history := []Entry{fixtureEntry(0, 0), fixtureEntry(1, 2), fixtureEntry(2, 4)}
	parent, _ := Select(history, 3, 3)
	end, added, _ := Delta(history, parent, 3, 4, 3)
	base := Ring{Head: 3, OriginRound: 3, Entries: parent}
	update := Update{PriorTipEpoch: 1, OriginRound: 4, OriginEpoch: 2, OldTipEnd: end, NewEntries: added}
	for _, tc := range []struct {
		name   string
		change func(*Ring, *Update)
		want   error
	}{
		{"empty", func(r *Ring, u *Update) { r.Entries = nil }, ErrInterval},
		{"head", func(r *Ring, u *Update) { r.Head = 4 }, ErrInterval},
		{"count", func(r *Ring, u *Update) {
			r.Entries = append(r.Entries, r.Entries...)
			r.Entries = append(r.Entries, r.Entries[0])
		}, ErrInterval},
		{"clock", func(r *Ring, u *Update) { u.OriginRound = 2 }, ErrClock},
		{"parent-coverage", func(r *Ring, u *Update) { r.Entries = r.Entries[1:] }, ErrInterval},
		{"parent-future", func(r *Ring, u *Update) { r.Entries[0].Start = 1; r.OriginRound = 0 }, ErrInterval},
		{"parent-gap", func(r *Ring, u *Update) { end := uint64(1); r.Entries[0].End = &end }, ErrInterval},
		{"wrong-tip", func(r *Ring, u *Update) { u.PriorTipEpoch = 0 }, ErrHistory},
		{"closed-tip", func(r *Ring, u *Update) { end := uint64(4); r.Entries[len(r.Entries)-1].End = &end }, ErrHistory},
		{"closure-replay", func(r *Ring, u *Update) { end := uint64(3); u.OldTipEnd = &end }, ErrInterval},
		{"closure-future", func(r *Ring, u *Update) { end := uint64(5); u.OldTipEnd = &end }, ErrInterval},
		{"missing-closure", func(r *Ring, u *Update) { u.OldTipEnd = nil }, ErrHistory},
		{"old-epoch", func(r *Ring, u *Update) { u.NewEntries[0].Epoch = 1 }, ErrHistory},
		{"new-bad-members", func(r *Ring, u *Update) { u.NewEntries[0].Members[0].Weight = 0 }, ErrMembers},
		{"append-gap", func(r *Ring, u *Update) { u.NewEntries[0].Start = 5; u.OriginRound = 5 }, ErrHistory},
		{"wrong-final-origin", func(r *Ring, u *Update) { u.OriginEpoch = 3 }, ErrInterval},
		{"closed-new-tail", func(r *Ring, u *Update) { end := uint64(5); u.NewEntries[0].End = &end }, ErrInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Entries = make([]Entry, len(base.Entries))
			for i, e := range base.Entries {
				r.Entries[i] = clone(e)
			}
			u := update
			u.NewEntries = []Entry{clone(update.NewEntries[0])}
			tc.change(&r, &u)
			before := make([]Entry, len(r.Entries))
			for i, e := range r.Entries {
				before[i] = clone(e)
			}
			if _, _, err := r.Apply(u, 3); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if !reflect.DeepEqual(before, r.Entries) && len(before) > 0 {
				t.Fatal("failed update mutated parent")
			}
		})
	}
	if advance(math.MaxUint64-2, 2, math.MaxUint64) != 0 {
		t.Fatal("ring overflow")
	}
	if _, _, err := base.Apply(update, math.MaxUint64); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
	if _, err := Select(nil, 4, 3); !errors.Is(err, ErrHistory) {
		t.Fatal(err)
	}
	if _, err := Select(history, 4, math.MaxUint64); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
	if _, err := Select([]Entry{fixtureEntry(1, 0)}, 4, 3); !errors.Is(err, ErrHistory) {
		t.Fatal(err)
	}
	if _, err := Select([]Entry{fixtureEntry(0, 7)}, 6, 3); !errors.Is(err, ErrInterval) {
		t.Fatal(err)
	}
}
func TestGrossClearsSurviveSlotReuse(t *testing.T) {
	parent := fixtureEntry(0, 0)
	next := fixtureEntry(1, 1)
	end := uint64(1)
	out, changes, err := (Ring{Entries: []Entry{parent}}).Apply(Update{PriorTipEpoch: 0, OriginEpoch: 1, OriginRound: 1, OldTipEnd: &end, NewEntries: []Entry{next}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if out.Head != 0 || len(out.Entries) != 1 {
		t.Fatal(out)
	}
	var cleared, inserted bool
	I, D := uint64(0), uint64(0)
	for _, w := range changes.Trace {
		if w.Clear {
			D++
		} else {
			I++
		}
		if w.Slot == QueueSlot(0) {
			if w.Clear && w.Value == Word(0) {
				cleared = true
			}
			if !w.Clear && w.Value == Word(1) {
				inserted = true
			}
		}
	}
	if !cleared || !inserted || len(changes.Trace) == len(changes.Final) {
		t.Fatal("gross slot reuse lost")
	}
	if I != 22 || D != 20 {
		t.Fatal(I, D)
	}
	gas, err := changes.WriteAllowance()
	if err != nil || gas != 22100*I+7100*D {
		t.Fatal(gas, err)
	}
}
func TestExactCandidateBindings(t *testing.T) {
	u := fixtureUpdate(fixtureProfile(1))
	b := Binding{ParentHash: u.ParentHash, BlockNumber: u.BlockNumber, OriginEpoch: u.OriginEpoch, OriginRound: u.OriginRound, OriginIdentity: u.OriginIdentity}
	if err := u.CheckBindings(b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Binding){func(b *Binding) { b.ParentHash[0] ^= 1 }, func(b *Binding) { b.BlockNumber++ }, func(b *Binding) { b.OriginEpoch++ }, func(b *Binding) { b.OriginRound++ }, func(b *Binding) { b.OriginIdentity[0] ^= 1 }} {
		bad := b
		change(&bad)
		if err := u.CheckBindings(bad); !errors.Is(err, ErrBinding) {
			t.Fatal(err)
		}
	}
}
