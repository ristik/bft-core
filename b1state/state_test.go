package b1state

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// fixtureDeployment binds the fixture registries' entry commitments.
var fixtureDeployment = Deployment{GenesisCommitment: [32]byte{12}, ProfileHash: [32]byte{13}}

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
// fixtureProfile's argument is B, the epochs one block may install.
func fixtureProfile(b uint64) Profile {
	p := Profile{Network: 3, RootGenesisID: [32]byte{1}, ExecutionChainID: 2, RuntimeHash: [32]byte{3}, CompilerHash: [32]byte{4}, MaxEpochsPerUpdate: b, DeltaEV: 1, DeltaHold: 2, RestGas: 100, CompanionBytes: 1000000, OtherCompanionBytes: 1024, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
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
	if k != 5 || c != 4096+16384*5 || tokens != 32+266*5 {
		t.Fatal(k, c, tokens)
	}
	if gas, _ := p.RequiredSystemGas(); gas != UpdateGasBase+PerEpochGas()*5+p.RestGas+ImportEnvelopeGas {
		t.Fatal(gas)
	}
	for _, tc := range []struct {
		name   string
		change func(*Profile)
		want   error
	}{
		{"B-zero", func(p *Profile) { p.MaxEpochsPerUpdate = 0 }, ErrProfile},
		{"B-below-the-supersession-span", func(p *Profile) { p.MaxEpochsPerUpdate = MinEpochsPerUpdate - 1 }, ErrProfile},
		{"B-overflow", func(p *Profile) { p.MaxEpochsPerUpdate = math.MaxUint64 }, ErrOverflow},
		{"no-runtime", func(p *Profile) { p.RuntimeHash = [32]byte{} }, ErrProfile},
		{"no-rest", func(p *Profile) { p.RestGas = 0 }, ErrProfile},
		{"hold", func(p *Profile) { p.DeltaHold = p.DeltaEV }, ErrProfile},
		{"system-small", func(p *Profile) { p.SystemGas-- }, ErrProfile},
		{"ordinary-small", func(p *Profile) { p.OrdinaryCapacity = 0 }, ErrProfile},
		{"partition-sum", func(p *Profile) { p.ForcedGas = 1 }, ErrProfile},
		{"transport-small", func(p *Profile) { p.CompanionBytes = 4096 + 16384*5 }, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := p
			tc.change(&x)
			if err := x.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("%v", err)
			}
		})
	}
	p.MaxEpochsPerUpdate = math.MaxUint64
	if _, _, _, err := p.Bounds(); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
	p = fixtureProfile(2)
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
	if _, _, err := Admit(bytes.Repeat([]byte{0}, 4096+16384*5+1), p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
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
	if used, err := SystemGas(100, 20, 30, 10, 30, 10); err != nil || used != 100 {
		t.Fatal(used, err)
	}
	for _, gs := range [][5]uint64{{101, 0, 0, 0, 0}, {20, 81, 0, 0, 0}, {20, 30, 51, 0, 0}, {20, 30, 10, 41, 0}, {20, 30, 10, 30, 11}, {math.MaxUint64, 1, 0, 0, 0}} {
		if _, err := SystemGas(100, gs[0], gs[1], gs[2], gs[3], gs[4]); !errors.Is(err, ErrBudget) {
			t.Fatal(err)
		}
	}
}

func TestGenesisWordsDescribeThePermanentRegistry(t *testing.T) {
	p := fixtureProfile(2)
	g := fixtureEntry(0, 7)
	g.Members[0].NodeID = string(bytes.Repeat([]byte{'a'}, 128))
	words, err := GenesisWords(p, g, fixtureDeployment.GenesisCommitment)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Hash()
	for name, want := range map[string][32]byte{
		"b1.format": Word(2), "b1.initialized": Word(1), "b1.network": Word(uint64(p.Network)), "b1.profileHash": h,
		"b1.genesisEpoch": Word(0), "b1.importedTipEpoch": Word(0), "b1.originReady": {}, "clock.rootRound": {}, "origin.rootEpoch": {},
	} {
		if got, ok := words[FixedSlot(name)]; !ok || got != want {
			t.Fatalf("%s = %x (present %v)", name, got, ok)
		}
	}
	for _, gone := range []string{"b1.wCert", "b1.head", "b1.count", "b1.queue"} {
		if _, ok := words[FixedSlot(gone)]; ok {
			t.Fatalf("%s must not exist in the permanent layout", gone)
		}
	}
	idword := words[MemberSlot(0, 0, 1)]
	if words[MemberSlot(0, 0, 6)][0] != g.Members[0].Key[32] || !bytes.Equal(idword[:], bytes.Repeat([]byte{'a'}, 32)) {
		t.Fatal("padding")
	}
}

func TestExactCandidateBindings(t *testing.T) {
	u := fixtureUpdate(fixtureProfile(2))
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

func TestTheRecordsHookIsPartOfTheProfile(t *testing.T) {
	base := fixtureProfile(2)
	baseHash, err := base.Hash()
	if err != nil {
		t.Fatal(err)
	}
	baseGas, _ := base.RequiredSystemGas()
	if g, _ := base.HookEnvelopeGas(); g != 0 {
		t.Fatal("a chain without custody reserves no hook gas", g)
	}

	with := base
	with.RecordsCustody, with.HRecords, with.HookRecordGas = [20]byte{0xc1}, 3, 2_000_000
	with.SystemGas, _ = with.RequiredSystemGas()
	with.MaxGas = with.SystemGas + with.OrdinaryCapacity
	if err := with.Validate(); err != nil {
		t.Fatal(err)
	}
	if g, _ := with.HookEnvelopeGas(); g != HookReadsGas+3*2_000_000 {
		t.Fatal("envelope is the gate reads plus H records", g)
	}
	if gas, _ := with.RequiredSystemGas(); gas != baseGas+HookReadsGas+3*2_000_000 {
		t.Fatal("the system envelope grows by exactly the hook envelope", gas, baseGas)
	}
	withHash, err := with.Hash()
	if err != nil || withHash == baseHash {
		t.Fatal("the hook is in the hash", err)
	}
	// each of the three pins changes the hash alone
	for name, change := range map[string]func(*Profile){
		"custody":    func(p *Profile) { p.RecordsCustody[0]++ },
		"H":          func(p *Profile) { p.HRecords++ },
		"record gas": func(p *Profile) { p.HookRecordGas++ },
	} {
		x := with
		change(&x)
		x.SystemGas, _ = x.RequiredSystemGas()
		x.MaxGas = x.SystemGas + x.OrdinaryCapacity
		h, err := x.Hash()
		if err != nil || h == withHash {
			t.Fatal(name, err)
		}
	}
	for name, change := range map[string]func(*Profile){
		"H zero with custody":        func(p *Profile) { p.HRecords = 0 },
		"H above custody's ceiling":  func(p *Profile) { p.HRecords = HookMaxRecords + 1 },
		"no record gas":              func(p *Profile) { p.HookRecordGas = 0 },
		"H without custody":          func(p *Profile) { p.RecordsCustody = [20]byte{} },
		"record gas without custody": func(p *Profile) { p.RecordsCustody, p.HRecords = [20]byte{}, 0 },
		"system gas below the hook":  func(p *Profile) { p.SystemGas-- },
	} {
		x := with
		change(&x)
		if err := x.Validate(); !errors.Is(err, ErrProfile) {
			t.Fatal(name, err)
		}
	}
}

func TestTheElectionHookIsPartOfTheProfile(t *testing.T) {
	records := fixtureProfile(2)
	records.RecordsCustody, records.HRecords, records.HookRecordGas = [20]byte{0xc1}, 3, 2_000_000
	records.SystemGas, _ = records.RequiredSystemGas()
	records.MaxGas = records.SystemGas + records.OrdinaryCapacity
	if err := records.Validate(); err != nil {
		t.Fatal(err)
	}
	recordsHash, err := records.Hash()
	if err != nil {
		t.Fatal(err)
	}
	recordsGas, _ := records.RequiredSystemGas()

	with := records
	with.ElectionContract, with.ElectGas = [20]byte{0xe1}, 45_000_000
	with.SystemGas, _ = with.RequiredSystemGas()
	with.MaxGas = with.SystemGas + with.OrdinaryCapacity
	if err := with.Validate(); err != nil {
		t.Fatal(err)
	}
	if gas, _ := with.RequiredSystemGas(); gas != recordsGas+45_000_000 {
		t.Fatal("the system envelope grows by exactly the election's price", gas, recordsGas)
	}
	if g, _ := with.HookEnvelopeGas(); g != HookReadsGas+3*2_000_000+45_000_000 {
		t.Fatal("the hook envelope is the reads, H records and the election", g)
	}
	withHash, err := with.Hash()
	if err != nil || withHash == recordsHash {
		t.Fatal("the election hook is in the hash", err)
	}
	// pinned: the enabled form is a new encoding (three more items), so its hash is a fixed vector
	if got := fmt.Sprintf("%x", withHash); got != "67625d750d467bc7f9046dcaa2370e7cc834132958348f4bfae2e6fe4ca9a6f1" {
		t.Fatal("the profile with the election hook hashes as the pinned vector, got", got)
	}
	// each pin changes the hash alone
	for name, change := range map[string]func(*Profile){
		"contract": func(p *Profile) { p.ElectionContract[0]++ },
		"gas":      func(p *Profile) { p.ElectGas++ },
	} {
		x := with
		change(&x)
		x.SystemGas, _ = x.RequiredSystemGas()
		x.MaxGas = x.SystemGas + x.OrdinaryCapacity
		h, err := x.Hash()
		if err != nil || h == withHash || h == recordsHash {
			t.Fatal(name, err)
		}
	}
	// a profile without the election hook hashes exactly as it did before the hook existed
	off := with
	off.ElectionContract, off.ElectGas = [20]byte{}, 0
	off.SystemGas, _ = off.RequiredSystemGas()
	off.MaxGas = off.SystemGas + off.OrdinaryCapacity
	if h, err := off.Hash(); err != nil || h != recordsHash {
		t.Fatal("dropping the election hook restores the previous hash", err)
	}
	for name, change := range map[string]func(*Profile){
		"contract without gas":       func(p *Profile) { p.ElectGas = 0 },
		"gas without contract":       func(p *Profile) { p.ElectionContract = [20]byte{} },
		"election without the hook":  func(p *Profile) { p.RecordsCustody, p.HRecords, p.HookRecordGas = [20]byte{}, 0, 0 },
		"system gas below the price": func(p *Profile) { p.SystemGas-- },
		"envelope overflows":         func(p *Profile) { p.ElectGas = ^uint64(0) },
	} {
		x := with
		change(&x)
		if err := x.Validate(); !errors.Is(err, ErrProfile) && !errors.Is(err, ErrOverflow) {
			t.Fatal(name, err)
		}
	}
}

// Apply closes each entry at its successor's start and ignores an asserted end, so Admit is where an inner entry's End must equal the next Start:
// the bytes the runtime executes must not carry a different one.
func TestAdmitRequiresEachInnerEntryToEndWhereItsSuccessorStarts(t *testing.T) {
	p := fixtureProfile(2)
	build := func(innerEnd uint64) Update {
		u := fixtureUpdate(p)
		first, second := fixtureEntry(1, 20), fixtureEntry(2, 30)
		first.End = &innerEnd
		old := uint64(20)
		u.OldTipEnd, u.PriorTipEpoch = &old, 0
		u.NewEntries, u.OriginEpoch, u.OriginRound = []Entry{first, second}, 2, 40
		return u
	}
	if _, _, err := Admit(build(30).Bytes(), p, math.MaxUint64); err != nil {
		t.Fatal("control:", err)
	}
	for _, end := range []uint64{29, 31} {
		if _, _, err := Admit(build(end).Bytes(), p, math.MaxUint64); !errors.Is(err, ErrInterval) {
			t.Fatalf("inner end %d: %v", end, err)
		}
	}
}
