package evmstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

type retirementFx struct {
	Requested          bool     `json:"requested"`
	Imported           bool     `json:"imported"`
	LiveExposures      uint64   `json:"liveExposures"`
	RefDigest          string   `json:"refDigest"`
	MaxLiabilityAnchor uint64   `json:"maxLiabilityAnchor"`
	LotRefs            []uint64 `json:"lotRefs"`
	RecordCursor       uint64   `json:"recordCursor"`
}

type rejectFx struct {
	SessionState    uint64 `json:"sessionState"`
	Attempt         uint64 `json:"attempt"`
	AssignmentState uint64 `json:"assignmentState"`
	Incumbent       string `json:"incumbent"`
	LastAcked       string `json:"lastAcked"`
}

var (
	custodyAddr  = [20]byte{0x8d, 0x2c, 19: 0x81}
	registryAddr = [20]byte{0xff, 19: 0x02}
)

func testPins(t testing.TB) Pins {
	return Pins{Custody: custodyAddr, Registry: registryAddr, CustodyCode: [32]byte(ethcrypto.Keccak256Hash([]byte("custody code"))),
		RegistryCode: [32]byte(ethcrypto.Keccak256Hash([]byte("registry code"))), NetworkWord: hexWord(t, loadFixture(t, "state-slots.json").NetworkWord)}
}

func addrWord(a [20]byte) (w word32) { copy(w[12:], a[:]); return w }

// registry storage the way the registry keeps it: the imported count, the authenticated target and the retirement key of (id, generation).
func registryStore(count, target, retirement, id, gen uint64) map[word32]word32 {
	return map[word32]word32{
		registryKey("records.count"):       bigWord(count),
		registryKey("records.targetCount"): bigWord(target),
		registryRetirementKey(id, gen):     bigWord(retirement),
	}
}

type setup struct {
	pins     Pins
	custody  map[word32]word32
	registry map[word32]word32
}

// custodyOf is the scenario's custody storage, its roots word pointing at the pinned registry (the custody test pairs a mock).
func custodyOf(t testing.TB, sc scenario) map[word32]word32 {
	st := storageOf(t, sc)
	st[baseSlot(custodyRoots)] = addrWord(registryAddr)
	return st
}

// worldOf builds the certified state: both contracts, with the pinned code hashes and the given storage.
func (s setup) world(t testing.TB) *world {
	cs := []contract{{addr: s.pins.Custody, codeHash: s.pins.CustodyCode, storage: s.custody}}
	if s.registry != nil {
		cs = append(cs, contract{addr: s.pins.Registry, codeHash: s.pins.RegistryCode, storage: s.registry})
	}
	return buildWorld(t, cs...)
}

// accountsFor records what the fact readers read and builds the matching witness accounts.
func accountsFor(t testing.TB, w *world, reads map[[20]byte]*recorder) []accountProof {
	raw := witnessFor(t, w, reads)
	got, err := decodeWitness(raw)
	require.NoError(t, err)
	return got.Accounts
}

func encode(t testing.TB, accounts []accountProof) []byte {
	raw, err := Witness{Accounts: accounts}.Encode()
	require.NoError(t, err)
	return raw
}

func retirementSetup(t testing.TB, sc scenario, count, target, retirement uint64) (setup, uint64) {
	var fx retirementFx
	require.NoError(t, json.Unmarshal(sc.Facts, &fx))
	pins := testPins(t)
	return setup{pins: pins, custody: custodyOf(t, sc), registry: registryStore(count, target, retirement, sc.ID, sc.Generation)}, fx.RecordCursor
}

func retirementWitness(t testing.TB, s setup, sc scenario) (w *world, raw []byte, accounts []accountProof, facts storage.RetirementFacts) {
	w = s.world(t)
	rc, rr := newRecorder(s.custody), newRecorder(s.registry)
	rc.read[baseSlot(custodyNetwork)], rc.read[baseSlot(custodyRoots)] = true, true // the deployment bindings the authority checks first
	require.NoError(t, readRetirement(rc, rr, sc.ID, sc.Generation, &facts))
	accounts = accountsFor(t, w, map[[20]byte]*recorder{s.pins.Custody: rc, s.pins.Registry: rr})
	return w, encode(t, accounts), accounts, facts
}

func TestRetirementFactsAreProvenFromTheCertifiedState(t *testing.T) {
	fx := loadFixture(t, "state-slots.json")
	n := 0
	for _, sc := range fx.Scenarios {
		if sc.Kind != "retirement" {
			continue
		}
		var f retirementFx
		require.NoError(t, json.Unmarshal(sc.Facts, &f))
		cursor := f.RecordCursor
		for _, reg := range []struct {
			name                      string
			count, target, retirement uint64
			caughtUp, notImported     bool
		}{
			{"caught up", cursor, cursor, 0, true, true},
			{"registry behind its source", cursor, cursor + 1, 0, false, true},
			{"custody ahead of the registry", cursor + 1, cursor + 1, 0, false, true},
			{"custody behind the registry", cursor, cursor, 0, true, true},
			{"retired in the registry", cursor, cursor, 5, true, false},
		} {
			if reg.name == "custody behind the registry" {
				continue // same words as caught up; the comparison is symmetric and covered by the two above
			}
			s, _ := retirementSetup(t, sc, reg.count, reg.target, reg.retirement)
			w, raw, _, _ := retirementWitness(t, s, sc)
			got, err := Authority{Pins: s.pins}.VerifyRetirement(raw, w.root, sc.ID, sc.Generation)
			require.NoError(t, err, "%s/%s", sc.Name, reg.name)

			refs := true
			for _, r := range f.LotRefs {
				refs = refs && r == 0
			}
			want := storage.RetirementFacts{ID: sc.ID, Generation: sc.Generation, RefDigest: hexWord(t, f.RefDigest), MaxLiabilityAnchor: f.MaxLiabilityAnchor,
				Requested: f.Requested, NotImported: !f.Imported && reg.notImported, NoLiveExposures: f.LiveExposures == 0, NoLotReferences: refs,
				RecordsCaughtUp: reg.caughtUp}
			require.Equal(t, want, got, "%s/%s", sc.Name, reg.name)
			n++
		}
	}
	require.GreaterOrEqual(t, n, 20)
}

func TestTheRetirableScenarioIsRetirableAndTheOthersAreNot(t *testing.T) {
	fx := loadFixture(t, "state-slots.json")
	byName := map[string]storage.RetirementFacts{}
	for _, sc := range fx.Scenarios {
		if sc.Kind != "retirement" {
			continue
		}
		var f retirementFx
		require.NoError(t, json.Unmarshal(sc.Facts, &f))
		s, _ := retirementSetup(t, sc, f.RecordCursor, f.RecordCursor, 0)
		w, raw, _, _ := retirementWitness(t, s, sc)
		got, err := Authority{Pins: s.pins}.VerifyRetirement(raw, w.root, sc.ID, sc.Generation)
		require.NoError(t, err)
		byName[sc.Name] = got
	}
	ok := func(f storage.RetirementFacts) bool {
		return f.Requested && f.NotImported && f.NoLiveExposures && f.NoLotReferences && f.RecordsCaughtUp
	}
	require.True(t, ok(byName["retirable"]))
	for _, name := range []string{"not-requested", "requested-live", "stayed-in-j", "imported"} {
		require.False(t, ok(byName[name]), name)
	}
	require.False(t, byName["not-requested"].Requested)
	require.False(t, byName["requested-live"].NoLiveExposures)
	require.False(t, byName["requested-live"].NoLotReferences, "the genesis exposure still references the lot")
	require.False(t, byName["stayed-in-j"].Requested)
	require.False(t, byName["imported"].NotImported)
}

func TestRejectFactsAreProvenFromTheCertifiedState(t *testing.T) {
	fx := loadFixture(t, "state-slots.json")
	n := 0
	for _, sc := range fx.Scenarios {
		if sc.Kind != "reject" {
			continue
		}
		var f rejectFx
		require.NoError(t, json.Unmarshal(sc.Facts, &f))
		pins := testPins(t)
		s := setup{pins: pins, custody: custodyOf(t, sc)}
		w := s.world(t)
		rc := newRecorder(s.custody)
		rc.read[baseSlot(custodyNetwork)] = true
		var facts storage.RejectFacts
		resultID := hexWord(t, sc.ResultID)
		require.NoError(t, readReject(rc, resultID, &facts))
		raw := encode(t, accountsFor(t, w, map[[20]byte]*recorder{pins.Custody: rc}))
		got, err := Authority{Pins: pins}.VerifyReject(raw, w.root, resultID, f.Attempt)
		require.NoError(t, err, sc.Name)
		want := storage.RejectFacts{ResultID: resultID, Attempt: f.Attempt, Unresolved: f.SessionState == 1 && f.AssignmentState == 1,
			NoInstalledSession: f.Incumbent == f.LastAcked}
		require.Equal(t, want, got, sc.Name)
		n++
	}
	require.Equal(t, 3, n)
	// the open session is the unresolved one; acknowledged and closed sessions are not
	open := func(name string) bool {
		for _, sc := range fx.Scenarios {
			if sc.Name == name {
				var f rejectFx
				require.NoError(t, json.Unmarshal(sc.Facts, &f))
				return f.SessionState == 1 && f.AssignmentState == 1
			}
		}
		t.Fatalf("no scenario %s", name)
		return false
	}
	require.True(t, open("session-open"))
	require.False(t, open("session-acknowledged"))
	require.False(t, open("session-closed"))
}

// ---- refusals ----------------------------------------------------------------------------------------------------------------------

type retirableWorld struct {
	s        setup
	sc       scenario
	w        *world
	accounts []accountProof
}

func newRetirable(t *testing.T, mutateStorage func(custody, registry map[word32]word32)) retirableWorld {
	fx := loadFixture(t, "state-slots.json")
	var sc scenario
	for _, c := range fx.Scenarios {
		if c.Name == "retirable" {
			sc = c
		}
	}
	require.Equal(t, "retirable", sc.Name)
	s, cursor := retirementSetup(t, sc, 0, 0, 0)
	s.registry = registryStore(cursor, cursor, 0, sc.ID, sc.Generation)
	if mutateStorage != nil {
		mutateStorage(s.custody, s.registry)
	}
	w, _, accounts, _ := retirementWitness(t, s, sc)
	return retirableWorld{s: s, sc: sc, w: w, accounts: accounts}
}

func (r retirableWorld) verify(accounts []accountProof, root word32) error {
	_, err := Authority{Pins: r.s.pins}.VerifyRetirement(encode(nil2t, accounts), root, r.sc.ID, r.sc.Generation)
	return err
}

var nil2t testing.TB = &testing.T{}

func TestWitnessRefusals(t *testing.T) {
	base := newRetirable(t, nil)
	require.NoError(t, base.verify(base.accounts, base.w.root))
	clone := func() []accountProof {
		out := make([]accountProof, len(base.accounts))
		for i, a := range base.accounts {
			out[i] = accountProof{Addr: bytes.Clone(a.Addr), Proofs: cloneNodes(a.Proofs)}
			for _, s := range a.Slots {
				out[i].Slots = append(out[i].Slots, slotProof{Slot: bytes.Clone(s.Slot), Value: bytes.Clone(s.Value), Proofs: cloneNodes(s.Proofs)})
			}
		}
		return out
	}
	custodyIdx := func(a []accountProof) int {
		for i := range a {
			if bytes.Equal(a[i].Addr, custodyAddr[:]) {
				return i
			}
		}
		t.Fatal("no custody account")
		return -1
	}
	slotIdx := func(a accountProof, slot word32) int {
		for i := range a.Slots {
			if bytes.Equal(a.Slots[i].Slot, slot[:]) {
				return i
			}
		}
		t.Fatalf("no slot %x", slot)
		return -1
	}
	type tc struct {
		name   string
		mutate func(a []accountProof) []accountProof
		want   error
	}
	cases := []tc{
		{"a flipped byte in an account proof node", func(a []accountProof) []accountProof {
			a[0].Proofs[len(a[0].Proofs)-1][3] ^= 1
			return a
		}, ErrProof},
		{"a flipped byte in a slot proof node", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			p := a[i].Slots[0].Proofs
			p[len(p)-1][3] ^= 1
			return a
		}, ErrProof},
		{"a claimed value that is not the proven one", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			j := slotIdx(a[i], baseSlot(custodyRecordCursor))
			a[i].Slots[j].Value[31] ^= 1
			return a
		}, ErrProof},
		{"a claimed zero for a slot that holds a value", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			j := slotIdx(a[i], baseSlot(custodyNetwork))
			a[i].Slots[j].Value = make([]byte, 32)
			return a
		}, ErrProof},
		{"a slot the verifier never reads", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			extra := baseSlot(custodyNetwork + 100)
			ap := slotProof{Slot: extra[:], Value: make([]byte, 32), Proofs: base.w.slotProof(t, custodyAddr, extra)}
			a[i].Slots = append(a[i].Slots, ap)
			sortSlots(a[i].Slots)
			return a
		}, ErrWitness},
		{"a slot the facts need but the witness lacks", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			j := slotIdx(a[i], baseSlot(custodyRecordCursor))
			a[i].Slots = append(a[i].Slots[:j], a[i].Slots[j+1:]...)
			return a
		}, ErrWitness},
		{"slots out of order", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			a[i].Slots[0], a[i].Slots[1] = a[i].Slots[1], a[i].Slots[0]
			return a
		}, ErrWitness},
		{"a duplicate slot", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			a[i].Slots = append(a[i].Slots, a[i].Slots[len(a[i].Slots)-1])
			return a
		}, ErrWitness},
		{"accounts out of order", func(a []accountProof) []accountProof { a[0], a[1] = a[1], a[0]; return a }, ErrWitness},
		{"a duplicate account", func(a []accountProof) []accountProof { return []accountProof{a[0], a[0]} }, ErrWitness},
		{"the registry account missing", func(a []accountProof) []accountProof { return a[:1] }, ErrWitness},
		{"no accounts", func(a []accountProof) []accountProof { return nil }, ErrWitness},
		{"a third account", func(a []accountProof) []accountProof {
			extra := accountProof{Addr: bytes.Repeat([]byte{0xff}, 20), Proofs: [][]byte{{1}}}
			return append(a, extra)
		}, ErrWitness},
		{"an account without a proof", func(a []accountProof) []accountProof { a[0].Proofs = nil; return a }, ErrWitness},
		{"a short value", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			a[i].Slots[0].Value = a[i].Slots[0].Value[:31]
			return a
		}, ErrWitness},
		{"a short slot", func(a []accountProof) []accountProof {
			i := custodyIdx(a)
			a[i].Slots[0].Slot = a[i].Slots[0].Slot[:31]
			return a
		}, ErrWitness},
		{"a short address", func(a []accountProof) []accountProof { a[0].Addr = a[0].Addr[:19]; return a }, ErrWitness},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := base.verify(c.mutate(clone()), base.w.root)
			require.ErrorIs(t, err, c.want)
			if c.want == ErrWitness {
				require.NotErrorIs(t, err, ErrProof)
			}
		})
	}

	t.Run("another state root", func(t *testing.T) {
		bad := base.w.root
		bad[0] ^= 1
		require.ErrorIs(t, base.verify(clone(), bad), ErrProof)
	})
	t.Run("bytes that are not canonical", func(t *testing.T) {
		raw := append(encode(t, clone()), 0)
		_, err := Authority{Pins: base.s.pins}.VerifyRetirement(raw, base.w.root, base.sc.ID, base.sc.Generation)
		require.ErrorIs(t, err, ErrWitness)
	})
	t.Run("a longer form of the same CBOR", func(t *testing.T) {
		canonical := encode(t, clone())
		require.Equal(t, byte(0x82), canonical[0], "two accounts")
		longForm := append([]byte{0x98, 0x02}, canonical[1:]...) // the array length in the next byte instead of the head
		_, err := Authority{Pins: base.s.pins}.VerifyRetirement(longForm, base.w.root, base.sc.ID, base.sc.Generation)
		require.ErrorIs(t, err, ErrWitness)
	})
	t.Run("an empty or oversize witness", func(t *testing.T) {
		for _, raw := range [][]byte{nil, make([]byte, MaxWitnessBytes+1)} {
			_, err := Authority{Pins: base.s.pins}.VerifyRetirement(raw, base.w.root, base.sc.ID, base.sc.Generation)
			require.ErrorIs(t, err, ErrWitness)
		}
	})
	t.Run("a reject witness where a retirement is judged", func(t *testing.T) {
		_, err := Authority{Pins: base.s.pins}.VerifyReject(encode(t, clone()), base.w.root, [32]byte{1}, 1)
		require.ErrorIs(t, err, ErrWitness, "two accounts where one is expected")
	})
}

func sortSlots(s []slotProof) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && bytes.Compare(s[j-1].Slot, s[j].Slot) > 0; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func cloneNodes(n [][]byte) [][]byte {
	out := make([][]byte, len(n))
	for i := range n {
		out[i] = bytes.Clone(n[i])
	}
	return out
}

func TestPinsBindTheWitnessToTheDeployment(t *testing.T) {
	base := newRetirable(t, nil)
	run := func(p Pins) error {
		_, err := Authority{Pins: p}.VerifyRetirement(encode(t, base.accounts), base.w.root, base.sc.ID, base.sc.Generation)
		return err
	}
	require.NoError(t, run(base.s.pins))
	for name, mutate := range map[string]func(p *Pins){
		"another custody code":     func(p *Pins) { p.CustodyCode[0] ^= 1 },
		"another registry code":    func(p *Pins) { p.RegistryCode[0] ^= 1 },
		"another network word":     func(p *Pins) { p.NetworkWord[0] ^= 1 },
		"another custody address":  func(p *Pins) { p.Custody[0] ^= 1 },
		"another registry address": func(p *Pins) { p.Registry[0] ^= 1 },
	} {
		p := base.s.pins
		mutate(&p)
		err := run(p)
		require.Error(t, err, name)
		require.True(t, ethcommon.Address(p.Custody) != ethcommon.Address(base.s.pins.Custody) || ethcommon.Address(p.Registry) != ethcommon.Address(base.s.pins.Registry) || errorsIsProof(err), name)
	}
	// custody.roots must be the pinned registry, so a witness of another registry contract cannot stand in
	other := newRetirable(t, func(c, r map[word32]word32) { c[baseSlot(custodyRoots)] = addrWord([20]byte{0xab}) })
	_, err := Authority{Pins: other.s.pins}.VerifyRetirement(encode(t, other.accounts), other.w.root, other.sc.ID, other.sc.Generation)
	require.ErrorIs(t, err, ErrProof)
}

func errIs(err, target error) bool { return errors.Is(err, target) }

func errorsIsProof(err error) bool {
	return err != nil && (errIs(err, ErrProof) || errIs(err, ErrWitness))
}

func TestAbsentAccountsAndBoundedLots(t *testing.T) {
	base := newRetirable(t, nil)
	// the registry is not in the certified state at all
	s := base.s
	s.registry = nil
	w := s.world(t)
	_, err := Authority{Pins: s.pins}.VerifyRetirement(encode(t, base.accounts), w.root, base.sc.ID, base.sc.Generation)
	require.ErrorIs(t, err, ErrProof, "an account that does not exist in the certified state")

	// a lot list longer than custody's own bound is refused, and so is a lot id that is not a uint64
	for name, mutate := range map[string]func(c map[word32]word32, lots word32){
		"a lot list beyond the bound": func(c map[word32]word32, lots word32) { c[lots] = bigWord(maxLots + 1) },
		"a length above uint64":       func(c map[word32]word32, lots word32) { c[lots] = word32{0: 1, 31: 1} },
		"more lots than the module reads even when custody's limit allows them": func(c map[word32]word32, lots word32) {
			limits := c[baseSlot(custodyLimits)]
			for i := 0; i < limitsLMaxSize; i++ {
				limits[32-limitsLMaxOffset-1-i] = 0xff
			}
			c[baseSlot(custodyLimits)], c[lots] = limits, bigWord(maxLots+1)
		},
		"a lot id above uint64": func(c map[word32]word32, lots word32) {
			c[lots] = bigWord(1)
			c[arrayElement(lots, 0)] = word32{0: 1, 31: 1}
		},
	} {
		sc := base.sc
		s := base.s
		s.custody = map[word32]word32{}
		for k, v := range base.s.custody {
			s.custody[k] = v
		}
		mutate(s.custody, nested(custodyGenerationLots, sc.ID, sc.Generation))
		w := s.world(t)
		rc, rr := newRecorder(s.custody), newRecorder(s.registry)
		rc.read[baseSlot(custodyNetwork)], rc.read[baseSlot(custodyRoots)] = true, true
		var facts storage.RetirementFacts
		require.Error(t, readRetirement(rc, rr, sc.ID, sc.Generation, &facts), name)
		accounts := accountsFor(t, w, map[[20]byte]*recorder{s.pins.Custody: rc, s.pins.Registry: rr})
		_, err = Authority{Pins: s.pins}.VerifyRetirement(encode(t, accounts), w.root, sc.ID, sc.Generation)
		require.ErrorIs(t, err, ErrWitness, name)
	}
}

func TestRejectWitnessShapeIsExact(t *testing.T) {
	fx := loadFixture(t, "state-slots.json")
	var sc scenario
	for _, c := range fx.Scenarios {
		if c.Name == "session-open" {
			sc = c
		}
	}
	pins := testPins(t)
	s := setup{pins: pins, custody: custodyOf(t, sc), registry: registryStore(0, 0, 0, 1, 1)}
	w := s.world(t)
	rc := newRecorder(s.custody)
	rc.read[baseSlot(custodyNetwork)] = true
	resultID := hexWord(t, sc.ResultID)
	var facts storage.RejectFacts
	require.NoError(t, readReject(rc, resultID, &facts))
	accounts := accountsFor(t, w, map[[20]byte]*recorder{pins.Custody: rc})
	run := func(a []accountProof) error {
		_, err := Authority{Pins: pins}.VerifyReject(encode(t, a), w.root, resultID, 1)
		return err
	}
	require.NoError(t, run(accounts))
	// an extra account, even a valid one with nothing read from it
	reg := accountProof{Addr: pins.Registry[:], Proofs: w.accountProof(t, pins.Registry)}
	require.ErrorIs(t, run(append(append([]accountProof(nil), accounts...), reg)), ErrWitness)
	// an extra proven slot on the custody account
	extra := baseSlot(custodyNetwork + 100)
	withExtra := accountProof{Addr: accounts[0].Addr, Proofs: accounts[0].Proofs, Slots: append(append([]slotProof(nil), accounts[0].Slots...),
		slotProof{Slot: extra[:], Value: make([]byte, 32), Proofs: w.slotProof(t, pins.Custody, extra)})}
	sortSlots(withExtra.Slots)
	err := run([]accountProof{withExtra})
	require.ErrorIs(t, err, ErrWitness)
	require.NotErrorIs(t, err, ErrProof)
}

func TestLotListIsBoundedByCustodysOwnLimit(t *testing.T) {
	base := newRetirable(t, nil)
	sc := base.sc
	s := base.s
	s.custody = map[word32]word32{}
	for k, v := range base.s.custody {
		s.custody[k] = v
	}
	limits := s.custody[baseSlot(custodyLimits)]
	require.NotZero(t, fieldUint(limits, limitsLMaxOffset, limitsLMaxSize))
	for i := 0; i < limitsLMaxSize; i++ { // lMax = 0 while the generation lists one lot
		limits[32-limitsLMaxOffset-1-i] = 0
	}
	s.custody[baseSlot(custodyLimits)] = limits
	w := s.world(t)
	rc, rr := newRecorder(s.custody), newRecorder(s.registry)
	rc.read[baseSlot(custodyNetwork)], rc.read[baseSlot(custodyRoots)] = true, true
	var facts storage.RetirementFacts
	require.Error(t, readRetirement(rc, rr, sc.ID, sc.Generation, &facts))
	accounts := accountsFor(t, w, map[[20]byte]*recorder{s.pins.Custody: rc, s.pins.Registry: rr})
	_, err := Authority{Pins: s.pins}.VerifyRetirement(encode(t, accounts), w.root, sc.ID, sc.Generation)
	require.ErrorIs(t, err, ErrWitness)
}

func TestAnUnresolvedResultNeedsBothAnOpenSessionAndAReservedAssignment(t *testing.T) {
	fx := loadFixture(t, "state-slots.json")
	var sc scenario
	for _, c := range fx.Scenarios {
		if c.Name == "session-open" {
			sc = c
		}
	}
	resultID := hexWord(t, sc.ResultID)
	session := mapSlot(baseSlot(custodySessions), resultID[:])
	base := storageOf(t, sc)
	assignment := base[slotWord(session, sessionAssignmentSlot)]
	asgSlot := slotWord(mapSlot(baseSlot(custodyAssignments), assignment[:]), assignmentStateSlot)
	for name, c := range map[string]struct {
		session, assignment uint64
		want                bool
	}{
		"open and reserved":                   {sessionOpen, assignmentReserved, true},
		"open but the assignment was aborted": {sessionOpen, 3, false},
		"open but the assignment is active":   {sessionOpen, 2, false},
		"closed but still reserved":           {3, assignmentReserved, false},
		"acknowledged but still reserved":     {2, assignmentReserved, false},
	} {
		store := map[word32]word32{}
		for k, v := range base {
			store[k] = v
		}
		store[slotWord(session, sessionStateSlot)] = bigWord(c.session)
		store[asgSlot] = bigWord(c.assignment)
		var f storage.RejectFacts
		require.NoError(t, readReject(newRecorder(store), resultID, &f))
		require.Equal(t, c.want, f.Unresolved, name)
	}
}

func TestNonCanonicalStoredValuesAndOversizeWitnessesAreRefused(t *testing.T) {
	saved := encodeSlotValue
	defer func() { encodeSlotValue = saved }()
	// a world whose trie stores the cursor word with a leading zero byte: not the canonical RLP of the word
	encodeSlotValue = func(v word32) []byte {
		if v == bigWord(2) {
			return []byte{0, 2}
		}
		return trimmed(v)
	}
	base := newRetirable(t, nil)
	_, err := Authority{Pins: base.s.pins}.VerifyRetirement(encode(t, base.accounts), base.w.root, base.sc.ID, base.sc.Generation)
	require.ErrorIs(t, err, ErrProof)
	encodeSlotValue = saved

	good := newRetirable(t, nil)
	huge := append([]accountProof(nil), good.accounts...)
	huge[0] = accountProof{Addr: good.accounts[0].Addr, Proofs: append(cloneNodes(good.accounts[0].Proofs), make([]byte, MaxWitnessBytes)), Slots: good.accounts[0].Slots}
	_, err = Authority{Pins: good.s.pins}.VerifyRetirement(encode(t, huge), good.w.root, good.sc.ID, good.sc.Generation)
	require.ErrorIs(t, err, ErrWitness)
	require.NotErrorIs(t, err, ErrProof)

	many := append([]accountProof(nil), good.accounts...)
	extra := make([]slotProof, maxSlots+1)
	for i := range extra {
		w := bigWord(uint64(i + 1000))
		extra[i] = slotProof{Slot: w[:], Value: make([]byte, 32), Proofs: [][]byte{{1}}}
	}
	many[0] = accountProof{Addr: good.accounts[0].Addr, Proofs: good.accounts[0].Proofs, Slots: extra}
	_, err = Authority{Pins: good.s.pins}.VerifyRetirement(encode(t, many), good.w.root, good.sc.ID, good.sc.Generation)
	require.ErrorIs(t, err, ErrWitness)
	require.NotErrorIs(t, err, ErrProof)
}
