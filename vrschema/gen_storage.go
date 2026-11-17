package vrschema

import (
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// StorageScenario is one account's storage as the frozen layout places it.
type StorageScenario struct {
	Name    string
	Account [20]byte
	Slots   map[Word]Word
	Reads   []StorageRead
}

// StorageRead is one reader call: the slots it reads (in order) and the decoded result, or the refusal.
type StorageRead struct {
	Name   string
	Slots  []Word
	Decode func([]Word) (any, error)
}

type proofList [][]byte

func (p *proofList) Put(_ []byte, v []byte) error {
	*p = append(*p, append([]byte(nil), v...))
	return nil
}
func (p *proofList) Delete([]byte) error { return nil }

func trimWord(w Word) []byte {
	i := 0
	for i < 32 && w[i] == 0 {
		i++
	}
	return w[i:]
}

// storageTrie builds the account storage trie (secure keys keccak(slot), values rlp(trimmed word)) and returns its root and a
// root-to-leaf proof per slot.
func storageTrie(slots map[Word]Word) (Word, map[Word][][]byte, error) {
	tr := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	for s, v := range slots {
		if v == (Word{}) {
			continue
		}
		enc, _ := rlp.EncodeToBytes(trimWord(v))
		k := keccak(s[:])
		if err := tr.Update(k[:], enc); err != nil {
			return Word{}, nil, err
		}
	}
	root := tr.Hash()
	proofs := map[Word][][]byte{}
	for s := range slots {
		var pl proofList
		k := keccak(s[:])
		if err := tr.Prove(k[:], &pl); err != nil {
			return Word{}, nil, err
		}
		proofs[s] = pl
	}
	return Word(root), proofs, nil
}

func bytesStorage(slot Word, data []byte, into map[Word]Word) {
	if len(data) < 32 {
		var v Word
		copy(v[:], data)
		v[31] = byte(2 * len(data))
		into[slot] = v
		return
	}
	into[slot] = U64(uint64(2*len(data) + 1))
	base := BytesDataSlot(slot)
	for i := 0; i*32 < len(data); i++ {
		var v Word
		copy(v[:], data[32*i:])
		into[SlotAdd(base, uint64(i))] = v
	}
}

func put(m map[Word]Word, slot Word, v Word, err error) {
	if err != nil {
		panic(err)
	}
	m[slot] = v
}

// StorageScenarios are the frozen storage scenarios; the Solidity fixture writes the same values through typed storage.
func StorageScenarios() []StorageScenario {
	var out []StorageScenario
	rid := w("result/R")
	// VR scalars and records
	vr := map[Word]Word{}
	put(vr, VRSlot(SlotNetwork), fxNetwork, nil)
	put(vr, VRSlot(SlotOpenOutput), rid, nil)
	put(vr, VRSlot(SlotLastAcked), GenesisResult, nil)
	lw, err := CommitteeLimits{4, 5, 7}.Word()
	put(vr, VRSlot(SlotCommitteeLimits), lw, err)
	hw, err := HookLimitsWord.Pack(map[string]any{"vMax": uint64(16), "lMax": uint64(8), "rMax": uint64(8), "maxBatch": uint64(32)})
	put(vr, VRSlot(SlotHookLimits), hw, err)
	sw, err := Status{Health: HealthFaulted, KnownRootEpoch: 5, RecordCursor: 42, ActivationCount: 2, HolderCount: 1}.Word()
	put(vr, VRSlot(SlotStatus), sw, err)
	put(vr, VRSlot(SlotActiveModule), AddrWord(fxModule), nil)
	put(vr, VRSlot(SlotActiveModuleHash), w("module-code"), nil)
	put(vr, VRSlot(SlotGovernor), AddrWord(fxOther), nil)
	cw, err := CountersWord.Pack(map[string]any{"nextChangeId": uint64(10), "identityCount": uint64(5), "nativeAttempt": uint64(2)})
	put(vr, VRSlot(SlotCounters), cw, err)
	fees := Fees{Previous: FeeParams{1_000_000, 8, fxOther}, Current: FeeParams{MaxBaseFee, 4, fxSender}, EffectiveBlock: 101}
	fw, err := fees.Words()
	if err != nil {
		panic(err)
	}
	for i := 0; i < 5; i++ {
		vr[VRSlot(uint64(SlotFeesPrevious+i))] = fw[i]
	}
	md, kd := w("members-digest"), w("k-digest")
	out1 := OutputRecord{State: OutPublished, Attempt: 7, ReservedProgress: 10_000, ExpiresAtProgress: 10_000 + Lifetime, Predecessor: GenesisResult,
		SourceModule: fxModule, ModuleTag: PoaModuleTag, MembersDigest: md, KDigest: kd, ChangesDigest: w("changes"), SnapshotDigest: w("snapshot"),
		PolicyDigest: w("policy"), OutputCommit: w("commit")}
	ow, err := out1.Words()
	if err != nil {
		panic(err)
	}
	for j := range ow {
		vr[OutputSlot(rid, uint64(j))] = ow[j]
	}
	nid := w("result/N")
	out2 := OutputRecord{State: OutInvalidated, Attempt: ^uint64(0), ReservedProgress: ^uint64(0) - Lifetime, ExpiresAtProgress: ^uint64(0), Predecessor: rid,
		Native: true, ModuleTag: RegistryNative, InvalidReason: InvalidWithdrawn, InvalidAtProgress: ^uint64(0) - 1}
	ow2, err := out2.Words()
	if err != nil {
		panic(err)
	}
	for j := range ow2 {
		vr[OutputSlot(nid, uint64(j))] = ow2[j]
	}
	payload := mustChange(KindCommitteeLimits, uint64(4), uint64(5), uint64(7))
	ch := ChangeRecord{Kind: KindCommitteeLimits, State: ChBound, NotBeforeProgress: 2000, NotBeforeTime: 3600, PayloadHash: PayloadHash(payload), BoundTo: rid,
		ScheduledAt: 2100, PayloadLength: uint32(len(payload))}
	chw, err := ch.Words()
	if err != nil {
		panic(err)
	}
	for j := range chw {
		vr[ChangeSlot(3, uint64(j))] = chw[j]
	}
	bytesStorage(ChangePayloadSlot(3), payload, vr)
	fr := mustChange(KindForceRemove, uint64(2))
	ch9 := ChangeRecord{Kind: KindForceRemove, State: ChRejected, RejectReason: VerdictConflict, NotBeforeProgress: ^uint64(0), NotBeforeTime: ^uint64(0),
		ActiveRootEpoch: ^uint64(0), PayloadHash: PayloadHash(fr), BoundTo: rid, ScheduledAt: ^uint64(0), PayloadLength: uint32(len(fr))}
	ch9w, _ := ch9.Words()
	for j := range ch9w {
		vr[ChangeSlot(^uint64(0), uint64(j))] = ch9w[j]
	}
	bytesStorage(ChangePayloadSlot(^uint64(0)), fr, vr)
	short := []byte("short-payload")
	bytesStorage(ChangePayloadSlot(0), short, vr)
	acts := []Activation{{RuleID: RuleID("a"), ReleaseDigest: w("1"), RootEpoch: 7, NotBeforeUcTime: 5000, State: ActSuperseded, ChangeID: 4},
		{RuleID: RuleID("a"), ReleaseDigest: w("2"), RootEpoch: 9, NotBeforeUcTime: 6000, State: ActLatched, ChangeID: 6}}
	for i, a := range acts {
		aw, _ := a.Words()
		for j := range aw {
			vr[ActivationSlot(uint32(i), uint64(j))] = aw[j]
		}
	}
	hold := Holder{Holder: fxOther, CodeHash: w("holder-code"), Module: fxModule, RegisteredEpoch: 3}
	hww, _ := hold.Words()
	for j := range hww {
		vr[HolderSlot(0, uint64(j))] = hww[j]
	}
	vr[RetiredSlot(0, 7, 1)] = BoolWord(true)
	vr[RetiredSlot(7, ^uint64(0), ^uint64(0))] = BoolWord(true)

	five := func(base int) []Word {
		var s []Word
		for i := 0; i < 5; i++ {
			s = append(s, VRSlot(uint64(base+i)))
		}
		return s
	}
	outSlots := func(r Word) []Word {
		var s []Word
		for j := 0; j < OutputWords; j++ {
			s = append(s, OutputSlot(r, uint64(j)))
		}
		return s
	}
	chSlots := func(id uint64) []Word {
		var s []Word
		for j := 0; j < ChangeWords; j++ {
			s = append(s, ChangeSlot(id, uint64(j)))
		}
		return s
	}
	n := func(k uint64) []Word { return []Word{VRSlot(k)} }
	out = append(out, StorageScenario{Name: "vr", Account: ValidatorRegistry, Slots: vr, Reads: []StorageRead{
		{"network", n(SlotNetwork), func(ws []Word) (any, error) { return Hexw(ws[0]), nil }},
		{"openOutput", n(SlotOpenOutput), func(ws []Word) (any, error) { return Hexw(ws[0]), nil }},
		{"lastAcked", n(SlotLastAcked), func(ws []Word) (any, error) { return Hexw(ws[0]), nil }},
		{"pendingPair", n(SlotPendingPair), func(ws []Word) (any, error) { return Hexw(ws[0]), nil }},
		{"committeeLimits", n(SlotCommitteeLimits), func(ws []Word) (any, error) { return DecodeCommitteeLimits(ws[0]) }},
		{"hookLimits", n(SlotHookLimits), func(ws []Word) (any, error) { return HookLimitsWord.Unpack(ws[0]) }},
		{"status", n(SlotStatus), func(ws []Word) (any, error) { return DecodeStatus(ws[0]) }},
		{"activeModule", n(SlotActiveModule), func(ws []Word) (any, error) { a, err := WordAddr(ws[0]); return hexa(a), err }},
		{"counters", n(SlotCounters), func(ws []Word) (any, error) { return CountersWord.Unpack(ws[0]) }},
		{"fees", five(SlotFeesPrevious), func(ws []Word) (any, error) {
			f, err := DecodeFees([5]Word(ws))
			return map[string]any{"previous": feeJSON(f.Previous), "current": feeJSON(f.Current), "effectiveBlock": f.EffectiveBlock}, err
		}},
		{"outputs[R]", outSlots(rid), outputReader},
		{"outputs[N] (native, invalidated, max widths)", outSlots(nid), outputReader},
		{"outputs[unknown]", outSlots(w("result/unknown")), outputReader},
		{"changes[3]", chSlots(3), changeReader},
		{"changes[2^64-1]", chSlots(^uint64(0)), changeReader},
		{"changePayload[3] (long bytes)", []Word{ChangePayloadSlot(3), BytesDataSlot(ChangePayloadSlot(3)), SlotAdd(BytesDataSlot(ChangePayloadSlot(3)), 1), SlotAdd(BytesDataSlot(ChangePayloadSlot(3)), 2)},
			func(ws []Word) (any, error) { return Hexb(words(ws[1:]...)[:96]), nil }},
		{"changePayload[0] (short bytes)", []Word{ChangePayloadSlot(0)}, func(ws []Word) (any, error) { return Hexb(ws[0][:ws[0][31]/2]), nil }},
		{"activations[0]", []Word{ActivationSlot(0, 0), ActivationSlot(0, 1), ActivationSlot(0, 2)}, activationReader},
		{"activations[1]", []Word{ActivationSlot(1, 0), ActivationSlot(1, 1), ActivationSlot(1, 2)}, activationReader},
		{"holders[0]", []Word{HolderSlot(0, 0), HolderSlot(0, 1), HolderSlot(0, 2)}, func(ws []Word) (any, error) {
			h, err := DecodeHolder([3]Word(ws))
			return map[string]any{"holder": hexa(h.Holder), "codeHash": Hexw(h.CodeHash), "module": hexa(h.Module), "registeredEpoch": h.RegisteredEpoch}, err
		}},
		{"retired[0][7][1]", []Word{RetiredSlot(0, 7, 1)}, boolReader},
		{"retired[7][2^64-1][2^64-1]", []Word{RetiredSlot(7, ^uint64(0), ^uint64(0))}, boolReader},
		{"retired[0][7][2]", []Word{RetiredSlot(0, 7, 2)}, boolReader},
	}})

	// liability holder layouts
	lia := map[Word]Word{}
	lia[LiabilityCursorSlot()] = U64(40)
	facts := []struct {
		id, gen uint64
		f       LiabilityFacts
	}{
		{0, 0, LiabilityFacts{Requested: true, LiveExposures: 1, LotReferences: 2, MaxLiabilityAnchor: 3, RefDigest: w("ref-0-0")}},
		{1, 1, LiabilityFacts{Requested: true, RefDigest: w("ref-1-1"), MaxLiabilityAnchor: 900}},
		{^uint64(0), ^uint64(0), LiabilityFacts{Requested: true, LiveExposures: ^uint32(0), LotReferences: ^uint32(0), MaxLiabilityAnchor: ^uint64(0), RefDigest: w("ref-max")}},
		{7, ^uint64(0), LiabilityFacts{Requested: false, LiveExposures: 5, RefDigest: w("ref-7")}},
	}
	for _, x := range facts {
		fw, _ := x.f.Words()
		lia[LiabilityFactsSlot(x.id, x.gen, 0)], lia[LiabilityFactsSlot(x.id, x.gen, 1)] = fw[0], fw[1]
	}
	// raw words the typed writer cannot produce: nonzero reserved bytes and requested = 2
	reserved := LiabilityFacts{Requested: true, RefDigest: w("ref-reserved")}
	rw, _ := reserved.Words()
	rw[0][0] = 0x01
	lia[LiabilityFactsSlot(9, 1, 0)], lia[LiabilityFactsSlot(9, 1, 1)] = rw[0], rw[1]
	two, _ := LiabilityFacts{RefDigest: w("ref-two")}.Words()
	two[0][31] = 2
	lia[LiabilityFactsSlot(9, 2, 0)], lia[LiabilityFactsSlot(9, 2, 1)] = two[0], two[1]
	cur := [20]byte{0xcc, 19: 0x0c}
	fs := func(id, gen uint64) []Word {
		return []Word{LiabilityFactsSlot(id, gen, 0), LiabilityFactsSlot(id, gen, 1)}
	}
	out = append(out, StorageScenario{Name: "liability", Account: cur, Slots: lia, Reads: []StorageRead{
		{"cursor", []Word{LiabilityCursorSlot()}, func(ws []Word) (any, error) { return DecodeLiabilityCursor(ws[0]) }},
		{"facts[0][0] (full word0)", fs(0, 0), factsReader},
		{"facts[1][1]", fs(1, 1), factsReader},
		{"facts[2^64-1][2^64-1] (max widths)", fs(^uint64(0), ^uint64(0)), factsReader},
		{"facts[7][2^64-1] (not requested)", fs(7, ^uint64(0)), factsReader},
		{"facts[5][5] (absent)", fs(5, 5), factsReader},
		{"facts[9][1] (nonzero reserved byte)", fs(9, 1), factsReader},
		{"facts[9][2] (requested = 2)", fs(9, 2), factsReader},
	}})
	return out
}

func outputReader(ws []Word) (any, error) {
	o, err := DecodeOutput([OutputWords]Word(ws))
	return map[string]any{"state": OutputStateNames[o.State], "attempt": Dec(o.Attempt), "reservedProgress": Dec(o.ReservedProgress), "expiresAtProgress": Dec(o.ExpiresAtProgress),
		"predecessor": Hexw(o.Predecessor), "sourceModule": hexa(o.SourceModule), "native": o.Native, "moduleTag": Hexw(o.ModuleTag), "membersDigest": Hexw(o.MembersDigest),
		"kDigest": Hexw(o.KDigest), "changesDigest": Hexw(o.ChangesDigest), "snapshotDigest": Hexw(o.SnapshotDigest), "policyDigest": Hexw(o.PolicyDigest),
		"outputCommit": Hexw(o.OutputCommit), "invalidReason": o.InvalidReason, "invalidAtProgress": Dec(o.InvalidAtProgress)}, err
}

func changeReader(ws []Word) (any, error) {
	c, err := DecodeChange([ChangeWords]Word(ws))
	return map[string]any{"kind": c.Kind, "state": ChangeStateNames[c.State], "rejectReason": c.RejectReason, "notBeforeProgress": Dec(c.NotBeforeProgress),
		"notBeforeTime": Dec(c.NotBeforeTime), "activeRootEpoch": Dec(c.ActiveRootEpoch), "payloadHash": Hexw(c.PayloadHash), "boundTo": Hexw(c.BoundTo),
		"scheduledAt": Dec(c.ScheduledAt), "payloadLength": c.PayloadLength}, err
}

func activationReader(ws []Word) (any, error) {
	a, err := DecodeActivation([3]Word(ws))
	return map[string]any{"ruleId": Hexw(a.RuleID), "releaseDigest": Hexw(a.ReleaseDigest), "rootEpoch": a.RootEpoch, "notBeforeUcTime": a.NotBeforeUcTime,
		"state": a.State, "changeId": a.ChangeID}, err
}

func boolReader(ws []Word) (any, error) { return WordBool(ws[0]) }

func factsReader(ws []Word) (any, error) {
	f, err := DecodeLiabilityFacts([2]Word(ws))
	return map[string]any{"requested": f.Requested, "liveExposures": f.LiveExposures, "lotReferences": f.LotReferences, "maxLiabilityAnchor": Dec(f.MaxLiabilityAnchor),
		"refDigest": Hexw(f.RefDigest)}, err
}

func genStorage() ([]Vector, error) {
	b := &vb{}
	for _, sc := range StorageScenarios() {
		root, proofs, err := storageTrie(sc.Slots)
		if err != nil {
			return nil, err
		}
		keys := make([]Word, 0, len(sc.Slots))
		for k := range sc.Slots {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return Hexw(keys[i]) < Hexw(keys[j]) })
		var stor []any
		for _, k := range keys {
			var nodes []string
			for _, n := range proofs[k] {
				nodes = append(nodes, Hexb(n))
			}
			stor = append(stor, map[string]any{"slot": Hexw(k), "word": Hexw(sc.Slots[k]), "proof": nodes})
		}
		b.add(sc.Name+" storage", "storage.account", map[string]any{"account": hexa(sc.Account)}, map[string]any{"storageRoot": Hexw(root), "slots": stor})
		for _, r := range sc.Reads {
			var ss, ws []string
			var vals []Word
			for _, s := range r.Slots {
				ss = append(ss, Hexw(s))
				ws = append(ws, Hexw(sc.Slots[s]))
				vals = append(vals, sc.Slots[s])
			}
			dec, err := r.Decode(vals)
			exp := map[string]any{"words": ws}
			if err != nil {
				exp["error"] = err.Error()
			} else {
				exp["decoded"] = dec
			}
			b.add(fmt.Sprintf("%s %s", sc.Name, r.Name), "storage.read", map[string]any{"account": hexa(sc.Account), "slots": ss}, exp)
		}
	}
	return b.out, b.err
}
