package vrschema

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-go-base/types"
)

func mustEnc(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

type vb struct {
	out []Vector
	err error
}

func (b *vb) add(name, op string, in, exp map[string]any) {
	b.out = append(b.out, Vector{Name: name, Op: op, Input: in, Expect: exp})
}

func (b *vb) fail(f string, a ...any) {
	if b.err == nil {
		b.err = fmt.Errorf(f, a...)
	}
}

// decodeCase records a module-return decoding vector after checking the reference agrees.
func (b *vb) decodeCase(op, name string, ret []byte, want CodecError, decode func([]byte) error) {
	got := Classify(decode(ret))
	if got != want {
		b.fail("%s/%s: decoder says %s, vector wants %s", op, name, got, want)
	}
	b.add(name, op, map[string]any{"returndata": Hexb(ret), "size": len(ret)}, map[string]any{"result": string(want)})
}

func mutate(b []byte, at int, v byte) []byte {
	c := append([]byte(nil), b...)
	c[at] = v
	return c
}

func genEncoding() ([]Vector, error) {
	b := &vb{}
	// --- namespaces and domains ---
	for _, id := range []string{VRNamespaceID, LiabilityNamespaceID, "example.main"} {
		b.add("erc7201 "+id, "domain.erc7201", map[string]any{"id": id}, map[string]any{"slot": Hexw(Erc7201(id))})
	}
	if Hexw(Erc7201("example.main")) != "0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500" {
		b.fail("erc7201 example.main")
	}
	if Hexw(LiabilityNS) != "0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00" {
		b.fail("liability namespace differs from the design constant")
	}
	for text, v := range domainTable() {
		b.add("domain "+text, "domain.keccak", map[string]any{"text": text}, map[string]any{"word": v})
	}
	for _, rule := range []string{"cancun-blob-fees", "vr-handoff-v2"} {
		b.add("ruleId "+rule, "domain.ruleId", map[string]any{"name": rule}, map[string]any{"ruleId": Hexw(RuleID(rule))})
	}

	// --- packed module returns ---
	rid := w("result-1")
	elect := func(name string, p PackedElect) {
		b.decodeCase("codec.elect", name, EncodeElect(p), CodecOK, func(r []byte) error { _, e := DecodeElect(r); return e })
	}
	elect("Disabled", PackedElect{Outcome: ElectDisabled})
	elect("NotDue", PackedElect{Outcome: ElectNotDue})
	elect("Reserved not ready", PackedElect{Outcome: ElectReserved, ResultID: rid})
	elect("Reserved ready", PackedElect{Outcome: ElectReserved, Ready: true, ResultID: rid})
	elect("NoCandidate", PackedElect{Outcome: ElectNoCandidate})
	good := EncodeElect(PackedElect{Outcome: ElectReserved, Ready: true, ResultID: rid})
	de := func(r []byte) error { _, e := DecodeElect(r); return e }
	b.decodeCase("codec.elect", "161 bytes oversize", append(append([]byte{}, good...), 0), CodecOversize, de)
	b.decodeCase("codec.elect", "192 bytes oversize", append(append([]byte{}, good...), make([]byte, 32)...), CodecOversize, de)
	b.decodeCase("codec.elect", "offset word 64", mutate(good, 31, 64), CodecEnvelope, de)
	b.decodeCase("codec.elect", "length word 64", mutate(good, 63, 64), CodecEnvelope, de)
	b.decodeCase("codec.elect", "not a whole word", good[:159], CodecEnvelope, de)
	b.decodeCase("codec.elect", "empty", nil, CodecEnvelope, de)
	b.decodeCase("codec.elect", "two content words", Envelope(good[64:128]), CodecLength, de)
	b.decodeCase("codec.elect", "outcome 4", mutate(good, 64+31, 4), CodecRange, de)
	b.decodeCase("codec.elect", "outcome high byte", mutate(good, 64, 1), CodecNarrow, de)
	b.decodeCase("codec.elect", "ready 2", mutate(good, 96+31, 2), CodecBool, de)
	b.decodeCase("codec.elect", "Reserved zero id", EncodeElect(PackedElect{Outcome: ElectReserved}), CodecZero, de)
	b.decodeCase("codec.elect", "NotDue with id", EncodeElect(PackedElect{Outcome: ElectNotDue, ResultID: rid}), CodecZero, de)
	b.decodeCase("codec.elect", "ready without reservation", EncodeElect(PackedElect{Outcome: ElectNotDue, Ready: true}), CodecRange, de)

	do := func(r []byte) error { _, e := DecodeOutputReturn(r); return e }
	hdr := OutputHeader{ResultID: rid, Predecessor: GenesisResult, Attempt: 7, SnapshotDigest: w("snapshot"), PolicyDigest: w("policy")}
	ready := func(n int) []byte {
		return EncodeOutput(PackedOutput{Status: StatusReady, Header: hdr, Members: fxMembers(n, rid)})
	}
	for _, n := range []int{1, 4, 16} {
		b.decodeCase("codec.output", fmt.Sprintf("Ready n=%d (%d bytes)", n, 64+32+192+320*n), ready(n), CodecOK, do)
	}
	b.decodeCase("codec.output", "Pending 96", EncodeOutput(PackedOutput{Status: StatusPending}), CodecOK, do)
	b.decodeCase("codec.output", "NotMine 96", EncodeOutput(PackedOutput{Status: StatusNotMine}), CodecOK, do)
	r16 := ready(16)
	b.decodeCase("codec.output", "5409 bytes refused", append(append([]byte{}, r16...), 0), CodecOversize, do)
	b.decodeCase("codec.output", "Ready n=17 oversize", ready(17), CodecOversize, do)
	b.decodeCase("codec.output", "Pending with a trailing word", Envelope(words(U64(1), Word{})), CodecLength, do)
	b.decodeCase("codec.output", "status 3 (NotReady) refused", EncodeOutput(PackedOutput{Status: StatusNotReady}), CodecRange, do)
	b.decodeCase("codec.output", "status 4", EncodeOutput(PackedOutput{Status: 4}), CodecRange, do)
	r2 := ready(2)
	b.decodeCase("codec.output", "header n=3 for 2 members", mutate(r2, 64+32*7-1, 3), CodecCount, do)
	b.decodeCase("codec.output", "header n=0", Envelope(append(words(U64(0)), words(hdr.ResultID, hdr.Predecessor, U64(7), hdr.SnapshotDigest, hdr.PolicyDigest, U64(0))...)), CodecCount, do)
	b.decodeCase("codec.output", "truncated member", Envelope(r2[64:len(r2)-32]), CodecLength, do)
	desc := fxMembers(2, rid)
	desc[0], desc[1] = desc[1], desc[0]
	b.decodeCase("codec.output", "descending ids", EncodeOutput(PackedOutput{Status: StatusReady, Header: hdr, Members: desc}), CodecOrder, do)
	dup := fxMembers(2, rid)
	dup[1].ID = 1
	b.decodeCase("codec.output", "duplicate ids", EncodeOutput(PackedOutput{Status: StatusReady, Header: hdr, Members: dup}), CodecOrder, do)
	b.decodeCase("codec.output", "payee high byte", mutate(r2, 64+224+8*32, 1), CodecNarrow, do)
	b.decodeCase("codec.output", "member id high byte", mutate(r2, 64+224, 1), CodecNarrow, do)
	b.decodeCase("codec.output", "attempt high byte", mutate(r2, 64+32*3, 1), CodecNarrow, do)

	da := func(r []byte) error { _, e := DecodeAdoption(r); return e }
	b.decodeCase("codec.adoption", "Ready", EncodeAdoption(StatusReady), CodecOK, da)
	b.decodeCase("codec.adoption", "NotReady", EncodeAdoption(StatusNotReady), CodecOK, da)
	b.decodeCase("codec.adoption", "Pending refused", EncodeAdoption(StatusPending), CodecRange, da)
	b.decodeCase("codec.adoption", "128 bytes oversize", Envelope(words(U64(0), Word{})), CodecOversize, da)
	b.decodeCase("codec.void", "empty", nil, CodecOK, func(r []byte) error { return DecodeVoid(r) })
	b.decodeCase("codec.void", "one word", make([]byte, 32), CodecOversize, func(r []byte) error { return DecodeVoid(r) })
	gb := words(U64(1), U64(2), U64(3), U64(4), U64(5), U64(6), U64(7), U64(8))
	dg := func(r []byte) error {
		_, e := DecodeMetadataWords(r, 8, []int{64, 64, 64, 64, 64, 64, 64, 64})
		return e
	}
	b.decodeCase("codec.metadata", "gasBounds 256", gb, CodecOK, dg)
	b.decodeCase("codec.metadata", "gasBounds 288 above 32x8", append(append([]byte{}, gb...), make([]byte, 32)...), CodecOversize, dg)
	b.decodeCase("codec.metadata", "gasBounds 224", gb[:224], CodecLength, dg)
	b.decodeCase("codec.metadata", "gasBounds word above uint64", mutate(gb, 0, 1), CodecNarrow, dg)
	dc := func(r []byte) error { _, e := DecodeMetadataWords(r, 1, []int{32}); return e }
	b.decodeCase("codec.metadata", "capabilities uint32", words(U64(3)), CodecOK, dc)
	b.decodeCase("codec.metadata", "capabilities above uint32", words(U64(1<<32)), CodecNarrow, dc)

	// --- elect context and attach context ---
	ctx := Context{Origin: w("origin"), Progress: 1000, UCTime: 1_700_000_000, KnownRootEpoch: 4, LastAcked: GenesisResult,
		Limits: CommitteeLimits{4, 5, 7}, DueWork: 2, ForceRemoved: 0b100}
	ce := ctx.Encode()
	if back, err := DecodeContext(ce); err != nil || back != ctx {
		b.fail("context round trip: %v", err)
	}
	b.add("context", "codec.context", map[string]any{"origin": Hexw(ctx.Origin), "progress": ctx.Progress, "ucTime": ctx.UCTime,
		"knownRootEpoch": ctx.KnownRootEpoch, "lastAcked": Hexw(ctx.LastAcked), "nMin": 4, "nTarget": 5, "nMax": 7, "dueWork": 2, "forceRemoved": 4},
		map[string]any{"bytes": Hexb(ce), "limitsWord": Hexw(ctx.Limits.LimitsWord())})
	b.add("context limits word high byte", "codec.context", map[string]any{"bytes": Hexb(mutate(ce, 5*32+19, 1))}, map[string]any{"result": string(Classify(func() error { _, e := DecodeContext(mutate(ce, 5*32+19, 1)); return e }()))})
	ac := AttachContext{LastAcked: GenesisResult, KnownRootEpoch: 4, Progress: 1000, UCTime: 1_700_000_000, IdentityCount: 5, Namespace: ValidatorRegistry,
		PrevModule: fxModule, PrevTag: PoaModuleTag, HolderIndex: 0, Committee: fxMembers(4, GenesisResult), InitData: []byte("init-data-17-bytes")}
	ab, err := ac.Encode()
	if err != nil {
		b.fail("attach: %v", err)
	}
	if back, err := DecodeAttachContext(ab); err != nil || len(back.Committee) != 4 || string(back.InitData) != string(ac.InitData) {
		b.fail("attach round trip: %v", err)
	}
	b.add("attach context n=4", "codec.attach", map[string]any{"holderIndex": 0, "n": 4, "initData": Hexb(ac.InitData)}, map[string]any{"bytes": Hexb(ab), "size": len(ab)})
	for name, bad := range map[string][]byte{
		"initData padding nonzero": mutate(ab, len(ab)-1, 1),
		"holder index 8":           mutate(ab, 9*32+31, 8),
		"version 2":                mutate(ab, 31, 2),
		"n=0":                      mutate(ab, 10*32+31, 0),
	} {
		_, err := DecodeAttachContext(bad)
		if err == nil {
			b.fail("attach %s accepted", name)
		}
		b.add("attach context "+name, "codec.attach", map[string]any{"bytes": Hexb(bad)}, map[string]any{"result": string(Classify(err))})
	}

	// --- digests ---
	ms := fxMembers(3, rid)
	for i, m := range ms {
		b.add(fmt.Sprintf("member %d", i+1), "digest.member", memberJSON(m), map[string]any{"words": Hexb(m.Words()), "hash": Hexw(MemberHash(m))})
	}
	md, _ := MembersDigest(ms)
	b.add("membersDigest n=3", "digest.members", map[string]any{"memberHashes": []string{Hexw(MemberHash(ms[0])), Hexw(MemberHash(ms[1])), Hexw(MemberHash(ms[2]))}},
		map[string]any{"membersDigest": Hexw(md)})
	if _, err := MembersDigest([]Member{ms[1], ms[0]}); err == nil {
		b.fail("descending members accepted")
	}
	kd, _ := MembersDigest(fxMembers(4, GenesisResult))
	empty, _ := ChangesDigest(nil)
	b.add("changesDigest empty", "digest.changes", map[string]any{"changes": []any{}}, map[string]any{"changesDigest": Hexw(empty)})
	bc := []BoundChange{{ID: 3, Kind: KindCommitteeLimits, PayloadHash: PayloadHash(mustChange(KindCommitteeLimits, uint64(4), uint64(5), uint64(7)))},
		{ID: 5, Kind: KindForceRemove, PayloadHash: PayloadHash(mustChange(KindForceRemove, uint64(2)))},
		{ID: 9, Kind: KindScheduleActivation, PayloadHash: w("schedule-payload")}}
	cd, _ := ChangesDigest(bc)
	var cj []any
	for _, c := range bc {
		cj = append(cj, map[string]any{"id": c.ID, "kind": c.Kind, "payloadHash": Hexw(c.PayloadHash)})
	}
	b.add("changesDigest n=3", "digest.changes", map[string]any{"changes": cj}, map[string]any{"changesDigest": Hexw(cd)})
	for _, native := range []bool{false, true} {
		tag := PoaModuleTag
		src := fxModule
		if native {
			tag = RegistryNative
		}
		in := OutputCommitInput{Network: fxNetwork, ChainID: fxChainID, Registry: ValidatorRegistry, ResultID: rid, Predecessor: GenesisResult, Attempt: 7,
			ModuleTag: tag, Native: native, SnapshotDigest: w("snapshot"), PolicyDigest: w("policy"), MembersDigest: md, KDigest: kd, ChangesDigest: cd}
		b.add(fmt.Sprintf("outputCommit native=%v", native), "digest.outputCommit", map[string]any{"network": Hexw(in.Network), "chainId": Hexw(in.ChainID),
			"registry": hexa(in.Registry), "resultId": Hexw(rid), "predecessor": Hexw(in.Predecessor), "attempt": 7, "moduleTag": Hexw(tag), "native": native,
			"snapshotDigest": Hexw(in.SnapshotDigest), "policyDigest": Hexw(in.PolicyDigest), "membersDigest": Hexw(md), "kDigest": Hexw(kd),
			"changesDigest": Hexw(cd), "sourceModule": hexa(src)}, map[string]any{"outputCommit": Hexw(OutputCommit(in))})
	}
	nr := NativeResultID(fxNetwork, fxChainID, ValidatorRegistry, GenesisResult, 2, w("origin"))
	b.add("native resultId", "digest.nativeResultId", map[string]any{"network": Hexw(fxNetwork), "chainId": Hexw(fxChainID), "registry": hexa(ValidatorRegistry),
		"lastAcked": Hexw(GenesisResult), "attempt": 2, "origin": Hexw(w("origin"))}, map[string]any{"resultId": Hexw(nr)})
	for _, binding := range []bool{false, true} {
		reg := fxRegistration(1, 4)
		id := uint64(0)
		op := "digest.register"
		if binding {
			reg, id, op = fxRegistration(7, 2), 1, "digest.binding"
		}
		d := RegistrationDigest(binding, fxNetwork, fxChainID, ValidatorRegistry, fxSender, id, reg)
		ri, ei := 2, 3
		if binding {
			ri, ei = 14, 15
		}
		in := regJSON(reg)
		in["network"], in["chainId"], in["registry"], in["sender"], in["id"] = Hexw(fxNetwork), Hexw(fxChainID), hexa(ValidatorRegistry), hexa(fxSender), id
		if err := reg.ValidShape(); err != nil {
			b.fail("registration shape: %v", err)
		}
		b.add(op, op, in, map[string]any{"digest": Hexw(d), "rootPoP": Hexb(signDigest(genKey(ri), d)), "evmPoP": Hexb(signDigest(genKey(ei), d))})
	}
	for _, bad := range []struct {
		name string
		f    func(*Registration)
	}{{"empty root node id", func(r *Registration) { r.RootNodeID = "" }}, {"129-byte evm node id", func(r *Registration) { r.EVMNodeID = string(make([]byte, 129)) }},
		{"32-byte key", func(r *Registration) { r.RootKey = r.RootKey[:32] }}, {"equal keys", func(r *Registration) { r.EVMKey = r.RootKey }},
		{"zero payee", func(r *Registration) { r.Payee = [20]byte{} }}} {
		r := fxRegistration(1, 0)
		bad.f(&r)
		err := r.ValidShape()
		if err == nil {
			b.fail("registration %s accepted", bad.name)
		}
		b.add("registration "+bad.name, "digest.registrationShape", regJSON(r), map[string]any{"error": err.Error()})
	}
	b.add("PoA exposure", "digest.poaExposure", map[string]any{"network": Hexw(fxNetwork), "chainId": Hexw(fxChainID), "registry": hexa(ValidatorRegistry),
		"resultId": Hexw(rid), "id": 3}, map[string]any{"exposureDigest": Hexw(PoaExposureDigest(fxNetwork, fxChainID, ValidatorRegistry, rid, 3))})
	if PoaExposureDigest(fxNetwork, fxChainID, ValidatorRegistry, rid, 3) != evmassign.ExposureID(evmassign.Deployment{NetworkWord: fxNetwork, ChainID: fxChainID, Custody: ValidatorRegistry}, rid, 3) {
		b.fail("PoA exposure is not the custody ExposureID formula")
	}
	b.add("retirement v2 dedup key", "digest.retirementV2Key", map[string]any{"holder": 0, "id": 7, "generation": 1},
		map[string]any{"key": Hexw(RetirementV2Key(0, 7, 1))})

	// --- records ---
	recs := []struct {
		name string
		kind uint8
		data []byte
	}{
		{"Boundary primary", RecBoundary, Boundary{ResultID: rid, ChangesEpoch: 5, InstalledRootEpoch: 5, InstalledShardEpoch: 9, ActivationRound: 1234, RejectedBitmap: 0b101}.Encode()},
		{"Boundary recovery", RecBoundary, Boundary{ResultID: rid, ChangesEpoch: 5, InstalledRootEpoch: 6, InstalledShardEpoch: 8, ActivationRound: 1300, Recovered: true}.Encode()},
		{"Boundary bitmap 16 changes", RecBoundary, Boundary{ResultID: rid, ChangesEpoch: 5, InstalledRootEpoch: 5, InstalledShardEpoch: 9, ActivationRound: 1, RejectedBitmap: 0xffff}.Encode()},
		{"OutputRejected Expired", RecOutputRejected, OutputRejected{ResultID: rid, Reason: RejExpired, ReadyBitmap: 0b0111}.Encode()},
		{"OutputRejected Invalidated", RecOutputRejected, OutputRejected{ResultID: rid, Reason: RejInvalidated}.Encode()},
		{"OutputRejected Invalid with member", RecOutputRejected, OutputRejected{ResultID: rid, Reason: RejInvalid, MemberID: 3}.Encode()},
		{"HolderRetirement", RecHolderRetirement, HolderRetirement{Holder: 0, ID: 7, Generation: 1, RefDigest: w("ref")}.Encode()},
		{"HolderRetirement max ids", RecHolderRetirement, HolderRetirement{Holder: 7, ID: ^uint64(0), Generation: ^uint64(0), RefDigest: w("ref")}.Encode()},
		{"PoPMissed", RecPoPMissed, PoPMissed{ResultID: rid, Deadline: 14_096, MissedBitmap: 0b10000}.Encode()},
		{"PoPMissed sixteen members", RecPoPMissed, PoPMissed{ResultID: rid, Deadline: ^uint64(0), MissedBitmap: 0xffff}.Encode()},
	}
	decodeRec := func(kind uint8, data []byte) error {
		switch kind {
		case RecBoundary:
			_, e := DecodeBoundary(data)
			return e
		case RecOutputRejected:
			_, e := DecodeOutputRejected(data)
			return e
		case RecHolderRetirement:
			_, e := DecodeHolderRetirement(data)
			return e
		case RecPoPMissed:
			_, e := DecodePoPMissed(data)
			return e
		}
		return CheckRecordPayload(kind, data)
	}
	for _, r := range recs {
		if err := decodeRec(r.kind, r.data); err != nil {
			b.fail("record %s: %v", r.name, err)
		}
		b.add(r.name, "record.decode", map[string]any{"kind": r.kind, "data": Hexb(r.data)}, map[string]any{"ok": true, "width": len(r.data)})
	}
	bnd := recs[0].data
	for _, bad := range []struct {
		name string
		kind uint8
		data []byte
	}{
		{"Boundary 192 bytes", RecBoundary, bnd[:192]},
		{"Boundary 256 bytes", RecBoundary, append(append([]byte{}, bnd...), make([]byte, 32)...)},
		{"Boundary recovered 2", RecBoundary, mutate(bnd, 5*32+31, 2)},
		{"Boundary bitmap bit 16", RecBoundary, mutate(bnd, 6*32+29, 1)},
		{"Boundary epoch high byte", RecBoundary, mutate(bnd, 32, 1)},
		{"Boundary zero result", RecBoundary, Boundary{ChangesEpoch: 1, InstalledRootEpoch: 1}.Encode()},
		{"Boundary recovery epoch not +1", RecBoundary, Boundary{ResultID: rid, ChangesEpoch: 5, InstalledRootEpoch: 5, Recovered: true}.Encode()},
		{"OutputRejected reason 0", RecOutputRejected, OutputRejected{ResultID: rid}.Encode()},
		{"OutputRejected reason 4", RecOutputRejected, OutputRejected{ResultID: rid, Reason: 4}.Encode()},
		{"OutputRejected reason high byte", RecOutputRejected, mutate(recs[3].data, 32+30, 1)},
		{"OutputRejected member outside Invalid", RecOutputRejected, OutputRejected{ResultID: rid, Reason: RejExpired, MemberID: 1}.Encode()},
		{"OutputRejected bitmap outside Expired", RecOutputRejected, OutputRejected{ResultID: rid, Reason: RejInvalid, ReadyBitmap: 1}.Encode()},
		{"HolderRetirement holder 8", RecHolderRetirement, HolderRetirement{Holder: 8, ID: 1, Generation: 1}.Encode()},
		{"HolderRetirement 96 bytes", RecHolderRetirement, recs[6].data[:96]},
		{"PoPMissed empty bitmap", RecPoPMissed, PoPMissed{ResultID: rid, Deadline: 1}.Encode()},
		{"PoPMissed zero result", RecPoPMissed, PoPMissed{Deadline: 1, MissedBitmap: 1}.Encode()},
		{"PoPMissed bitmap bit 16", RecPoPMissed, mutate(recs[8].data, 2*32+29, 1)},
		{"PoPMissed deadline high byte", RecPoPMissed, mutate(recs[8].data, 32, 1)},
		{"PoPMissed 128 bytes", RecPoPMissed, append(append([]byte{}, recs[8].data...), make([]byte, 32)...)},
		{"kind 10", 10, make([]byte, 32)},
		{"SessionClosed 64 bytes", RecSessionClosed, make([]byte, 64)},
		{"Ack id high byte", RecAck, mutate(make([]byte, 128), 32, 1)},
	} {
		err := decodeRec(bad.kind, bad.data)
		if err == nil {
			b.fail("record %s accepted", bad.name)
		}
		b.add(bad.name, "record.decode", map[string]any{"kind": bad.kind, "data": Hexb(bad.data)}, map[string]any{"ok": false, "error": err.Error()})
	}
	for k := uint8(1); k <= 9; k++ {
		b.add(fmt.Sprintf("width kind %d", k), "record.width", map[string]any{"kind": k, "types": RecordWordTypes[k]}, map[string]any{"width": RecordWidths[k]})
		if 32*len(RecordWordTypes[k]) != RecordWidths[k] {
			b.fail("width %d", k)
		}
	}
	b.add("import gas inputs", "record.gas", map[string]any{"scanBase": ImportScanBaseGas, "scanByte": ImportScanByteGas, "entry": ImportEntryGas,
		"maxBytes": ImportMaxBytes, "maxEntries": ImportMaxEntries}, map[string]any{"maxAdmission": ImportScanBaseGas + ImportScanByteGas*ImportMaxBytes + ImportEntryGas*ImportMaxEntries,
		"widestNewKindWords": 7, "executionBoundWords": ImportMaxWordsSeen})

	// --- change payloads ---
	pdr := fxPDR(7, 3, 2, 0, 3)
	shard := pdr.ShardID.Bytes()
	succ := fxPDR(7, 3, 3, 3, 3)
	payloads := []struct {
		name string
		kind uint8
		vals []any
	}{
		{"SetModule", KindSetModule, []any{fxModule, w("code"), []byte("init")}},
		{"ModuleAction Admit", KindModuleAction, []any{fxModule, words(U64(ModuleActionAdmit), U64(5))}},
		{"SetGovernor", KindSetGovernor, []any{fxOther, w("multisig-code")}},
		{"CommitteeLimits", KindCommitteeLimits, []any{uint64(4), uint64(5), uint64(7)}},
		{"FeeParams floor 1<<62", KindFeeParams, []any{MaxBaseFee, uint64(8), fxOther}},
		{"ReplaceAggregatorValidators", KindReplaceAggregator, []any{uint64(7), shard, pdrHash(pdr), mustCBOR(succ), fxChangePoPs(11, succ, 3)}},
		{"AddPartition", KindAddPartition, []any{mustCBOR(fxPDR(9, 3, 0, 10, 2)), fxChangePoPs(12, fxPDR(9, 3, 0, 10, 2), 10)}},
		{"UpdatePartition", KindUpdatePartition, []any{uint64(7), shard, pdrHash(pdr), mustCBOR(fxPDR(7, 3, 3, 0, 3))}},
		{"ScheduleActivation", KindScheduleActivation, []any{RuleID("vr-handoff-v2"), w("release-1.2.0"), uint64(12), uint64(1_700_100_000), "release 1.2.0"}},
		{"ForceRemove", KindForceRemove, []any{uint64(3)}},
	}
	var sm []byte
	for _, p := range payloads {
		enc := mustChange(p.kind, p.vals...)
		back, err := DecodeChangePayload(p.kind, enc)
		if err != nil || len(back) != len(p.vals) {
			b.fail("payload %s: %v", p.name, err)
		}
		b.add(p.name, "change.payload", map[string]any{"kind": p.kind, "types": ChangePayloadTypes[p.kind], "fields": ChangePayloadFields[p.kind], "values": abiJSON(p.vals)},
			map[string]any{"payload": Hexb(enc), "payloadHash": Hexw(PayloadHash(enc)), "size": len(enc)})
		if p.kind == KindSetModule {
			sm = enc
		}
	}
	lim := mustChange(KindCommitteeLimits, uint64(4), uint64(5), uint64(7))
	sched := mustChange(KindScheduleActivation, RuleID("r"), w("rel"), uint64(12), uint64(5000), "ok")
	badUTF := mustChange(KindScheduleActivation, RuleID("r"), w("rel"), uint64(12), uint64(5000), "ab")
	badUTF[len(badUTF)-32] = 0xff
	for _, bad := range []struct {
		name string
		kind uint8
		data []byte
	}{
		{"SetModule offset 0x80", KindSetModule, mutate(sm, 2*32+31, 0x80)},
		{"SetModule nonzero padding", KindSetModule, mutate(sm, len(sm)-1, 1)},
		{"SetModule length beyond data", KindSetModule, mutate(sm, 3*32+31, 64)},
		{"SetModule trailing word", KindSetModule, append(append([]byte{}, sm...), make([]byte, 32)...)},
		{"SetModule address high byte", KindSetModule, mutate(sm, 0, 1)},
		{"CommitteeLimits nMin above uint32", KindCommitteeLimits, mutate(lim, 27, 1)},
		{"CommitteeLimits 64 bytes", KindCommitteeLimits, lim[:64]},
		{"payload 16385 bytes", KindSetModule, mustOversize()},
		{"unknown kind 11", 11, lim},
	} {
		_, err := DecodeChangePayload(bad.kind, bad.data)
		if err == nil {
			b.fail("payload %s accepted", bad.name)
		}
		b.add(bad.name, "change.payload", map[string]any{"kind": bad.kind, "payload": Hexb(bad.data)}, map[string]any{"ok": false, "error": err.Error()})
	}
	_ = sched
	if _, err := DecodeChangePayload(KindScheduleActivation, badUTF); err != nil {
		b.fail("non-UTF-8 label refused: %v", err)
	}
	b.add("ScheduleActivation label of non-UTF-8 bytes is canonical", "change.canonicality", map[string]any{"kind": KindScheduleActivation, "payload": Hexb(badUTF)},
		map[string]any{"ok": true, "note": "byte canonicality only; no UTF-8 or length rule beyond the 16 KiB payload bound"})
	env := QueueEnv{KnownRootEpoch: 4, UCTime: 10_000, Pending: 3, PendingForce: 1, Committee: []uint64{1, 2, 3, 4, 5}, MaxGas: 30_000_000, SystemGas: 2_000_000}
	queue := []struct {
		name string
		kind uint8
		vals []any
		env  func(QueueEnv) QueueEnv
	}{
		{"limits valid", KindCommitteeLimits, []any{uint64(1), uint64(5), uint64(16)}, nil},
		{"limits nMax 17", KindCommitteeLimits, []any{uint64(1), uint64(5), uint64(17)}, nil},
		{"limits nMin 0", KindCommitteeLimits, []any{uint64(0), uint64(5), uint64(7)}, nil},
		{"limits nTarget below nMin", KindCommitteeLimits, []any{uint64(5), uint64(4), uint64(7)}, nil},
		{"fees floor 1<<62", KindFeeParams, []any{MaxBaseFee, uint64(8), fxOther}, nil},
		{"fees floor 1<<62 + 1", KindFeeParams, []any{MaxBaseFee + 1, uint64(8), fxOther}, nil},
		{"fees denominator 0", KindFeeParams, []any{uint64(1), uint64(0), fxOther}, nil},
		{"fees zero collector", KindFeeParams, []any{uint64(1), uint64(8), [20]byte{}}, nil},
		{"fees odd ordinary capacity", KindFeeParams, []any{uint64(1), uint64(8), fxOther}, func(e QueueEnv) QueueEnv { e.MaxGas++; return e }},
		{"schedule rootEpoch = known + 3", KindScheduleActivation, []any{RuleID("r"), w("rel"), uint64(7), uint64(13_600), ""}, nil},
		{"schedule rootEpoch = known + 2", KindScheduleActivation, []any{RuleID("r"), w("rel"), uint64(6), uint64(13_600), ""}, nil},
		{"schedule notBefore = ucTime + 3599", KindScheduleActivation, []any{RuleID("r"), w("rel"), uint64(7), uint64(13_599), ""}, nil},
		{"schedule label of 65 bytes (no label cap)", KindScheduleActivation, []any{RuleID("r"), w("rel"), uint64(7), uint64(13_600), string(make([]byte, 65))}, nil},
		{"schedule zero ruleId (FD-24)", KindScheduleActivation, []any{Word{}, w("rel"), uint64(7), uint64(13_600), ""}, nil},
		{"empty module action (no rule)", KindModuleAction, []any{fxModule, []byte{}}, nil},
		{"AddPartition with an unreadable partition id (FD-25)", KindAddPartition, []any{[]byte{0x83, 1, 2, 3}, []byte{0x80}}, nil},
		{"AddPartition with a readable PDR head", KindAddPartition, []any{mustCBOR(fxPDR(9, 3, 0, 10, 2)), []byte{0x80}}, nil},
		{"force remove member", KindForceRemove, []any{uint64(3)}, nil},
		{"force remove non-member", KindForceRemove, []any{uint64(9)}, nil},
		{"force remove fifth pending", KindForceRemove, []any{uint64(3)}, func(e QueueEnv) QueueEnv { e.PendingForce = 4; return e }},
		{"thirty-third pending change", KindCommitteeLimits, []any{uint64(1), uint64(5), uint64(7)}, func(e QueueEnv) QueueEnv { e.Pending = 32; return e }},
		{"set module zero code hash", KindSetModule, []any{fxModule, Word{}, []byte{}}, nil},
	}
	for _, q := range queue {
		e := env
		if q.env != nil {
			e = q.env(env)
		}
		p := mustChange(q.kind, q.vals...)
		err := QueueCheck(q.kind, p, e)
		b.add("queue "+q.name, "change.queue", map[string]any{"kind": q.kind, "payload": Hexb(p), "knownRootEpoch": e.KnownRootEpoch, "ucTime": e.UCTime,
			"pending": e.Pending, "pendingForceRemove": e.PendingForce, "committee": e.Committee, "maxGas": e.MaxGas, "systemGas": e.SystemGas},
			map[string]any{"ok": err == nil, "error": errName(err)})
	}

	// --- VR-mode controls ---
	chain := [32]byte(fxChainID)
	sc := fxSupport(1, RuleID("vr-handoff-v2"), w("release-1.2.0"))
	sc2 := fxSupport(1, RuleID("zz-other-rule"), w("release-1.2.0"))
	if string(sc.RuleID) > string(sc2.RuleID) {
		sc, sc2 = sc2, sc
	}
	ctlCases := []struct {
		name string
		op   uint64
		ctx  ControlContext
		data []byte
		wh   [32]byte
	}{
		{"HandoffView", OpHandoffView, ControlContext{IntentDigest: wb("intent"), View: 3}, nil, [32]byte{}},
		{"RuleSupport two rules", OpRuleSupport, ControlContext{Commitments: []SupportCommitment{sc, sc2}}, nil, [32]byte{}},
		{"HolderRetirement v2", OpHolderRetirement, ControlContext{EVMBlockHash: wb("block"), EVMStateRoot: wb("state")}, recs[6].data, w("witness")},
		{"RejectResult v2", OpRejectResult, ControlContext{Predecessor: wb("pred"), Attempt: 2, EVMBlockHash: wb("block"), EVMStateRoot: wb("state")}, recs[3].data, w("witness")},
		{"CloseLiability", OpCloseLiability, ControlContext{ClosedEpoch: 4, BundleSemanticID: wb("bundle")}, make([]byte, 192), w("witness")},
		{"PoPRequest", OpPoPRequest, ControlContext{IntentDigest: wb("intent")}, nil, [32]byte{}},
		{"RejectResult v2 with certified misses", OpRejectResult, ControlContext{Predecessor: wb("pred"), Attempt: 2, EVMBlockHash: wb("block"), EVMStateRoot: wb("state"),
			Misses: fxMisses()}, recs[3].data, w("witness")},
	}
	for _, c := range ctlCases {
		enc, err := EncodeVRControl(fxRootNetwork, chain, ValidatorRegistry, 5, 900, c.op, c.ctx, c.data, c.wh)
		if err != nil {
			b.fail("control %s: %v", c.name, err)
			continue
		}
		if op, _, _, err := DecodeVRControl(enc); err != nil || op != c.op {
			b.fail("control %s decode: %v", c.name, err)
		}
		b.add(c.name, "control.encode", map[string]any{"op": c.op, "network": fxRootNetwork, "chainId": Hexw(fxChainID), "registry": hexa(ValidatorRegistry),
			"orderingEpoch": 5, "orderingRound": 900, "data": Hexb(c.data), "witnessHash": Hexb(c.wh[:])}, map[string]any{"bytes": Hexb(enc)})
	}
	for _, c := range []struct {
		name string
		op   uint64
		ctx  ControlContext
		data []byte
		wh   [32]byte
	}{
		{"HandoffView view 0", OpHandoffView, ControlContext{IntentDigest: wb("intent"), View: 0}, nil, [32]byte{}},
		{"HandoffView with data", OpHandoffView, ControlContext{IntentDigest: wb("intent"), View: 1}, make([]byte, 32), [32]byte{}},
		{"HandoffView with witness", OpHandoffView, ControlContext{IntentDigest: wb("intent"), View: 1}, nil, w("witness")},
		{"RuleSupport unsorted", OpRuleSupport, ControlContext{Commitments: []SupportCommitment{sc2, sc}}, nil, [32]byte{}},
		{"RuleSupport empty", OpRuleSupport, ControlContext{}, nil, [32]byte{}},
		{"RejectResult v1 width", OpRejectResult, ControlContext{Predecessor: wb("pred"), EVMBlockHash: wb("b"), EVMStateRoot: wb("s")}, rid[:], w("witness")},
		{"PoPRequest zero intent", OpPoPRequest, ControlContext{IntentDigest: make([]byte, 32)}, nil, [32]byte{}},
		{"PoPRequest with witness", OpPoPRequest, ControlContext{IntentDigest: wb("intent")}, nil, w("witness")},
		{"RejectResult misses unsorted", OpRejectResult, ControlContext{Predecessor: wb("pred"), Attempt: 2, EVMBlockHash: wb("block"), EVMStateRoot: wb("state"),
			Misses: []MissCertificate{fxMisses()[1], fxMisses()[0]}}, recs[3].data, w("witness")},
		{"op 7", 7, ControlContext{}, nil, [32]byte{}},
	} {
		_, err := EncodeVRControl(fxRootNetwork, chain, ValidatorRegistry, 5, 900, c.op, c.ctx, c.data, c.wh)
		if err == nil {
			b.fail("control %s accepted", c.name)
		}
		b.add(c.name, "control.encode", map[string]any{"op": c.op}, map[string]any{"ok": false, "error": err.Error()})
	}
	pr, _ := ProjectRejectResult(recs[3].data)
	b.add("RejectResult projection", "control.project", map[string]any{"data": Hexb(recs[3].data)},
		map[string]any{"records": []any{map[string]any{"kind": pr[0][0], "data": Hexb(pr[0][1].([]byte))}, map[string]any{"kind": pr[1][0], "data": Hexb(pr[1][1].([]byte))}}})
	pm, err := ProjectRejectResultMissed(recs[3].data, PoPMissed{Deadline: 14_096, MissedBitmap: 0b10000})
	if err != nil || len(pm) != 3 {
		b.fail("RejectResult projection with misses: %v", err)
	} else {
		var rs []any
		for _, x := range pm {
			rs = append(rs, map[string]any{"kind": x[0], "data": Hexb(x[1].([]byte))})
		}
		b.add("RejectResult projection with certified misses", "control.project", map[string]any{"data": Hexb(recs[3].data), "deadline": Dec(14_096),
			"missedBitmap": 0b10000}, map[string]any{"records": rs})
	}
	genPoPMissEncodings(b, rid)

	// --- candidate v6, handoff messages, Freeze v5 ---
	genHandoffEncodings(b, rid)
	return b.out, b.err
}

func mustOversize() []byte {
	b, _ := EncodeABI(ChangePayloadTypes[KindSetModule], []any{fxModule, w("code"), make([]byte, MaxChangePayload-128+1)})
	return b
}

func memberJSON(m Member) map[string]any {
	return map[string]any{"id": m.ID, "generation": m.Generation, "weight": m.Weight, "rawWeight": m.RawWeight, "rootNodeWord": Hexw(m.RootNodeWord),
		"rootKeyHash": Hexw(m.RootKeyHash), "evmNodeWord": Hexw(m.EVMNodeWord), "evmKeyHash": Hexw(m.EVMKeyHash), "payee": hexa(m.Payee),
		"exposureDigest": Hexw(m.ExposureDigest)}
}

func regJSON(r Registration) map[string]any {
	return map[string]any{"rootNodeId": r.RootNodeID, "rootKey": Hexb(r.RootKey), "evmNodeId": r.EVMNodeID, "evmKey": Hexb(r.EVMKey),
		"payee": hexa(r.Payee), "nonce": r.Nonce}
}

func abiJSON(vals []any) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		switch x := v.(type) {
		case [20]byte:
			out[i] = hexa(x)
		case Word:
			out[i] = Hexw(x)
		case []byte:
			out[i] = Hexb(x)
		case uint64:
			out[i] = Dec(x)
		default:
			out[i] = x
		}
	}
	return out
}

// fxSupport is a support commitment by member id's root key (test key 2*id).
func fxSupport(id uint64, rule, release Word) SupportCommitment {
	sid := U64(id)
	kh := keccak(pubOf(genKey(int(2 * id))))
	ref := Member{ID: id, Generation: 1, RootNodeWord: keccak([]byte(fmt.Sprintf("root-%d", id))), RootKeyHash: kh, EVMNodeWord: keccak([]byte(fmt.Sprintf("evm-%d", id))),
		EVMKeyHash: keccak(pubOf(genKey(int(2*id + 1)))), Payee: [20]byte{byte(id)}}.BindingRef()
	c := SupportCommitment{Network: fxRootNetwork, StakingID: sid[:], Generation: 1, RootKeyHash: kh[:], BindingRef: ref[:], RuleID: rule[:], ReleaseDigest: release[:]}
	msg, err := c.SignedBytes()
	if err != nil {
		panic(err)
	}
	c.Sig, err = signerOf(genKey(int(2 * id))).SignBytes(msg)
	if err != nil {
		panic(err)
	}
	return c
}

func genHandoffEncodings(b *vb, rid Word) {
	ids := []evmassign.Identity{}
	for i := 1; i <= 4; i++ {
		r := fxRegistration(i, 0)
		sid := U64(uint64(i))
		exp := PoaExposureDigest(fxNetwork, fxChainID, ValidatorRegistry, rid, uint64(i))
		ids = append(ids, evmassign.Identity{StakingID: sid[:], Generation: 1, RootNodeID: r.RootNodeID, RootKey: r.RootKey, EVMNodeID: r.EVMNodeID,
			EVMKey: r.EVMKey, Weight: 1, RawWeight: 1, OperatorPayee: r.Payee[:], ExposureDigest: exp[:]})
	}
	limits := mustChange(KindCommitteeLimits, uint64(4), uint64(4), uint64(7))
	sched := mustChange(KindScheduleActivation, RuleID("vr-handoff-v2"), w("release-1.2.0"), uint64(12), uint64(1_700_100_000), "release 1.2.0")
	rc := []RegistryChange{{ID: 3, Kind: uint64(KindCommitteeLimits), Payload: limits, Verdict: 0}, {ID: 9, Kind: uint64(KindScheduleActivation), Payload: sched, Verdict: uint64(VerdictPastCutoff)}}
	c := CandidateV6{Version: CandidateV6Version, Kind: evmassign.KindPrimary, Network: fxRootNetwork, Predecessor: wb("pred-body"), Attempt: 1,
		OldShardEpoch: 4, OldActiveHash: wb("old-active"), Assignment: mustCBOR(fxPDR(2, 8, 5, 40, 4)), Identities: ids, SourceRef: rid[:], RegistryChanges: rc}
	for _, i := range ids {
		c.RootMembers = append(c.RootMembers, evmassign.RootMember{NodeID: i.RootNodeID, Key: i.RootKey, Weight: 1})
		c.Bindings = append(c.Bindings, evmassign.Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
	}
	enc, err := c.Encode()
	if err != nil {
		b.fail("candidate v6: %v", err)
		return
	}
	if back, err := DecodeCandidateV6(enc); err != nil || len(back.RegistryChanges) != 2 {
		b.fail("candidate v6 round trip: %v", err)
	}
	cdig := sha256.Sum256(enc)
	chd, _ := ChangesDigestOf(rc)
	// independent check: the unsigned candidate's PoPs (field 10) is the empty CBOR array 0x80 and Changes (field 16) is null 0xf6
	var generic []any
	if err := types.Cbor.Unmarshal(enc, &generic); err != nil || len(generic) != 2 {
		b.fail("candidate generic decode: %v", err)
		return
	}
	fields := generic[1].([]any)
	if pops, ok := fields[9].([]any); !ok || len(pops) != 0 || fields[15] != nil {
		b.fail("candidate v6: PoPs %#v Changes %#v", fields[9], fields[15])
	}
	b.add("candidate v6 unsigned", "handoff.candidateV6", map[string]any{"sourceRef": Hexw(rid), "registryChanges": rcJSON(rc)},
		map[string]any{"bytes": Hexb(enc), "digest": Hexb(cdig[:]), "rejectedBitmap": RejectedBitmap(rc), "changesDigest": Hexw(chd),
			"popsField": "0x80 (empty array)", "changesField": "0xf6 (null)"})
	nullPoPs, _ := types.Cbor.Marshal([]any{candidateDomain, c}) // c.PoPs is nil here: the non-canonical null form
	if _, err := DecodeCandidateV6(nullPoPs); err == nil || bytes.Equal(nullPoPs, enc) {
		b.fail("candidate with null PoPs accepted")
	}
	b.add("candidate v6 with PoPs null refused", "handoff.candidateV6", map[string]any{"bytes": Hexb(nullPoPs)}, map[string]any{"ok": false, "error": "non-canonical encoding"})
	for name, f := range map[string]func(*CandidateV6){
		"v5 version":         func(x *CandidateV6) { x.Version = 5 },
		"empty SourceRef":    func(x *CandidateV6) { x.SourceRef = nil },
		"carried Changes":    func(x *CandidateV6) { x.Changes = []evmassign.Change{{Kind: 1, Payload: []byte{1}}} },
		"ModuleAction entry": func(x *CandidateV6) { x.RegistryChanges = []RegistryChange{{ID: 1, Kind: 2, Payload: limits}} },
		"descending ids":     func(x *CandidateV6) { x.RegistryChanges = []RegistryChange{rc[1], rc[0]} },
		"rejected EVM-side": func(x *CandidateV6) {
			x.RegistryChanges = []RegistryChange{{ID: 3, Kind: 4, Payload: limits, Verdict: 1}}
		},
		"two CommitteeLimits": func(x *CandidateV6) {
			x.RegistryChanges = []RegistryChange{{ID: 3, Kind: 4, Payload: limits}, {ID: 4, Kind: 4, Payload: limits}}
		},
		"verdict 16 (EVM-only)": func(x *CandidateV6) {
			x.RegistryChanges = []RegistryChange{{ID: 9, Kind: 9, Payload: sched, Verdict: 16}}
		},
	} {
		x := c
		f(&x)
		_, err := x.Encode()
		if err == nil {
			b.fail("candidate %s accepted", name)
		}
		b.add("candidate v6 "+name, "handoff.candidateV6", map[string]any{"mutation": name}, map[string]any{"ok": false, "error": err.Error()})
	}

	src := Source{ResultID: rid[:], EVMBlockHash: wb("evm-block"), EVMBlockNumber: 812, CertRootRound: 4400, OutputCommit: wb("commit")}
	in := Intent{Version: IntentVersion, Network: fxRootNetwork, Genesis: wb("genesis"), PredecessorBodyID: wb("pred-body"), Attempt: 1,
		AnchorRound: AnchorRound(4400, 4390), Source: src, Candidate: enc}
	ie, err := in.Encode()
	if err != nil {
		b.fail("intent: %v", err)
		return
	}
	idg := sha256.Sum256(ie)
	b.add("intent", "handoff.intent", map[string]any{"anchorRound": in.AnchorRound, "attemptOpenRound": 4390, "certRootRound": 4400, "candidate": Hexb(enc)},
		map[string]any{"bytes": Hexb(ie), "intentDigest": Hexb(idg[:]), "earliestActivation": EarliestActivation(in.AnchorRound)})
	order := AssemblerOrder(idg, []string{fxNodeID(2), fxNodeID(4), fxNodeID(6), fxNodeID(8), fxNodeID(10)})
	b.add("assembler order n=5", "handoff.assemblerOrder", map[string]any{"intentDigest": Hexb(idg[:]), "incumbents": []string{fxNodeID(2), fxNodeID(4), fxNodeID(6), fxNodeID(8), fxNodeID(10)}},
		map[string]any{"order": order, "assemblerOfSlot7": Assembler(order, 7)})
	// the assembled candidate (here the unsigned one stands in; PoP bytes are verified, not compared)
	asm := Assembly{IntentDigest: idg[:], Slot: 2, Candidate: enc}
	asb, _ := asm.SignedBytes()
	asm.Sig, _ = signerOf(genKey(2)).SignBytes(asb)
	if Verify(pubOf(genKey(2)), asm.Sig, asb) != nil {
		b.fail("assembly signature")
	}
	b.add("assembly", "handoff.assembly", map[string]any{"intentDigest": Hexb(idg[:]), "slot": 2, "candidate": Hexb(enc), "signerKey": Hexb(pubOf(genKey(2)))},
		map[string]any{"signedBytes": Hexb(asb), "sig": Hexb(asm.Sig), "bytes": Hexb(mustCBOR(asm))})
	scs := []SupportCommitment{fxSupport(1, RuleID("vr-handoff-v2"), w("release-1.2.0"))}
	scm, _ := scs[0].SignedBytes()
	scd, _ := scs[0].Digest()
	b.add("support commitment", "handoff.supportCommitment", map[string]any{"network": fxRootNetwork, "stakingId": Hexb(scs[0].StakingID), "generation": 1,
		"rootKeyHash": Hexb(scs[0].RootKeyHash), "ruleId": Hexb(scs[0].RuleID), "releaseDigest": Hexb(scs[0].ReleaseDigest)},
		map[string]any{"signedBytes": Hexb(scm), "sig": Hexb(scs[0].Sig), "digest": Hexb(scd[:])})
	rsd, _ := RuleSupportDigest(scs)
	rse, _ := RuleSupportDigest([]SupportCommitment{})
	b.add("rule support digest one rule", "handoff.ruleSupportDigest", map[string]any{"commitments": 1}, map[string]any{"digest": Hexb(rsd[:])})
	b.add("rule support digest empty", "handoff.ruleSupportDigest", map[string]any{"commitments": 0}, map[string]any{"digest": Hexb(rse[:])})
	var readiness []Readiness
	body := w("successor-body")
	for i := 1; i <= 4; i++ {
		cs := []SupportCommitment{fxSupport(uint64(i), RuleID("vr-handoff-v2"), w("release-1.2.0"))}
		d, _ := RuleSupportDigest(cs)
		rctx := q3format.ReceiptContext{Network: fxRootNetwork, Genesis: w("genesis"), Predecessor: w("pred-body"), Attempt: 1, CandidateDigest: cdig,
			BodyID: body, Config: w("q3-config")}
		rcpt, err := q3format.SignReceipt(rctx, ids[i-1].RootNodeID, signerOf(genKey(2*i)))
		if err != nil {
			b.fail("receipt: %v", err)
		}
		rset, err := EncodeReadinessReceipt(rcpt)
		if err != nil {
			b.fail("receipt set: %v", err)
		}
		r := Readiness{IntentDigest: idg[:], Slot: 2, CandidateDigest: cdig[:], BodyID: body[:], RuleSupportDigest: d[:], Commitments: cs,
			Receipt: rset, TrustBaseSig: []byte(fmt.Sprintf("trust-base-sig-%d", i))}
		if i == 1 {
			b.add("readiness receipt (singleton q3format receipt set)", "handoff.receipt", map[string]any{"network": rctx.Network, "genesis": Hexw(rctx.Genesis),
				"predecessor": Hexw(rctx.Predecessor), "attempt": rctx.Attempt, "candidateDigest": Hexw(rctx.CandidateDigest), "bodyId": Hexw(rctx.BodyID),
				"config": Hexw(rctx.Config), "nodeId": rcpt.NodeID, "signerKey": Hexb(pubOf(genKey(2)))},
				map[string]any{"message": Hexb(rctx.Message(rcpt.NodeID)), "signature": Hexb(rcpt.Signature), "receipt": Hexb(rset)})
		}
		env, err := r.EnvelopeBytes()
		if err != nil {
			b.fail("readiness: %v", err)
		}
		r.EnvelopeSig, _ = signerOf(genKey(2 * i)).SignBytes(env)
		readiness = append(readiness, r)
		if i == 1 {
			b.add("readiness envelope", "handoff.readiness", map[string]any{"intentDigest": Hexb(idg[:]), "slot": 2, "candidateDigest": Hexb(cdig[:]),
				"bodyId": Hexw(body), "ruleSupportDigest": Hexb(d[:]), "trustBaseSig": Hexb(r.TrustBaseSig), "signerKey": Hexb(pubOf(genKey(2)))},
				map[string]any{"envelopeBytes": Hexb(env), "envelopeSig": Hexb(r.EnvelopeSig), "bytes": Hexb(mustEnc(r.Encode()))})
			nr := r
			nr.Commitments = nil
			raw := mustCBOR(nr)
			if _, err := DecodeReadiness(raw); err == nil {
				b.fail("readiness with null commitments accepted")
			}
			b.add("readiness with commitments null refused", "handoff.readiness", map[string]any{"bytes": Hexb(raw)}, map[string]any{"ok": false})
		}
	}
	var succIDs []string
	for _, i := range ids {
		succIDs = append(succIDs, i.RootNodeID)
	}
	cert := ViewCertificate{Assembly: asm, Readiness: readiness}
	if err := cert.CheckShape(succIDs, body[:]); err != nil {
		b.fail("certificate: %v", err)
	}
	b.add("view certificate", "handoff.certificate", map[string]any{"successors": succIDs}, map[string]any{"bytes": Hexb(mustEnc(cert.Encode())), "ok": true})
	for name, f := range map[string]func(*ViewCertificate){
		"three readiness for four": func(c *ViewCertificate) { c.Readiness = c.Readiness[:3] },
		"readiness of another slot": func(c *ViewCertificate) {
			r := c.Readiness[1]
			r.Slot = 3
			c.Readiness = append([]Readiness{c.Readiness[0], r}, c.Readiness[2:]...)
		},
		"readiness of another body": func(c *ViewCertificate) {
			r := c.Readiness[1]
			r.BodyID = wb("x")
			c.Readiness = append([]Readiness{c.Readiness[0], r}, c.Readiness[2:]...)
		},
		"receipt of another member": func(c *ViewCertificate) {
			r := c.Readiness[1]
			r.Receipt = c.Readiness[0].Receipt
			c.Readiness = append([]Readiness{c.Readiness[0], r}, c.Readiness[2:]...)
		},
		"receipt set of two": func(c *ViewCertificate) {
			r0, _ := ReadinessReceipt(c.Readiness[0].Receipt, succIDs[0])
			r1, _ := ReadinessReceipt(c.Readiness[1].Receipt, succIDs[1])
			two, _ := q3format.EncodeReceipts([]q3format.Receipt{r0, r1})
			r := c.Readiness[0]
			r.Receipt = two
			c.Readiness = append([]Readiness{r}, c.Readiness[1:]...)
		},
		"rule support digest wrong": func(c *ViewCertificate) {
			r := c.Readiness[2]
			r.RuleSupportDigest = rse[:]
			c.Readiness = append(append([]Readiness{}, c.Readiness[:2]...), append([]Readiness{r}, c.Readiness[3:]...)...)
		},
	} {
		x := ViewCertificate{Assembly: cert.Assembly, Readiness: append([]Readiness{}, cert.Readiness...)}
		f(&x)
		err := x.CheckShape(succIDs, body[:])
		if err == nil {
			b.fail("certificate %s accepted", name)
		}
		b.add("view certificate "+name, "handoff.certificate", map[string]any{"mutation": name}, map[string]any{"ok": false, "error": err.Error()})
	}
	ref, _ := fxSupport(3, RuleID("vr-handoff-v2"), w("release-1.2.0")).Digest()
	kr := func(id uint64) Readiness {
		cs := []SupportCommitment{fxSupport(id, RuleID("vr-handoff-v2"), w("release-1.2.0"))}
		d, _ := RuleSupportDigest(cs)
		r := Readiness{IntentDigest: idg[:], Slot: 2, CandidateDigest: cdig[:], BodyID: body[:], RuleSupportDigest: d[:], Commitments: cs,
			Receipt: []byte{}, TrustBaseSig: []byte(fmt.Sprintf("k-trust-base-sig-%d", id))}
		env, _ := r.EnvelopeBytes()
		r.EnvelopeSig, _ = signerOf(genKey(int(2 * id))).SignBytes(env)
		return r
	}
	fz := FreezeV5{Candidate: enc, Certificate: cert, RuleSupport: RuleSupportEvidence{Refs: [][]byte{ref[:]}, Fresh: []SupportCommitment{fxSupport(5, RuleID("vr-handoff-v2"), w("release-1.2.0"))},
		KReadiness: []Readiness{kr(6), kr(7)}}, Witness: []byte("witness-bytes")}
	fze, err := fz.Encode()
	if err != nil {
		b.fail("freeze: %v", err)
	}
	if back, err := DecodeFreezeV5(fze); err != nil || len(back.RuleSupport.KReadiness) != 2 {
		b.fail("freeze round trip: %v", err)
	}
	b.add("freeze v5", "handoff.freezeV5", map[string]any{"refs": 1, "fresh": 1, "kReadiness": []int{6, 7}}, map[string]any{"bytes": Hexb(fze), "witnessHash": Hexb(func() []byte { h := sha256.Sum256(fz.Witness); return h[:] }())})
	for _, m := range []struct {
		name string
		ks   []Readiness
	}{{"K readiness descending", []Readiness{kr(7), kr(6)}}, {"K readiness duplicate", []Readiness{kr(6), kr(6)}},
		{"K readiness without commitments", func() []Readiness { r := kr(6); r.Commitments = []SupportCommitment{}; return []Readiness{r} }()}} {
		x := fz
		x.RuleSupport.KReadiness = m.ks
		_, err := x.Encode()
		if err == nil {
			b.fail("freeze %s accepted", m.name)
		}
		b.add("freeze v5 "+m.name, "handoff.freezeV5", map[string]any{"mutation": m.name}, map[string]any{"ok": false, "error": err.Error()})
	}
	nullRefs, _ := types.Cbor.Marshal([]any{FreezeDomain, uint64(FreezeVersion), FreezeV5{Candidate: enc, Certificate: cert.canonical(), Witness: []byte("w")}})
	if _, err := DecodeFreezeV5(nullRefs); err == nil {
		b.fail("freeze with null lists accepted")
	}
	b.add("freeze v5 with null evidence lists refused", "handoff.freezeV5", map[string]any{"bytes": Hexb(nullRefs)}, map[string]any{"ok": false})
	bo := HandoffBackoff{Level: 3, Epoch: 5, Attempt: 2, N: 4, Intent: idg[:], LastView: 6, Prepared: true}
	boe, _ := bo.Encode()
	bod, _ := bo.Digest()
	b.add("backoff state", "handoff.backoffState", map[string]any{"level": 3, "epoch": 5, "attempt": 2, "n": 4, "intent": Hexb(idg[:]), "lastView": 6, "prepared": true, "settled": false},
		map[string]any{"bytes": Hexb(boe), "digest": Hexb(bod[:])})
}

func rcJSON(rc []RegistryChange) []any {
	var out []any
	for _, c := range rc {
		out = append(out, map[string]any{"id": c.ID, "kind": c.Kind, "payload": Hexb(c.Payload), "verdict": c.Verdict})
	}
	return out
}
