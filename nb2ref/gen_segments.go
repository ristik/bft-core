package nb2ref

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Seal receipt, gap proof, chain fold, segment log, wallet and primitive vectors.

// syntheticVerdict is a mock verifier's verdict for a vault of domain d.
func syntheticVerdict(d, eta [32]byte, a uint64, amount int64, recipient [20]byte) []byte {
	return (&Verdict{Domain: d, Eta: eta, MinSegment: a, Asset: AssetUCT, Recipient: recipient, Amount: big.NewInt(amount)}).ABI()
}

// sealedRun pays segs*K synthetic identifiers into a fresh vault of w and returns the vault.
func sealedRun(w *World, segs int, seed string) (*Vault, error) {
	v, err := NewVault(w.Gamma, w.Env(), w.Params)
	if err != nil {
		return nil, err
	}
	if err := v.Deposit(big.NewInt(1_000_000), FirstOwner(Key("a")), HE([]byte("rho"))); err != nil {
		return nil, err
	}
	for i := 0; i < segs*int(w.Cfg.K); i++ {
		eta := HU([]byte(seed), CUint(uint64(i)))
		c := v.C()
		if _, err := v.Redeem(eta, c, nil, VerifierCall{Return: syntheticVerdict(v.D, eta, c, 1, Recipient20("r"))}, RecipientAccepts); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func sealEvents(v *Vault) []Event {
	var out []Event
	for _, e := range v.Events {
		if e.Name == "SegmentSealed" {
			out = append(out, e)
		}
	}
	return out
}

func segmentsOf(v *Vault) []*Segment {
	var out []*Segment
	for _, e := range sealEvents(v) {
		t, _ := BuildGapTree(e.IDs)
		out = append(out, &Segment{Index: e.Segment, Before: e.Before, After: e.After, Z: e.IDs, Root: t.Root()})
	}
	return out
}

func (g *gen) sealReceipts() error {
	w := g.worlds["k4"]
	v, err := sealedRun(w, 2, "seal-receipts")
	if err != nil {
		return err
	}
	ev := sealEvents(v)
	data0, data1 := SegmentSealedData(ev[0].Before, ev[0].After, ev[0].IDs), SegmentSealedData(ev[1].Before, ev[1].After, ev[1].IDs)
	otherRoot, err := NewCommittee("root-other", 3)
	if err != nil {
		return err
	}
	wrongPart := &EVMShard{Network: DevNetwork, Partition: DevEVMPartition + 1, PDRs: []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevEVMPartition+1, types.ShardID{}, 0, "evm-a")}}
	left, _ := types.ShardID{}.Split()
	wrongShard := &EVMShard{Network: DevNetwork, Partition: DevEVMPartition, Shard: left, PDRs: []*types.PartitionDescriptionRecord{FixturePDR(DevNetwork, DevEVMPartition, left, 0, "evm-a")}}
	unsorted := append([][32]byte(nil), ev[0].IDs...)
	unsorted[0], unsorted[1] = unsorted[1], unsorted[0]
	cases := []struct {
		id, note, want, inner string
		seg                   uint64
		data                  []byte
		o                     ReceiptOpts
		raw                   func(p []byte) []byte
	}{
		{id: "ok-seal-before-rotation", note: "14.7: shard epoch 0, root epoch 1", seg: 0, data: data0, o: ReceiptOpts{Type: 2, TxIndex: 1}},
		{id: "ok-seal-after-rotation", note: "14.7: shard epoch 1, root epoch 2, judged under epoch 2", seg: 1, data: data1, o: ReceiptOpts{Type: 2, TxIndex: 3, Rotated: true}},
		{id: "seal-altered-shardconfhash", note: "14.7", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{TamperUC: func(uc *types.UnicityCertificate) { uc.ShardConfHash = sl(HU([]byte("x"))) }}},
		{id: "seal-wrong-partition", note: "14.7", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{EVM: wrongPart}},
		{id: "seal-wrong-shard", note: "14.7", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{EVM: wrongShard}},
		{id: "seal-other-root-deployment", note: "14.7", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{Committee: otherRoot}},
		{id: "seal-latest-committee", note: "an epoch 1 seal signed by the epoch 2 committee", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{Committee: w.Roots[1]}},
		{id: "seal-ir-tampered", note: "14.7", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{TamperUC: func(uc *types.UnicityCertificate) { uc.InputRecord.RoundNumber++ }}},
		{id: "seal-header-tampered", note: "14.7", want: "SealReceipt", inner: "DepositHeader", seg: 0, data: data0, o: ReceiptOpts{MutProof: func(p *DepositProof) { p.Header = retaggedHeader(p.Header) }}},
		{id: "seal-arity-7", note: "14.7: the protocol 8 container with a PDR", want: "SealReceipt", inner: "Shape", seg: 0, data: data0, raw: func(b []byte) []byte {
			p, _ := DecodeDepositProof(b)
			pdr, _ := types.Cbor.Marshal(w.EVM.PDRs[0])
			return CArr(CUint(1), CBytes(pdr), CBytes(p.UC), CBytes(p.Header), CUint(p.TxIndex), CUint(p.LogIndex), nodesCBOR(p.Nodes))
		}},
		{id: "seal-no-entry-for-epoch", note: "14.6, 14.7: an otherwise valid UC from an epoch absent from the bundle; retryable (extend the trust-base history and retry), DepositUC on chain", want: "SealReceipt", inner: "NoEntryForEpoch", seg: 0, data: data0, o: ReceiptOpts{Seal: &SealOpts{Network: DevNetwork, Epoch: 3, RootRound: 3 * RotationRound}}},
		{id: "seal-root-before-epoch", note: "14.7 multi-fault: the IR changed after sealing and the seal names an epoch the bundle does not hold; the root fails first, so DepositUC, not the retryable NoEntryForEpoch", want: "SealReceipt", inner: "DepositUC", seg: 0, data: data0, o: ReceiptOpts{Seal: &SealOpts{Network: DevNetwork, Epoch: 3, RootRound: 3 * RotationRound}, TamperUC: func(uc *types.UnicityCertificate) { uc.InputRecord.Timestamp++ }}},
		{id: "seal-failed-transaction", want: "SealReceipt", inner: "ReceiptStatus", seg: 0, data: data0, o: ReceiptOpts{MutReceipt: func(r *RawReceipt) { r.Status = []byte{} }}},
		{id: "seal-path", want: "SealReceipt", inner: "ReceiptPath", seg: 0, data: data0, o: ReceiptOpts{TxIndex: 2, MutProof: func(p *DepositProof) { p.TxIndex = 0 }}},
		{id: "seal-emitter", want: "SealReceipt", inner: "LogEmitter", seg: 0, data: data0, o: ReceiptOpts{MutLog: func(l *RawLog) { l.Address = Recipient20("impostor") }}},
		{id: "seal-topic0", note: "a Deposited log in a seal receipt", want: "SealReceipt", inner: "LogTopics", seg: 0, data: data0, o: ReceiptOpts{MutLog: func(l *RawLog) { l.Topics[0] = TopicDeposited }}},
		{id: "seal-segment-2^48", want: "SealReceipt", inner: "LogTopics", seg: 0, data: data0, o: ReceiptOpts{MutLog: func(l *RawLog) { l.Topics[1] = u256u(1 << 48) }}},
		{id: "seal-data-length", want: "SealReceipt", inner: "LogData", seg: 0, data: data0[:len(data0)-32]},
		{id: "seal-unsorted", want: "SealReceipt", inner: "SegmentLog", seg: 0, data: SegmentSealedData(ev[0].Before, ev[0].After, unsorted)},
		{id: "seal-head-link", note: "headAfter is not NextHead(D, j, headBefore, M_j)", want: "SealReceipt", inner: "SegmentLog", seg: 1, data: SegmentSealedData(ev[1].Before, ev[0].After, ev[1].IDs)},
		{id: "seal-wrong-index", note: "segment 0's log under topic 1", want: "SealReceipt", inner: "SegmentLog", seg: 1, data: data0},
	}
	for _, c := range cases {
		receipt, err := w.SealReceiptProof(c.seg, c.data, c.o)
		if err != nil {
			return fmt.Errorf("%s: %w", c.id, err)
		}
		if c.raw != nil {
			receipt = c.raw(receipt)
		}
		sr, err := VerifySealReceipt(w.Cfg, w.Trust, receipt)
		if e := checkExpect(c.id, err, c.want); e != nil {
			return e
		}
		vec := SealReceiptVector{ID: g.id(c.id), Deployment: "k4", Note: c.note, Receipt: receipt, Expect: expectOf(err)}
		if err != nil {
			inner := RuleOf(errorsUnwrapOnce(err))
			if inner == nil || inner.Name != c.inner {
				return fmt.Errorf("%s: inner rule %v, want %s (%v)", c.id, inner, c.inner, err)
			}
			vec.Inner = inner.Name
		} else {
			vec.Result = sealResult(w.Cfg, sr)
		}
		g.f.Seal = append(g.f.Seal, vec)
	}
	g.f.Seal = append(g.f.Seal, SealReceiptVector{ID: g.id("no-seal-receipt"), Deployment: "k4", Note: "no receipt held: a = 0, start head H_0",
		NoReceipt: true, Receipt: Hex{}, Result: sealResult(w.Cfg, nil)})
	return nil
}

// errorsUnwrapOnce returns the cause a wrap(outer, inner) carries.
func errorsUnwrapOnce(err error) error {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		es := u.Unwrap()
		if len(es) == 2 {
			return es[1]
		}
	}
	return nil
}

func w256(n uint64) [32]byte { return u256u(n) }

var maxID = func() (m [32]byte) {
	for i := range m {
		m[i] = 0xff
	}
	return
}()

func (g *gen) gapProofs() error {
	add := func(id string, k uint64, ids [][32]byte, eta [32]byte, proof []byte, valid bool) error {
		t, ok := BuildGapTree(ids)
		if !ok {
			return fmt.Errorf("gap %s: ids", id)
		}
		m, ok := GapRoot(k, eta, proof)
		got := ok && m == t.Root()
		if got != valid {
			return fmt.Errorf("gap %s: valid %v, want %v", id, got, valid)
		}
		vec := GapVector{ID: g.id(id), K: k, Root: h32(t.Root()), Eta: h32(eta), Proof: proof}
		for _, x := range ids {
			vec.IDs = append(vec.IDs, h32(x))
		}
		if !valid {
			vec.Expect = expectOf(&PositionError{Rule: ErrBadGapProof, Position: 0})
		}
		g.f.Gap = append(g.f.Gap, vec)
		return nil
	}
	setA := [][32]byte{w256(0), w256(5), w256(9), maxID} // zero and the maximum are ordinary identifiers
	setB := [][32]byte{w256(3), w256(7), w256(11), w256(13)}
	ta, _ := BuildGapTree(setA)
	tb, _ := BuildGapTree(setB)
	prove := func(t *GapTree, eta [32]byte) []byte { p, _ := t.Prove(eta); return p }
	mut := func(p []byte, f func(q []byte)) []byte { q := append([]byte(nil), p...); f(q); return q }
	below := maxID
	below[31] = 0xfe
	steps := []error{
		add("gap-k4-interior-0", 4, setA, w256(1), prove(ta, w256(1)), true),
		add("gap-k4-interior-1", 4, setA, w256(6), prove(ta, w256(6)), true),
		add("gap-k4-interior-last", 4, setA, below, prove(ta, below), true),
		add("gap-k4-exterior-above", 4, setB, w256(200), prove(tb, w256(200)), true),
		add("gap-k4-exterior-below", 4, setB, w256(1), prove(tb, w256(1)), true),
		add("gap-k4-exterior-zero", 4, setB, w256(0), prove(tb, w256(0)), true),
		add("gap-k4-exterior-max", 4, setB, maxID, prove(tb, maxID), true),
		add("gap-k4-paid-lower-endpoint", 4, setA, w256(5), prove(ta, w256(6)), false),
		add("gap-k4-paid-zero", 4, setA, w256(0), mut(prove(ta, w256(1)), func(q []byte) {}), false),
		add("gap-k4-paid-max-as-exterior", 4, setA, maxID, mut(prove(ta, below), func(q []byte) {}), false),
		add("gap-k4-outside-gap", 4, setA, w256(7), prove(ta, w256(1)), false),
		add("gap-k4-index-k", 4, setB, w256(5), mut(prove(tb, w256(5)), func(q []byte) { q[0] = 4 }), false),
		add("gap-k4-wrong-index", 4, setB, w256(5), mut(prove(tb, w256(5)), func(q []byte) { q[0] ^= 1 }), false),
		add("gap-k4-swapped-bounds", 4, setB, w256(5), mut(prove(tb, w256(5)), func(q []byte) { copy(q[1:33], setB[1][:]); copy(q[33:65], setB[0][:]) }), false),
		add("gap-k4-interior-as-exterior", 4, setB, w256(5), mut(prove(tb, w256(5)), func(q []byte) { q[0] = 3 }), false),
		add("gap-k4-sibling", 4, setB, w256(5), mut(prove(tb, w256(5)), func(q []byte) { q[70] ^= 1 }), false),
		add("gap-k4-short", 4, setB, w256(5), prove(tb, w256(5))[:128], false),
		add("gap-k4-long", 4, setB, w256(5), append(prove(tb, w256(5)), 0), false),
	}
	for _, e := range steps {
		if e != nil {
			return e
		}
	}
	// K = 64: pseudo-random identifiers.
	rng := rand.New(rand.NewSource(64))
	var ids [][32]byte
	for i := 0; i < 64; i++ {
		var x [32]byte
		rng.Read(x[:])
		ids = append(ids, x)
	}
	sortIDs(ids)
	t, _ := BuildGapTree(ids)
	var mid [32]byte
	copy(mid[:], ids[20][:])
	mid[31]++
	if err := add("gap-k64-interior", 64, ids, mid, prove(t, mid), true); err != nil {
		return err
	}
	if err := add("gap-k64-exterior-max", 64, ids, maxID, prove(t, maxID), true); err != nil {
		return err
	}
	return add("gap-k64-paid", 64, ids, ids[20], prove(t, mid), false)
}

func sortIDs(ids [][32]byte) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && less(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

func (g *gen) folds() error {
	w := g.worlds["k4"]
	v, err := sealedRun(w, 3, "folds")
	if err != nil {
		return err
	}
	segs := segmentsOf(v)
	d, k := w.Cfg.Domain(), w.Cfg.K
	eta := HU([]byte("unpaid"))
	add := func(id string, a uint64, history []byte, stored [32]byte, want Expect) error {
		pl := GapProofLen(k)
		var proofs [][]byte
		for i := 32; i+pl <= len(history); i += pl {
			proofs = append(proofs, history[i:i+pl])
		}
		x, err := FoldHistory(d, k, eta, a, [32]byte(history[:32]), proofs)
		if err == nil && x != stored {
			err = ErrChainMismatch
		}
		got := expectOf(err)
		if got.Error != want.Error || argStr(got.Args) != argStr(want.Args) {
			return fmt.Errorf("fold %s: got %v want %v", id, got, want)
		}
		g.f.Folds = append(g.f.Folds, FoldVector{ID: g.id(id), Domain: h32(d), K: k, Eta: h32(eta), Start: a, History: history, StoredHead: h32(stored), Expect: got})
		return nil
	}
	h0 := GenesisHead(d, k)
	full, _ := BuildHistory(segs, eta, 0, 3, h0)
	from1, _ := BuildHistory(segs, eta, 1, 3, segs[1].Before)
	bad := append([]byte(nil), full...)
	bad[32+GapProofLen(k)] = byte(k) // proof 1's index out of range
	wrongStart := append([]byte(nil), full...)
	wrongStart[0] ^= 1
	paidEta := segs[1].Z[2]
	paidHist, _ := BuildHistory(segs[:1], paidEta, 0, 1, h0) // a valid proof for segment 0 only
	t1, _ := BuildGapTree(segs[1].Z)
	var near [32]byte
	copy(near[:], paidEta[:])
	near[31]++
	np, _ := t1.Prove(near)
	paidHist = append(paidHist, np...)
	for _, e := range []error{
		add("fold-from-genesis", 0, full, segs[2].After, Expect{}),
		add("fold-from-1", 1, from1, segs[2].After, Expect{}),
		add("fold-bad-proof-1", 0, bad, segs[2].After, Expect{Error: "BadGapProof", Args: []string{"1"}}),
		add("fold-wrong-start-head", 0, wrongStart, segs[2].After, Expect{Error: "ChainMismatch"}),
		add("fold-one-short", 0, full[:len(full)-GapProofLen(k)], segs[2].After, Expect{Error: "ChainMismatch"}),
		add("fold-reordered", 0, swapProofs(full, k, 0, 1), segs[2].After, reorderedExpect(d, k, eta, full)),
		add("fold-skipped-segment", 0, append(append([]byte(nil), full[:32+GapProofLen(k)]...), full[32+2*GapProofLen(k):]...), segs[2].After, Expect{Error: "ChainMismatch"}),
	} {
		if e != nil {
			return e
		}
	}
	// A paid identifier has no gap in its segment: the neighbouring gap's proof fails for it.
	pl := GapProofLen(k)
	var proofs [][]byte
	for i := 32; i < len(paidHist); i += pl {
		proofs = append(proofs, paidHist[i:i+pl])
	}
	_, err = FoldHistory(d, k, paidEta, 0, h0, proofs)
	if e := expectOf(err); e.Error != "BadGapProof" || argStr(e.Args) != "1" {
		return fmt.Errorf("fold paid: %v", err)
	}
	g.f.Folds = append(g.f.Folds, FoldVector{ID: g.id("fold-paid-in-segment-1"), Domain: h32(d), K: k, Eta: h32(paidEta), Start: 0, History: paidHist,
		StoredHead: h32(segs[1].After), Expect: expectOf(err)})
	return nil
}

func (g *gen) segmentLogs() error {
	w := g.worlds["k4"]
	v, err := sealedRun(w, 2, "segment-logs")
	if err != nil {
		return err
	}
	ev := sealEvents(v)
	d, k := w.Cfg.Domain(), w.Cfg.K
	add := func(id string, j uint64, before [32]byte, data []byte, want string) error {
		seg, err := CheckSegmentLog(d, k, j, before, data)
		if e := checkExpect(id, err, want); e != nil {
			return e
		}
		vec := SegmentLogVector{ID: g.id(id), Domain: h32(d), K: k, Segment: j, ExpectBefore: h32(before), Data: data, Expect: expectOf(err)}
		if seg != nil {
			vec.Root, vec.HeadAfter = h32(seg.Root), h32(seg.After)
		}
		g.f.SegmentLogs = append(g.f.SegmentLogs, vec)
		return nil
	}
	data := SegmentSealedData(ev[1].Before, ev[1].After, ev[1].IDs)
	dup := append([][32]byte(nil), ev[1].IDs...)
	dup[1] = dup[0]
	off := append([]byte(nil), data...)
	off[95] = 0x40
	for _, e := range []error{
		add("segment-log-ok", 1, ev[0].After, data, ""),
		add("segment-log-length", 1, ev[0].After, data[:len(data)-1], "SegmentLog"),
		add("segment-log-offset", 1, ev[0].After, off, "SegmentLog"),
		add("segment-log-duplicate", 1, ev[0].After, SegmentSealedData(ev[1].Before, ev[1].After, dup), "SegmentLog"),
		add("segment-log-gap-in-chain", 1, ev[1].After, data, "SegmentLog"),
		add("segment-log-wrong-index", 0, ev[0].After, data, "SegmentLog"),
	} {
		if e != nil {
			return e
		}
	}
	return nil
}

func (g *gen) wallet() error {
	// gas is a linear planning model for the vectors: base + per-proof, both carried in the vector.
	cap := func(id, stage string, lMax, lT, lO, k, a, cObs, reserve, p, gasBase, gasPerProof, gas, user uint64, want string) error {
		var err error
		if stage == "preflight" {
			err = CapacityPreflight(Preflight{LMax: lMax, LT: lT, LO: lO, K: k, A: a, CObs: cObs, Reserve: reserve, UserGasLimit: user,
				GasAt: func(p uint64) uint64 { return gasBase + gasPerProof*p }})
		} else {
			err = CapacityExceeded(lMax, lT, lO, k, p, gas, user)
		}
		if e := checkExpect(id, err, want); e != nil {
			return e
		}
		pMax, base := MaxProofs(lMax, lT, lO, k)
		g.f.Wallet.Capacity = append(g.f.Wallet.Capacity, CapacityVector{ID: g.id(id), Stage: stage, LMax: lMax, LT: lT, LO: lO, K: k, PMax: pMax, BaseFits: base,
			A: a, CObs: cObs, Reserve: reserve, GasBase: gasBase, GasPerProof: gasPerProof, Proofs: p, GasLimit: gas, UserGasLimit: user, Expect: expectOf(err)})
		return nil
	}
	// At K = 64 a proof is 257 bytes; 512 KiB with 20 KiB of evidence and 2 KiB of framing is 1952 proofs: at c = 2500 an index
	// a = 0 is unredeemable before the burn (astra finding 1), a = 2490 leaves 10 + 64 proofs.
	sr := func(id string, ro bool, read, ver, jump uint64, want string) error {
		err := CheckStateRead(ro, read, ver, jump)
		if e := checkExpect(id, err, want); e != nil {
			return e
		}
		g.f.Wallet.StateReads = append(g.f.Wallet.StateReads, StateReadVector{ID: g.id(id), StateReadOnly: ro, Read: read, Verified: ver, MaxJump: jump, Expect: expectOf(err)})
		return nil
	}
	comp := func(id, status string, w int, want string) error {
		err := CheckCompanion(status, w)
		if e := checkExpect(id, err, want); e != nil {
			return e
		}
		g.f.Wallet.Companions = append(g.f.Wallet.Companions, CompanionVector{ID: g.id(id), Status: status, Witnesses: w, Expect: expectOf(err)})
		return nil
	}
	for _, e := range []error{
		comp("companion-found", "found", 2, ""),
		comp("companion-pruned", "unavailable", 0, "EvidencePruned"),
		comp("companion-unknown", "unknown", 0, "CompanionUnknown"),
		comp("companion-three-witnesses", "found", 3, "CompanionProvider"),
		comp("companion-status-ok", "ok", 2, "CompanionProvider"),
		cap("capacity-preflight-ok", "preflight", 524288, 20480, 2048, 64, 2490, 2500, 64, 0, 2_000_000, 12_000, 0, 30_000_000, ""),
		cap("capacity-preflight-exact", "preflight", 32+64*257+1000, 1000, 32, 64, 0, 0, 64, 0, 0, 1, 0, 64, ""),
		cap("capacity-preflight-one-short", "preflight", 32+64*257+999, 1000, 32, 64, 0, 0, 64, 0, 0, 1, 0, 64, "CapacityPreflight"),
		cap("capacity-preflight-old-index", "preflight", 524288, 20480, 2048, 64, 0, 2500, 64, 0, 2_000_000, 1, 0, 30_000_000, "CapacityPreflight"),
		cap("capacity-preflight-gas", "preflight", 524288, 2048, 400, 64, 0, 0, 64, 0, 29_500_000, 12_000, 0, 30_000_000, "CapacityPreflight"),
		cap("capacity-preflight-gas-exact", "preflight", 524288, 2048, 400, 64, 0, 0, 64, 0, 29_232_000, 12_000, 0, 30_000_000, ""),
		cap("capacity-preflight-evidence-too-large", "preflight", 131072, 131072, 0, 64, 0, 0, 1, 0, 0, 1, 0, 30_000_000, "CapacityPreflight"),
		cap("capacity-redeem-ok", "redemption", 524288, 20480, 400, 64, 0, 0, 0, 1958, 0, 0, 29_000_000, 30_000_000, ""),
		cap("capacity-redeem-proofs", "redemption", 524288, 20480, 400, 64, 0, 0, 0, 1959, 0, 0, 29_000_000, 30_000_000, "CapacityExceeded"),
		cap("capacity-preflight-oversized-base-no-history", "preflight", 100, 101, 0, 64, 0, 0, 0, 0, 0, 0, 0, 30_000_000, "CapacityPreflight"),
		cap("capacity-preflight-exact-base-no-history", "preflight", 100, 60, 40, 64, 0, 0, 0, 0, 0, 0, 0, 30_000_000, ""),
		cap("capacity-preflight-size-overflow", "preflight", 524288, ^uint64(0), 1, 64, 0, 0, 64, 0, 0, 1, 0, 30_000_000, "CapacityPreflight"),
		cap("capacity-preflight-owed-overflow", "preflight", 524288, 1000, 0, 64, 0, ^uint64(0), 64, 0, 0, 0, 0, 30_000_000, "CapacityPreflight"),
		cap("capacity-redeem-oversized-base-no-history", "redemption", 100, 101, 0, 64, 0, 0, 0, 0, 0, 0, 0, 1, "CapacityExceeded"),
		cap("capacity-redeem-exact-base-no-history", "redemption", 100, 60, 40, 64, 0, 0, 0, 0, 0, 0, 0, 1, ""),
		cap("capacity-redeem-size-overflow", "redemption", 524288, ^uint64(0), 1, 64, 0, 0, 0, 1, 0, 0, 0, 1, "CapacityExceeded"),
		cap("capacity-redeem-gas", "redemption", 524288, 20480, 400, 64, 0, 0, 0, 10, 0, 0, 30_000_001, 30_000_000, "CapacityExceeded"),
		sr("state-read-ok", true, 70, 10, 64, ""),
		sr("state-read-jump", true, 75, 10, 64, "ImplausibleIndex"),
		sr("state-read-backwards", true, 9, 10, 64, "ImplausibleIndex"),
		sr("state-read-not-admitted", false, 10, 10, 64, "StateReadNotAdmitted"),
	} {
		if e != nil {
			return e
		}
	}
	return nil
}

func (g *gen) primitives() error {
	n := u256(secpN)
	nm1 := u256(new(big.Int).Sub(secpN, big.NewInt(1)))
	for _, s := range []struct {
		k    [32]byte
		want string
	}{{w256(0), "invalid"}, {w256(1), ""}, {nm1, ""}, {n, "invalid"}, {maxID, "invalid"}} {
		_, err := MinterKeyFromScalar(s.k)
		if (err == nil) != (s.want == "") {
			return fmt.Errorf("minter scalar %x: %v", s.k, err)
		}
		g.f.Primitives.MinterScalars = append(g.f.Primitives.MinterScalars, MinterScalarVector{Scalar: h32(s.k), Valid: err == nil})
	}
	if err := g.unlockPrimitives(); err != nil {
		return err
	}
	sel := func(s string) Hex { h := HE([]byte(s)); return Hex(h[:4]) }
	g.f.Primitives.Constants = map[string]Hex{
		"DEPOSIT_SECRET":        h32(TagDepositSecret),
		"ARCHIVE_GENESIS":       h32(TagArchiveGenesis),
		"ARCHIVE_STEP":          h32(TagArchiveStep),
		"asset":                 h32(AssetUCT),
		"topic0.Deposited":      h32(TopicDeposited),
		"topic0.Paid":           h32(TopicPaid),
		"topic0.SegmentSealed":  h32(TopicSegmentSealed),
		"selector.deposit":      sel("deposit(bytes,bytes32)"),
		"selector.redeem":       sel("redeem(bytes,bytes32,uint64,bytes)"),
		"selector.domain":       sel("domain()"),
		"selector.config":       sel("config()"),
		"selector.state":        sel("state()"),
		"selector.verifyReturn": sel("verifyReturn(bytes,bytes)"),
	}
	return nil
}

// AstraUnlockKeyID2 is the source key of astra's constructed recovery ID 2 example (briefs/astra-review-1110-r2-answer.md): digest
// integer 1, r = 2, s = 1; R is the even-y point with x = n + 2 and Q = r^-1 (R - G).
const AstraUnlockKeyID2 = "028a0dee06163f357e0e71688f3785eb53891144624c633ed43706b6268bb4316f"

// unlockPrimitives emits the section 14.7 primitive recovery vectors: valid and invalid recovery IDs 2 and 3, all
// UnlockRecovery under the NB2 unlock restriction, with ID 0/1 and ID 4 controls.
func (g *gen) unlockPrimitives() error {
	one := w256(1)
	sig := func(r, s *big.Int, id byte) []byte {
		out := make([]byte, 65)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:64])
		out[64] = id
		return out
	}
	// The key a (digest, r||s, id) recovers to under the SDK relation, nil when recovery fails.
	recovered := func(d [32]byte, u []byte) *secp256k1.PublicKey {
		c := append([]byte{27 + 4 + u[64]}, u[:64]...)
		k, _, err := ecdsa.RecoverCompact(c, d[:])
		if err != nil {
			return nil
		}
		return k
	}
	two, s1 := big.NewInt(2), big.NewInt(1)
	astra2, astra3 := sig(two, s1, 2), sig(two, s1, 3)
	k2, k3 := recovered(one, astra2), recovered(one, astra3)
	if k2 == nil || k3 == nil || fmt.Sprintf("%x", k2.SerializeCompressed()) != AstraUnlockKeyID2 {
		return fmt.Errorf("unlock primitives: astra's ID 2 example does not recover %s", AstraUnlockKeyID2)
	}
	ctl := KeyFromSeed("nb2-unlock-primitive")
	cd := HU([]byte("nb2-unlock-primitive"))
	cs := ecdsa.SignCompact(ctl, cd[:], true)
	ctlSig := append(append([]byte(nil), cs[1:]...), cs[0]-27-4)
	other := append([]byte(nil), ctlSig...)
	other[64] ^= 1
	nm1 := new(big.Int).Sub(secpN, big.NewInt(1)) // r + n >= p: no point for IDs 2 and 3
	cases := []struct {
		id, note, want string
		key            *secp256k1.PublicKey
		d              [32]byte
		u              []byte
	}{
		{id: "unlock-id0-1-valid", note: "control: an ordinary signature (recovery ID 0 or 1) recovering the source key", key: ctl.PubKey(), d: cd, u: ctlSig},
		{id: "unlock-id0-1-other-key", note: "control: the other of IDs 0/1 recovers another key", want: "UnlockKey", key: ctl.PubKey(), d: cd, u: other},
		{id: "unlock-id2-valid", note: "astra's construction: digest 1, r = 2, s = 1, ID 2 (x = n + 2, even y) recovers the source key and verifies under the SDK relation; NB2 refuses it", want: "UnlockRecovery", key: k2, d: one, u: astra2},
		{id: "unlock-id3-valid", note: "as unlock-id2-valid with the odd-y point (ID 3): valid under the SDK relation; NB2 refuses it", want: "UnlockRecovery", key: k3, d: one, u: astra3},
		{id: "unlock-id2-other-key", note: "ID 2 recovering a key other than the source key", want: "UnlockRecovery", key: ctl.PubKey(), d: one, u: astra2},
		{id: "unlock-id3-other-key", note: "ID 3 recovering a key other than the source key", want: "UnlockRecovery", key: k2, d: one, u: astra3},
		{id: "unlock-id2-unrecoverable", note: "ID 2 with r = n - 1: r + n >= p, recovery fails", want: "UnlockRecovery", key: k2, d: one, u: sig(nm1, s1, 2)},
		{id: "unlock-id3-unrecoverable", note: "ID 3 with r = n - 1: r + n >= p, recovery fails", want: "UnlockRecovery", key: k3, d: one, u: sig(nm1, s1, 3)},
		{id: "unlock-id4", note: "outside the SDK's 0..3", want: "UnlockRecovery", key: ctl.PubKey(), d: cd, u: append(append([]byte(nil), ctlSig[:64]...), 4)},
	}
	for _, c := range cases {
		err := VerifyUnlockDigest(c.key, c.d, c.u)
		if e := checkExpect(c.id, err, c.want); e != nil {
			return e
		}
		sdk := c.u[64] <= 3 && sdkRecover(c.key, c.d, c.u[:64], c.u[64]) == nil
		if sdk != (c.id == "unlock-id0-1-valid" || c.id == "unlock-id2-valid" || c.id == "unlock-id3-valid") {
			return fmt.Errorf("unlock primitive %s: SDK relation accepts = %v", c.id, sdk)
		}
		g.f.Primitives.Unlocks = append(g.f.Primitives.Unlocks, UnlockVector{ID: g.id(c.id), Note: c.note, Key: Hex(c.key.SerializeCompressed()),
			Digest: h32(c.d), Unlock: Hex(c.u), SDKValid: sdk, Expect: expectOf(err)})
	}
	return nil
}

func swapProofs(h []byte, k uint64, i, j int) []byte {
	pl := GapProofLen(k)
	out := append([]byte(nil), h...)
	copy(out[32+i*pl:32+(i+1)*pl], h[32+j*pl:32+(j+1)*pl])
	copy(out[32+j*pl:32+(j+1)*pl], h[32+i*pl:32+(i+1)*pl])
	return out
}

// reorderedExpect: two segments' proofs swapped either stop being gap proofs for eta or fold to another chain.
func reorderedExpect(d [32]byte, k uint64, eta [32]byte, full []byte) Expect {
	h := swapProofs(full, k, 0, 1)
	pl := GapProofLen(k)
	var proofs [][]byte
	for i := 32; i+pl <= len(h); i += pl {
		proofs = append(proofs, h[i:i+pl])
	}
	if _, err := FoldHistory(d, k, eta, 0, [32]byte(h[:32]), proofs); err != nil {
		return expectOf(err)
	}
	return Expect{Error: "ChainMismatch"}
}
