package nb2ref

import (
	"math/big"
	"testing"
)

// TestGapProofsExhaustive: every 4-subset of a 10-identifier universe that includes zero and the maximum, every identifier
// of the universe and every value between neighbours: a proof exists iff the identifier is not in the set, it derives the
// root, and it fails for every identifier outside its gap. The exterior gap is exercised by every set.
func TestGapProofsExhaustive(t *testing.T) {
	var u [][32]byte
	for _, n := range []uint64{0, 2, 4, 6, 8, 10, 12, 14} {
		u = append(u, w256(n))
	}
	below := maxID
	below[31] = 0xfd
	u = append(u, below, maxID)
	var probes [][32]byte
	for _, x := range u {
		probes = append(probes, x)
		y := x
		y[31]++ // odd values and maxID-1 lie between neighbours; maxID+1 wraps to 0x..00 of the next word, harmless
		probes = append(probes, y)
	}
	cases := 0
	for a := 0; a < len(u); a++ {
		for b := a + 1; b < len(u); b++ {
			for c := b + 1; c < len(u); c++ {
				for d := c + 1; d < len(u); d++ {
					set := [][32]byte{u[a], u[b], u[c], u[d]}
					tree, _ := BuildGapTree(set)
					for _, eta := range probes {
						in := false
						for _, x := range set {
							in = in || x == eta
						}
						p, ok := tree.Prove(eta)
						if ok == in {
							t.Fatalf("set %x eta %x: proof exists %v", set, eta, ok)
						}
						if ok {
							if m, ok := GapRoot(4, eta, p); !ok || m != tree.Root() {
								t.Fatalf("proof does not derive the root")
							}
						}
						for _, other := range probes {
							if !ok {
								break
							}
							m, ok2 := GapRoot(4, other, p)
							inGap := ok2 && m == tree.Root()
							// The proof is valid for exactly the identifiers strictly inside its gap.
							i := int(p[0])
							l, r := set[i], set[(i+1)%4]
							want := (i < 3 && less(l, other) && less(other, r)) || (i == 3 && (less(l, other) || less(other, r)))
							if inGap != want {
								t.Fatalf("gap %d: identifier %x accepted %v", i, other, inGap)
							}
						}
						cases++
					}
				}
			}
		}
	}
	if cases != 210*len(probes) {
		t.Fatalf("%d cases", cases)
	}
}

// TestModelEquivalence: the vault model against the unbounded paid-set reference at K = 4 and K = 8 over random sequences
// with replays, same-block duplicates, one and two rollovers, forged claimed identifiers and wrong starting heads.
func TestModelEquivalence(t *testing.T) {
	total := map[string]int{}
	for _, kb := range [][2]uint64{{4, 2}, {8, 4}} {
		w := mustWorld(t, kb[0], kb[1], 1)
		for seed := int64(0); seed < 150; seed++ {
			wl, err := NewWorkload(w, seed)
			if err != nil {
				t.Fatal(err)
			}
			if err := wl.Run(80); err != nil {
				t.Fatalf("K=%d seed %d: %v", kb[0], seed, err)
			}
			for k, v := range wl.stats {
				total[k] += v
			}
		}
	}
	for _, need := range []string{"fresh:ok", "duplicate:AlreadyPaid", "prepared-0:ok", "prepared-1:ok", "prepared-2:StaleEndpoint", "replay:AlreadyPaid",
		"replay:BadGapProof", "forged-claim:ClaimMismatch", "wrong-start-head:ChainMismatch"} {
		if total[need] == 0 {
			t.Errorf("workload never produced %s (%v)", need, total)
		}
	}
	t.Logf("%v", total)
}

// TestSplitScenario: 100 into 60 and 40, 40 into 15 and 25, each returned once, total 100; each pays once in the vault and a
// second payment of each is refused.
func TestSplitScenario(t *testing.T) {
	w := mustWorld(t, 4, 2, 1)
	evs, err := SplitScenario(w, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVault(w.Gamma, w.Env(), w.Params)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Deposit(big.NewInt(100), FirstOwner(Key("a")), HE([]byte("rho"))); err != nil {
		t.Fatal(err)
	}
	// Two sealed segments of other payments, so the parts' indices 0, 1 and 2 are all in the past or present.
	for i := 0; i < 8; i++ {
		e := HU([]byte("other"), CUint(uint64(i)))
		if _, err := v.Redeem(e, v.C(), []byte{}, VerifierCall{Return: syntheticVerdict(v.D, e, v.C(), 1, Recipient20("o"))}, RecipientAccepts); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Deposit(big.NewInt(8), FirstOwner(Key("a")), HE([]byte("rho2"))); err != nil {
		t.Fatal(err)
	}
	history := func(eta [32]byte, a uint64) []byte {
		segs := segmentsOf(v)
		ha := GenesisHead(v.D, v.Cfg.K)
		if a > 0 {
			ha = segs[a-1].After
		}
		h, _ := BuildHistory(segs, eta, a, v.C(), ha)
		return h
	}
	total := new(big.Int)
	var verdicts []*Verdict
	for _, ev := range evs {
		vd, err := VerifyReturn(w.Gamma, ev, w.Trust, w.Params)
		if err != nil {
			t.Fatal(err)
		}
		total.Add(total, vd.Amount)
		verdicts = append(verdicts, vd)
		if _, err := v.Redeem(vd.Eta, vd.MinSegment, history(vd.Eta, vd.MinSegment), VerifierCall{Return: vd.ABI()}, RecipientAccepts); err != nil {
			t.Fatal(err)
		}
	}
	if total.Int64() != 100 || v.Q().Sign() != 0 {
		t.Fatalf("returned %s, outstanding %s", total, v.Q())
	}
	for _, vd := range verdicts {
		if _, err := v.Redeem(vd.Eta, vd.MinSegment, history(vd.Eta, vd.MinSegment), VerifierCall{Return: vd.ABI()}, RecipientAccepts); RuleOf(err) != ErrAlreadyPaid {
			t.Fatalf("second payment: %v", err)
		}
	}
}

// TestSpecConstants pins the section 3 and 13 values.
func TestSpecConstants(t *testing.T) {
	for name, c := range map[string]struct {
		got  []byte
		want string
	}{
		"DEPOSIT_SECRET":       {TagDepositSecret[:], "dfa87a7a4c6db3c7c307e4f2c3cc2d4a07e33d349f542b47f8e0bba49f62e645"},
		"ARCHIVE_GENESIS":      {TagArchiveGenesis[:], "45076af3d8858f1d7a9bb6e037bb5ca4270d0b4fa90f9397eb7adb905590a339"},
		"ARCHIVE_STEP":         {TagArchiveStep[:], "c68efdc45f5c9a20bf6abfda6493e8e295d8e31495fd1e744cd4c35f74785dfa"},
		"Deposited":            {TopicDeposited[:], "853a9d825910065273b44cf4f0ad33d2525f875d3da0a53f967ae40b7508d2b8"},
		"Paid":                 {TopicPaid[:], "606160394df2742a67735645b7e783304d61d2dbc5b550e8c6acfaf27b6291d7"},
		"SegmentSealed":        {TopicSegmentSealed[:], "06e724201a1c72937156cbdb3b9522d26b3818ee33ace10cd7cda65bb9cae916"},
		"verifyReturn":         {sel4("verifyReturn(bytes,bytes)"), "df447dca"},
		"deposit":              {sel4("deposit(bytes,bytes32)"), "3489c151"},
		"redeem":               {sel4("redeem(bytes,bytes32,uint64,bytes)"), "91de2955"},
		"BadHistoryLength":     {sel4(ErrBadHistoryLength.Signature()), "37c8cb02"},
		"AlreadyPaid":          {sel4(ErrAlreadyPaid.Signature()), "f4b76a0e"},
		"BadConfig":            {sel4(ErrBadConfig.Signature()), "0dad7c22"},
		"LiabilityCap":         {sel4(ErrLiabilityCap.Signature()), "5586a2e8"},
		"SegmentCounterExhaus": {sel4(ErrSegmentCounterExhausted.Signature()), "011469c0"},
	} {
		if hx := hexOf(c.got); hx != c.want {
			t.Errorf("%s: %s, spec %s", name, hx, c.want)
		}
	}
	if got := FirstOwner(Key("a"))[:9]; string(got) != string(FirstOwnerPrefix) || len(FirstOwner(Key("a"))) != 42 {
		t.Errorf("first owner prefix %x", got)
	}
}

func sel4(s string) []byte { h := HE([]byte(s)); return h[:4] }
