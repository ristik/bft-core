package nb2ref

import (
	"fmt"
	"math/big"
)

// Vault vectors: one scripted sequence per vault rule, the split payout, rollovers, and recorded random workloads.

type script struct {
	g   *gen
	w   *World
	dep string
	v   *Vault
	vec VaultVector
	err error
}

func (g *gen) script(dep, id, note string) *script {
	w := g.worlds[dep]
	v, err := NewVault(w.Gamma, w.Env(), w.Params)
	return &script{g: g, w: w, dep: dep, v: v, vec: VaultVector{ID: g.id(id), Deployment: dep, Note: note}, err: err}
}

func (s *script) step(st VaultStep, want, inner string) *script {
	if s.err != nil {
		return s
	}
	if err := record(s.v, &st, want, inner); err != nil {
		s.err = fmt.Errorf("vault %s step %d: %w", s.vec.ID, len(s.vec.Steps), err)
		return s
	}
	s.vec.Steps = append(s.vec.Steps, st)
	return s
}

func (s *script) deposit(value *big.Int, want string) *script {
	return s.depositRaw(value, FirstOwner(Key("depositor")), want)
}

func (s *script) depositRaw(value *big.Int, fo []byte, want string) *script {
	return s.step(VaultStep{Op: "deposit", Value: value.String(), FirstOwner: fo, Rho: h32(HE([]byte(fmt.Sprint("rho-", len(s.vec.Steps)))))}, want, "")
}

// pay redeems eta at a with the honest history to the current endpoint and a matching verdict of amount.
func (s *script) pay(eta [32]byte, a uint64, amount int64, want string) *script {
	return s.redeemWith(eta, a, s.honest(eta, a, s.v.C()), VerifierCall{Return: syntheticVerdict(s.v.D, eta, a, amount, Recipient20("r"))}, "accepts", want, "")
}

func (s *script) redeemWith(eta [32]byte, a uint64, history []byte, call VerifierCall, rcp, want, inner string) *script {
	st := VaultStep{Op: "redeem", ClaimedEta: h32(eta), ClaimedStart: a, History: history, Recipient: rcp}
	if call.Revert != nil {
		st.VerifierRevert = call.Revert
	} else {
		st.VerifierReturn = call.Return
	}
	return s.step(st, want, inner)
}

// honest is the wallet's history over the vault's own SegmentSealed events.
func (s *script) honest(eta [32]byte, a, e uint64) []byte {
	segs := segmentsOf(s.v)
	if a == e {
		return []byte{}
	}
	ha := GenesisHead(s.v.D, s.v.Cfg.K)
	if a > 0 {
		ha = segs[a-1].After
	}
	h, paid := BuildHistory(segs, eta, a, e, ha)
	if paid {
		return nil
	}
	return h
}

func (s *script) fill(n int, tag string) *script {
	for i := 0; i < n && s.err == nil; i++ {
		s.pay(HU([]byte(tag), CUint(uint64(i))), s.v.C(), 1, "")
	}
	return s
}

func (s *script) done() error {
	if s.err != nil {
		return s.err
	}
	s.vec.Final = StateOf(s.v)
	s.g.f.Vault = append(s.g.f.Vault, s.vec)
	return nil
}

func eta(s string) [32]byte { return HU([]byte("eta:" + s)) }

func (g *gen) vault() error {
	big1m := big.NewInt(1_000_000)
	k4 := g.worlds["k4"]
	d4 := k4.Cfg.Domain()
	vr := func(e [32]byte, a uint64, amount int64) VerifierCall {
		return VerifierCall{Return: syntheticVerdict(d4, e, a, amount, Recipient20("r"))}
	}
	verdictWith := func(f func(v *Verdict)) VerifierCall {
		v := &Verdict{Domain: d4, Eta: eta("x"), Asset: AssetUCT, Recipient: Recipient20("r"), Amount: big.NewInt(1)}
		f(v)
		return VerifierCall{Return: v.ABI()}
	}
	scripts := []func() error{
		func() error { // the design's split payout
			return g.script("k4", "vault-split-100", "deposit 100; pay 60, 15 and 25; the liability returns to zero").
				deposit(big.NewInt(100), "").pay(eta("60"), 0, 60, "").pay(eta("15"), 0, 15, "").pay(eta("25"), 0, 25, "").
				pay(eta("1-more"), 0, 1, "LiabilityUnderflow").done()
		},
		func() error { // sealing, one tolerated rollover, two stale, rebuild
			s := g.script("k4", "vault-rollover", "a history built at c=1 survives one seal (e = c-1) but not two; rebuilt, it pays")
			s.deposit(big1m, "").fill(4, "r0")
			late := eta("late")
			h1 := s.honest(late, 0, 1)
			s.fill(4, "r1") // c = 2: e = 1 = c - 1, tolerated
			s.redeemWith(late, 0, h1, vr(late, 0, 1), "accepts", "", "")
			later := eta("later")
			h2 := s.honest(later, 0, 2)
			s.fill(7, "r2") // c = 4 after two seals: stale
			s.redeemWith(later, 0, h2, vr(later, 0, 1), "accepts", "StaleEndpoint", "")
			s.redeemWith(later, 0, s.honest(later, 0, s.v.C()), vr(later, 0, 1), "accepts", "", "")
			return s.done()
		},
		func() error {
			s := g.script("k4", "vault-BadHistoryLength", "")
			return s.deposit(big1m, "").redeemWith(eta("x"), 0, make([]byte, 31), vr(eta("x"), 0, 1), "accepts", "BadHistoryLength", "").
				redeemWith(eta("x"), 0, make([]byte, 32), vr(eta("x"), 0, 1), "accepts", "BadHistoryLength", "").done()
		},
		func() error {
			s := g.script("k4", "vault-FutureIndex", "")
			return s.deposit(big1m, "").redeemWith(eta("x"), 1, []byte{}, vr(eta("x"), 1, 1), "accepts", "FutureIndex", "").
				redeemWith(eta("x"), ^uint64(0), make([]byte, 32+GapProofLen(4)), vr(eta("x"), 0, 1), "accepts", "FutureIndex", "").done()
		},
		func() error {
			s := g.script("k4", "vault-StaleEndpoint", "a = 0 with no proofs after two seals")
			return s.deposit(big1m, "").fill(8, "f").redeemWith(eta("x"), 0, []byte{}, vr(eta("x"), 0, 1), "accepts", "StaleEndpoint", "").done()
		},
		func() error {
			s := g.script("k4", "vault-BadGapProof", "proof 0's index set to K")
			s.deposit(big1m, "").fill(4, "f")
			h := append([]byte(nil), s.honest(eta("x"), 0, 1)...)
			h[32] = 4
			return s.redeemWith(eta("x"), 0, h, vr(eta("x"), 0, 1), "accepts", "BadGapProof", "").done()
		},
		func() error {
			s := g.script("k4", "vault-ChainMismatch", "a wrong start head is repairable for the same burn")
			s.deposit(big1m, "").fill(4, "f")
			h := append([]byte(nil), s.honest(eta("x"), 0, 1)...)
			h[0] ^= 1
			s.redeemWith(eta("x"), 0, h, vr(eta("x"), 0, 1), "accepts", "ChainMismatch", "")
			return s.pay(eta("x"), 0, 1, "").done()
		},
		func() error {
			s := g.script("k4", "vault-AlreadyPaid", "same identifier in the current buffer, then in the previous buffer at e = c - 1, then in a sealed segment (no gap: BadGapProof)")
			x := eta("x")
			s.deposit(big1m, "").pay(x, 0, 1, "").pay(x, 0, 1, "AlreadyPaid").fill(3, "f")
			s.redeemWith(x, 0, []byte{}, vr(x, 0, 1), "accepts", "AlreadyPaid", "") // a = c - 1 = 0, P = 0: previous buffer scanned
			s.fill(4, "g")
			// Paid in sealed segment 0: the neighbouring gap's proof does not cover it.
			near := x
			near[31] ^= 1
			s.redeemWith(x, 0, s.honest(near, 0, 2), vr(x, 0, 1), "accepts", "BadGapProof", "")
			return s.done()
		},
		func() error {
			sel := HE([]byte("ReturnAmount()"))
			return g.script("k4", "vault-VerifierRefused", "").deposit(big1m, "").
				redeemWith(eta("x"), 0, []byte{}, VerifierCall{Revert: sel[:4]}, "accepts", "VerifierRefused", "").done()
		},
		func() error {
			s := g.script("k4", "vault-VerifierBadReturn", "191 bytes; then a minSegment word with high bytes set")
			s.deposit(big1m, "").redeemWith(eta("x"), 0, []byte{}, VerifierCall{Return: syntheticVerdict(d4, eta("x"), 0, 1, Recipient20("r"))[:191]}, "accepts", "VerifierBadReturn", "")
			bad := syntheticVerdict(d4, eta("x"), 0, 1, Recipient20("r"))
			bad[64] = 1
			s.redeemWith(eta("x"), 0, []byte{}, VerifierCall{Return: bad}, "accepts", "VerifierBadReturn", "")
			bad = syntheticVerdict(d4, eta("x"), 0, 1, Recipient20("r"))
			bad[128] = 1
			return s.redeemWith(eta("x"), 0, []byte{}, VerifierCall{Return: bad}, "accepts", "VerifierBadReturn", "").done()
		},
		func() error {
			s := g.script("k4", "vault-verifier-revert-bound", "MAX_VERIFIER_REVERT = 1024: a revert of exactly 1024 bytes is VerifierRefused with those bytes; 1025 and 4096 bytes are VerifierBadReturn (never copied)")
			rev := make([]byte, MaxVerifierRevert+1)
			for i := range rev {
				rev[i] = byte(i)
			}
			s.deposit(big1m, "").redeemWith(eta("x"), 0, []byte{}, VerifierCall{Revert: rev[:MaxVerifierRevert]}, "accepts", "VerifierRefused", "")
			s.redeemWith(eta("x"), 0, []byte{}, VerifierCall{Revert: rev}, "accepts", "VerifierBadReturn", "")
			return s.redeemWith(eta("x"), 0, []byte{}, VerifierCall{Revert: make([]byte, 4096)}, "accepts", "VerifierBadReturn", "").done()
		},
		func() error {
			long := make([]byte, 4096)
			copy(long, syntheticVerdict(d4, eta("x"), 0, 1, Recipient20("r")))
			return g.script("k4", "vault-verifier-return-4096", "4096 bytes of return data, a valid verdict first: not exactly 192 bytes").deposit(big1m, "").
				redeemWith(eta("x"), 0, []byte{}, VerifierCall{Return: long}, "accepts", "VerifierBadReturn", "").done()
		},
		func() error {
			return g.script("k4", "vault-DomainMismatch", "").deposit(big1m, "").
				redeemWith(eta("x"), 0, []byte{}, verdictWith(func(v *Verdict) { v.Domain = HU([]byte("other")) }), "accepts", "DomainMismatch", "").done()
		},
		func() error {
			return g.script("k4", "vault-AssetMismatch", "").deposit(big1m, "").
				redeemWith(eta("x"), 0, []byte{}, verdictWith(func(v *Verdict) { v.Asset = HU([]byte("other")) }), "accepts", "AssetMismatch", "").done()
		},
		func() error {
			s := g.script("k4", "vault-ClaimMismatch", "a forged claimed identifier passes the gap proofs and the scan; the verdict's identifier, or index, differs")
			s.deposit(big1m, "").fill(4, "f")
			forged := eta("forged")
			s.redeemWith(forged, 0, s.honest(forged, 0, 1), vr(eta("real"), 0, 1), "accepts", "ClaimMismatch", "")
			s.redeemWith(forged, 0, s.honest(forged, 0, 1), vr(forged, 1, 1), "accepts", "ClaimMismatch", "")
			return s.done()
		},
		func() error {
			s := g.script("k4", "vault-BadRecipient", "zero, then the vault")
			s.deposit(big1m, "").redeemWith(eta("x"), 0, []byte{}, VerifierCall{Return: syntheticVerdict(d4, eta("x"), 0, 1, [20]byte{})}, "accepts", "BadRecipient", "")
			return s.redeemWith(eta("x"), 0, []byte{}, VerifierCall{Return: syntheticVerdict(d4, eta("x"), 0, 1, k4.Cfg.Vault)}, "accepts", "BadRecipient", "").done()
		},
		func() error {
			return g.script("k4", "vault-ZeroAmount", "").deposit(big1m, "").redeemWith(eta("x"), 0, []byte{}, vr(eta("x"), 0, 0), "accepts", "ZeroAmount", "").done()
		},
		func() error {
			return g.script("k4", "vault-LiabilityUnderflow", "").deposit(big.NewInt(10), "").redeemWith(eta("x"), 0, []byte{}, vr(eta("x"), 0, 11), "accepts", "LiabilityUnderflow", "").done()
		},
		func() error {
			s := g.script("k4", "vault-SegmentCounterExhausted", "harness: c = 2^48 - 1 with K - 1 payments; the sealing payment reverts")
			cur := [][32]byte{eta("h0"), eta("h1"), eta("h2")}
			prev := [][32]byte{eta("p0"), eta("p1"), eta("p2"), eta("p3")}
			s.v.SetState(1, MaxSegment, 3, big.NewInt(100), HE([]byte("head")), HE([]byte("prev")), cur, prev)
			hs := StateOf(s.v)
			s.vec.Harness = &hs
			return s.redeemWith(eta("x"), MaxSegment, []byte{}, vr(eta("x"), MaxSegment, 1), "accepts", "SegmentCounterExhausted", "").done()
		},
		func() error {
			s := g.script("k4", "vault-PayoutFailed", "a reverting recipient on the sealing payment: the seal, its log and the payment all revert")
			s.deposit(big1m, "").fill(3, "f")
			s.redeemWith(eta("x"), 0, []byte{}, vr(eta("x"), 0, 1), "reverts", "PayoutFailed", "")
			return s.pay(eta("x"), 0, 1, "").done()
		},
		func() error {
			s := g.script("k4", "vault-Reentrancy", "the recipient re-enters redeem, then deposit, from its receive hook; the inner call reverts with Reentrancy, the recipient swallows it and the outer payout succeeds")
			s.deposit(big1m, "")
			s.redeemWith(eta("x"), 0, []byte{}, vr(eta("x"), 0, 1), "reenters-redeem", "", "Reentrancy")
			return s.redeemWith(eta("y"), 0, []byte{}, vr(eta("y"), 0, 1), "reenters-deposit", "", "Reentrancy").done()
		},
		func() error {
			return g.script("k4", "vault-ZeroValue", "").deposit(big.NewInt(0), "ZeroValue").done()
		},
		func() error {
			fo := FirstOwner(Key("a"))
			bad := append([]byte(nil), fo...)
			bad[9] = 0x04
			burn := append([]byte(nil), fo...)
			burn[6] = 0x02
			return g.script("k4", "vault-BadFirstOwner", "41 bytes; then key prefix 0x04; then the burn predicate code").
				depositRaw(big.NewInt(1), fo[:41], "BadFirstOwner").depositRaw(big.NewInt(1), bad, "BadFirstOwner").
				depositRaw(big.NewInt(1), burn, "BadFirstOwner").done()
		},
		func() error {
			q := new(big.Int).Sub(k4.Cfg.Qmax, big.NewInt(5))
			return g.script("k4", "vault-LiabilityCap", "Qmax reached exactly, then exceeded by one").
				deposit(q, "").deposit(big.NewInt(5), "").deposit(big.NewInt(1), "LiabilityCap").done()
		},
		func() error {
			s := g.script("k4", "vault-DepositCounterExhausted", "harness: n = 2^56 - 1")
			s.v.SetState(MaxDeposit, 0, 0, big.NewInt(0), s.v.Head, [32]byte{}, nil, nil)
			hs := StateOf(s.v)
			s.vec.Harness = &hs
			return s.deposit(big.NewInt(1), "DepositCounterExhausted").done()
		},
		func() error { // the maximum admitted K: the K-th payment seals and stores m = 0, never m = K in the 8-bit field
			s := g.script("main", "vault-k64-seal-resets-m", "production K = 64, B = 16: 64 payments, the last seals; population reads 0, segment 1")
			s.deposit(big1m, "").fill(63, "k64")
			if s.err == nil && s.v.M() != 63 {
				return fmt.Errorf("k64: m = %d", s.v.M())
			}
			s.fill(1, "k64-last")
			if s.err == nil && (s.v.M() != 0 || s.v.C() != 1) {
				return fmt.Errorf("k64: m = %d, c = %d after the seal", s.v.M(), s.v.C())
			}
			return s.done()
		},
		func() error { // the maximum test K
			s := g.script("k8", "vault-k8-seal-resets-m", "test build's largest K = 8: the 8th payment seals and stores m = 0")
			s.deposit(big1m, "").fill(7, "k8")
			if s.err == nil && s.v.M() != 7 {
				return fmt.Errorf("k8: m = %d", s.v.M())
			}
			s.fill(1, "k8-last")
			if s.err == nil && (s.v.M() != 0 || s.v.C() != 1) {
				return fmt.Errorf("k8: m = %d, c = %d", s.v.M(), s.v.C())
			}
			return s.done()
		},
		func() error { // K = 8, B = 4: concentrated bucket, previous-buffer scan of 2K - 1 positions
			s := g.script("k8", "vault-k8-concentrated", "every identifier in bucket 0; a second payment of each identifier scanned through both buffers")
			s.deposit(big1m, "")
			var ids [][32]byte
			for i := 0; i < 15; i++ {
				x := eta(fmt.Sprint("hot-", i))
				x[0] = 0
				ids = append(ids, x)
				s.pay(x, s.v.C(), 1, "")
			}
			d8 := s.v.D
			// c = 1, m = 7: replay the first payment at the previous-buffer endpoint: m + K = 15 = 2K - 1 positions scanned.
			x := ids[0]
			s.redeemWith(x, 0, s.honest(x, 0, 0), VerifierCall{Return: syntheticVerdict(d8, x, 0, 1, Recipient20("r"))}, "accepts", "AlreadyPaid", "")
			return s.done()
		},
	}
	for _, f := range scripts {
		if err := f(); err != nil {
			return err
		}
	}
	// Recorded random workloads.
	for i, dep := range []string{"k4", "k4", "k8"} {
		wl, err := NewWorkload(g.worlds[dep], int64(1000+i))
		if err != nil {
			return err
		}
		if err := wl.Run(60); err != nil {
			return fmt.Errorf("workload %d: %w", i, err)
		}
		g.f.Vault = append(g.f.Vault, VaultVector{ID: g.id(fmt.Sprintf("vault-random-%s-%d", dep, i)), Deployment: dep,
			Note:  "random workload (fresh, prepared, replay, duplicate, forged claim, wrong start head, deposits) checked against the unbounded paid-set reference",
			Steps: wl.Steps, Final: StateOf(wl.V)})
	}
	return nil
}
