package nb2ref

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
)

// The unbounded paid-set reference and the random workload the vault model is checked against. The reference keeps every
// paid identifier forever and decides a redemption without the gap verifier: a history is acceptable only when it is the
// byte-exact honest history for (eta, a, e) built from the true segments (gap proofs and the start head are unique for an
// unpaid identifier), and an identifier is payable only when it was never paid at all.

// Reference is the unbounded model.
type Reference struct {
	D     [32]byte
	K, B  uint64
	Vault [20]byte
	Qmax  *big.Int
	N     uint64
	Q     *big.Int
	Paid  [][32]byte // arrival order
	paid  map[[32]byte]bool
	Heads [][32]byte // H_0 .. H_c
	Segs  [][][32]byte
}

// NewReference starts the reference of a configuration.
func NewReference(c *Config) *Reference {
	return &Reference{D: c.Domain(), K: c.K, B: c.B, Vault: c.Vault, Qmax: c.Qmax, Q: new(big.Int), paid: map[[32]byte]bool{},
		Heads: [][32]byte{GenesisHead(c.Domain(), c.K)}}
}

// C is the current segment.
func (r *Reference) C() uint64 { return uint64(len(r.Segs)) }

// Honest is the wallet's history for (eta, a, e) over the true segments, nil when eta was paid in one of them or the range
// is not a range of sealed segments.
func (r *Reference) Honest(eta [32]byte, a, e uint64) []byte {
	if a > e || e > r.C() {
		return nil
	}
	var proofs [][]byte
	for j := a; j < e; j++ {
		t, _ := BuildGapTree(r.Segs[j])
		p, ok := t.Prove(eta)
		if !ok {
			return nil
		}
		proofs = append(proofs, p)
	}
	return EncodeHistory(r.Heads[a], proofs)
}

// Deposit reports acceptance of a deposit.
func (r *Reference) Deposit(value *big.Int, firstOwner []byte) bool {
	if value.Sign() <= 0 || len(firstOwner) != FirstOwnerBytes || !bytes.Equal(firstOwner[:9], FirstOwnerPrefix) || (firstOwner[9] != 2 && firstOwner[9] != 3) ||
		new(big.Int).Add(r.Q, value).Cmp(r.Qmax) > 0 || r.N >= MaxDeposit {
		return false
	}
	r.N++
	r.Q.Add(r.Q, value)
	return true
}

// Redeem reports acceptance of a redemption whose verifier verdict is vd (nil: the verifier reverted or returned garbage).
func (r *Reference) Redeem(claimed [32]byte, a uint64, history []byte, vd *Verdict) bool {
	pl := uint64(GapProofLen(r.K))
	l := uint64(len(history))
	if l != 0 && (l < 32+pl || (l-32)%pl != 0) {
		return false
	}
	var p uint64
	if l != 0 {
		p = (l - 32) / pl
	}
	c, e := r.C(), a+p
	if a > c || e < a || !(e == c || (c > 0 && e == c-1)) {
		return false
	}
	if p > 0 && !bytes.Equal(history, r.Honest(claimed, a, e)) {
		return false
	}
	if vd == nil || r.paid[vd.Eta] || r.paid[claimed] {
		return false
	}
	if vd.Domain != r.D || vd.Asset != AssetUCT || vd.Eta != claimed || vd.MinSegment != a || vd.Recipient == ([20]byte{}) || vd.Recipient == r.Vault ||
		vd.Amount.Sign() == 0 || vd.Amount.Cmp(r.Q) > 0 {
		return false
	}
	r.paid[vd.Eta] = true
	r.Paid = append(r.Paid, vd.Eta)
	r.Q.Sub(r.Q, vd.Amount)
	if uint64(len(r.Paid))%r.K == 0 {
		z := append([][32]byte(nil), r.Paid[len(r.Paid)-int(r.K):]...)
		sortIDs(z)
		t, _ := BuildGapTree(z)
		r.Heads = append(r.Heads, NextHead(r.D, c, r.Heads[c], t.Root()))
		r.Segs = append(r.Segs, z)
	}
	return true
}

// runStep applies one vector step to the vault and returns its error and the inner (re-entrant) error.
func runStep(v *Vault, st *VaultStep) (error, error) {
	switch st.Op {
	case "deposit":
		val, _ := new(big.Int).SetString(st.Value, 10)
		return v.Deposit(val, st.FirstOwner, [32]byte(st.Rho)), nil
	case "redeem":
		call := VerifierCall{Return: st.VerifierReturn}
		if st.VerifierRevert != nil {
			call = VerifierCall{Revert: st.VerifierRevert}
		}
		rc := map[string]Recipient{"": RecipientAccepts, "accepts": RecipientAccepts, "reverts": RecipientReverts,
			"reenters-redeem": RecipientReentersRedeem, "reenters-deposit": RecipientReentersDeposit}[st.Recipient]
		hist := st.History
		if hist == nil {
			hist = []byte{}
		}
		res, err := v.Redeem([32]byte(st.ClaimedEta), st.ClaimedStart, hist, call, rc)
		if res != nil {
			return err, res.Inner
		}
		return err, nil
	}
	return fmt.Errorf("nb2: unknown op %q", st.Op), nil
}

// record runs st on v, fills its outcome and events, and checks it against want ("" accepts).
func record(v *Vault, st *VaultStep, want, wantInner string) error {
	before := len(v.Events)
	err, inner := runStep(v, st)
	st.Expect = expectOf(err)
	if inner != nil {
		st.Inner = RuleName(inner)
	}
	st.Events = []EventJSON{}
	for _, e := range v.Events[before:] {
		st.Events = append(st.Events, eventJSON(v.Cfg, e))
	}
	if st.Expect.Error != want || st.Inner != wantInner {
		return fmt.Errorf("step %s: got %v inner %q (%v), want %q inner %q", st.Op, st.Expect, st.Inner, err, want, wantInner)
	}
	return nil
}

// StateOf is the observable state of v.
func StateOf(v *Vault) VaultState {
	n, c, m, q, h, p := v.State()
	cur, prev := v.LiveIDs()
	s := VaultState{Deposits: n, Segment: c, Population: m, Outstanding: q.String(), Head: h32(h), PrevHead: h32(p), Current: []Hex{}, Previous: []Hex{}}
	for _, x := range cur {
		s.Current = append(s.Current, h32(x))
	}
	for _, x := range prev {
		s.Previous = append(s.Previous, h32(x))
	}
	return s
}

// Workload is a random redemption sequence against one vault and the reference.
type Workload struct {
	V      *Vault
	R      *Reference
	Steps  []VaultStep
	rng    *rand.Rand
	burns  []*burn
	stats  map[string]int
	target [20]byte
}

type burn struct {
	eta    [32]byte
	a      uint64
	amount int64
	paid   bool
	prep   []byte // a prepared history (possibly stale)
	prepE  uint64 // the segment it was prepared at
}

// NewWorkload starts a workload on a fresh vault of w with the given seed.
func NewWorkload(w *World, seed int64) (*Workload, error) {
	v, err := NewVault(w.Gamma, w.Env(), w.Params)
	if err != nil {
		return nil, err
	}
	return &Workload{V: v, R: NewReference(w.Cfg), rng: rand.New(rand.NewSource(seed)), stats: map[string]int{}, target: Recipient20("workload")}, nil
}

func (wl *Workload) eta() [32]byte {
	var x [32]byte
	wl.rng.Read(x[:])
	if wl.rng.Intn(3) == 0 {
		x[0] = 0 // concentrate a third of the identifiers in bucket 0
	}
	return x
}

func (wl *Workload) honestNow(b *burn) []byte {
	c := wl.V.C()
	h := wl.R.Honest(b.eta, b.a, c)
	if h == nil {
		// Paid in a sealed segment: the best a replayer can do is the neighbouring gap.
		var near [32]byte
		copy(near[:], b.eta[:])
		near[31] ^= 1
		h = wl.R.Honest(near, b.a, c)
		if h == nil {
			h = []byte{}
		}
	}
	return h
}

// step runs one redemption or deposit on both models and requires equal acceptance; it records the step.
func (wl *Workload) redeem(kind string, claimed [32]byte, a uint64, history []byte, vd *Verdict) error {
	st := VaultStep{Op: "redeem", ClaimedEta: h32(claimed), ClaimedStart: a, History: history, VerifierReturn: vd.ABI(), Recipient: "accepts"}
	refOK := wl.R.Redeem(claimed, a, history, vd)
	before := len(wl.V.Events)
	err, _ := runStep(wl.V, &st)
	st.Expect = expectOf(err)
	st.Events = []EventJSON{}
	for _, e := range wl.V.Events[before:] {
		st.Events = append(st.Events, eventJSON(wl.V.Cfg, e))
	}
	if (err == nil) != refOK {
		return fmt.Errorf("%s: vault %v, reference accepts %v", kind, err, refOK)
	}
	wl.stats[kind+":"+map[bool]string{true: "ok", false: st.Expect.Error}[err == nil]]++
	wl.Steps = append(wl.Steps, st)
	return wl.compare()
}

func (wl *Workload) compare() error {
	v, r := wl.V, wl.R
	if v.C() != r.C() || v.Q().Cmp(r.Q) != 0 || v.N() != r.N || v.Head != r.Heads[r.C()] || (r.C() > 0 && v.Prev != r.Heads[r.C()-1]) {
		return fmt.Errorf("state differs: c %d/%d Q %s/%s", v.C(), r.C(), v.Q(), r.Q)
	}
	cur, prev := v.LiveIDs()
	k := int(r.K)
	tail := r.Paid[len(r.Paid)-len(r.Paid)%k:]
	if len(cur) != len(tail) {
		return fmt.Errorf("current buffer %d, reference %d", len(cur), len(tail))
	}
	for i := range cur {
		if cur[i] != tail[i] {
			return fmt.Errorf("current buffer differs at %d", i)
		}
	}
	if r.C() > 0 {
		pp := r.Paid[len(r.Paid)-len(r.Paid)%k-k : len(r.Paid)-len(r.Paid)%k]
		for i := range prev {
			if prev[i] != pp[i] {
				return fmt.Errorf("previous buffer differs at %d", i)
			}
		}
	}
	return nil
}

// Run performs n actions.
func (wl *Workload) Run(n int) error {
	fo := FirstOwner(Key("depositor"))
	dep := func(val int64) error {
		st := VaultStep{Op: "deposit", Value: fmt.Sprint(val), FirstOwner: fo, Rho: h32(HE([]byte(fmt.Sprint("rho-", len(wl.Steps)))))}
		ok := wl.R.Deposit(big.NewInt(val), fo)
		if err := record(wl.V, &st, map[bool]string{true: "", false: "?"}[ok], ""); err != nil && ok {
			return err
		}
		wl.Steps = append(wl.Steps, st)
		return wl.compare()
	}
	if err := dep(1_000_000); err != nil {
		return err
	}
	verdict := func(b *burn) *Verdict {
		return &Verdict{Domain: wl.V.D, Eta: b.eta, MinSegment: b.a, Asset: AssetUCT, Recipient: wl.target, Amount: big.NewInt(b.amount)}
	}
	for i := 0; i < n; i++ {
		c := wl.V.C()
		switch x := wl.rng.Intn(20); {
		case x < 7 || len(wl.burns) == 0: // a fresh burn, redeemed now with an honest history from a <= c
			back := uint64(wl.rng.Intn(4))
			if back > c {
				back = c
			}
			b := &burn{eta: wl.eta(), a: c - back, amount: int64(1 + wl.rng.Intn(5))}
			wl.burns = append(wl.burns, b)
			if wl.rng.Intn(3) == 0 {
				b.prep, b.prepE = wl.R.Honest(b.eta, b.a, c), c // prepared now, submitted later
				continue
			}
			if err := wl.redeem("fresh", b.eta, b.a, wl.R.Honest(b.eta, b.a, c), verdict(b)); err != nil {
				return err
			}
			b.paid = true
			if wl.rng.Intn(4) == 0 { // same-block duplicate
				if err := wl.redeem("duplicate", b.eta, b.a, wl.R.Honest(b.eta, b.a, wl.V.C()), verdict(b)); err != nil {
					return err
				}
			}
		case x < 10: // submit a prepared (possibly stale) history: one rollover is tolerated, two are not
			b := wl.burns[wl.rng.Intn(len(wl.burns))]
			if b.prep == nil {
				continue
			}
			roll := wl.V.C() - b.prepE
			if roll > 2 {
				roll = 2
			}
			if err := wl.redeem(fmt.Sprintf("prepared-%d", roll), b.eta, b.a, b.prep, verdict(b)); err != nil {
				return err
			}
			b.paid = b.paid || wl.R.paid[b.eta]
			b.prep = nil
		case x < 14: // replay a burn (paid or not) with the best history now
			b := wl.burns[wl.rng.Intn(len(wl.burns))]
			if err := wl.redeem("replay", b.eta, b.a, wl.honestNow(b), verdict(b)); err != nil {
				return err
			}
			b.paid = b.paid || wl.R.paid[b.eta]
		case x < 16: // a forged claimed identifier whose history is valid for the forgery
			b := wl.burns[wl.rng.Intn(len(wl.burns))]
			f := wl.eta()
			if err := wl.redeem("forged-claim", f, b.a, wl.R.Honest(f, b.a, c), verdict(b)); err != nil {
				return err
			}
		case x < 18: // a wrong start head
			b := wl.burns[wl.rng.Intn(len(wl.burns))]
			h := wl.honestNow(b)
			if len(h) == 0 {
				continue
			}
			h = append([]byte(nil), h...)
			h[wl.rng.Intn(32)] ^= 1
			if err := wl.redeem("wrong-start-head", b.eta, b.a, h, verdict(b)); err != nil {
				return err
			}
		default:
			if err := dep(int64(1 + wl.rng.Intn(100))); err != nil {
				return err
			}
		}
	}
	return nil
}
