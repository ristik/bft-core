package nb2ref

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// The vault model (sections 5.2, 9, 10.4, 11.1): the packed accounting word, the position-tag recent buffers, rotation and
// sealing, with the frozen check order of redeem. The verifier is outside the model: a redeem step carries the verifier's raw
// return data or its revert, as a mock verifier would give them. The recipient's behaviour is part of the step too.

// Vault is Σ = (A, T_0, T_1, H_c, H_{c-1}, S_0, S_1) of one deployment.
type Vault struct {
	Cfg     *Config
	D       [32]byte
	A       *big.Int      // n << 200 | c << 152 | m << 144 | Q
	T       [2][]*big.Int // tag words per buffer
	S       [2][][32]byte // K identifier cells per buffer
	Head    [32]byte      // H_c
	Prev    [32]byte      // H_{c-1}, invalid (zero) at c = 0
	entered bool
	Events  []Event
}

// Event is one emitted log.
type Event struct {
	Name string // "Deposited", "Paid", "SegmentSealed"
	// Deposited
	N          uint64
	Amount     *big.Int
	Rho        [32]byte
	FirstOwner []byte
	// Paid
	Eta       [32]byte
	Recipient [20]byte
	// SegmentSealed
	Segment       uint64
	Before, After [32]byte
	IDs           [][32]byte
}

// Accounting word field layout.
const (
	shiftN, bitsN = 200, 56
	shiftC, bitsC = 152, 48
	shiftM, bitsM = 144, 8
	shiftQ, bitsQ = 0, 144
)

func field(a *big.Int, shift, width uint) *big.Int {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	return new(big.Int).And(new(big.Int).Rsh(a, shift), mask)
}

// put is a masked field update; a value outside the field width is a model invariant violation (the vault range-checks first).
func put(a *big.Int, shift, width uint, v *big.Int) *big.Int {
	if v.Sign() < 0 || v.BitLen() > int(width) {
		panic(fmt.Sprintf("nb2: accounting field overflow at shift %d", shift))
	}
	mask := new(big.Int).Lsh(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1)), shift)
	out := new(big.Int).AndNot(a, mask)
	return out.Or(out, new(big.Int).Lsh(v, shift))
}

// NewVault constructs the vault from Γ under the environment; nothing but A = 0 and H_0 is written.
func NewVault(gamma []byte, env Environment, p Params) (*Vault, error) {
	c, err := Construct(gamma, env, p)
	if err != nil {
		return nil, err
	}
	return newVault(c, c.Domain()), nil
}

func newVault(c *Config, domain [32]byte) *Vault {
	v := &Vault{Cfg: c, D: domain, A: new(big.Int)}
	w := tagWords(c.K, c.B)
	for p := 0; p < 2; p++ {
		v.S[p] = make([][32]byte, c.K)
		for i := 0; i < w; i++ {
			v.T[p] = append(v.T[p], new(big.Int))
		}
	}
	v.Head = GenesisHead(v.D, c.K)
	return v
}

func log2(x uint64) uint {
	n := uint(0)
	for x > 1 {
		x >>= 1
		n++
	}
	return n
}

// tagWords is words(K, B) = ceil(K / floor(256 / log2 B)).
func tagWords(k, b uint64) int {
	t := 256 / log2(b)
	return int((uint(k) + t - 1) / t)
}

// N, C, M, Q read the accounting word.
func (v *Vault) N() uint64   { return field(v.A, shiftN, bitsN).Uint64() }
func (v *Vault) C() uint64   { return field(v.A, shiftC, bitsC).Uint64() }
func (v *Vault) M() uint64   { return field(v.A, shiftM, bitsM).Uint64() }
func (v *Vault) Q() *big.Int { return field(v.A, shiftQ, bitsQ) }

func (v *Vault) tag(p int, i uint64) uint64 {
	lb := log2(v.Cfg.B)
	t := uint64(256 / lb)
	return field(v.T[p][i/t], uint(lb*uint(i%t)), lb).Uint64()
}

func (v *Vault) setTag(p int, i uint64, tag uint64) {
	lb := log2(v.Cfg.B)
	t := uint64(256 / lb)
	v.T[p][i/t] = put(v.T[p][i/t], uint(lb*uint(i%t)), lb, new(big.Int).SetUint64(tag))
}

// LiveIDs returns the live identifiers of the current and previous buffer.
func (v *Vault) LiveIDs() (current, previous [][32]byte) {
	p := int(v.C() % 2)
	current = append(current, v.S[p][:v.M()]...)
	if v.C() > 0 {
		previous = append(previous, v.S[1-p]...)
	}
	return
}

// State is the state() view (section 13.1).
func (v *Vault) State() (deposits, segment, population uint64, outstanding *big.Int, head, previousHead [32]byte) {
	prev := v.Prev
	if v.C() == 0 {
		prev = [32]byte{}
	}
	return v.N(), v.C(), v.M(), v.Q(), v.Head, prev
}

// Deposit is deposit(firstOwner, rho) with msg.value = value.
func (v *Vault) Deposit(value *big.Int, firstOwner []byte, rho [32]byte) error {
	if v.entered {
		return fail(ErrReentrancy)
	}
	if value.Sign() <= 0 {
		if err := fail(ErrZeroValue); err != nil {
			return err
		}
	}
	validOwner := len(firstOwner) == FirstOwnerBytes && bytes.Equal(firstOwner[:9], FirstOwnerPrefix)
	if validOwner {
		_, err := ParseKey(firstOwner[9:])
		validOwner = err == nil
	}
	if !validOwner {
		if err := fail(ErrBadFirstOwner); err != nil {
			return err
		}
	}
	room := new(big.Int).Sub(v.Cfg.Qmax, v.Q())
	if value.Cmp(room) > 0 {
		if err := argsErr(ErrLiabilityCap, v.Q(), value, v.Cfg.Qmax); err != nil {
			return err
		}
	}
	n := v.N()
	if n >= MaxDeposit {
		return fail(ErrDepositCounterExhausted)
	}
	q := new(big.Int).Add(v.Q(), value)
	if q.BitLen() > bitsQ {
		return ErrLiabilityCap // only reachable with the LiabilityCap check disabled
	}
	v.A = put(put(v.A, shiftN, bitsN, new(big.Int).SetUint64(n+1)), shiftQ, bitsQ, q)
	v.Events = append(v.Events, Event{Name: "Deposited", N: n + 1, Amount: new(big.Int).Set(value), Rho: rho, FirstOwner: bytes.Clone(firstOwner)})
	return nil
}

// Recipient is the payout target's behaviour.
type Recipient int

const (
	RecipientAccepts           Recipient = iota // an EOA or a contract that accepts value
	RecipientReverts                            // reverts on receipt: PayoutFailed
	RecipientReentersRedeem                     // calls redeem from its receive hook, swallows the revert, accepts
	RecipientReentersDeposit                    // calls deposit from its receive hook, swallows the revert, accepts
	RecipientPropagatesReentry                  // propagates the inner Reentrancy failure and rejects payout
)

// VerifierCall is the mock verifier's answer: Revert non-nil means it reverted with that data, otherwise Return is its
// return data.
type VerifierCall struct {
	Revert []byte
	Return []byte
}

// RedeemResult reports what happened in a successful redeem besides the state change: the inner call's error when the
// recipient re-entered.
type RedeemResult struct {
	Inner error
}

// Redeem is redeem(evidence, claimedEta, claimedStart, history) with the verifier's answer and the recipient's behaviour.
// A failure reverts every effect, including a seal and its logs.
func (v *Vault) Redeem(claimedEta [32]byte, claimedStart uint64, history []byte, ver VerifierCall, rcp Recipient) (*RedeemResult, error) {
	if v.entered {
		return nil, fail(ErrReentrancy)
	}
	snap := v.snapshot()
	res, err := v.redeem(claimedEta, claimedStart, history, func() (VerifierCall, error) { return ver, nil }, rcp)
	if err != nil {
		v.restore(snap)
		return nil, err
	}
	return res, nil
}

// ArgsError carries the arguments of LiabilityCap, LiabilityUnderflow, FutureIndex, StaleEndpoint, BadHistoryLength,
// AlreadyPaid and VerifierRefused: Vals as typed values (for the ABI revert data), Args as their vector strings.
type ArgsError struct {
	Rule *Rule
	Args []string
	Vals []any
}

func (e *ArgsError) Error() string { return e.Rule.Error() + fmt.Sprint(e.Args) }
func (e *ArgsError) Unwrap() error { return e.Rule }

func argsErr(r *Rule, args ...any) error {
	if disabled[r] {
		return nil
	}
	out := &ArgsError{Rule: r, Vals: args}
	for _, a := range args {
		switch x := a.(type) {
		case [32]byte:
			out.Args = append(out.Args, fmt.Sprintf("0x%x", x[:]))
		case []byte:
			out.Args = append(out.Args, fmt.Sprintf("0x%x", x))
		default:
			out.Args = append(out.Args, fmt.Sprint(x))
		}
	}
	return out
}

func (v *Vault) redeem(eta [32]byte, a uint64, history []byte, verify func() (VerifierCall, error), rcp Recipient) (*RedeemResult, error) {
	k := v.Cfg.K
	pl := uint64(GapProofLen(k))
	// 1. History length.
	l := uint64(len(history))
	var P uint64
	if l != 0 {
		if l < 32+pl || (l-32)%pl != 0 {
			if err := argsErr(ErrBadHistoryLength, l); err != nil {
				return nil, err
			}
			return nil, ErrBadHistoryLength
		}
		P = (l - 32) / pl
	}
	// 2. Range.
	c := v.C()
	if a > c {
		if err := argsErr(ErrFutureIndex, a, c); err != nil {
			return nil, err
		}
	}
	e := a + P
	if e < a || !(e == c || (c > 0 && e == c-1)) {
		if err := argsErr(ErrStaleEndpoint, e, c); err != nil {
			return nil, err
		}
	}
	// 3. Historical proofs.
	if P > 0 {
		var proofs [][]byte
		for i := uint64(0); i < P; i++ {
			proofs = append(proofs, history[32+i*pl:32+(i+1)*pl])
		}
		x, err := FoldHistory(v.D, k, eta, a, [32]byte(history[:32]), proofs)
		if err != nil {
			return nil, err
		}
		want := v.Head
		if e != c {
			want = v.Prev
		}
		if x != want {
			if err := fail(ErrChainMismatch); err != nil {
				return nil, err
			}
		}
	}
	// 4. Recent buffers.
	if err := v.scanRecent(eta, c, e); err != nil {
		return nil, err
	}
	ver, err := verify()
	if err != nil {
		return nil, err
	}
	// 5. The verifier. A revert of at most MaxVerifierRevert bytes is VerifierRefused(revertData); a longer revert, like return data
	// that is not exactly 192 canonical bytes, is VerifierBadReturn (the vault never copies unbounded revert data).
	if ver.Revert != nil && len(ver.Revert) > MaxVerifierRevert {
		return nil, ErrVerifierBadReturn
	}
	if ver.Revert != nil {
		disabledRefused := disabled[ErrVerifierRefused]
		delete(disabled, ErrVerifierRefused)
		err := argsErr(ErrVerifierRefused, ver.Revert) // no verdict exists without the call's return: never skipped
		if disabledRefused {
			disabled[ErrVerifierRefused] = true
		}
		return nil, err
	}
	vd, ok := decodeVerdictABI(ver.Return)
	if !ok {
		return nil, ErrVerifierBadReturn
	}
	return v.pay(vd, eta, a, rcp)
}

func (v *Vault) scanRecent(eta [32]byte, c, e uint64) error {
	p := int(c % 2)
	b := Bucket(eta, v.Cfg.B)
	scan := []struct {
		buf int
		pop uint64
	}{{p, v.M()}}
	if c > 0 && e == c-1 {
		scan = append(scan, struct {
			buf int
			pop uint64
		}{1 - p, v.Cfg.K})
	}
	for _, s := range scan {
		for i := uint64(0); i < s.pop; i++ {
			if v.tag(s.buf, i) == b && v.S[s.buf][i] == eta {
				if err := argsErr(ErrAlreadyPaid, eta); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (v *Vault) pay(vd *Verdict, eta [32]byte, a uint64, rcp Recipient) (*RedeemResult, error) {
	p, k := int(v.C()%2), v.Cfg.K
	q := v.Q()
	switch {
	case vd.Domain != v.D:
		if err := fail(ErrDomainMismatch); err != nil {
			return nil, err
		}
	}
	if vd.Asset != AssetUCT {
		if err := fail(ErrAssetMismatch); err != nil {
			return nil, err
		}
	}
	if vd.Eta != eta || vd.MinSegment != a {
		if err := fail(ErrClaimMismatch); err != nil {
			return nil, err
		}
	}
	if vd.Recipient == ([20]byte{}) || vd.Recipient == v.Cfg.Vault {
		if err := fail(ErrBadRecipient); err != nil {
			return nil, err
		}
	}
	if vd.Amount.Sign() == 0 {
		if err := fail(ErrZeroAmount); err != nil {
			return nil, err
		}
	}
	if vd.Amount.Cmp(q) > 0 {
		if err := argsErr(ErrLiabilityUnderflow, q, vd.Amount); err != nil {
			return nil, err
		}
		return nil, ErrLiabilityUnderflow // no state can carry a negative liability
	}
	// 7. Effects. The paid identifier is the verdict's (equal to the claim unless ClaimMismatch is disabled). When m + 1 == K the
	// payment seals and m is stored as 0, otherwise m + 1 is stored: m < K always holds in storage.
	m := v.M()
	v.S[p][m] = vd.Eta
	v.setTag(p, m, Bucket(vd.Eta, v.Cfg.B))
	m++
	v.A = put(v.A, shiftQ, bitsQ, new(big.Int).Sub(q, vd.Amount))
	v.Events = append(v.Events, Event{Name: "Paid", Eta: vd.Eta, Recipient: vd.Recipient, Amount: new(big.Int).Set(vd.Amount)})
	if m == k {
		if err := v.seal(p); err != nil {
			return nil, err
		}
	} else {
		v.A = put(v.A, shiftM, bitsM, new(big.Int).SetUint64(m))
	}
	// 8. Payout.
	res := &RedeemResult{}
	v.entered = true
	switch rcp {
	case RecipientReverts:
		v.entered = false
		return nil, fail(ErrPayoutFailed)
	case RecipientReentersRedeem, RecipientPropagatesReentry:
		_, res.Inner = v.Redeem(eta, a, nil, VerifierCall{}, RecipientAccepts)
		if rcp == RecipientPropagatesReentry {
			v.entered = false
			return nil, fail(ErrPayoutFailed)
		}
	case RecipientReentersDeposit:
		res.Inner = v.Deposit(big.NewInt(1), nil, [32]byte{})
	}
	v.entered = false
	return res, nil
}

// errSealOrder is the seal's assertion (strict increase, every identifier in its tagged bucket): a revert with no rule name.
var errSealOrder = errors.New("nb2: seal assertion failed")

// seal is section 10.4 on the full buffer p.
func (v *Vault) seal(p int) error {
	c, k := v.C(), v.Cfg.K
	if c >= MaxSegment {
		return fail(ErrSegmentCounterExhausted)
	}
	buckets := make([][][32]byte, v.Cfg.B)
	for i := uint64(0); i < k; i++ {
		t := v.tag(p, i)
		buckets[t] = append(buckets[t], v.S[p][i])
	}
	var z [][32]byte
	for t, bk := range buckets {
		sort.Slice(bk, func(i, j int) bool { return less(bk[i], bk[j]) })
		for _, x := range bk {
			if Bucket(x, v.Cfg.B) != uint64(t) {
				return errSealOrder
			}
		}
		z = append(z, bk...)
	}
	tree, ok := BuildGapTree(z)
	if !ok {
		return errSealOrder // unreachable while AlreadyPaid holds: the live buffers stay distinct
	}
	next := NextHead(v.D, c, v.Head, tree.Root())
	v.Events = append(v.Events, Event{Name: "SegmentSealed", Segment: c, Before: v.Head, After: next, IDs: z})
	v.Prev, v.Head = v.Head, next
	v.A = put(put(v.A, shiftC, bitsC, new(big.Int).SetUint64(c+1)), shiftM, bitsM, new(big.Int))
	return nil
}

// MaxVerifierRevert is MAX_VERIFIER_REVERT, the longest verifier revert the vault relays as VerifierRefused(revertData).
const MaxVerifierRevert = 1024

// decodeVerdictABI accepts exactly 192 canonical bytes: uint64 and address words with zero high bytes.
func decodeVerdictABI(b []byte) (*Verdict, bool) {
	if len(b) != 192 || !bytes.Equal(b[64:88], make([]byte, 24)) || !bytes.Equal(b[128:140], make([]byte, 12)) {
		return nil, false
	}
	vd := &Verdict{Domain: [32]byte(b[0:32]), Eta: [32]byte(b[32:64]), Asset: [32]byte(b[96:128]), Amount: new(big.Int).SetBytes(b[160:192])}
	vd.MinSegment = new(big.Int).SetBytes(b[64:96]).Uint64()
	copy(vd.Recipient[:], b[140:160])
	return vd, true
}

type vaultSnap struct {
	a      *big.Int
	t      [2][]*big.Int
	s      [2][][32]byte
	h, p   [32]byte
	events int
}

func (v *Vault) snapshot() vaultSnap {
	s := vaultSnap{a: new(big.Int).Set(v.A), h: v.Head, p: v.Prev, events: len(v.Events)}
	for i := 0; i < 2; i++ {
		for _, w := range v.T[i] {
			s.t[i] = append(s.t[i], new(big.Int).Set(w))
		}
		s.s[i] = append([][32]byte(nil), v.S[i]...)
	}
	return s
}

func (v *Vault) restore(s vaultSnap) {
	v.A, v.T, v.S, v.Head, v.Prev = s.a, s.t, s.s, s.h, s.p
	v.Events = v.Events[:s.events]
	v.entered = false
}

// SetState is the test harness's storage injection (for SegmentCounterExhausted and DepositCounterExhausted, which no sequence
// can reach): it writes the accounting fields, the heads and the live identifiers with their tags.
func (v *Vault) SetState(n, c, m uint64, q *big.Int, head, prev [32]byte, current, previous [][32]byte) {
	v.A = put(put(put(put(new(big.Int), shiftN, bitsN, new(big.Int).SetUint64(n)), shiftC, bitsC, new(big.Int).SetUint64(c)),
		shiftM, bitsM, new(big.Int).SetUint64(m)), shiftQ, bitsQ, q)
	v.Head, v.Prev = head, prev
	p := int(c % 2)
	for i, x := range current {
		v.S[p][i] = x
		v.setTag(p, uint64(i), Bucket(x, v.Cfg.B))
	}
	for i, x := range previous {
		v.S[1-p][i] = x
		v.setTag(1-p, uint64(i), Bucket(x, v.Cfg.B))
	}
}
