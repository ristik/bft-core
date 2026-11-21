package nb2ref

import (
	"fmt"
	"math/big"
)

func flatGapStart(e FlatEvent, p FlatGapPacket) (uint64, [32]byte) {
	if e.Kind == FlatGapEvent {
		return e.NextSegment, e.Head
	}
	if p.StartHead != nil {
		return e.Verdict.MinSegment, *p.StartHead
	}
	return e.Verdict.MinSegment, [32]byte{}
}

func flatGapEnd(start uint64, count int) (uint64, error) {
	if start > MaxSegment || uint64(count) > MaxSegment-start {
		return 0, ErrFlatStep
	}
	return start + uint64(count), nil
}

func (v *FlatVerifier) AdvanceFlatGaps(data []byte) (FlatEvent, error) {
	p, err := DecodeFlatGap(data, FlatAdvanceGaps, v.cfg.K)
	if err != nil {
		return FlatEvent{}, err
	}
	e, err := v.event(p.Header, p.Kind, p.Receipt)
	if err != nil {
		return FlatEvent{}, err
	}
	start, head := flatGapStart(e, p)
	end, err := flatGapEnd(start, len(p.Proofs))
	if err != nil {
		return FlatEvent{}, err
	}
	seq, err := flatNextSeq(e.Seq)
	if err != nil {
		return FlatEvent{}, err
	}
	next, err := FoldHistory(e.Verdict.Domain, v.cfg.K, e.Verdict.Eta, start, head, p.Proofs)
	if err != nil {
		return FlatEvent{}, err
	}
	return FlatEvent{Kind: FlatGapEvent, Session: e.Session, Seq: seq, Verdict: e.Verdict, NextSegment: end, Head: next}, nil
}

// FlatVault is the concrete chain-free model for one vault generation. Both
// entry points mutate the same bounded state. Balances track successful
// modeled native transfers; unsolicited donations are outside this model.
type FlatVault struct {
	model    *Vault
	verifier *FlatVerifier
	balances map[[20]byte]*big.Int
}

func NewFlatVault(v *FlatVerifier, env Environment) (*FlatVault, error) {
	c := v.cfg
	if env.Address != c.Vault || env.ChainID != c.ChainID || env.VerifierCodeHash != c.VerifierCodeHash {
		return nil, ErrBadConfig
	}
	return &FlatVault{newVault(c, v.domain), v, make(map[[20]byte]*big.Int)}, nil
}

func (v *FlatVault) Deposit(amount *big.Int, firstOwner []byte, rho [32]byte) error {
	if err := v.model.Deposit(amount, firstOwner, rho); err != nil {
		return err
	}
	v.credit(v.model.Cfg.Vault, amount)
	return nil
}

func (v *FlatVault) credit(who [20]byte, amount *big.Int) {
	if v.balances[who] == nil {
		v.balances[who] = new(big.Int)
	}
	v.balances[who].Add(v.balances[who], amount)
}

func (v *FlatVault) recordPayout() {
	for i := len(v.model.Events) - 1; i >= 0; i-- {
		p := v.model.Events[i]
		if p.Name == "Paid" {
			v.credit(v.model.Cfg.Vault, new(big.Int).Neg(p.Amount))
			v.credit(p.Recipient, p.Amount)
			return
		}
	}
}

func (v *FlatVault) Balance(who [20]byte) *big.Int {
	if b := v.balances[who]; b != nil {
		return new(big.Int).Set(b)
	}
	return new(big.Int)
}

func (v *FlatVault) State() (uint64, uint64, uint64, *big.Int, [32]byte, [32]byte) {
	return v.model.State()
}

func (v *FlatVault) LiveIDs() (current, previous [][32]byte) { return v.model.LiveIDs() }

func (v *FlatVault) Logs() []Event {
	out := append([]Event(nil), v.model.Events...)
	for i := range out {
		if out[i].Amount != nil {
			out[i].Amount = new(big.Int).Set(out[i].Amount)
		}
		out[i].FirstOwner = append([]byte(nil), out[i].FirstOwner...)
		out[i].IDs = append([][32]byte(nil), out[i].IDs...)
	}
	return out
}

func (v *FlatVault) Redeem(evidence []byte, eta [32]byte, start uint64, history []byte, rcp Recipient) (*RedeemResult, error) {
	m := v.model
	if m.entered {
		return nil, ErrReentrancy
	}
	snap := m.snapshot()
	res, err := m.redeem(eta, start, history, func() (VerifierCall, error) {
		verdict, err := v.verifier.VerifyFlatReturn(evidence)
		if err != nil {
			return VerifierCall{}, fmt.Errorf("flat ordinary verifier: %w", err)
		}
		return VerifierCall{Return: verdict.ABI()}, nil
	}, rcp)
	if err != nil {
		m.restore(snap)
		return nil, err
	}
	v.recordPayout()
	return res, nil
}

func (v *FlatVault) RedeemRecovered(data []byte, rcp Recipient) (*RedeemResult, error) {
	m := v.model
	if m.entered {
		return nil, ErrReentrancy
	}
	p, err := DecodeFlatGap(data, FlatRedeemRecovered, m.Cfg.K)
	if err != nil {
		return nil, err
	}
	e, err := v.verifier.event(p.Header, p.Kind, p.Receipt)
	if err != nil {
		return nil, err
	}
	verdict := e.Verdict
	c := m.C()
	if verdict.MinSegment > c {
		return nil, argsErr(ErrFutureIndex, verdict.MinSegment, c)
	}
	start, head := flatGapStart(e, p)
	end, err := flatGapEnd(start, len(p.Proofs))
	if err != nil {
		return nil, err
	}
	if end != c && (c == 0 || end != c-1) {
		return nil, argsErr(ErrStaleEndpoint, end, c)
	}
	if len(p.Proofs) > 0 || p.Kind == FlatGapEvent {
		next, err := FoldHistory(m.D, m.Cfg.K, verdict.Eta, start, head, p.Proofs)
		if err != nil {
			return nil, err
		}
		want := m.Head
		if end != c {
			want = m.Prev
		}
		if next != want {
			return nil, ErrChainMismatch
		}
	}
	if err := m.scanRecent(verdict.Eta, c, end); err != nil {
		return nil, err
	}
	snap := m.snapshot()
	res, err := m.pay(verdict, verdict.Eta, verdict.MinSegment, rcp)
	if err != nil {
		m.restore(snap)
		return nil, err
	}
	v.recordPayout()
	return res, nil
}
