package vrschema

import "fmt"

func genArithmetic() ([]Vector, error) {
	b := &vb{}
	max64 := ^uint64(0)
	for _, c := range []struct {
		l    uint8
		v    uint64
		n    uint32
		want uint8
	}{{1, max64, 1, 9}, {0, 0, 4, 1}, {2, 5, 4, 4}, {4, 0, 4, 5}, {8, 0, 1, 9}, {9, 0, 1, 9}, {0, 31, 4, 8}, {0, 35, 4, 9}, {3, 15, 16, 4}} {
		got := IncLevel(c.l, c.v, c.n)
		if got != c.want {
			b.fail("incLevel(%d,%d,%d) = %d", c.l, c.v, c.n, got)
		}
		b.add(fmt.Sprintf("incLevel(%d,%s,%d)", c.l, Dec(c.v), c.n), "arith.incLevel", map[string]any{"level": c.l, "views": Dec(c.v), "n": c.n}, map[string]any{"level": got})
	}
	for _, c := range []struct {
		l    uint8
		v    uint64
		n    uint32
		want uint8
	}{{9, max64, 1, 8}, {2, 8, 4, 3}, {9, 0, 4, 8}, {0, 0, 4, 0}, {1, 0, 4, 0}, {5, 0, 4, 4}, {4, 0, 4, 3}, {0, 100, 1, 8}} {
		got := DecLevel(c.l, c.v, c.n)
		if got != c.want {
			b.fail("decLevel(%d,%d,%d) = %d", c.l, c.v, c.n, got)
		}
		b.add(fmt.Sprintf("decLevel(%d,%s,%d)", c.l, Dec(c.v), c.n), "arith.decLevel", map[string]any{"level": c.l, "view": Dec(c.v), "n": c.n}, map[string]any{"level": got})
	}
	for _, c := range []struct {
		l uint8
		v uint64
		n uint32
	}{{0, 0, 4}, {1, 0, 4}, {9, 0, 4}, {9, 3, 4}, {1, max64, 1}, {0, 36, 1}, {0, 37, 1}, {5, 31, 1}, {6, 31, 1}, {36, 1 << 63, 1}, {2, 32, 16}} {
		t, never := ViewTimeoutSeconds(c.l, c.v, c.n)
		b.add(fmt.Sprintf("T(%d,%s,%d)", c.l, Dec(c.v), c.n), "arith.viewTimeout", map[string]any{"level": c.l, "view": Dec(c.v), "n": c.n},
			map[string]any{"seconds": Dec(t), "never": never})
	}
	if t, _ := ViewTimeoutSeconds(LMax, 0, 4); t != 5120 {
		b.fail("T(LMax, 0) = %d", t)
	}
	for _, c := range []struct {
		open uint64
		l    uint8
		v    uint64
		n    uint32
	}{{1000, 1, 0, 4}, {max64 - 5, 1, 0, 4}, {max64 - 20, 1, 0, 4}, {max64 - 5, 36, 1 << 63, 1}, {0, 9, 0, 1}} {
		at, never := Deadline(c.open, c.l, c.v, c.n)
		b.add(fmt.Sprintf("deadline open=%s l=%d v=%s", Dec(c.open), c.l, Dec(c.v)), "arith.deadline", map[string]any{"open": Dec(c.open), "level": c.l, "view": Dec(c.v), "n": c.n},
			map[string]any{"at": Dec(at), "never": never})
	}
	for _, d := range []uint64{100_000, 80_000, 10, 0, 20_000} {
		b.add(fmt.Sprintf("T_req(D=%d ms)", d), "arith.tReq", map[string]any{"dMillis": d}, map[string]any{"seconds": TReq(d)})
	}
	for _, t := range []uint64{20, 80, 5120} {
		b.add(fmt.Sprintf("residence wait T=%d", t), "arith.residence", map[string]any{"tSeconds": t}, map[string]any{"waitMillis": ResidenceWaitMillis(t)})
	}
	for bb := uint64(0); bb <= 5; bb++ {
		b.add(fmt.Sprintf("F_r(b=%d)", bb), "arith.recoveryAllowance", map[string]any{"b": bb}, map[string]any{"rounds": RecoveryAllowance(bb)})
	}
	b.add("LeaderLag(16)", "arith.leaderLag", map[string]any{"n": 16}, map[string]any{"rounds": LeaderLag(16), "minEpochGap": MinEpochGap, "gapCovers": MinEpochGap >= LeaderLag(16)})
	for _, n := range []int{4, 5, 7, 16} {
		b.add(fmt.Sprintf("quorum n=%d", n), "arith.quorum", map[string]any{"n": n}, map[string]any{"quorum": Quorum(n)})
	}
	b.add("deadlines from LIFETIME", "arith.deadlines", map[string]any{"lifetime": Lifetime, "maxElectionInterval": 1000},
		map[string]any{"forceDeadline": ForceDeadline(1000), "stallDeadline": ForceDeadline(1000), "parkPeriod": ParkPeriod, "expiresAt(reserved=500)": 500 + Lifetime})

	// fee profile bounds
	col := fxOther
	for _, c := range []struct {
		name         string
		maxGas, sys  uint64
		floor, denom uint64
		collector    [20]byte
	}{{"floor 1<<62", 30_000_000, 2_000_000, MaxBaseFee, 8, col}, {"floor 1<<62 + 1", 30_000_000, 2_000_000, MaxBaseFee + 1, 8, col},
		{"floor 1", 30_000_000, 2_000_000, 1, 1, col}, {"floor 0", 30_000_000, 2_000_000, 0, 8, col}, {"denominator 0", 30_000_000, 2_000_000, 1, 0, col},
		{"system gas = max gas", 30_000_000, 30_000_000, 1, 8, col}, {"odd ordinary capacity", 30_000_001, 2_000_000, 1, 8, col}, {"zero collector", 30_000_000, 2_000_000, 1, 8, [20]byte{}}} {
		err := ValidateProfile(c.maxGas, c.sys, FeeParams{BaseFeeFloor: c.floor, ChangeDenominator: c.denom, FeeCollector: c.collector})
		b.add(c.name, "fee.validate", map[string]any{"maxGas": c.maxGas, "systemGas": c.sys, "baseFeeFloor": Dec(c.floor), "changeDenominator": c.denom, "feeCollector": hexa(c.collector)},
			map[string]any{"ok": err == nil, "error": errName(err)})
	}
	for _, c := range []struct {
		name                   string
		parent, used, capacity uint64
		floor, denom           uint64
	}{{"at target", 10_000_000, 14_000_000, 28_000_000, 1_000_000, 8}, {"full", 10_000_000, 28_000_000, 28_000_000, 1_000_000, 8},
		{"idle stops at the floor", 1_000_001, 0, 28_000_000, 1_000_000, 8}, {"wide product", 10_000_000_000_000, 28_000_000, 28_000_000, 1, 8},
		{"clamped at MAX_BASE_FEE", MaxBaseFee, 28_000_000, 28_000_000, 1, 8}, {"upward floor jump", 1_000_000, 14_000_000, 28_000_000, 5_000_000, 8},
		{"denominator 1", 1_000_000, 28_000_000, 28_000_000, 1, 1}, {"minimum increase 1", 7, 14_000_001, 28_000_000, 1, 8}} {
		got, err := NextBaseFee(c.parent, c.used, c.capacity, FeeParams{BaseFeeFloor: c.floor, ChangeDenominator: c.denom, FeeCollector: col})
		b.add(c.name, "fee.nextBaseFee", map[string]any{"parentBaseFee": Dec(c.parent), "ordinaryUsed": c.used, "ordinaryCapacity": c.capacity, "baseFeeFloor": Dec(c.floor),
			"changeDenominator": c.denom}, map[string]any{"nextBaseFee": Dec(got), "error": errName(err)})
	}
	prev := FeeParams{BaseFeeFloor: 1_000_000, ChangeDenominator: 8, FeeCollector: col}
	next := FeeParams{BaseFeeFloor: 5_000_000, ChangeDenominator: 4, FeeCollector: fxSender}
	st := Fees{Previous: prev, Current: prev, EffectiveBlock: 0}
	st = ApplyFeeBoundary(st, next, 100)
	var rows []any
	base := uint64(1_200_000)
	for n := uint64(99); n <= 103; n++ {
		f := FeesFor(n, st)
		pf := FeesFor(n-1, st)
		perr := ReconcileParentBaseFee(base, pf)
		child, err := NextBaseFee(base, 14_000_000, 28_000_000, f)
		rows = append(rows, map[string]any{"block": n, "fN": feeJSON(f), "fNminus1": feeJSON(pf), "parentBaseFee": Dec(base), "parentReconciles": perr == nil,
			"childBaseFee": Dec(child), "error": errName(err), "beneficiary": hexa(f.FeeCollector)})
		base = child
	}
	b.add("FeeParams boundary in B_ack = 100", "fee.transition", map[string]any{"previous": feeJSON(prev), "new": feeJSON(next), "bAck": 100, "ordinaryUsed": 14_000_000,
		"ordinaryCapacity": 28_000_000}, map[string]any{"effectiveBlock": st.EffectiveBlock, "blocks": rows})
	return b.out, b.err
}

func feeJSON(f FeeParams) map[string]any {
	return map[string]any{"baseFeeFloor": Dec(f.BaseFeeFloor), "changeDenominator": f.ChangeDenominator, "feeCollector": hexa(f.FeeCollector)}
}
