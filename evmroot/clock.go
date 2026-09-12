package evmroot

// CertifiedRoundClock models the "Certified Round Clock" rule
// (evm-partition.tex §"Round Parameters"): protocol deadlines are evaluated
// against the certified root round recorded in seal-registry state, using
// threshold comparisons (>=), never equality against an expected round, and
// never the EVM timestamp or block height as elapsed real time.
//
// The feed may skip root rounds (evm-partition.tex §"Seal Feed"): the
// recorded round jumps from whatever the last import saw to the root round
// of the next imported certificate. A threshold that the recorded round
// steps over — e.g. imports at 98 then 107, threshold 100 — must still
// fire, exactly once. AdvanceTo/Fired implement that: idempotent, skip-safe,
// monotone.
type CertifiedRoundClock struct {
	recorded uint64          // last imported root round in state (0 = nothing imported yet)
	fired    map[uint64]bool // thresholds already triggered
}

// NewCertifiedRoundClock returns a clock with nothing imported yet.
func NewCertifiedRoundClock() *CertifiedRoundClock {
	return &CertifiedRoundClock{fired: map[uint64]bool{}}
}

// Recorded returns the certified root round currently in state.
func (c *CertifiedRoundClock) Recorded() uint64 { return c.recorded }

// AdvanceTo records the root round of a newly imported certificate. It
// panics if asked to move backwards — a certificate selected by "latest
// local arrival" rather than by authorizing the proposed shard round is
// the classic way that happens, and it must be a hard error, not a silent
// rewind (appendix-evm.tex §"Seal registry state": "The source is the
// certificate authorizing the proposed shard round, not the newest message
// locally observed"). Re-importing the same round is a no-op (a duplicate
// certificate for the same statement).
func (c *CertifiedRoundClock) AdvanceTo(rootRound uint64) {
	if rootRound < c.recorded {
		panic("evmroot: certified round clock cannot move backwards")
	}
	c.recorded = rootRound
}

// Due reports whether threshold has been reached by the recorded round.
func (c *CertifiedRoundClock) Due(threshold uint64) bool { return c.recorded >= threshold }

// Fire returns true the first time it is called for a threshold that Due
// reports as reached, and false every time after — the "trigger fires
// exactly once" semantics a deadline needs even when the recorded round
// skipped past the threshold value. Returns false while the threshold is
// not yet due.
func (c *CertifiedRoundClock) Fire(threshold uint64) bool {
	if !c.Due(threshold) || c.fired[threshold] {
		return false
	}
	c.fired[threshold] = true
	return true
}
