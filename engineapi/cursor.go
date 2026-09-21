package engineapi

import "errors"

// cursorState distinguishes a constructed cursor from the zero value. The ordering matters: the
// zero value is cursorUnset, so a SealRegistryCursor that was never constructed is refused rather
// than silently read as 0.
type cursorState uint8

const (
	cursorUnset cursorState = iota
	cursorNotActivated
	cursorCommitted
)

// SealRegistryCursor is D1 §5's seal-registry cursor — the highest root round whose outcome this
// node has COMMITTED to its seal registry — as far as this branch can source it.
//
// Its zero value is deliberately unusable. A bare uint64 would let a caller who forgot the cursor
// pass 0, and evmroot.ValidateBoundCertificate refuses when cert.RootRound < lastAppliedRootRound
// (evmroot/d1select.go), so a 0 silently deletes that refusal — F2c §6 calls this negative 4b, the
// unsafe direction. There are exactly two honest ways to get a cursor and both are explicit:
//
//   - CursorNotActivated(): the cursor rule is off, and its doc says precisely which refusal stops
//     being enforced.
//   - CommittedCursor(n): the cursor is pinned from committed state, and a certificate behind n is
//     refused.
//
// A caller that constructs neither gets a refusal from Adapter.Build, never a silently disabled
// check.
type SealRegistryCursor struct {
	state cursorState
	value uint64
}

// CursorNotActivated is the explicit "the seal-registry cursor rule is not enforced" choice, and the
// only honest one on this branch: no seal registry exists in this repository, ureth's registry is
// not readable from here, and the adapter cannot see the root round of the last APPLIED certificate
// without another executor-boundary extension.
//
// What is off, precisely: rootinput.Derive pins Context.LastAppliedRootRound = 0, so
// evmroot.ValidateBoundCertificate's "bound certificate root round N is behind the seal-registry
// cursor M" refusal (M > N) never fires. A certificate behind this node's committed applied history
// is therefore accepted where committed state would have refused it — F2c §6's stale bound
// selection. Nothing else is relaxed: every other refusal rootinput.Derive makes still applies.
//
// The preferable end state is CommittedCursor, pinned from committed execution state. When a seal
// registry — or a boundary exposing the last applied root round — arrives, this constructor should
// be replaced at the construction site by CommittedCursor.
func CursorNotActivated() SealRegistryCursor {
	return SealRegistryCursor{state: cursorNotActivated}
}

// CommittedCursor pins the cursor from committed execution state: the highest root round whose
// outcome the seal registry has applied. A certificate whose root round is below n is then refused
// by rootinput.Derive, which is the rule F2c §6 prefers.
func CommittedCursor(n uint64) SealRegistryCursor {
	return SealRegistryCursor{state: cursorCommitted, value: n}
}

// activated reports whether the stale-cursor refusal is enforced.
func (c SealRegistryCursor) activated() bool {
	return c.state == cursorCommitted
}

// appliedRootRound returns the value to pin as rootinput.Context.LastAppliedRootRound, or a refusal
// when the cursor was never constructed.
func (c SealRegistryCursor) appliedRootRound() (uint64, error) {
	switch c.state {
	case cursorCommitted:
		return c.value, nil
	case cursorNotActivated:
		return 0, nil
	default:
		return 0, errors.New("engineapi: seal-registry cursor was never constructed — use CursorNotActivated() or CommittedCursor(n); refusing rather than silently disabling the stale-cursor check")
	}
}

// startupWarning is the once-at-startup message for a cursor that does not enforce the stale-cursor
// refusal, or ok=false when there is nothing to report.
func (c SealRegistryCursor) startupWarning() (string, bool) {
	switch c.state {
	case cursorCommitted:
		return "", false
	case cursorNotActivated:
		return "engineapi: seal-registry cursor rule is NOT activated: a bound certificate behind this node's committed applied history is accepted where committed state would refuse it (docs/design/f2c-root-input-wiring-contract.md §6)", true
	default:
		return "engineapi: seal-registry cursor was never constructed: every Adapter.Build will refuse (use CursorNotActivated() or CommittedCursor(n))", true
	}
}
