package vrschema

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// IncLevel is the failure step: l + views/n + 1, capped at LMax, compared before adding. Valid state: l <= LMax, 1 <= n <= 16.
func IncLevel(l uint8, views uint64, n uint32) uint8 {
	q := views / uint64(n)
	if q >= uint64(LMax-l) {
		return LMax
	}
	return l + uint8(q) + 1
}

// DecLevel is the success step: max(min(l + view/n, LMax) - 1, 0).
func DecLevel(l uint8, view uint64, n uint32) uint8 {
	q := view / uint64(n)
	e := uint64(LMax)
	if q < uint64(LMax-l) {
		e = uint64(l) + q
	}
	if e == 0 {
		return 0
	}
	return uint8(e - 1)
}

// ViewTimeoutSeconds is T(l, v) = 10 * 2^(l + v/n) seconds, or never when the exponent is at least 37 or T exceeds 2^40.
func ViewTimeoutSeconds(l uint8, view uint64, n uint32) (secs uint64, never bool) {
	q := view / uint64(n)
	if q >= uint64(SatExponent-uint64(l)) {
		return 0, true
	}
	t := uint64(T0Seconds) << (uint64(l) + q)
	if t > SatSeconds {
		return 0, true
	}
	return t, false
}

// Deadline is open + T with a carry (or never) giving an unsatisfiable deadline.
func Deadline(open uint64, l uint8, view uint64, n uint32) (at uint64, never bool) {
	t, nv := ViewTimeoutSeconds(l, view, n)
	if nv {
		return 0, true
	}
	s, carry := bits.Add64(open, t, 0)
	if carry != 0 {
		return 0, true
	}
	return s, false
}

// TReq is the per-view adequacy bound ceil(D (1 + rho)) + 1 in integer seconds for D given in milliseconds (rho = 1/10000).
func TReq(dMillis uint64) uint64 {
	num := dMillis * (PremiseRhoDen + PremiseRhoNum)
	den := uint64(1000 * PremiseRhoDen)
	return (num+den-1)/den + 1
}

// ResidenceWaitMillis is T (1 + rho) in milliseconds, rounded up: the live-vote residence wait.
func ResidenceWaitMillis(tSeconds uint64) uint64 {
	return (tSeconds*1000*(PremiseRhoDen+PremiseRhoNum) + PremiseRhoDen - 1) / PremiseRhoDen
}

// ControlKind is the root's handoff control state after a block, as the backoff identity reads it.
type ControlKind uint8

const (
	CtlIdle     ControlKind = 0
	CtlAborted  ControlKind = 1
	CtlPrepared ControlKind = 2
	CtlFrozen   ControlKind = 3 // a valid Freeze is endorsed and the handoff is running to H
)

// ControlState is the summary of the root control state after a committed block.
type ControlState struct {
	Kind         ControlKind `json:"kind"`
	Attempt      uint64      `json:"attempt"`      // k
	OrderedRound uint64      `json:"orderedRound"` // the Prepare's ordered round (Prepared, Frozen)
}

// ErrHandoffApproval is the checked refusal at k = 2^64 - 1: no next attempt exists.
var ErrHandoffApproval = errors.New("ErrHandoffApproval")

// PlannableAttempt is the design section 5.5.2 identity table. ok is false where it is undefined.
func PlannableAttempt(c ControlState, round uint64) (uint64, bool, error) {
	switch c.Kind {
	case CtlIdle:
		return 0, true, nil
	case CtlAborted:
		if c.Attempt == ^uint64(0) {
			return 0, false, ErrHandoffApproval
		}
		return c.Attempt + 1, true, nil
	case CtlPrepared:
		if c.OrderedRound > ^uint64(0)-PrepareCooldown || round <= c.OrderedRound+PrepareCooldown {
			return 0, false, nil
		}
		if c.Attempt == ^uint64(0) {
			return 0, false, ErrHandoffApproval
		}
		return c.Attempt + 1, true, nil
	}
	return 0, false, nil
}

// FreezeInTime is the lapse rule: a Freeze is valid only in a block whose round is at most OrderedRound + 24.
func FreezeInTime(orderedRound, blockRound uint64) bool {
	return orderedRound <= ^uint64(0)-PrepareLapse && blockRound <= orderedRound+PrepareLapse
}

// HandoffBackoff is the per-shard backoff state committed in the control-state digest.
type HandoffBackoff struct {
	_        struct{}  `cbor:",toarray"`
	Level    uint8     `json:"level"`
	Epoch    uint64    `json:"epoch"`
	Attempt  uint64    `json:"attempt"`
	N        uint32    `json:"n"`
	Intent   hex.Bytes `json:"intent"` // 32 bytes, zero until bound
	LastView uint64    `json:"lastView"`
	Prepared bool      `json:"prepared"`
	Settled  bool      `json:"settled"`
}

// Encode is the canonical CBOR ["UNICITY_VR_HANDOFF_BACKOFF", 1, state] the control-state digest hashes; Digest is its SHA-256.
func (b HandoffBackoff) Encode() ([]byte, error) {
	if len(b.Intent) != 32 || b.Level > LMax || b.N < 1 || b.N > MaxCommittee {
		return nil, fmt.Errorf("%w: backoff state", ErrRange)
	}
	return types.Cbor.Marshal([]any{BackoffDomain, uint64(1), b})
}

// Digest is SHA-256 of Encode.
func (b HandoffBackoff) Digest() ([32]byte, error) {
	e, err := b.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(e), nil
}

// GenesisBackoff initializes the state without an open or a settle.
func GenesisBackoff(epoch uint64, n uint32) HandoffBackoff {
	return HandoffBackoff{Epoch: epoch, N: n, Intent: make([]byte, 32)}
}

// BackoffEvent is one committed control of a block, in payload order.
type BackoffEvent struct {
	Op      string    `json:"op"`               // "HV", "PR", "FZ"
	Intent  hex.Bytes `json:"intent,omitempty"` // HV
	View    uint64    `json:"view,omitempty"`   // HV: v; FZ: v*
	Epoch   uint64    `json:"epoch"`            // PR, FZ: the attempt identity the control is for
	Attempt uint64    `json:"attempt"`
}

// Block is one committed root block as the backoff machine reads it.
type Block struct {
	Epoch         uint64         `json:"epoch"`
	Round         uint64         `json:"round"`
	Events        []BackoffEvent `json:"events"`
	ControlAfter  ControlState   `json:"controlAfter"`
	CommitteeSize uint32         `json:"committeeSize"`
}

// ErrBackoffEvent refuses a control the stored state does not admit (the block is invalid).
var ErrBackoffEvent = errors.New("vrschema: control does not match the backoff state")

func (b *HandoffBackoff) settle() {
	if !b.Prepared {
		b.Level = IncLevel(b.Level, b.LastView, b.N)
	}
	b.Settled = true
}

// ApplyBlock applies one committed block: its controls in payload order against the stored identity, then the Open step once at the
// end. Controls for an identity opened by this block are valid only from the next block.
func ApplyBlock(b HandoffBackoff, blk Block) (HandoffBackoff, error) {
	b.Intent = append([]byte(nil), b.Intent...)
	zero := make([]byte, 32)
	for _, e := range blk.Events {
		switch e.Op {
		case "HV":
			if len(e.Intent) != 32 || string(e.Intent) == string(zero) || b.Settled {
				return b, fmt.Errorf("%w: HandoffView", ErrBackoffEvent)
			}
			switch {
			case string(b.Intent) == string(zero) && e.View == 1:
				b.Intent = append([]byte(nil), e.Intent...)
			case string(b.Intent) == string(e.Intent) && b.LastView != ^uint64(0) && e.View == b.LastView+1:
			default:
				return b, fmt.Errorf("%w: HandoffView %d after %d", ErrBackoffEvent, e.View, b.LastView)
			}
			b.LastView = e.View
		case "PR":
			if e.Epoch != b.Epoch || e.Attempt != b.Attempt || b.Settled || b.Prepared {
				return b, fmt.Errorf("%w: Prepare", ErrBackoffEvent)
			}
			b.Prepared = true
		case "FZ":
			if e.Epoch != b.Epoch || e.Attempt != b.Attempt || b.Settled || !b.Prepared {
				return b, fmt.Errorf("%w: Freeze", ErrBackoffEvent)
			}
			b.Level = DecLevel(b.Level, e.View, b.N)
			b.Settled = true
		default:
			return b, fmt.Errorf("%w: op %q", ErrBackoffEvent, e.Op)
		}
	}
	// Undefined (including attempt exhaustion, which planning reports as ErrHandoffApproval) is a no-op here.
	k, ok, _ := PlannableAttempt(blk.ControlAfter, blk.Round)
	if !ok {
		return b, nil
	}
	if blk.Epoch == b.Epoch && k == b.Attempt {
		return b, nil
	}
	if !b.Settled {
		b.settle()
	}
	return HandoffBackoff{Level: b.Level, Epoch: blk.Epoch, Attempt: k, N: blk.CommitteeSize, Intent: make([]byte, 32)}, nil
}
