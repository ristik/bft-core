package vradmit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// RootState is the root's VR-mode control state, committed in the control-state digest: the handoff backoff of the coupled EVM shard
// (design section 5.5), the committed UC time of the block that opened the bound intent's latest view (the replay floor's openTime), and
// the rule-support table (section 7.3). Only committed root blocks change it.
type RootState struct {
	Backoff vrschema.HandoffBackoff
	// OpenUCTime is openTime(Backoff.LastView) while an intent is bound; zero otherwise (view 0 opens at the intent's anchor block,
	// whose time the executor supplies).
	OpenUCTime uint64
	Support    SupportTable
}

type rootStateWire struct {
	_          struct{} `cbor:",toarray"`
	Domain     string
	Version    uint64
	Backoff    hex.Bytes
	OpenUCTime uint64
	Support    hex.Bytes
}

const rootStateDomain = "UNICITY_VR_ROOT_STATE"

// GenesisRootState initializes the state at the genesis epoch with the genesis committee size (no open, no settle).
func GenesisRootState(epoch uint64, n uint32) RootState {
	return RootState{Backoff: vrschema.GenesisBackoff(epoch, n)}
}

// Encode is the canonical encoding the control state carries.
func (s RootState) Encode() ([]byte, error) {
	b, err := s.Backoff.Encode()
	if err != nil {
		return nil, err
	}
	t, err := s.Support.Encode()
	if err != nil {
		return nil, err
	}
	if (s.Backoff.LastView == 0) && s.OpenUCTime != 0 {
		return nil, fmt.Errorf("%w: an open time without a committed view", ErrRootState)
	}
	return types.Cbor.Marshal(rootStateWire{Domain: rootStateDomain, Version: 1, Backoff: b, OpenUCTime: s.OpenUCTime, Support: t})
}

// Digest is SHA-256 of Encode.
func (s RootState) Digest() ([32]byte, error) {
	b, err := s.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// ErrRootState reports a VR root state encoding that is malformed or not canonical.
var ErrRootState = errors.New("vradmit: VR root state")

// DecodeRootState accepts exactly the canonical encoding.
func DecodeRootState(raw []byte) (RootState, error) {
	var w rootStateWire
	if err := types.Cbor.Unmarshal(raw, &w); err != nil || w.Domain != rootStateDomain || w.Version != 1 {
		return RootState{}, fmt.Errorf("%w: encoding", ErrRootState)
	}
	var bw struct {
		_       struct{} `cbor:",toarray"`
		Domain  string
		Version uint64
		State   vrschema.HandoffBackoff
	}
	if err := types.Cbor.Unmarshal(w.Backoff, &bw); err != nil || bw.Domain != vrschema.BackoffDomain || bw.Version != 1 {
		return RootState{}, fmt.Errorf("%w: backoff", ErrRootState)
	}
	t, err := DecodeSupportTable(w.Support)
	if err != nil {
		return RootState{}, errors.Join(ErrRootState, err)
	}
	s := RootState{Backoff: bw.State, OpenUCTime: w.OpenUCTime, Support: t}
	again, err := s.Encode()
	if err != nil || !bytes.Equal(again, raw) {
		return RootState{}, fmt.Errorf("%w: not canonical", ErrRootState)
	}
	return s, nil
}

// ViewEnv is what the replay rule of one HandoffView reads from committed history (design section 5.3.2): whether the intent is the
// derivable one with a still-valid source, whether a Prepare is committed for the intent's attempt, the anchor block's UC time
// (openTime(0)), the HandoffView count of the carrying block and its UC time.
type ViewEnv struct {
	IntentDerivable  bool
	PrepareCommitted bool
	AnchorUCTime     uint64
	InBlock          int
	BlockUCTime      uint64
}

// Replay is the vrschema replay input of HandoffView(intent, view) over this state.
func (s RootState) Replay(intent []byte, view uint64, env ViewEnv) vrschema.HandoffViewReplay {
	b := s.Backoff
	zero := make([]byte, 32)
	bound := !bytes.Equal(b.Intent, zero)
	agrees := !b.Settled && len(intent) == 32 && !bytes.Equal(intent, zero) &&
		((!bound && view == 1) || (bound && bytes.Equal(b.Intent, intent) && b.LastView != ^uint64(0) && view == b.LastView+1))
	committed, open := uint64(0), env.AnchorUCTime
	if bound && bytes.Equal(b.Intent, intent) {
		committed, open = b.LastView, s.OpenUCTime
	}
	return vrschema.HandoffViewReplay{IntentDerivable: env.IntentDerivable && (!bound || bytes.Equal(b.Intent, intent)), CommittedView: committed,
		BackoffAgrees: agrees, PrepareCommitted: env.PrepareCommitted || b.Prepared, OpenUCTime: open, Level: b.Level, N: b.N, InBlock: env.InBlock}
}

// ApplyHandoffView is control op 5 (root-only, no record): the replay rule, then the HV transition, then the new view's open time.
func (s RootState) ApplyHandoffView(intent []byte, view uint64, env ViewEnv) (RootState, error) {
	if err := vrschema.VerifyHandoffView(s.Replay(intent, view, env), view, env.BlockUCTime); err != nil {
		return s, err
	}
	b, err := vrschema.ApplyBlock(s.Backoff, vrschema.Block{Epoch: s.Backoff.Epoch, Events: []vrschema.BackoffEvent{{Op: "HV", Intent: intent, View: view}},
		ControlAfter: vrschema.ControlState{Kind: vrschema.CtlFrozen}}) // ControlAfter undefined: no Open here; the block end opens
	if err != nil {
		return s, err
	}
	s.Backoff, s.OpenUCTime = b, env.BlockUCTime
	return s, nil
}

// ApplyPrepare and ApplyFreeze are the PR and FZ transitions of a committed Prepare or Freeze of the stored attempt (vStar is the
// certificate's view).
func (s RootState) ApplyPrepare(epoch, attempt uint64) (RootState, error) {
	return s.event(vrschema.BackoffEvent{Op: "PR", Epoch: epoch, Attempt: attempt})
}

func (s RootState) ApplyFreeze(epoch, attempt, vStar uint64) (RootState, error) {
	return s.event(vrschema.BackoffEvent{Op: "FZ", Epoch: epoch, Attempt: attempt, View: vStar})
}

func (s RootState) event(e vrschema.BackoffEvent) (RootState, error) {
	b, err := vrschema.ApplyBlock(s.Backoff, vrschema.Block{Epoch: s.Backoff.Epoch, Events: []vrschema.BackoffEvent{e},
		ControlAfter: vrschema.ControlState{Kind: vrschema.CtlFrozen}})
	if err != nil {
		return s, err
	}
	s.Backoff = b
	return s, nil
}

// EndBlock is the Open step, once at the end of every committed block after all records and controls: when the attempt identity of the
// control state after the block is defined and differs from the stored one, the stored attempt settles and the state resets to the new
// identity with the current committee size; the open time goes with the intent.
func (s RootState) EndBlock(epoch, round uint64, after vrschema.ControlState, committee uint32) (RootState, error) {
	b, err := vrschema.ApplyBlock(s.Backoff, vrschema.Block{Epoch: epoch, Round: round, ControlAfter: after, CommitteeSize: committee})
	if err != nil {
		return s, err
	}
	if b.Epoch != s.Backoff.Epoch || b.Attempt != s.Backoff.Attempt {
		s.OpenUCTime = 0
	}
	s.Backoff = b
	return s, nil
}

// ResidenceWaitMillis is the live-vote residence wait of view v at level L: ceil(T(L, v) * 1000 * (1 + rho)) ms; never is false.
func ResidenceWaitMillis(level uint8, view uint64, n uint32) (uint64, bool) {
	t, never := vrschema.ViewTimeoutSeconds(level, view, n)
	if never {
		return 0, false
	}
	return vrschema.ResidenceWaitMillis(t), true
}

// ResidenceEligible is the live-vote residence rule (design section 5.3.2): an honest root votes for a proposal carrying HandoffView(I,
// v+1) only once T(L, v)(1+rho) has passed on its local monotonic clock since it first held the opening commit of view v (seenMillis;
// a restart resets it to the re-learning time). It is a voting policy, never a validity rule: a root that is not yet eligible defers its
// vote, it never marks the block invalid. Times are monotonic milliseconds; no time.Duration.
func ResidenceEligible(seenMillis, nowMillis uint64, level uint8, view uint64, n uint32) bool {
	wait, ok := ResidenceWaitMillis(level, view, n)
	if !ok || nowMillis < seenMillis {
		return false
	}
	return nowMillis-seenMillis >= wait
}
