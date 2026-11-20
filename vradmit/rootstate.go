package vradmit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
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
	// Acknowledged is the root's acknowledged result (design section 5.2 item 2): GENESIS_RESULT at genesis, then the result of every
	// projected Boundary, primary or recovered (a recovery reproduces J's authorization, so its result is J's).
	Acknowledged vrschema.Word
	// PrepareUCTime is the committed UC time of the block that ordered the stored attempt's Prepare, which the activation time gate reads
	// at the Freeze (section 7.1); zero until a Prepare of the attempt is committed, and reset with the attempt.
	PrepareUCTime uint64
	// Staged is the primary a committed Freeze admitted, until its Boundary: the successor body the commit and the acknowledgement name it
	// by, its result and the Boundary's rejectedBitmap (bit i: RegistryChanges entry i is not Accepted, design section 4.1). StagedBody is
	// zero when none is staged.
	StagedBody   [32]byte
	StagedResult vrschema.Word
	StagedBitmap uint16
	// StagedSupport are the staged primary's own readiness commitments (by J's exact bindings), which enter the support table at its
	// primary Boundary (MaterializeJ); a recovered Boundary drops them.
	StagedSupport SupportTable
	// StagedKSupport is K's own support that the staged primary's Freeze verified (its fresh commitments and K readiness, by K's exact
	// bindings): a recovered Boundary keeps K installed and promotes it into the table (design section 7.3); a primary one drops it.
	StagedKSupport SupportTable
	// AttemptOpenRound and AttemptOpenUCTime are the round and committed UC time of the block whose end opened the stored attempt identity
	// (the Open step, design section 5.5.2): the intent's attemptOpenRound, of which its anchor is max(source.certRootRound,
	// attemptOpenRound), and openTime(0) when the anchor is that block (VT-05b). Zero for the genesis attempt, which no block opened.
	AttemptOpenRound  uint64
	AttemptOpenUCTime uint64
	// Schedule is the root's committed activation schedule (design section 7.1, VT-07a): every Accepted ScheduleActivation of a handoff
	// that committed, in change order, with the latch of the root history applied (an entry whose E <= an installed epoch is Latched at
	// that commit, permanently). It is the fold's, the cutoff's and the support gates' schedule, and what the fences and the warnings
	// read; VR's own activations[] follows at the Boundary and is what ureth reads. Bounded by MAX_ACTIVATIONS.
	Schedule []vrschema.Activation
	// StagedSchedule are the entries the staged primary's Accepted schedule changes append when its H commits (cleared with the staging:
	// an Abort before H drops them).
	StagedSchedule []vrschema.Activation
}

type activationWire struct {
	_               struct{} `cbor:",toarray"`
	RuleID          hex.Bytes
	ReleaseDigest   hex.Bytes
	RootEpoch       uint64
	NotBeforeUcTime uint64
	State           uint64
	ChangeID        uint64
}

func encodeActivations(as []vrschema.Activation) []activationWire {
	out := make([]activationWire, len(as))
	for i, a := range as {
		out[i] = activationWire{RuleID: a.RuleID[:], ReleaseDigest: a.ReleaseDigest[:], RootEpoch: a.RootEpoch, NotBeforeUcTime: a.NotBeforeUcTime,
			State: uint64(a.State), ChangeID: a.ChangeID}
	}
	return out
}

func decodeActivations(ws []activationWire) ([]vrschema.Activation, error) {
	if len(ws) > vrschema.MaxActivations {
		return nil, fmt.Errorf("%w: %d activations", ErrRootState, len(ws))
	}
	var out []vrschema.Activation
	for _, w := range ws {
		if len(w.RuleID) != 32 || len(w.ReleaseDigest) != 32 || w.State < uint64(vrschema.ActActive) || w.State > uint64(vrschema.ActLatched) {
			return nil, fmt.Errorf("%w: activation entry", ErrRootState)
		}
		out = append(out, vrschema.Activation{RuleID: vrschema.Word(w.RuleID), ReleaseDigest: vrschema.Word(w.ReleaseDigest), RootEpoch: w.RootEpoch,
			NotBeforeUcTime: w.NotBeforeUcTime, State: uint8(w.State), ChangeID: w.ChangeID})
	}
	return out, nil
}

// StageSchedule records, at a Freeze, the entries its Accepted kind 9 changes append (verdicts index by index, the fold's): they enter
// Schedule when H commits. A list of another length is refused.
func (s RootState) StageSchedule(rc []vrschema.RegistryChange, verdicts []uint8) (RootState, error) {
	if len(verdicts) != len(rc) {
		return s, fmt.Errorf("%w: %d verdicts for %d changes", ErrRootState, len(verdicts), len(rc))
	}
	s.StagedSchedule = nil
	for i, c := range rc {
		if uint8(c.Kind) != vrschema.KindScheduleActivation || verdicts[i] != vrschema.VerdictAccepted {
			continue
		}
		sc, err := vrschema.DecodeSchedule(c.Payload)
		if err != nil {
			return s, errors.Join(ErrRootState, err)
		}
		s.StagedSchedule = append(s.StagedSchedule, vrschema.Activation{RuleID: sc.RuleID, ReleaseDigest: sc.ReleaseDigest, RootEpoch: sc.RootEpoch,
			NotBeforeUcTime: sc.NotBeforeUcTime, State: vrschema.ActActive, ChangeID: c.ID})
	}
	return s, nil
}

// CommitSchedule is H's commit into root epoch installed: the staged entries append (a change id already present is skipped, so the
// recovery's second commit of the same result changes nothing), each superseding its rule's earlier effective entry, and every
// effective entry with E <= installed latches permanently. It is the whole root-history schedule transition (design section 7.1).
func (s RootState) CommitSchedule(installed uint64) (RootState, error) {
	sched := append([]vrschema.Activation(nil), s.Schedule...)
	for _, a := range s.StagedSchedule {
		seen := false
		for _, e := range sched {
			if e.ChangeID == a.ChangeID {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		next, err := vrschema.AppendSchedule(sched, vrschema.Schedule{RuleID: a.RuleID, ReleaseDigest: a.ReleaseDigest, RootEpoch: a.RootEpoch,
			NotBeforeUcTime: a.NotBeforeUcTime}, a.ChangeID)
		if errors.Is(err, vrschema.ErrOversize) {
			// VR's queue-time check counts recorded plus pending schedules against MAX_ACTIVATIONS (64), so this cannot happen against a
			// correct VR; if it ever does, every root ignores the entry identically rather than halting
			continue
		} else if err != nil {
			return s, errors.Join(ErrRootState, err)
		}
		sched = next
	}
	s.Schedule = vrschema.Latch(sched, installed)
	return s, nil
}

type rootStateWire struct {
	_             struct{} `cbor:",toarray"`
	Domain        string
	Version       uint64
	Backoff       hex.Bytes
	OpenUCTime    uint64
	Support       hex.Bytes
	Acknowledged  hex.Bytes
	PrepareUCTime uint64
	StagedBody    hex.Bytes
	StagedResult  hex.Bytes
	StagedBitmap  uint64
	StagedSupport hex.Bytes
	StagedKSupport hex.Bytes
	AttemptOpen   uint64
	AttemptOpenUC uint64
	Schedule      []activationWire
	StagedSched   []activationWire
}

const rootStateDomain = "UNICITY_VR_ROOT_STATE"

// GenesisRootState initializes the state at the genesis epoch with the genesis committee size (no open, no settle).
func GenesisRootState(epoch uint64, n uint32) RootState {
	return RootState{Backoff: vrschema.GenesisBackoff(epoch, n), Acknowledged: vrschema.GenesisResult}
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
	if (s.StagedBody == [32]byte{}) != (s.StagedResult == vrschema.Word{}) || (s.StagedBody == [32]byte{} && (s.StagedBitmap != 0 || len(s.StagedSupport.Entries) != 0 || len(s.StagedKSupport.Entries) != 0 || len(s.StagedSchedule) != 0)) {
		return nil, fmt.Errorf("%w: a staged boundary without its body or result", ErrRootState)
	}
	st, err := s.StagedSupport.Encode()
	if err != nil {
		return nil, err
	}
	sk, err := s.StagedKSupport.Encode()
	if err != nil {
		return nil, err
	}
	return types.Cbor.Marshal(rootStateWire{Domain: rootStateDomain, Version: 2, Backoff: b, OpenUCTime: s.OpenUCTime, Support: t, StagedSupport: st, StagedKSupport: sk,
		Acknowledged: s.Acknowledged[:], PrepareUCTime: s.PrepareUCTime, StagedBody: s.StagedBody[:], StagedResult: s.StagedResult[:],
		StagedBitmap: uint64(s.StagedBitmap), AttemptOpen: s.AttemptOpenRound, AttemptOpenUC: s.AttemptOpenUCTime,
		Schedule: encodeActivations(s.Schedule), StagedSched: encodeActivations(s.StagedSchedule)})
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

// ErrRootStateV1 is the refusal of a version 1 VR root state (a checkpoint written before the activation schedule joined the committed
// control state, VT-07a). The change is not backward compatible: the control digest and every replay hash differ, so a v1 chain cannot be
// continued by this release. A new generation is required.
var ErrRootStateV1 = fmt.Errorf("%w: a version 1 VR root state: this release adds the committed activation schedule to the control state, which changes its encoding and digest; a new generation is required (a v1 checkpoint cannot be continued)", ErrRootState)

// DecodeRootState accepts exactly the canonical encoding.
func DecodeRootState(raw []byte) (RootState, error) {
	var head []any
	if err := types.Cbor.Unmarshal(raw, &head); err == nil && len(head) >= 2 && head[0] == rootStateDomain {
		if v, ok := head[1].(uint64); ok && v == 1 {
			return RootState{}, ErrRootStateV1
		}
	}
	var w rootStateWire
	if err := types.Cbor.Unmarshal(raw, &w); err != nil || w.Domain != rootStateDomain || w.Version != 2 {
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
	staged, err := DecodeSupportTable(w.StagedSupport)
	if err != nil {
		return RootState{}, errors.Join(ErrRootState, err)
	}
	stagedK, err := DecodeSupportTable(w.StagedKSupport)
	if err != nil {
		return RootState{}, errors.Join(ErrRootState, err)
	}
	if len(w.Acknowledged) != 32 || len(w.StagedBody) != 32 || len(w.StagedResult) != 32 || w.StagedBitmap > 0xFFFF {
		return RootState{}, fmt.Errorf("%w: field widths", ErrRootState)
	}
	sched, err := decodeActivations(w.Schedule)
	if err != nil {
		return RootState{}, err
	}
	stagedSched, err := decodeActivations(w.StagedSched)
	if err != nil {
		return RootState{}, err
	}
	s := RootState{Schedule: sched, StagedSchedule: stagedSched, Backoff: bw.State, OpenUCTime: w.OpenUCTime, Support: t, Acknowledged: vrschema.Word(w.Acknowledged), PrepareUCTime: w.PrepareUCTime,
		StagedBody: [32]byte(w.StagedBody), StagedResult: vrschema.Word(w.StagedResult), StagedBitmap: uint16(w.StagedBitmap), StagedSupport: staged, StagedKSupport: stagedK,
		AttemptOpenRound: w.AttemptOpen, AttemptOpenUCTime: w.AttemptOpenUC}
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
// certificate's view). ucTime is the committed UC time of the block that ordered the Prepare.
func (s RootState) ApplyPrepare(epoch, attempt, ucTime uint64) (RootState, error) {
	n, err := s.event(vrschema.BackoffEvent{Op: "PR", Epoch: epoch, Attempt: attempt})
	if err != nil {
		return s, err
	}
	n.PrepareUCTime = ucTime
	return n, nil
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
		s.OpenUCTime, s.PrepareUCTime = 0, 0
	}
	s.Backoff = b
	return s, nil
}

// EndBlockAt is EndBlock for the block at round with committed UC time ucTime: an Open step that changes the attempt identity records
// that block as the attempt's opening.
func (s RootState) EndBlockAt(epoch, round, ucTime uint64, after vrschema.ControlState, committee uint32) (RootState, error) {
	n, err := s.EndBlock(epoch, round, after, committee)
	if err != nil {
		return n, err
	}
	if n.Backoff.Epoch != s.Backoff.Epoch || n.Backoff.Attempt != s.Backoff.Attempt {
		n.AttemptOpenRound, n.AttemptOpenUCTime = round, ucTime
	}
	return n, nil
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

// ControlOf is the backoff's view of a committed root control state (evmroot.ControlState): idle, aborted at k, prepared at k with its
// ordered round, or a handoff running past its Freeze (endorsed, committed, frozen), whose next attempt is undefined.
func ControlOf(c *evmroot.ControlState) vrschema.ControlState {
	if c == nil {
		return vrschema.ControlState{Kind: vrschema.CtlFrozen}
	}
	switch c.Phase {
	case "idle":
		return vrschema.ControlState{Kind: vrschema.CtlIdle}
	case "aborted":
		return vrschema.ControlState{Kind: vrschema.CtlAborted, Attempt: c.Attempt}
	case "prepared":
		return vrschema.ControlState{Kind: vrschema.CtlPrepared, Attempt: c.Attempt, OrderedRound: c.OrderedRound}
	}
	return vrschema.ControlState{Kind: vrschema.CtlFrozen, Attempt: c.Attempt, OrderedRound: c.OrderedRound}
}

// PlannedAttempt is VR-mode planning aligned with the cooldown predicate (design section 5.5.2, "plannedAttempt alignment"): the
// attempt identity, the intent's attemptOpenRound and control validation all read PlannableAttempt, so between a Prepare's lapse
// (round > OrderedRound + 24) and the end of its cooldown (round > OrderedRound + 48) no next attempt exists. ok is false where it is
// undefined; k = 2^64 - 1 is ErrHandoffApproval. The legacy (pre-VR) planner keeps its lapse rule, which stages the next plan during
// the cooldown.
func PlannedAttempt(c *evmroot.ControlState, round uint64) (uint64, bool, error) {
	return vrschema.PlannableAttempt(ControlOf(c), round)
}
