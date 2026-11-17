package vrschema

import (
	"errors"
	"fmt"
	"sort"
)

// VRModel is the reference model of VR's output and change state machines (design sections 3.4.2, 3.5.2 and 8.1 S2a): what VR stores
// and the effects it emits, without gas, modules or storage. VT-02's contract must agree with it on every vector.
type VRModel struct {
	Outputs     map[Word]*ModelOutput   `json:"-"`
	Changes     map[uint64]*ModelChange `json:"-"`
	OpenOutput  Word
	PendingPair Word
	PendingRec  bool // the staged pair is a RecoveryAck
	LastAcked   Word
	Health      uint8
	Active      [20]byte
	Detached    map[[20]byte]bool
	Cursor      uint64 // records applied
	Log         []LogRecord
	Progress    uint64
	UCTime      uint64
	NextChange  uint64
	Effects     []string // emitted effects, in order
}

// ModelOutput is one output.
type ModelOutput struct {
	State  uint8
	Source [20]byte
	Native bool
	Bound  []uint64
}

// ModelChange is one change.
type ModelChange struct {
	Kind         uint8
	State        uint8
	RejectReason uint8
	NotBeforeP   uint64
	NotBeforeT   uint64
	ScheduledAt  uint64
	BoundTo      Word
	PayloadSize  int
	Released     int
}

// LogRecord is one imported root record as VR applies it.
type LogRecord struct {
	Kind           uint8  `json:"kind"`
	ResultID       Word   `json:"-"`
	Recovered      bool   `json:"recovered,omitempty"`
	RejectedBitmap uint16 `json:"rejectedBitmap,omitempty"`
}

// NewVRModel is the genesis state: lastAcked = GENESIS_RESULT, the given active module, healthy, nothing open.
func NewVRModel(active [20]byte) *VRModel {
	return &VRModel{Outputs: map[Word]*ModelOutput{}, Changes: map[uint64]*ModelChange{}, LastAcked: GenesisResult, Active: active,
		Detached: map[[20]byte]bool{}, NextChange: 1}
}

// Refusals of the model's public calls.
var (
	ErrNotSource          = errors.New("NotSource")
	ErrPreconditionFailed = errors.New("PreconditionFailed")
	ErrInconsistent       = errors.New("Inconsistent")
	ErrNotCaughtUp        = errors.New("CursorBehind")
	ErrOpen               = errors.New("OutputOpen")
	ErrPair               = errors.New("PairPending")
	ErrDelay              = errors.New("DelayNotElapsed")
	ErrCancel             = errors.New("NotCancellable")
	ErrTooManyPending     = errors.New("TooManyPending")
	ErrNoWork             = errors.New("NoScheduledWork")
	ErrEpochGap           = errors.New("EpochGap")
)

func (m *VRModel) emit(f string, a ...any) { m.Effects = append(m.Effects, fmt.Sprintf(f, a...)) }

func (m *VRModel) anomaly(why string) {
	m.Health = HealthInconsistent
	m.emit("RecordAnomaly(%s)", why)
}

func (m *VRModel) pending() int {
	n := 0
	for _, c := range m.Changes {
		if c.State != ChActive && c.State != ChCancelled && c.State != ChRejected {
			n++
		}
	}
	return n
}

// Queue queues a change at the model's current progress and UC time.
func (m *VRModel) Queue(kind uint8, payloadSize int) (uint64, error) {
	if m.pending() >= MaxPendingChanges {
		return 0, ErrTooManyPending
	}
	id := m.NextChange
	m.NextChange++
	m.Changes[id] = &ModelChange{Kind: kind, State: ChQueued, NotBeforeP: m.Progress + DelayRounds, NotBeforeT: m.UCTime + DelaySeconds, PayloadSize: payloadSize}
	m.emit("Queued(%d)", id)
	return id, nil
}

// Execute moves a Queued change past both delays to Scheduled; a ModuleAction instead executes into the active module (ok reports the
// contained onGovernance outcome).
func (m *VRModel) Execute(id uint64, target [20]byte, ok bool) error {
	c := m.Changes[id]
	if c == nil || c.State != ChQueued {
		return ErrPreconditionFailed
	}
	if m.Health == HealthInconsistent {
		return ErrInconsistent
	}
	if m.Progress < c.NotBeforeP || m.UCTime < c.NotBeforeT {
		return ErrDelay
	}
	if c.Kind == KindModuleAction {
		switch {
		case target != m.Active:
			c.State, c.RejectReason = ChRejected, RejectNotActive
		case !ok:
			c.State, c.RejectReason = ChRejected, RejectActionFailed
		default:
			c.State = ChActive
		}
		m.emit("ModuleActionExecuted(%d,%s)", id, ChangeStateNames[c.State])
		return nil
	}
	c.State, c.ScheduledAt = ChScheduled, m.Progress
	m.emit("Scheduled(%d)", id)
	return nil
}

// Cancel cancels a Queued or Scheduled change; never once Bound.
func (m *VRModel) Cancel(id uint64) error {
	c := m.Changes[id]
	if c == nil || (c.State != ChQueued && c.State != ChScheduled) {
		return ErrCancel
	}
	c.State = ChCancelled
	m.emit("Cancelled(%d)", id)
	return nil
}

// Reserve opens an output. The gates hold for module and native reservations alike: not Inconsistent, no open output, no pending
// pair, and VR's cursor caught up with the SealRegistry's imported count (imported records all applied). A module reservation must
// come from the active module; a native one requires Faulted or Stalled health. Every bound id must be Scheduled.
//
// Native repair additionally needs Scheduled boundary work to bind (at least one id) and MIN_EPOCH_GAP progress units since the epoch's
// first ordinary round (sinceEpochStart), design section 3.6.2. A module reservation's due rule (design section 3.7.2: no open output,
// MIN_EPOCH_GAP since the last boundary and the epoch start, pending work) is the module's own and a precondition of the call here.
func (m *VRModel) Reserve(r Word, source [20]byte, native bool, bind []uint64, imported uint64, sinceEpochStart uint64) error {
	switch {
	case m.Health == HealthInconsistent:
		return ErrInconsistent
	case m.Cursor != imported:
		return ErrNotCaughtUp
	case m.OpenOutput != Word{}:
		return ErrOpen
	case m.PendingPair != Word{}:
		return ErrPair
	case m.Outputs[r] != nil || r == (Word{}):
		return ErrPreconditionFailed
	case native && m.Health != HealthFaulted && m.Health != HealthStalled:
		return ErrPreconditionFailed
	case native && len(bind) == 0:
		return ErrNoWork
	case native && sinceEpochStart < MinEpochGap:
		return ErrEpochGap
	case !native && source != m.Active:
		return ErrPreconditionFailed
	}
	ids := append([]uint64(nil), bind...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if c := m.Changes[id]; c == nil || c.State != ChScheduled {
			return ErrPreconditionFailed
		}
	}
	for _, id := range ids {
		m.Changes[id].State, m.Changes[id].BoundTo = ChBound, r
	}
	state := OutReserved
	if native {
		state = OutPublished
	}
	m.Outputs[r] = &ModelOutput{State: state, Source: source, Native: native, Bound: ids}
	m.OpenOutput = r
	m.emit("Reserved(%x)", r[:4])
	return nil
}

// Publish publishes a Ready, valid output (design section 3.4.2 row publish).
func (m *VRModel) Publish(r Word) (uint8, error) {
	o := m.Outputs[r]
	if o == nil {
		return PubNotMine, nil
	}
	if m.Health == HealthInconsistent {
		return PubPreconditionFailed, ErrInconsistent
	}
	if o.State != OutReserved {
		return PubPreconditionFailed, ErrPreconditionFailed
	}
	o.State = OutPublished
	m.emit("Published(%x)", r[:4])
	return PubPublished, nil
}

// Invalidate is total and lock-exempt: by the source it moves Reserved or Published to Invalidated and is otherwise a no-op; by anyone
// else it reverts NotSource for a known id and is a no-op for an unknown one. Reason 0 is the storage sentinel "not invalidated", so a
// source call with reason 0 is a no-op in every state; it never reverts.
func (m *VRModel) Invalidate(r Word, by [20]byte, reason uint8) (bool, error) {
	o := m.Outputs[r]
	if o == nil {
		return false, nil
	}
	if by != o.Source || o.Native {
		return false, ErrNotSource
	}
	if reason == 0 {
		return false, nil
	}
	if o.State == OutReserved || o.State == OutPublished {
		o.State = OutInvalidated
		m.emit("Invalidated(%x,%d)", r[:4], reason)
		return true, nil
	}
	return false, nil
}

func (m *VRModel) release(r Word, o *ModelOutput, resolution uint8, bitmap uint16) {
	for i, id := range o.Bound {
		c := m.Changes[id]
		c.Released++
		switch {
		case resolution == ResClosed:
			c.State, c.BoundTo = ChScheduled, Word{}
		case bitmap&(1<<uint(i)) != 0:
			c.State, c.RejectReason = ChRejected, VerdictConflict // the Boundary carries only the bitmap: Conflict is the generic root-rejection marker (schema 3.3)
		default:
			c.State = ChActive
		}
	}
	if m.OpenOutput == r {
		m.OpenOutput = Word{}
	}
	if !o.Native && !m.Detached[o.Source] {
		m.emit("onResolved(%x,%d)", r[:4], resolution)
	}
}

// Import appends records to the imported log (the SealRegistry side).
func (m *VRModel) Import(rs ...LogRecord) { m.Log = append(m.Log, rs...) }

// Apply applies exactly min(n, available) records; VR never reverts for record content.
func (m *VRModel) Apply(n int) int {
	done := 0
	for done < n && m.Cursor < uint64(len(m.Log)) {
		m.applyOne(m.Log[m.Cursor])
		m.Cursor++
		done++
	}
	return done
}

// Redeliver models a replayed record: the same authenticated index delivered again is never re-applied.
func (m *VRModel) Redeliver(index uint64) bool { return index < m.Cursor }

func (m *VRModel) applyOne(rec LogRecord) {
	o := m.Outputs[rec.ResultID]
	terminal := o != nil && (o.State == OutAcknowledged || o.State == OutRecovered || o.State == OutClosed)
	switch rec.Kind {
	case RecOutputRejected:
		switch {
		case o == nil:
			m.anomaly("OutputRejected of an unknown output")
		case o.State == OutReserved || o.State == OutPublished || o.State == OutInvalidated:
			o.State = OutRejected
			m.emit("Rejected(%x)", rec.ResultID[:4])
		}
	case RecSessionClosed:
		switch {
		case o == nil:
			m.anomaly("SessionClosed of an unknown output")
		case terminal:
		default:
			o.State = OutClosed
			m.emit("Closed(%x)", rec.ResultID[:4])
			m.release(rec.ResultID, o, ResClosed, 0)
		}
	case RecAck, RecRecoveryAck:
		switch {
		case o == nil:
			m.anomaly("acknowledgement of an unknown output")
		case terminal:
		case o.State == OutPublished || o.State == OutInvalidated:
			if m.PendingPair != (Word{}) {
				m.anomaly("a second pending pair")
				return
			}
			m.PendingPair, m.PendingRec = rec.ResultID, rec.Kind == RecRecoveryAck
			m.emit("PairStaged(%x)", rec.ResultID[:4])
		default:
			m.anomaly("acknowledgement of a Reserved or Rejected output")
		}
	case RecBoundary:
		if o == nil || m.PendingPair != rec.ResultID || rec.Recovered != m.PendingRec || (o.State != OutPublished && o.State != OutInvalidated) {
			m.anomaly("Boundary without its pair")
			return
		}
		res := ResAcknowledged
		o.State = OutAcknowledged
		if rec.Recovered {
			o.State, res = OutRecovered, ResRecovered
		}
		m.emit("%s(%x)", OutputStateNames[o.State], rec.ResultID[:4])
		m.release(rec.ResultID, o, res, rec.RejectedBitmap)
		m.LastAcked, m.PendingPair, m.PendingRec = rec.ResultID, Word{}, false
	}
}

// Snapshot is the observable model state the vectors assert.
type Snapshot struct {
	Outputs     map[string]string `json:"outputs"`
	Changes     map[string]string `json:"changes"`
	OpenOutput  string            `json:"openOutput"`
	PendingPair string            `json:"pendingPair"`
	LastAcked   string            `json:"lastAcked"`
	Health      uint8             `json:"health"`
	Cursor      uint64            `json:"cursor"`
}

// Snap is the snapshot under the given output names.
func (m *VRModel) Snap(names map[Word]string) Snapshot {
	nm := func(w Word) string {
		if w == (Word{}) {
			return ""
		}
		if w == GenesisResult {
			return "GENESIS_RESULT"
		}
		if n, ok := names[w]; ok {
			return n
		}
		return hx(w)
	}
	s := Snapshot{Outputs: map[string]string{}, Changes: map[string]string{}, OpenOutput: nm(m.OpenOutput), PendingPair: nm(m.PendingPair),
		LastAcked: nm(m.LastAcked), Health: m.Health, Cursor: m.Cursor}
	for r, o := range m.Outputs {
		s.Outputs[nm(r)] = OutputStateNames[o.State]
	}
	for id, c := range m.Changes {
		v := ChangeStateNames[c.State]
		if c.RejectReason != 0 {
			v += "(" + VerdictNames[c.RejectReason] + ")"
		}
		s.Changes[fmt.Sprint(id)] = fmt.Sprintf("%s released=%d", v, c.Released)
	}
	return s
}

// BindCandidate is one Scheduled change offered to binding selection.
type BindCandidate struct {
	ID          uint64 `json:"id"`
	Kind        uint8  `json:"kind"`
	PayloadSize int    `json:"payloadSize"`
	Scope       string `json:"scope"`               // ChangeScope of its payload ("" for kinds 2 and 10)
	Performed   bool   `json:"performed,omitempty"` // ForceRemove: the chosen trial performs it
}

// SelectBinding scans Scheduled changes ascending by id and binds while at most 8 root-side and 16 total changes and at most 64 KiB of
// payload are bound and the change's scope (ChangeScope) is not yet bound in this output: one per singleton kind, one per shard across
// kinds 6 and 8, one per partition for kind 7, one per rule for kind 9. A change that does not fit is deferred and stays Scheduled; it
// is never bound to be rejected later. A ForceRemove is bound only if the chosen trial performs it. ModuleAction never binds.
func SelectBinding(cands []BindCandidate) (bound, deferred []uint64) {
	cs := append([]BindCandidate(nil), cands...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	root, total, bytes := 0, 0, 0
	seen := map[string]bool{}
	for _, c := range cs {
		fits := c.Kind != KindModuleAction && total < MaxBoundTotal && bytes+c.PayloadSize <= MaxBoundPayload &&
			(!RootSide(c.Kind) || root < MaxBoundRootSide) && (c.Scope == "" || !seen[c.Scope]) &&
			(c.Kind != KindForceRemove || c.Performed)
		if !fits {
			deferred = append(deferred, c.ID)
			continue
		}
		bound = append(bound, c.ID)
		total++
		bytes += c.PayloadSize
		if RootSide(c.Kind) {
			root++
		}
		if c.Scope != "" {
			seen[c.Scope] = true
		}
	}
	return bound, deferred
}

// SwitchStep is one step of a pointer-switching Boundary.
type SwitchStep struct {
	Step   string `json:"step"`
	Module string `json:"module,omitempty"`
	From   uint64 `json:"from,omitempty"`
	Count  uint64 `json:"count,omitempty"`
}

// SwitchSequence is the frozen order of a batch [from, from+count) whose record at index boundaryAt applies a Boundary that switches
// the pointer (design section 3.6.1): the code-hash and liability-holder checks; adoptionReady when the module declares
// ADOPTION_CHECK; then the old module's onRecords through and including the switching Boundary; detach of the old module; the pointer
// and metadata switch; attach of the new module; the holder entry allocated only when attach succeeded and the new module is a
// liability holder (health Faulted and repair mode when attach failed); the remainder of the batch to the new pointer. When the switch
// is refused (code or holder mismatch, adoption not ready) the change is Rejected before any module call and the old module receives
// the whole batch in one onRecords.
func SwitchSequence(from, count, boundaryAt uint64, codeOK, adoptionReady, attachOK, holder bool) []SwitchStep {
	out := []SwitchStep{{Step: "checkCodeAndHolder", Module: "new"}}
	if !codeOK {
		return append(out, SwitchStep{Step: "reject", Module: "new"}, SwitchStep{Step: "onRecords", Module: "old", From: from, Count: count})
	}
	out = append(out, SwitchStep{Step: "adoptionReady", Module: "new"})
	if !adoptionReady {
		return append(out, SwitchStep{Step: "reject", Module: "new"}, SwitchStep{Step: "onRecords", Module: "old", From: from, Count: count})
	}
	out = append(out, SwitchStep{Step: "onRecords", Module: "old", From: from, Count: boundaryAt - from + 1}, SwitchStep{Step: "detach", Module: "old"},
		SwitchStep{Step: "setPointer", Module: "new"}, SwitchStep{Step: "attach", Module: "new"})
	if attachOK && holder {
		out = append(out, SwitchStep{Step: "allocateHolder", Module: "new"})
	}
	if !attachOK {
		out = append(out, SwitchStep{Step: "fault", Module: "new"})
	}
	if rest := from + count - boundaryAt - 1; rest > 0 {
		out = append(out, SwitchStep{Step: "onRecords", Module: "new", From: boundaryAt + 1, Count: rest})
	}
	return out
}
