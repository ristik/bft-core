package vrschema

import (
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
)

// script is a recorded sequence of steps against the VR model (and optionally the root model), with the observable state after each.
type script struct {
	vr    *VRModel
	root  *RootModel
	names map[Word]string
	steps []any
	b     *vb
	name  string
}

func newScript(b *vb, name string) *script {
	s := &script{vr: NewVRModel(fxModule), root: NewRootModel(5), names: map[Word]string{}, b: b, name: name}
	s.vr.Progress, s.vr.UCTime = 10_000, 1_700_000_000
	return s
}

func (s *script) id(n string) Word {
	r := w("result/" + n)
	s.names[r] = n
	return r
}

func (s *script) step(actor, op string, args map[string]any, err error, want string) {
	got := errName(err)
	if got != want {
		s.b.fail("%s: step %s %s: got %q want %q", s.name, actor, op, got, want)
	}
	s.steps = append(s.steps, map[string]any{"actor": actor, "op": op, "args": args, "error": got, "state": s.vr.Snap(s.names), "effects": s.vr.Effects,
		"root": map[string]any{"control": s.root.Control, "records": len(s.root.Out)}})
	s.vr.Effects = nil
}

// deliver imports the root's projected records into VR's log and applies n of them (n < 0: all).
func (s *script) deliver(n int) {
	recs := s.root.Out
	s.root.Out = nil
	s.vr.Import(recs...)
	if n < 0 {
		n = len(s.vr.Log)
	}
	var kinds []int
	for _, r := range recs {
		kinds = append(kinds, int(r.Kind))
	}
	s.vr.Apply(n)
	s.step("vr", "applyRootRecords", map[string]any{"imported": kinds, "apply": n}, nil, "")
}

func (s *script) record(rec LogRecord, apply int) {
	s.vr.Import(rec)
	s.vr.Apply(apply)
	s.step("vr", "applyRootRecords", map[string]any{"imported": []int{int(rec.Kind)}, "result": s.names[rec.ResultID], "recovered": rec.Recovered,
		"rejectedBitmap": rec.RejectedBitmap, "apply": apply}, nil, "")
}

func (s *script) done(op string) {
	s.b.add(s.name, op, map[string]any{"steps": len(s.steps)}, map[string]any{"trace": s.steps})
}

func (s *script) reserve(n string, bind []uint64, want string) Word {
	r := s.id(n)
	err := s.vr.Reserve(r, fxModule, false, bind, uint64(len(s.vr.Log)), MinEpochGap)
	s.step("vr", "reserve", map[string]any{"result": n, "bind": bind}, err, want)
	return r
}

func (s *script) publish(r Word) {
	_, err := s.vr.Publish(r)
	s.step("vr", "publish", map[string]any{"result": s.names[r]}, err, "")
}

func (s *script) schedule(kind uint8) uint64 {
	id, _ := s.vr.Queue(kind, 96)
	s.vr.Progress += DelayRounds
	s.vr.UCTime += DelaySeconds
	err := s.vr.Execute(id, fxModule, StepOK)
	s.step("vr", "queue+execute", map[string]any{"kind": kind, "id": id}, err, "")
	return id
}

func genStateMachines() ([]Vector, error) {
	b := &vb{}
	genOutputTable(b)
	genS2a(b)
	genChangeLifecycle(b)
	genFold(b)
	genBackoff(b)
	genViews(b)
	genMisc(b)
	genReviewBoundaries(b)
	return b.out, b.err
}

// ---- section 3.4.2 table, exhaustively ----

func genOutputTable(b *vb) {
	states := []string{"Reserved", "Published", "Invalidated", "Rejected", "Closed", "Acknowledged", "Recovered", "Unknown"}
	events := []string{"invalidateBySource", "invalidateByOther", "invalidateReason0", "publish", "OutputRejected", "SessionClosed", "Ack", "RecoveryAck",
		"BoundaryWithPair", "BoundaryWithoutPair"}
	for _, st := range states {
		for _, ev := range events {
			s := newScript(b, fmt.Sprintf("table %s x %s", st, ev))
			r := w("result/R")
			s.names[r] = "R"
			if st != "Unknown" {
				s.vr.Reserve(r, fxModule, false, nil, 0, MinEpochGap)
			}
			switch st {
			case "Published", "Invalidated", "Rejected", "Closed", "Acknowledged", "Recovered":
				s.vr.Publish(r)
			}
			switch st {
			case "Invalidated":
				s.vr.Invalidate(r, fxModule, InvalidWithdrawn)
			case "Rejected", "Closed":
				s.vr.Import(LogRecord{Kind: RecOutputRejected, ResultID: r})
				s.vr.Apply(1)
				if st == "Closed" {
					s.vr.Import(LogRecord{Kind: RecSessionClosed, ResultID: r})
					s.vr.Apply(1)
				}
			case "Acknowledged", "Recovered":
				rec := st == "Recovered"
				k := RecAck
				if rec {
					k = RecRecoveryAck
				}
				s.vr.Import(LogRecord{Kind: k, ResultID: r}, LogRecord{Kind: RecBoundary, ResultID: r, Recovered: rec})
				s.vr.Apply(2)
			}
			s.vr.Effects = nil
			s.step("setup", "state", map[string]any{"state": st}, nil, "")
			if ev == "BoundaryWithPair" {
				if st != "Published" && st != "Invalidated" {
					continue // not reachable: the Ack before it is an anomaly or a no-op
				}
				s.vr.Import(LogRecord{Kind: RecAck, ResultID: r})
				s.vr.Apply(1)
				s.step("vr", "applyRootRecords", map[string]any{"imported": []int{int(RecAck)}}, nil, "")
			}
			var err error
			var ret any
			switch ev {
			case "invalidateBySource":
				ret, err = s.vr.Invalidate(r, fxModule, InvalidWithdrawn)
			case "invalidateByOther":
				ret, err = s.vr.Invalidate(r, fxOther, InvalidWithdrawn)
			case "invalidateReason0":
				ret, err = s.vr.Invalidate(r, fxModule, 0)
			case "publish":
				ret, err = s.vr.Publish(r)
			case "OutputRejected", "SessionClosed", "Ack", "RecoveryAck":
				k := map[string]uint8{"OutputRejected": RecOutputRejected, "SessionClosed": RecSessionClosed, "Ack": RecAck, "RecoveryAck": RecRecoveryAck}[ev]
				s.vr.Import(LogRecord{Kind: k, ResultID: r})
				s.vr.Apply(1)
			case "BoundaryWithPair", "BoundaryWithoutPair":
				s.vr.Import(LogRecord{Kind: RecBoundary, ResultID: r})
				s.vr.Apply(1)
			}
			want := errName(err)
			if ev == "invalidateReason0" && (err != nil || ret != false) {
				s.b.fail("invalidate with reason 0 must be a non-reverting no-op in %s", st)
			}
			s.step("event", ev, map[string]any{"return": ret}, err, want)
			s.done("output.table")
		}
	}
}

// ---- S2a and record replay ----

func genS2a(b *vb) {
	for _, variant := range []string{"Published", "Invalidated", "Rejected"} {
		s := newScript(b, "S2a-1 lapse and cooldown keep R "+variant)
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.publish(r)
		s.step("root", "prepare", map[string]any{"result": "R", "round": 100}, s.root.Prepare(r, 100), "")
		if variant == "Invalidated" {
			_, err := s.vr.Invalidate(r, fxModule, InvalidLost)
			s.step("vr", "invalidate", map[string]any{"result": "R", "reason": InvalidLost}, err, "")
		}
		if variant == "Rejected" {
			s.vr.Import(LogRecord{Kind: RecOutputRejected, ResultID: r})
			s.vr.Apply(1)
			s.step("vr", "applyRootRecords", map[string]any{"imported": []int{int(RecOutputRejected)}, "note": "a split batch: SessionClosed not yet imported"}, nil, "")
		}
		s.step("root", "freeze", map[string]any{"round": 125}, s.root.Freeze(125, true), "PrepareLapsed")
		k, ok, _ := PlannableAttempt(s.root.Control, 148)
		s.step("root", "plannable", map[string]any{"round": 148, "attempt": k, "defined": ok}, nil, "")
		k, ok, _ = PlannableAttempt(s.root.Control, 149)
		s.step("root", "plannable", map[string]any{"round": 149, "attempt": k, "defined": ok}, nil, "")
		err := s.vr.Reserve(s.id("R2"), fxModule, false, nil, uint64(len(s.vr.Log)), MinEpochGap)
		s.step("vr", "reserve", map[string]any{"result": "R2", "note": "no replacement reservation while R is open"}, err, "OutputOpen")
		s.done("s2a.lapse")
	}
	{
		s := newScript(b, "S2a-2 RejectResult first refuses a later Freeze before the closure is imported")
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.publish(r)
		due, ok := RejectDue(OutPublished, 10_000+Lifetime, 10_000+Lifetime, false)
		s.step("root", "rejectDue", map[string]any{"progress": 10_000 + Lifetime, "expiresAt": 10_000 + Lifetime, "reason": due, "due": ok}, nil, "")
		s.step("root", "reject", map[string]any{"result": "R", "round": 200}, s.root.Reject(r, 200, ok), "")
		s.step("root", "prepare", map[string]any{"result": "R", "round": 201}, s.root.Prepare(r, 201), "Resolved")
		s.step("root", "reject", map[string]any{"result": "R", "round": 202, "note": "a repeated RejectResult is refused"}, s.root.Reject(r, 202, true), "Resolved")
		s.deliver(1)
		s.deliver(-1)
		s.done("s2a.rejectFirst")
	}
	{
		s := newScript(b, "S2a-3a Prepare first, lapse, rejection admissible only after cooldown and due")
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.publish(r)
		s.step("root", "prepare", map[string]any{"result": "R", "round": 100}, s.root.Prepare(r, 100), "")
		s.step("root", "reject", map[string]any{"round": 120}, s.root.Reject(r, 120, true), "NotQuiet")
		s.step("root", "reject", map[string]any{"round": 148}, s.root.Reject(r, 148, true), "NotQuiet")
		s.step("root", "reject", map[string]any{"round": 149, "due": false}, s.root.Reject(r, 149, false), "NotDue")
		s.step("root", "reject", map[string]any{"round": 150, "due": true}, s.root.Reject(r, 150, true), "")
		s.deliver(-1)
		s.done("s2a.prepareFirst")
	}
	{
		s := newScript(b, "S2a-3b Prepare and Freeze first, success with Active and Rejected changes")
		c1 := s.schedule(KindCommitteeLimits)
		c2 := s.schedule(KindScheduleActivation)
		r := s.reserve("R", []uint64{c1, c2}, "")
		s.publish(r)
		s.step("root", "prepare", map[string]any{"round": 100}, s.root.Prepare(r, 100), "")
		s.step("root", "freeze", map[string]any{"round": 124}, s.root.Freeze(124, true), "")
		s.step("root", "commitH", map[string]any{"rejectedBitmap": 2}, s.root.Commit(false, 0b10), "")
		recs := s.root.Out
		s.root.Out = nil
		s.record(recs[0], 1)
		err := s.vr.Reserve(s.id("R2"), fxModule, false, nil, uint64(len(s.vr.Log)), MinEpochGap)
		s.step("vr", "reserve", map[string]any{"result": "R2", "note": "split Ack/Boundary import: R stays open with its pair pending"}, err, "OutputOpen")
		s.record(recs[1], 1)
		s.step("vr", "redeliver", map[string]any{"index": 1, "replay": s.vr.Redeliver(1)}, nil, "")
		s.record(LogRecord{Kind: RecBoundary, ResultID: r}, 1)
		s.done("s2a.success")
	}
	{
		s := newScript(b, "S2a abort of a retained primary closes R; a recovery abort does not")
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.publish(r)
		s.step("root", "prepare", map[string]any{"round": 100}, s.root.Prepare(r, 100), "")
		s.step("root", "freeze", map[string]any{"round": 110}, s.root.Freeze(110, true), "")
		s.root.Abort(false)
		s.step("root", "abort", map[string]any{"recovery": false}, nil, "")
		s.deliver(-1)
		s2 := s.reserve("R2", []uint64{c}, "")
		s.publish(s2)
		s.step("root", "prepare", map[string]any{"round": 200}, s.root.Prepare(s2, 200), "")
		s.step("root", "freeze", map[string]any{"round": 210}, s.root.Freeze(210, true), "")
		s.root.Abort(true)
		s.step("root", "abort", map[string]any{"recovery": true, "records": len(s.root.Out)}, nil, "")
		s.step("root", "abortBeforeFreeze", map[string]any{"note": "a pre-Freeze abort projects nothing either"}, nil, "")
		s.done("s2a.abort")
	}
	{
		s := newScript(b, "cursor gate: an imported but unapplied Ack blocks module and native reservations")
		r := s.reserve("R", nil, "")
		s.publish(r)
		s.vr.Import(LogRecord{Kind: RecAck, ResultID: r}, LogRecord{Kind: RecBoundary, ResultID: r})
		s.step("vr", "import", map[string]any{"imported": []int{int(RecAck), int(RecBoundary)}, "apply": 0}, nil, "")
		s.vr.Apply(2)
		s.step("vr", "applyRootRecords", map[string]any{"apply": 2}, nil, "")
		s.vr.Import(LogRecord{Kind: RecSessionClosed, ResultID: w("result/foreign")})
		s.step("vr", "import", map[string]any{"imported": []int{int(RecSessionClosed)}, "apply": 0}, nil, "")
		err := s.vr.Reserve(s.id("R2"), fxModule, false, nil, uint64(len(s.vr.Log)), MinEpochGap)
		s.step("vr", "reserve", map[string]any{"result": "R2"}, err, "CursorBehind")
		s.vr.Health = HealthFaulted
		err = s.vr.Reserve(s.id("N"), [20]byte{}, true, nil, uint64(len(s.vr.Log)), MinEpochGap)
		s.step("vr", "reserveNative", map[string]any{"result": "N", "health": "Faulted"}, err, "CursorBehind")
		s.done("s2a.cursorGate")
	}
	{
		s := newScript(b, "Inconsistent is absorbing and still completes a committed Ack and Boundary")
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.publish(r)
		s.record(LogRecord{Kind: RecBoundary, ResultID: r}, 1)
		s.record(LogRecord{Kind: RecAck, ResultID: r}, 1)
		s.record(LogRecord{Kind: RecBoundary, ResultID: r}, 1)
		err := s.vr.Reserve(s.id("R2"), fxModule, false, nil, uint64(len(s.vr.Log)), MinEpochGap)
		s.step("vr", "reserve", map[string]any{"result": "R2"}, err, "Inconsistent")
		_, err = s.vr.Publish(r)
		s.step("vr", "publish", map[string]any{"result": "R"}, err, "Inconsistent")
		s.done("s2a.inconsistent")
	}
}

// ---- change lifecycle and binding selection ----

func genChangeLifecycle(b *vb) {
	{
		s := newScript(b, "delays, cancel and binding races")
		s.vr.Progress, s.vr.UCTime = 0, 0
		id, err := s.vr.Queue(KindCommitteeLimits, 96)
		s.step("vr", "queue", map[string]any{"kind": KindCommitteeLimits, "progress": 0, "ucTime": 0, "id": id}, err, "")
		for _, pt := range [][2]uint64{{1999, 3600}, {2000, 3599}, {2000, 3600}} {
			s.vr.Progress, s.vr.UCTime = pt[0], pt[1]
			err := s.vr.Execute(id, fxModule, StepOK)
			want := "DelayNotElapsed"
			if pt == [2]uint64{2000, 3600} {
				want = ""
			}
			s.step("vr", "execute", map[string]any{"id": id, "progress": pt[0], "ucTime": pt[1]}, err, want)
		}
		r := s.reserve("R", []uint64{id}, "")
		s.step("vr", "cancel", map[string]any{"id": id, "note": "never once Bound"}, s.vr.Cancel(id), "NotCancellable")
		s.publish(r)
		s.record(LogRecord{Kind: RecOutputRejected, ResultID: r}, 1)
		s.record(LogRecord{Kind: RecSessionClosed, ResultID: r}, 1)
		s.step("vr", "cancel", map[string]any{"id": id, "note": "back to Scheduled after closure: cancellable"}, s.vr.Cancel(id), "")
		s.step("vr", "cancel", map[string]any{"id": id}, s.vr.Cancel(id), "NotCancellable")
		id2, _ := s.vr.Queue(KindForceRemove, 32)
		s.step("vr", "cancel", map[string]any{"id": id2, "note": "Queued is cancellable"}, s.vr.Cancel(id2), "")
		s.done("change.lifecycle")
	}
	{
		s := newScript(b, "ModuleAction executes into the active module only")
		execute := func(id uint64, target [20]byte, step StepOutcome, name, want string) {
			s.step("vr", "execute", map[string]any{"id": id, "case": name, "step": step}, s.vr.Execute(id, target, step), want)
		}
		queue := func() uint64 {
			id, _ := s.vr.Queue(KindModuleAction, 64)
			s.vr.Progress += DelayRounds
			s.vr.UCTime += DelaySeconds
			return id
		}
		execute(queue(), fxModule, StepOK, "active, succeeds", "")
		short := queue()
		execute(short, fxModule, StepBudgetShort, "active, too little gas: BudgetShort, still Queued, health unchanged", "BudgetShort")
		if s.vr.Health != HealthHealthy || s.vr.Changes[short].State != ChQueued {
			b.fail("BudgetShort changed health or state")
		}
		execute(short, fxModule, StepOK, "the same action retried with enough gas", "")
		failed := queue()
		execute(failed, fxModule, StepFault, "active, fully funded onGovernance fails: ActionFailed and Faulted", "")
		if s.vr.Health != HealthFaulted || s.vr.Changes[failed].RejectReason != RejectActionFailed {
			b.fail("a funded onGovernance failure must reject the action and fault the module")
		}
		execute(queue(), fxOther, StepOK, "not the active module: NotActive, no call, no fault", "")
		s.done("change.lifecycle")
	}
	{
		s := newScript(b, "thirty-two pending changes")
		for i := 0; i < MaxPendingChanges; i++ {
			s.vr.Queue(KindForceRemove, 32)
		}
		_, err := s.vr.Queue(KindForceRemove, 32)
		s.step("vr", "queue", map[string]any{"pending": MaxPendingChanges}, err, "TooManyPending")
		s.done("change.lifecycle")
	}
	{
		s := newScript(b, "a closed output releases its changes once and they bind again")
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.publish(r)
		s.record(LogRecord{Kind: RecOutputRejected, ResultID: r}, 1)
		s.record(LogRecord{Kind: RecSessionClosed, ResultID: r}, 1)
		s.record(LogRecord{Kind: RecSessionClosed, ResultID: r}, 1)
		r2 := s.reserve("R2", []uint64{c}, "")
		s.publish(r2)
		s.record(LogRecord{Kind: RecAck, ResultID: r2}, 1)
		s.record(LogRecord{Kind: RecBoundary, ResultID: r2}, 1)
		s.done("change.lifecycle")
	}
	sel := []struct {
		name  string
		cands []BindCandidate
	}{
		{"count: 17 Scheduled, 16 bound", func() []BindCandidate {
			var cs []BindCandidate
			for i := 1; i <= 17; i++ {
				cs = append(cs, BindCandidate{ID: uint64(i), Kind: KindScheduleActivation, PayloadSize: 256})
			}
			return cs
		}()},
		{"bytes: 64 KiB total", []BindCandidate{{1, KindAddPartition, 16384, "", false}, {2, KindAddPartition, 16384, "", false}, {3, KindAddPartition, 16384, "", false},
			{4, KindAddPartition, 16000, "", false}, {5, KindAddPartition, 1000, "", false}, {6, KindCommitteeLimits, 96, "", false}}},
		{"root-side: 9 root-side, 8 bound", func() []BindCandidate {
			var cs []BindCandidate
			for i := 1; i <= 9; i++ {
				cs = append(cs, BindCandidate{ID: uint64(i), Kind: KindUpdatePartition, PayloadSize: 512})
			}
			return append(cs, BindCandidate{ID: 10, Kind: KindFeeParams, PayloadSize: 96})
		}()},
		{"singletons: a second SetModule and FeeParams defer", []BindCandidate{{1, KindSetModule, 160, "kind:1", false}, {2, KindFeeParams, 96, "kind:5", false}, {3, KindSetModule, 160, "kind:1", false},
			{4, KindFeeParams, 96, "kind:5", false}, {5, KindSetGovernor, 64, "kind:3", false}}},
		{"ForceRemove: only performed removals bind", []BindCandidate{{1, KindForceRemove, 32, "", false}, {2, KindForceRemove, 32, "", true}, {3, KindModuleAction, 64, "", false}}},
	}
	for _, c := range sel {
		bound, deferred := SelectBinding(c.cands)
		var in []any
		for _, x := range c.cands {
			in = append(in, map[string]any{"id": x.ID, "kind": x.Kind, "payloadSize": x.PayloadSize, "scope": x.Scope, "performed": x.Performed})
		}
		b.add(c.name, "change.binding", map[string]any{"scheduled": in}, map[string]any{"bound": bound, "deferred": deferred})
	}
}

// ---- the fold ----

func genFold(b *vb) {
	evm := fxPDR(2, 8, 5, 40, 4)
	agg := fxPDR(7, 3, 2, 0, 3)
	ctl := fxPDR(1, 1, 0, 60, 3)
	base := FoldInput{Network: fxRootNetwork, SuccessorRootEpoch: 6, ReservedPartitions: []uint32{0xFFFFFFFF, 0xFFFFFFFE, 2, 1}, PartitionCeiling: PartitionCeiling,
		Installed: map[ShardKey]*types.PartitionDescriptionRecord{keyOf(evm): evm, keyOf(agg): agg, keyOf(ctl): ctl},
		Schedule: []Activation{{RuleID: RuleID("latched-rule"), ReleaseDigest: w("r0"), RootEpoch: 4, State: ActLatched, ChangeID: 1},
			{RuleID: RuleID("scheduled-rule"), ReleaseDigest: w("r1"), RootEpoch: 10, NotBeforeUcTime: 5000, State: ActActive, ChangeID: 2}}}
	replace := func(id uint64, expected Word, base int) RegistryChange {
		succ := fxPDR(7, 3, 3, base, 3)
		return RegistryChange{ID: id, Kind: uint64(KindReplaceAggregator), Payload: mustChange(KindReplaceAggregator, uint64(7), succ.ShardID.Bytes(), expected, mustCBOR(succ), fxChangePoPs(id, succ, base))}
	}
	update := func(id uint64, part uint32, cur *types.PartitionDescriptionRecord, f func(*types.PartitionDescriptionRecord)) RegistryChange {
		succ := fxPDR(part, uint32(cur.PartitionTypeID), cur.Epoch+1, 0, 0)
		succ.Validators = cur.Validators
		succ.T2Timeout = cur.T2Timeout + 500_000_000
		if f != nil {
			f(succ)
		}
		return RegistryChange{ID: id, Kind: uint64(KindUpdatePartition), Payload: mustChange(KindUpdatePartition, uint64(part), succ.ShardID.Bytes(), pdrHash(cur), mustCBOR(succ))}
	}
	add := func(id uint64, part, typ uint32, popID uint64) RegistryChange {
		p := fxPDR(part, typ, 0, 20, 2)
		return RegistryChange{ID: id, Kind: uint64(KindAddPartition), Payload: mustChange(KindAddPartition, mustCBOR(p), fxChangePoPs(popID, p, 20))}
	}
	sched := func(id uint64, rule string, e uint64) RegistryChange {
		return RegistryChange{ID: id, Kind: uint64(KindScheduleActivation), Payload: mustChange(KindScheduleActivation, RuleID(rule), w("rel"), e, uint64(9000), "")}
	}
	limits := RegistryChange{ID: 1, Kind: uint64(KindCommitteeLimits), Payload: mustChange(KindCommitteeLimits, uint64(4), uint64(5), uint64(7))}
	addP := func(id uint64, part uint32, popID uint64, params map[string]string) RegistryChange {
		p := fxPDR(part, 3, 0, 20, 2)
		p.PartitionParams = params
		return RegistryChange{ID: id, Kind: uint64(KindAddPartition), Payload: mustChange(KindAddPartition, mustCBOR(p), fxChangePoPs(popID, p, 20))}
	}
	risc0 := map[string]string{"proof_type": "risc0"}
	badUpdate := func(id uint64) RegistryChange {
		return RegistryChange{ID: id, Kind: uint64(KindUpdatePartition), Payload: mustChange(KindUpdatePartition, uint64(7), agg.ShardID.Bytes(), pdrHash(agg), []byte{0x80})}
	}
	badPoPsAdd := func(id uint64) RegistryChange {
		return RegistryChange{ID: id, Kind: uint64(KindAddPartition), Payload: mustChange(KindAddPartition, mustCBOR(fxPDR(9, 3, 0, 20, 2)), []byte{0x83, 1, 2, 3})}
	}
	badPoPsReplace := func(id uint64) RegistryChange {
		succ := fxPDR(7, 3, 3, 3, 3)
		return RegistryChange{ID: id, Kind: uint64(KindReplaceAggregator), Payload: mustChange(KindReplaceAggregator, uint64(7), succ.ShardID.Bytes(), pdrHash(agg), mustCBOR(succ), []byte{0x83, 1, 2, 3})}
	}
	cases := []struct {
		name string
		in   func(FoldInput) FoldInput
		rc   []RegistryChange
		want []string // independent expectations, written by hand from the schema text
	}{
		{"replace accepted, then update of the same shard conflicts", nil, []RegistryChange{limits, replace(2, pdrHash(agg), 3), update(3, 7, agg, nil)}, []string{"Accepted", "Accepted", "Conflict"}},
		{"replace with a stale expected hash conflicts", nil, []RegistryChange{replace(2, w("stale"), 3)}, []string{"Conflict"}},
		{"replace with PoPs for another change id", nil, func() []RegistryChange {
			c := replace(2, pdrHash(agg), 3)
			c.ID = 4
			return []RegistryChange{c}
		}(), []string{"BadPoP"}},
		{"update with changed validators is invalid", nil, []RegistryChange{update(2, 7, agg, func(p *types.PartitionDescriptionRecord) { p.Validators = fxPDR(7, 3, 3, 9, 3).Validators })}, []string{"Invalid"}},
		{"update of the EVM partition is invalid", nil, []RegistryChange{update(2, 2, evm, nil)}, []string{"Invalid"}},
		{"update with a changed type id length is invalid", nil, []RegistryChange{update(2, 7, agg, func(p *types.PartitionDescriptionRecord) { p.TypeIDLen = 16 })}, []string{"Invalid"}},
		{"two additions of partition 9: accepted, conflict", nil, []RegistryChange{add(2, 9, 3, 2), add(3, 9, 3, 3)}, []string{"Accepted", "Conflict"}},
		{"identical payload twice: accepted, duplicate", nil, []RegistryChange{add(2, 9, 3, 2), func() RegistryChange { c := add(3, 9, 3, 2); return c }()}, []string{"Accepted", "Duplicate"}},
		{"addition of a reserved, an installed and an EVM-typed partition", nil, []RegistryChange{add(2, 1, 3, 2), add(3, 7, 3, 3), add(4, 11, 8, 4)}, []string{"Invalid", "Invalid", "Invalid"}},
		{"partition ceiling", func(in FoldInput) FoldInput { in.PartitionCeiling = 4; return in }, []RegistryChange{add(2, 9, 3, 2), add(3, 10, 3, 3)}, []string{"Accepted", "Ceiling"}},
		{"malformed PDR bytes", nil, []RegistryChange{{ID: 2, Kind: uint64(KindAddPartition), Payload: mustChange(KindAddPartition, []byte{0x83, 1, 2, 3}, []byte{0x80})}}, []string{"Malformed"}},
		{"schedule: accepted, past cutoff, latched", nil, []RegistryChange{sched(2, "new-rule", 8), sched(3, "late-rule", 7), sched(4, "latched-rule", 20)}, []string{"Accepted", "PastCutoff", "Latched"}},
		{"schedule postponement: later accepted", nil, []RegistryChange{sched(2, "scheduled-rule", 12)}, []string{"Accepted"}},
		{"schedule postponement: earlier refused", nil, []RegistryChange{sched(2, "scheduled-rule", 9)}, []string{"Earlier"}},
		{"schedule postponement: equal E conflicts", nil, []RegistryChange{sched(2, "scheduled-rule", 10)}, []string{"Conflict"}},
		{"schedule postponement past the current cutoff", func(in FoldInput) FoldInput { in.SuccessorRootEpoch = 9; return in }, []RegistryChange{sched(2, "scheduled-rule", 14)}, []string{"PastCutoff"}},
		{"two schedules of one rule in one list", nil, []RegistryChange{sched(2, "new-rule", 8), sched(3, "new-rule", 9)}, []string{"Accepted", "Conflict"}},
		{"a rejected first schedule still claims its rule", nil, []RegistryChange{sched(2, "new-rule", 7), sched(3, "new-rule", 12)}, []string{"PastCutoff", "Conflict"}},
		{"an invalid proof configuration consumes no partition slot", func(in FoldInput) FoldInput { in.PartitionCeiling = 4; return in },
			[]RegistryChange{addP(2, 9, 2, risc0), add(3, 10, 3, 3)}, []string{"Invalid", "Accepted"}},
		{"a malformed embedded PDR claims no scope: malformed, then valid update", nil, []RegistryChange{badUpdate(2), update(3, 7, agg, nil)}, []string{"Malformed", "Accepted"}},
		{"a malformed embedded PDR after a valid update of its shard is Malformed", nil, []RegistryChange{update(2, 7, agg, nil), badUpdate(3)}, []string{"Accepted", "Malformed"}},
		{"a malformed PoP list claims no partition: malformed, then valid addition", nil, []RegistryChange{badPoPsAdd(2), add(3, 9, 3, 3)}, []string{"Malformed", "Accepted"}},
		{"a malformed PoP list after a valid addition of its partition is Malformed", nil, []RegistryChange{add(2, 9, 3, 2), badPoPsAdd(3)}, []string{"Accepted", "Malformed"}},
		{"a null PoP list is Malformed", nil, []RegistryChange{{ID: 2, Kind: uint64(KindAddPartition), Payload: mustChange(KindAddPartition, mustCBOR(fxPDR(9, 3, 0, 20, 2)), []byte{0xf6})}}, []string{"Malformed"}},
		{"an empty PoP list for two validators is BadPoP", nil, []RegistryChange{{ID: 2, Kind: uint64(KindAddPartition), Payload: mustChange(KindAddPartition, mustCBOR(fxPDR(9, 3, 0, 20, 2)), []byte{0x80})}}, []string{"BadPoP"}},
		{"a replace with a malformed PoP list claims no shard", nil, []RegistryChange{badPoPsReplace(2), replace(3, pdrHash(agg), 3)}, []string{"Malformed", "Accepted"}},
		{"an invalid proof configuration, then the identical payload", nil, []RegistryChange{addP(2, 9, 2, risc0), addP(3, 9, 2, risc0)}, []string{"Invalid", "Conflict"}},
		{"sp1 without vkey_path is invalid", nil, []RegistryChange{addP(2, 9, 2, map[string]string{"proof_type": "sp1", "chain_id": "3"})}, []string{"Invalid"}},
		{"protocol-valid sp1 is accepted whatever the local build supports", nil,
			[]RegistryChange{addP(2, 9, 2, map[string]string{"proof_type": "sp1", "vkey_path": "/keys/sp1.vk", "chain_id": "3"})}, []string{"Accepted"}},
		{"an update of a partition added earlier in the list is invalid (FD-29)", nil,
			[]RegistryChange{add(2, 9, 3, 2), update(3, 9, fxPDR(9, 3, 0, 20, 2), nil)}, []string{"Accepted", "Invalid"}},
		{"a replace of a partition added earlier in the list is invalid (FD-29)", nil,
			[]RegistryChange{add(2, 9, 3, 2), func() RegistryChange {
				succ := fxPDR(9, 3, 1, 30, 2)
				return RegistryChange{ID: 3, Kind: uint64(KindReplaceAggregator), Payload: mustChange(KindReplaceAggregator, uint64(9), succ.ShardID.Bytes(),
					pdrHash(fxPDR(9, 3, 0, 20, 2)), mustCBOR(succ), fxChangePoPs(3, succ, 30))}
			}()}, []string{"Accepted", "Invalid"}},
		{"update to an unknown proof type is invalid and leaves the shard installed", nil,
			[]RegistryChange{update(2, 7, agg, func(p *types.PartitionDescriptionRecord) {
				p.PartitionParams = map[string]string{"proof_type": "zk_magic"}
			})}, []string{"Invalid"}},
	}
	for _, c := range cases {
		in := base
		if c.in != nil {
			in = c.in(base)
		}
		got, err := FoldVerdicts(in, c.rc)
		if err != nil {
			b.fail("fold %s: %v", c.name, err)
			continue
		}
		names := make([]string, len(got))
		for i, v := range got {
			names[i] = VerdictNames[v]
		}
		if fmt.Sprint(names) != fmt.Sprint(c.want) {
			b.fail("fold %s: reference gives %v, the schema text gives %v", c.name, names, c.want)
		}
		b.add(c.name, "fold.verdicts", foldJSON(in, c.rc), map[string]any{"verdicts": ints8(got), "names": names})
	}
	_, err := FoldVerdicts(base, []RegistryChange{{ID: 1, Kind: uint64(KindModuleAction), Payload: limits.Payload}})
	b.add("a ModuleAction in the list is not bindable", "fold.verdicts", map[string]any{"kinds": []int{2}}, map[string]any{"error": errName(err)})
	// the acknowledgement gate is not a fold input
	rc := []RegistryChange{replace(2, pdrHash(agg), 3)}
	v, _ := FoldVerdicts(base, rc)
	for _, st := range []struct {
		stage string
		acked bool
	}{{"intent", false}, {"readiness", false}, {"freeze (ack arrived between readiness and Freeze)", true}, {"freeze (not acknowledged)", false}} {
		_, ok := AckGate(rc, v, map[ShardKey]bool{keyOf(agg): st.acked}, true)
		b.add("ack gate at "+st.stage, "fold.ackGate", map[string]any{"stage": st.stage, "shardAcked": st.acked, "changes": rcJSON(rc)},
			map[string]any{"verdicts": ints8(v), "gate": ok})
	}
	_, ok := AckGate(rc, v, map[ShardKey]bool{keyOf(agg): true}, false)
	b.add("ack gate EVM shard unacknowledged", "fold.ackGate", map[string]any{"evmAcked": false}, map[string]any{"gate": ok})
}

func foldJSON(in FoldInput, rc []RegistryChange) map[string]any {
	keys := make([]ShardKey, 0, len(in.Installed))
	for k := range in.Installed {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Partition < keys[j].Partition })
	var inst []any
	for _, k := range keys {
		inst = append(inst, map[string]any{"partition": k.Partition, "shard": Hexb([]byte(k.Shard)), "pdr": Hexb(mustCBOR(in.Installed[k])), "pdrHash": Hexw(pdrHash(in.Installed[k]))})
	}
	var sch []any
	for _, a := range in.Schedule {
		sch = append(sch, map[string]any{"ruleId": Hexw(a.RuleID), "rootEpoch": a.RootEpoch, "notBeforeUcTime": a.NotBeforeUcTime, "state": a.State})
	}
	return map[string]any{"network": in.Network, "successorRootEpoch": in.SuccessorRootEpoch, "installed": inst, "reserved": in.ReservedPartitions,
		"ceiling": in.PartitionCeiling, "schedule": sch, "registry": hexa(ValidatorRegistry), "changes": rcJSON(rc)}
}

// ---- backoff ----

func genBackoff(b *vb) {
	intent := w("intent-1")
	intent2 := w("intent-2")
	type blk = Block
	run := func(name string, start HandoffBackoff, blocks []blk, wantErr map[int]string) {
		st := start
		var trace []any
		for i, bl := range blocks {
			next, err := ApplyBlock(st, bl)
			if errName(err) != wantErr[i] {
				b.fail("backoff %s block %d: %v", name, i, err)
			}
			if err == nil {
				st = next
			}
			trace = append(trace, map[string]any{"block": bl, "error": errName(err), "state": st})
		}
		b.add(name, "backoff.trace", map[string]any{"start": start}, map[string]any{"trace": trace})
	}
	hv := func(i Word, v uint64) BackoffEvent { return BackoffEvent{Op: "HV", Intent: i[:], View: v} }
	g := GenesisBackoff(5, 4)
	b.add("genesis", "backoff.genesis", map[string]any{"epoch": 5, "n": 4}, map[string]any{"state": g})
	run("views, prepare, freeze at p+24", g, []blk{
		{Epoch: 5, Round: 10, Events: []BackoffEvent{hv(intent, 1)}, CommitteeSize: 4},
		{Epoch: 5, Round: 11, Events: []BackoffEvent{hv(intent, 2)}, CommitteeSize: 4},
		{Epoch: 5, Round: 12, Events: []BackoffEvent{hv(intent, 2)}, CommitteeSize: 4},
		{Epoch: 5, Round: 20, Events: []BackoffEvent{{Op: "PR", Epoch: 5, Attempt: 0}}, ControlAfter: ControlState{Kind: CtlPrepared, OrderedRound: 20}, CommitteeSize: 4},
		{Epoch: 5, Round: 44, Events: []BackoffEvent{{Op: "FZ", Epoch: 5, Attempt: 0, View: 2}}, ControlAfter: ControlState{Kind: CtlFrozen, OrderedRound: 20}, CommitteeSize: 4},
		{Epoch: 6, Round: 60, ControlAfter: ControlState{Kind: CtlIdle}, CommitteeSize: 5},
	}, map[int]string{2: "vrschema: control does not match the backoff state: HandoffView 2 after 2"})
	run("prepared lapse keeps the level; cooldown then abort is one identity", HandoffBackoff{Level: 5, Epoch: 5, N: 4, Intent: make([]byte, 32)}, []blk{
		{Epoch: 5, Round: 100, Events: []BackoffEvent{{Op: "PR", Epoch: 5}}, ControlAfter: ControlState{Kind: CtlPrepared, OrderedRound: 100}, CommitteeSize: 4},
		{Epoch: 5, Round: 148, ControlAfter: ControlState{Kind: CtlPrepared, OrderedRound: 100}, CommitteeSize: 4},
		{Epoch: 5, Round: 149, ControlAfter: ControlState{Kind: CtlPrepared, OrderedRound: 100}, CommitteeSize: 4},
		{Epoch: 5, Round: 150, ControlAfter: ControlState{Kind: CtlAborted, Attempt: 0}, CommitteeSize: 4},
	}, nil)
	run("cooldown and abort in one block open once", HandoffBackoff{Level: 1, Epoch: 5, N: 4, Intent: make([]byte, 32)}, []blk{
		{Epoch: 5, Round: 100, Events: []BackoffEvent{hv(intent, 1), {Op: "PR", Epoch: 5}}, ControlAfter: ControlState{Kind: CtlPrepared, OrderedRound: 100}, CommitteeSize: 4},
		{Epoch: 5, Round: 160, ControlAfter: ControlState{Kind: CtlAborted, Attempt: 0}, CommitteeSize: 4},
	}, nil)
	run("attempt 0 of a new epoch is a new identity", HandoffBackoff{Level: 2, Epoch: 5, Attempt: 3, N: 4, Intent: intent[:], LastView: 4}, []blk{
		{Epoch: 6, Round: 500, ControlAfter: ControlState{Kind: CtlIdle}, CommitteeSize: 7},
	}, nil)
	run("expiry into a different result id: 2 -> 4 -> 5 -> 5 -> 4", HandoffBackoff{Level: 2, Epoch: 5, N: 4, Intent: make([]byte, 32)}, []blk{
		{Epoch: 5, Round: 10, Events: []BackoffEvent{hv(intent, 1)}, CommitteeSize: 4},
		{Epoch: 5, Round: 11, Events: []BackoffEvent{hv(intent, 2)}, CommitteeSize: 4},
		{Epoch: 5, Round: 12, Events: []BackoffEvent{hv(intent, 3)}, CommitteeSize: 4},
		{Epoch: 5, Round: 13, Events: []BackoffEvent{hv(intent, 4)}, CommitteeSize: 4},
		{Epoch: 5, Round: 14, Events: []BackoffEvent{hv(intent, 5)}, CommitteeSize: 4},
		{Epoch: 5, Round: 20, Events: []BackoffEvent{hv(intent2, 1)}, ControlAfter: ControlState{Kind: CtlAborted, Attempt: 0}, CommitteeSize: 4},
		{Epoch: 5, Round: 20, ControlAfter: ControlState{Kind: CtlAborted, Attempt: 0}, CommitteeSize: 4},
		{Epoch: 5, Round: 31, Events: []BackoffEvent{hv(intent2, 1)}, ControlAfter: ControlState{Kind: CtlAborted, Attempt: 1}, CommitteeSize: 4},
		{Epoch: 5, Round: 40, Events: []BackoffEvent{{Op: "PR", Epoch: 5, Attempt: 2}}, ControlAfter: ControlState{Kind: CtlPrepared, Attempt: 2, OrderedRound: 40}, CommitteeSize: 4},
		{Epoch: 5, Round: 89, ControlAfter: ControlState{Kind: CtlPrepared, Attempt: 2, OrderedRound: 40}, CommitteeSize: 4},
		{Epoch: 5, Round: 95, Events: []BackoffEvent{{Op: "PR", Epoch: 5, Attempt: 3}}, ControlAfter: ControlState{Kind: CtlPrepared, Attempt: 3, OrderedRound: 95}, CommitteeSize: 4},
		{Epoch: 5, Round: 100, Events: []BackoffEvent{{Op: "FZ", Epoch: 5, Attempt: 3, View: 0}}, ControlAfter: ControlState{Kind: CtlFrozen, Attempt: 3, OrderedRound: 95}, CommitteeSize: 4},
	}, map[int]string{5: "vrschema: control does not match the backoff state: HandoffView 1 after 5"})
	for _, c := range []struct {
		name string
		cs   ControlState
		r    uint64
	}{{"idle", ControlState{}, 5}, {"aborted at 3", ControlState{Kind: CtlAborted, Attempt: 3}, 5}, {"prepared p+48", ControlState{Kind: CtlPrepared, Attempt: 3, OrderedRound: 100}, 148},
		{"prepared p+49", ControlState{Kind: CtlPrepared, Attempt: 3, OrderedRound: 100}, 149}, {"frozen", ControlState{Kind: CtlFrozen, Attempt: 3, OrderedRound: 100}, 400},
		{"aborted at 2^64-1 (exhaustion)", ControlState{Kind: CtlAborted, Attempt: ^uint64(0)}, 5}} {
		k, ok, err := PlannableAttempt(c.cs, c.r)
		b.add(c.name, "backoff.plannable", map[string]any{"control": c.cs, "round": c.r}, map[string]any{"attempt": Dec(k), "defined": ok, "error": errName(err)})
	}
	for _, r := range []uint64{124, 125} {
		b.add(fmt.Sprintf("freeze at p+%d", r-100), "backoff.freezeInTime", map[string]any{"orderedRound": 100, "blockRound": r}, map[string]any{"valid": FreezeInTime(100, r)})
	}
}

// ---- view protocol judgments ----

func genViews(b *vb) {
	seen := func(n int, at uint64) []uint64 {
		s := make([]uint64, n)
		for i := range s {
			s[i] = at
		}
		return s
	}
	astra := seen(4, 1_002_000)
	astra[2] = 1_005_000
	traces := []struct {
		name string
		t    ViewTrace
	}{
		{"astra 1000/1002/1020/1005", ViewTrace{N: 4, Byzantine: []int{3}, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 1000, SeenMs: astra,
			ProposalMs: 1_002_000, ProposalUC: 1020, Assembler: 2, DMs: 14_000}},
		{"stale opening timestamp 900", ViewTrace{N: 4, Byzantine: []int{3}, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 900, SeenMs: astra,
			ProposalMs: 1_002_000, ProposalUC: 1002, Assembler: 2, DMs: 14_000}},
		{"future opening: replay floor not met", ViewTrace{N: 4, Byzantine: []int{3}, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 1010, SeenMs: astra,
			ProposalMs: 1_002_000, ProposalUC: 1020, Assembler: 2, DMs: 14_000}},
		{"accelerating assembler: early proposal waits for residence", ViewTrace{N: 4, Byzantine: []int{0}, Level: 0, View: 0, Assemblers: 4, OpenUCTime: 1000, SeenMs: seen(4, 1_000_000),
			ProposalMs: 1_000_100, ProposalUC: 1010, Assembler: 1, DMs: 5_000}},
		{"delayed opening delivery: T = T_req completes", ViewTrace{N: 4, Level: 0, View: 1, Assemblers: 4, OpenUCTime: 1000, SeenMs: seen(4, 1_000_000),
			ProposalMs: 1_000_000, ProposalUC: 1100, Assembler: 1, DMs: 9_000}},
		{"delayed opening delivery: window short by a second fails", ViewTrace{N: 4, Level: 0, View: 1, Assemblers: 4, OpenUCTime: 1000, SeenMs: seen(4, 1_000_000),
			ProposalMs: 1_000_000, ProposalUC: 1100, Assembler: 1, DMs: 11_000}},
		{"too-short timeout T=60 against D=100", ViewTrace{N: 16, Level: 0, View: 0, Assemblers: 16, TOverride: 60, OpenUCTime: 1000, SeenMs: seen(16, 1_000_000),
			ProposalMs: 1_000_000, ProposalUC: 1060, Assembler: 4, DMs: 100_000}},
		{"adequate timeout T=102 = T_req(D=100 s)", ViewTrace{N: 16, Level: 0, View: 0, Assemblers: 16, TOverride: 102, OpenUCTime: 1000, SeenMs: seen(16, 1_000_000),
			ProposalMs: 1_000_000, ProposalUC: 1102, Assembler: 4, DMs: 100_000}},
		{"late restart of a quorum-irrelevant root", ViewTrace{N: 4, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 1000, SeenMs: seen(4, 1_000_000),
			RestartMs: map[int]uint64{3: 1_024_000}, ProposalMs: 1_000_000, ProposalUC: 1020, Assembler: 0, DMs: 10_000}},
		{"restart at c_v+T-1, re-learn at c_v+T+4, remaining quorum suffices", ViewTrace{N: 4, Byzantine: []int{3}, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 1000,
			SeenMs: seen(4, 1_000_000), RestartMs: map[int]uint64{1: 1_024_000}, ProposalMs: 1_000_000, ProposalUC: 1020, Assembler: 0, DMs: 10_000}},
		{"restart at c_v+T-1, re-learn at c_v+T+4, quorum-relevant", ViewTrace{N: 4, Silent: []int{3}, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 1000,
			SeenMs: seen(4, 1_000_000), RestartMs: map[int]uint64{1: 1_024_000}, ProposalMs: 1_000_000, ProposalUC: 1020, Assembler: 0, DMs: 10_000}},
		{"silent assembler", ViewTrace{N: 4, Silent: []int{2}, Level: 1, View: 0, Assemblers: 4, OpenUCTime: 1000, SeenMs: seen(4, 1_000_000),
			ProposalMs: 1_020_002, ProposalUC: 1020, Assembler: 2, DMs: 1_000}},
		{"D counted once from c_v (astra VT-16 example): T=20, D=15, successors by 10 s", ViewTrace{N: 4, Silent: []int{3}, Level: 1, View: 0, Assemblers: 4,
			OpenUCTime: 1000, SeenMs: []uint64{0, 0, 0, 0}, ProposalMs: 0, ProposalUC: 1020, Assembler: 1, DMs: 15_000}},
		{"saturated timeout is never", ViewTrace{N: 4, Level: 9, View: 112, Assemblers: 4, OpenUCTime: 1000, SeenMs: seen(4, 1_000_000), ProposalMs: 1, ProposalUC: ^uint64(0),
			Assembler: 0, DMs: 1}},
	}
	// independent expectations for the boundary traces (hand-computed from the model text in schema section 14)
	wantCompletes := map[string]bool{"astra 1000/1002/1020/1005": true, "stale opening timestamp 900": true,
		"delayed opening delivery: T = T_req completes": true, "delayed opening delivery: window short by a second fails": false,
		"too-short timeout T=60 against D=100": false, "adequate timeout T=102 = T_req(D=100 s)": true, "silent assembler": false,
		"D counted once from c_v (astra VT-16 example): T=20, D=15, successors by 10 s": true}
	wantCommit := map[string]uint64{"astra 1000/1002/1020/1005": 1_022_002, "D counted once from c_v (astra VT-16 example): T=20, D=15, successors by 10 s": 20_002,
		"restart at c_v+T-1, re-learn at c_v+T+4, quorum-relevant": 1_044_002, "restart at c_v+T-1, re-learn at c_v+T+4, remaining quorum suffices": 1_020_002}
	for _, c := range traces {
		j := c.t.Judge()
		if want, ok := wantCompletes[c.name]; ok && want != j.Completes {
			b.fail("view %s: completes %v, the schema text gives %v", c.name, j.Completes, want)
		}
		if want, ok := wantCommit[c.name]; ok && want != j.EarliestCommitMs {
			b.fail("view %s: earliest commit %d, the schema text gives %d", c.name, j.EarliestCommitMs, want)
		}
		b.add(c.name, "view.trace", map[string]any{"trace": c.t}, map[string]any{"judgment": j})
	}
	if TReq(100_000) != 102 {
		b.fail("T_req(100 s) = %d", TReq(100_000))
	}
	rep := []struct {
		name string
		r    HandoffViewReplay
		v    uint64
		uc   uint64
	}{
		{"valid at the floor", HandoffViewReplay{IntentDerivable: true, CommittedView: 0, BackoffAgrees: true, OpenUCTime: 1000, Level: 1, N: 4, InBlock: 1}, 1, 1020},
		{"one second before the floor", HandoffViewReplay{IntentDerivable: true, CommittedView: 0, BackoffAgrees: true, OpenUCTime: 1000, Level: 1, N: 4, InBlock: 1}, 1, 1019},
		{"skips a view", HandoffViewReplay{IntentDerivable: true, CommittedView: 0, BackoffAgrees: true, OpenUCTime: 1000, Level: 1, N: 4, InBlock: 1}, 2, 5000},
		{"after a committed Prepare", HandoffViewReplay{IntentDerivable: true, CommittedView: 3, BackoffAgrees: true, PrepareCommitted: true, OpenUCTime: 1000, Level: 1, N: 4, InBlock: 1}, 4, 9000},
		{"two in one block", HandoffViewReplay{IntentDerivable: true, CommittedView: 0, BackoffAgrees: true, OpenUCTime: 1000, Level: 1, N: 4, InBlock: 2}, 1, 1020},
		{"intent not derivable", HandoffViewReplay{IntentDerivable: false, CommittedView: 0, BackoffAgrees: true, OpenUCTime: 1000, Level: 1, N: 4, InBlock: 1}, 1, 1020},
		{"never deadline", HandoffViewReplay{IntentDerivable: true, CommittedView: 111, BackoffAgrees: true, OpenUCTime: 1000, Level: 9, N: 4, InBlock: 1}, 112, ^uint64(0)},
		{"deadline carry", HandoffViewReplay{IntentDerivable: true, CommittedView: 0, BackoffAgrees: true, OpenUCTime: ^uint64(0) - 5, Level: 1, N: 4, InBlock: 1}, 1, ^uint64(0)},
	}
	for _, c := range rep {
		err := VerifyHandoffView(c.r, c.v, c.uc)
		b.add(c.name, "view.replay", map[string]any{"replay": c.r, "view": c.v, "blockUcTime": Dec(c.uc)}, map[string]any{"valid": err == nil, "error": errName(err)})
	}
	for _, c := range []struct {
		name                                string
		cert, gates, viewDue, rejDue, quiet bool
	}{{"certificate and a due view: Prepare", true, true, true, false, true}, {"due view, no certificate: HandoffView", false, true, true, false, true},
		{"due rejection over a fresh Prepare", true, true, false, true, true}, {"certificate, gates fail: HandoffView", true, false, true, false, true},
		{"censoring leader then honest run: the honest leader proposes Prepare", true, true, true, false, false}} {
		b.add(c.name, "view.leaderPolicy", map[string]any{"certComplete": c.cert, "gatesHold": c.gates, "viewDue": c.viewDue, "rejectionDue": c.rejDue, "quiet": c.quiet},
			map[string]any{"choice": LeaderChoice(c.cert, c.gates, c.viewDue, c.rejDue, c.quiet)})
	}
	for _, c := range []struct {
		name          string
		cv, committed uint64
		frozen        bool
	}{{"certificate of the current view", 3, 3, false}, {"late certificate of an earlier view after HandoffView committed first", 2, 3, false},
		{"certificate of a future view", 4, 3, false}, {"after the first committed Freeze", 3, 3, true}, {"I-RET: view h usable at h+6", 1, 7, false}} {
		b.add(c.name, "view.certificateAdmissible", map[string]any{"certView": c.cv, "committedView": c.committed, "freezeCommitted": c.frozen},
			map[string]any{"admissible": CertificateAdmissible(c.cv, c.committed, c.frozen)})
	}
}

// ---- remaining judgments: due table, pointer switch, activation, retirement ----

func genMisc(b *vb) {
	for _, c := range []struct {
		name  string
		st    uint8
		p, e  uint64
		fails bool
	}{{"Reserved before expiry", OutReserved, 100, 16_484, false}, {"Reserved at expiry", OutReserved, 16_484, 16_484, false}, {"Published at expiry", OutPublished, 20_000, 16_484, false},
		{"Published with admission failure", OutPublished, 100, 16_484, true}, {"Reserved with admission failure (not Published)", OutReserved, 100, 16_484, true},
		{"Invalidated immediately", OutInvalidated, 0, 16_484, false}, {"Rejected never", OutRejected, 99_999, 16_484, false}, {"Closed never", OutClosed, 99_999, 16_484, false},
		{"Acknowledged never", OutAcknowledged, 99_999, 16_484, false}} {
		r, due := RejectDue(c.st, c.p, c.e, c.fails)
		b.add(c.name, "reject.due", map[string]any{"state": OutputStateNames[c.st], "progress": c.p, "expiresAt": c.e, "admissionFails": c.fails},
			map[string]any{"due": due, "reason": r})
	}
	for _, c := range []struct {
		name                        string
		from, count, at             uint64
		code, ready, attach, holder bool
	}{{"switch mid-batch, holder module", 10, 6, 12, true, true, true, true}, {"switch is the last record", 10, 3, 12, true, true, true, false},
		{"attach fails: no holder entry, Faulted", 10, 6, 12, true, true, false, true}, {"adoption not ready: old module keeps the batch", 10, 6, 12, true, false, true, true},
		{"code hash mismatch", 10, 6, 10, false, true, true, true}} {
		b.add(c.name, "switch.sequence", map[string]any{"from": c.from, "count": c.count, "boundaryAt": c.at, "codeOK": c.code, "adoptionReady": c.ready,
			"attachOK": c.attach, "liabilityHolder": c.holder}, map[string]any{"steps": SwitchSequence(c.from, c.count, c.at, c.code, c.ready, c.attach, c.holder)})
	}
	eff := Effective([]Activation{{RuleID: RuleID("a"), RootEpoch: 7, NotBeforeUcTime: 5000, State: ActActive, ChangeID: 1},
		{RuleID: RuleID("b"), RootEpoch: 9, NotBeforeUcTime: 9000, State: ActActive, ChangeID: 2}})
	for _, c := range []struct {
		name   string
		ej, uc uint64
	}{{"e_J = 6 reaches E = 7 via recovery: time gate holds", 6, 5000}, {"e_J = 6, UC time below T", 6, 4999}, {"e_J = 5: E = 7 beyond e_J + 1", 5, 0},
		{"e_J = 8: both rules, b's time not reached", 8, 8999}} {
		err := PrepareTimeGate(c.ej, c.uc, eff)
		b.add(c.name, "activation.timeGate", map[string]any{"successorEpoch": c.ej, "ucTime": c.uc, "schedule": []any{map[string]any{"rule": "a", "E": 7, "T": 5000},
			map[string]any{"rule": "b", "E": 9, "T": 9000}}}, map[string]any{"ok": err == nil, "error": errName(err)})
	}
	entries := []Activation{{RuleID: RuleID("a"), ReleaseDigest: w("1"), RootEpoch: 7, NotBeforeUcTime: 5000, State: ActActive, ChangeID: 1}}
	post, _ := AppendSchedule(entries, Schedule{RuleID: RuleID("a"), ReleaseDigest: w("2"), RootEpoch: 9, NotBeforeUcTime: 6000}, 4)
	lat := Latch(post, 9)
	b.add("postpone then latch", "activation.entries", map[string]any{"start": entries, "append": map[string]any{"rule": "a", "E": 9, "changeId": 4}, "latchAt": 9},
		map[string]any{"afterAppend": post, "afterLatch": lat, "requiredAt8": RuleRequired(Effective(lat), RuleID("a"), 8), "requiredAt9": RuleRequired(Effective(lat), RuleID("a"), 9)})
	full := make([]Activation, MaxActivations)
	for i := range full {
		full[i] = Activation{RuleID: RuleID(fmt.Sprint(i)), RootEpoch: 100, State: ActActive, ChangeID: uint64(i + 1)}
	}
	_, err := AppendSchedule(full, Schedule{RuleID: RuleID("x"), RootEpoch: 100}, 65)
	b.add("sixty-fifth activation", "activation.entries", map[string]any{"count": MaxActivations}, map[string]any{"error": errName(err)})

	ok := RetirementWitness{VRHolder: Holder{Holder: fxOther, CodeHash: w("holder-code"), Module: fxModule}, HolderKnown: true, RecordCount: 40, TargetCount: 40,
		HolderCodeHash: w("holder-code"), HolderCursor: 40, Facts: LiabilityFacts{Requested: true, RefDigest: w("ref"), MaxLiabilityAnchor: 900}, BlockProgress: 1000}
	hr := HolderRetirement{Holder: 0, ID: 7, Generation: 1, RefDigest: w("ref")}
	for _, c := range []struct {
		name string
		f    func(*RetirementWitness)
	}{{"retirable", nil}, {"handoff in flight", func(x *RetirementWitness) { x.HandoffInFlight = true }}, {"unknown holder", func(x *RetirementWitness) { x.HolderKnown = false }},
		{"code hash mismatch", func(x *RetirementWitness) { x.HolderCodeHash = w("other") }}, {"already retired", func(x *RetirementWitness) { x.Retired = true }},
		{"registry behind its source", func(x *RetirementWitness) { x.TargetCount = 41 }}, {"dedup key present", func(x *RetirementWitness) { x.DedupPresent = true }},
		{"stale holder cursor", func(x *RetirementWitness) { x.HolderCursor = 39 }}, {"not requested", func(x *RetirementWitness) { x.Facts.Requested = false }},
		{"live exposure", func(x *RetirementWitness) { x.Facts.LiveExposures = 1 }}, {"nonzero lotReferences", func(x *RetirementWitness) { x.Facts.LotReferences = 2 }},
		{"refDigest differs", func(x *RetirementWitness) { x.Facts.RefDigest = w("other") }}, {"liability anchor ahead", func(x *RetirementWitness) { x.Facts.MaxLiabilityAnchor = 1001 }}} {
		x := ok
		if c.f != nil {
			c.f(&x)
		}
		err := VerifyHolderRetirement(x, hr)
		b.add(c.name, "retirement.verify", map[string]any{"holderKnown": x.HolderKnown, "retired": x.Retired, "recordCount": x.RecordCount, "targetCount": x.TargetCount,
			"dedupPresent": x.DedupPresent, "pinnedCodeHash": Hexw(x.VRHolder.CodeHash), "holderCodeHash": Hexw(x.HolderCodeHash), "holderCursor": x.HolderCursor,
			"requested": x.Facts.Requested, "liveExposures": x.Facts.LiveExposures, "lotReferences": x.Facts.LotReferences, "refDigest": Hexw(x.Facts.RefDigest),
			"maxLiabilityAnchor": x.Facts.MaxLiabilityAnchor, "blockProgress": x.BlockProgress, "handoffInFlight": x.HandoffInFlight, "data": Hexb(hr.Encode())},
			map[string]any{"ok": err == nil, "error": errName(err)})
	}
}

func keyOf(p *types.PartitionDescriptionRecord) ShardKey {
	return ShardKey{uint32(p.PartitionID), string(p.ShardID.Bytes())}
}

func ints8(v []uint8) []int {
	out := make([]int, len(v))
	for i, x := range v {
		out[i] = int(x)
	}
	return out
}

// ---- the boundaries the VT-16 reviews named, each with a hand-written expectation the reference must meet ----

func genReviewBoundaries(b *vb) {
	// the protocol proof-configuration predicate
	for _, c := range []struct {
		name   string
		params map[string]string
		want   string
	}{{"absent", nil, ""}, {"none", map[string]string{"proof_type": "none"}, ""}, {"aggregator_rsmt_v1", map[string]string{"proof_type": "aggregator_rsmt_v1"}, ""},
		{"exec", map[string]string{"proof_type": "exec"}, ""}, {"aggregator_zk_v1", map[string]string{"proof_type": "aggregator_zk_v1"}, ""},
		{"sp1 complete", map[string]string{"proof_type": "sp1", "vkey_path": "/k", "chain_id": "3"}, ""},
		{"sp1 without vkey_path", map[string]string{"proof_type": "sp1", "chain_id": "3"}, "ProofVKeyPathMissing"},
		{"sp1 without chain_id", map[string]string{"proof_type": "sp1", "vkey_path": "/k"}, "ProofChainIDMissing"},
		{"light_client with chain_id", map[string]string{"proof_type": "light_client", "chain_id": "18446744073709551615"}, ""},
		{"light_client chain_id non-decimal", map[string]string{"proof_type": "light_client", "chain_id": "0x3"}, "ProofChainIDMissing"},
		{"light_client chain_id leading zero", map[string]string{"proof_type": "light_client", "chain_id": "03"}, "ProofChainIDMissing"},
		{"light_client chain_id two zeros", map[string]string{"proof_type": "light_client", "chain_id": "00"}, "ProofChainIDMissing"},
		{"light_client chain_id leading zeros before the maximum", map[string]string{"proof_type": "light_client", "chain_id": "00018446744073709551615"}, "ProofChainIDMissing"},
		{"light_client chain_id plus sign", map[string]string{"proof_type": "light_client", "chain_id": "+3"}, "ProofChainIDMissing"},
		{"light_client chain_id minus sign", map[string]string{"proof_type": "light_client", "chain_id": "-3"}, "ProofChainIDMissing"},
		{"light_client chain_id leading space", map[string]string{"proof_type": "light_client", "chain_id": " 3"}, "ProofChainIDMissing"},
		{"light_client chain_id trailing space", map[string]string{"proof_type": "light_client", "chain_id": "3 "}, "ProofChainIDMissing"},
		{"light_client chain_id separator", map[string]string{"proof_type": "light_client", "chain_id": "3_000"}, "ProofChainIDMissing"},
		{"light_client chain_id overflow", map[string]string{"proof_type": "light_client", "chain_id": "18446744073709551616"}, "ProofChainIDMissing"},
		{"light_client chain_id empty", map[string]string{"proof_type": "light_client", "chain_id": ""}, "ProofChainIDMissing"},
		{"light_client chain_id 0", map[string]string{"proof_type": "light_client", "chain_id": "0"}, ""},
		{"light_client chain_id 3", map[string]string{"proof_type": "light_client", "chain_id": "3"}, ""},
		{"risc0 (no verifier)", map[string]string{"proof_type": "risc0"}, "UnknownProofType"},
		{"unknown type", map[string]string{"proof_type": "smt"}, "UnknownProofType"}} {
		got := errName(ProofConfigValid(c.params))
		if got != c.want {
			b.fail("proof config %s: %q, want %q", c.name, got, c.want)
		}
		b.add(c.name, "fold.proofConfig", map[string]any{"params": c.params}, map[string]any{"ok": got == "", "error": got})
	}

	// scoped binding selection: deferral, never Conflict
	pdrA := fxPDR(7, 3, 3, 3, 3)
	repl := mustChange(KindReplaceAggregator, uint64(7), pdrA.ShardID.Bytes(), w("old"), mustCBOR(pdrA), []byte{0x80})
	upd := mustChange(KindUpdatePartition, uint64(7), pdrA.ShardID.Bytes(), w("old"), mustCBOR(pdrA))
	upd8 := mustChange(KindUpdatePartition, uint64(8), pdrA.ShardID.Bytes(), w("old"), mustCBOR(pdrA))
	add9 := mustChange(KindAddPartition, mustCBOR(fxPDR(9, 3, 0, 10, 2)), []byte{0x80})
	add9b := mustChange(KindAddPartition, mustCBOR(fxPDR(9, 3, 0, 12, 2)), []byte{0x80})
	s1 := mustChange(KindScheduleActivation, RuleID("r"), w("1"), uint64(20), uint64(0), "")
	s2 := mustChange(KindScheduleActivation, RuleID("r"), w("2"), uint64(30), uint64(0), "")
	s3 := mustChange(KindScheduleActivation, RuleID("q"), w("1"), uint64(20), uint64(0), "")
	cand := func(id uint64, kind uint8, payload []byte) BindCandidate {
		sc, err := ChangeScope(kind, payload)
		if err != nil {
			b.fail("scope: %v", err)
		}
		return BindCandidate{ID: id, Kind: kind, PayloadSize: len(payload), Scope: sc}
	}
	for _, c := range []struct {
		name     string
		cs       []BindCandidate
		bound    []uint64
		deferred []uint64
	}{
		{"two schedules of one rule: the second defers", []BindCandidate{cand(1, KindScheduleActivation, s1), cand(2, KindScheduleActivation, s2), cand(3, KindScheduleActivation, s3)}, []uint64{1, 3}, []uint64{2}},
		{"kinds 6 and 8 on one shard: the second defers", []BindCandidate{cand(1, KindReplaceAggregator, repl), cand(2, KindUpdatePartition, upd), cand(3, KindUpdatePartition, upd8)}, []uint64{1, 3}, []uint64{2}},
		{"two additions of one partition: the second defers", []BindCandidate{cand(4, KindAddPartition, add9), cand(5, KindAddPartition, add9b)}, []uint64{4}, []uint64{5}},
	} {
		bound, deferred := SelectBinding(c.cs)
		if fmt.Sprint(bound) != fmt.Sprint(c.bound) || fmt.Sprint(deferred) != fmt.Sprint(c.deferred) {
			b.fail("binding %s: %v / %v", c.name, bound, deferred)
		}
		var in []any
		for _, x := range c.cs {
			in = append(in, map[string]any{"id": x.ID, "kind": x.Kind, "payloadSize": x.PayloadSize, "scope": x.Scope})
		}
		b.add(c.name, "change.binding", map[string]any{"scheduled": in}, map[string]any{"bound": c.bound, "deferred": c.deferred})
	}
	if p, err := PDRPartition(mustCBOR(fxPDR(9, 3, 0, 10, 2))); err != nil || p != 9 {
		b.fail("PDRPartition: %d %v", p, err)
	}
	for _, c := range []struct {
		name string
		pdr  []byte
		want string
	}{{"canonical PDR of partition 9", mustCBOR(fxPDR(9, 3, 0, 10, 2)), "partition:9"},
		{"canonical PDR of partition 70000", mustCBOR(fxPDR(70000, 3, 0, 10, 2)), "partition:70000"},
		{"no tag", []byte{0x83, 1, 3, 9}, "UnreadableScope"},
		{"non-shortest partition id", []byte{0xd9, 0x98, 0x60, 0x83, 1, 3, 0x18, 9}, "UnreadableScope"},
		{"tag, array of 3, uints 1, 3, 9", []byte{0xd9, 0x98, 0x60, 0x83, 1, 3, 9}, "partition:9"}} {
		got, err := ChangeScope(KindAddPartition, mustChange(KindAddPartition, c.pdr, []byte{0x80}))
		if err != nil {
			got = "UnreadableScope"
		}
		if got != c.want {
			b.fail("scope %s: %s, want %s", c.name, got, c.want)
		}
		b.add(c.name, "change.scope", map[string]any{"kind": KindAddPartition, "pdr": Hexb(c.pdr)}, map[string]any{"scope": c.want})
	}

	// the pointer switch, in the design's order
	want := "[checkCodeAndHolder adoptionReady onRecords(old,10,3) detach setPointer attach allocateHolder onRecords(new,13,3)]"
	var got []string
	for _, st := range SwitchSequence(10, 6, 12, true, true, true, true) {
		if st.Step == "onRecords" {
			got = append(got, fmt.Sprintf("onRecords(%s,%d,%d)", st.Module, st.From, st.Count))
		} else {
			got = append(got, st.Step)
		}
	}
	if fmt.Sprint(got) != want {
		b.fail("switch order %v", got)
	}

	// S2a with a Reserved R: attempt changes keep it; only expiry makes it rejectable
	{
		s := newScript(b, "S2a-1 attempt changes keep a Reserved R until its expiry")
		c := s.schedule(KindCommitteeLimits)
		r := s.reserve("R", []uint64{c}, "")
		s.root.Abort(false)
		s.step("root", "abort", map[string]any{"note": "an unrelated attempt ends; no Prepare exists against an unpublished R"}, nil, "")
		k, ok, _ := PlannableAttempt(s.root.Control, 10)
		s.step("root", "plannable", map[string]any{"attempt": k, "defined": ok}, nil, "")
		_, due := RejectDue(OutReserved, 10_000+Lifetime-1, 10_000+Lifetime, false)
		s.step("root", "reject", map[string]any{"result": "R", "progress": 10_000 + Lifetime - 1}, s.root.Reject(r, 20, due), "NotDue")
		reason, due := RejectDue(OutReserved, 10_000+Lifetime, 10_000+Lifetime, false)
		s.step("root", "reject", map[string]any{"result": "R", "progress": 10_000 + Lifetime, "reason": reason}, s.root.Reject(r, 21, due), "")
		s.deliver(-1)
		s.done("s2a.lapse")
	}
	// the root never restarts an exhausted or undefined attempt at zero
	for _, c := range []struct {
		name  string
		ctl   ControlState
		round uint64
		want  string
	}{
		{"Prepare at OrderedRound near 2^64 never dies", ControlState{Kind: CtlPrepared, Attempt: 7, OrderedRound: ^uint64(0) - 20}, ^uint64(0) - 10, "NotQuiet"},
		{"Prepare at the last round after a cooldown near 2^64", ControlState{Kind: CtlPrepared, Attempt: 7, OrderedRound: ^uint64(0) - 48}, ^uint64(0), "NotQuiet"},
		{"aborted attempt 2^64-1 is exhausted", ControlState{Kind: CtlAborted, Attempt: ^uint64(0)}, 5, "ErrHandoffApproval"},
		{"prepared attempt 2^64-1 after its cooldown is exhausted", ControlState{Kind: CtlPrepared, Attempt: ^uint64(0), OrderedRound: 100}, 149, "ErrHandoffApproval"},
		{"aborted attempt 7 plans attempt 8", ControlState{Kind: CtlAborted, Attempt: 7}, 5, ""},
	} {
		rm := NewRootModel(5)
		rm.Control = c.ctl
		err := rm.Prepare(w("R"), c.round)
		if errName(err) != c.want {
			b.fail("root %s: %v", c.name, err)
		}
		exp := map[string]any{"error": errName(err), "controlAfter": rm.Control}
		b.add(c.name, "root.prepare", map[string]any{"control": c.ctl, "round": Dec(c.round)}, exp)
	}
	// native repair preconditions
	for _, c := range []struct {
		name string
		bind bool
		gap  uint64
		want string
	}{{"native repair with work after MIN_EPOCH_GAP", true, MinEpochGap, ""}, {"native repair without Scheduled work", false, MinEpochGap, "NoScheduledWork"},
		{"native repair before MIN_EPOCH_GAP", true, MinEpochGap - 1, "EpochGap"}} {
		s := newScript(b, c.name)
		var bind []uint64
		if c.bind {
			bind = []uint64{s.schedule(KindForceRemove)}
		}
		s.vr.Health = HealthFaulted
		err := s.vr.Reserve(s.id("N"), [20]byte{}, true, bind, uint64(len(s.vr.Log)), c.gap)
		s.step("vr", "reserveNative", map[string]any{"bind": bind, "sinceEpochStart": c.gap}, err, c.want)
		s.done("s2a.native")
	}
	// the root latches at H; VR at its Boundary
	{
		rootSched := []Activation{{RuleID: RuleID("a"), ReleaseDigest: w("1"), RootEpoch: 7, NotBeforeUcTime: 5000, State: ActActive, ChangeID: 4}}
		vrSched := append([]Activation(nil), rootSched...)
		var trace []any
		rootSched = Latch(rootSched, 7)
		trace = append(trace, map[string]any{"event": "H committed into root epoch 7 (root history)", "root": rootSched, "vr": vrSched})
		post := Schedule{RuleID: RuleID("a"), ReleaseDigest: w("2"), RootEpoch: 12, NotBeforeUcTime: 9000}
		v := ScheduleVerdict(post, 8, Effective(rootSched))
		if v != VerdictLatched {
			b.fail("root latch: fold gives %d", v)
		}
		trace = append(trace, map[string]any{"event": "fold of a candidate into epoch 8 reads the root schedule, Boundary still delayed", "verdict": VerdictNames[v],
			"withVRScheduleWouldBe": VerdictNames[ScheduleVerdict(post, 8, Effective(vrSched))]})
		vrSched = Latch(vrSched, 7)
		trace = append(trace, map[string]any{"event": "the matching Boundary is imported and applied", "root": rootSched, "vr": vrSched})
		b.add("root latches at H, VR at the delayed Boundary", "activation.latch", map[string]any{"rule": "a", "E": 7}, map[string]any{"trace": trace})
	}
}
