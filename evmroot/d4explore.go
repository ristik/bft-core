package evmroot

import "fmt"

// D4 bounded exploration: run the handoff state machine through the fault
// scenarios D4's acceptance contract names and check the safety invariants
// after every step.

// InvariantViolation names a broken safety property and where.
type InvariantViolation struct {
	Invariant string
	Detail    string
}

// checkInvariants evaluates the D4 safety invariants against a handoff
// state. rounds is the window of imported root rounds to probe.
func checkInvariants(h *Handoff, rounds []uint64) []InvariantViolation {
	var v []InvariantViolation

	// INV1: no two effective successors. Only a Committed/Activated/
	// Acknowledged handoff names a successor; an Aborted one names none.
	if h.Phase == PhaseAborted && len(h.SuccessorTRHash) != 0 {
		v = append(v, InvariantViolation{"single_successor", "aborted handoff still carries a successor technical record"})
	}

	// INV2: no root round authorised by both assignments, and none by
	// neither. Below A* -> old; at/above A* -> new; before commit/after
	// abort -> old for all rounds.
	for _, r := range rounds {
		a := h.Authorized(r)
		switch h.Phase {
		case PhaseCommitted, PhaseActivated, PhaseAcknowledged:
			want := OldAssignment
			if r >= h.ActivationRound {
				want = NewAssignment
			}
			if a != want {
				v = append(v, InvariantViolation{"no_overlap_no_gap",
					fmt.Sprintf("round %d authorised by %q, want %q (A*=%d)", r, a, want, h.ActivationRound)})
			}
		default:
			if a != OldAssignment {
				v = append(v, InvariantViolation{"no_overlap_no_gap",
					fmt.Sprintf("phase %s: round %d authorised by %q, want old", h.Phase, r, a)})
			}
		}
	}

	// INV3: no signed message binds state unknown at signing time.
	if h.Phase >= PhaseEndorsed && h.Phase != PhaseAborted {
		if !FieldsAreKnown(h.EndorsementDomain) {
			v = append(v, InvariantViolation{"no_future_signature", "endorsement domain binds post-commit state"})
		}
		if h.EndorsementDomain.ActivationRound != 0 {
			v = append(v, InvariantViolation{"no_future_signature", "endorsement bound an activation round"})
		}
	}

	// INV4: A* is final under pipelining.
	if h.Phase >= PhaseCommitted && h.Phase != PhaseAborted {
		if h.ActivationRound < h.CommitRound+PipelineDepth {
			v = append(v, InvariantViolation{"activation_final_under_pipelining",
				fmt.Sprintf("A*=%d < commit %d + pipeline %d", h.ActivationRound, h.CommitRound, PipelineDepth)})
		}
	}
	return v
}

// Step is one named action in a scenario.
type Step struct {
	Name string
	Do   func(h *Handoff) error
}

// ScenarioResult records how a scenario ran.
type ScenarioResult struct {
	Name         string               `json:"name"`
	Note         string               `json:"note"`
	Steps        []ScenarioStepResult `json:"steps"`
	FinalPhase   string               `json:"final_phase"`
	WantPhase    string               `json:"want_phase"`
	PhaseOK      bool                 `json:"phase_ok"`
	Violations   []InvariantViolation `json:"violations"`
	InvariantsOK bool                 `json:"invariants_ok"`
}

type ScenarioStepResult struct {
	Step string `json:"step"`
	Err  string `json:"err,omitempty"`
}

var probeRounds = []uint64{0, 5, 9, 10, 11, 20, 100, 1000}

// runScenario executes steps against a fresh handoff and checks invariants
// after each.
func runScenario(name, note, wantPhase string, start *Handoff, steps []Step) ScenarioResult {
	res := ScenarioResult{Name: name, Note: note, WantPhase: wantPhase, InvariantsOK: true}
	h := start
	for _, s := range steps {
		err := s.Do(h)
		sr := ScenarioStepResult{Step: s.Name}
		if err != nil {
			sr.Err = err.Error()
		}
		res.Steps = append(res.Steps, sr)
		for _, iv := range checkInvariants(h, probeRounds) {
			res.Violations = append(res.Violations, iv)
			res.InvariantsOK = false
		}
	}
	res.FinalPhase = h.Phase.String()
	res.PhaseOK = res.FinalPhase == wantPhase
	return res
}

func freshHandoff() *Handoff {
	c := Candidate{
		Network: 3, NextEpoch: 8, Attempt: 0,
		PredecessorHash: rep(0xE7, 32), MinActivation: 10, MembersHash: rep(0xAA, 32),
	}
	return NewHandoff(c, 1)
}

func body(h *Handoff) TrustBaseBodyV2 { return sampleHandoffBody(h.Candidate.PredecessorHash) }

// D4Scenarios builds the full scenario set.
func D4Scenarios() []ScenarioResult {
	var out []ScenarioResult
	oldThreshold := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())

	// Happy path (with a deliberately delayed endorsement signature — it
	// still lands before commit, so the outcome is unchanged).
	out = append(out, runScenario("delayed_signatures",
		"Endorsement weight arrives in two batches; the second crosses the threshold before Commit.",
		"acknowledged", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"freeze", func(h *Handoff) error { return h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h)) }},
			{"endorse_below_threshold", func(h *Handoff) error {
				err := h.Endorse(oldThreshold-1, oldThreshold)
				if err == nil {
					return fmt.Errorf("under-threshold endorsement accepted")
				}
				return nil
			}},
			{"endorse_at_threshold", func(h *Handoff) error { return h.Endorse(oldThreshold, oldThreshold) }},
			{"commit", func(h *Handoff) error { return h.Commit(6, 10, rep(0x33, 32)) }},
			{"activate_at_boundary", func(h *Handoff) error { return h.Activate(10) }},
			{"acknowledge", func(h *Handoff) error { return h.Acknowledge(41) }},
		}))

	// Asymmetric delivery: one replica sees Commit + Activate, another is
	// stuck at Endorsed. The stuck replica must not activate and must keep
	// authorising the old set.
	out = append(out, func() ScenarioResult {
		stuck := freshHandoff()
		_ = stuck.Prepare()
		_ = stuck.Freeze(rep(0x11, 32), rep(0x22, 32), body(stuck))
		_ = stuck.Endorse(oldThreshold, oldThreshold)
		return runScenario("asymmetric_delivery",
			"A replica that never received the commit record stays at endorsed; it cannot self-activate and keeps the old assignment authoritative for every round.",
			"endorsed", stuck, []Step{
				{"try_activate_without_commit", func(h *Handoff) error {
					if err := h.Activate(1000); err == nil {
						return fmt.Errorf("activated without a commit record")
					}
					return nil
				}},
			})
	}())

	// Missed earliest activation: the observed round runs past A_min while
	// still at Frozen; activation is impossible until Commit fixes A*.
	out = append(out, runScenario("missed_earliest_activation",
		"Observed root round passes A_min before Commit; activation waits for the committed A*, not the proposed start.",
		"acknowledged", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"freeze", func(h *Handoff) error { return h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h)) }},
			{"round_passes_A_min_no_commit", func(h *Handoff) error {
				if err := h.Activate(50); err == nil {
					return fmt.Errorf("activated on clock passage")
				}
				return nil
			}},
			{"endorse", func(h *Handoff) error { return h.Endorse(oldThreshold, oldThreshold) }},
			{"commit_A_star_ge_observed", func(h *Handoff) error { return h.Commit(50, 60, rep(0x33, 32)) }},
			{"activate_at_A_star", func(h *Handoff) error { return h.Activate(60) }},
			{"acknowledge", func(h *Handoff) error { return h.Acknowledge(200) }},
		}))

	// Crash at each phase: resume from the same durable state; an attempt
	// to skip the next phase fails.
	for _, cp := range []struct {
		name  string
		build func() *Handoff
		skip  Step
	}{
		{"crash_at_prepared", func() *Handoff { h := freshHandoff(); _ = h.Prepare(); return h },
			Step{"skip_to_endorse", func(h *Handoff) error {
				if err := h.Endorse(oldThreshold, oldThreshold); err == nil {
					return fmt.Errorf("endorsed without freeze")
				}
				return nil
			}}},
		{"crash_at_frozen", func() *Handoff {
			h := freshHandoff()
			_ = h.Prepare()
			_ = h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h))
			return h
		}, Step{"skip_to_commit", func(h *Handoff) error {
			if err := h.Commit(6, 10, rep(0x33, 32)); err == nil {
				return fmt.Errorf("committed without endorse")
			}
			return nil
		}}},
		{"crash_at_endorsed", func() *Handoff {
			h := freshHandoff()
			_ = h.Prepare()
			_ = h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h))
			_ = h.Endorse(oldThreshold, oldThreshold)
			return h
		}, Step{"skip_to_activate", func(h *Handoff) error {
			if err := h.Activate(10); err == nil {
				return fmt.Errorf("activated without commit")
			}
			return nil
		}}},
		{"crash_at_committed", func() *Handoff {
			h := freshHandoff()
			_ = h.Prepare()
			_ = h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h))
			_ = h.Endorse(oldThreshold, oldThreshold)
			_ = h.Commit(6, 10, rep(0x33, 32))
			return h
		}, Step{"resume_and_activate", func(h *Handoff) error { return h.Activate(10) }}},
	} {
		want := cp.build().Phase.String()
		if cp.name == "crash_at_committed" {
			want = "activated"
		}
		out = append(out, runScenario(cp.name,
			"Resume from the durable phase; the next phase cannot be skipped.",
			want, cp.build(), []Step{cp.skip}))
	}

	// Old quorum lost after prepare: endorsement can never reach the
	// threshold; safety over progress — no path to Activated.
	out = append(out, runScenario("old_quorum_loss_after_prepare",
		"Old quorum is unavailable after Prepare; endorsement cannot complete and the handoff stalls with the old set still authoritative.",
		"frozen", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"freeze", func(h *Handoff) error { return h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h)) }},
			{"endorse_fails_forever", func(h *Handoff) error {
				if err := h.Endorse(oldThreshold-5, oldThreshold); err == nil {
					return fmt.Errorf("endorsed below quorum")
				}
				return nil
			}},
			{"activate_still_impossible", func(h *Handoff) error {
				if err := h.Activate(10_000); err == nil {
					return fmt.Errorf("activated with no endorsement or commit")
				}
				return nil
			}},
		}))

	// Committed abort vs late activate: a committed handoff cannot be
	// aborted; an aborted (pre-commit) attempt cannot be activated. The two
	// records can never both be effective.
	out = append(out, runScenario("committed_abort_vs_late_activate",
		"Once committed, Abort is rejected; once aborted, Activate is rejected. Conflicting records cannot both take effect.",
		"committed", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"freeze", func(h *Handoff) error { return h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h)) }},
			{"endorse", func(h *Handoff) error { return h.Endorse(oldThreshold, oldThreshold) }},
			{"commit", func(h *Handoff) error { return h.Commit(6, 10, rep(0x33, 32)) }},
			{"abort_after_commit_rejected", func(h *Handoff) error {
				if err := h.Abort("too late"); err == nil {
					return fmt.Errorf("aborted a committed handoff")
				}
				return nil
			}},
		}))
	out = append(out, runScenario("aborted_then_activate_rejected",
		"A pre-commit abort kills attempt j; Activate is impossible afterwards; a replacement needs attempt j+1.",
		"aborted", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"freeze", func(h *Handoff) error { return h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h)) }},
			{"abort", func(h *Handoff) error { return h.Abort("candidate replaced") }},
			{"activate_rejected", func(h *Handoff) error {
				if err := h.Activate(10_000); err == nil {
					return fmt.Errorf("activated an aborted handoff")
				}
				return nil
			}},
		}))

	// Incomplete prepare cannot activate through local REST insertion or
	// clock passage.
	out = append(out, runScenario("incomplete_prepare_then_clock",
		"Prepare only, then the round counter reaches the proposed start: no activation.",
		"prepared", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"clock_reaches_proposed_start", func(h *Handoff) error {
				if err := h.Activate(10); err == nil {
					return fmt.Errorf("clock passage activated an incomplete prepare")
				}
				return nil
			}},
		}))
	out = append(out, runScenario("incomplete_prepare_then_rest_insertion",
		"A locally submitted trust base (simulated as an Activate with no committed record) is rejected.",
		"prepared", freshHandoff(), []Step{
			{"prepare", func(h *Handoff) error { return h.Prepare() }},
			{"local_rest_insertion", func(h *Handoff) error {
				if err := h.Activate(999999); err == nil {
					return fmt.Errorf("local insertion activated a trust base")
				}
				return nil
			}},
		}))

	return out
}
