package evmroot

import (
	"encoding/json"
	"fmt"
)

// D4 vector set: the handoff scenario results plus an exhaustive check that
// only the canonical phase order reaches a committed handoff and that the
// new assignment is never authorised before commit.

type D4VectorSet struct {
	PipelineDepth uint64               `json:"pipeline_depth"`
	Scenarios     []ScenarioResult     `json:"scenarios"`
	Interleavings D4InterleaveCheck    `json:"phase_order_interleavings"`
	MultiReplica  []MultiReplicaResult `json:"multi_replica_exploration"`
	Summary       D4Summary            `json:"summary"`
}

type D4InterleaveCheck struct {
	Note                    string   `json:"note"`
	Permutations            int      `json:"permutations"`
	ReachedCommitted        []string `json:"orders_reaching_committed"`
	NewAuthorizedEarly      []string `json:"orders_authorising_new_before_commit"`
	CanonicalOrder          []string `json:"canonical_order"`
	OnlyCanonicalCommits    bool     `json:"only_canonical_commits"`
	NoEarlyNewAuthorization bool     `json:"no_early_new_authorization"`
}

type D4Summary struct {
	Scenarios            int  `json:"scenarios"`
	AllPhaseExpectations bool `json:"all_phase_expectations_met"`
	AllInvariantsHeld    bool `json:"all_invariants_held"`
	MultiReplicaRuns     int  `json:"multi_replica_runs"`
	AllGlobalInvariants  bool `json:"all_global_invariants_held"`
}

func BuildD4Vectors() D4VectorSet {
	vs := D4VectorSet{PipelineDepth: PipelineDepth}
	vs.Scenarios = D4Scenarios()

	allPhase, allInv := true, true
	for _, s := range vs.Scenarios {
		allPhase = allPhase && s.PhaseOK
		allInv = allInv && s.InvariantsOK
	}
	vs.MultiReplica = D4MultiReplicaRuns()
	allGlobal := true
	for _, m := range vs.MultiReplica {
		allGlobal = allGlobal && m.G1NoEquivocation && m.G2SingleSuccessor && m.G3NoOverlap && m.G4FinalCommit
	}

	vs.Summary = D4Summary{
		Scenarios: len(vs.Scenarios), AllPhaseExpectations: allPhase, AllInvariantsHeld: allInv,
		MultiReplicaRuns: len(vs.MultiReplica), AllGlobalInvariants: allGlobal,
	}

	// --- exhaustive 4-phase interleaving ---------------------------------
	oldThreshold := RootQuorumThreshold(func() uint64 { w, _ := d3Assignment().TotalWeight(); return w }())
	names := []string{"prepare", "freeze", "endorse", "commit"}
	apply := func(h *Handoff, step string) error {
		switch step {
		case "prepare":
			return h.Prepare()
		case "freeze":
			return h.Freeze(rep(0x11, 32), rep(0x22, 32), body(h))
		case "endorse":
			return h.Endorse(oldThreshold, oldThreshold)
		case "commit":
			return h.Commit(6, 10, rep(0x33, 32))
		}
		return fmt.Errorf("unknown step %q", step)
	}

	var reached, early []string
	for _, perm := range permute(names) {
		h := freshHandoff()
		earlyNew := false
		for _, step := range perm {
			_ = apply(h, step)
			if h.Phase < PhaseCommitted && h.Authorized(1000) == NewAssignment {
				earlyNew = true
			}
		}
		label := join(perm, "->")
		if h.Phase == PhaseCommitted {
			reached = append(reached, label)
		}
		if earlyNew {
			early = append(early, label)
		}
	}
	vs.Interleavings = D4InterleaveCheck{
		Note: "All 24 orderings of the four core phases are run; only the canonical order reaches a committed handoff, " +
			"and no ordering authorises the new assignment before commit.",
		Permutations:            24,
		ReachedCommitted:        reached,
		NewAuthorizedEarly:      early,
		CanonicalOrder:          names,
		OnlyCanonicalCommits:    len(reached) == 1 && reached[0] == join(names, "->"),
		NoEarlyNewAuthorization: len(early) == 0,
	}

	return vs
}

func MarshalD4Vectors(vs D4VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// permute returns all permutations of s (n! ; n is 4 here).
func permute(s []string) [][]string {
	if len(s) <= 1 {
		return [][]string{append([]string(nil), s...)}
	}
	var out [][]string
	for i := range s {
		rest := make([]string, 0, len(s)-1)
		rest = append(rest, s[:i]...)
		rest = append(rest, s[i+1:]...)
		for _, p := range permute(rest) {
			out = append(out, append([]string{s[i]}, p...))
		}
	}
	return out
}

func join(s []string, sep string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += sep
		}
		out += v
	}
	return out
}
