package vradmit

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// VerifyCandidateRules is item (5) of VerifyRegistryOutput, moved (#1306): a leader runs it before it orders a Prepare, so a candidate it
// refuses is one every root's Freeze admission refuses with the same error, and a candidate it accepts passes item (5) of admission.
func TestVerifyCandidateRulesIsAdmissionItemFive(t *testing.T) {
	w := newWorld(t)
	a := w.admission()
	require.NoError(t, VerifyCandidateRules(a.Candidate, a.Verify, a.Lifecycle), "the published output passes item (5)")

	// an EVM-only change: the current root committee is the candidate's own, while the EVM validators change (the #1306 trigger, a
	// delegate swap that stays refused under #1286's rebinding rule)
	evmOnly := a
	evmOnly.Verify.CurrentRoot = w.jRoot
	err := VerifyCandidateRules(evmOnly.Candidate, evmOnly.Verify, evmOnly.Lifecycle)
	require.ErrorIs(t, err, ErrH3)
	require.ErrorIs(t, err, evmassign.ErrEVMOnly)
	_, full := VerifyRegistryOutput(evmOnly)
	require.ErrorIs(t, full, ErrH3)
	require.ErrorIs(t, full, evmassign.ErrEVMOnly)
	require.Equal(t, err.Error(), full.Error(), "admission refuses with exactly the error of the leader-side check")

	// every item-(5) refusal of the admission table is the check's too
	for name, break_ := range map[string]func(*Admission){
		"a missing PoP": func(a *Admission) { a.Candidate.PoPs = a.Candidate.PoPs[1:] },
		"continuity":    func(a *Admission) { a.Lifecycle.Policy.MaxM = 0; a.Lifecycle.Policy.MaxDistNum = 0 },
		"no authorization": func(a *Admission) {
			c := a.Candidate
			c.Authorization = nil
			a.Candidate = c
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := w.admission()
			break_(&b)
			err := VerifyCandidateRules(b.Candidate, b.Verify, b.Lifecycle)
			require.ErrorIs(t, err, ErrH3)
			_, full := VerifyRegistryOutput(b)
			require.ErrorIs(t, full, ErrH3)
			require.True(t, errors.Is(err, ErrAdmission), "a deterministic admission refusal")
		})
	}
}
