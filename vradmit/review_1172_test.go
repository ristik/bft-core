package vradmit

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// Regressions for the #1172 reviews.

// astra 2: one successor's readiness may not carry commitments the committed support state cannot take: an unscheduled rule, another
// network, or more than the table bound. Admission and the committed transition agree, even when no gate is due.
func TestReadinessCommitmentsMustEnterCommittedState(t *testing.T) {
	admit := func(w *world, schedule []vrschema.Activation, cs []vrschema.SupportCommitment) error {
		a := w.admission()
		a.Fold.Schedule = schedule
		id, _ := evmassign.CustodyID(w.j[0].StakingID)
		a.Certificate.Certificate = w.certificate(0, map[uint64][]vrschema.SupportCommitment{id: cs})
		_, err := VerifyRegistryOutput(a)
		return err
	}
	w := newWorld(t)
	var many []vrschema.SupportCommitment
	for i := 0; i < 65; i++ {
		many = append(many, w.commitment(w.j[0], vrschema.RuleID(fmt.Sprintf("unscheduled-%d", i))))
	}
	sort.Slice(many, func(i, j int) bool { return bytes.Compare(many[i].RuleID, many[j].RuleID) < 0 })
	err := admit(w, nil, many)
	require.ErrorIs(t, err, ErrActivation)
	require.ErrorIs(t, err, ErrSupport)

	far := vrschema.Activation{RuleID: vrschema.RuleID("far"), RootEpoch: 50, State: vrschema.ActActive, ChangeID: 1}
	require.ErrorIs(t, admit(w, []vrschema.Activation{far}, many[:1]), ErrSupport, "one unscheduled rule, no gate due")
	require.NoError(t, admit(w, []vrschema.Activation{far}, []vrschema.SupportCommitment{w.commitment(w.j[0], far.RuleID)}),
		"a commitment for a scheduled rule, not yet required")
	other := w.commitment(w.j[0], far.RuleID)
	other.Network = fxNetwork + 1
	msg, err := other.SignedBytes()
	require.NoError(t, err)
	other.Sig, err = w.signer(other.StakingID).signer.SignBytes(msg)
	require.NoError(t, err)
	require.ErrorIs(t, admit(w, []vrschema.Activation{far}, []vrschema.SupportCommitment{other}), ErrSupport, "another network")
}

// astra 3 and sol 2: materialization prunes the outgoing bindings before the bound is enforced, so a full committee that replaces a member
// (ids 1..16 -> 2..17) or rotates a binding materializes into the final 16-member table.
func TestMaterializePrunesBeforeTheBound(t *testing.T) {
	w := newWorld(t)
	for i := uint64(6); i <= 17; i++ {
		w.members[i] = member{id: i, root: fmt.Sprintf("r%02d", i), evm: fmt.Sprintf("e%02d", i), rk: mkKey(t, byte(40+i)), ek: mkKey(t, byte(80+i))}
	}
	rule := vrschema.RuleID("fork")
	var old, next []evmassign.Identity
	var table SupportTable
	for i := uint64(1); i <= 17; i++ {
		id := w.identity(i)
		if i <= 16 {
			old = append(old, id)
			var err error
			table, err = table.Add(w.commitment(id, rule))
			require.NoError(t, err)
		}
		if i >= 2 {
			next = append(next, id)
		}
	}
	require.Len(t, table.Entries, 16)
	var readiness []vrschema.Readiness
	for _, id := range next {
		readiness = append(readiness, vrschema.Readiness{Commitments: []vrschema.SupportCommitment{w.commitment(id, rule)}})
	}
	got, err := MaterializeJ(table, readiness, next)
	require.NoError(t, err)
	require.Len(t, got.Entries, 16)
	for _, e := range got.Entries {
		_, ok := memberByID(next, e.StakingID)
		require.True(t, ok, "only the new committee's bindings remain")
	}

	// a rotated binding: the old entry is pruned and the new one materializes
	rotated := append([]evmassign.Identity(nil), old...)
	rotated[3].Generation = 2
	rs := []vrschema.Readiness{{Commitments: []vrschema.SupportCommitment{w.commitment(rotated[3], rule)}}}
	got, err = MaterializeJ(table, rs, rotated)
	require.NoError(t, err)
	require.Len(t, got.Entries, 16)

	// a commitment of a binding outside keep never enters the table
	got, err = MaterializeJ(SupportTable{}, readiness, next[:3])
	require.NoError(t, err)
	require.Len(t, got.Entries, 3)
}

// astra 4: a proven network word other than the deployment's is a proven admission failure, so a Published R is due as Invalid, and
// past its expiry as Expired; neither is refused by an unconditional network guard.
func TestWrongNetworkWordIsRejectable(t *testing.T) {
	dep := Deployment{RootNetwork: 3, NetworkWord: vrschema.Keccak([]byte("net"))}
	r := vrschema.Keccak([]byte("R"))
	s := RejectState{Progress: 100, Output: OutputState{ResultID: r, Network: vrschema.Keccak([]byte("another network")),
		Output: vrschema.OutputRecord{State: vrschema.OutPublished, ExpiresAtProgress: 100 + vrschema.Lifetime, Predecessor: vrschema.GenesisResult}}}
	require.True(t, AdmissionFailsAtP(s.Output, dep, vrschema.GenesisResult, vrschema.Word{}))
	require.NoError(t, VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: vrschema.RejInvalid}, dep, vrschema.GenesisResult, vrschema.Word{}))
	require.ErrorIs(t, VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: vrschema.RejExpired}, dep, vrschema.GenesisResult, vrschema.Word{}),
		ErrReject, "not expired yet")
	s.Progress = 100 + vrschema.Lifetime
	require.NoError(t, VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: vrschema.RejExpired}, dep, vrschema.GenesisResult, vrschema.Word{}),
		"past its expiry it is Expired")
	s.Output.Output.State = vrschema.OutReserved
	s.Progress = 100
	require.ErrorIs(t, VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: vrschema.RejInvalid}, dep, vrschema.GenesisResult, vrschema.Word{}),
		ErrReject, "a Reserved R is never Invalid")
}

// sol r2: with a scheduled rule not yet due (E = 50, e_J = 2), every evidence item is still resolved and authenticated: a fresh
// commitment with a forged signature, a reference absent from the committed table and a K readiness with a forged envelope are refused.
func TestEvidenceVerifiesWhenNoGateIsDue(t *testing.T) {
	w := newWorld(t)
	far := vrschema.Activation{RuleID: vrschema.RuleID("far"), RootEpoch: 50, State: vrschema.ActActive, ChangeID: 1}
	admit := func(ev vrschema.RuleSupportEvidence) error {
		a := w.admission()
		a.Fold.Schedule = []vrschema.Activation{far}
		a.Support.Evidence = ev
		_, err := VerifyRegistryOutput(a)
		return err
	}
	require.NoError(t, admit(vrschema.RuleSupportEvidence{}), "the control: no evidence, no gate due")
	good := w.commitment(w.k[0], far.RuleID)
	require.NoError(t, admit(vrschema.RuleSupportEvidence{Fresh: []vrschema.SupportCommitment{good}}), "a valid fresh commitment")

	forged := good
	forged.Sig = make([]byte, 65)
	require.ErrorIs(t, admit(vrschema.RuleSupportEvidence{Fresh: []vrschema.SupportCommitment{forged}}), ErrSupport, "a 65-zero-byte signature")

	ref, err := good.Digest()
	require.NoError(t, err)
	require.ErrorIs(t, admit(vrschema.RuleSupportEvidence{Refs: [][]byte{ref[:]}}), ErrSupport, "a reference absent from the committed table")

	raw, err := w.cand.Encode()
	require.NoError(t, err)
	kr := w.readiness(w.k[0], 0, raw, []vrschema.SupportCommitment{good})
	require.NoError(t, admit(vrschema.RuleSupportEvidence{KReadiness: []vrschema.Readiness{kr}}), "a valid K readiness")
	kr.EnvelopeSig = w.readiness(w.k[1], 0, raw, nil).EnvelopeSig
	require.ErrorIs(t, admit(vrschema.RuleSupportEvidence{KReadiness: []vrschema.Readiness{kr}}), ErrSupport, "a forged K-readiness envelope")
}
