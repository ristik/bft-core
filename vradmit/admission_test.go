package vradmit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func TestAdmissionAcceptsThePublishedOutput(t *testing.T) {
	w := newWorld(t)
	v, err := VerifyRegistryOutput(w.admission())
	require.NoError(t, err)
	require.Equal(t, []uint8{vrschema.VerdictAccepted}, v.Verdicts)
	require.Equal(t, w.cand.Assignment, v.Successor)
}

// TestAdmissionRefusesOnePerItem is the VT-05a acceptance row "admission refusals, one per section 5.2 item": each case breaks exactly
// one item of an otherwise valid admission and is refused with that item's error.
func TestAdmissionRefusesOnePerItem(t *testing.T) {
	cases := []struct {
		name   string
		item   error
		break_ func(w *world, a *Admission)
	}{
		{"1 VR network word", ErrNetwork, func(w *world, a *Admission) { a.State.Network = vrschema.Keccak([]byte("other")) }},
		{"1 root network", ErrNetwork, func(w *world, a *Admission) { a.Deployment.RootNetwork = 6 }},
		{"2 R not the open output", ErrNotOpen, func(w *world, a *Admission) { a.State.OpenOutput = vrschema.Keccak([]byte("other")) }},
		{"2 R not Published", ErrNotOpen, func(w *world, a *Admission) { a.State.Output.State = vrschema.OutReserved }},
		{"2 predecessor is not the root's acknowledged result", ErrNotOpen, func(w *world, a *Admission) { a.Acknowledged = vrschema.Keccak([]byte("x")) }},
		{"2 a pending pair", ErrNotOpen, func(w *world, a *Admission) { a.State.PendingPair = vrschema.Keccak([]byte("pair")) }},
		{"3 a member's payee", ErrCommit, func(w *world, a *Admission) {
			ids := append([]evmassignIdentity(nil), a.Candidate.Identities...)
			ids[0].OperatorPayee = append([]byte{0x77}, ids[0].OperatorPayee[1:]...)
			a.Candidate.Identities = ids
		}},
		{"3 a registry change not the bound one", ErrCommit, func(w *world, a *Admission) {
			p, _ := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(4), uint64(4), uint64(7))
			a.Candidate.RegistryChanges = []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits), Payload: p}}
		}},
		{"3 K is not the acknowledged committee", ErrCommit, func(w *world, a *Admission) { a.Lifecycle.Incumbent = w.j }},
		{"3 the authorization names another snapshot", ErrCommit, func(w *world, a *Admission) {
			auth := *a.Candidate.Authorization
			auth.SnapshotDigest = make([]byte, 32)
			a.Candidate.Authorization = &auth
		}},
		{"4 limits not reached and not closer", ErrLimits, func(w *world, a *Admission) {
			a.State.Limits = vrschema.CommitteeLimits{NMin: 5, NTarget: 5, NMax: 7}
		}},
		{"5 a missing PoP", ErrH3, func(w *world, a *Admission) { a.Candidate.PoPs = a.Candidate.PoPs[1:] }},
		{"5 a supersession carrying an Accepted root-side change", ErrH3, func(w *world, a *Admission) {
			add, _ := vrschema.EncodeChange(vrschema.KindAddPartition, []byte{1}, []byte{0x80})
			a.Candidate.Supersedes = &evmassign.Supersession{}
			a.Candidate.RegistryChanges = append(append([]vrschema.RegistryChange(nil), a.Candidate.RegistryChanges...),
				vrschema.RegistryChange{ID: 5, Kind: uint64(vrschema.KindAddPartition), Payload: add})
			w.cand = a.Candidate
			w.commit()
			a.State.Output = w.state.Output
		}},
		{"5 continuity", ErrH3, func(w *world, a *Admission) { a.Lifecycle.Policy.MaxM = 0; a.Lifecycle.Policy.MaxDistNum = 0 }},
		{"6 verdict", ErrVerdicts, func(w *world, a *Admission) {
			a.Candidate.RegistryChanges = []vrschema.RegistryChange{a.Candidate.RegistryChanges[0]}
			a.Candidate.RegistryChanges[0].Verdict = uint64(vrschema.VerdictConflict)
		}},
		{"6 EVM shard unacknowledged at the Freeze block", ErrAckGate, func(w *world, a *Admission) { a.EVMAcked = false }},
		{"7 activation time gate", ErrActivation, func(w *world, a *Admission) {
			a.Fold.Schedule = []vrschema.Activation{{RuleID: vrschema.RuleID("r"), RootEpoch: 3, NotBeforeUcTime: 5000, State: vrschema.ActActive, ChangeID: 1}}
		}},
		{"7 rule support", ErrActivation, func(w *world, a *Admission) {
			a.Fold.Schedule = []vrschema.Activation{{RuleID: vrschema.RuleID("r"), RootEpoch: 3, State: vrschema.ActActive, ChangeID: 1}}
		}},
		{"8 Inconsistent", ErrInconsistent, func(w *world, a *Admission) { a.State.Status.Health = vrschema.HealthInconsistent }},
		{"9 a readiness missing", ErrCertificate, func(w *world, a *Admission) {
			a.Certificate.Certificate.Readiness = a.Certificate.Certificate.Readiness[1:]
		}},
		{"9 an assembly of an uncommitted view", ErrCertificate, func(w *world, a *Admission) {
			a.Certificate.Certificate = w.certificate(1, nil)
		}},
		{"resolved", ErrResolved, func(w *world, a *Admission) { a.Resolved = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			a := w.admission()
			c.break_(w, &a)
			_, err := VerifyRegistryOutput(a)
			require.ErrorIs(t, err, c.item)
			for _, other := range []error{ErrNetwork, ErrNotOpen, ErrCommit, ErrLimits, ErrH3, ErrVerdicts, ErrAckGate, ErrActivation, ErrInconsistent, ErrCertificate, ErrResolved} {
				if other != c.item {
					require.NotErrorIs(t, err, other, "exactly one item is refused")
				}
			}
		})
	}
}

// TestNativeOutputsAreExemptFromLimits: CommitteeLimits judge module outputs only; |S| <= 16 holds for every output. The native
// output carries the real zero snapshot and policy digests VR writes for it (review #1172, astra 1): its authorization maps them to
// REGISTRY_NATIVE, so it passes both item 3 and the recovery authorization's nonzero rule in item 5, continuity still applied.
func TestNativeOutputsAreExemptFromLimits(t *testing.T) {
	w := newWorld(t)
	w.snap, w.pol, w.native = vrschema.Word{}, vrschema.Word{}, true
	w.build()
	w.state.Limits = vrschema.CommitteeLimits{NMin: 5, NTarget: 5, NMax: 7}
	a := w.admission()
	_, err := VerifyRegistryOutput(a)
	require.NoError(t, err)
	// the recovery path: the authorization the native J publishes is the one a recovery reproduces
	_, err = w.cand.Authorization.Digest()
	require.NoError(t, err)
	installed, err := evmassign.Activate(w.succ, 40)
	require.NoError(t, err)
	_, _, _, _, err = evmassign.DeriveRecovery(evmassign.Head{Candidate: V5Of(w.cand), Successor: w.succ}, installed)
	require.NoError(t, err)

	// the same zero words on a module output are still judged by the limits
	w.native = false
	w.build()
	w.state.Limits = vrschema.CommitteeLimits{NMin: 5, NTarget: 5, NMax: 7}
	_, err = VerifyRegistryOutput(w.admission())
	require.ErrorIs(t, err, ErrLimits)

	// continuity still applies to a native output
	w.native = true
	w.build()
	a = w.admission()
	a.Lifecycle.Policy.MaxM, a.Lifecycle.Policy.MaxDistNum = 0, 0
	_, err = VerifyRegistryOutput(a)
	require.ErrorIs(t, err, ErrH3)

	// a candidate that carries the raw zero words is refused at item 3 (and could never pass item 5)
	w.build()
	a = w.admission()
	auth := *a.Candidate.Authorization
	auth.SnapshotDigest, auth.Policies = make([]byte, 32), make([]byte, 32)
	a.Candidate.Authorization = &auth
	_, err = VerifyRegistryOutput(a)
	require.ErrorIs(t, err, ErrCommit)
}

func TestLimitsSatisfied(t *testing.T) {
	l := vrschema.CommitteeLimits{NMin: 5, NTarget: 6, NMax: 7}
	require.True(t, LimitsSatisfied(l, 4, 5))
	require.True(t, LimitsSatisfied(l, 3, 4), "strictly toward the range")
	require.False(t, LimitsSatisfied(l, 4, 4))
	require.False(t, LimitsSatisfied(l, 4, 3))
	require.True(t, LimitsSatisfied(l, 9, 8))
	require.False(t, LimitsSatisfied(l, 4, 9), "overshoot farther than before")
}

// TestServedBindingsAreHashVerified: captured-binding preimages from the unproven write-once view count only when they hash to the
// proven membersDigest (FD-16).
func TestServedBindingsAreHashVerified(t *testing.T) {
	w := newWorld(t)
	require.NoError(t, VerifyMembers(w.j, w.state.Output.MembersDigest))
	bad := append([]evmassignIdentity(nil), w.j...)
	bad[1].EVMNodeID = "z"
	require.ErrorIs(t, VerifyMembers(bad, w.state.Output.MembersDigest), ErrCommit)
}

// The supersession rule of item 5 (F6, approved by astra): an Accepted change of kind 6, 7 or 8 in a supersession is refused, a rejected
// one is allowed (it installs nothing), other kinds are unaffected, and a change the fold Accepts cannot pass labelled rejected: item 6
// refuses the false verdict.
func TestASupersessionCarriesNoAcceptedRootSideChange(t *testing.T) {
	sup := &evmassign.Supersession{}
	for _, k := range []uint8{vrschema.KindReplaceAggregator, vrschema.KindAddPartition, vrschema.KindUpdatePartition} {
		c := vrschema.CandidateV6{Supersedes: sup, RegistryChanges: []vrschema.RegistryChange{{ID: 5, Kind: uint64(k)}}}
		require.ErrorIs(t, supersessionChanges(c), ErrH3, "kind %d", k)
		c.RegistryChanges[0].Verdict = uint64(vrschema.VerdictInvalid)
		require.NoError(t, supersessionChanges(c), "kind %d rejected: the control", k)
		c.Supersedes = nil
		c.RegistryChanges[0].Verdict = 0
		require.NoError(t, supersessionChanges(c), "kind %d outside a supersession", k)
	}
	require.NoError(t, supersessionChanges(vrschema.CandidateV6{Supersedes: sup, RegistryChanges: []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits)}}}))

	// a false rejected verdict on a change the fold Accepts passes the item 5 rule by its label and is refused at item 6
	w := newWorld(t)
	a := w.admission()
	a.Candidate.RegistryChanges[0].Verdict = uint64(vrschema.VerdictConflict)
	_, err := VerifyRegistryOutput(a)
	require.ErrorIs(t, err, ErrVerdicts)
}
