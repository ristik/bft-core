package storage_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// verified is the history entry of the fixture's activation and the genesis entry before it.
func verified(t *testing.T, f *q3fixture.Fixture) (activated, genesis q3format.Entry) {
	t.Helper()
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	next, err := h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	return next.Tip(), h.Tip()
}

func TestWeightedRequestPolicyIsSelectedOnlyByAVerifiedActivation(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	entry, genesis := verified(t, f)
	record := f.Proof.Record

	t.Run("the activation counts requests by the mirrored weights", func(t *testing.T) {
		a, err := storage.ActivationFromVerifiedV3(entry, record, f.Candidate, crypto.SHA256, 1)
		require.NoError(t, err)
		ctx := a.RequestContext()
		require.Equal(t, quorumweight.PolicyEVMWeighted, ctx.Policy())
		require.EqualValues(t, 9, ctx.TotalWeight())
		require.EqualValues(t, 5, ctx.Threshold(), "EVM majority of W=9")
		weights := map[uint64]int{}
		for _, id := range ctx.NodeIDs() {
			w, err := ctx.SignerWeight(id)
			require.NoError(t, err)
			weights[w]++
		}
		require.Equal(t, map[uint64]int{6: 1, 1: 3}, weights)
		require.True(t, ctx.QuorumReached(6), "the heavy validator alone certifies")
		require.False(t, ctx.QuorumReached(3), "three light validators cannot")
		impossible, err := ctx.QuorumImpossible(3, 3)
		require.NoError(t, err)
		require.False(t, impossible, "three lights cannot prove impossibility with the heavy validator unseen")
		require.EqualValues(t, 2, ctx.RootEpoch())
		body := entry.BodyID()
		require.Equal(t, body[:], ctx.RootBodyID())
	})

	t.Run("a legacy or zero entry has no weighted branch", func(t *testing.T) {
		for name, e := range map[string]q3format.Entry{"zero": {}, "genesis": genesis} {
			_, err := storage.ActivationFromVerifiedV3(e, record, f.Candidate, crypto.SHA256, 1)
			require.ErrorIs(t, err, storage.ErrRecordNotCommitted, name)
		}
	})
	t.Run("the record must be the committed one", func(t *testing.T) {
		mutations := map[string]func(*evmroot.OrderedHandoffRecord){
			"another attempt":    func(r *evmroot.OrderedHandoffRecord) { r.Attempt++ },
			"another boundary":   func(r *evmroot.OrderedHandoffRecord) { r.ActivationRound++ },
			"another epoch":      func(r *evmroot.OrderedHandoffRecord) { r.Epoch++ },
			"a freeze":           func(r *evmroot.OrderedHandoffRecord) { r.Kind = "freeze" },
			"another successor":  func(r *evmroot.OrderedHandoffRecord) { r.SuccessorTRHash = make([]byte, 32) },
			"another body":       func(r *evmroot.OrderedHandoffRecord) { r.NextBodyID = make([]byte, 32) },
			"another predecesor": func(r *evmroot.OrderedHandoffRecord) { r.PredecessorBodyID = make([]byte, 32) },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				r := record
				mutate(&r)
				_, err := storage.ActivationFromVerifiedV3(entry, r, f.Candidate, crypto.SHA256, 1)
				require.ErrorIs(t, err, storage.ErrRecordNotCommitted)
			})
		}
	})
	t.Run("the candidate must be the one the body binds", func(t *testing.T) {
		_, err := storage.ActivationFromVerifiedV3(entry, record, append(append([]byte(nil), f.Candidate...), 0), crypto.SHA256, 1)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
		_, err = storage.ActivationFromVerifiedV3(entry, record, nil, crypto.SHA256, 1)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	})
}

// Each property of the candidate is wrong in turn, with every hash of the chain consistent with the edit: the body binds the edited
// candidate, so only the guard under test can refuse it.
func TestAWeightedCandidateThatIsNotTheActivatedCommitteeIsRefused(t *testing.T) {
	cases := map[string]struct {
		opts q3fixture.Options
		want error
	}{
		"an EVM weight that does not mirror its root member":        {q3fixture.Options{Assignment: true, EVMWeights: []uint64{2, 2, 2, 2}}, storage.ErrAssignmentHistory},
		"a root committee with other weights, coupled consistently": {q3fixture.Options{Assignment: true, CandidateRootWeights: []uint64{3, 3, 3, 3}}, storage.ErrAssignmentHistory},
		"a root committee with another key": {q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) {
			c.RootMembers[1].Key = c.RootMembers[2].Key
		}}, storage.ErrAssignmentHistory},
		"a root committee of more members": {q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) {
			c.RootMembers = append(c.RootMembers, evmassign.RootMember{NodeID: "z-extra", Key: c.RootMembers[0].Key, Weight: 1})
		}}, storage.ErrAssignmentHistory},
		"a root committee of fewer members": {q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) {
			c.RootMembers = c.RootMembers[:3]
		}}, storage.ErrAssignmentHistory},
		"another network": {q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) { c.Network++ }}, storage.ErrAssignmentHistory},
		"another attempt": {q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) { c.Attempt++ }}, storage.ErrAssignmentHistory},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := q3fixture.New(t, tc.opts)
			entry, _ := verified(t, f)
			_, err := storage.ActivationFromVerifiedV3(entry, f.Proof.Record, f.Candidate, crypto.SHA256, 1)
			require.ErrorIs(t, err, tc.want)
		})
	}
}
