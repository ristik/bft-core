package vradmit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// supportCase is a gate input over the fixture: J the fixture's successors with fresh commitments for rule in their readiness, K the
// given members, every K member in supporters committed in the table and referenced by the evidence.
func supportCase(t *testing.T, w *world, rule vrschema.Activation, k []evmassign.Identity, supporters []evmassign.Identity) SupportInput {
	var table SupportTable
	var refs [][]byte
	var err error
	for _, m := range supporters {
		c := w.commitment(m, rule.RuleID)
		if table, err = table.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range table.Entries {
		d, _ := e.Digest()
		refs = append(refs, d[:])
	}
	sortRefs(refs)
	cs := map[uint64][]vrschema.SupportCommitment{}
	for _, m := range w.j {
		id, _ := evmassign.CustodyID(m.StakingID)
		cs[id] = []vrschema.SupportCommitment{w.commitment(m, rule.RuleID)}
	}
	cert := w.certificate(0, cs)
	return SupportInput{Network: fxNetwork, SuccessorEpoch: 2, Schedule: []vrschema.Activation{rule}, Table: table,
		Evidence: vrschema.RuleSupportEvidence{Refs: refs}, Readiness: cert.Readiness, IntentDigest: w.intent[:], J: w.j, K: k}
}

func sortRefs(rs [][]byte) {
	for i := range rs {
		for j := i + 1; j < len(rs); j++ {
			if string(rs[j]) < string(rs[i]) {
				rs[i], rs[j] = rs[j], rs[i]
			}
		}
	}
}

// The VT-05a RuleSupport acceptance rows: 4/5 K support admits; exactly 2/3 waits; a binding replacement invalidates the commitment;
// latched rules need no new commitment.
func TestRuleSupportGate(t *testing.T) {
	w := newWorld(t)
	rule := vrschema.Activation{RuleID: vrschema.RuleID("fork-a"), RootEpoch: 3, State: vrschema.ActActive, ChangeID: 1}
	five := []evmassign.Identity{w.identity(1), w.identity(2), w.identity(3), w.identity(4), w.identity(5)}

	t.Run("4/5 of K admits", func(t *testing.T) {
		require.NoError(t, VerifyRuleSupport(supportCase(t, w, rule, five, five[:4])))
	})
	t.Run("exactly 2/3 of K waits", func(t *testing.T) {
		in := supportCase(t, w, rule, five[:3], five[:2])
		require.ErrorIs(t, VerifyRuleSupport(in), ErrSupportWait)
	})
	t.Run("a binding replacement invalidates the commitment", func(t *testing.T) {
		in := supportCase(t, w, rule, five, five[:4])
		rotated := append([]evmassign.Identity(nil), five...)
		rotated[0].Generation = 2 // member 1 rotated its binding after committing
		in.K = rotated
		require.ErrorIs(t, VerifyRuleSupport(in), ErrSupportWait, "3/5 is not more than 2/3")
	})
	t.Run("a successor without fresh support waits", func(t *testing.T) {
		in := supportCase(t, w, rule, five, five)
		in.Readiness = w.certificate(0, nil).Readiness
		require.ErrorIs(t, VerifyRuleSupport(in), ErrSupportWait)
	})
	t.Run("a latched rule needs no new commitment", func(t *testing.T) {
		latched := rule
		latched.State = vrschema.ActLatched
		in := supportCase(t, w, latched, five, nil)
		in.Readiness = w.certificate(0, nil).Readiness // no fresh commitments at all
		for _, m := range w.j {
			var err error
			in.Table, err = in.Table.Add(w.commitment(m, rule.RuleID))
			require.NoError(t, err)
		}
		require.NoError(t, VerifyRuleSupport(in))
	})
	t.Run("a rule beyond e_J + 1 needs nothing", func(t *testing.T) {
		far := rule
		far.RootEpoch = 4
		in := supportCase(t, w, far, five, nil)
		in.Readiness = w.certificate(0, nil).Readiness
		require.NoError(t, VerifyRuleSupport(in))
	})
	t.Run("an unknown reference refuses", func(t *testing.T) {
		in := supportCase(t, w, rule, five, five[:4])
		in.Table = SupportTable{}
		err := VerifyRuleSupport(in)
		require.ErrorIs(t, err, ErrSupport)
		require.NotErrorIs(t, err, ErrSupportWait)
	})
	t.Run("K readiness counts as support", func(t *testing.T) {
		in := supportCase(t, w, rule, five, nil)
		raw, err := w.cand.Encode()
		require.NoError(t, err)
		for _, m := range five[:4] {
			in.Evidence.KReadiness = append(in.Evidence.KReadiness, w.readiness(m, 0, raw, []vrschema.SupportCommitment{w.commitment(m, rule.RuleID)}))
		}
		require.NoError(t, VerifyRuleSupport(in))
	})
}

func TestRuleSupportControl(t *testing.T) {
	w := newWorld(t)
	rule := vrschema.RuleID("fork-a")
	sched := []vrschema.Activation{{RuleID: rule, RootEpoch: 9, State: vrschema.ActActive, ChangeID: 1}}
	c := w.commitment(w.k[0], rule)
	tbl, err := ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{c}, w.k, sched)
	require.NoError(t, err)
	require.Len(t, tbl.Entries, 1)

	_, err = ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{w.commitment(w.identity(5), rule)}, w.k, sched)
	require.ErrorIs(t, err, ErrSupport, "not a committee binding")
	_, err = ApplyRuleSupport(SupportTable{}, fxNetwork+1, []vrschema.SupportCommitment{c}, w.k, sched)
	require.ErrorIs(t, err, ErrSupport, "another network")
	_, err = ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{w.commitment(w.k[0], vrschema.RuleID("x"))}, w.k, sched)
	require.ErrorIs(t, err, ErrSupport, "no such rule")
	forged := c
	forged.Sig = w.commitment(w.k[1], rule).Sig
	_, err = ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{forged}, w.k, sched)
	require.ErrorIs(t, err, ErrSupport, "another key's signature")

	// a newer commitment of the pair replaces the old; pruning keeps exactly the current bindings
	again := w.commitment(w.k[0], rule)
	tbl, err = tbl.Add(again)
	require.NoError(t, err)
	require.Len(t, tbl.Entries, 1)
	rotated := append([]evmassign.Identity(nil), w.k...)
	rotated[0].Generation = 2
	require.Empty(t, tbl.Prune(rotated).Entries)
	require.Len(t, tbl.Prune(w.k).Entries, 1)

	raw, err := tbl.Encode()
	require.NoError(t, err)
	back, err := DecodeSupportTable(raw)
	require.NoError(t, err)
	require.Equal(t, tbl.Entries[0].Sig, back.Entries[0].Sig)
}

// An EVM-key-only rotation keeps the staking id, generation, root key and payee, but it is a new binding: a commitment made under the old
// binding must not count for it (#1286), while a fresh commitment by the same root key does.
func TestCommitmentDoesNotSurviveEVMOnlyRotation(t *testing.T) {
	w := newWorld(t)
	rule := vrschema.RuleID("fork-a")
	sched := []vrschema.Activation{{RuleID: rule, RootEpoch: 9, State: vrschema.ActActive, ChangeID: 1}}
	old := w.k[0]
	rotated := old
	rotated.EVMNodeID = old.EVMNodeID + "-rotated"
	rotated.EVMKey = w.identity(5).EVMKey
	require.NotEqual(t, old.BindingRef(), rotated.BindingRef())
	require.Equal(t, old.RootKey, rotated.RootKey)

	c := w.commitment(old, rule)
	require.NoError(t, VerifyCommitment(c, old))
	require.ErrorIs(t, VerifyCommitment(c, rotated), ErrSupport, "old-binding commitment against the rotated binding")

	members := append([]evmassign.Identity{rotated}, w.k[1:]...)
	_, err := ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{c}, members, sched)
	require.ErrorIs(t, err, ErrSupport, "ApplyRuleSupport refuses the old-binding commitment")

	tbl, err := ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{c}, w.k, sched)
	require.NoError(t, err)
	require.Len(t, tbl.Entries, 1)
	require.Empty(t, tbl.Prune(members).Entries, "prune drops the old-binding entry")
	require.Len(t, tbl.Prune(w.k).Entries, 1, "prune keeps it for the unchanged binding")

	fresh := w.commitment(rotated, rule)
	require.NoError(t, VerifyCommitment(fresh, rotated))
	tbl, err = ApplyRuleSupport(SupportTable{}, fxNetwork, []vrschema.SupportCommitment{fresh}, members, sched)
	require.NoError(t, err)
	require.Len(t, tbl.Entries, 1)

	// the binding ref is signed: rewriting it to the new binding invalidates the signature
	forged := c
	forged.BindingRef = fresh.BindingRef
	require.ErrorIs(t, VerifyCommitment(forged, rotated), ErrSupport, "replayed signature under a rewritten binding ref")
	short := c
	short.BindingRef = short.BindingRef[:31]
	require.ErrorIs(t, VerifyCommitment(short, old), ErrSupport, "shape")
}
