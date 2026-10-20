package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
)

// P6 (#53): transport agents across the proposal -> selection boundary. Agents fetch the elected candidate with its proofs and
// propose it; the root's Prepare selects ONE body for the open attempt, and from then on only that body's Freeze (endorsed by the
// old committee) is ordered. A competing or stale agent's candidate is refused at the boundary and changes nothing; a committed
// Abort ends the attempt for every agent; an agent that never delivers lets the Prepare lapse, after which only the next attempt
// (after the cooldown) may be prepared. Each refusal is a block the store does not add, so the control state stays as it was.
func TestTransportAgentsAcrossTheProposalSelectionBoundary(t *testing.T) {
	newFixture := func(t *testing.T) *assignmentFixture {
		f := newAssignmentFixture(t)
		f.useRealOrchestration(t)
		f.seedFees(t)
		return f
	}
	phaseAt := func(t *testing.T, f *assignmentFixture, round uint64) string {
		return mustBlock(t, f.store, round).ShardState.Control.Phase
	}

	t.Run("after the Prepare selected agent A's body, competing and stale agents are refused and A's Freeze commits", func(t *testing.T) {
		f := newFixture(t)
		a := f.build(t, f.candidate(t))
		// agent B transports the same Election result but a different successor body (another state summary)
		otherBody := f.build(t, f.candidate(t), func(_ *FreezeAssignmentAuthorization, b *evmroot.TrustBaseBodyV2) {
			b.StateSummary = bytes.Repeat([]byte{4}, 32)
		})
		require.NotEqual(t, a.freeze.NextBodyID, otherBody.freeze.NextBodyID)
		// agent C transports a candidate under another Election result
		otherResult := f.build(t, freshResult(f.candidate(t), 9))
		require.NotEqual(t, a.freeze.NextBodyID, otherResult.freeze.NextBodyID)
		// agent D is stale: it built its candidate for the next attempt while attempt 0 is open
		f.pop.Attempt = 1
		stale := f.build(t, f.candidate(t))
		f.pop.Attempt = 0
		// agent A' recomputes A's candidate independently: the same bytes (agents agree on the certified candidate)
		again := f.build(t, f.candidate(t))
		require.Equal(t, a.freeze.Bytes(), again.freeze.Bytes())
		require.Equal(t, a.companion, again.companion)

		addProfileBlock(t, f.store, 2, [][]byte{a.prepare.Bytes()})
		require.Equal(t, "prepared", phaseAt(t, f, 2))
		for _, c := range []struct {
			name, why string
			b         builtFreeze
		}{
			{"another body of the same result", "does not match its Prepare (phase prepared, lapsed false)", otherBody},
			{"another result", "does not match its Prepare (phase prepared, lapsed false)", otherResult},
			{"a stale attempt", "not of the open attempt", stale},
		} {
			err := f.tryAt(t, 3, c.b.freeze.Bytes(), c.b.companion)
			require.ErrorIs(t, err, ErrHandoffRecord, c.name)
			require.ErrorContains(t, err, c.why, c.name)
		}
		// a competing Prepare cannot replace the selection while its attempt is live
		require.ErrorIs(t, f.tryAt(t, 3, otherBody.prepare.Bytes()), ErrHandoffRecord, "one live attempt")
		require.Equal(t, "prepared", phaseAt(t, f, 2), "the refusals changed nothing")
		f.addAt(t, 3, again.freeze.Bytes(), again.companion)
		require.NotEqual(t, "prepared", phaseAt(t, f, 3), "the selected body's Freeze is ordered")
		ordered, err := DecodeOrderedHandoffRecord(mustBlock(t, f.store, 3).ShardState.Control.RecordBytes)
		require.NoError(t, err)
		require.Equal(t, a.freeze.NextBodyID, ordered.NextBodyID)
	})

	t.Run("a committed Abort ends the attempt: the agent's late Freeze is refused", func(t *testing.T) {
		f := newFixture(t)
		a := f.build(t, f.candidate(t))
		addProfileBlock(t, f.store, 2, [][]byte{a.prepare.Bytes()})
		abort := a.prepare
		abort.Kind, abort.OrderedRound = "abort", 3
		f.addAt(t, 3, abort.Bytes(), f.abortCompanionFor(t, abort))
		require.Equal(t, "aborted", phaseAt(t, f, 3))
		late := a.freeze
		late.OrderedRound = 4
		require.ErrorIs(t, f.tryAt(t, 4, late.Bytes(), a.companion), ErrFreezeBeforePrepare)
		require.Equal(t, "aborted", phaseAt(t, f, 3))
		// a retry of the same Election result under the next attempt is ErrResolvedResult
		// (TestARetryOfAnAbortedPrimaryCannotReuseItsElectionResult)
	})

	t.Run("an agent that never delivers: the Prepare lapses, its late Freeze is refused, the next attempt waits for the cooldown", func(t *testing.T) {
		f := newFixture(t)
		a := f.build(t, f.candidate(t))
		addProfileBlock(t, f.store, 2, [][]byte{a.prepare.Bytes()})
		lapse := uint64(2 + PrepareFreezeLapseRounds + 1)
		for r := uint64(3); r < lapse; r++ {
			f.addAt(t, r)
		}
		late := a.freeze
		late.OrderedRound = lapse
		err := f.tryAt(t, lapse, late.Bytes(), a.companion)
		require.ErrorIs(t, err, ErrHandoffRecord, "a Freeze for the lapsed attempt")
		require.ErrorContains(t, err, "lapsed true")
		f.pop.Attempt = 1
		cooldownEnd := uint64(2 + PrepareFreezeLapseRounds + PrepareCooldownRounds)
		f.base = lapse
		early := f.build(t, f.candidate(t))
		err = f.tryAt(t, lapse, early.prepare.Bytes())
		require.ErrorIs(t, err, ErrHandoffRecord, "a Prepare before the cooldown")
		require.ErrorContains(t, err, "before the cooldown")
		for r := lapse; r <= cooldownEnd; r++ {
			f.addAt(t, r)
		}
		f.base = cooldownEnd + 1
		next := f.build(t, f.candidate(t))
		f.addAt(t, cooldownEnd+1, next.prepare.Bytes())
		require.Equal(t, "prepared", phaseAt(t, f, cooldownEnd+1))
		require.Equal(t, uint64(1), mustBlock(t, f.store, cooldownEnd+1).ShardState.Control.Attempt)
	})
}
