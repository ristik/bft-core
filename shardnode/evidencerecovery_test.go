package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

/*
The two halves against each other, over genuinely signed certificates: the real requester as the real
applier's TargetSource, with only the network and the executor stubbed.

It exists because both halves passed their own fixtures while disagreeing with each other. The
requester decided readiness from the certificate's IDENTITY and the applier from the whole
CERTIFICATE, and a repeat — same round, same input record, a later root round — falls exactly in the
gap: the requester answered "already ready" and did nothing, the applier answered "that target was
verified against another certificate" and refused, and the node sat between them making no progress
while every unit test passed. A fixture that only ever asks one half a question cannot find that.
*/

type recoveryPair struct {
	*recoveryFixture
	applier *TargetApplier
	ex      *stubExecutor
}

func newRecoveryPair(t *testing.T, fetch fetchFunc) *recoveryPair {
	t.Helper()
	rf := newRecoveryFixture(t, []peer.ID{"a"}, testBudget(), fetch)
	ex := &stubExecutor{}
	a, err := NewTargetApplier(ApplyConfig{
		Executor: ex,
		Source:   rf.req, // the real requester, satisfying TargetSource
		Budget:   testApplyBudget(),
		Now:      rf.clock.now,
	})
	require.NoError(t, err)
	return &recoveryPair{recoveryFixture: rf, applier: a, ex: ex}
}

// recoverFor runs one full cycle for the certificate held: ask, then apply.
func (p *recoveryPair) recoverFor(t *testing.T, link EvidenceLink, head BlockRef) ApplyResult {
	t.Helper()
	require.NoError(t, p.req.Need())
	st := p.settled(t)
	require.Equal(t, RecoveryReady, st.State, "recovery did not become ready: %v", st.LastErr)
	binding, err := BindingFor(link.UC)
	require.NoError(t, err)
	return p.applier.Apply(context.Background(), binding, head)
}

/*
The measured situation carried through end to end, and then across a repeat.

A repeat is an ordinary product of a root-chain timeout, so a node that recovers and then sees one is
not an edge case — it is what a quiet shard does whenever the root chain misses a round.
*/
func TestAnchorRecovery_RequesterAndApplierAgreeAcrossARepeat(t *testing.T) {
	stateB, blockB := h32(0x0b), h32(0xbb)
	var full AnchorEvidence
	fetches := 0
	p := newRecoveryPair(t, func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) {
		fetches++
		return full, nil
	})
	f := p.evidenceFixture
	source, mid, head := quietTailChain(f)
	full = bundleOf(source, mid, head)

	behind := BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))}
	recovered := BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}
	p.ex.head = func(context.Context) (BlockRef, error) { return recovered, nil }

	// 1. The node is a block behind across a quiet tail, and recovers.
	p.observe(t, source, mid, head)
	res := p.recoverFor(t, head, behind)
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	require.Equal(t, Hash(blockB), res.Target.BlockHash)
	require.Equal(t, 1, fetches)

	// 2. The root chain times out and re-certifies round 16: the SAME input record, so the same
	//    identity, at a later root round, assigning a different next round.
	repeat := f.cert(16, 125, stateB, stateB, nil, 21)
	p.observe(t, repeat)

	// The target is not ready for it until it has been carried — identity alone would have said it
	// was, which is the disagreement this fixture exists for.
	_, ok := p.req.Target()
	require.False(t, ok, "a target verified against root round 120 is not one for root round 125")

	// 3. And the cycle completes anyway: the requester carries the retained bundle across the repeat
	//    LOCALLY, with no second request, and the applier accepts the result.
	res = p.recoverFor(t, repeat, behind)
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	require.Equal(t, 1, fetches, "carrying a retained bundle across a repeat asks nobody")

	vt, ok := p.req.Target()
	require.True(t, ok)
	require.EqualValues(t, 125, vt.For.RootRound, "the binding followed the repeat")
	require.Equal(t, Hash(blockB), vt.Anchor.BlockHash, "and it is still the same block")
	require.Equal(t, 2, p.applier.Status().Applied)
}

// The same agreement across an ordinary quiet round, where the identity DOES change — the case that
// worked before, kept so a fix aimed at repeats cannot break it.
func TestAnchorRecovery_RequesterAndApplierAgreeAcrossAQuietRound(t *testing.T) {
	stateB, blockB := h32(0x0b), h32(0xbb)
	var full AnchorEvidence
	fetches := 0
	p := newRecoveryPair(t, func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) {
		fetches++
		return full, nil
	})
	f := p.evidenceFixture
	source, mid, head := quietTailChain(f)
	full = bundleOf(source, mid, head)
	behind := BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))}
	p.ex.head = func(context.Context) (BlockRef, error) {
		return BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}, nil
	}

	p.observe(t, source, mid, head)
	require.Equal(t, ApplyApplied, p.recoverFor(t, head, behind).Outcome)

	next := f.cert(19, 130, stateB, stateB, nil, 23) // the round 16 assigned, still quiet
	p.observe(t, next)
	_, ok := p.req.Target()
	require.False(t, ok)

	res := p.recoverFor(t, next, behind)
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	require.Equal(t, 1, fetches)
}

/*
And the other direction: a node whose executor is still syncing across a quiet tail keeps getting
attempts as certificates arrive. This is the pairing of §6.3's carry with §6.4's per-certificate
renewal, and it is the case a state-keyed budget stranded.
*/
func TestAnchorRecovery_ASyncingExecutorKeepsGettingAttempts(t *testing.T) {
	stateB, blockB := h32(0x0b), h32(0xbb)
	var full AnchorEvidence
	p := newRecoveryPair(t, func(context.Context, peer.ID, EvidenceRequest) (AnchorEvidence, error) {
		return full, nil
	})
	f := p.evidenceFixture
	source, mid, head := quietTailChain(f)
	full = bundleOf(source, mid, head)
	behind := BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))}

	syncing := true
	p.ex.commit = func(context.Context, Hash) (Status, error) {
		if syncing {
			return StatusSyncing, nil
		}
		return StatusValid, nil
	}
	p.ex.head = func(context.Context) (BlockRef, error) {
		return BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}, nil
	}

	p.observe(t, source, mid, head)
	require.NoError(t, p.req.Need())
	require.Equal(t, RecoveryReady, p.settled(t).State)

	// Spend the whole budget for the certificate held, while the executor is still syncing.
	held, err := BindingFor(head.UC)
	require.NoError(t, err)
	for i := 0; i < testApplyBudget().MaxAttempts; i++ {
		require.Equal(t, ApplyPayloadUnavailable, p.applier.Apply(context.Background(), held, behind).Outcome)
		p.clock.advance(2 * time.Second)
	}
	require.Equal(t, ApplyExhausted, p.applier.Apply(context.Background(), held, behind).Outcome)

	// The shard stays quiet — the state root never moves — and the payload arrives. The next
	// certificate is what gives this node its next attempt.
	syncing = false
	next := f.cert(19, 130, stateB, stateB, nil, 23)
	p.observe(t, next)
	res := p.recoverFor(t, next, behind)
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	require.Equal(t, 1, p.applier.Status().Applied)
}
