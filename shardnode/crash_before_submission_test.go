package shardnode

/*
F6i section 1: a fault before proposal submission (#14 position 1).

A process builds a candidate, the authority signs it, and the process dies before the request reaches
the root chain. A second process re-derives the round deterministically and arrives at the identical
candidate. The authority's retained response is what lets it recover without a second conflicting
vote: an identical re-request returns the retained bytes, and a different candidate for the same
assigned round is still refused.

One authority spans both processes, because the authority outlives the shard process by design (F6c).
Process A is a Round that signs through a real signingauthority.Authority and whose send fails, which
stands for a request that never left this host. Process B is fresh, over the same executor, and uses
the same authority session.
*/

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

// crashBeforeSubmission records what it was asked to send and fails every attempt, standing for a
// request that never reached the root chain. Round.send retries with the same signed bytes, so every
// recorded request is identical and the first is the signed candidate.
type crashBeforeSubmission struct {
	mu   sync.Mutex
	sent []*certification.BlockCertificationRequest
}

func (s *crashBeforeSubmission) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, req)
	return errors.New("the request never reached the root chain")
}

func (s *crashBeforeSubmission) first(t *testing.T) *certification.BlockCertificationRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.sent, "nothing was attempted")
	return s.sent[0]
}

// sizeVaryingExecutor is a steadyExecutor whose sealed block carries a different size, so a second
// process builds a candidate for the same round that differs from the first process's while the
// certified state still matches. The difference is what the authority refuses: a candidate that
// differed in state or block hash would fail P-id before the signer was reached.
type sizeVaryingExecutor struct {
	*steadyExecutor
	blockSize uint64
}

func (e *sizeVaryingExecutor) Seal(ctx context.Context, id BuildID) (Block, error) {
	b, err := e.steadyExecutor.Seal(ctx, id)
	if err != nil {
		return b, err
	}
	b.BlockSize = e.blockSize
	return b, nil
}

// crashRound builds one shard-node process: a Round over exec, signing through the authority session,
// with the given submitter. It is wiringFixture.round with the authority signer in place.
func crashRound(t *testing.T, f *wiringFixture, authority *signingauthority.Authority, session signingauthority.Session, exec Executor, sub Submitter) (*Round, *Health) {
	t.Helper()
	r := NewRound(wiringNodeID, authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), f.signer, sub, nil)
	health := NewHealth()
	r.SetHealth(health)
	r.SetCertificationSigner(authoritySignerFor(t, signingauthority.NewLocalClient(authority, session), f.authorityKey(t, authority)))
	return r, health
}

// TestCrashBeforeSubmissionRecoversTheRetainedSignature: the identical candidate after the crash gets
// the one retained statement back. Nothing here is a second signature or a conflict.
func TestCrashBeforeSubmissionRecoversTheRetainedSignature(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	authority, session := f.authorityFor(t)

	// Process A: it builds and signs round 6, and the send fails.
	exec := &steadyExecutor{head: BlockRef{Number: 5, Hash: f.blockHash, StateRoot: f.stateRoot}}
	subA := &crashBeforeSubmission{}
	roundA, _ := crashRound(t, f, authority, session, exec, subA)
	require.ErrorIs(t, roundA.HandleCertificate(ctx, f.uc, f.tr), ErrSubmissionFailed,
		"the signed request never reached the root chain")
	aSigned := subA.first(t)

	statusA := authority.Status()
	require.True(t, statusA.HasReservation, "the authority reserved the round")
	require.EqualValues(t, 6, statusA.ReservedRound)
	require.True(t, statusA.ResponseRetained, "and retained the signed response before release")

	// Process A dies. Process B is fresh, over the same executor and the same authority session.
	subB := &countingSubmitter{}
	roundB, healthB := crashRound(t, f, authority, session, exec, subB)
	require.NoError(t, roundB.HandleCertificate(ctx, f.uc, f.tr),
		"the identical re-request is answered with the retained response, not refused")

	require.Len(t, subB.reqs, 1)
	aBytes, err := aSigned.Bytes()
	require.NoError(t, err)
	bBytes, err := subB.reqs[0].Bytes()
	require.NoError(t, err)
	require.Equal(t, aBytes, bBytes, "the authority released the one retained statement, byte for byte")

	statusB := authority.Status()
	require.EqualValues(t, 6, statusB.ReservedRound, "the reserved round is unchanged")
	require.True(t, statusB.ResponseRetained)
	require.True(t, healthB.Snapshot().Voting)
}

// TestCrashBeforeSubmissionStillRefusesADifferentCandidate: the boundary of the case above. A second
// process whose candidate differs must be refused, so the first test cannot pass because the
// authority is permissive.
func TestCrashBeforeSubmissionStillRefusesADifferentCandidate(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	authority, session := f.authorityFor(t)

	execA := &steadyExecutor{head: BlockRef{Number: 5, Hash: f.blockHash, StateRoot: f.stateRoot}}
	subA := &crashBeforeSubmission{}
	roundA, _ := crashRound(t, f, authority, session, execA, subA)
	require.ErrorIs(t, roundA.HandleCertificate(ctx, f.uc, f.tr), ErrSubmissionFailed)
	require.EqualValues(t, 6, authority.Status().ReservedRound)

	// Process B builds a DIFFERENT candidate for the same assigned round. The certified state still
	// matches, so P-id admits it, but the complete bytes differ and the authority refuses.
	execB := &sizeVaryingExecutor{
		steadyExecutor: &steadyExecutor{head: BlockRef{Number: 5, Hash: f.blockHash, StateRoot: f.stateRoot}},
		blockSize:      1,
	}
	subB := &countingSubmitter{}
	roundB, healthB := crashRound(t, f, authority, session, execB, subB)
	require.NoError(t, roundB.HandleCertificate(ctx, f.uc, f.tr),
		"a refusal is an abstention, not a processing error")

	require.Empty(t, subB.sent, "the different candidate is not signed")
	require.Contains(t, healthB.Snapshot().NonVotingReason, signingauthority.ErrConflict.Error())
	require.EqualValues(t, 6, authority.Status().ReservedRound, "the original reservation is untouched")
}
