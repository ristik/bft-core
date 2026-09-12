package signingauthority

/*
Step 2 of the F6c handoff (§8.2): the in-memory signing record, custody and fencing.

What these tests are about is what the authority refuses after it has already admitted something.
Step 1 established that a request is genuine; nothing there stops a genuine request being presented
twice, or a second genuine authorization asking for different bytes at a round already answered.

The crash model is the design's: the shard client is discarded at each boundary while the authority
survives, which is the case this profile exists to handle (§6). Authority death is the other
direction and is tested as permanent loss of both key and record.
*/

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// assignment builds a genuine authorization for `round`, with `blockSize` distinguishing otherwise
// identical proposals. Rounds are not consecutive in practice, so any round may be asked for.
func (f *fixture) assignment(t *testing.T, round, blockSize uint64) Request {
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{
		Round: round, Epoch: shardEpoch, Leader: testNodeID, StatHash: zero, FeeHash: zero,
	}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	certified := &types.InputRecord{
		Version: 1, RoundNumber: round - 1, Epoch: shardEpoch,
		PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], certified, f.pdr, 50+round, zero, trHash)
	f.signSealTo(t, uc, quorum(len(f.signers)))
	return Request{UC: uc, Technical: tr, Proposed: &certification.BlockCertificationRequest{
		PartitionID: testPartitionID, ShardID: types.ShardID{}, NodeID: testNodeID,
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: round, Epoch: shardEpoch,
			PreviousHash: uc.InputRecord.Hash, Hash: bytes.Repeat([]byte{0xa1}, 32),
			BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: uc.UnicitySeal.Timestamp,
		},
		BlockSize: blockSize, StateSize: 42,
	}}
}

func digestOf(t *testing.T, req Request) [32]byte {
	t.Helper()
	b, err := req.Proposed.Bytes()
	require.NoError(t, err)
	return sha256.Sum256(b)
}

// session opens an authority with its first client session, the way an operator would.
func (f *fixture) session(t *testing.T) (*Authority, Session) {
	t.Helper()
	a := f.authority(t)
	s, err := a.ReplaceSession()
	require.NoError(t, err)
	return a, s
}

// complete runs the whole sequence for one request and returns the released response.
func complete(t *testing.T, a *Authority, s Session, req Request) []byte {
	t.Helper()
	ctx := context.Background()
	auth, err := a.Reserve(ctx, s, req)
	require.NoError(t, err)
	require.NoError(t, a.Sign(s))
	require.NoError(t, a.RetainResponse(s))
	response, err := a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.NoError(t, err)
	return response
}

func TestTheAssignedRoundIsTheLock(t *testing.T) {
	ctx := context.Background()

	t.Run("the same request is admitted again, and answers identically", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		first := complete(t, a, s, f.assignment(t, 5, 11))
		second := complete(t, a, s, f.assignment(t, 5, 11))
		require.Equal(t, first, second, "a client that lost its answer retries rather than rebuilding")
	})

	t.Run("different complete bytes at that round are a conflict", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(r *certification.BlockCertificationRequest)
		}{
			{"block size", func(r *certification.BlockCertificationRequest) { r.BlockSize++ }},
			{"state size", func(r *certification.BlockCertificationRequest) { r.StateSize++ }},
			{"an empty proof instead of none", func(r *certification.BlockCertificationRequest) { r.ZkProof = []byte{} }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, 1)
				a, s := f.session(t)
				complete(t, a, s, f.assignment(t, 5, 11))

				other := f.assignment(t, 5, 11)
				tc.mutate(other.Proposed)
				_, err := a.Reserve(ctx, s, other)
				require.ErrorIs(t, err, ErrConflict, "the whole request is the lock, not its input record")
			})
		}
	})

	t.Run("a lower round is stale, even for identical bytes", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		earlier := f.assignment(t, 5, 11)
		complete(t, a, s, earlier)
		complete(t, a, s, f.assignment(t, 9, 11))

		_, err := a.Reserve(ctx, s, earlier)
		require.ErrorIs(t, err, ErrStale, "old delivery retries stop once newer signing work has superseded them")
	})

	t.Run("a gap is permitted when an authenticated assignment names the round", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		complete(t, a, s, f.assignment(t, 5, 11))
		auth, err := a.Reserve(ctx, s, f.assignment(t, 40, 11))
		require.NoError(t, err, "assigned rounds are not consecutive integers")
		require.EqualValues(t, 40, auth.AssignedRound)
	})
}

func TestCrashBoundariesKeepOneStatement(t *testing.T) {
	// The shard client is discarded at each boundary; the authority survives, and a replacement
	// client is fenced in. What must hold at every cut: the old session is refused, the round cannot
	// be reopened with different bytes, and a retry of the same request answers identically.
	ctx := context.Background()
	for _, cut := range []struct {
		name  string
		steps int
	}{
		{"before the reservation", 0},
		{"after the reservation", 1},
		{"after signing", 2},
		{"after the response is retained", 3},
		{"after the response is released", 4},
	} {
		t.Run(cut.name, func(t *testing.T) {
			f := newFixture(t, 1)
			a, old := f.session(t)
			req := f.assignment(t, 5, 11)
			// The round and digest the client would name, known before anything is reserved, so the
			// "before the reservation" cut can reach the same calls without having reserved.
			round, requested := uint64(5), digestOf(t, req)

			var released []byte
			if cut.steps >= 1 {
				auth, err := a.Reserve(ctx, old, req)
				require.NoError(t, err)
				require.Equal(t, round, auth.AssignedRound)
				require.Equal(t, requested, auth.UnsignedDigest)
			} else {
				require.False(t, a.Status().HasReservation, "nothing was asked for at all")
			}
			if cut.steps >= 2 {
				require.NoError(t, a.Sign(old))
			}
			if cut.steps >= 3 {
				require.NoError(t, a.RetainResponse(old))
			}
			if cut.steps >= 4 {
				var err error
				released, err = a.Release(old, round, requested)
				require.NoError(t, err)
			}

			// The client dies and the operator fences it out.
			fresh, err := a.ReplaceSession()
			require.NoError(t, err)
			_, err = a.Release(old, round, requested)
			require.ErrorIs(t, err, ErrFenced, "the old session cannot release after being fenced")

			if cut.steps >= 1 {
				require.True(t, a.Status().HasReservation, "fencing a client does not clear the record")
				changed := f.assignment(t, 5, 12)
				_, err = a.Reserve(ctx, fresh, changed)
				require.ErrorIs(t, err, ErrConflict, "a new client cannot reopen the round with different bytes")
			}

			// The replacement client repeats the same request and gets the same statement.
			after := complete(t, a, fresh, f.assignment(t, 5, 11))
			if released != nil {
				require.Equal(t, released, after, "a released response replays byte for byte")
			}
		})
	}
}

func TestFencingIsOperatorControlled(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1)
	a, old := f.session(t)
	auth, err := a.Reserve(ctx, old, f.assignment(t, 5, 11))
	require.NoError(t, err)
	require.NoError(t, a.Sign(old))
	require.NoError(t, a.RetainResponse(old))

	fresh, err := a.ReplaceSession()
	require.NoError(t, err)
	require.NotEqual(t, old, fresh)

	for _, op := range []struct {
		name string
		call func(s Session) error
	}{
		{"reserve", func(s Session) error { _, err := a.Reserve(ctx, s, f.assignment(t, 6, 11)); return err }},
		{"sign", func(s Session) error { return a.Sign(s) }},
		{"retain", func(s Session) error { return a.RetainResponse(s) }},
		{"release", func(s Session) error { _, err := a.Release(s, auth.AssignedRound, auth.UnsignedDigest); return err }},
	} {
		t.Run("the fenced client cannot "+op.name, func(t *testing.T) {
			require.ErrorIs(t, op.call(old), ErrFenced)
		})
	}

	t.Run("a client cannot mint a session", func(t *testing.T) {
		// Session has no exported field, so the zero value is all a caller outside this package can
		// construct, and it is never admitted.
		require.ErrorIs(t, a.Sign(Session{}), ErrFenced)
	})

	t.Run("the replacement inherits the record rather than a clean slate", func(t *testing.T) {
		response, err := a.Release(fresh, auth.AssignedRound, auth.UnsignedDigest)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.EqualValues(t, 5, a.Status().ReservedRound)
	})
}

func TestAnOlderNodeBackupCannotResetTheAuthority(t *testing.T) {
	// A whole older shard backup comes with its old session token and its old, lower round. Neither
	// moves the authority's history.
	ctx := context.Background()
	f := newFixture(t, 1)
	a, old := f.session(t)
	complete(t, a, old, f.assignment(t, 5, 11))
	complete(t, a, old, f.assignment(t, 9, 11))

	restored, err := a.ReplaceSession()
	require.NoError(t, err)
	_, err = a.Reserve(ctx, old, f.assignment(t, 5, 11))
	require.ErrorIs(t, err, ErrFenced, "the backup's own token is fenced")
	_, err = a.Reserve(ctx, restored, f.assignment(t, 5, 11))
	require.ErrorIs(t, err, ErrStale, "and its round is below what this authority has reserved")
	require.EqualValues(t, 9, a.Status().ReservedRound, "the authority's history is unchanged")
}

func TestAuthorityDeathLosesKeyAndRecordTogether(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1)
	a, s := f.session(t)
	auth, err := a.Reserve(ctx, s, f.assignment(t, 5, 11))
	require.NoError(t, err)
	require.NoError(t, a.Sign(s))
	require.NoError(t, a.RetainResponse(s))

	a.Close()

	status := a.Status()
	require.True(t, status.KeyLost)
	require.False(t, status.HasReservation, "a record that outlived its key would describe signing nothing can perform")

	_, err = a.Reserve(ctx, s, f.assignment(t, 6, 11))
	require.ErrorIs(t, err, ErrKeyLost)
	require.ErrorIs(t, a.Sign(s), ErrKeyLost)
	_, err = a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.ErrorIs(t, err, ErrKeyLost)
	_, err = a.ReplaceSession()
	require.ErrorIs(t, err, ErrKeyLost, "a dead authority cannot be handed to a new client")
}

func TestDetectedInconsistencyLatchesAndKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1)
	a, s := f.session(t)
	auth, err := a.Reserve(ctx, s, f.assignment(t, 5, 11))
	require.NoError(t, err)

	a.MarkUntrusted("an operator saw something this authority cannot see")

	_, err = a.Reserve(ctx, s, f.assignment(t, 6, 11))
	require.ErrorIs(t, err, ErrStateUntrusted)
	require.ErrorIs(t, a.Sign(s), ErrStateUntrusted)
	_, err = a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.ErrorIs(t, err, ErrStateUntrusted)
	_, err = a.ReplaceSession()
	require.ErrorIs(t, err, ErrStateUntrusted, "a new session is not a way out of a latched fault")

	status := a.Status()
	require.True(t, status.Faulted)
	require.EqualValues(t, 5, status.ReservedRound, "the record is kept: there is no reset that retains the key")
}

func TestAnInconsistentRecordIsDetectedAndLatched(t *testing.T) {
	// The authority can only detect inconsistencies between its own parts, and these are the two it
	// can see. They are kept apart on purpose: the first is caught by the invariant check on
	// admission, the second only when the reserved bytes are used, and a test that conflated them
	// would leave the invariant check itself uncovered.
	ctx := context.Background()

	t.Run("the reserved bytes no longer match their digest", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		_, err := a.Reserve(ctx, s, f.assignment(t, 5, 11))
		require.NoError(t, err)

		a.mu.Lock()
		a.rec.digest[0] ^= 0xff // the bytes still decode; the record no longer agrees with itself
		a.mu.Unlock()

		require.ErrorIs(t, a.Sign(s), ErrStateUntrusted)
		require.True(t, a.Status().Faulted, "the fault latches rather than being reported once")
	})

	t.Run("the reserved bytes no longer decode", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		_, err := a.Reserve(ctx, s, f.assignment(t, 5, 11))
		require.NoError(t, err)

		a.mu.Lock()
		broken := append(bytes.Clone(a.rec.unsigned), 0x00)
		a.rec.unsigned = broken
		a.rec.digest = sha256.Sum256(broken) // consistent with itself, and still not a request
		a.mu.Unlock()

		require.ErrorIs(t, a.Sign(s), ErrStateUntrusted)
		require.True(t, a.Status().Faulted)
	})
}

func TestReleaseNamesItsReservation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1)
	a, s := f.session(t)
	req := f.assignment(t, 5, 11)
	auth, err := a.Reserve(ctx, s, req)
	require.NoError(t, err)

	_, err = a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.ErrorIs(t, err, ErrResponseNotRetained, "nothing is released before it is retained")

	require.NoError(t, a.Sign(s))
	require.NoError(t, a.RetainResponse(s))

	_, err = a.Release(s, 4, auth.UnsignedDigest)
	require.ErrorIs(t, err, ErrStale, "a delayed call for an older reservation is not answered from the newer one")
	_, err = a.Release(s, auth.AssignedRound, digestOf(t, f.assignment(t, 5, 12)))
	require.ErrorIs(t, err, ErrConflict, "and a call naming other bytes is not answered either")

	response, err := a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.NoError(t, err)
	require.Equal(t, response, mustRelease(t, a, s, auth), "release is a replay, not a new signature")
}

func mustRelease(t *testing.T, a *Authority, s Session, auth *Authorization) []byte {
	t.Helper()
	b, err := a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.NoError(t, err)
	return b
}

func TestTheResponseIsTheReservedRequestSigned(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1)
	a, s := f.session(t)
	req := f.assignment(t, 5, 11)
	auth, err := a.Reserve(ctx, s, req)
	require.NoError(t, err)
	require.NoError(t, a.Sign(s))
	require.NoError(t, a.RetainResponse(s))
	response, err := a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.NoError(t, err)

	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(response, &signed))
	require.NotEmpty(t, signed.Signature)

	// It is the reserved request, unchanged, and it verifies under this authority's own key.
	unsigned, err := signed.Bytes()
	require.NoError(t, err)
	require.Equal(t, auth.Unsigned, unsigned)

	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(pub)
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(verifier))
}

func TestConcurrentClientsCannotBothWinOneRound(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1)
	a, s := f.session(t)
	first, second := f.assignment(t, 5, 11), f.assignment(t, 5, 12)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, req := range []Request{first, second} {
		wg.Add(1)
		go func(r Request) {
			defer wg.Done()
			_, err := a.Reserve(ctx, s, r)
			results <- err
		}(req)
	}
	wg.Wait()
	close(results)

	var admitted, conflicts int
	for err := range results {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected refusal: %v", err)
		}
	}
	require.Equal(t, 1, admitted, "exactly one candidate holds the round")
	require.Equal(t, 1, conflicts)
}

func TestACancelledCallerDoesNotUndoItsReservation(t *testing.T) {
	f := newFixture(t, 1)
	a, s := f.session(t)
	req := f.assignment(t, 5, 11)
	auth, err := a.Reserve(context.Background(), s, req)
	require.NoError(t, err)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = a.Reserve(cancelled, s, f.assignment(t, 6, 11))
	require.Error(t, err, "a cancelled caller is not served")
	require.EqualValues(t, 5, a.Status().ReservedRound, "and cancelling does not return the round it already holds")

	require.NoError(t, a.Sign(s))
	require.NoError(t, a.RetainResponse(s))
	_, err = a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
	require.NoError(t, err, "the admitted reservation is still there to finish")
}

func TestGenerationsNeverWrap(t *testing.T) {
	f := newFixture(t, 1)
	a := f.authority(t)
	a.mu.Lock()
	a.generation = math.MaxUint64
	a.mu.Unlock()

	_, err := a.ReplaceSession()
	require.ErrorIs(t, err, ErrStateUntrusted, "exhaustion disables admission rather than reusing an old generation")
	require.True(t, a.Status().Faulted)
}

// sizedRequest returns an assignment whose complete encoding is as close to `target` bytes as the
// proof field allows, without exceeding it. The proof is the only field whose size a caller chooses.
func (f *fixture) sizedRequest(t *testing.T, round uint64, target int) Request {
	t.Helper()
	req := f.assignment(t, round, 11)
	req.Proposed.ZkProof = make([]byte, 1)
	for i := 0; i < 4; i++ {
		encoded, err := req.Proposed.Bytes()
		require.NoError(t, err)
		gap := target - len(encoded)
		if gap == 0 {
			break
		}
		size := len(req.Proposed.ZkProof) + gap
		require.Greater(t, size, 0, "the target is smaller than an empty request")
		req.Proposed.ZkProof = make([]byte, size)
	}
	encoded, err := req.Proposed.Bytes()
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), target)
	return req
}

func TestASessionBelongsToTheAuthorityThatIssuedIt(t *testing.T) {
	// Every authority starts its generation counter at the same place, so a token that is only a
	// counter is admitted by any authority that happens to be at the same count. A token names the
	// authority that issued it, and a foreign token is refused on every client operation.
	ctx := context.Background()
	f := newFixture(t, 1)
	first, firstSession := f.session(t)
	second, secondSession := f.session(t)
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)

	require.Equal(t, firstSession.Generation(), secondSession.Generation(),
		"the two authorities are at the same generation, which is what made the counter alone insufficient")

	// Give the second authority a reservation, so every operation below has something to act on.
	auth, err := second.Reserve(ctx, secondSession, f.assignment(t, 5, 11))
	require.NoError(t, err)
	require.NoError(t, second.Sign(secondSession))

	for _, op := range []struct {
		name string
		call func() error
	}{
		{"reserve", func() error { _, err := second.Reserve(ctx, firstSession, f.assignment(t, 6, 11)); return err }},
		{"sign", func() error { return second.Sign(firstSession) }},
		{"retain", func() error { return second.RetainResponse(firstSession) }},
		{"release", func() error {
			_, err := second.Release(firstSession, auth.AssignedRound, auth.UnsignedDigest)
			return err
		}},
	} {
		t.Run("a foreign session cannot "+op.name, func(t *testing.T) {
			require.ErrorIs(t, op.call(), ErrFenced)
		})
	}

	require.EqualValues(t, 5, second.Status().ReservedRound, "and none of it moved the second authority's record")
}

func TestAnAdmittedRequestCanAlwaysBeCompleted(t *testing.T) {
	// The request cap and the record cap have to compose: a request this authority admits must be
	// signable, retainable and releasable. A 750,000 byte proof was admitted and signed and then
	// could never be retained, which left the round locked and answerable by nothing.
	ctx := context.Background()

	t.Run("the largest admitted request completes", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		req := f.sizedRequest(t, 5, MaxUnsignedRequestBytes)
		encoded, err := req.Proposed.Bytes()
		require.NoError(t, err)
		require.Greater(t, len(encoded), MaxUnsignedRequestBytes-64, "this test is about the upper edge")

		auth, err := a.Reserve(ctx, s, req)
		require.NoError(t, err)
		require.NoError(t, a.Sign(s))
		require.NoError(t, a.RetainResponse(s))
		response, err := a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.False(t, a.Status().Faulted, "a valid request at the size boundary is not an inconsistency")
	})

	t.Run("the review's 750 KB proof completes too", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		req := f.assignment(t, 5, 11)
		req.Proposed.ZkProof = bytes.Repeat([]byte{1}, 750000)
		auth, err := a.Reserve(ctx, s, req)
		require.NoError(t, err)
		require.NoError(t, a.Sign(s))
		require.NoError(t, a.RetainResponse(s), "an admitted and signed request must be retainable")
		_, err = a.Release(s, auth.AssignedRound, auth.UnsignedDigest)
		require.NoError(t, err)
	})

	t.Run("an oversize request is refused before it is reserved", func(t *testing.T) {
		f := newFixture(t, 1)
		a, s := f.session(t)
		req := f.assignment(t, 5, 11)
		req.Proposed.ZkProof = make([]byte, MaxUnsignedRequestBytes)

		_, err := a.Reserve(ctx, s, req)
		require.ErrorIs(t, err, ErrRequestTooLarge)
		status := a.Status()
		require.False(t, status.HasReservation, "a refused request locks nothing")
		require.False(t, status.Faulted, "and refusing it is not a fault")
	})

	t.Run("the caps compose by construction", func(t *testing.T) {
		// The record bound is derived from the request bound rather than chosen independently, so
		// this cannot drift back into two numbers that do not fit together.
		require.GreaterOrEqual(t, MaxRecordBytes, projectedSize(make([]byte, MaxUnsignedRequestBytes), make([]byte, maxAuthorizationIDBytes)),
			"the largest admitted request plus its response must fit the record")
	})
}
