package shardnode

/*
Step 3 of the F6c handoff (§8.3): every certification request goes through one signer, and a refusal
is an abstention rather than a reason to find another way to sign.

These tests drive the real Round. What they are about is the boundary: which requests reach the
signer, what the round does when it refuses, and that nothing falls back to the local key.
*/

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const wiringNodeID = "wiring-node"

// recordingSigner is a CertificationSigner that records what it was asked to sign, and either signs
// with a key of its own or refuses with a given error.
type recordingSigner struct {
	mu       sync.Mutex
	proposed []*certification.BlockCertificationRequest
	signer   abcrypto.Signer
	refuse   error
}

func (s *recordingSigner) Sign(_ context.Context, _ *types.UnicityCertificate, _ *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proposed = append(s.proposed, proposed)
	if s.refuse != nil {
		return nil, s.refuse
	}
	signed := *proposed
	if err := signed.Sign(s.signer); err != nil {
		return nil, err
	}
	return &signed, nil
}

func (s *recordingSigner) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.proposed)
}

// wiringFixture is one shard node at a certified head, with the certificate that assigns its next
// round. It is the shape restore_voting_test.go uses, with the certificates authenticable by a
// signing authority as well.
type wiringFixture struct {
	signer    abcrypto.Signer
	tb        *types.RootTrustBaseV1
	pdr       *types.PartitionDescriptionRecord
	confHash  []byte
	uc        *types.UnicityCertificate
	tr        *certification.TechnicalRecord
	stateRoot []byte
	blockHash []byte
}

func newWiringFixture(t *testing.T) *wiringFixture {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)

	f := &wiringFixture{
		signer: signer, tb: tb, pdr: pdr, confHash: confHash,
		stateRoot: bytes.Repeat([]byte{0xa1}, 32),
		blockHash: bytes.Repeat([]byte{0xb1}, 32),
	}
	zero := make([]byte, 32)
	f.tr = &certification.TechnicalRecord{Round: 6, Epoch: 0, Leader: wiringNodeID, StatHash: zero, FeeHash: zero}
	trHash, err := f.tr.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: 5, PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: f.stateRoot,
		BlockHash: f.blockHash, SummaryValue: []byte{}, Timestamp: 1,
	}
	f.uc = testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, 41, zero, trHash)
	return f
}

// next is the authorization that follows an unanswered round: a repeat certificate at a later root
// round, certifying the same state and assigning a fresh round. It is a different authorization, so
// a round that abstained on the previous one builds normally for this one.
func (f *wiringFixture) next(t *testing.T) *wiringFixture {
	t.Helper()
	zero := make([]byte, 32)
	nextTR := &certification.TechnicalRecord{Round: 7, Epoch: 0, Leader: wiringNodeID, StatHash: zero, FeeHash: zero}
	trHash, err := nextTR.Hash()
	require.NoError(t, err)
	repeat := *f.uc.InputRecord
	return &wiringFixture{
		signer: f.signer, tb: f.tb, pdr: f.pdr, confHash: f.confHash,
		stateRoot: f.stateRoot, blockHash: f.blockHash, tr: nextTR,
		uc: testcertificates.CreateUnicityCertificate(t, f.signer, &repeat, f.pdr, 42, zero, trHash),
	}
}

// round builds a node whose executor is already on the certified block, so the round reaches the
// signing gate rather than abstaining earlier.
func (f *wiringFixture) round(t *testing.T) (*Round, *countingSubmitter, *Health) {
	t.Helper()
	exec := &steadyExecutor{head: BlockRef{Number: 5, Hash: f.blockHash, StateRoot: f.stateRoot}}
	sub := &countingSubmitter{}
	r := NewRound(wiringNodeID, authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), f.signer, sub, nil)
	health := NewHealth()
	r.SetHealth(health)
	return r, sub, health
}

func TestEveryCertificationRequestGoesThroughTheSigner(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, _ := f.round(t)

	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	signer := &recordingSigner{signer: other}
	r.SetCertificationSigner(signer)

	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))

	require.Equal(t, 1, signer.calls(), "the round signs through the configured signer")
	require.Len(t, sub.reqs, 1)

	// What was sent is what the signer returned, signed by ITS key and not by the node's own.
	verifier, err := other.Verifier()
	require.NoError(t, err)
	require.NoError(t, sub.reqs[0].IsValid(verifier), "the request carries the configured signer's signature")

	localVerifier, err := f.signer.Verifier()
	require.NoError(t, err)
	require.Error(t, sub.reqs[0].IsValid(localVerifier), "and not the local key's")

	// And it is the proposal, unchanged.
	proposedBytes, err := signer.proposed[0].Bytes()
	require.NoError(t, err)
	sentBytes, err := sub.reqs[0].Bytes()
	require.NoError(t, err)
	require.Equal(t, proposedBytes, sentBytes)
}

func TestARefusalIsAnAbstentionNotAFallback(t *testing.T) {
	ctx := context.Background()
	for _, refusal := range []struct {
		name string
		err  error
	}{
		{"conflict", signingauthority.ErrConflict},
		{"stale", signingauthority.ErrStale},
		{"fenced", signingauthority.ErrFenced},
		{"untrusted", signingauthority.ErrStateUntrusted},
		{"key lost", signingauthority.ErrKeyLost},
		{"an unavailable authority", errors.New("connection refused")},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			f := newWiringFixture(t)
			r, sub, health := f.round(t)
			signer := &recordingSigner{refuse: refusal.err}
			r.SetCertificationSigner(signer)

			// The certificate is still applied: observing and committing happened before signing,
			// and a refusal must not turn into a delivery failure that re-drives the round.
			require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))

			require.Equal(t, 1, signer.calls())
			require.Empty(t, sub.sent, "nothing is sent when the request was not signed")
			snapshot := health.Snapshot()
			require.False(t, snapshot.Voting)
			require.Contains(t, snapshot.NonVotingReason, "was not signed")
			require.Contains(t, snapshot.NonVotingReason, refusal.err.Error(),
				"the reason names the refusal, so an operator can tell these apart")
		})
	}
}

func TestTheSignerIsNotReachedWhenTheRoundMayNotVote(t *testing.T) {
	ctx := context.Background()

	t.Run("a node that cannot prove its executor is on the certified block", func(t *testing.T) {
		f := newWiringFixture(t)
		// An executor on a different block: P-id fails, and that decision belongs before signing.
		exec := &steadyExecutor{head: BlockRef{Number: 5, Hash: bytes.Repeat([]byte{0xcc}, 32), StateRoot: f.stateRoot}}
		sub := &countingSubmitter{}
		r := NewRound(wiringNodeID, authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), f.signer, sub, nil)
		r.SetHealth(NewHealth())
		signer := &recordingSigner{}
		r.SetCertificationSigner(signer)

		require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
		require.Zero(t, signer.calls(), "P-id is retained before the signer is asked for anything")
		require.Empty(t, sub.sent)
	})

	t.Run("a restored process", func(t *testing.T) {
		f := newWiringFixture(t)
		r, sub, _ := f.round(t)
		signer := &recordingSigner{}
		r.SetCertificationSigner(signer)
		r.MarkRestored(5)

		require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
		require.Zero(t, signer.calls(), "P-sign still withholds the vote, and step 3 does not re-enable it")
		require.Empty(t, sub.sent)
	})
}

func TestARedeliveredRoundReplaysWithoutSigningAgain(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, _ := f.round(t)
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	signer := &recordingSigner{signer: other}
	r.SetCertificationSigner(signer)

	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))

	require.Equal(t, 1, signer.calls(), "the second delivery replays the retained request")
	require.Len(t, sub.sent, 2)
	first, err := sub.reqs[0].Bytes()
	require.NoError(t, err)
	second, err := sub.reqs[1].Bytes()
	require.NoError(t, err)
	require.Equal(t, first, second, "and puts the same bytes on the wire")
}

// authorityFor enrolls a signing authority for this fixture's shard, and opens the first session the
// way an operator would. The round never sees the authority itself, only the signer built from it.
func (f *wiringFixture) authorityFor(t *testing.T) (*signingauthority.Authority, signingauthority.Session) {
	t.Helper()
	authority, err := signingauthority.New(signingauthority.Enrollment{
		AuthorityID: "authority-1", NodeID: wiringNodeID, NetworkID: 5, PartitionID: authPartitionID,
		ShardID: types.ShardID{}, ShardEpoch: 0, RootEpoch: signingauthority.PinRootEpoch(1),
		ShardConfHash: f.confHash, Profile: signingauthority.ProfileLegacyBCRv1,
	}, staticTrust{tb: f.tb})
	require.NoError(t, err)
	t.Cleanup(authority.Close)
	session, err := authority.ReplaceSession()
	require.NoError(t, err)
	return authority, session
}

// authoritySignerFor builds the signer under test, failing the test rather than the round if the
// wiring itself is wrong.
func authoritySignerFor(t *testing.T, client SigningAuthorityClient, session signingauthority.Session, key abcrypto.Verifier) CertificationSigner {
	t.Helper()
	signer, err := NewAuthoritySigner(client, session, key)
	require.NoError(t, err)
	return signer
}

// authorityKey is the enrolled authority's key as a deployment would provision it: read from the
// authority at wiring time, never from a response.
func (f *wiringFixture) authorityKey(t *testing.T, authority *signingauthority.Authority) abcrypto.Verifier {
	t.Helper()
	pub, err := authority.SigningPublicKey()
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(pub)
	require.NoError(t, err)
	return verifier
}

// localVerifier is the fixture's own key, which the scripted clients below sign with.
func (f *wiringFixture) localVerifier(t *testing.T) abcrypto.Verifier {
	t.Helper()
	verifier, err := f.signer.Verifier()
	require.NoError(t, err)
	return verifier
}

type staticTrust struct{ tb *types.RootTrustBaseV1 }

func (s staticTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

func TestARoundSignsThroughARealAuthority(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, health := f.round(t)
	authority, session := f.authorityFor(t)
	r.SetCertificationSigner(authoritySignerFor(t, authority, session, f.authorityKey(t, authority)))

	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.Len(t, sub.reqs, 1)
	require.True(t, health.Snapshot().Voting)

	pub, err := authority.SigningPublicKey()
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(pub)
	require.NoError(t, err)
	require.NoError(t, sub.reqs[0].IsValid(verifier), "the authority's key signed what went on the wire")

	status := authority.Status()
	require.True(t, status.HasReservation)
	require.EqualValues(t, 6, status.ReservedRound, "and the authority holds the round it answered")
}

func TestARebuiltCandidateNeverOverwritesAReservation(t *testing.T) {
	// The authority already holds a request for this round, made by an earlier process. This node
	// rebuilds a different candidate for the same round, which is the situation §8.3 names: it must
	// abstain rather than overwrite the reservation to regain liveness.
	ctx := context.Background()
	f := newWiringFixture(t)
	authority, session := f.authorityFor(t)

	earlier := &certification.BlockCertificationRequest{
		PartitionID: authPartitionID, ShardID: types.ShardID{}, NodeID: wiringNodeID,
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: 6, Epoch: 0, PreviousHash: f.uc.InputRecord.Hash,
			Hash: bytes.Repeat([]byte{0xd1}, 32), BlockHash: bytes.Repeat([]byte{0xd2}, 32),
			SummaryValue: []byte{}, Timestamp: f.uc.UnicitySeal.Timestamp,
		},
		BlockSize: 999, StateSize: 999,
	}
	reserved, err := authority.Reserve(ctx, session, signingauthority.Request{UC: f.uc, Technical: f.tr, Proposed: earlier})
	require.NoError(t, err)

	r, sub, health := f.round(t)
	r.SetCertificationSigner(authoritySignerFor(t, authority, session, f.authorityKey(t, authority)))
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))

	require.Empty(t, sub.sent, "the rebuilt candidate is not signed")
	require.Contains(t, health.Snapshot().NonVotingReason, signingauthority.ErrConflict.Error())

	// The reservation is untouched: it still answers for the request it admitted.
	require.NoError(t, authority.Sign(session))
	require.NoError(t, authority.RetainResponse(session))
	released, err := authority.Release(session, reserved.AssignedRound, reserved.UnsignedDigest)
	require.NoError(t, err)
	require.NotEmpty(t, released)
	require.EqualValues(t, 6, authority.Status().ReservedRound)
}

func TestTheClientInterfaceOmitsSessionReplacement(t *testing.T) {
	// The interface a round is given omits ReplaceSession, which narrows what this code can call.
	// That is all this test establishes: a declared method set. It is not process isolation and not
	// a capability boundary, because a value whose dynamic type is *signingauthority.Authority can
	// be asserted to an interface that does have ReplaceSession, and in this unactivated profile the
	// round holds the legacy key as well. Separate credentials and an authority lifetime independent
	// of the shard process remain prerequisites for activation.
	var methods []string
	iface := reflect.TypeOf((*SigningAuthorityClient)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		methods = append(methods, iface.Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Release", "Reserve", "RetainResponse", "Sign"}, methods,
		"the declared method set is reserve, sign, retain and release, and nothing else")
}

// scriptedClient is a signing authority that answers the protocol correctly up to the released
// bytes, which the test chooses. It stands for an authority that is wrong or compromised rather than
// unavailable: the client must check what it is handed before it puts it on the wire (§5).
type scriptedClient struct {
	release      func(unsigned []byte) []byte
	lastUnsigned []byte
}

func (c *scriptedClient) Reserve(_ context.Context, _ signingauthority.Session, req signingauthority.Request) (*signingauthority.Authorization, error) {
	unsigned, err := req.Proposed.Bytes()
	if err != nil {
		return nil, err
	}
	c.lastUnsigned = unsigned
	return &signingauthority.Authorization{
		AssignedRound:  req.Proposed.InputRecord.RoundNumber,
		Unsigned:       unsigned,
		UnsignedDigest: sha256.Sum256(unsigned),
	}, nil
}

func (c *scriptedClient) Sign(signingauthority.Session) error           { return nil }
func (c *scriptedClient) RetainResponse(signingauthority.Session) error { return nil }

func (c *scriptedClient) Release(_ signingauthority.Session, _ uint64, _ [32]byte) ([]byte, error) {
	return c.release(nil), nil
}

func TestAnAuthorityResponseIsCheckedBeforeItGoesOnTheWire(t *testing.T) {
	ctx := context.Background()

	encode := func(t *testing.T, req *certification.BlockCertificationRequest) []byte {
		t.Helper()
		b, err := types.Cbor.Marshal(req)
		require.NoError(t, err)
		return b
	}

	for _, tc := range []struct {
		name    string
		release func(t *testing.T, f *wiringFixture) []byte
		reason  string
	}{
		{
			name: "a response for a different candidate",
			release: func(t *testing.T, f *wiringFixture) []byte {
				other, err := abcrypto.NewInMemorySecp256K1Signer()
				require.NoError(t, err)
				req := &certification.BlockCertificationRequest{
					PartitionID: authPartitionID, ShardID: types.ShardID{}, NodeID: wiringNodeID,
					InputRecord: &types.InputRecord{
						Version: 1, RoundNumber: 6, PreviousHash: f.stateRoot,
						Hash: bytes.Repeat([]byte{0xe1}, 32), BlockHash: bytes.Repeat([]byte{0xe2}, 32),
						SummaryValue: []byte{}, Timestamp: f.uc.UnicitySeal.Timestamp,
					},
				}
				require.NoError(t, req.Sign(other))
				return encode(t, req)
			},
			reason: "different request",
		},
		{
			name: "a response that carries no signature",
			release: func(t *testing.T, f *wiringFixture) []byte {
				// The proposal itself, unsigned: the released bytes match what was reserved, and
				// the only thing missing is the signature the authority was asked to produce.
				return nil
			},
			reason: "does not verify under the enrolled signing key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWiringFixture(t)
			r, sub, health := f.round(t)
			client := &scriptedClient{}
			client.release = func(unsigned []byte) []byte {
				if body := tc.release(t, f); body != nil {
					return body
				}
				return client.lastUnsigned
			}
			r.SetCertificationSigner(authoritySignerFor(t, client, signingauthority.Session{}, f.localVerifier(t)))

			require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
			require.Empty(t, sub.sent, "an unchecked response must never reach the root chain")
			require.Contains(t, health.Snapshot().NonVotingReason, tc.reason)
		})
	}
}

func TestReplacingTheSignerWithNothingIsIgnored(t *testing.T) {
	// Wiring the authority in is a runtime step, and a nil signer is a wiring mistake rather than an
	// instruction to stop signing. It must not leave the round with no signer at all, which would
	// crash the node on its next certificate instead of abstaining from a vote.
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, _ := f.round(t)
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	signer := &recordingSigner{signer: other}
	r.SetCertificationSigner(signer)
	r.SetCertificationSigner(nil)

	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.Equal(t, 1, signer.calls(), "the configured signer is still the one that signs")
	require.Len(t, sub.reqs, 1)
}

/*
substitutingClient answers CONSISTENTLY for a request this round did not propose: its reservation
and its release both describe the substituted request, and it signs that request properly. Nothing
in the exchange disagrees with itself, which is the point. The first revision of this signer compared
the released response with the reservation, so two remote answers agreeing established the response,
and a mis-correlated or compromised client's request was forwarded to the root chain as this node's
own signed statement.

The repair compares both answers with the proposal this round owns.
*/
type substitutingClient struct {
	t        *testing.T
	signer   abcrypto.Signer
	saw      int // how often this round's own proposal reached the client
	response []byte
}

func (c *substitutingClient) substitute(proposed *certification.BlockCertificationRequest) *certification.BlockCertificationRequest {
	c.t.Helper()
	c.saw++
	other := *proposed
	other.BlockSize += 100
	require.NoError(c.t, other.Sign(c.signer))
	return &other
}

func (c *substitutingClient) Reserve(_ context.Context, _ signingauthority.Session, req signingauthority.Request) (*signingauthority.Authorization, error) {
	other := c.substitute(req.Proposed)
	unsigned, err := other.Bytes()
	require.NoError(c.t, err)
	c.response, err = types.Cbor.Marshal(other)
	require.NoError(c.t, err)
	return &signingauthority.Authorization{
		AssignedRound:  other.InputRecord.RoundNumber,
		Unsigned:       unsigned,
		UnsignedDigest: sha256.Sum256(unsigned),
	}, nil
}

func (c *substitutingClient) Sign(signingauthority.Session) error           { return nil }
func (c *substitutingClient) RetainResponse(signingauthority.Session) error { return nil }

func (c *substitutingClient) Release(signingauthority.Session, uint64, [32]byte) ([]byte, error) {
	return c.response, nil
}

func TestAConsistentlySubstitutedExchangeIsRefused(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, health := f.round(t)
	client := &substitutingClient{t: t, signer: f.signer}
	r.SetCertificationSigner(authoritySignerFor(t, client, signingauthority.Session{}, f.localVerifier(t)))

	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.Empty(t, sub.sent, "a request this round did not propose must never be sent as this node's vote")
	require.Contains(t, health.Snapshot().NonVotingReason, "different request than the one proposed",
		"the refusal is decided against the local proposal, not against the other answer")
	require.Equal(t, 1, client.saw, "this round's own proposal did reach the client, so the substitution was reachable")
}

func TestASignatureThatDoesNotVerifyIsRefused(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		// response builds the released bytes from the reserved unsigned preimage.
		response func(t *testing.T, f *wiringFixture, unsigned []byte) []byte
	}{
		{
			name: "a signature that is present but not a signature",
			response: func(t *testing.T, f *wiringFixture, unsigned []byte) []byte {
				var req certification.BlockCertificationRequest
				require.NoError(t, types.Cbor.Unmarshal(unsigned, &req))
				req.Signature = []byte{1}
				b, err := types.Cbor.Marshal(req)
				require.NoError(t, err)
				return b
			},
		},
		{
			name: "a valid signature by a key this node did not enrol",
			response: func(t *testing.T, f *wiringFixture, unsigned []byte) []byte {
				var req certification.BlockCertificationRequest
				require.NoError(t, types.Cbor.Unmarshal(unsigned, &req))
				stranger, err := abcrypto.NewInMemorySecp256K1Signer()
				require.NoError(t, err)
				require.NoError(t, req.Sign(stranger))
				b, err := types.Cbor.Marshal(req)
				require.NoError(t, err)
				return b
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWiringFixture(t)
			r, sub, health := f.round(t)
			client := &scriptedClient{}
			client.release = func([]byte) []byte { return tc.response(t, f, client.lastUnsigned) }
			// The expected key is this node's configured one, read at wiring time.
			r.SetCertificationSigner(authoritySignerFor(t, client, signingauthority.Session{}, f.localVerifier(t)))

			require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
			require.Empty(t, sub.sent, "an answer that does not verify is not cached as a completed round")
			require.Contains(t, health.Snapshot().NonVotingReason, "does not verify under the enrolled signing key")
		})
	}
}

func TestTheSignerIsWiredWithAnExpectedKeyAndAClient(t *testing.T) {
	f := newWiringFixture(t)
	_, err := NewAuthoritySigner(nil, signingauthority.Session{}, f.localVerifier(t))
	require.ErrorContains(t, err, "no signing authority client")
	_, err = NewAuthoritySigner(&scriptedClient{}, signingauthority.Session{}, nil)
	require.ErrorContains(t, err, "no expected signing key",
		"the key a response is checked against is provisioned, never taken from the response")
}

func TestARefusedAuthorizationStaysRefusedOnRedelivery(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, health := f.round(t)
	signer := &recordingSigner{refuse: errors.New("authority unavailable")}
	r.SetCertificationSigner(signer)

	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))

	require.Equal(t, 1, signer.calls(),
		"the authority may already hold a reservation for the first candidate; a second attempt for the same round is not this node's to make")
	require.Empty(t, sub.sent)
	snapshot := health.Snapshot()
	require.False(t, snapshot.Voting)
	require.Contains(t, snapshot.NonVotingReason, "authority unavailable",
		"the reason recorded at the refusal is the one reported afterwards")
}

func TestARefusedAuthorizationIsNotRebuiltAfterAPersistenceFailure(t *testing.T) {
	/*
		The production path the review named: persistingDriver saves the certificate after the round
		returns, so a failed checkpoint write re-delivers a certificate the round already handled. If
		the signer refused the first time and the executor's mempool has moved on, rebuilding would
		take a DIFFERENT candidate to the authority for the same round — which strands the first
		answer behind a conflict at best, and is a second signed statement for one round at worst.
	*/
	ctx := context.Background()
	f := newWiringFixture(t)
	exec := &retryExecutor{
		head:      BlockRef{Number: 5, Hash: f.blockHash, StateRoot: f.stateRoot},
		held:      map[string]BlockRef{},
		available: true,
	}
	sub := &countingSubmitter{}
	round := NewRound(wiringNodeID, authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), f.signer, sub, nil)
	round.SetHealth(NewHealth())
	signer := &recordingSigner{refuse: signingauthority.ErrFenced}
	round.SetCertificationSigner(signer)

	roDir := filepath.Join(t.TempDir(), "read-only")
	require.NoError(t, os.Mkdir(roDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })

	client := &BFTClient{
		partitionID:    authPartitionID,
		shardID:        types.ShardID{},
		shardConfHash:  f.confHash,
		nodeID:         wiringNodeID,
		trustBaseStore: stubTrustBaseStore{tb: f.tb},
		driver:         &persistingDriver{driver: round, store: NewFileStore(filepath.Join(roDir, "luc.cbor"))},
	}
	client.lastCertResponseTime.Store(1)
	respond := &certification.CertificationResponse{
		Partition: authPartitionID, Shard: types.ShardID{}, Technical: *f.tr, UC: *f.uc,
	}

	require.ErrorContains(t, client.handleCertificationResponse(ctx, respond), "persisting certificate")
	require.Equal(t, 1, signer.calls())

	// A transaction arrives between the two deliveries, so a rebuild would produce other bytes.
	exec.queue([]byte("a transaction that arrived between the two deliveries"))
	_ = client.handleCertificationResponse(ctx, respond)

	require.Equal(t, 1, signer.calls(), "the re-delivery does not take a second candidate to the signer")
	require.Empty(t, sub.sent, "and nothing is sent for a round that was never signed")
}

func TestANewAuthorizationIsBuiltAfterARefusedOne(t *testing.T) {
	// The refusal is retained for the authorization that produced it, not for the node. A repeat
	// certificate at a later root round assigns a fresh round, and that is ordinary work.
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, health := f.round(t)
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	signer := &recordingSigner{refuse: signingauthority.ErrStale}
	r.SetCertificationSigner(signer)
	require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
	require.Empty(t, sub.sent)

	signer.mu.Lock()
	signer.refuse = nil
	signer.signer = other
	signer.mu.Unlock()

	next := f.next(t)
	require.NoError(t, r.HandleCertificate(ctx, next.uc, next.tr))
	require.Equal(t, 2, signer.calls())
	require.Len(t, sub.reqs, 1, "the next authorization is answered normally")
	require.True(t, health.Snapshot().Voting)
}

// mismatchedReservationClient reserves something other than what this round proposed, and then
// releases the correct signed response. The release alone would pass every check; the reservation is
// the part that disagrees with this round's work, and a client whose two answers disagree is one
// this node cannot correlate, whichever of them is right.
type mismatchedReservationClient struct {
	scriptedClient
	round  uint64
	digest [32]byte
	bytes  []byte
}

func (c *mismatchedReservationClient) Reserve(ctx context.Context, s signingauthority.Session, req signingauthority.Request) (*signingauthority.Authorization, error) {
	authorization, err := c.scriptedClient.Reserve(ctx, s, req)
	if err != nil {
		return nil, err
	}
	if c.round != 0 {
		authorization.AssignedRound = c.round
	}
	if c.digest != [32]byte{} {
		authorization.UnsignedDigest = c.digest
	}
	if c.bytes != nil {
		authorization.Unsigned = c.bytes
	}
	return authorization, nil
}

func TestAReservationThatDoesNotNameThisRoundsWorkIsRefused(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		set    func(c *mismatchedReservationClient)
		reason string
	}{
		{"another round", func(c *mismatchedReservationClient) { c.round = 99 }, "reserved round 99"},
		{"another digest", func(c *mismatchedReservationClient) { c.digest = sha256.Sum256([]byte("elsewhere")) }, "digest that does not name"},
		{"another preimage", func(c *mismatchedReservationClient) { c.bytes = []byte("elsewhere") }, "reserved a different request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWiringFixture(t)
			r, sub, health := f.round(t)
			client := &mismatchedReservationClient{}
			tc.set(client)
			// The release is the correct, properly signed answer: only the reservation disagrees.
			client.release = func([]byte) []byte {
				var req certification.BlockCertificationRequest
				require.NoError(t, types.Cbor.Unmarshal(client.lastUnsigned, &req))
				require.NoError(t, req.Sign(f.signer))
				b, err := types.Cbor.Marshal(req)
				require.NoError(t, err)
				return b
			}
			r.SetCertificationSigner(authoritySignerFor(t, client, signingauthority.Session{}, f.localVerifier(t)))

			require.NoError(t, r.HandleCertificate(ctx, f.uc, f.tr))
			require.Empty(t, sub.sent)
			require.Contains(t, health.Snapshot().NonVotingReason, tc.reason)
		})
	}
}
