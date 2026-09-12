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
	"errors"
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

type staticTrust struct{ tb *types.RootTrustBaseV1 }

func (s staticTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

func TestARoundSignsThroughARealAuthority(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t)
	r, sub, health := f.round(t)
	authority, session := f.authorityFor(t)
	r.SetCertificationSigner(NewAuthoritySigner(authority, session))

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
	r.SetCertificationSigner(NewAuthoritySigner(authority, session))
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

func TestAShardNodeCannotMintItsOwnSession(t *testing.T) {
	// The interface a round is given deliberately omits ReplaceSession. Session replacement is the
	// operator control plane, and a shard process that could call it could take itself back into
	// service after being fenced.
	var methods []string
	iface := reflect.TypeOf((*SigningAuthorityClient)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		methods = append(methods, iface.Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Release", "Reserve", "RetainResponse", "Sign"}, methods,
		"a shard node reserves, signs, retains and releases; it does not replace sessions or hold a key")
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
		AssignedRound: req.Proposed.InputRecord.RoundNumber,
		Unsigned:      unsigned,
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
			reason: "unsigned request",
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
			r.SetCertificationSigner(NewAuthoritySigner(client, signingauthority.Session{}))

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
