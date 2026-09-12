package signingauthority

/*
Step 1 of the F6c handoff (§8.1): the authority boundary, with real certificates.

Every certificate here is produced by the actual certificate constructor and verified by the actual
verification path against a real trust base. No test hands the authority a "this was authenticated"
flag, because the point of the boundary is that the authority does not accept such a claim.

These tests cover authentication and scope only. They do not test a signing record, a reservation or
fencing, which are step 2: an authenticated request is not yet an authorized one, and nothing here
re-enables restored voting.
*/

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"errors"
	"reflect"
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	testNetworkID   types.NetworkID   = 5
	testPartitionID types.PartitionID = 8
	testNodeID                        = "validator-A"
	certifiedRound                    = 4
	assignedRound                     = 5
	shardEpoch                        = 1
	rootEpoch                         = 1
)

type trustStub struct {
	tb  *types.RootTrustBaseV1
	err error
}

func (s trustStub) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.tb, nil
}

type fixture struct {
	signers  []abcrypto.Signer
	tb       *types.RootTrustBaseV1
	pdr      *types.PartitionDescriptionRecord
	confHash []byte
	enroll   Enrollment
	uc       *types.UnicityCertificate
	tr       *certification.TechnicalRecord
}

func nodeIDOf(t *testing.T, signer abcrypto.Signer) string {
	t.Helper()
	v, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	key, err := p2pcrypto.UnmarshalSecp256k1PublicKey(pub)
	require.NoError(t, err)
	id, err := peer.IDFromPublicKey(key)
	require.NoError(t, err)
	return id.String()
}

// newFixture builds a shard whose certificates are signed by `signers` root nodes, of which the
// trust base requires a two thirds plus one quorum.
func newFixture(t *testing.T, rootNodes int) *fixture {
	t.Helper()
	f := &fixture{}
	for i := 0; i < rootNodes; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		f.signers = append(f.signers, s)
	}
	tb, ok := testtrustbase.NewTrustBase(t, f.signers...).(*types.RootTrustBaseV1)
	require.True(t, ok)
	f.tb = tb

	f.pdr = &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, T2Timeout: 2500000000,
	}
	var err error
	f.confHash, err = f.pdr.Hash(gocrypto.SHA256)
	require.NoError(t, err)

	zero := make([]byte, 32)
	f.tr = &certification.TechnicalRecord{
		Round: assignedRound, Epoch: shardEpoch, Leader: testNodeID, StatHash: zero, FeeHash: zero,
	}
	trHash, err := f.tr.Hash()
	require.NoError(t, err)

	certified := &types.InputRecord{
		Version: 1, RoundNumber: certifiedRound, Epoch: shardEpoch,
		PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
	}
	f.uc = testcertificates.CreateUnicityCertificate(t, f.signers[0], certified, f.pdr, 50, zero, trHash)
	f.signSealTo(t, f.uc, quorum(rootNodes))

	f.enroll = Enrollment{
		AuthorityID: "authority-1", NodeID: testNodeID, NetworkID: testNetworkID,
		PartitionID: testPartitionID, ShardID: types.ShardID{}, ShardEpoch: shardEpoch,
		RootEpoch: PinRootEpoch(rootEpoch), ShardConfHash: f.confHash, Profile: ProfileLegacyBCRv1,
	}
	return f
}

// quorum is the two thirds plus one the trust base computes for equally staked nodes.
func quorum(rootNodes int) int { return rootNodes*2/3 + 1 }

// signSealTo brings the seal up to `signatures` valid signatures, starting from the first signer.
func (f *fixture) signSealTo(t *testing.T, uc *types.UnicityCertificate, signatures int) {
	t.Helper()
	for i := 0; i < signatures; i++ {
		require.NoError(t, uc.UnicitySeal.Sign(nodeIDOf(t, f.signers[i]), f.signers[i]))
	}
	require.NoError(t, uc.UnicitySeal.Verify(f.tb), "the fixture's own certificate must carry a quorum")
}

// proposal is the certification request the shard node would build for the assigned round.
func (f *fixture) proposal() *certification.BlockCertificationRequest {
	return &certification.BlockCertificationRequest{
		PartitionID: testPartitionID,
		ShardID:     types.ShardID{},
		NodeID:      testNodeID,
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: assignedRound, Epoch: shardEpoch,
			// A round that certifies work: the state moves, so a block hash belongs with it.
			PreviousHash: f.uc.InputRecord.Hash, Hash: bytes.Repeat([]byte{0xa1}, 32), BlockHash: bytes.Repeat([]byte{0xb1}, 32),
			SummaryValue: []byte{}, Timestamp: f.uc.UnicitySeal.Timestamp,
		},
		BlockSize: 11, StateSize: 42,
	}
}

func (f *fixture) request() Request {
	return Request{UC: f.uc, Technical: f.tr, Proposed: f.proposal()}
}

func (f *fixture) authority(t *testing.T) *Authority {
	t.Helper()
	a, err := New(f.enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	return a
}

func TestAuthenticateAcceptsTheEnrolledAssignment(t *testing.T) {
	f := newFixture(t, 1)
	a := f.authority(t)
	req := f.request()

	auth, err := a.Authenticate(context.Background(), req)
	require.NoError(t, err)
	require.EqualValues(t, assignedRound, auth.AssignedRound, "the assigned round comes from the technical record")
	require.EqualValues(t, shardEpoch, auth.AssignedEpoch)
	require.NotEmpty(t, auth.ID)

	// The preimage is exactly what the shard node signs today. This profile adds nothing to it.
	wire, err := req.Proposed.Bytes()
	require.NoError(t, err)
	require.Equal(t, wire, auth.Unsigned, "the authority signs the legacy request bytes, unchanged")

	// And those bytes are a complete, verifiable request once signed.
	signed := f.proposal()
	require.NoError(t, signed.Sign(f.signers[0]))
	v, err := f.signers[0].Verifier()
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(v))
}

func TestEnrollmentIsAGuardNotANamespace(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()

	t.Run("another node's request", func(t *testing.T) {
		a := f.authority(t)
		req := f.request()
		req.Proposed.NodeID = "validator-B"
		_, err := a.Authenticate(ctx, req)
		require.ErrorIs(t, err, ErrContextMismatch)
	})

	t.Run("another partition", func(t *testing.T) {
		a := f.authority(t)
		req := f.request()
		req.Proposed.PartitionID = testPartitionID + 1
		_, err := a.Authenticate(ctx, req)
		require.ErrorIs(t, err, ErrContextMismatch)
	})

	t.Run("another network", func(t *testing.T) {
		// The same genuinely signed certificate, an authority enrolled for a different network. The
		// legacy preimage names no network, so this is caught against the provisioned trust base.
		enroll := f.enroll
		enroll.NetworkID = testNetworkID + 1
		a, err := New(enroll, trustStub{tb: f.tb})
		require.NoError(t, err)
		_, err = a.Authenticate(ctx, f.request())
		require.ErrorIs(t, err, ErrContextMismatch)
	})

	t.Run("another shard configuration", func(t *testing.T) {
		other := &types.PartitionDescriptionRecord{
			Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, T2Timeout: 5000000000,
		}
		otherHash, err := other.Hash(gocrypto.SHA256)
		require.NoError(t, err)
		require.NotEqual(t, f.confHash, otherHash)

		enroll := f.enroll
		enroll.ShardConfHash = otherHash
		a, err := New(enroll, trustStub{tb: f.tb})
		require.NoError(t, err)
		_, err = a.Authenticate(ctx, f.request())
		require.ErrorIs(t, err, ErrContextMismatch)
	})

	t.Run("another shard epoch", func(t *testing.T) {
		enroll := f.enroll
		enroll.ShardEpoch = shardEpoch + 1
		a, err := New(enroll, trustStub{tb: f.tb})
		require.NoError(t, err)
		_, err = a.Authenticate(ctx, f.request())
		require.ErrorIs(t, err, ErrContextMismatch, "an epoch transition freezes this authority rather than opening a new scope")
	})

	t.Run("an assignment for another shard epoch", func(t *testing.T) {
		// The assignment's epoch is read from the technical record, so it needs its own case: here
		// the certificate's input record carries the enrolled epoch and the bound technical record
		// does not. Without this, the input-record check alone would hide a missing one.
		zero := make([]byte, 32)
		otherEpoch := &certification.TechnicalRecord{
			Round: assignedRound, Epoch: shardEpoch + 1, Leader: testNodeID, StatHash: zero, FeeHash: zero,
		}
		trHash, err := otherEpoch.Hash()
		require.NoError(t, err)
		certified := &types.InputRecord{
			Version: 1, RoundNumber: certifiedRound, Epoch: shardEpoch,
			PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
		}
		uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], certified, f.pdr, 52, zero, trHash)
		f.signSealTo(t, uc, quorum(1))

		req := f.request()
		req.UC, req.Technical = uc, otherEpoch
		req.Proposed.InputRecord.Epoch = shardEpoch + 1
		req.Proposed.InputRecord.Timestamp = uc.UnicitySeal.Timestamp

		a := f.authority(t)
		_, err = a.Authenticate(ctx, req)
		require.ErrorIs(t, err, ErrContextMismatch, "the enrolled epoch bounds the assignment, not only the certified state")
	})

	t.Run("an unsupported profile is refused at enrollment", func(t *testing.T) {
		enroll := f.enroll
		enroll.Profile = "some-other-profile"
		_, err := New(enroll, trustStub{tb: f.tb})
		require.ErrorIs(t, err, ErrUnsupportedVersion)
	})
}

func TestAuthenticationUsesTheAuthoritysOwnTrust(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()

	t.Run("a forged seal is refused", func(t *testing.T) {
		a := f.authority(t)
		req := f.request()
		forgedSeal := *f.uc.UnicitySeal
		forgedSeal.Signatures = types.SignatureMap{"nobody": []byte("not a signature")}
		forged := *f.uc
		forged.UnicitySeal = &forgedSeal
		req.UC = &forged
		_, err := a.Authenticate(ctx, req)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("an unknown root epoch is refused, not assumed", func(t *testing.T) {
		a, err := New(f.enroll, trustStub{err: errors.New("unknown epoch")})
		require.NoError(t, err)
		_, err = a.Authenticate(ctx, f.request())
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("a technical record the certificate does not bind is refused", func(t *testing.T) {
		a := f.authority(t)
		req := f.request()
		other := *f.tr
		other.Leader = "validator-B"
		req.Technical = &other
		_, err := a.Authenticate(ctx, req)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})
}

func TestProposalMustBeTheOneTheAuthorizationAssigns(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	a := f.authority(t)

	for _, tc := range []struct {
		name   string
		mutate func(ir *types.InputRecord)
	}{
		{"another round", func(ir *types.InputRecord) { ir.RoundNumber = assignedRound + 1 }},
		{"another epoch", func(ir *types.InputRecord) { ir.Epoch = shardEpoch + 1 }},
		{"another previous state", func(ir *types.InputRecord) { ir.PreviousHash = make([]byte, 32); ir.PreviousHash[0] = 0xff }},
		{"another timestamp", func(ir *types.InputRecord) { ir.Timestamp++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := f.request()
			tc.mutate(req.Proposed.InputRecord)
			_, err := a.Authenticate(ctx, req)
			require.ErrorIs(t, err, ErrProposalMismatch)
		})
	}

	t.Run("an already signed proposal is refused", func(t *testing.T) {
		req := f.request()
		require.NoError(t, req.Proposed.Sign(f.signers[0]))
		_, err := a.Authenticate(ctx, req)
		require.ErrorIs(t, err, ErrProposalMismatch, "the caller is not supposed to have a signing path of its own")
	})
}

func TestMissingProofIsDistinctFromAnEmptyOne(t *testing.T) {
	// The legacy preimage encodes the whole request. A nil proof and an empty one are different
	// messages, and the authority must not collapse them into one authorization.
	f := newFixture(t, 1)
	ctx := context.Background()
	a := f.authority(t)

	withNil := f.request()
	withNil.Proposed.ZkProof = nil
	nilAuth, err := a.Authenticate(ctx, withNil)
	require.NoError(t, err)

	withEmpty := f.request()
	withEmpty.Proposed.ZkProof = []byte{}
	emptyAuth, err := a.Authenticate(ctx, withEmpty)
	require.NoError(t, err)

	require.NotEqual(t, nilAuth.Unsigned, emptyAuth.Unsigned, "nil and empty proofs are different signed bytes")
	require.NotEqual(t, nilAuth.UnsignedDigest, emptyAuth.UnsignedDigest)
	require.Equal(t, nilAuth.ID, emptyAuth.ID, "the authorization is the same; only the proposal differs")
}

func TestAnOversizeRequestIsRefusedBeforeItIsRetained(t *testing.T) {
	f := newFixture(t, 1)
	a := f.authority(t)
	req := f.request()
	req.Proposed.ZkProof = make([]byte, MaxUnsignedRequestBytes+1)
	_, err := a.Authenticate(context.Background(), req)
	require.ErrorIs(t, err, ErrRequestTooLarge)
}

func TestValidSignerSubsetsAreOneAuthorization(t *testing.T) {
	// Four root nodes, a quorum of three. Two different valid three-signature subsets of the same
	// seal are the same authorization: the identity is defined over the seal's signature-free bytes.
	f := newFixture(t, 4)
	a := f.authority(t)
	ctx := context.Background()

	first := *f.uc
	firstSeal := *f.uc.UnicitySeal
	firstSeal.Signatures = nil
	first.UnicitySeal = &firstSeal
	for _, i := range []int{0, 1, 2} {
		require.NoError(t, firstSeal.Sign(nodeIDOf(t, f.signers[i]), f.signers[i]))
	}

	second := *f.uc
	secondSeal := *f.uc.UnicitySeal
	secondSeal.Signatures = nil
	second.UnicitySeal = &secondSeal
	for _, i := range []int{1, 2, 3} {
		require.NoError(t, secondSeal.Sign(nodeIDOf(t, f.signers[i]), f.signers[i]))
	}
	require.NotEqual(t, firstSeal.Signatures, secondSeal.Signatures, "the subsets must actually differ")

	reqA, reqB := f.request(), f.request()
	reqA.UC, reqB.UC = &first, &second
	authA, err := a.Authenticate(ctx, reqA)
	require.NoError(t, err)
	authB, err := a.Authenticate(ctx, reqB)
	require.NoError(t, err)

	require.Equal(t, authA.ID, authB.ID, "valid signer subsets identify the same authorization")
	require.Equal(t, authA.AssignedRound, authB.AssignedRound)
	require.Equal(t, authA.Unsigned, authB.Unsigned)
}

func TestRepeatedAssignmentsAndRepeatCertificates(t *testing.T) {
	f := newFixture(t, 1)
	a := f.authority(t)
	ctx := context.Background()

	first, err := a.Authenticate(ctx, f.request())
	require.NoError(t, err)
	again, err := a.Authenticate(ctx, f.request())
	require.NoError(t, err)
	require.Equal(t, first.ID, again.ID, "the same assignment is the same authorization every time")
	require.Equal(t, first.UnsignedDigest, again.UnsignedDigest)

	// A repeat certificate for the same assigned round: a new root round, the same work. The
	// authorization identity differs, and the assigned round, which is the conflict key, does not.
	trHash, err := f.tr.Hash()
	require.NoError(t, err)
	zero := make([]byte, 32)
	certified := &types.InputRecord{
		Version: 1, RoundNumber: certifiedRound, Epoch: shardEpoch,
		PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
	}
	repeat := testcertificates.CreateUnicityCertificate(t, f.signers[0], certified, f.pdr, 51, zero, trHash)
	f.signSealTo(t, repeat, quorum(1))

	req := f.request()
	req.UC = repeat
	req.Proposed.InputRecord.Timestamp = repeat.UnicitySeal.Timestamp
	repeated, err := a.Authenticate(ctx, req)
	require.NoError(t, err)
	require.Equal(t, first.AssignedRound, repeated.AssignedRound, "the conflict key is the assigned round")
	require.NotEqual(t, first.ID, repeated.ID, "a different root round is a different authorization")
}

func TestAuthorityOffersNoGenericSigningOrKeyImport(t *testing.T) {
	// The absence of these methods is the contract, so it is asserted rather than assumed. A future
	// SignBytes, ImportKey, ExportKey or LoadJournal would fail this test, which is the point.
	var methods []string
	at := reflect.TypeOf(&Authority{})
	for i := 0; i < at.NumMethod(); i++ {
		methods = append(methods, at.Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Authenticate", "Close", "Enrollment", "SigningPublicKey"}, methods,
		"this authority admits structured requests only: no generic signing, key import, key export or journal load")

	f := newFixture(t, 1)
	t.Run("an enrollment naming a key is refused", func(t *testing.T) {
		enroll := f.enroll
		enroll.SigningKeyFingerprint = []byte{0x01}
		_, err := New(enroll, trustStub{tb: f.tb})
		require.ErrorContains(t, err, "no key-import path")
	})

	t.Run("every lifetime has its own key", func(t *testing.T) {
		first, err := New(f.enroll, trustStub{tb: f.tb})
		require.NoError(t, err)
		second, err := New(f.enroll, trustStub{tb: f.tb})
		require.NoError(t, err)
		firstKey, err := first.SigningPublicKey()
		require.NoError(t, err)
		secondKey, err := second.SigningPublicKey()
		require.NoError(t, err)
		require.NotEqual(t, firstKey, secondKey, "a replacement authority cannot recreate the old identity")
		require.NotEqual(t, first.Enrollment().SigningKeyFingerprint, second.Enrollment().SigningKeyFingerprint)
	})

	t.Run("a closed authority authenticates nothing and cannot be revived", func(t *testing.T) {
		a := f.authority(t)
		a.Close()
		_, err := a.Authenticate(context.Background(), f.request())
		require.ErrorIs(t, err, ErrKeyLost)
		_, err = a.SigningPublicKey()
		require.ErrorIs(t, err, ErrKeyLost)
	})
}

func TestEnrollmentBytesAreOwnedByTheAuthority(t *testing.T) {
	f := newFixture(t, 1)
	callerOwned := make([]byte, len(f.confHash))
	copy(callerOwned, f.confHash)
	enroll := f.enroll
	enroll.ShardConfHash = callerOwned

	a, err := New(enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	for i := range callerOwned {
		callerOwned[i] ^= 0xff
	}
	_, err = a.Authenticate(context.Background(), f.request())
	require.NoError(t, err, "mutating the caller's slice cannot change what this authority enforces")

	returned := a.Enrollment()
	returned.ShardConfHash[0] ^= 0xff
	*returned.RootEpoch = rootEpoch + 99
	_, err = a.Authenticate(context.Background(), f.request())
	require.NoError(t, err, "nor can mutating a copy handed back by Enrollment, including its pinned root epoch")

	// The pinned epoch the caller passed in is owned too. This starts from a clean enrollment,
	// because the one above has had its configuration hash mutated on purpose.
	callerEpoch := PinRootEpoch(rootEpoch)
	pinned := f.enroll
	pinned.RootEpoch = callerEpoch
	withPinnedEpoch, err := New(pinned, trustStub{tb: f.tb})
	require.NoError(t, err)
	*callerEpoch = rootEpoch + 99
	_, err = withPinnedEpoch.Authenticate(context.Background(), f.request())
	require.NoError(t, err, "mutating the caller's pinned epoch cannot move the freeze")
}

// mutatingTrust runs a caller's change at the moment the authority looks up its trust base. That is
// the widest window in Authenticate, and it is exactly where the review's reproductions struck.
type mutatingTrust struct {
	tb     *types.RootTrustBaseV1
	mutate func()
}

func (m mutatingTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if m.mutate != nil {
		m.mutate()
	}
	return m.tb, nil
}

func TestTheRequestIsOwnedBeforeItIsChecked(t *testing.T) {
	ctx := context.Background()

	t.Run("a proposal made valid during the check is judged as it arrived", func(t *testing.T) {
		// The review's reproduction. An invalid round-999 proposal becomes the assigned round while
		// the authority waits for its trust base. What is judged, and what would be returned, is the
		// proposal as taken at entry, so this is refused.
		f := newFixture(t, 1)
		req := f.request()
		req.Proposed.InputRecord.RoundNumber = 999
		asArrived, err := req.Proposed.Bytes()
		require.NoError(t, err)

		a, err := New(f.enroll, mutatingTrust{tb: f.tb, mutate: func() {
			req.Proposed.InputRecord.RoundNumber = assignedRound
		}})
		require.NoError(t, err)

		_, authErr := a.Authenticate(ctx, req)
		require.ErrorIs(t, authErr, ErrProposalMismatch,
			"the proposal taken at entry names round 999, so it cannot become authentic mid-check")

		// And the caller's structure really was changed underneath, so the test is not vacuous.
		nowValid, err := req.Proposed.Bytes()
		require.NoError(t, err)
		require.NotEqual(t, asArrived, nowValid)
	})

	t.Run("a proposal made invalid during the check is still the one returned", func(t *testing.T) {
		// The other direction. A valid proposal is broken while the authority waits; the
		// authorization must still describe, and return, the proposal as taken at entry.
		f := newFixture(t, 1)
		req := f.request()
		asArrived, err := req.Proposed.Bytes()
		require.NoError(t, err)

		a, err := New(f.enroll, mutatingTrust{tb: f.tb, mutate: func() {
			req.Proposed.InputRecord.RoundNumber = 999
			req.Proposed.BlockSize = 4242
		}})
		require.NoError(t, err)

		auth, err := a.Authenticate(ctx, req)
		require.NoError(t, err)
		require.EqualValues(t, assignedRound, auth.AssignedRound)
		require.Equal(t, asArrived, auth.Unsigned, "the returned preimage is what was validated")
	})

	t.Run("the certificate and technical record are copies too", func(t *testing.T) {
		f := newFixture(t, 1)
		req := f.request()
		unchanged, err := New(f.enroll, trustStub{tb: f.tb})
		require.NoError(t, err)
		expected, err := unchanged.Authenticate(ctx, f.request())
		require.NoError(t, err)

		a, err := New(f.enroll, mutatingTrust{tb: f.tb, mutate: func() {
			// Both would break authentication if they were read after this point.
			req.UC.InputRecord.Hash = bytes.Repeat([]byte{0xee}, 32)
			req.Technical.Leader = "validator-B"
		}})
		require.NoError(t, err)

		auth, err := a.Authenticate(ctx, req)
		require.NoError(t, err, "the certificate and technical record are read from the snapshot")
		require.Equal(t, expected.ID, auth.ID, "including the authorization identity derived from them")
	})
}

func TestRootEpochIsFrozenByEnrollment(t *testing.T) {
	// The review's second reproduction. The next root epoch is genuine: it verifies against the
	// trust base the authority is given. This profile does not follow a transition, so the authority
	// refuses rather than carrying the same key into the new epoch.
	f := newFixture(t, 1)
	ctx := context.Background()
	a := f.authority(t)

	_, err := a.Authenticate(ctx, f.request())
	require.NoError(t, err, "the enrolled epoch is ordinary work")

	f.uc.UnicitySeal.Epoch++
	f.tb.Epoch++
	f.signSealTo(t, f.uc, quorum(1))

	_, err = a.Authenticate(ctx, f.request())
	require.ErrorIs(t, err, ErrContextMismatch, "a genuine next root epoch is a freeze, not ordinary work")
	require.NotErrorIs(t, err, ErrUnauthenticated,
		"and it is not an authentication failure: the certificate verifies, which is why this refusal has to exist")
}

func TestTheFreezeRefusalDoesNotAssertAuthenticity(t *testing.T) {
	// The freeze is checked before the trust lookup, so that an epoch chosen by the sender cannot
	// select which trust base is fetched. A certificate that is forged AND names another epoch is
	// therefore refused by the freeze, at a point where nothing about it has been authenticated.
	// The refusal must not read as a statement that the certificate is genuinely from that epoch.
	f := newFixture(t, 1)
	a := f.authority(t)
	req := f.request()
	req.UC.UnicitySeal.Epoch = 99 // not re-signed: this seal verifies against nothing

	_, err := a.Authenticate(context.Background(), req)
	require.ErrorIs(t, err, ErrContextMismatch)
	require.NotErrorIs(t, err, ErrUnauthenticated)
	require.Contains(t, err.Error(), "claims root epoch 99")
	require.Contains(t, err.Error(), "not established")
	require.NotContains(t, err.Error(), "is for root epoch",
		"the authority has verified nothing at this point and must not say the certificate is from that epoch")

	// A forgery that names the ENROLLED epoch does reach verification, and is reported as a forgery.
	// This needs its own fixture: the certificate above was mutated in place.
	g := newFixture(t, 1)
	sameEpoch := g.request()
	forgedSeal := *g.uc.UnicitySeal
	forgedSeal.Signatures = types.SignatureMap{"nobody": []byte("not a signature")}
	forged := *g.uc
	forged.UnicitySeal = &forgedSeal
	sameEpoch.UC = &forged
	_, err = g.authority(t).Authenticate(context.Background(), sameEpoch)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestEnrollmentMustStateItsRootEpoch(t *testing.T) {
	// "Not stated" and "pinned to epoch 0" are different, and nothing rejects epoch 0 in a seal, so
	// an enrollment that never named one is refused rather than defaulted.
	f := newFixture(t, 1)
	enroll := f.enroll
	enroll.RootEpoch = nil
	_, err := New(enroll, trustStub{tb: f.tb})
	require.ErrorContains(t, err, "states no root epoch")

	enroll.RootEpoch = PinRootEpoch(0)
	pinnedToZero, err := New(enroll, trustStub{tb: f.tb})
	require.NoError(t, err, "epoch 0 is a pin like any other")
	_, err = pinnedToZero.Authenticate(context.Background(), f.request())
	require.ErrorIs(t, err, ErrContextMismatch)
}
