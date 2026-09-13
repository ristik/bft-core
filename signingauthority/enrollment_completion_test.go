package signingauthority

/*
Completing a pending enrollment, which is how a deployment enrolls an authority.

The shard configuration hash that certificates commit to covers every validator's signing key, and
the authority generates its key in New. So a real configuration can only name the authority's key
after New has returned, and the hash is stated afterwards, once, from a configuration the authority
has checked. These tests hold that the check is the authority's own, that nothing is admitted
before it, and that it does not reopen.
*/

import (
	gocrypto "crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// pending enrolls an authority for the fixture's scope without a configuration hash.
func (f *fixture) pending(t *testing.T) *Authority {
	t.Helper()
	enroll := f.enroll
	enroll.ShardConfHash = nil
	a, err := New(enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	t.Cleanup(a.Close)
	return a
}

// confNaming is a valid shard configuration for the fixture's scope with one validator.
func confNaming(nodeID string, sigKey []byte) *types.PartitionDescriptionRecord {
	return &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, PartitionTypeID: 1,
		ShardID: types.ShardID{}, Epoch: shardEpoch, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout:  2500 * time.Millisecond,
		Validators: []*types.NodeInfo{{NodeID: nodeID, SigKey: sigKey, Stake: 1}},
	}
}

// ownConf is the configuration a deployment writes for this authority: the enrolled node, with the
// key the authority generated.
func ownConf(t *testing.T, a *Authority) *types.PartitionDescriptionRecord {
	t.Helper()
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	return confNaming(testNodeID, pub)
}

// requestUnder is the fixture's request, certified by the root under the given configuration.
func (f *fixture) requestUnder(t *testing.T, conf *types.PartitionDescriptionRecord) Request {
	t.Helper()
	zero := make([]byte, 32)
	trHash, err := f.tr.Hash()
	require.NoError(t, err)
	certified := &types.InputRecord{
		Version: 1, RoundNumber: certifiedRound, Epoch: shardEpoch,
		PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], certified, conf, 50, zero, trHash)
	f.signSealTo(t, uc, quorum(len(f.signers)))
	req := f.request()
	req.UC = uc
	req.Proposed.InputRecord.PreviousHash = uc.InputRecord.Hash
	req.Proposed.InputRecord.Timestamp = uc.UnicitySeal.Timestamp
	return req
}

func TestAPendingAuthorityAdmitsNothingUntilItsConfigurationIsStated(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	req := f.requestUnder(t, conf)

	require.Empty(t, a.Enrollment().ShardConfHash)
	_, err := a.ReplaceSession()
	require.ErrorIs(t, err, ErrEnrollmentIncomplete, "no credential is issued for an authority that cannot check a configuration")
	_, err = a.Authenticate(t.Context(), req)
	require.ErrorIs(t, err, ErrEnrollmentIncomplete, "and nothing is authenticated")
	require.Zero(t, a.Status().Generation)

	require.NoError(t, a.CompleteEnrollment(conf))
	want, err := conf.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, want, a.Enrollment().ShardConfHash, "the hash is the authority's own computation over the checked configuration")

	session, err := a.ReplaceSession()
	require.NoError(t, err)
	authorization, err := a.Reserve(t.Context(), session, req)
	require.NoError(t, err)
	require.NoError(t, a.Sign(session))
	require.NoError(t, a.RetainResponse(session))
	released, err := a.Release(session, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)

	// What the root chain does with it: verify under the key this configuration names for the node.
	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(released, &signed))
	verifier, err := conf.Validators[0].SigVerifier()
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(verifier), "the response verifies under the configuration the authority completed")
}

func TestCompletingAnEnrollmentChecksTheConfigurationAgainstTheAuthority(t *testing.T) {
	f := newFixture(t, 1)
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	otherVerifier, err := other.Verifier()
	require.NoError(t, err)
	otherKey, err := otherVerifier.MarshalPublicKey()
	require.NoError(t, err)

	refused := func(t *testing.T, a *Authority, conf *types.PartitionDescriptionRecord, target error) {
		t.Helper()
		require.ErrorIs(t, a.CompleteEnrollment(conf), target)
		require.Empty(t, a.Enrollment().ShardConfHash, "a refused completion changes nothing")
		_, err := a.ReplaceSession()
		require.ErrorIs(t, err, ErrEnrollmentIncomplete)
	}

	t.Run("the node with another key", func(t *testing.T) {
		a := f.pending(t)
		refused(t, a, confNaming(testNodeID, otherKey), ErrContextMismatch)
	})

	t.Run("this key for another node", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		conf.Validators[0].NodeID = "validator-B"
		refused(t, a, conf, ErrContextMismatch)
	})

	t.Run("another network", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		conf.NetworkID = testNetworkID + 1
		refused(t, a, conf, ErrContextMismatch)
	})

	t.Run("another partition", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		conf.PartitionID = testPartitionID + 1
		refused(t, a, conf, ErrContextMismatch)
	})

	t.Run("another shard epoch", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		conf.Epoch = shardEpoch + 1
		refused(t, a, conf, ErrContextMismatch)
	})

	t.Run("an invalid configuration", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		conf.T2Timeout = time.Millisecond
		refused(t, a, conf, ErrContextMismatch)
	})

	t.Run("no configuration", func(t *testing.T) {
		refused(t, f.pending(t), nil, ErrContextMismatch)
	})

	t.Run("a refusal leaves the enrollment completable", func(t *testing.T) {
		a := f.pending(t)
		refused(t, a, confNaming(testNodeID, otherKey), ErrContextMismatch)
		require.NoError(t, a.CompleteEnrollment(ownConf(t, a)))
	})

	t.Run("a completed enrollment is not reopened, even for the same configuration", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		require.NoError(t, a.CompleteEnrollment(conf))
		stated := a.Enrollment().ShardConfHash

		require.ErrorIs(t, a.CompleteEnrollment(conf), ErrContextMismatch)
		moved := ownConf(t, a)
		moved.T2Timeout = 5 * time.Second
		require.ErrorIs(t, a.CompleteEnrollment(moved), ErrContextMismatch)
		require.Equal(t, stated, a.Enrollment().ShardConfHash)
	})

	t.Run("an enrollment stated at New is already complete", func(t *testing.T) {
		a := f.authority(t)
		require.ErrorIs(t, a.CompleteEnrollment(ownConf(t, a)), ErrContextMismatch)
		require.Equal(t, f.confHash, a.Enrollment().ShardConfHash)
	})

	t.Run("a closed authority", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		a.Close()
		require.ErrorIs(t, a.CompleteEnrollment(conf), ErrKeyLost)
	})

	t.Run("a faulted authority", func(t *testing.T) {
		a := f.pending(t)
		conf := ownConf(t, a)
		a.MarkUntrusted("test")
		require.ErrorIs(t, a.CompleteEnrollment(conf), ErrStateUntrusted)
	})
}
