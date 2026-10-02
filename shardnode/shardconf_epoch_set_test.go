package shardnode

/*
After an EVM assignment is activated the root certifies the shard under the successor configuration. The client must then accept
certificates under the hash of the epoch each one claims, and nothing else: an epoch-indexed set, seeded with the genesis entry and
extended only from verified committed assignment steps.
*/

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

type confEpochFixture struct {
	tb           *types.RootTrustBaseV1
	signer       abcrypto.Signer
	conf0, conf1 []byte
	tr0, tr1     *certification.TechnicalRecord
	uc0, uc1     *types.UnicityCertificate // epoch 0 under conf0, epoch 1 under conf1
	ucEpoch1Old  *types.UnicityCertificate // claims epoch 1 (its TR) but carries epoch 0's configuration
}

func newConfEpochFixture(t *testing.T) *confEpochFixture {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	zero := make([]byte, 32)
	pdr0 := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000, Epoch: 0}
	pdr1 := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000, Epoch: 1, EpochStart: 20}
	conf0, err := pdr0.Hash(crypto.SHA256)
	require.NoError(t, err)
	conf1, err := pdr1.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, conf0, conf1)
	f := &confEpochFixture{tb: tb, signer: signer, conf0: conf0, conf1: conf1,
		tr0: &certification.TechnicalRecord{Round: 5, Epoch: 0, Leader: "conf-epoch-node", StatHash: zero, FeeHash: zero},
		tr1: &certification.TechnicalRecord{Round: 25, Epoch: 1, Leader: "conf-epoch-node", StatHash: zero, FeeHash: zero}}
	h0, err := f.tr0.Hash()
	require.NoError(t, err)
	h1, err := f.tr1.Hash()
	require.NoError(t, err)
	ir0 := &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1}
	ir1 := &types.InputRecord{Version: 1, RoundNumber: 24, PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 2}
	f.uc0 = testcertificates.CreateUnicityCertificate(t, signer, ir0, pdr0, 50, zero, h0)
	f.uc1 = testcertificates.CreateUnicityCertificate(t, signer, ir1, pdr1, 60, zero, h1)
	f.ucEpoch1Old = testcertificates.CreateUnicityCertificate(t, signer, ir1, pdr0, 60, zero, h1)
	return f
}

func (f *confEpochFixture) respond(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) *certification.CertificationResponse {
	return &certification.CertificationResponse{Partition: authPartitionID, Shard: types.ShardID{}, Technical: *tr, UC: *uc}
}

func (f *confEpochFixture) client(t *testing.T) (*BFTClient, *recordingDriver) {
	t.Helper()
	b := &confBindingFixture{tb: f.tb}
	c, drv := b.client(f.conf0)
	c.confs = map[uint64][]byte{0: f.conf0}
	return c, drv
}

func TestCertificatesAreVerifiedUnderTheirOwnEpochsConfiguration(t *testing.T) {
	ctx := context.Background()
	f := newConfEpochFixture(t)

	t.Run("a new-epoch certificate is refused before its assignment is installed, retryably", func(t *testing.T) {
		c, drv := f.client(t)
		err := c.handleCertificationResponse(ctx, f.respond(f.uc1, f.tr1))
		require.ErrorIs(t, err, ErrShardConfEpochUnknown)
		require.Empty(t, drv.rounds())
		require.Nil(t, c.luc)
		// "retryable after the install": the very same certificate is accepted once the verified step is installed
		require.NoError(t, c.InstallShardConf(1, f.conf1))
		require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.uc1, f.tr1)))
		require.Equal(t, []uint64{24}, drv.rounds())
	})

	t.Run("an old-epoch certificate still verifies under its own configuration after the install", func(t *testing.T) {
		c, drv := f.client(t)
		require.NoError(t, c.InstallShardConf(1, f.conf1))
		require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.uc0, f.tr0)))
		require.Equal(t, []uint64{4}, drv.rounds(), "catch-up, archive replay and history keep working")
	})

	t.Run("a certificate claiming epoch 1 with epoch 0's configuration is refused", func(t *testing.T) {
		c, drv := f.client(t)
		require.NoError(t, c.InstallShardConf(1, f.conf1))
		err := c.handleCertificationResponse(ctx, f.respond(f.ucEpoch1Old, f.tr1))
		require.ErrorContains(t, err, "shard configuration hash", "the stale hash is not accepted at the new epoch")
		require.NotErrorIs(t, err, ErrShardConfEpochUnknown)
		require.Empty(t, drv.rounds())
	})

	t.Run("a certificate claiming epoch 0 with epoch 1's configuration is refused", func(t *testing.T) {
		c, drv := f.client(t)
		require.NoError(t, c.InstallShardConf(1, f.conf1))
		wrong := f.respond(f.uc1, f.tr0) // the TR is not the one the certificate binds
		require.Error(t, c.handleCertificationResponse(ctx, wrong))
		require.Empty(t, drv.rounds())
	})
}

func TestInstallShardConfIsOnlyEverConsistent(t *testing.T) {
	f := newConfEpochFixture(t)
	c, _ := f.client(t)
	require.NoError(t, c.InstallShardConf(1, f.conf1))
	require.NoError(t, c.InstallShardConf(1, f.conf1), "the same step again is a no-op")
	require.ErrorIs(t, c.InstallShardConf(1, f.conf0), ErrShardConfConflict, "a different hash for an installed epoch is refused")
	require.ErrorIs(t, c.InstallShardConf(0, f.conf1), ErrShardConfConflict, "and the genesis entry cannot be replaced")
	require.Error(t, c.InstallShardConf(2, []byte{1, 2, 3}), "a malformed hash is refused")
	_, err := c.expectedShardConf(2)
	require.ErrorIs(t, err, ErrShardConfEpochUnknown, "an epoch that was never installed has no fallback")
}

// The set is rebuilt after a restart from genesis plus the verified followed bundles: the follower replays every persisted bundle
// through the same step-install, so a fresh client, which knows only genesis, refuses the new epoch until it has.
func TestRestartRebuildsTheConfigurationSetFromGenesisAndTheFollowedSteps(t *testing.T) {
	ctx := context.Background()
	f := newConfEpochFixture(t)
	fresh, _ := f.client(t)
	delete(fresh.confs, 0)
	fresh.confs = nil // as constructed: only the genesis pin, no assignment known
	err := fresh.handleCertificationResponse(ctx, f.respond(f.uc1, f.tr1))
	require.ErrorIs(t, err, ErrShardConfEpochUnknown, "never trust the startup configuration alone")

	steps := []struct {
		epoch uint64
		hash  []byte
	}{{0, f.conf0}, {1, f.conf1}, {1, f.conf1}} // replaying a bundle twice (restore then catch-up) is harmless
	for _, s := range steps {
		require.NoError(t, fresh.InstallShardConf(s.epoch, s.hash))
	}
	drv := &recordingDriver{}
	fresh.driver = drv
	require.NoError(t, fresh.handleCertificationResponse(ctx, f.respond(f.uc1, f.tr1)))
	require.Equal(t, []uint64{24}, drv.rounds())
}

// The identity handed to the admission factory is the deployment's GENESIS configuration, always: the factory pins it against the
// registry genesis, and assignments are verified separately. An installed assignment must not change it.
func TestAdmissionIdentityStaysTheGenesisConfigurationAfterAnAssignmentIsInstalled(t *testing.T) {
	f := newConfEpochFixture(t)
	c, _ := f.client(t)
	require.NoError(t, c.InstallShardConf(1, f.conf1))
	id, err := ownAdmissionIdentity(c.partitionID, c.shardID, c.shardConfHash, c.trustBaseStore)
	require.NoError(t, err)
	require.Equal(t, f.conf0, id.FullShardConfHash)
	require.NotEqual(t, f.conf1, id.FullShardConfHash)
}

// The queue-side authorization check (an ordering guard that repeats the delivery checks) takes the hash of the claimed epoch too.
func TestCertificationAuthorizationUsesTheClaimedEpochsConfiguration(t *testing.T) {
	ctx := context.Background()
	f := newConfEpochFixture(t)
	c, _ := f.client(t)
	_, err := c.verifyCertificationAuthorization(ctx, f.respond(f.uc1, f.tr1))
	require.ErrorIs(t, err, ErrShardConfEpochUnknown)
	require.NoError(t, c.InstallShardConf(1, f.conf1))
	_, err = c.verifyCertificationAuthorization(ctx, f.respond(f.uc1, f.tr1))
	require.NoError(t, err)
	_, err = c.verifyCertificationAuthorization(ctx, f.respond(f.uc0, f.tr0))
	require.NoError(t, err, "history still verifies")
	_, err = c.verifyCertificationAuthorization(ctx, f.respond(f.ucEpoch1Old, f.tr1))
	require.ErrorContains(t, err, "shard configuration hash")
}

// A late certificate from a retired root epoch is authenticated before it is dropped, under the configuration of the epoch it claims.
func TestRetiredRootEpochCertificatesAreAuthenticatedUnderTheirOwnConfiguration(t *testing.T) {
	f := newConfEpochFixture(t)
	build := func(t *testing.T) (*BFTClient, *certification.CertificationResponse) {
		b := &confBindingFixture{tb: f.tb, ucMine: f.uc1}
		client, _ := newAdmissionTestClient(t, &admissionSink{}, &admissionTestNet{})
		client.trustBaseStore = activeV2AdmissionTrustStore{stubTrustBaseStore{tb: f.tb}}
		client.admission = &admissionTestSession{epoch: 3, profile2Ready: true, callbacks: AdmissionCallbacks{
			AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
		}}
		client.shardConfHash, client.confs = f.conf0, nil
		uc := *b.ucMine
		seal := *uc.UnicitySeal
		uc.UnicitySeal = &seal
		seal.Epoch = 2 // a retired root epoch (the admission session is at 3)
		seal.Signatures = nil
		for signer := range f.uc1.UnicitySeal.Signatures {
			require.NoError(t, seal.Sign(signer, f.signer))
		}
		response := f.respond(&uc, f.tr1)
		require.NoError(t, response.IsValid())
		return client, response
	}
	t.Run("unknown shard epoch is refused, as an invalid stale certificate", func(t *testing.T) {
		client, response := build(t)
		err := client.handleCertificationResponse(context.Background(), response)
		require.ErrorIs(t, err, ErrStaleEpochCertificateInvalid)
		require.ErrorIs(t, err, ErrShardConfEpochUnknown)
	})
	t.Run("an installed epoch verifies and is dropped", func(t *testing.T) {
		client, response := build(t)
		require.NoError(t, client.InstallShardConf(1, f.conf1))
		require.NoError(t, client.handleCertificationResponse(context.Background(), response))
	})
}
