package shardnode

/*
#134: a certificate is this node's authority only if it commits to the shard configuration THIS NODE
was started with.

The situation under test is not a forgery. Every certificate here is signed by the same trusted root
quorum, for the same partition and the same shard; they differ only in the shard configuration they
were issued under. Before this binding existed, `UC.Verify` was called with a nil configuration hash
on both the live and the restore path — and `UnicityCertificate.IsValid` compares the configuration
ONLY when it is given one, so nil did not make the check lenient, it removed it. A certificate about
another chain became local authority, reached the round driver and authenticated from disk.

The refusal must also be distinguishable from a bad signature: one means a peer or root chain serving
a different chain, the other means a forgery, and an operator needs to tell them apart.
*/

import (
	"bytes"
	"context"
	"crypto"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// silentNet is a RootNetwork that sends nowhere and delivers nothing: these tests drive
// handleCertificationResponse directly, and only need a client that constructs.
type silentNet struct{ ch chan any }

func (n silentNet) Send(context.Context, any, ...peer.ID) error { return nil }
func (n silentNet) ReceivedChannel() <-chan any                 { return n.ch }

// confBindingFixture builds two shard configurations for the SAME partition and shard, differing
// only in a field every certificate commits to, and a genuinely signed certificate under each.
type confBindingFixture struct {
	tb        *types.RootTrustBaseV1
	signer    abcrypto.Signer
	confMine  []byte
	confOther []byte
	ucMine    *types.UnicityCertificate
	ucOther   *types.UnicityCertificate
	technical *certification.TechnicalRecord
}

func newConfBindingFixture(t *testing.T) *confBindingFixture {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	zero := make([]byte, 32)

	mine := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	other := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 5000000000}
	confMine, err := mine.Hash(crypto.SHA256)
	require.NoError(t, err)
	confOther, err := other.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, confMine, confOther, "the two configurations must commit differently, or this test proves nothing")

	technical := &certification.TechnicalRecord{Round: 5, Epoch: 0, Leader: "conf-binding-node", StatHash: zero, FeeHash: zero}
	trHash, err := technical.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1}

	f := &confBindingFixture{
		tb: tb, signer: signer, confMine: confMine, confOther: confOther, technical: technical,
		ucMine:  testcertificates.CreateUnicityCertificate(t, signer, ir, mine, 50, zero, trHash),
		ucOther: testcertificates.CreateUnicityCertificate(t, signer, ir, other, 50, zero, trHash),
	}
	// Both are authentic: same trusted quorum, same partition, same shard. Only the configuration
	// they name differs, and each verifies against its own.
	require.NoError(t, f.ucMine.Verify(tb, crypto.SHA256, authPartitionID, types.ShardID{}, confMine))
	require.NoError(t, f.ucOther.Verify(tb, crypto.SHA256, authPartitionID, types.ShardID{}, confOther))
	require.Equal(t, f.ucMine.GetPartitionID(), f.ucOther.GetPartitionID())
	require.True(t, f.ucMine.GetShardID().Equal(f.ucOther.GetShardID()))
	return f
}

func (f *confBindingFixture) respond(uc *types.UnicityCertificate) *certification.CertificationResponse {
	return &certification.CertificationResponse{
		Partition: authPartitionID, Shard: types.ShardID{}, Technical: *f.technical, UC: *uc,
	}
}

func (f *confBindingFixture) client(confHash []byte) (*BFTClient, *recordingDriver) {
	drv := &recordingDriver{}
	c := &BFTClient{
		partitionID:    authPartitionID,
		shardID:        types.ShardID{},
		shardConfHash:  confHash,
		nodeID:         "conf-binding-node",
		trustBaseStore: stubTrustBaseStore{tb: f.tb},
		driver:         drv,
		log:            slog.New(&capturingHandler{}),
	}
	c.lastCertResponseTime.Store(1)
	return c, drv
}

func TestLiveDeliveryIsBoundToTheConfiguredShardConfiguration(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)

	t.Run("a certificate for the configured shard configuration is accepted", func(t *testing.T) {
		c, drv := f.client(f.confMine)
		require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
		require.Equal(t, []uint64{4}, drv.rounds(), "it reaches the round driver")
		require.NotNil(t, c.luc, "and becomes this node's certificate cursor")
	})

	t.Run("a genuinely signed certificate for another configuration is refused", func(t *testing.T) {
		c, drv := f.client(f.confMine)
		err := c.handleCertificationResponse(ctx, f.respond(f.ucOther))
		require.Error(t, err)
		require.ErrorContains(t, err, "shard configuration hash",
			"the refusal must name what differs, not merely fail verification")
		require.Empty(t, drv.rounds(), "it must not reach the round driver")
		require.Nil(t, c.luc, "and must not become the certificate cursor")
	})

	t.Run("that refusal is distinguishable from a forgery", func(t *testing.T) {
		forged := *f.ucMine
		seal := *forged.UnicitySeal
		seal.Signatures = types.SignatureMap{"nobody": []byte("not a signature")}
		forged.UnicitySeal = &seal

		c, drv := f.client(f.confMine)
		err := c.handleCertificationResponse(ctx, f.respond(&forged))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "shard configuration hash",
			"a forged certificate for the right configuration is a different situation")
		require.Empty(t, drv.rounds())
	})

	t.Run("a client with no configured configuration refuses instead of accepting anything", func(t *testing.T) {
		c, drv := f.client(nil)
		err := c.handleCertificationResponse(ctx, f.respond(f.ucMine))
		require.ErrorContains(t, err, "no configured shard configuration hash",
			"an absent expectation removes the check, so it must be refused rather than skipped")
		require.Empty(t, drv.rounds())
	})
}

func TestRestoredCertificateIsBoundToTheConfiguredShardConfiguration(t *testing.T) {
	f := newConfBindingFixture(t)
	store := stubTrustBaseStore{tb: f.tb}

	t.Run("the configured configuration authenticates", func(t *testing.T) {
		require.NoError(t, verifyRestoredLUC(f.ucMine, store, authPartitionID, types.ShardID{}, f.confMine))
	})

	t.Run("another configuration does not, however genuine", func(t *testing.T) {
		err := verifyRestoredLUC(f.ucOther, store, authPartitionID, types.ShardID{}, f.confMine)
		require.ErrorContains(t, err, "shard configuration hash")
	})

	t.Run("an encoded checkpoint on disk for another configuration does not authenticate", func(t *testing.T) {
		// The production restore sequence: SaveLUC/LoadLUC, then authentication, before SeedLUC.
		fs := NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
		require.NoError(t, fs.SaveLUC(f.ucOther))
		loaded, err := fs.LoadLUC()
		require.NoError(t, err)
		require.NotNil(t, loaded)
		require.ErrorContains(t,
			verifyRestoredLUC(loaded, store, authPartitionID, types.ShardID{}, f.confMine),
			"shard configuration hash")

		// ...and the same file under the configuration it was issued for does authenticate, so the
		// refusal above is about the configuration and not about the encoding.
		require.NoError(t, verifyRestoredLUC(loaded, store, authPartitionID, types.ShardID{}, f.confOther))
	})

	t.Run("no configured configuration is a refusal, not a skipped check", func(t *testing.T) {
		err := verifyRestoredLUC(f.ucMine, store, authPartitionID, types.ShardID{}, nil)
		require.ErrorContains(t, err, "no shard configuration hash configured")
	})
}

func TestNodeRequiresTheConfiguredShardConfiguration(t *testing.T) {
	// Checked before anything else is built, so this reaches the refusal without a peer or network:
	// a deployment that cannot say which configuration it runs must not start, whatever else it has.
	for _, tc := range []struct {
		name string
		hash []byte
	}{{"absent", nil}, {"empty", []byte{}}} {
		t.Run(tc.name+" shard configuration hash is refused at construction", func(t *testing.T) {
			_, err := New(nil, nil, nil, authPartitionID, types.ShardID{}, tc.hash, nil, nil, nil, nil, nil, BFTClientOptions{})
			require.ErrorContains(t, err, "no shard configuration hash")
		})
	}
}

func TestConfiguredShardConfigurationIsOwnedByTheClient(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)

	// The caller keeps its own slice and mutates it after construction. Verification policy must not
	// move with it: the client cloned the value.
	callerOwned := bytes.Clone(f.confMine)
	c, err := NewBFTClient(
		testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)),
		silentNet{ch: make(chan any, 1)},
		f.signer, authPartitionID, types.ShardID{}, callerOwned,
		stubTrustBaseStore{tb: f.tb}, &recordingDriver{}, nil, DefaultBFTClientOptions)
	require.NoError(t, err)

	for i := range callerOwned {
		callerOwned[i] ^= 0xff
	}
	require.NotEqual(t, callerOwned, f.confMine, "the caller's slice really was mutated")

	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)),
		"the configured configuration is still accepted")
	require.ErrorContains(t,
		c.handleCertificationResponse(ctx, f.respond(f.ucOther)), "shard configuration hash",
		"and another configuration is still refused")
}

func TestNewBFTClientRequiresTheConfiguredShardConfiguration(t *testing.T) {
	f := newConfBindingFixture(t)
	_, err := NewBFTClient(
		testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)),
		silentNet{ch: make(chan any, 1)},
		f.signer, authPartitionID, types.ShardID{}, nil,
		stubTrustBaseStore{tb: f.tb}, &recordingDriver{}, nil, DefaultBFTClientOptions)
	require.ErrorContains(t, err, "no shard configuration hash")
}

func TestMalformedConfiguredShardHashRefusedBeforeUse(t *testing.T) {
	for _, size := range []int{1, 31, 33} {
		hash := make([]byte, size)
		_, err := New(nil, nil, nil, authPartitionID, types.ShardID{}, hash, nil, nil, nil, nil, nil, BFTClientOptions{})
		require.ErrorContains(t, err, "malformed shard configuration hash")
		_, err = NewBFTClient(nil, nil, nil, authPartitionID, types.ShardID{}, hash, nil, nil, nil, BFTClientOptions{})
		require.ErrorContains(t, err, "malformed shard configuration hash")
		// A malformed expectation is refused before dereferencing the certificate or looking up trust.
		err = verifyRestoredLUC(nil, stubTrustBaseStore{}, authPartitionID, types.ShardID{}, hash)
		require.ErrorContains(t, err, "malformed shard configuration hash")
	}
}
