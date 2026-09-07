package shardnode

import (
	"context"
	"crypto"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const authPartitionID types.PartitionID = 1

type stubTrustBaseStore struct {
	tb  *types.RootTrustBaseV1
	err error
}

func (s stubTrustBaseStore) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.tb, nil
}

func authFixture(t *testing.T) (abcrypto.Signer, *types.RootTrustBaseV1, *types.UnicityCertificate) {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	h := make([]byte, 32)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h,
		SummaryValue: []byte{}, Timestamp: 1,
	}
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, 50, h, h)
	return signer, tb, uc
}

// TestVerifyRestoredLUC covers issue #86 delivery step 4: nothing malformed, unsigned,
// wrong-shard or from an untrusted epoch may become this node's non-equivocation
// authority. Before this, LoadLUC's JSON decode was the only gate.
func TestVerifyRestoredLUC(t *testing.T) {
	_, tb, authentic := authFixture(t)
	store := stubTrustBaseStore{tb: tb}

	t.Run("an authentic certificate is accepted", func(t *testing.T) {
		require.NoError(t, verifyRestoredLUC(authentic, store, authPartitionID, types.ShardID{}))
	})

	t.Run("an unsigned certificate is rejected", func(t *testing.T) {
		forged := &types.UnicityCertificate{
			Version:     1,
			InputRecord: authentic.InputRecord,
			UnicitySeal: &types.UnicitySeal{
				Version: 1, RootChainRoundNumber: 999999, Timestamp: 1,
				Hash: make([]byte, 32), Signatures: nil,
			},
		}
		require.Error(t, verifyRestoredLUC(forged, store, authPartitionID, types.ShardID{}))
	})

	t.Run("a certificate for another partition is rejected", func(t *testing.T) {
		require.Error(t, verifyRestoredLUC(authentic, store, authPartitionID+1, types.ShardID{}))
	})

	t.Run("an unavailable or untrusted epoch is rejected, not adopted", func(t *testing.T) {
		err := verifyRestoredLUC(authentic, stubTrustBaseStore{err: errors.New("unknown epoch")}, authPartitionID, types.ShardID{})
		require.ErrorContains(t, err, "loading trust base for root epoch")
	})

	t.Run("no configured trust base store is rejected", func(t *testing.T) {
		require.ErrorContains(t, verifyRestoredLUC(authentic, nil, authPartitionID, types.ShardID{}), "no trust base store")
	})

	t.Run("a tampered but decodable certificate is rejected", func(t *testing.T) {
		// Round-trip an authentic certificate, then alter one input record field. It still
		// decodes perfectly; its signatures no longer cover it.
		path := filepath.Join(t.TempDir(), "luc.cbor")
		s := NewFileStore(path)
		require.NoError(t, s.SaveLUC(authentic))
		restored, err := s.LoadLUC()
		require.NoError(t, err)
		require.NoError(t, verifyRestoredLUC(restored, store, authPartitionID, types.ShardID{}))

		restored.InputRecord.RoundNumber = 5
		require.NoError(t, s.SaveLUC(restored))
		reloaded, err := s.LoadLUC()
		require.NoError(t, err, "it decodes")
		require.Error(t, verifyRestoredLUC(reloaded, store, authPartitionID, types.ShardID{}), "but must not be authoritative")
	})
}

// TestRestartLoadSeedReplay exercises the production load-and-seed sequence — LoadLUC,
// verifyRestoredLUC, BFTClient.SeedLUC — and then replays the same certificate and its
// successor through the same classification the network path uses.
//
// Scope, stated honestly: this drives the real store, the real verification helper, the
// real SeedLUC and the real ClassifyUC. It does not construct a full Node with libp2p
// networking, so it does not cover the transport. The chaos suite's restart scenarios
// cover that end; this covers the logic that wedged.
func TestRestartLoadSeedReplay(t *testing.T) {
	signer, tb, authentic := authFixture(t)
	store := stubTrustBaseStore{tb: tb}

	path := filepath.Join(t.TempDir(), "luc.cbor")
	fs := NewFileStore(path)
	require.NoError(t, fs.SaveLUC(authentic))

	// --- restart ---
	loaded, err := fs.LoadLUC()
	require.NoError(t, err)
	require.NoError(t, verifyRestoredLUC(loaded, store, authPartitionID, types.ShardID{}))

	c := &BFTClient{}
	c.SeedLUC(loaded)

	t.Run("replaying the same certificate is a duplicate, not a conflict", func(t *testing.T) {
		class, err := ClassifyUC(c.luc, authentic)
		require.NoError(t, err, "the certificate this node itself stored must not be rejected")
		require.Equal(t, UCDuplicate, class, "and must not be executed or submitted again")
	})

	t.Run("the successor round is accepted and extends the restored state", func(t *testing.T) {
		h := make([]byte, 32)
		next := &types.InputRecord{
			Version: 1, RoundNumber: 5, PreviousHash: h, Hash: []byte{0x22},
			BlockHash: []byte{0xb5}, SummaryValue: []byte{}, Timestamp: 1,
		}
		pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
		successor := testcertificates.CreateUnicityCertificate(t, signer, next, pdr, 51, h, h)
		require.NoError(t, successor.Verify(tb, crypto.SHA256, authPartitionID, types.ShardID{}, successor.ShardConfHash))

		class, err := ClassifyUC(c.luc, successor)
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})
}

// TestDescribeUCConflictSeesNilEmpty is the diagnostic reproducer from issue #86: the
// previous field-list implementation used bytes.Equal and so reported "input records are
// equal" for the very conflict it existed to explain.
func TestDescribeUCConflictSeesNilEmpty(t *testing.T) {
	h := make([]byte, 32)
	withEmpty := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h, SummaryValue: []byte{}, Timestamp: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 50, Timestamp: 1},
	}
	withNil := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: h, Hash: h, SummaryValue: nil, Timestamp: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 50, Timestamp: 1},
	}

	got := DescribeUCConflict(withNil, withEmpty)
	require.Contains(t, got, "summaryValue", "the changed field must be named")
	require.Contains(t, got, "canonical IR bytes: DIFFER", "canonical bytes are the authority")
	require.NotContains(t, got, "IDENTICAL")
	require.Contains(t, got, "summary:nil")
	require.Contains(t, got, "summary:empty")
	require.Contains(t, got, "ts:1", "timestamp is spelled out; InputRecord.String omits it")
}
