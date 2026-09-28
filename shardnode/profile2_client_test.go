package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type profile2MarkedTrust struct{ stubTrustBaseStore }

func (profile2MarkedTrust) IsV2Epoch(epoch uint64) bool { return epoch == 8 }

func TestProfile2ClientDoesNotDispatchOldRepeat(t *testing.T) {
	ctx := context.Background()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 1}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	zero := make([]byte, 32)
	technical := func(round uint64) certification.TechnicalRecord {
		return certification.TechnicalRecord{Round: round + 1, Epoch: 0, Leader: "test-node", StatHash: zero, FeeHash: zero}
	}
	signed := func(round, rootRound, rootEpoch uint64, previous, state, block []byte) *types.UnicityCertificate {
		t.Helper()
		ir := &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: previous,
			Hash: state, BlockHash: block, SummaryValue: []byte{}, Timestamp: 1}
		tr := technical(round)
		trHash, err := tr.Hash()
		require.NoError(t, err)
		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, zero, trHash)
		var signerID string
		for id := range uc.UnicitySeal.Signatures {
			signerID = id
		}
		uc.UnicitySeal.Epoch = rootEpoch
		uc.UnicitySeal.Signatures = nil
		require.NoError(t, uc.UnicitySeal.Sign(signerID, signer))
		require.NoError(t, uc.Verify(tb, crypto.SHA256, 1, types.ShardID{}, confHash))
		return uc
	}
	response := func(uc *types.UnicityCertificate) *certification.CertificationResponse {
		return &certification.CertificationResponse{Partition: 1, Technical: technical(uc.GetRoundNumber()), UC: *uc}
	}
	newClient := func(consumer *Profile2Consumer, held *types.UnicityCertificate) (*BFTClient, *recordingDriver) {
		driver := &recordingDriver{}
		c := &BFTClient{partitionID: 1, shardConfHash: confHash, nodeID: "test-node",
			trustBaseStore: stubTrustBaseStore{tb: tb}, driver: driver}
		require.NoError(t, c.SeedLUC(held))
		require.NoError(t, c.SetProfile2Consumer(consumer))
		return c, driver
	}

	held := signed(1, 10, 7, []byte{0}, []byte{1}, []byte{2})
	late := signed(1, 100, 7, []byte{0}, []byte{1}, []byte{2})
	proof, old := profile2Proof(t, held)
	path := filepath.Join(t.TempDir(), "consumer.json")
	consumer, err := NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err)
	c, driver := newClient(consumer, held)
	for _, phase := range []string{"before proof", "after proof"} {
		if phase == "after proof" {
			require.NoError(t, consumer.Install(proof))
		}
		require.NoError(t, c.handleCertificationResponse(ctx, response(late)), phase)
		require.Same(t, held, c.luc, phase)
		require.Empty(t, driver.rounds(), phase)
	}
	// The model snapshot uses its D4 shard checkpoint root, so the ordinary
	// signed UC above has a different tree root. With the authenticated R_H it
	// is specifically a historical terminal repeat, with the same disposition.
	terminalRepeat := *late
	seal := *late.UnicitySeal
	seal.Hash, err = proof.Snapshot.Root()
	require.NoError(t, err)
	terminalRepeat.UnicitySeal = &seal
	class, err := consumer.Classify(held, &terminalRepeat)
	require.Equal(t, UCStale, class)
	require.ErrorIs(t, err, ErrProfile2TerminalRepeat)
	// The D4 model's shard snapshot hash differs from the runtime UC tree
	// hash. For this handler disposition check, substitute the signed UC root
	// in the verified view. Proof verification is tested independently.
	verified := *consumer.verified
	verified.Root = bytes.Clone(late.UnicitySeal.Hash)
	terminalConsumer := &Profile2Consumer{partition: 1, verified: &verified}
	terminalClient, terminalDriver := newClient(terminalConsumer, held)
	require.NoError(t, terminalClient.handleCertificationResponse(ctx, response(late)))
	require.Same(t, held, terminalClient.luc)
	require.Empty(t, terminalDriver.rounds())

	restored, err := NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err)
	restarted, restartedDriver := newClient(restored, held)
	require.NoError(t, restarted.handleCertificationResponse(ctx, response(late)))
	require.Same(t, held, restarted.luc)
	require.Empty(t, restartedDriver.rounds())
	require.NoError(t, restored.SetReady())
	newUC := signed(2, 13, 8, []byte{1}, []byte{3}, []byte{4})
	unguardedDriver := &recordingDriver{}
	unguarded := &BFTClient{partitionID: 1, shardConfHash: confHash, nodeID: "test-node",
		trustBaseStore: profile2MarkedTrust{stubTrustBaseStore{tb: tb}}, driver: unguardedDriver}
	require.NoError(t, unguarded.SeedLUC(held))
	require.ErrorIs(t, unguarded.handleCertificationResponse(ctx, response(newUC)), ErrProfile2Unready)
	require.Same(t, held, unguarded.luc)
	require.Empty(t, unguardedDriver.rounds())
	restarted.mu.Lock()
	restarted.submittedSinceHandshake = true // delivery spends this credit; no test transport is needed
	restarted.mu.Unlock()
	require.NoError(t, restarted.handleCertificationResponse(ctx, response(newUC)))
	require.True(t, bytes.Equal(newUC.InputRecord.Hash, restarted.luc.InputRecord.Hash))
	require.Equal(t, []uint64{2}, restartedDriver.rounds())
}
