package signingauthority_test

/*
The authority restates the shard node's assignment rule instead of importing it, because step 3
wires shardnode.Round to this package and importing shardnode from it would be a cycle. Restating a
safety rule is only acceptable if drift is caught, so this test holds the two against each other.

It lives in the external test package for the same cycle reason: once shardnode imports
signingauthority, only an external test may import both.
*/

import (
	"context"
	gocrypto "crypto"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type oneTrustBase struct{ tb *types.RootTrustBaseV1 }

func (s oneTrustBase) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

func TestExpectationMatchesTheShardNodeRule(t *testing.T) {
	const (
		networkID   types.NetworkID   = 5
		partitionID types.PartitionID = 8
		nodeID                        = "validator-A"
		epoch                         = 1
		assigned                      = 5
	)
	ctx := context.Background()

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)

	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: networkID, PartitionID: partitionID, T2Timeout: 2500000000}
	confHash, err := pdr.Hash(gocrypto.SHA256)
	require.NoError(t, err)

	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: assigned, Epoch: epoch, Leader: nodeID, StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	certified := &types.InputRecord{
		Version: 1, RoundNumber: 4, Epoch: epoch, PreviousHash: zero, Hash: zero,
		SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, signer, certified, pdr, 50, zero, trHash)

	authority, err := signingauthority.New(signingauthority.Enrollment{
		AuthorityID: "authority-1", NodeID: nodeID, NetworkID: networkID, PartitionID: partitionID,
		ShardID: types.ShardID{}, ShardEpoch: epoch, ShardConfHash: confHash,
		Profile: signingauthority.ProfileLegacyBCRv1,
	}, oneTrustBase{tb: tb})
	require.NoError(t, err)

	// The shard node's own expectation for this certificate and technical record.
	exp, err := shardnode.ExpectationFromCertificate(uc, tr.Round, tr.Epoch)
	require.NoError(t, err)

	proposalFor := func(mutate func(ir *types.InputRecord)) *certification.BlockCertificationRequest {
		ir := &types.InputRecord{
			Version: 1, RoundNumber: assigned, Epoch: epoch,
			PreviousHash: uc.InputRecord.Hash, Hash: make([]byte, 32), BlockHash: make([]byte, 32),
			SummaryValue: []byte{}, Timestamp: uc.UnicitySeal.Timestamp,
		}
		for i := range ir.Hash {
			ir.Hash[i], ir.BlockHash[i] = 0xa1, 0xb1
		}
		if mutate != nil {
			mutate(ir)
		}
		return &certification.BlockCertificationRequest{
			PartitionID: partitionID, ShardID: types.ShardID{}, NodeID: nodeID,
			InputRecord: ir, BlockSize: 11, StateSize: 42,
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(ir *types.InputRecord)
	}{
		{"the assigned proposal", nil},
		{"another round", func(ir *types.InputRecord) { ir.RoundNumber = assigned + 1 }},
		{"an earlier round", func(ir *types.InputRecord) { ir.RoundNumber = assigned - 1 }},
		{"another epoch", func(ir *types.InputRecord) { ir.Epoch = epoch + 1 }},
		{"another previous state", func(ir *types.InputRecord) { ir.PreviousHash = []byte{0xff} }},
		{"another timestamp", func(ir *types.InputRecord) { ir.Timestamp++ }},
		{"an unchanged state carrying a block hash", func(ir *types.InputRecord) { ir.Hash = ir.PreviousHash }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposed := proposalFor(tc.mutate)
			shardErr := shardnode.ValidateLocal(proposed.InputRecord, exp)
			_, authErr := authority.Authenticate(ctx, signingauthority.Request{UC: uc, Technical: tr, Proposed: proposed})

			if shardErr == nil {
				require.NoError(t, authErr, "the shard node accepts this proposal, so the authority must too")
				return
			}
			require.ErrorIs(t, authErr, signingauthority.ErrProposalMismatch,
				"the shard node rejects this proposal (%v), so the authority must reject it as a proposal mismatch", shardErr)
		})
	}
}
