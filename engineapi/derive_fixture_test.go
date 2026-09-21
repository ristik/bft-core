package engineapi

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// These fixtures build genuinely signed certificates over a real root quorum, the same way
// rootinput's own acceptance tests do: nothing here is a caller-supplied "verified" flag, so the
// adapter's derivation is exercised against evidence the production verifier accepts.
const (
	fixtureNetworkID   types.NetworkID   = 5
	fixturePartitionID types.PartitionID = 8
)

type fixtureTrustBases struct {
	tb  *types.RootTrustBaseV1
	err error
}

func (s fixtureTrustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.tb, nil
}

// derivationFixture is a four-node root quorum, quorum 2/3+1, that can mint certificates authorizing
// a named shard round.
type derivationFixture struct {
	signers  []abcrypto.Signer
	nodeIDs  []string
	tb       *types.RootTrustBaseV1
	pdr      *types.PartitionDescriptionRecord
	confHash []byte
	parent   []byte
}

func newDerivationFixture(t *testing.T) *derivationFixture {
	t.Helper()
	f := &derivationFixture{
		pdr:    &types.PartitionDescriptionRecord{Version: 1, NetworkID: fixtureNetworkID, PartitionID: fixturePartitionID, T2Timeout: 2500000000},
		parent: bytes.Repeat([]byte{0xa9}, 32),
	}
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id, err := network.NodeIDFromPublicKeyBytes(pub)
		require.NoError(t, err)
		f.signers = append(f.signers, s)
		f.nodeIDs = append(f.nodeIDs, id.String())
	}
	tb, ok := testtrustbase.NewTrustBase(t, f.signers...).(*types.RootTrustBaseV1)
	require.True(t, ok)
	f.tb = tb
	h, err := f.pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	f.confHash = h
	return f
}

func (f *derivationFixture) technical(round uint64) *certification.TechnicalRecord {
	zero := make([]byte, 32)
	return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: "shard-leader", StatHash: zero, FeeHash: zero}
}

// cert builds a genuinely signed certificate authorizing shard round `authorized` and certifying
// shard round `certified` at root round `rootRound`, plus the technical record it commits to.
func (f *derivationFixture) cert(t *testing.T, certified, authorized, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := f.technical(authorized)
	trHash, err := tr.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: certified, Epoch: 0,
		PreviousHash: bytes.Repeat([]byte{0xa0}, 32),
		Hash:         bytes.Repeat([]byte{0xa1}, 32),
		BlockHash:    bytes.Repeat([]byte{0xb1}, 32),
		SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], ir, f.pdr, rootRound, make([]byte, 32), trHash)
	uc.UnicitySeal.NetworkID = fixtureNetworkID
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(f.nodeIDs[0], f.signers[0]))
	for _, i := range []int{1, 2} {
		require.NoError(t, uc.UnicitySeal.Sign(f.nodeIDs[i], f.signers[i]))
	}
	return uc, tr
}

// verifier is the adapter's derivation context for this fixture, with the given cursor.
func (f *derivationFixture) verifier(cursor SealRegistryCursor) *VerifierContext {
	return &VerifierContext{
		NetworkID:     fixtureNetworkID,
		PartitionID:   fixturePartitionID,
		ShardID:       types.ShardID{},
		ShardConfHash: f.confHash,
		TrustBases:    fixtureTrustBases{tb: f.tb},
		Cursor:        cursor,
	}
}
