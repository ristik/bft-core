package archivewiring

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/frontier"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

type bindingEpochAuthority struct{ epoch uint64 }

func (a bindingEpochAuthority) CurrentRootEpoch() (uint64, bool) { return a.epoch, true }

type bindingEpochTrust struct {
	bases map[uint64]*basetypes.RootTrustBaseV1
}

func (s bindingEpochTrust) GetByEpoch(_ context.Context, e uint64) (*basetypes.RootTrustBaseV1, error) {
	return s.bases[e], nil
}

func TestArchiveBindingUsesEachCertificateEpochAtHandoff(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	var result basetypes.UnicityCertificate
	require.NoError(t, basetypes.Cbor.Unmarshal(rec.ResultingUC, &result))
	base2 := *f.chain.TrustBase
	base2.Epoch = 2
	base2.Signatures = nil
	trust := bindingEpochTrust{bases: map[uint64]*basetypes.RootTrustBaseV1{1: f.chain.TrustBase, 2: &base2}}
	f.context.Observation.TrustBases = trust
	f.context.Observation.EpochAuthority = bindingEpochAuthority{epoch: 2}
	result.UnicitySeal.Epoch = 2
	result.UnicitySeal.RootChainRoundNumber = 1
	signers := result.UnicitySeal.Signatures
	result.UnicitySeal.Signatures = nil
	for signer := range signers {
		require.NoError(t, result.UnicitySeal.Sign(signer, f.chain.Signer))
	}
	var err error
	rec.ResultingUC, err = basetypes.Cbor.Marshal(&result)
	require.NoError(t, err)
	var header types.Header
	require.NoError(t, rlp.DecodeBytes(rec.Header, &header))
	r := frontier.Record{Epoch: 2, Round: 1, Height: 1, StateRoot: [32]byte(header.Root), Subject: q}
	binding := CertifiedBinding{Context: f.context, Subject: f.subject}
	require.NoError(t, binding.VerifyCertified(r, rec))
	r.Epoch = 1
	require.ErrorIs(t, binding.VerifyCertified(r, rec), frontier.ErrInvalid)
}
