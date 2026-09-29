package signingauthority

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func successorTrust(f *fixture, epoch uint64) *types.RootTrustBaseV1 {
	tb := *f.tb
	tb.Epoch = epoch
	return &tb
}

func successorRequest(t *testing.T, f *fixture, conf *types.PartitionDescriptionRecord, rootEpoch, round uint64) Request {
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: round, Epoch: conf.Epoch, Leader: testNodeID, StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], &types.InputRecord{
		Version: 1, RoundNumber: round - 1, Epoch: conf.Epoch, PreviousHash: zero,
		Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
	}, conf, 50+round, zero, trHash)
	uc.UnicitySeal.Epoch = rootEpoch
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(nodeIDOf(t, f.signers[0]), f.signers[0]))
	proposal := f.proposal()
	proposal.InputRecord.RoundNumber = round
	proposal.InputRecord.Epoch = conf.Epoch
	proposal.InputRecord.PreviousHash = bytes.Clone(uc.InputRecord.Hash)
	proposal.InputRecord.Timestamp = uc.UnicitySeal.Timestamp
	return Request{UC: uc, Technical: tr, Proposed: proposal}
}

func TestAuthorityAdvanceAcrossTwoEpochsRetainsSigningHighWater(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	session, err := a.ReplaceSession()
	require.NoError(t, err)
	first := f.requestUnder(t, conf)
	_, err = a.Reserve(t.Context(), session, first)
	require.NoError(t, err)
	require.NoError(t, a.Sign(session))
	require.NoError(t, a.RetainResponse(session))

	next := *conf
	next.Epoch++
	require.NoError(t, a.AdvanceEpoch(t.Context(), &next, successorTrust(f, 2)))
	require.Equal(t, uint64(assignedRound), a.Status().ReservedRound)
	_, err = a.Reserve(t.Context(), session, successorRequest(t, f, &next, 2, 7))
	require.ErrorIs(t, err, ErrFenced)
	session, err = a.ReplaceSession()
	require.NoError(t, err)
	require.ErrorIs(t, a.Sign(session), ErrContextMismatch, "old reservation cannot be signed under the successor scope")
	_, err = a.Reserve(t.Context(), session, successorRequest(t, f, &next, 2, assignedRound))
	require.ErrorIs(t, err, ErrConflict, "the boundary round stays locked")
	_, err = a.Reserve(t.Context(), session, successorRequest(t, f, &next, 2, 7))
	require.NoError(t, err)
	require.NoError(t, a.Sign(session))
	require.NoError(t, a.RetainResponse(session))

	// A replacement session models a shard-process restart; the authority and
	// its key and record survive it.
	session, err = a.ReplaceSession()
	require.NoError(t, err)
	require.NoError(t, a.AdvanceEpoch(t.Context(), &next, successorTrust(f, 3)))
	session, err = a.ReplaceSession()
	require.NoError(t, err)
	_, err = a.Reserve(t.Context(), session, successorRequest(t, f, &next, 3, 9))
	require.NoError(t, err)
	require.Equal(t, uint64(9), a.Status().ReservedRound)
	_, err = a.Reserve(t.Context(), session, successorRequest(t, f, &next, 3, 8))
	require.ErrorIs(t, err, ErrStale, "the high-water mark spans both epoch advances")
}

func TestAuthorityAdvanceRejectsIsolatedInvalidContexts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*types.PartitionDescriptionRecord, *types.RootTrustBaseV1)
	}{
		{"lower root epoch", func(_ *types.PartitionDescriptionRecord, tb *types.RootTrustBaseV1) { tb.Epoch = 0 }},
		{"same epoch", func(conf *types.PartitionDescriptionRecord, tb *types.RootTrustBaseV1) { conf.Epoch--; tb.Epoch = 1 }},
		{"lower shard epoch", func(conf *types.PartitionDescriptionRecord, _ *types.RootTrustBaseV1) { conf.Epoch = 0 }},
		{"wrong network", func(conf *types.PartitionDescriptionRecord, _ *types.RootTrustBaseV1) { conf.NetworkID++ }},
		{"wrong trust network", func(_ *types.PartitionDescriptionRecord, tb *types.RootTrustBaseV1) { tb.NetworkID++ }},
		{"wrong partition", func(conf *types.PartitionDescriptionRecord, _ *types.RootTrustBaseV1) { conf.PartitionID++ }},
		{"wrong shard", func(conf *types.PartitionDescriptionRecord, _ *types.RootTrustBaseV1) {
			_, conf.ShardID = conf.ShardID.Split()
		}},
		{"node removed", func(conf *types.PartitionDescriptionRecord, _ *types.RootTrustBaseV1) {
			conf.Validators[0].NodeID = "other"
		}},
		{"wrong node key", func(conf *types.PartitionDescriptionRecord, _ *types.RootTrustBaseV1) {
			conf.Validators[0].SigKey = bytes.Repeat([]byte{2}, len(conf.Validators[0].SigKey))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 1)
			a := f.pending(t)
			conf := ownConf(t, a)
			require.NoError(t, a.CompleteEnrollment(conf))
			before := a.Enrollment()
			next := *conf
			validator := *conf.Validators[0]
			next.Validators = []*types.NodeInfo{&validator}
			next.Epoch++
			tb := successorTrust(f, 2)
			tc.mutate(&next, tb)
			require.ErrorIs(t, a.AdvanceEpoch(t.Context(), &next, tb), ErrContextMismatch)
			require.Equal(t, before, a.Enrollment(), "refusal must not change enrollment")
		})
	}
}

func TestAuthorityAdvanceShardEpochUnderSameRoot(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	next := *conf
	next.Epoch++
	next.T2Timeout++
	require.NoError(t, a.AdvanceEpoch(t.Context(), &next, successorTrust(f, 1)))
	require.Equal(t, next.Epoch, a.Enrollment().ShardEpoch)
}

func TestAuthorityAdvanceRejectsChangedRootOnlyConfigAndForgedCertificate(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	changed := *conf
	changed.T2Timeout++
	require.ErrorIs(t, a.AdvanceEpoch(t.Context(), &changed, successorTrust(f, 2)), ErrContextMismatch)
	require.NoError(t, a.AdvanceEpoch(t.Context(), conf, successorTrust(f, 2)))
	session, err := a.ReplaceSession()
	require.NoError(t, err)
	forged := successorRequest(t, f, conf, 2, 7)
	forged.UC.UnicitySeal.Signatures = nil
	_, err = a.Reserve(context.Background(), session, forged)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Zero(t, a.Status().ReservedRound)
	hash, err := conf.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, hash, a.Enrollment().ShardConfHash)
}
