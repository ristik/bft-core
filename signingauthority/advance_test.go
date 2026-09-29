package signingauthority

import (
	"bytes"
	"context"
	"crypto"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
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

func TestSameRootEpochRequiresIdenticalTrustHash(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	next := *conf
	next.Epoch++ // a shard advance must not permit root-key substitution at epoch 1
	other, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	otherTB, ok := testtrustbase.NewTrustBase(t, other).(*types.RootTrustBaseV1)
	require.True(t, ok)
	successor := *otherTB
	successor.Epoch = rootEpoch
	successor.NetworkID = f.tb.NetworkID
	require.ErrorIs(t, a.AdvanceEpoch(t.Context(), &next, &successor), ErrContextMismatch)
}

type blockingTrust struct {
	tb      *types.RootTrustBaseV1
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingTrust) GetByEpoch(ctx context.Context, _ uint64) (*types.RootTrustBaseV1, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return b.tb, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestReserveRechecksScopeAfterTrustLookup(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	trust := &blockingTrust{tb: f.tb, entered: make(chan struct{}), release: make(chan struct{})}
	a.trust = trust
	session, err := a.ReplaceSession()
	require.NoError(t, err)
	request := f.requestUnder(t, conf)
	type result struct{ err error }
	done := make(chan result, 1)
	go func() { _, err := a.Reserve(context.Background(), session, request); done <- result{err} }()
	<-trust.entered // Authenticate is paused after Reserve's first admission check.
	require.NoError(t, a.AdvanceEpoch(t.Context(), conf, successorTrust(f, 2)))
	close(trust.release)
	got := <-done
	require.ErrorIs(t, got.err, ErrContextMismatch)
	require.Zero(t, a.Status().ReservedRound, "an authorization from the prior scope must not reserve a round")
}

func TestOldScopeCannotRetainOrReleaseAfterAdvance(t *testing.T) {
	for _, operation := range []string{"retain", "release"} {
		t.Run(operation, func(t *testing.T) {
			f := newFixture(t, 1)
			a := f.pending(t)
			conf := ownConf(t, a)
			require.NoError(t, a.CompleteEnrollment(conf))
			session, err := a.ReplaceSession()
			require.NoError(t, err)
			auth, err := a.Reserve(t.Context(), session, f.requestUnder(t, conf))
			require.NoError(t, err)
			require.NoError(t, a.Sign(session))
			require.NoError(t, a.RetainResponse(session))
			require.NoError(t, a.AdvanceEpoch(t.Context(), conf, successorTrust(f, 2)))
			current, err := a.ReplaceSession()
			require.NoError(t, err)
			if operation == "retain" {
				require.ErrorIs(t, a.RetainResponse(current), ErrContextMismatch)
			} else {
				_, err = a.Release(current, auth.AssignedRound, auth.UnsignedDigest)
				require.ErrorIs(t, err, ErrContextMismatch)
			}
		})
	}
}

func TestReserveRejectsIdenticalBytesReservedUnderPriorScope(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	session, err := a.ReplaceSession()
	require.NoError(t, err)
	oldRequest := f.requestUnder(t, conf)
	_, err = a.Reserve(t.Context(), session, oldRequest)
	require.NoError(t, err)
	require.NoError(t, a.AdvanceEpoch(t.Context(), conf, successorTrust(f, 2))) // root only; shard config and epoch unchanged
	current, err := a.ReplaceSession()
	require.NoError(t, err)
	// Keep the unsigned proposal byte-for-byte identical while presenting a
	// valid authorization from the successor root epoch. This reaches the
	// reservation's scopeVersion guard before the different-bytes guard.
	uc := *oldRequest.UC
	seal := *oldRequest.UC.UnicitySeal
	seal.Epoch = 2
	seal.Signatures = nil
	require.NoError(t, seal.Sign(nodeIDOf(t, f.signers[0]), f.signers[0]))
	uc.UnicitySeal = &seal
	successorRequest := oldRequest
	successorRequest.UC = &uc
	oldUnsigned, err := oldRequest.Proposed.Bytes()
	require.NoError(t, err)
	newUnsigned, err := successorRequest.Proposed.Bytes()
	require.NoError(t, err)
	require.Equal(t, oldUnsigned, newUnsigned)
	_, err = a.Reserve(t.Context(), current, successorRequest)
	require.ErrorIs(t, err, ErrConflict)
	require.Equal(t, oldRequest.Proposed.InputRecord.RoundNumber, a.Status().ReservedRound)
}
