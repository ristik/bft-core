package configuredprogress

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

func TestReviewProgressTokenRejectsForeignAndReopenedStore(t *testing.T) {
	f := newFixture(t, 1)
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.db")
	pathB := filepath.Join(dir, "b.db")

	a, err := OpenConfiguredV2(pathA, Settings{Retain: 2})
	require.NoError(t, err)
	_, _, err = a.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	require.NoError(t, a.Close())
	raw, err := os.ReadFile(pathA)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pathB, raw, 0o600))

	a, err = OpenConfiguredV2(pathA, Settings{Retain: 2})
	require.NoError(t, err)
	b, err := OpenConfiguredV2(pathB, Settings{Retain: 2})
	require.NoError(t, err)
	_, token, err := a.Load(context.Background(), f.ctx)
	require.NoError(t, err)

	ad, ac, ah, ar, err := a.readRaw()
	require.NoError(t, err)
	bd, bc, bh, br, err := b.readRaw()
	require.NoError(t, err)
	require.Equal(t, [][]byte{ad, ac, ah, ar}, [][]byte{bd, bc, bh, br}, "the foreign store presents the same durable image")
	require.True(t, a.Unchanged(token))
	require.False(t, b.Unchanged(token), "matching durable bytes do not confer token ownership")
	require.NoError(t, b.Close())
	require.NoError(t, a.Close())

	reopened, err := OpenConfiguredV2(pathA, Settings{Retain: 2})
	require.NoError(t, err)
	defer reopened.Close()
	require.False(t, reopened.Unchanged(token), "reopening the same database creates another store instance")
}

func TestReviewLoadRejectsAuthenticatedHeadBeyondObserved(t *testing.T) {
	t.Run("newer", func(t *testing.T) {
		f := newFixture(t, 2)
		s, _ := f.open(3)
		defer s.Close()
		installObserved(t, s, f, f.first(1, 2, 5))
		installUncheckedHead(t, s, f, f.record(2, f.ordinary(2, 3, 6)))

		_, _, err := s.Load(context.Background(), f.ctx)
		require.ErrorIs(t, err, ErrUntrusted)
		require.ErrorContains(t, err, "head newer/conflicting with observed")
	})

	t.Run("same round conflict", func(t *testing.T) {
		f := newFixture(t, 1)
		s, _ := f.open(3)
		defer s.Close()
		observed := f.first(1, 2, 5)
		installObserved(t, s, f, observed)

		alt := f.c.ExecutedWith(f.c.Blocks[0], 1, 5, []byte("conflicting-B1"))
		ir := &types.InputRecord{Version: 1, RoundNumber: 1, Hash: alt.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_001, BlockHash: alt.Hash.Bytes()}
		conflicting := f.observation(ir, 2, 5)
		r := certifiedstore.Record{BlockHash: alt.Hash, BlockNumber: alt.Number, StateRoot: alt.StateRoot, PartitionRound: alt.Round, Certificate: conflicting.Certificate(), Technical: conflicting.TechnicalRecord(), Witness: alt.Evidence}
		installUncheckedHead(t, s, f, r)

		_, _, err := s.Load(context.Background(), f.ctx)
		require.ErrorIs(t, err, ErrUntrusted)
		require.ErrorContains(t, err, "head newer/conflicting with observed")
	})
}

func TestReviewObservationIdentitySignatureSubsetAndPreviousHashConflict(t *testing.T) {
	f := newFixture(t, 1)
	signers := []abcrypto.Signer{f.c.Signer}
	for range 3 {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers = append(signers, signer)
	}
	tb, ok := testtrustbase.NewTrustBase(t, signers...).(*types.RootTrustBaseV1)
	require.True(t, ok)
	f.ctx.Observation.TrustBases = testTrust{tb}
	f.ctx.Record.TrustBases = testTrust{tb}

	ir := &types.InputRecord{Version: 1, RoundNumber: 1, Hash: f.c.Blocks[1].StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_001, BlockHash: f.c.Blocks[1].Hash.Bytes()}
	uc, tr := f.sign(ir, 2, 5)
	for _, signer := range signers[1:] {
		signSeal(t, uc, signer)
	}
	full := authenticateReviewObservation(t, f, uc, tr)

	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	p, out, err := s.PrepareObservation(context.Background(), f.ctx, full)
	require.NoError(t, err)
	require.Equal(t, ObservationAdvanced, out)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)

	subsetUC := cloneCertificate(t, uc)
	for id := range subsetUC.UnicitySeal.Signatures {
		delete(subsetUC.UnicitySeal.Signatures, id)
		break
	}
	subset := authenticateReviewObservation(t, f, subsetUC, tr)
	p, out, err = s.PrepareObservation(context.Background(), f.ctx, subset)
	require.NoError(t, err)
	require.Equal(t, ObservationDuplicate, out, "signature-map subsets do not change signed statement identity")
	_, out, err = s.CommitObservation(p)
	require.NoError(t, err)
	require.Equal(t, ObservationDuplicate, out)
	state, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), state.Revision(), "equivalent signatures must not rewrite control")

	conflictUC := cloneCertificate(t, uc)
	conflictUC.UnicitySeal.PreviousHash = bytes.Repeat([]byte{0xc1}, common.HashLength)
	conflictUC.UnicitySeal.Signatures = nil
	for _, signer := range signers[:3] {
		signSeal(t, conflictUC, signer)
	}
	conflict := authenticateReviewObservation(t, f, conflictUC, tr)
	_, _, err = s.PrepareObservation(context.Background(), f.ctx, conflict)
	require.ErrorIs(t, err, ErrConflict, "a genuinely signed predecessor change is a different root statement")
}

func installObserved(t *testing.T, s *Store, f *fixture, o rootinput.VerifiedObservationV2) {
	t.Helper()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	p, _, err := s.PrepareObservation(context.Background(), f.ctx, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
}

// installUncheckedHead writes an individually verified record and a freshly checksummed control image,
// deliberately bypassing PrepareRecord's observed-order check so Load must defend the durable boundary.
func installUncheckedHead(t *testing.T, s *Store, f *fixture, r certifiedstore.Record) {
	t.Helper()
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	key, raw, _, _, err := encodeOuterRecord(context.Background(), f.ctx, st.i.descriptorDigest, r)
	require.NoError(t, err)
	_, err = verifyOuterRecord(context.Background(), f.ctx, st.i.descriptorDigest, key, raw)
	require.NoError(t, err, "the head is valid in isolation")
	cw := st.i.control
	cw.Revision++
	cw.HeadKey = bytes.Clone(key)
	payload, err := marshal(cw)
	require.NoError(t, err)
	control, err := encodeEnvelope(kindControl, payload, MaxControlBytes)
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := b.Put(key, raw); err != nil {
			return err
		}
		return b.Put(controlKey, control)
	}))
}

func authenticateReviewObservation(t *testing.T, f *fixture, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) rootinput.VerifiedObservationV2 {
	t.Helper()
	o, err := rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, uc, tr)
	require.NoError(t, err)
	return o
}

func cloneCertificate(t *testing.T, uc *types.UnicityCertificate) *types.UnicityCertificate {
	t.Helper()
	raw, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)
	var clone types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &clone))
	return &clone
}

func signSeal(t *testing.T, uc *types.UnicityCertificate, signer abcrypto.Signer) {
	t.Helper()
	v, err := signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), signer))
}
