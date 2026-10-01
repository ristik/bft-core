package certifiedstore

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type v2Deployment struct {
	t      *testing.T
	chain  *certifiedchain.Chain
	pdr    [2]*types.PartitionDescriptionRecord // genesis, rotated
	hash   [2][32]byte
	ctx    Context
	blocks []certifiedchain.Block // genesis, B1 (genesis assignment), B2 (acknowledgement, rotated)
}

func newV2Deployment(t *testing.T) *v2Deployment {
	chain := certifiedchain.NewV2(t, 3, 0)
	d := &v2Deployment{t: t, chain: chain}
	d.pdr[0] = chain.Full
	key := func(id string) *types.NodeInfo {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		return &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}
	}
	succ, err := evmassign.NewSuccessor(chain.Full, []*types.NodeInfo{key("v-a"), key("v-b"), key("v-c")})
	require.NoError(t, err)
	d.pdr[1], err = evmassign.Activate(succ, 40)
	require.NoError(t, err)
	for i := range d.pdr {
		h, err := evmassign.PDRHash(d.pdr[i])
		require.NoError(t, err)
		d.hash[i] = h
	}
	b0 := certifiedchain.Block{Hash: chain.Genesis.EVMGenesisHash(), StateRoot: chain.Genesis.StateRoot(), Evidence: chain.Genesis.Evidence()}
	b1 := chain.Executed(b0, 1, 5)
	b2 := chain.ExecutedState(b1, 2, 9, []byte("ack"), map[string]common.Hash{
		"assignment.epoch": w(1), "assignment.rootEpoch": w(2), "assignment.activeConfHash": common.Hash(d.hash[1]),
		"transition.cursor": w(1), "transition.bodyID": w(7), "transition.genesisID": w(8), "transition.frozenID": w(9),
		"transition.commitID": w(10), "transition.frozenParent": common.Hash(b1.Hash), "transition.successorTR": w(12), "origin.rootEpoch": w(2),
	})
	d.blocks = []certifiedchain.Block{b0, b1, b2}

	tb2 := *chain.TrustBase
	tb2.Epoch, tb2.Signatures = 2, nil
	d.ctx = Context{NetworkID: 3, PartitionID: 8, ShardID: chain.Full.ShardID, FullShardConfHash: chain.Genesis.FullShardConfHash().Bytes(),
		GenesisPDR: chain.Full, Registry: chain.Genesis.ProofContext(), TrustBases: multiTrust{chain.TrustBase, &tb2},
		EpochAuthority: currentRootEpoch(2)}
	return d
}

func w(v uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(v)) }

func (d *v2Deployment) certify(pdr *types.PartitionDescriptionRecord, b, prev certifiedchain.Block, irEpoch, trEpoch, rootEpoch uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	ir := &types.InputRecord{Version: 1, RoundNumber: b.Round, Epoch: irEpoch, PreviousHash: prev.StateRoot.Bytes(), Hash: b.StateRoot.Bytes(),
		SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}
	tr := certifiedchain.Technical(b.Round)
	tr.Epoch = trEpoch
	uc := d.chain.CertifyFor(pdr, d.chain.Signer, ir, tr, 4+b.Round)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Epoch = rootEpoch
	uc.UnicitySeal.Signatures = nil
	v, err := d.chain.Signer.Verifier()
	require.NoError(d.t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(d.t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(d.t, err)
	require.NoError(d.t, uc.UnicitySeal.Sign(id.String(), d.chain.Signer))
	return uc, tr
}

func (d *v2Deployment) record(b certifiedchain.Block, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, pdr *types.PartitionDescriptionRecord) Record {
	return Record{BlockHash: b.Hash, BlockNumber: b.Number, StateRoot: b.StateRoot, PartitionRound: b.Round, Certificate: uc, Technical: tr,
		Witness: b.Evidence, ConfigPDR: pdr}
}

func TestVersion2RecordVerifiesAnAssignmentOtherThanGenesis(t *testing.T) {
	d := newV2Deployment(t)
	t.Run("a block of the genesis assignment stays a version 1 record", func(t *testing.T) {
		uc, tr := d.certify(d.pdr[0], d.blocks[1], d.blocks[0], 0, 0, 1)
		raw, l, err := EncodeVerifiedRecord(context.Background(), d.ctx, d.record(d.blocks[1], uc, tr, nil))
		require.NoError(t, err)
		sr, err := decodeRecord(raw)
		require.NoError(t, err)
		require.Equal(t, RecordVersion, sr.Version)
		pdr, err := l.ConfigPDR()
		require.NoError(t, err)
		require.Nil(t, pdr)
	})
	t.Run("the acknowledgement block verifies against its own PDR", func(t *testing.T) {
		uc, tr := d.certify(d.pdr[1], d.blocks[2], d.blocks[1], 1, 1, 2)
		raw, l, err := EncodeVerifiedRecord(context.Background(), d.ctx, d.record(d.blocks[2], uc, tr, d.pdr[1]))
		require.NoError(t, err)
		sr, err := decodeRecord(raw)
		require.NoError(t, err)
		require.Equal(t, RecordVersionV2, sr.Version)
		pdr, err := l.ConfigPDR()
		require.NoError(t, err)
		require.Equal(t, d.hash[1], mustHash(t, pdr))
		again, err := VerifyEncodedRecord(context.Background(), d.ctx, raw)
		require.NoError(t, err, "a stored version 2 record re-verifies from its bytes alone")
		require.EqualValues(t, 1, again.Snapshot().Fields().ShardEpoch)
	})
}

func mustHash(t *testing.T, p *types.PartitionDescriptionRecord) [32]byte {
	t.Helper()
	h, err := evmassign.PDRHash(p)
	require.NoError(t, err)
	return h
}

func TestVersion2RecordIsolatedRefusals(t *testing.T) {
	d := newV2Deployment(t)
	ctx := context.Background()
	ackUC, ackTR := d.certify(d.pdr[1], d.blocks[2], d.blocks[1], 1, 1, 2)

	t.Run("a recertification of P is authorization, not P's resulting evidence", func(t *testing.T) {
		// Certified epoch 0 with authorized epoch 1 over the successor configuration.
		uc, tr := d.certify(d.pdr[1], d.blocks[1], d.blocks[0], 0, 1, 2)
		_, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[1], uc, tr, d.pdr[1]))
		require.ErrorIs(t, err, ErrEpoch)
		require.ErrorContains(t, err, "input record epoch 0, configured shard epoch 1")
	})
	t.Run("the technical record's epoch differs from the configuration's", func(t *testing.T) {
		uc, tr := d.certify(d.pdr[1], d.blocks[2], d.blocks[1], 1, 0, 2)
		_, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], uc, tr, d.pdr[1]))
		require.ErrorIs(t, err, ErrEpoch)
		require.ErrorContains(t, err, "technical record epoch 0, configured shard epoch 1")
	})
	t.Run("a rotated certificate in a version 1 record", func(t *testing.T) {
		_, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], ackUC, ackTR, nil))
		require.ErrorIs(t, err, ErrWrongContext)
	})
	t.Run("a PDR that is not the certificate's configuration", func(t *testing.T) {
		_, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], ackUC, ackTR, d.pdr[0]))
		require.ErrorIs(t, err, ErrWrongContext)
	})
	t.Run("no genesis pin in the store context", func(t *testing.T) {
		c := d.ctx
		c.GenesisPDR = nil
		_, _, err := EncodeVerifiedRecord(ctx, c, d.record(d.blocks[2], ackUC, ackTR, d.pdr[1]))
		require.ErrorIs(t, err, ErrConfig)
	})
	t.Run("a genesis pin that is not the deployment identity", func(t *testing.T) {
		c := d.ctx
		other := *d.pdr[0]
		other.T2Timeout++
		c.GenesisPDR = &other
		_, _, err := EncodeVerifiedRecord(ctx, c, d.record(d.blocks[2], ackUC, ackTR, d.pdr[1]))
		require.ErrorIs(t, err, ErrConfig)
	})
	t.Run("the PDR changes a non-membership setting", func(t *testing.T) {
		succ, err := evmassign.NewSuccessor(d.pdr[0], d.pdr[1].Validators)
		require.NoError(t, err)
		succ.T2Timeout += 1
		bad, err := evmassign.Activate(succ, 40)
		require.NoError(t, err)
		uc, tr := d.certify(bad, d.blocks[2], d.blocks[1], 1, 1, 2)
		_, _, err = EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], uc, tr, bad))
		require.ErrorIs(t, err, ErrWrongContext)
		require.ErrorContains(t, err, "non-membership setting")
	})
	t.Run("a malformed validator set", func(t *testing.T) {
		succ, err := evmassign.NewSuccessor(d.pdr[0], d.pdr[1].Validators)
		require.NoError(t, err)
		succ.Validators[1].SigKey = bytes.Clone(succ.Validators[0].SigKey)
		bad, err := evmassign.Activate(succ, 40)
		require.NoError(t, err)
		uc, tr := d.certify(bad, d.blocks[2], d.blocks[1], 1, 1, 2)
		_, _, err = EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], uc, tr, bad))
		require.ErrorIs(t, err, ErrWrongContext)
		require.ErrorContains(t, err, "configuration PDR")
	})
	t.Run("the registry's active assignment differs from the record's configuration", func(t *testing.T) {
		wrong := d.chain.ExecutedState(d.blocks[1], 2, 9, []byte("ack"), map[string]common.Hash{
			"assignment.epoch": w(1), "assignment.rootEpoch": w(2), "assignment.activeConfHash": w(99),
			"transition.cursor": w(1), "transition.bodyID": w(7), "transition.genesisID": w(8), "transition.frozenID": w(9),
			"transition.commitID": w(10), "transition.frozenParent": common.Hash(d.blocks[1].Hash), "transition.successorTR": w(12), "origin.rootEpoch": w(2),
		})
		uc, tr := d.certify(d.pdr[1], wrong, d.blocks[1], 1, 1, 2)
		_, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(wrong, uc, tr, d.pdr[1]))
		require.ErrorIs(t, err, ErrWitness)
		require.ErrorContains(t, err, "differs from the record's configuration")
	})
	t.Run("a stored version 2 record whose PDR bytes were altered", func(t *testing.T) {
		raw, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], ackUC, ackTR, d.pdr[1]))
		require.NoError(t, err)
		sr, err := decodeRecord(raw)
		require.NoError(t, err)
		sr.ConfigPDR = append(bytes.Clone(sr.ConfigPDR), 0)
		payload, err := marshalPayload(sr)
		require.NoError(t, err)
		_, err = VerifyEncodedRecord(ctx, d.ctx, envelopeWithPayload(t, sr.Version, payload))
		require.Error(t, err)
		require.True(t, errorsIsAny(err, ErrRecordUntrusted, ErrWrongContext), "%v", err)
	})
	t.Run("the version marker and the PDR must agree", func(t *testing.T) {
		raw, _, err := EncodeVerifiedRecord(ctx, d.ctx, d.record(d.blocks[2], ackUC, ackTR, d.pdr[1]))
		require.NoError(t, err)
		sr, err := decodeRecord(raw)
		require.NoError(t, err)
		sr.Version = RecordVersion // version 1 marker with a PDR
		_, err = verify(ctx, d.ctx, sr)
		require.ErrorIs(t, err, ErrRecordUntrusted)
	})
}

func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

func envelopeWithPayload(t *testing.T, version uint32, payload []byte) []byte {
	t.Helper()
	return envelopeWith(t, version, payload)
}

// currentRootEpoch is the installed root epoch: the rotation advanced it to 2 with identical root keys.
type currentRootEpoch uint64

func (e currentRootEpoch) CurrentRootEpoch() (uint64, bool) { return uint64(e), true }
