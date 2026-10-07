package certifiedstore

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// b1Rotated is the block-0 certified record of a fresh B1 deployment, certified under pdr (the genesis
// configuration when pdr is the fixture's own) at root epoch 2, over registry words that name the given
// assignment after one installed transition.
func b1Rotated(t *testing.T, f *b1fixture.Fixture, pdr *types.PartitionDescriptionRecord, epoch uint64, conf common.Hash) (Context, Record) {
	t.Helper()
	words := f.Genesis.B1Words()
	set := func(name string, v common.Hash) { words[common.Hash(b1state.FixedSlot(name))] = v }
	set("assignment.epoch", w(epoch))
	set("assignment.rootEpoch", w(2))
	set("assignment.activeConfHash", conf)
	set("transition.cursor", w(1))
	for i, n := range []string{"bodyID", "genesisID", "frozenID", "commitID", "frozenParent", "successorTR"} {
		set("transition."+n, w(uint64(7+i)))
	}
	set("origin.rootEpoch", w(2))
	set("clock.rootRound", w(5))
	set("round.authorized", w(1))
	set("outcomes.round", w(1))
	set("outcomes.commitment", common.Hash{9})
	rc, hash, ev, _ := b1fixture.ParentAt(t, f, words, 1)
	full, err := f.Genesis.FullConfig()
	require.NoError(t, err)
	if pdr == nil {
		pdr = full
	}
	// The certified state is whatever the proven header commits to.
	var root common.Hash
	{
		root = headerRoot(t, ev.Header)
	}
	tr := certifiedchain.Technical(1)
	tr.Epoch = pdr.Epoch
	ir := &types.InputRecord{Version: 1, RoundNumber: 1, Epoch: pdr.Epoch, Hash: root.Bytes(), PreviousHash: f.Genesis.StateRoot().Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_001, BlockHash: hash.Bytes()}
	uc := f.Chain.CertifyFor(pdr, f.Chain.Signer, ir, tr, 5)
	uc.UnicitySeal.NetworkID = 5
	uc.UnicitySeal.Epoch = 2
	uc.UnicitySeal.Signatures = nil
	v, err := f.Chain.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), f.Chain.Signer))
	tb2 := *f.Chain.TrustBase
	tb2.Epoch, tb2.Signatures = 2, nil
	ctx := Context{NetworkID: 5, PartitionID: 8, ShardID: full.ShardID, FullShardConfHash: f.Genesis.FullShardConfHash().Bytes(), GenesisPDR: full,
		Registry: rc, TrustBases: multiTrust{f.Chain.TrustBase, &tb2}, EpochAuthority: currentRootEpoch(2)}
	r := Record{BlockHash: hash, BlockNumber: 1, PartitionRound: 1, StateRoot: root, Certificate: uc, Technical: tr, Witness: ev}
	if pdr != full {
		r.ConfigPDR = pdr
	}
	return ctx, r
}

func TestFreshB1CertifiedRecordAssignmentBinding(t *testing.T) {
	f := b1fixture.New(t, 1)
	ctx := context.Background()
	full, err := f.Genesis.FullConfig()
	require.NoError(t, err)
	var vals []*types.NodeInfo
	for _, id := range []string{"v-a", "v-b", "v-c"} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		vals = append(vals, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1})
	}
	succ, err := evmassign.NewSuccessor(full, vals)
	require.NoError(t, err)
	next, err := evmassign.Activate(succ, 40)
	require.NoError(t, err)
	nextHash, err := evmassign.PDRHash(next)
	require.NoError(t, err)

	t.Run("the matching assignment is accepted and re-verifies", func(t *testing.T) {
		c, r := b1Rotated(t, f, next, next.Epoch, common.Hash(nextHash))
		raw, _, err := EncodeVerifiedRecord(ctx, c, r)
		require.NoError(t, err)
		_, err = VerifyEncodedRecord(ctx, c, raw)
		require.NoError(t, err)
	})
	t.Run("a different active configuration", func(t *testing.T) {
		c, r := b1Rotated(t, f, next, next.Epoch, w(99))
		_, _, err := EncodeVerifiedRecord(ctx, c, r)
		require.ErrorIs(t, err, ErrWitness)
		require.ErrorContains(t, err, "differs from the record's configuration")
	})
	t.Run("a different shard epoch", func(t *testing.T) {
		succ2, err := evmassign.NewSuccessor(next, vals)
		require.NoError(t, err)
		next2, err := evmassign.Activate(succ2, 41)
		require.NoError(t, err)
		next2Hash, err := evmassign.PDRHash(next2)
		require.NoError(t, err)
		c, r := b1Rotated(t, f, next2, next.Epoch, common.Hash(next2Hash))
		_, _, err = EncodeVerifiedRecord(ctx, c, r)
		require.ErrorIs(t, err, ErrWitness)
		require.ErrorContains(t, err, "differs from the record's configuration")
	})
}

func headerRoot(t *testing.T, raw []byte) common.Hash {
	t.Helper()
	var h ethtypes.Header
	require.NoError(t, rlp.DecodeBytes(raw, &h))
	return h.Root
}
