package consensus

import (
	"bytes"
	gocrypto "crypto"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// pairedCommittee is four fixed keys with trust bases for epochs 1 to 3; epoch 2 (and so 3) signs with scheme 2.
type pairedCommittee struct {
	store   *trustbase.TrustBaseStore
	signers map[string]abcrypto.Signer
	ids     []string
	cfg     votesig.Config
}

func newPairedCommittee(t *testing.T) *pairedCommittee {
	t.Helper()
	c := &pairedCommittee{signers: map[string]abcrypto.Signer{}, cfg: votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("paired-qc-test-genesis"))}}
	var nodes []*types.NodeInfo
	for _, id := range []string{"1", "2", "3", "4"} {
		k := sha256.Sum256([]byte("paired-qc-test-key/" + id))
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		c.signers[id], c.ids = s, append(c.ids, id)
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: key, Stake: 1})
	}
	store, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	var prev *types.RootTrustBaseV1
	for epoch := uint64(1); epoch <= 3; epoch++ {
		opts := []types.Option{types.WithEpoch(epoch), types.WithEpochStart(1 + (epoch-1)*9)}
		if prev != nil {
			h, err := prev.Hash(gocrypto.SHA256)
			require.NoError(t, err)
			opts = append(opts, types.WithPreviousTrustBaseHash(h))
		}
		fresh := make([]*types.NodeInfo, len(nodes))
		for i, n := range nodes {
			fresh[i] = &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: 1}
		}
		tb, err := quorumweight.NewTrustBase(5, fresh, opts...)
		require.NoError(t, err)
		for _, id := range c.ids {
			require.NoError(t, tb.Sign(id, c.signers[id]))
		}
		require.NoError(t, store.Store(tb))
		prev = tb
	}
	require.NoError(t, store.ActivateSigning(2, c.cfg))
	c.store = store
	return c
}

// vote is a signed scheme 2 vote of the author for epoch 2, round 12. A nil commit hash is a non-committing vote.
func (c *pairedCommittee) vote(t *testing.T, author string, commitHash []byte) *abdrc.VoteMsg {
	t.Helper()
	const epoch, round = 2, 12
	exec := bytes.Repeat([]byte{0x5e}, 32)
	vi := votesig.VoteInfo{Epoch: epoch, Round: round, Parent: round - 1}
	copy(vi.Exec[:], exec)
	vh, err := c.cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, PreviousHash: vh[:]}
	if commitHash != nil {
		seal = &types.UnicitySeal{Version: 1, NetworkID: 5, PreviousHash: vh[:], RootChainRoundNumber: round - 1, Epoch: epoch, Timestamp: types.GenesisTime + 4242, Hash: commitHash}
	}
	v := &abdrc.VoteMsg{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: round, Epoch: epoch, ParentRoundNumber: round - 1, CurrentRootHash: exec}, LedgerCommitInfo: seal, Author: author}
	require.NoError(t, v.SignDomainBound(c.signers[author], c.cfg))
	return v
}

// committedBlock is an executed block with one certified shard, and the root hash a commit of it seals.
func committedBlock(t *testing.T) (*storage.ExecutedBlock, []byte) {
	t.Helper()
	_, validators := testutils.CreateTestNodes(t, 3)
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID, ShardID: shardID, PartitionTypeID: 8, TypeIDLen: 8,
		UnitIDLen: 256, T2Timeout: 2500 * time.Millisecond, Validators: validators, Epoch: 0, EpochStart: 1}
	shardState, err := storage.NewShardInfo(conf, gocrypto.SHA256)
	require.NoError(t, err)
	shardState.IR.BlockHash = bytes.Repeat([]byte{5}, 32)
	shardState.IR.Hash = bytes.Repeat([]byte{0x37}, 32)
	predecessor := bytes.Repeat([]byte{1}, 32)
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: 4, ActivationRound: 7, PredecessorBodyID: predecessor,
		NextBodyID: bytes.Repeat([]byte{3}, 32), FrozenID: bytes.Repeat([]byte{2}, 32), SuccessorTRHash: bytes.Repeat([]byte{6}, 32), Kind: "commit"}
	control := evmroot.ControlState{Network: 5, Epoch: 1, OrderedRound: 4, PredecessorBodyID: predecessor, Phase: "committed", RecordBytes: record.Bytes(),
		PreviousDigest: bytes.Repeat([]byte{4}, 32), FrozenParent: bytes.Repeat([]byte{5}, 32)}
	key := types.PartitionShardID{PartitionID: partitionID, ShardID: shardID.Key()}
	state := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{key: shardState}, Changed: storage.ShardSet{key: {}}, Control: &control}
	tree, _, err := state.UnicityTree(gocrypto.SHA256)
	require.NoError(t, err)
	return &storage.ExecutedBlock{HashAlgo: gocrypto.SHA256, RootHash: tree.RootHash(), ShardState: state}, tree.RootHash()
}

func TestPairedQCFormationAndUCExport(t *testing.T) {
	c := newPairedCommittee(t)
	block, root := committedBlock(t)
	quorum, err := c.store.GetByEpoch(2)
	require.NoError(t, err)

	r := NewVoteRegister()
	for _, id := range []string{"1", "2"} {
		qc, err := r.InsertVote(c.vote(t, id, root), quorum)
		require.NoError(t, err)
		require.Nil(t, qc, "two of four is below the threshold of three")
	}
	qc, err := r.InsertVote(c.vote(t, "3", root), quorum)
	require.NoError(t, err)
	require.NotNil(t, qc)
	require.EqualValues(t, votesig.SchemeDomainBound, qc.Scheme)
	require.Len(t, qc.Signatures, 3)
	require.Len(t, qc.SealSignatures, 3, "a committing certificate carries both maps")
	for id := range qc.Signatures {
		require.Contains(t, qc.SealSignatures, id, "identical signer sets")
		require.NotEqual(t, qc.Signatures[id], qc.SealSignatures[id], "two different statements are signed")
	}
	require.NoError(t, qc.VerifyWith(c.store))
	raw, err := types.Cbor.Marshal(qc)
	require.NoError(t, err)
	var back drctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(raw, &back))
	require.NoError(t, back.VerifyWith(c.store))

	// UC export: the certificate takes the seal signatures and verifies like any native one
	crs, err := block.GenerateCertificates(qc)
	require.NoError(t, err)
	require.Len(t, crs, 1)
	uc := crs[0].UC
	tb := quorum
	require.NoError(t, uc.Verify(quorumweight.Checked(tb), gocrypto.SHA256, partitionID, shardID, uc.ShardConfHash))
	require.Equal(t, qc.SealSignatures, uc.UnicitySeal.Signatures)

	// and fails with the vote signatures: those sign another statement
	wrong := *uc.UnicitySeal
	wrong.Signatures = qc.Signatures
	wrongUC := uc
	wrongUC.UnicitySeal = &wrong
	require.ErrorIs(t, wrongUC.Verify(quorumweight.Checked(tb), gocrypto.SHA256, partitionID, shardID, uc.ShardConfHash), quorumweight.ErrQuorumNotReached)

	// a scheme 2 commit QC without seal signatures exports nothing
	bare := *qc
	bare.SealSignatures = nil
	_, err = block.GenerateCertificates(&bare)
	require.ErrorIs(t, err, votesig.ErrSignerSets)
}

func TestPairedQCFormationNonCommitting(t *testing.T) {
	c := newPairedCommittee(t)
	quorum, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	r := NewVoteRegister()
	var qc *drctypes.QuorumCert
	for _, id := range []string{"1", "2", "3"} {
		qc, err = r.InsertVote(c.vote(t, id, nil), quorum)
		require.NoError(t, err)
	}
	require.NotNil(t, qc)
	require.Empty(t, qc.SealSignatures, "a non-committing certificate has no seal signatures")
	require.NoError(t, qc.VerifyWith(c.store))
}

func TestVotesOfDifferentSchemesAreNeverGroupedOrCountedTogether(t *testing.T) {
	c := newPairedCommittee(t)
	quorum, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	// two scheme 2 votes and two legacy-form votes that carry the very same commit info
	r := NewVoteRegister()
	for _, id := range []string{"1", "2"} {
		qc, err := r.InsertVote(c.vote(t, id, nil), quorum)
		require.NoError(t, err)
		require.Nil(t, qc)
	}
	same := c.vote(t, "3", nil)
	for _, id := range []string{"3", "4"} {
		legacy := *same
		legacy.Author, legacy.Scheme, legacy.SealSignature = id, 0, nil
		qc, err := r.InsertVote(&legacy, quorum)
		require.NoError(t, err)
		require.Nil(t, qc, "4 of 4 votes in total, but 2 in each scheme: no group reaches the threshold")
	}
}

func TestPairedVoteRegisterRefusals(t *testing.T) {
	c := newPairedCommittee(t)
	quorum, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	_, root := committedBlock(t)

	noSeal := c.vote(t, "1", root)
	noSeal.SealSignature = nil
	_, err = NewVoteRegister().InsertVote(noSeal, quorum)
	require.ErrorIs(t, err, votesig.ErrSignerSets, "a committing scheme 2 vote needs its seal signature")

	// an author that voted in one scheme and then the other in the same round equivocates
	r := NewVoteRegister()
	_, err = r.InsertVote(c.vote(t, "1", nil), quorum)
	require.NoError(t, err)
	other := *c.vote(t, "1", nil)
	other.Scheme, other.SealSignature = 0, nil
	_, err = r.InsertVote(&other, quorum)
	require.ErrorContains(t, err, "equivocating vote")
	_, err = r.InsertVote(c.vote(t, "1", nil), quorum)
	require.ErrorIs(t, err, quorumweight.ErrDuplicateSigner)
}
