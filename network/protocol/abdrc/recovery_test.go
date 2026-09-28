package abdrc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	test "github.com/unicitynetwork/bft-core/internal/testutils"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/m2contract"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type recoveryHistoryProof struct{}

type anchorRecoveryHistory struct{}

func (anchorRecoveryHistory) ByEpoch(uint64) (trusthistorystore.Record, error) {
	return trusthistorystore.Record{}, nil
}

type anchorRecoveryVerifier struct{ expected []byte }

func (v anchorRecoveryVerifier) VerifyRecoveryAnchor(head *CommittedBlock) error {
	if !bytes.Equal(head.Anchor.GenesisID, v.expected) {
		return ErrRecoveryEpoch
	}
	return nil
}

func TestRecoveryCommittedHeadRequiresVerifiedTypedAnchor(t *testing.T) {
	a := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 6,
		StateRoot: bytes.Repeat([]byte{2}, 32)}
	head := &CommittedBlock{Block: &rctypes.BlockData{Version: 2, Epoch: 2, Round: 6,
		Payload: &rctypes.Payload{Version: 2}, Anchor: a}, Anchor: a,
		Control: &evmroot.ControlState{Network: 5, Epoch: 1, PredecessorBodyID: make([]byte, 32)}}
	encoded, err := types.Cbor.Marshal(head)
	require.NoError(t, err)
	var decoded CommittedBlock
	require.NoError(t, types.Cbor.Unmarshal(encoded, &decoded))
	require.Equal(t, head, &decoded)
	require.NoError(t, head.IsValid())
	state := &StateMsg{CommittedHead: head}
	tb := &types.RootTrustBaseV1{Epoch: 2}
	require.ErrorIs(t, state.VerifyWithHistory(crypto.SHA256, tb, anchorRecoveryHistory{}), ErrRecoveryEpoch)
	require.NoError(t, state.VerifyWithAnchor(crypto.SHA256, tb, anchorRecoveryHistory{}, anchorRecoveryVerifier{a.GenesisID}))
	wrong := bytes.Repeat([]byte{3}, 32)
	require.Error(t, state.VerifyWithAnchor(crypto.SHA256, tb, anchorRecoveryHistory{}, anchorRecoveryVerifier{wrong}))
	head.Qc = &rctypes.QuorumCert{}
	require.ErrorIs(t, head.IsValid(), ErrRecoveryEpoch)
}

func (recoveryHistoryProof) VerifyActivation(context.Context, trusthistorystore.Record, m2contract.TrustInterval, []byte) error {
	return nil // This recovery fixture supplies an already accepted transition.
}

type recoveryHistoryRecordOverride struct {
	base   HistoricalTrustBases
	record trusthistorystore.Record
}

func (h recoveryHistoryRecordOverride) ByEpoch(epoch uint64) (trusthistorystore.Record, error) {
	if epoch == h.record.Epoch {
		return h.record, nil
	}
	return h.base.ByEpoch(epoch)
}

type recoveryHistoryMutating struct {
	base   HistoricalTrustBases
	mutate func()
}

func (h recoveryHistoryMutating) ByEpoch(epoch uint64) (trusthistorystore.Record, error) {
	h.mutate()
	return h.base.ByEpoch(epoch)
}

func TestRecoveryBlock_GetRound(t *testing.T) {
	t.Run("recovery block is nil", func(t *testing.T) {
		var block *CommittedBlock = nil
		require.EqualValues(t, 0, block.GetRound())
	})
	t.Run("block data is nil", func(t *testing.T) {
		block := &CommittedBlock{
			Block: nil,
		}
		require.EqualValues(t, 0, block.GetRound())
	})
	t.Run("block data round is 3", func(t *testing.T) {
		block := &CommittedBlock{
			Block: &rctypes.BlockData{
				Round: 3,
			},
		}
		require.EqualValues(t, 3, block.GetRound())
	})
}

func TestStateMsg_CanRecoverToRound(t *testing.T) {
	t.Run("commit head is nil", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: nil,
		}
		require.ErrorContains(t, sm.CanRecoverToRound(3), "committed block is nil")
	})
	t.Run("commit head commit qc is nil", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: &CommittedBlock{},
		}
		require.ErrorContains(t, sm.CanRecoverToRound(3), "state has no data block for round 3")
	})
	t.Run("commit head block is from later round", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: &CommittedBlock{
				Block: &rctypes.BlockData{
					Round: 5,
					Qc:    &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4}},
				},
			},
		}
		require.ErrorContains(t, sm.CanRecoverToRound(3), "can't recover to round 3 with committed block for round 5")
	})
	t.Run("exact block for round not found", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: &CommittedBlock{
				Block: &rctypes.BlockData{
					Round: 5,
					Qc:    &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4}},
				},
			},
		}
		require.ErrorContains(t, sm.CanRecoverToRound(8), "state has no data block for round 8")
	})
	t.Run("commit head is the block needed", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: &CommittedBlock{
				Block: &rctypes.BlockData{
					Round: 5,
					Qc:    &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4}},
				},
			},
		}
		require.NoError(t, sm.CanRecoverToRound(5))
	})
	t.Run("most common case", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: &CommittedBlock{
				Block: &rctypes.BlockData{
					Round: 5,
					Qc:    &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4}},
				},
			},
			Pending: []*rctypes.BlockData{
				{
					Round: 6,
					Qc:    &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 5}},
				},
				{
					Round: 7,
					Qc:    &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 6}},
				},
			},
		}
		require.NoError(t, sm.CanRecoverToRound(7))
	})
}

func TestStateMsg_Verify(t *testing.T) {
	r4vInfo := &rctypes.RoundInfo{
		RoundNumber:       4,
		ParentRoundNumber: 3,
		CurrentRootHash:   test.RandomBytes(32),
		Timestamp:         types.NewTimestamp(),
	}
	r5vInfo := &rctypes.RoundInfo{
		RoundNumber:       5,
		ParentRoundNumber: 4,
		CurrentRootHash:   test.RandomBytes(32),
		Timestamp:         types.NewTimestamp(),
	}
	r6vInfo := &rctypes.RoundInfo{
		RoundNumber:       6,
		ParentRoundNumber: 5,
		CurrentRootHash:   test.RandomBytes(32),
		Timestamp:         types.NewTimestamp(),
	}

	headIR := &types.InputRecord{
		Version:         1,
		PreviousHash:    test.RandomBytes(32),
		Hash:            test.RandomBytes(32),
		BlockHash:       test.RandomBytes(32),
		SummaryValue:    test.RandomBytes(32),
		RoundNumber:     3,
		SumOfEarnedFees: 10,
		Timestamp:       types.NewTimestamp(),
	}

	shardConf := types.PartitionDescriptionRecord{
		PartitionID: 1,
	}

	signer, _ := testsig.CreateSignerAndVerifier(t)

	uc := testcertificates.CreateUnicityCertificate(
		t,
		signer,
		headIR,
		&shardConf,
		1,
		make([]byte, 32),
		make([]byte, 32),
	)

	validStateMsg := func() StateMsg {
		h4, err := r4vInfo.Hash(crypto.SHA256)
		require.NoError(t, err)
		h5, err := r5vInfo.Hash(crypto.SHA256)
		require.NoError(t, err)
		h6, err := r6vInfo.Hash(crypto.SHA256)
		require.NoError(t, err)
		return StateMsg{
			CommittedHead: &CommittedBlock{
				ShardInfo: []ShardInfo{{
					Partition:     1,
					PrevEpochStat: []byte{0, 0, 0, 0, 0},
					PrevEpochFees: []byte{0xF, 0xE, 0xE, 5},
					RootHash:      test.RandomBytes(32),
					Fees:          map[string]uint64{"A": 0},
					UC:            uc,
					TR: &certification.TechnicalRecord{
						Round:    5,
						Epoch:    1,
						Leader:   "A",
						StatHash: []byte{5},
						FeeHash:  []byte{0xF, 0xE, 0xE},
					},
					IR:            headIR,
					ShardConfHash: test.DoHash(t, &shardConf),
				}},
				Block: &rctypes.BlockData{
					Round:   5,
					Payload: &rctypes.Payload{},
					Qc: &rctypes.QuorumCert{
						VoteInfo: r4vInfo,
						LedgerCommitInfo: &types.UnicitySeal{
							Version:      1,
							PreviousHash: h4,
							Signatures:   map[string]hex.Bytes{"test": test.RandomBytes(65)},
						},
						Signatures: map[string]hex.Bytes{"test": test.RandomBytes(65)},
					},
				},
				Qc: &rctypes.QuorumCert{
					VoteInfo: r5vInfo,
					LedgerCommitInfo: &types.UnicitySeal{
						Version:      1,
						PreviousHash: h5,
						Signatures:   map[string]hex.Bytes{"test": test.RandomBytes(65)},
					},
					Signatures: map[string]hex.Bytes{"test": test.RandomBytes(65)},
				},
				CommitQc: &rctypes.QuorumCert{
					VoteInfo: r6vInfo,
					LedgerCommitInfo: &types.UnicitySeal{
						Version:      1,
						PreviousHash: h6,
						Signatures:   map[string]hex.Bytes{"test": test.RandomBytes(65)},
					},
					Signatures: map[string]hex.Bytes{"test": test.RandomBytes(65)},
				},
			},
			Pending: []*rctypes.BlockData{{
				Round:   6,
				Payload: &rctypes.Payload{},
				Qc: &rctypes.QuorumCert{
					VoteInfo: r5vInfo,
					LedgerCommitInfo: &types.UnicitySeal{
						Version:              1,
						PreviousHash:         h5,
						RootChainRoundNumber: 5,
						Hash:                 test.RandomBytes(32),
						Signatures:           map[string]hex.Bytes{"test": test.RandomBytes(65)},
					},
					Signatures: map[string]hex.Bytes{"test": test.RandomBytes(65)},
				},
			},
			},
		}
	}

	t.Run("ok", func(t *testing.T) {
		sm := validStateMsg()
		tb := testtb.NewAlwaysValidTrustBase(t)
		require.NoError(t, sm.Verify(crypto.SHA256, tb))
	})

	t.Run("commit head is nil", func(t *testing.T) {
		sm := &StateMsg{
			CommittedHead: nil,
			Pending:       nil,
		}
		require.ErrorContains(t, sm.Verify(crypto.SHA256, &types.RootTrustBaseV1{}), "commit head is nil")
	})

	t.Run("commit head, invalid block", func(t *testing.T) {
		sm := validStateMsg()
		sm.CommittedHead.Block.Qc = nil
		require.ErrorContains(t, sm.Verify(crypto.SHA256, &types.RootTrustBaseV1{}), "invalid commit head: invalid block data: proposed block is missing quorum certificate")
	})

	t.Run("commit head, invalid QC", func(t *testing.T) {
		sm := validStateMsg()
		sm.CommittedHead.Block.Qc.LedgerCommitInfo.PreviousHash[0]++
		require.EqualError(t, sm.Verify(crypto.SHA256, &types.RootTrustBaseV1{}), "block qc verification error: vote info hash verification failed")
	})

	t.Run("invalid block node data", func(t *testing.T) {
		sm := validStateMsg()
		sm.Pending[0].Qc = nil
		tb := testtb.NewAlwaysValidTrustBase(t)
		require.ErrorContains(t, sm.Verify(crypto.SHA256, tb), "invalid block node: proposed block is missing quorum certificate")
	})

	t.Run("profile 2 checks each inherited LastCR under its own epoch", func(t *testing.T) {
		first := testtb.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
		secondSigner, _ := testsig.CreateSignerAndVerifier(t)
		secondGenesis := testtb.NewTrustBase(t, secondSigner).(*types.RootTrustBaseV1)
		identity := sha256.Sum256([]byte("recovery-test-execution"))
		history, err := trusthistorystore.Open(context.Background(), memorydb.New(), first, identity, recoveryHistoryProof{})
		require.NoError(t, err)
		anchorHash, err := first.Hash(crypto.SHA256)
		require.NoError(t, err)
		predecessor, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: uint64(first.NetworkID), Epoch: 1, HashIncludingSigs: anchorHash})
		require.NoError(t, err)
		body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: uint64(first.NetworkID), Epoch: 2,
			EarliestActivation: 10, Members: evmroot.WeightSet{{StakingID: "stake-2", NodeID: secondGenesis.RootNodes[0].NodeID,
				ConsensusKey: secondGenesis.RootNodes[0].SigKey, Weight: 1}}, RootThreshold: 1,
			StateSummary: bytes.Repeat([]byte{3}, 32), ChangeRecordHash: bytes.Repeat([]byte{4}, 32), PredecessorHash: predecessor}
		bodyID := body.Identity()
		interval := m2contract.TrustInterval{Body: body, Activation: evmroot.ActivatedTrustBase{
			BodyIdentity: bodyID[:], EpochStart: 11, ActivationCommitID: bytes.Repeat([]byte{5}, 32)}}
		require.NoError(t, history.AppendVerified(context.Background(), interval, []byte("proof")))

		secondConf := types.PartitionDescriptionRecord{PartitionID: 2}
		secondUC := testcertificates.CreateUnicityCertificate(t, secondSigner, headIR, &secondConf, 11,
			make([]byte, 32), make([]byte, 32))
		secondUC.UnicitySeal.Epoch = 2
		require.NoError(t, secondUC.UnicitySeal.Sign(secondGenesis.RootNodes[0].NodeID, secondSigner))
		makeState := func() StateMsg {
			sm := validStateMsg()
			secondShard := sm.CommittedHead.ShardInfo[0]
			secondShard.Partition = 2
			secondShard.UC = secondUC
			secondShard.ShardConfHash = test.DoHash(t, &secondConf)
			sm.CommittedHead.ShardInfo = append(sm.CommittedHead.ShardInfo, secondShard)
			return sm
		}
		current := testtb.NewAlwaysValidTrustBase(t) // consensus QCs in this fixture
		sm := makeState()
		require.NoError(t, sm.VerifyWithHistory(crypto.SHA256, current, history))
		// The legacy path remains available with the switch off.
		require.NoError(t, sm.Verify(crypto.SHA256, current))

		t.Run("wrong signer epoch", func(t *testing.T) {
			sm := makeState()
			wrong := *uc
			seal := *uc.UnicitySeal
			seal.Signatures = nil
			wrong.UnicitySeal = &seal
			wrong.UnicitySeal.Epoch = 2
			require.NoError(t, wrong.UnicitySeal.Sign(first.RootNodes[0].NodeID, signer))
			sm.CommittedHead.ShardInfo[0].UC = &wrong
			require.ErrorIs(t, sm.VerifyWithHistory(crypto.SHA256, current, history), ErrHistoricalUC)
		})

		t.Run("right signer epoch but wrong shard identity", func(t *testing.T) {
			sm := makeState()
			// The UC and its epoch signature remain valid, but the recovery
			// record claims that the certificate belongs to another shard.
			wrongShard, _ := (types.ShardID{}).Split()
			sm.CommittedHead.ShardInfo[1].Shard = wrongShard
			shard := sm.CommittedHead.ShardInfo[1]
			// Isolate the final expected-identity binding: the same UC is
			// authentic under its own identity and epoch trust base.
			require.NoError(t, verifyRecoveryUC(shard, secondGenesis, crypto.SHA256, false))
			require.ErrorContains(t, verifyRecoveryUC(shard, secondGenesis, crypto.SHA256, true), "invalid shard ID")
			require.ErrorContains(t, sm.VerifyWithHistory(crypto.SHA256, current, history), "invalid shard ID")
		})

		t.Run("right epoch and shard but wrong shard configuration hash", func(t *testing.T) {
			sm := makeState()
			// The initial structural validation accepts the matching hash. Change
			// only the expected recovery hash before historical UC verification.
			shardConfHash := sm.CommittedHead.ShardInfo[1].ShardConfHash
			err := sm.VerifyWithHistory(crypto.SHA256, current, recoveryHistoryMutating{
				base: history,
				mutate: func() {
					shardConfHash[0]++
				},
			})
			require.ErrorIs(t, err, ErrHistoricalUC)
		})

		t.Run("missing body never falls back", func(t *testing.T) {
			onlyFirst, err := trusthistorystore.Open(context.Background(), memorydb.New(), first, identity, recoveryHistoryProof{})
			require.NoError(t, err)
			sm := makeState()
			err = sm.VerifyWithHistory(crypto.SHA256, current, onlyFirst)
			require.ErrorIs(t, err, ErrHistoricalTrustBase)
			require.ErrorIs(t, err, trusthistorystore.ErrNotFound)
		})

		t.Run("missing resolver refuses", func(t *testing.T) {
			sm := makeState()
			require.ErrorIs(t, sm.VerifyWithHistory(crypto.SHA256, current, nil), ErrHistoricalTrustBase)
		})

		t.Run("unverified body refuses", func(t *testing.T) {
			record, err := history.ByEpoch(2)
			require.NoError(t, err)
			record.BodyID[0]++
			sm := makeState()
			require.ErrorIs(t, sm.VerifyWithHistory(crypto.SHA256, current,
				recoveryHistoryRecordOverride{history, record}), ErrHistoricalTrustBase)
		})

		t.Run("pending consensus stays in one epoch", func(t *testing.T) {
			sm := makeState()
			sm.Pending[0].Epoch++
			require.ErrorIs(t, sm.VerifyWithHistory(crypto.SHA256, current, history), ErrRecoveryEpoch)
		})
	})
}

func TestRecoveryBlock_IsValid(t *testing.T) {
	headIR := &types.InputRecord{
		Version:         1,
		PreviousHash:    test.RandomBytes(32),
		Hash:            test.RandomBytes(32),
		BlockHash:       test.RandomBytes(32),
		SummaryValue:    test.RandomBytes(32),
		RoundNumber:     3,
		SumOfEarnedFees: 10,
		Timestamp:       types.NewTimestamp(),
	}

	pdr := types.PartitionDescriptionRecord{
		PartitionID: 1,
	}

	signer, _ := testsig.CreateSignerAndVerifier(t)

	uc := testcertificates.CreateUnicityCertificate(
		t,
		signer,
		headIR,
		&pdr,
		1,
		make([]byte, 32),
		make([]byte, 32),
	)
	validBlock := func() CommittedBlock {
		return CommittedBlock{
			Block: &rctypes.BlockData{
				Round:   5,
				Payload: &rctypes.Payload{},
				Qc: &rctypes.QuorumCert{
					VoteInfo: &rctypes.RoundInfo{
						RoundNumber:       4,
						ParentRoundNumber: 3,
						CurrentRootHash:   test.RandomBytes(32),
						Timestamp:         types.NewTimestamp(),
					},
					LedgerCommitInfo: &types.UnicitySeal{
						Version:      1,
						PreviousHash: test.RandomBytes(32),
					},
				},
			},
			ShardInfo: []ShardInfo{{
				Partition:     1,
				PrevEpochStat: []byte{0, 0, 0, 0, 0},
				PrevEpochFees: []byte{0xF, 0xE, 0xE, 5},
				RootHash:      test.RandomBytes(32),
				Fees:          map[string]uint64{"A": 10},
				UC:            uc,
				IR:            headIR,
				TR: &certification.TechnicalRecord{
					Round:    5,
					Epoch:    1,
					Leader:   "A",
					StatHash: []byte{5},
					FeeHash:  []byte{0xF, 0xE, 0xE},
				},
				ShardConfHash: test.DoHash(t, &pdr),
			}},
			Qc:       &rctypes.QuorumCert{},
			CommitQc: &rctypes.QuorumCert{},
		}
	}

	b := validBlock()
	require.NoError(t, b.IsValid())

	t.Run("invalid ShardInfo", func(t *testing.T) {
		r := validBlock()
		r.ShardInfo[0].Partition = 0
		require.ErrorContains(t, r.IsValid(), "invalid ShardInfo[00000000 - ]: missing partition id")
	})

	t.Run("input record is nil", func(t *testing.T) {
		r := validBlock()
		r.ShardInfo[0].IR = nil
		require.ErrorContains(t, r.IsValid(), "invalid ShardInfo[00000001 - ]: invalid input record: input record is nil")
	})

	t.Run("shard info nil root hash is allowed", func(t *testing.T) {
		r := validBlock()
		r.ShardInfo[0].RootHash = nil
		require.NoError(t, r.IsValid())
	})

	t.Run("block data is nil", func(t *testing.T) {
		r := validBlock()
		r.Block = nil
		require.ErrorContains(t, r.IsValid(), "block data is nil")
	})

	t.Run("block data is invalid", func(t *testing.T) {
		r := validBlock()
		r.Block.Qc.VoteInfo.ParentRoundNumber = 0
		require.ErrorContains(t, r.IsValid(), "invalid block data: invalid quorum certificate: invalid vote info: parent round number is not assigned")
	})

	t.Run("head is missing qc", func(t *testing.T) {
		r := validBlock()
		r.Qc = nil
		require.ErrorContains(t, r.IsValid(), "commit head is missing qc certificate")
	})

	t.Run("head is missing commit qc", func(t *testing.T) {
		r := validBlock()
		r.CommitQc = nil
		require.ErrorContains(t, r.IsValid(), "commit head is missing commit qc certificate")
	})
}
