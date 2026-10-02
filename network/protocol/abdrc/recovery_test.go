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
						Version:              1,
						PreviousHash:         h6,
						RootChainRoundNumber: 5, // the head's commit QC commits the head: it names what it commits
						Hash:                 test.RandomBytes(32),
						Signatures:           map[string]hex.Bytes{"test": test.RandomBytes(65)},
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

		// The head's commit QC commits the head, so the empty seal of a QC that commits nothing is never valid in that slot (it is elsewhere): the
		// typed epoch refusal, at verification.
		sm = makeState()
		commitQc := *sm.CommittedHead.CommitQc
		seal := *commitQc.LedgerCommitInfo
		seal.RootChainRoundNumber, seal.Hash = 0, nil
		commitQc.LedgerCommitInfo = &seal
		sm.CommittedHead.CommitQc = &commitQc
		require.ErrorIs(t, sm.VerifyWithHistory(crypto.SHA256, current, history), ErrRecoveryEpoch)
		sm = makeState()
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

		// Every pointer of a peer's StateMsg can be nil or empty, whatever the peer is. Verification must refuse such a message, never panic
		// (a remote peer could otherwise stop a recovering root), and the refusals that have a reason carry a typed error.
		t.Run("no nil or empty field of a peer's state panics verification", func(t *testing.T) {
			type mutation struct {
				name   string
				mutate func(*StateMsg)
				want   error // nil: it must only be refused, with any error
			}
			// The certificate is shared by the fixture: copy it before taking a part away.
			ownUC := func(sm *StateMsg) *types.UnicityCertificate {
				c := *sm.CommittedHead.ShardInfo[0].UC
				sm.CommittedHead.ShardInfo[0].UC = &c
				return &c
			}
			mutations := []mutation{
				{"no committed head", func(sm *StateMsg) { sm.CommittedHead = nil }, nil},
				{"head without a block", func(sm *StateMsg) { sm.CommittedHead.Block = nil }, nil},
				{"head block without a payload", func(sm *StateMsg) { sm.CommittedHead.Block.Payload = nil }, nil},
				{"head block without a QC", func(sm *StateMsg) { sm.CommittedHead.Block.Qc = nil }, nil},
				{"head block QC without vote info", func(sm *StateMsg) { sm.CommittedHead.Block.Qc.VoteInfo = nil }, nil},
				{"head block QC without commit info", func(sm *StateMsg) { sm.CommittedHead.Block.Qc.LedgerCommitInfo = nil }, nil},
				{"head block QC without signatures", func(sm *StateMsg) { sm.CommittedHead.Block.Qc.Signatures = nil }, nil},
				{"head without a QC", func(sm *StateMsg) { sm.CommittedHead.Qc = nil }, nil},
				{"head QC without vote info", func(sm *StateMsg) { sm.CommittedHead.Qc.VoteInfo = nil }, nil},
				{"head QC without commit info", func(sm *StateMsg) { sm.CommittedHead.Qc.LedgerCommitInfo = nil }, nil},
				{"head without a commit QC", func(sm *StateMsg) { sm.CommittedHead.CommitQc = nil }, nil},
				{"head commit QC without vote info", func(sm *StateMsg) { sm.CommittedHead.CommitQc.VoteInfo = nil }, nil},
				{"head commit QC without commit info", func(sm *StateMsg) { sm.CommittedHead.CommitQc.LedgerCommitInfo = nil }, nil},
				{"shard info without a certificate", func(sm *StateMsg) { sm.CommittedHead.ShardInfo[0].UC = nil }, nil},
				{"shard info certificate without a seal", func(sm *StateMsg) { ownUC(sm).UnicitySeal = nil }, nil},
				{"shard info certificate without a unicity tree certificate", func(sm *StateMsg) { ownUC(sm).UnicityTreeCertificate = nil }, nil},
				{"shard info certificate with an empty shard tree certificate", func(sm *StateMsg) {
					ownUC(sm).ShardTreeCertificate = types.ShardTreeCertificate{}
				}, nil},
				{"shard info certificate without an input record", func(sm *StateMsg) { ownUC(sm).InputRecord = nil }, nil},
				{"shard info without an input record", func(sm *StateMsg) { sm.CommittedHead.ShardInfo[0].IR = nil }, nil},
				{"shard info without a technical record", func(sm *StateMsg) { sm.CommittedHead.ShardInfo[0].TR = nil }, ErrRecoveryState},
				{"shard info without fees", func(sm *StateMsg) { sm.CommittedHead.ShardInfo[0].Fees = nil }, nil},
				{"a nil pending block", func(sm *StateMsg) { sm.Pending = []*rctypes.BlockData{nil} }, ErrRecoveryState},
				{"a nil pending block after a valid one", func(sm *StateMsg) { sm.Pending = append(sm.Pending, nil) }, ErrRecoveryState},
				{"pending block without a payload", func(sm *StateMsg) { sm.Pending[0].Payload = nil }, nil},
				{"pending block without a QC", func(sm *StateMsg) { sm.Pending[0].Qc = nil }, nil},
				{"pending QC without vote info", func(sm *StateMsg) { sm.Pending[0].Qc.VoteInfo = nil }, nil},
				{"pending QC without commit info", func(sm *StateMsg) { sm.Pending[0].Qc.LedgerCommitInfo = nil }, nil},
				{"pending block carrying an anchor the head does not", func(sm *StateMsg) {
					sm.Pending[0].Anchor = &rctypes.EpochAnchor{GenesisID: make([]byte, 32), Epoch: 1, Slot: 1, StateRoot: make([]byte, 32)}
				}, nil},
				{"a head that is the first successor of an anchor (anchor set, no QC): wait for the next state", func(sm *StateMsg) {
					a := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 4, StateRoot: bytes.Repeat([]byte{2}, 32)}
					sm.CommittedHead.Block.Version, sm.CommittedHead.Block.Payload.Version = 2, 2
					sm.CommittedHead.Block.Anchor, sm.CommittedHead.Block.Qc = a, nil
					sm.CommittedHead.Block.Epoch, sm.CommittedHead.Block.Round = a.Epoch, a.Slot+1
					sm.CommittedHead.Control = &evmroot.ControlState{Network: 5, Epoch: a.Epoch, PredecessorBodyID: make([]byte, 32)}
				}, ErrRecoveryEpoch},
				{"a head with an anchor but no control checkpoint", func(sm *StateMsg) {
					sm.CommittedHead.Anchor = &rctypes.EpochAnchor{GenesisID: make([]byte, 32), Epoch: 1, Slot: 1, StateRoot: make([]byte, 32)}
				}, nil},
				{"a head with a control checkpoint but a v1 block", func(sm *StateMsg) {
					sm.CommittedHead.Control = &evmroot.ControlState{Network: 5, Epoch: 1, PredecessorBodyID: make([]byte, 32)}
				}, nil},
			}
			// The test trust base accepts any signature, so a QC that only lacks signatures verifies; nothing else on this list may.
			acceptable := map[string]bool{"head block QC without signatures": true}
			// A profile-2 state may legitimately carry a shard without a last certificate; the legacy path has no such shard.
			acceptableInHistory := map[string]bool{"shard info without a certificate": true}
			verifiers := map[string]func(StateMsg) error{
				"legacy":  func(sm StateMsg) error { return sm.Verify(crypto.SHA256, current) },
				"history": func(sm StateMsg) error { return sm.VerifyWithHistory(crypto.SHA256, current, history) },
				"anchor": func(sm StateMsg) error {
					return sm.VerifyWithAnchor(crypto.SHA256, current, history, anchorRecoveryVerifier{expected: bytes.Repeat([]byte{1}, 32)})
				},
			}
			for _, m := range mutations {
				for name, verify := range verifiers {
					t.Run(m.name+" ("+name+")", func(t *testing.T) {
						sm := makeState()
						if m.name != "no committed head" {
							sm.Pending = append([]*rctypes.BlockData(nil), sm.Pending...)
						}
						require.NotPanics(t, func() {
							m.mutate(&sm)
							err := verify(sm)
							if !acceptable[m.name] && !(acceptableInHistory[m.name] && name != "legacy") {
								require.Error(t, err)
							}
							if m.want != nil {
								require.ErrorIs(t, err, m.want)
							}
							_ = sm.CanRecoverToRound(6)
						})
					})
				}
			}
		})

		// A QC that commits nothing (after a timed-out round, or right after an epoch anchor) carries the empty seal. Recovery accepts it
		// when what it VOTES for is in the epoch, and still refuses everything that names another epoch (#366).
		t.Run("a QC that commits nothing is in the epoch if its vote is", func(t *testing.T) {
			// The epoch must not be 0: the empty seal's own epoch is 0, so in an epoch-0 fixture the pre-#366 rule (every commit info
			// must be in the epoch) accepts the empty seal as well, and nothing here could tell the two rules apart.
			const epoch = 7
			current := epochTrustBase{RootTrustBase: current, epoch: epoch}
			inEpoch := func(qc *rctypes.QuorumCert) *rctypes.QuorumCert {
				info := *qc.VoteInfo
				info.Epoch = epoch
				h, err := info.Hash(crypto.SHA256)
				require.NoError(t, err)
				seal := *qc.LedgerCommitInfo
				seal.PreviousHash = h
				if !isEmptyCommitInfo(&seal) {
					seal.Epoch = epoch
				}
				out := *qc
				out.VoteInfo, out.LedgerCommitInfo = &info, &seal
				return &out
			}
			stateInEpoch := func() StateMsg {
				sm := makeState()
				head := *sm.CommittedHead
				block := *head.Block
				block.Epoch = epoch
				block.Qc = inEpoch(block.Qc)
				head.Block, head.Qc, head.CommitQc = &block, inEpoch(head.Qc), inEpoch(head.CommitQc)
				sm.CommittedHead = &head
				pending := make([]*rctypes.BlockData, len(sm.Pending))
				for i, b := range sm.Pending {
					cp := *b
					cp.Epoch, cp.Qc = epoch, inEpoch(b.Qc)
					pending[i] = &cp
				}
				sm.Pending = pending
				return sm
			}
			withQC := func(voteEpoch uint64, seal func(previous []byte) *types.UnicitySeal) StateMsg {
				sm := stateInEpoch()
				info := *sm.Pending[0].Qc.VoteInfo
				info.Epoch = voteEpoch
				h, err := info.Hash(crypto.SHA256)
				require.NoError(t, err)
				sm.Pending[0].Qc = &rctypes.QuorumCert{VoteInfo: &info, LedgerCommitInfo: seal(h), Signatures: map[string]hex.Bytes{"test": test.RandomBytes(65)}}
				return sm
			}
			empty := func(previous []byte) *types.UnicitySeal {
				return &types.UnicitySeal{Version: 1, PreviousHash: previous}
			}
			commits := func(sealEpoch uint64) func([]byte) *types.UnicitySeal {
				return func(previous []byte) *types.UnicitySeal {
					return &types.UnicitySeal{Version: 1, PreviousHash: previous, NetworkID: 1, Epoch: sealEpoch, RootChainRoundNumber: 5, Hash: test.RandomBytes(32), Timestamp: 7}
				}
			}
			base := stateInEpoch()
			require.NoError(t, base.VerifyWithHistory(crypto.SHA256, current, history), "control: the whole fixture state in the epoch")
			require.True(t, isEmptyCommitInfo(base.CommittedHead.Qc.LedgerCommitInfo), "premise: the head QCs of the fixture commit nothing")
			sm := withQC(epoch, empty)
			require.NoError(t, sm.VerifyWithHistory(crypto.SHA256, current, history), "the empty seal of a QC voting in this epoch")
			sm = withQC(epoch, commits(epoch))
			require.NoError(t, sm.VerifyWithHistory(crypto.SHA256, current, history), "control: a committing QC of this epoch")

			for name, bad := range map[string]StateMsg{
				"the empty seal of a QC that votes in another epoch": withQC(epoch+1, empty),
				"a committing seal of another epoch":                 withQC(epoch, commits(epoch+1)),
				"a committing seal of another epoch and vote":        withQC(epoch+1, commits(epoch+1)),
			} {
				require.ErrorIs(t, bad.VerifyWithHistory(crypto.SHA256, current, history), ErrRecoveryEpoch, name)
			}
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

// recoveryQCEpoch skips the commit epoch only for the exact empty seal. The table runs in epoch 3 so that "epoch 0" is never the epoch.
func TestRecoveryQCEpochAcceptsOnlyTheExactEmptySealWithoutACommitEpoch(t *testing.T) {
	const epoch = 3
	qc := func(voteEpoch uint64, seal *types.UnicitySeal) *rctypes.QuorumCert {
		return &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{Epoch: voteEpoch}, LedgerCommitInfo: seal}
	}
	empty := func() *types.UnicitySeal { return &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}} }
	with := func(mutate func(*types.UnicitySeal)) *types.UnicitySeal { s := empty(); mutate(s); return s }
	for _, tc := range []struct {
		name string
		qc   *rctypes.QuorumCert
		want bool
	}{
		{"no QC", nil, true},
		{"the empty seal, voting in the epoch", qc(epoch, empty()), true},
		{"a seal committing in the epoch, voting in the epoch", qc(epoch, with(func(s *types.UnicitySeal) { s.Epoch, s.RootChainRoundNumber, s.Hash = epoch, 9, []byte{7} })), true},
		{"the empty seal, voting in another epoch", qc(epoch+1, empty()), false},
		{"the empty seal, voting in an older epoch", qc(epoch-1, empty()), false},
		{"a seal committing in another epoch", qc(epoch, with(func(s *types.UnicitySeal) { s.Epoch, s.RootChainRoundNumber, s.Hash = epoch-1, 9, []byte{7} })), false},
		{"epoch 0 but a committed round", qc(epoch, with(func(s *types.UnicitySeal) { s.RootChainRoundNumber = 9 })), false},
		{"epoch 0 but a root hash", qc(epoch, with(func(s *types.UnicitySeal) { s.Hash = []byte{7} })), false},
		{"epoch 0 but a network", qc(epoch, with(func(s *types.UnicitySeal) { s.NetworkID = 5 })), false},
		{"epoch 0 but a timestamp", qc(epoch, with(func(s *types.UnicitySeal) { s.Timestamp = 7 })), false},
		{"no vote info", &rctypes.QuorumCert{LedgerCommitInfo: empty()}, false},
		{"no commit info", &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{Epoch: epoch}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, recoveryQCEpoch(tc.qc, epoch))
		})
	}
	require.True(t, isEmptyCommitInfo(empty()))
	require.False(t, isEmptyCommitInfo(nil))
}

// epochTrustBase reports another epoch than the always-valid trust base, which is epoch 0.
type epochTrustBase struct {
	types.RootTrustBase
	epoch uint64
}

func (e epochTrustBase) GetEpoch() uint64 { return e.epoch }
