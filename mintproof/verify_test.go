package mintproof

import (
	"bytes"
	gocrypto "crypto"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-go-base/types"
)

var fixtureEmitter = common.HexToAddress("0x1234000000000000000000000000000000001234")
var fixtureTopic = common.HexToHash("0xaaaa")

type proofFixture struct {
	store    *archive.Store
	request  ExtractRequest
	bundle   []byte
	trust    types.RootTrustBase
	claim    ExpectedClaim
	chain    *certifiedchain.Chain
	receipts [][]byte
}

func newProofFixture(t *testing.T, statuses []uint64, corruptRoot, mismatchedType bool) proofFixture {
	t.Helper()
	chain := certifiedchain.New(t, 3, 0)
	to := common.HexToAddress("0x2222000000000000000000000000000000002222")
	txs := make(gethtypes.Transactions, len(statuses))
	receipts := make(gethtypes.Receipts, len(statuses))
	for i := range statuses {
		if i == 0 {
			txs[i] = gethtypes.NewTx(&gethtypes.LegacyTx{Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)})
		} else {
			txs[i] = gethtypes.NewTx(&gethtypes.DynamicFeeTx{ChainID: big.NewInt(1337), Nonce: uint64(i), To: &to, Value: big.NewInt(1), Gas: 21000, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2)})
		}
		receiptType := txs[i].Type()
		if mismatchedType && i == 0 {
			receiptType = gethtypes.DynamicFeeTxType
		}
		receipts[i] = &gethtypes.Receipt{Type: receiptType, Status: statuses[i], CumulativeGasUsed: uint64((i + 1) * 21000), Logs: []*gethtypes.Log{{Address: fixtureEmitter, Topics: []common.Hash{fixtureTopic, common.HexToHash("0xbb")}, Data: []byte{0x01, 0x02}}}}
	}
	encReceipts := make([][]byte, len(receipts))
	for i, receipt := range receipts {
		encReceipts[i], _ = receipt.MarshalBinary()
	}
	state := common.HexToHash("0x9876")
	withdrawals := gethtypes.EmptyWithdrawalsHash
	blobGas, excessBlob := uint64(0), uint64(0)
	beacon := common.Hash{}
	header := &gethtypes.Header{ParentHash: common.HexToHash("0x1111"), UncleHash: gethtypes.EmptyUncleHash,
		Root: state, TxHash: gethtypes.DeriveSha(txs, trie.NewStackTrie(nil)), ReceiptHash: gethtypes.DeriveSha(receipts, trie.NewStackTrie(nil)),
		Bloom: gethtypes.CreateBloom(receipts), Difficulty: new(big.Int), Number: big.NewInt(1), GasLimit: 1_000_000,
		GasUsed: uint64(len(txs) * 21000), Time: 1_700_000_000, BaseFee: big.NewInt(1), WithdrawalsHash: &withdrawals,
		BlobGasUsed: &blobGas, ExcessBlobGas: &excessBlob, ParentBeaconRoot: &beacon}
	if corruptRoot {
		header.ReceiptHash[0] ^= 0x80
	}
	headerRLP, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	tr := certifiedchain.Technical(1)
	ir := &types.InputRecord{Version: 1, RoundNumber: 1, Epoch: 0, PreviousHash: bytes.Repeat([]byte{0x77}, 32), Hash: state.Bytes(), BlockHash: header.Hash().Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000}
	uc := chain.Certify(chain.Signer, ir, tr, 5)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	verifier, err := chain.Signer.Verifier()
	require.NoError(t, err)
	pub, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	nodeID, err := network.NodeIDFromPublicKeyBytes(pub)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(nodeID.String(), chain.Signer))
	ucRaw, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)
	trRaw, err := types.Cbor.Marshal(tr)
	require.NoError(t, err)
	body, err := rlp.EncodeToBytes(&gethtypes.Body{Transactions: txs, Withdrawals: []*gethtypes.Withdrawal{}})
	require.NoError(t, err)
	confHash, err := chain.Full.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	var conf [32]byte
	copy(conf[:], confHash)
	var receiptList []byte
	receiptList, err = rlp.EncodeToBytes(encReceipts)
	require.NoError(t, err)
	ctx := archive.Context{NetworkID: 3, PartitionID: 8, ShardID: chain.Full.ShardID, ShardEpoch: 0, RootEpoch: 1,
		FullShardConfHash: conf, RegistryAddress: [20]byte{1}, RegistryCodeHash: [32]byte{1}, GenesisCommitment: [32]byte{1}, EVMGenesisHash: [32]byte{1}, ExecutionIdentity: []byte("proof-fixture")}
	q := archive.Request{Context: ctx, BlockHash: [32]byte(header.Hash())}
	rec := &archive.Record{Header: headerRLP, Body: body, CanonicalRootInput: []byte{1}, OriginalUC: ucRaw, OriginalTR: trRaw, ResultingUC: ucRaw, ResultingTR: trRaw, Companion: []byte("{}"), Extensions: map[string][]byte{archive.ReceiptListKey: receiptList}}
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.Put(q, rec))
	var bundle MintReasonBundleV1
	if corruptRoot || mismatchedType {
		txRaw, marshalErr := txs[0].MarshalBinary()
		require.NoError(t, marshalErr)
		txProof, proofErr := buildProof(txValues(txs), 0)
		require.NoError(t, proofErr)
		receiptProof, proofErr := buildProof(encReceipts, 0)
		require.NoError(t, proofErr)
		bundle = MintReasonBundleV1{Context: Context{Network: ctx.NetworkID, Partition: ctx.PartitionID, Shard: ctx.ShardID.Bytes(), ShardConf: conf}, SubjectUC: ucRaw, HeaderRLP: headerRLP,
			Evidence: Evidence{TxEnvelope: txRaw, TxProof: txProof, Receipt: encReceipts[0], ReceiptProof: receiptProof}}
	} else {
		bundle, err = Extract(store, ExtractRequest{Archive: q, TxIndex: 0, LogIndex: 0})
		require.NoError(t, err)
	}
	raw, err := bundle.MarshalCBOR()
	require.NoError(t, err)
	tb := *chain.TrustBase
	tb.NetworkID = 3
	claim := ExpectedClaim{Network: 3, Partition: 8, Shard: ctx.ShardID.Bytes(), ShardConf: conf, BlockHash: q.BlockHash, BlockNumber: 1,
		MatchLog: func(log *gethtypes.Log) bool {
			return log.Address == fixtureEmitter && len(log.Topics) == 2 && log.Topics[0] == fixtureTopic && log.Data[0] == 1
		}}
	return proofFixture{store: store, request: ExtractRequest{Archive: q, TxIndex: 0, LogIndex: 0}, bundle: raw, trust: &tb, claim: claim, chain: chain, receipts: encReceipts}
}

func TestOfflineInclusionAndBlockAbsence(t *testing.T) {
	f := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful, gethtypes.ReceiptStatusSuccessful}, false, false)
	require.NoError(t, Verify(f.bundle, f.trust, f.claim, DefaultLimits()))
	absent, err := Extract(f.store, ExtractRequest{Archive: f.request.Archive, Absence: true})
	require.NoError(t, err)
	absentRaw, err := absent.MarshalCBOR()
	require.NoError(t, err)
	noEvent := f.claim
	noEvent.MatchLog = func(*gethtypes.Log) bool { return false }
	require.NoError(t, Verify(absentRaw, f.trust, noEvent, DefaultLimits()))

	mutated := absent
	mutated.Evidence.AllReceipts = mutated.Evidence.AllReceipts[:1]
	truncatedList, err := mutated.MarshalCBOR()
	require.NoError(t, err)
	require.ErrorIs(t, Verify(truncatedList, f.trust, noEvent, DefaultLimits()), ErrInvalid)
	mutated = absent
	mutated.Evidence.AllReceipts[0], mutated.Evidence.AllReceipts[1] = mutated.Evidence.AllReceipts[1], mutated.Evidence.AllReceipts[0]
	reordered, err := mutated.MarshalCBOR()
	require.NoError(t, err)
	require.ErrorIs(t, Verify(reordered, f.trust, noEvent, DefaultLimits()), ErrInvalid)
}

func TestInclusionRejectsClaimAndReceiptMismatches(t *testing.T) {
	f := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful}, false, false)
	for name, change := range map[string]func(*MintReasonBundleV1, *ExpectedClaim){
		"wrong log index": func(b *MintReasonBundleV1, _ *ExpectedClaim) { b.Evidence.LogIndex = 1 },
		"wrong emitter": func(_ *MintReasonBundleV1, c *ExpectedClaim) {
			c.MatchLog = func(log *gethtypes.Log) bool { return log.Address != fixtureEmitter }
		},
		"wrong topic": func(_ *MintReasonBundleV1, c *ExpectedClaim) {
			c.MatchLog = func(log *gethtypes.Log) bool { return len(log.Topics) > 0 && log.Topics[0] == common.HexToHash("0xbb") }
		},
		"wrong decoded data": func(_ *MintReasonBundleV1, c *ExpectedClaim) {
			c.MatchLog = func(log *gethtypes.Log) bool { return bytes.Equal(log.Data, []byte{0x03, 0x04}) }
		},
		"wrong transaction index": func(b *MintReasonBundleV1, _ *ExpectedClaim) { b.Evidence.TxIndex = 1 },
		"wrong transaction type":  func(b *MintReasonBundleV1, _ *ExpectedClaim) { b.Evidence.TxEnvelope = b.Evidence.Receipt },
	} {
		t.Run(name, func(t *testing.T) {
			b, err := DecodeBundle(f.bundle, DefaultLimits())
			require.NoError(t, err)
			claim := f.claim
			change(&b, &claim)
			raw, err := b.MarshalCBOR()
			require.NoError(t, err)
			require.ErrorIs(t, Verify(raw, f.trust, claim, DefaultLimits()), ErrInvalid)
		})
	}
	fail := newProofFixture(t, []uint64{gethtypes.ReceiptStatusFailed}, false, false)
	require.ErrorIs(t, Verify(fail.bundle, fail.trust, fail.claim, DefaultLimits()), ErrInvalid, "a reverted receipt cannot authorize a mint")
	wrongTxHash := f.claim
	wrongHash := common.HexToHash("0xdead")
	wrongTxHash.TransactionHash = &wrongHash
	require.ErrorIs(t, Verify(f.bundle, f.trust, wrongTxHash, DefaultLimits()), ErrInvalid)
	wrongRoot := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful}, true, false)
	require.ErrorIs(t, Verify(wrongRoot.bundle, wrongRoot.trust, wrongRoot.claim, DefaultLimits()), ErrInvalid)
	wrongType := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful}, false, true)
	require.ErrorIs(t, Verify(wrongType.bundle, wrongType.trust, wrongType.claim, DefaultLimits()), ErrInvalid)
}

func TestBundleDecoderRejectsTruncationNoncanonicalAndOversize(t *testing.T) {
	f := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful}, false, false)
	require.Error(t, Verify(f.bundle[:len(f.bundle)-1], f.trust, f.claim, DefaultLimits()))
	b, err := DecodeBundle(f.bundle, DefaultLimits())
	require.NoError(t, err)
	canonical, err := b.MarshalCBOR()
	require.NoError(t, err)
	// Encode the version integer using a nonminimal two-byte representation.
	noncanonical := append([]byte{0x98, 0x05}, canonical[1:]...)
	if bytes.Equal(noncanonical, canonical) {
		t.Fatal("fixture unexpectedly uses a different prefix")
	}
	require.Error(t, Verify(noncanonical, f.trust, f.claim, DefaultLimits()))
	unsupported := bytes.Clone(canonical)
	unsupported[1] = 0x02
	require.ErrorIs(t, Verify(unsupported, f.trust, f.claim, DefaultLimits()), ErrInvalid)
	extraField := append([]byte{0x86}, canonical[1:]...)
	extraField = append(extraField, 0x00)
	require.ErrorIs(t, Verify(extraField, f.trust, f.claim, DefaultLimits()), ErrInvalid)
	limits := DefaultLimits()
	limits.MaxBytes = len(f.bundle) - 1
	require.ErrorIs(t, Verify(f.bundle, f.trust, f.claim, limits), ErrTooLarge)
}

func TestWrongEpochAndWrongRequestedBlockFail(t *testing.T) {
	f := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful}, false, false)
	wrongEpoch := *f.trust.(*types.RootTrustBaseV1)
	wrongEpoch.Epoch++
	require.ErrorIs(t, Verify(f.bundle, &wrongEpoch, f.claim, DefaultLimits()), ErrInvalid)
	claim := f.claim
	claim.BlockNumber++
	require.ErrorIs(t, Verify(f.bundle, f.trust, claim, DefaultLimits()), ErrInvalid)
}

func TestVerifierRejectsUCSignaturePathKeysAndContextChanges(t *testing.T) {
	f := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful}, false, false)
	for name, change := range map[string]func(*types.UnicityCertificate){
		"invalid signature": func(uc *types.UnicityCertificate) {
			for id := range uc.UnicitySeal.Signatures {
				uc.UnicitySeal.Signatures[id] = []byte{0x01}
			}
		},
		"missing quorum":     func(uc *types.UnicityCertificate) { uc.UnicitySeal.Signatures = nil },
		"invalid shard path": func(uc *types.UnicityCertificate) { uc.InputRecord.Hash[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bundle, err := DecodeBundle(f.bundle, DefaultLimits())
			require.NoError(t, err)
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(bundle.SubjectUC, &uc))
			change(&uc)
			bundle.SubjectUC, err = types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			raw, err := bundle.MarshalCBOR()
			require.NoError(t, err)
			require.ErrorIs(t, Verify(raw, f.trust, f.claim, DefaultLimits()), ErrInvalid)
		})
	}
	wrongKeys := *f.trust.(*types.RootTrustBaseV1)
	originalNode := wrongKeys.RootNodes[0]
	wrongKeys.RootNodes = []*types.NodeInfo{{NodeID: originalNode.NodeID + "-other", SigKey: bytes.Clone(originalNode.SigKey), Stake: originalNode.Stake}}
	require.ErrorIs(t, Verify(f.bundle, &wrongKeys, f.claim, DefaultLimits()), ErrInvalid)
	for name, mutate := range map[string]func(*ExpectedClaim){
		"network":       func(c *ExpectedClaim) { c.Network++ },
		"partition":     func(c *ExpectedClaim) { c.Partition++ },
		"shard":         func(c *ExpectedClaim) { c.Shard = []byte{0x01} },
		"configuration": func(c *ExpectedClaim) { c.ShardConf[0] ^= 1 },
		"block hash":    func(c *ExpectedClaim) { c.BlockHash[0] ^= 1 },
	} {
		t.Run("wrong "+name, func(t *testing.T) {
			claim := f.claim
			mutate(&claim)
			require.ErrorIs(t, Verify(f.bundle, f.trust, claim, DefaultLimits()), ErrInvalid)
		})
	}
}

func FuzzDecodeBundleIsBounded(f *testing.F) {
	f.Add([]byte{0x85, 0x01})
	f.Add([]byte{0xff, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, raw []byte) {
		limits := Limits{MaxBytes: 1 << 16, MaxNodes: 1024, MaxWork: 1 << 17}
		_, _ = DecodeBundle(raw, limits)
	})
}
