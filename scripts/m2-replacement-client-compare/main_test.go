package main

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archivewiring"
	unicitytypes "github.com/unicitynetwork/bft-go-base/types"
)

func TestEqualCertifiedBlockChecksRootsAndAllCompanionBytes(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*storedBlock)
	}{
		{"block root", func(b *storedBlock) { b.header.Root[0] ^= 1 }},
		{"receipt root", func(b *storedBlock) { b.header.ReceiptHash[0] ^= 1 }},
		{"header bytes", func(b *storedBlock) { b.record.Header[0] ^= 1 }},
		{"body bytes", func(b *storedBlock) { b.record.Body[0] ^= 1 }},
		{"canonical input", func(b *storedBlock) { b.record.CanonicalRootInput[0] ^= 1 }},
		{"authorizing UC", func(b *storedBlock) { b.record.OriginalUC[0] ^= 1 }},
		{"authorizing TR", func(b *storedBlock) { b.record.OriginalTR[0] ^= 1 }},
		{"resulting UC", func(b *storedBlock) { b.record.ResultingUC[0] ^= 1 }},
		{"resulting TR", func(b *storedBlock) { b.record.ResultingTR[0] ^= 1 }},
		{"seal companion", func(b *storedBlock) { b.record.Companion[0] ^= 1 }},
		{"receipt list", func(b *storedBlock) { b.record.Extensions[archive.ReceiptListKey][0] ^= 1 }},
	}
	// The unmutated pair must pass, or every mutation below would "pass" vacuously by tripping over some unrelated difference.
	t.Run("baseline pair passes", func(t *testing.T) {
		a, b := equalPair()
		require.NoError(t, equalCertifiedBlock(7, a, b))
	})
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			a, b := equalPair()
			tc.mutate(b)
			require.ErrorIs(t, equalCertifiedBlock(7, a, b), ErrBlockMismatch, "equalCertifiedBlock accepted mutated %s", tc.name)
		})
	}
}

func equalPair() (*storedBlock, *storedBlock) {
	header := gethtypes.Header{Number: big.NewInt(7), Root: common.HexToHash("0x11"), ReceiptHash: common.HexToHash("0x22")}
	left := &storedBlock{header: header, record: &archive.Record{
		Header: []byte{1}, Body: []byte{2}, CanonicalRootInput: []byte{3}, OriginalUC: []byte{4}, OriginalTR: []byte{5},
		ResultingUC: []byte{6}, ResultingTR: []byte{7}, Companion: []byte{8},
		Extensions: map[string][]byte{archive.ReceiptListKey: []byte{9}},
	}}
	right := &storedBlock{header: header, record: &archive.Record{
		Header: []byte{1}, Body: []byte{2}, CanonicalRootInput: []byte{3}, OriginalUC: []byte{4}, OriginalTR: []byte{5},
		ResultingUC: []byte{6}, ResultingTR: []byte{7}, Companion: []byte{8},
		Extensions: map[string][]byte{archive.ReceiptListKey: []byte{9}},
	}}
	return left, right
}

// synthBlock builds a verified-looking archived block without a chain: a paid block carries one successful legacy transaction
// and its receipt, an idle block neither. Every field compareHistories reads is real (receipt list included).
func synthBlock(t *testing.T, height uint64, parent common.Hash, paid bool, epoch uint64) *storedBlock {
	t.Helper()
	var txs []*gethtypes.Transaction
	var receipts gethtypes.Receipts
	if paid {
		tx := gethtypes.NewTx(&gethtypes.LegacyTx{Nonce: height, To: &common.Address{1}, Gas: 21000, GasPrice: big.NewInt(1), Value: big.NewInt(1)})
		txs = []*gethtypes.Transaction{tx}
		receipts = gethtypes.Receipts{{Type: tx.Type(), Status: gethtypes.ReceiptStatusSuccessful, CumulativeGasUsed: 21000}}
	}
	header := gethtypes.Header{Number: new(big.Int).SetUint64(height), ParentHash: parent, Root: common.BigToHash(big.NewInt(int64(height))),
		TxHash:      gethtypes.DeriveSha(gethtypes.Transactions(txs), trie.NewStackTrie(nil)),
		ReceiptHash: gethtypes.DeriveSha(receipts, trie.NewStackTrie(nil)), Bloom: gethtypes.CreateBloom(receipts)}
	body := gethtypes.Body{Transactions: txs}
	rawHeader, err := rlp.EncodeToBytes(&header)
	require.NoError(t, err)
	rawBody, err := rlp.EncodeToBytes(&body)
	require.NoError(t, err)
	var envelopes [][]byte
	for _, r := range receipts {
		raw, err := r.MarshalBinary()
		require.NoError(t, err)
		envelopes = append(envelopes, raw)
	}
	rec, err := archivewiring.WithReceiptList(&archive.Record{Header: rawHeader, Body: rawBody, CanonicalRootInput: []byte{byte(height)},
		OriginalUC: []byte{1}, OriginalTR: []byte{2}, ResultingUC: []byte{3}, ResultingTR: []byte{4}, Companion: []byte{5}}, envelopes)
	require.NoError(t, err)
	return &storedBlock{request: archive.Request{BlockHash: header.Hash()}, record: rec, header: header, body: body,
		uc:    &unicitytypes.UnicityCertificate{UnicitySeal: &unicitytypes.UnicitySeal{Epoch: epoch, RootChainRoundNumber: height * 10}},
		input: []byte{byte(height)}}
}

// historyFixture is a passing comparison: six parent-linked blocks across root epochs 1-3, paid and idle in each, identical on both
// sides, with the source log admitting and the replacement log restoring and admitting an epoch-3 block.
type blockShape struct {
	paid  bool
	epoch uint64
}

var passingShape = []blockShape{{true, 1}, {false, 1}, {true, 2}, {false, 2}, {true, 3}, {false, 3}}

func historyFixture(t *testing.T) historyInput { return historyFromShape(t, passingShape) }

func historyFromShape(t *testing.T, shape []blockShape) historyInput {
	t.Helper()
	in := historyInput{sourceDir: "source", replacementDir: "replacement", source: map[uint64]*storedBlock{}, replacement: map[uint64]*storedBlock{},
		sourceAdmissions: map[string]bool{}, sourceRootInputs: map[string][]byte{}, replacementEpoch3: map[string]bool{},
		replacementText: []byte("msg=\"execution journal restored\" handoff activated rootEpoch=2 handoff activated rootEpoch=3\n" +
			"msg=\"certificate admitted\" block=00 height=5 round=1 rootEpoch=3\n")}
	parent := common.Hash{}
	for i, step := range shape {
		height := uint64(i + 1)
		a := synthBlock(t, height, parent, step.paid, step.epoch)
		b := synthBlock(t, height, parent, step.paid, step.epoch)
		in.source[height], in.replacement[height] = a, b
		hash := fmt.Sprintf("%x", a.request.BlockHash)
		in.sourceAdmissions[hash] = true
		in.sourceRootInputs[hash] = a.input
		if step.epoch == 3 {
			in.replacementEpoch3[hash] = true
		}
		parent = a.header.Hash()
	}
	return in
}

func TestCompareHistories(t *testing.T) {
	t.Run("baseline passes", func(t *testing.T) {
		out, err := compareHistories(historyFixture(t))
		require.NoError(t, err)
		require.Equal(t, 6, out.ComparedBlocks)
		require.Equal(t, []uint64{1, 2, 3}, out.Epochs)
	})
	cases := []struct {
		name   string
		mutate func(*historyInput)
		want   error
	}{
		{"too few blocks in an archive", func(in *historyInput) {
			for h := uint64(4); h <= 6; h++ {
				delete(in.replacement, h)
				delete(in.source, h)
			}
		}, ErrTooFewBlocks},
		{"too few common blocks", func(in *historyInput) {
			// The archives are large enough but share only three heights.
			for h := uint64(1); h <= 3; h++ {
				in.replacement[h+10] = in.replacement[h]
				delete(in.replacement, h)
			}
		}, ErrTooFewBlocks},
		{"a height gap", func(in *historyInput) { delete(in.replacement, 3) }, ErrHeightGap},
		{"a missing certificate admission", func(in *historyInput) {
			delete(in.sourceAdmissions, fmt.Sprintf("%x", in.source[2].request.BlockHash))
		}, ErrMissingAdmission},
		{"a missing verified root input", func(in *historyInput) {
			delete(in.sourceRootInputs, fmt.Sprintf("%x", in.source[2].request.BlockHash))
		}, ErrMissingRootInput},
		{"a root input that differs from the archive", func(in *historyInput) {
			in.sourceRootInputs[fmt.Sprintf("%x", in.source[2].request.BlockHash)] = []byte("other")
		}, ErrRootInputMismatch},
		{"a history that is not parent-linked", func(in *historyInput) {
			in.source[4].header.ParentHash = common.Hash{9}
			in.replacement[4].header.ParentHash = common.Hash{9}
		}, ErrNotParentLinked},
		{"a source/replacement difference", func(in *historyInput) { in.replacement[2].record.Body[0] ^= 1 }, ErrBlockMismatch},
		{"a replacement log without the restore", func(in *historyInput) { in.replacementText = []byte("rootEpoch=3 handoff activated") }, ErrNoRestoreEvidence},
		{"a replacement that never admitted after the boundary", func(in *historyInput) {
			in.replacementText = []byte("msg=\"execution journal restored\" handoff activated rootEpoch=3")
		}, ErrNoPostBoundaryAdmission},
		{"a restored block absent from the compared history", func(in *historyInput) { in.replacementEpoch3 = map[string]bool{} }, ErrNoRestoredBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := historyFixture(t)
			tc.mutate(&in)
			_, err := compareHistories(in)
			require.ErrorIs(t, err, tc.want)
		})
	}
	shapes := []struct {
		name  string
		shape []blockShape
		want  error
	}{
		{"an epoch without an idle block", []blockShape{{true, 1}, {false, 1}, {true, 2}, {true, 2}, {true, 3}, {false, 3}}, ErrEpochCoverage},
		{"an epoch without a paid block", []blockShape{{true, 1}, {false, 1}, {false, 2}, {false, 2}, {true, 3}, {false, 3}}, ErrEpochCoverage},
		{"a history that never crosses epoch 1 to 2", []blockShape{{true, 1}, {false, 1}, {true, 1}, {false, 1}, {true, 3}, {false, 3}}, ErrNoEpochCrossing},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compareHistories(historyFromShape(t, tc.shape))
			require.ErrorIs(t, err, tc.want)
		})
	}
}
