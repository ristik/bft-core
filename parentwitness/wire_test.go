package parentwitness

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

func fixtureTarget(t *testing.T) (*certifiedchain.Chain, Target) {
	t.Helper()
	c := certifiedchain.New(t, 3, 2)
	pc := registryproof.Context{RegistryAddress: registryproof.RegistryAddress, RegistryCodeHash: c.Pins.RegistryCodeHash, GenesisCommitment: c.Genesis.GenesisCommitment(), FullShardConfHash: c.Genesis.FullShardConfHash(), ShardEpoch: 0, RootEpoch: 1, EVMGenesisHash: c.Blocks[0].Hash}
	target, err := NewTarget(TargetConfig{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: pc.FullShardConfHash, Registry: pc, BlockHash: c.Blocks[1].Hash})
	require.NoError(t, err)
	return c, target
}

type proofNodeList [][]byte

func (l *proofNodeList) Put(_, value []byte) error {
	*l = append(*l, common.CopyBytes(value))
	return nil
}

func (*proofNodeList) Delete([]byte) error { return nil }

func proveTrie(t *testing.T, tr *trie.Trie, path []byte) [][]byte {
	t.Helper()
	var nodes proofNodeList
	require.NoError(t, tr.Prove(path, &nodes))
	return nodes
}

func testTrie() *trie.Trie {
	return trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
}

func trieStorageValue(t *testing.T, value common.Hash) []byte {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(common.TrimLeftZeroes(value[:]))
	require.NoError(t, err)
	return encoded
}

func buildLargeStorageWitness(t *testing.T, c *certifiedchain.Chain, fillerSlots int) (Target, registryproof.Evidence) {
	t.Helper()
	storage := testTrie()
	words := c.Genesis.Storage()
	rootRound := uint64(5)
	words["clock.rootRound"] = common.BigToHash(new(big.Int).SetUint64(rootRound))
	words["origin.rootEpoch"] = common.BigToHash(big.NewInt(1))
	words["origin.timestamp"] = common.BigToHash(new(big.Int).SetUint64(1_700_000_000 + rootRound))
	words["origin.treeRoot"] = crypto.Keccak256Hash([]byte("U5"))
	words["origin.identity"] = crypto.Keccak256Hash([]byte("O5"))
	words["origin.trHash"] = crypto.Keccak256Hash([]byte("T5"))
	words["round.authorized"] = common.BigToHash(big.NewInt(1))
	words["input.commitment"] = crypto.Keccak256Hash([]byte("X1"))
	words["certified.round"] = common.Hash{}
	words["certified.stateHash"] = c.Blocks[0].StateRoot
	words["outcomes.round"] = common.BigToHash(big.NewInt(1))
	words["outcomes.commitment"] = crypto.Keccak256Hash([]byte("R1"))
	for i, name := range registryproof.SlotNames {
		value := words[name]
		if value == (common.Hash{}) {
			continue
		}
		slot := registryproof.SlotKey(i)
		require.NoError(t, storage.Update(crypto.Keccak256(slot[:]), trieStorageValue(t, value)))
	}
	// Model a real EVM storage trie: use distinct 256-bit slot keys, Keccak-hash
	// each slot into the trie path, and store a full 32-byte nonzero value in every leaf.
	for i := 1; i <= fillerSlots; i++ {
		slot := common.BigToHash(big.NewInt(int64(i)))
		value := crypto.Keccak256Hash([]byte("large-storage-slot"), slot[:])
		value[0] |= 0x80 // Keep every stored word at the full 32-byte EVM width.
		require.NoError(t, storage.Update(crypto.Keccak256(slot[:]), trieStorageValue(t, value)))
	}

	accountPath := crypto.Keccak256(registryproof.RegistryAddress[:])
	account := &ethTypes.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: storage.Hash(), CodeHash: c.Pins.RegistryCodeHash.Bytes()}
	accountRLP, err := rlp.EncodeToBytes(account)
	require.NoError(t, err)
	state := testTrie()
	require.NoError(t, state.Update(accountPath, accountRLP))
	withdrawals, beacon := ethTypes.EmptyWithdrawalsHash, common.Hash{}
	zero := uint64(0)
	header := &ethTypes.Header{
		ParentHash: c.Blocks[0].Hash, UncleHash: ethTypes.EmptyUncleHash, Root: state.Hash(), TxHash: ethTypes.EmptyTxsHash,
		ReceiptHash: ethTypes.EmptyReceiptsHash, Difficulty: new(big.Int), Number: big.NewInt(1),
		GasLimit: 30_000_000, Time: 1_700_000_001, Extra: []byte("near-cap-registry-proof"), BaseFee: big.NewInt(7),
		WithdrawalsHash: &withdrawals, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon,
	}
	headerRLP, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	ctx := registryproof.Context{
		RegistryAddress: c.Pins.RegistryAddress, RegistryCodeHash: c.Pins.RegistryCodeHash,
		GenesisCommitment: c.Genesis.GenesisCommitment(), FullShardConfHash: c.Genesis.FullShardConfHash(),
		ShardEpoch: 0, RootEpoch: c.Pins.RootEpoch, EVMGenesisHash: c.Genesis.EVMGenesisHash(),
	}
	target, err := NewTarget(TargetConfig{
		NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: ctx.FullShardConfHash,
		Registry: ctx, BlockHash: header.Hash(),
	})
	require.NoError(t, err)
	ev := registryproof.Evidence{Header: headerRLP, AccountProof: proveTrie(t, state, accountPath), StorageProofs: make([][][]byte, registryproof.FieldCount)}
	for i := range ev.StorageProofs {
		slot := registryproof.SlotKey(i)
		ev.StorageProofs[i] = proveTrie(t, storage, crypto.Keccak256(slot[:]))
	}
	return target, ev
}

func TestCryptographicallyValidLargeStorageWitness(t *testing.T) {
	const fillerSlots = 1_000_000
	chain, _ := fixtureTarget(t)
	target, evidence := buildLargeStorageWitness(t, chain, fillerSlots)
	raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: evidence})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(raw), 64<<10, "the fixture should retain a large authentic proof")
	require.LessOrEqual(t, len(raw), MaxResponseBytes)
	proofNodes, maxNodesPerStorageProof := len(evidence.AccountProof), 0
	for _, proof := range evidence.StorageProofs {
		proofNodes += len(proof)
		if len(proof) > maxNodesPerStorageProof {
			maxNodesPerStorageProof = len(proof)
		}
	}
	latencies := make([]time.Duration, 20)
	for i := range latencies {
		started := time.Now()
		verified, err := VerifyResponse(target, raw)
		latencies[i] = time.Since(started)
		require.NoError(t, err)
		require.True(t, verified.Found())
		require.Less(t, latencies[i], 5*time.Second)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("cryptographically valid large-storage witness: filler_storage_slots=%d registry_proof_paths=%d evidence_bytes=%d response_bytes=%d response_cap_bytes=%d proof_nodes=%d max_storage_nodes_per_proof=%d verify_p50=%s verify_p99=%s", fillerSlots, registryproof.FieldCount, evidenceSize(evidence), len(raw), MaxResponseBytes, proofNodes, maxNodesPerStorageProof, latencies[(len(latencies)-1)/2], latencies[len(latencies)-1])
}

func evidenceSize(e registryproof.Evidence) int {
	n := len(e.Header)
	for _, proof := range append([][][]byte{e.AccountProof}, e.StorageProofs...) {
		for _, node := range proof {
			n += len(node)
		}
	}
	return n
}

func TestVerifiedFoundAndOwnedBoundaries(t *testing.T) {
	c, target := fixtureTarget(t)
	r := Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}
	raw, err := EncodeResponse(r)
	require.NoError(t, err)
	r.Evidence.Header[0] ^= 1
	verified, err := VerifyResponse(target, raw)
	require.NoError(t, err)
	require.True(t, verified.Valid())
	require.True(t, verified.Found())
	require.Equal(t, OutcomeFound, verified.Outcome())
	require.Equal(t, c.Blocks[1].StateRoot, verified.Snapshot().StateRoot())
	e := verified.Evidence()
	e.Header[0] ^= 1
	require.NotEqual(t, e.Header, verified.Evidence().Header)
}

func TestExactEchoAndLocalVerification(t *testing.T) {
	c, target := fixtureTarget(t)
	for name, mutate := range map[string]func(*Response){
		"block":   func(r *Response) { r.Request.BlockHash[0] ^= 1 },
		"context": func(r *Response) { r.Request.Context.RootEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			r := Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}
			mutate(&r)
			raw, err := EncodeResponse(r)
			require.NoError(t, err)
			_, err = VerifyResponse(target, raw)
			require.ErrorIs(t, err, ErrContext)
		})
	}
	r := Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}
	r.Evidence.Header = bytes.Clone(r.Evidence.Header)
	r.Evidence.Header[20] ^= 1
	raw, err := EncodeResponse(r)
	require.NoError(t, err)
	_, err = VerifyResponse(target, raw)
	require.ErrorIs(t, err, registryproof.ErrHeaderHash)
}

func TestHighBitsCannotAliasLocalContext(t *testing.T) {
	_, target := fixtureTarget(t)
	for name, mutate := range map[string]func(*contextWire){
		"network":   func(c *contextWire) { c.NetworkID += 1 << 16 },
		"partition": func(c *contextWire) { c.PartitionID += 1 << 32 },
	} {
		t.Run(name+" request", func(t *testing.T) {
			w := requestWire{Version: Version, Context: contextToWire(target.request.Context), BlockHash: target.request.BlockHash.Bytes()}
			mutate(&w.Context)
			raw, err := marshalCanonical(w)
			require.NoError(t, err)
			_, err = DecodeRequest(raw)
			require.ErrorIs(t, err, ErrWire)
		})
		t.Run(name+" response", func(t *testing.T) {
			w := responseWire{Version: Version, Context: contextToWire(target.request.Context), BlockHash: target.request.BlockHash.Bytes(), Outcome: uint64(OutcomeBusy)}
			mutate(&w.Context)
			raw, err := marshalCanonical(w)
			require.NoError(t, err)
			_, err = VerifyResponse(target, raw)
			require.ErrorIs(t, err, ErrWire)
		})
	}
}

func TestOutcomesEvidenceAndCanonicalRefusals(t *testing.T) {
	_, target := fixtureTarget(t)
	for outcome := OutcomeUnavailable; outcome <= OutcomeInvalidRequest; outcome++ {
		raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: outcome, Detail: "bounded"})
		require.NoError(t, err)
		got, err := VerifyResponse(target, raw)
		require.NoError(t, err)
		require.True(t, got.Valid())
		require.False(t, got.Found())
		require.Equal(t, outcome, got.Outcome())
	}
	_, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeBusy, Evidence: registryproof.Evidence{Header: []byte{1}}})
	require.ErrorIs(t, err, ErrWire)
	raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeBusy})
	require.NoError(t, err)
	noncanonical := append([]byte{0x9f}, raw[1:]...)
	noncanonical = append(noncanonical, 0xff)
	_, err = VerifyResponse(target, noncanonical)
	require.ErrorIs(t, err, ErrWire)
}

func TestPredecodeCBORBounds(t *testing.T) {
	for name, raw := range map[string][]byte{
		"node bytes":  append([]byte{0x59, 0x04, 0x01}, make([]byte, 1025)...),
		"array count": {0x99, 0x08, 0x01},
		"indefinite":  {0x9f, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateCBORBounds(raw)
			require.Error(t, err)
		})
	}
}

func TestFramingRejectsOversizeBeforeBodyRead(t *testing.T) {
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], MaxRequestBytes+1)
	tracked := &prefixGuardReader{prefix: bytes.Clone(prefix[:n])}
	_, err := ReadRequestFrame(tracked)
	require.ErrorIs(t, err, ErrBounds)
	require.Equal(t, n, tracked.read)
	require.False(t, tracked.overread, "oversize admission never asks the underlying reader for body bytes")
}

func TestVerifyResponseChecksFrameBoundBeforeDecode(t *testing.T) {
	_, target := fixtureTarget(t)
	raw := make([]byte, MaxResponseBytes+1)
	_, err := VerifyResponse(target, raw)
	require.ErrorIs(t, err, ErrBounds)
	owned, err := cloneBoundedResponse(raw)
	require.ErrorIs(t, err, ErrBounds)
	require.Nil(t, owned, "the bound helper returns no owned allocation for oversized input")
}

func TestFramingRejectsShortWrites(t *testing.T) {
	_, target := fixtureTarget(t)
	err := WriteRequestFrame(shortWriter{}, target.Request())
	require.ErrorIs(t, err, io.ErrShortWrite)
}

func TestTargetCopiesMutableInputs(t *testing.T) {
	_, target := fixtureTarget(t)
	r := target.Request()
	r.Context.ShardID, _ = shardFromBytes([]byte{0x40})
	require.Empty(t, target.Request().Context.ShardID)
	_, err := registryproof.Verify(target.registry, target.request.BlockHash, registryproof.Evidence{})
	require.ErrorIs(t, err, registryproof.ErrUnavailable)
}

type prefixGuardReader struct {
	prefix   []byte
	read     int
	overread bool
}

func (r *prefixGuardReader) Read(p []byte) (int, error) {
	remaining := len(r.prefix) - r.read
	if remaining == 0 {
		return 0, io.EOF
	}
	if len(p) > remaining {
		r.overread = true
		return 0, errors.New("reader was asked to cross from prefix into body")
	}
	n := copy(p, r.prefix[r.read:])
	r.read += n
	return n, nil
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestWorstCaseResponseFitsFrozenCap(t *testing.T) {
	_, target := fixtureTarget(t)
	// Fill all permitted proof nodes to CBOR's 24-byte threshold, then move as
	// many as possible across its 256-byte threshold within the byte budget.
	nodes := make([][]byte, (registryproof.FieldCount+1)*65)
	remaining := MaxEvidenceBytes - 1024 - len(nodes)*24
	for i := range nodes {
		size := 24
		if remaining >= 232 {
			size = 256
			remaining -= 232
		} else if remaining > 0 {
			size += remaining
			remaining = 0
		}
		nodes[i] = bytes.Repeat([]byte{byte(i)}, size)
	}
	var nodeBytes int
	for _, n := range nodes {
		nodeBytes += len(n)
	}
	require.Equal(t, MaxEvidenceBytes-1024, nodeBytes)
	ev := registryproof.Evidence{Header: bytes.Repeat([]byte{1}, 1024), AccountProof: nodes[:65], StorageProofs: make([][][]byte, registryproof.FieldCount)}
	for i := range ev.StorageProofs {
		ev.StorageProofs[i] = nodes[65+i*65 : 65+(i+1)*65]
	}
	raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: ev})
	require.NoError(t, err)
	t.Logf("measured worst-case found response: %d bytes; frozen frame cap: %d bytes; conservative upper bound: %d bytes", len(raw), MaxResponseBytes, MaxFoundResponseBytesUpperBound)
	require.LessOrEqual(t, len(raw), MaxResponseBytes)
	require.Equal(t, 267110, len(raw), "freeze adversarial prefix distribution with fixture context")
	require.LessOrEqual(t, len(raw)+(35-2)+(202-1), MaxFoundResponseBytesUpperBound)
	require.Less(t, MaxFoundResponseBytesUpperBound, MaxResponseBytes)
}
