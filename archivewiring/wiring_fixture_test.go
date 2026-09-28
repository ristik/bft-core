package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type fixtureTrust struct{ base *types.RootTrustBaseV1 }

func (f fixtureTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return f.base, nil
}

type wiringFixture struct {
	store   *configuredprogress.Store
	path    string
	context configuredprogress.Context
	limits  configuredprogress.JournalLimits
	subject archive.Context
	entries []configuredprogress.JournalEntry
	chain   *certifiedchain.Chain
}

func signWiring(t *testing.T, chain *certifiedchain.Chain, ir *types.InputRecord, assigned, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := certifiedchain.Technical(assigned - 1)
	uc := chain.Certify(chain.Signer, ir, tr, rootRound)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := chain.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), chain.Signer))
	return uc, tr
}

func wiringBlock(t *testing.T, parentHash, state [32]byte, number, rootRound uint64, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (hash [32]byte, raw []byte, size uint64) {
	t.Helper()
	rootInput := []byte{byte(number)}
	commitment := sha256.Sum256(rootInput)
	ucBytes, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)
	trBytes, err := types.Cbor.Marshal(tr)
	require.NoError(t, err)
	var companion engineapi.SealCompanion
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"rootInput":"0x%x","witnesses":["0x%x","0x%x"],"provenance":"build"}`, rootInput, ucBytes, trBytes)), &companion))
	beacon := common.Hash(evmroot.DeriveBeaconRoot(rootRound, number))
	withdrawals := gethtypes.DeriveSha(gethtypes.Withdrawals{}, trie.NewStackTrie(nil))
	zero := uint64(0)
	header := &gethtypes.Header{
		ParentHash: common.Hash(parentHash), UncleHash: gethtypes.EmptyUncleHash,
		Root: common.Hash(state), TxHash: gethtypes.DeriveSha(gethtypes.Transactions{}, trie.NewStackTrie(nil)),
		ReceiptHash: gethtypes.EmptyReceiptsHash, Bloom: gethtypes.Bloom{}, Difficulty: new(big.Int),
		Number: new(big.Int).SetUint64(number), GasLimit: 30_000_000, GasUsed: 0,
		Time: 1_700_000_000 + number, Extra: commitment[:], BaseFee: big.NewInt(1_000_000),
		WithdrawalsHash: &withdrawals, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon,
	}
	hash = [32]byte(header.Hash())
	payload := engineapi.ExecutionPayloadV3{
		ParentHash: parentHash, StateRoot: state, ReceiptsRoot: [32]byte(gethtypes.EmptyReceiptsHash),
		LogsBloom: make([]byte, 256), GasLimit: 30_000_000,
		ExtraData: commitment[:], BaseFeePerGas: 1_000_000,
		BlockHash: hash, Transactions: nil, Withdrawals: nil,
	}
	reflect.ValueOf(&payload).Elem().FieldByName("BlockNumber").SetUint(number)
	reflect.ValueOf(&payload).Elem().FieldByName("Timestamp").SetUint(1_700_000_000 + number)
	block, err := engineapi.EncodeBlockWithSealCompanion(payload, &companion)
	require.NoError(t, err)
	return hash, block.Raw, block.BlockSize
}

func newWiringFixture(t *testing.T, blocks int) *wiringFixture {
	return newWiringFixtureWithLimits(t, blocks, configuredprogress.JournalLimits{Candidates: 16, Observations: 32, Bytes: 32 << 20})
}

func newWiringFixtureWithLimits(t *testing.T, blocks int, limits configuredprogress.JournalLimits) *wiringFixture {
	return newWiringFixtureMode(t, blocks, limits, false)
}

func newWiringFixtureWithTimeouts(t *testing.T, blocks int) *wiringFixture {
	return newWiringFixtureMode(t, blocks, configuredprogress.JournalLimits{Candidates: 16, Observations: 32, Bytes: 32 << 20}, true)
}

func newWiringFixtureMode(t *testing.T, blocks int, limits configuredprogress.JournalLimits, timeouts bool) *wiringFixture {
	t.Helper()
	chain := certifiedchain.New(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(chain.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, _ := json.Marshal(doc)
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), chain.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	trust := fixtureTrust{chain.TrustBase}
	identity := []byte("checked execution identity")
	c := configuredprogress.Context{
		Origin: origin, ExecutionConfigV2: sha256.Sum256(identity),
		Observation: rootinput.ObservationContextV2{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: trust},
		Record:      certifiedstore.Context{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: origin.FullShardConfHash().Bytes(), Registry: origin.ProofContext(), TrustBases: trust},
	}
	path := t.TempDir() + "/journal.db"
	store, err := configuredprogress.OpenConfiguredV2(path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(context.Background(), c)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(context.Background(), c, limits))
	admit := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) {
		o, err := rootinput.AuthenticateObservationV2(context.Background(), c.Observation, uc, tr)
		require.NoError(t, err)
		p, _, err := store.PrepareObservation(context.Background(), c, o)
		require.NoError(t, err)
		_, _, err = store.CommitObservation(p)
		require.NoError(t, err)
	}
	parentUC, parentTR := signWiring(t, chain, &types.InputRecord{Version: 1}, 1, 4)
	admit(parentUC, parentTR)
	parentHash := [32]byte(chain.Blocks[0].Hash)
	parentState := [32]byte(chain.Blocks[0].StateRoot)
	for number := 1; number <= blocks; number++ {
		var state [32]byte
		state[0], state[31] = byte(number), byte(number+17)
		hash, raw, size := wiringBlock(t, parentHash, state, uint64(number), parentUC.GetRootRoundNumber(), parentUC, parentTR)
		candidate := configuredprogress.JournalCandidate{Round: uint64(number), Number: uint64(number), ParentNumber: uint64(number - 1),
			Hash: hash[:], StateRoot: state[:], ParentHash: parentHash[:], ParentState: parentState[:], Raw: raw,
			BlockSize: size, AuthorizingUC: parentUC, AuthorizingTR: parentTR}
		require.NoError(t, store.PutJournalCandidate(context.Background(), c, limits, candidate), "candidate %d", number)
		ir := &types.InputRecord{Version: 1, RoundNumber: uint64(number), Hash: state[:], BlockHash: hash[:], SummaryValue: []byte{}, Timestamp: 1_700_000_000 + uint64(number)}
		if number > 1 {
			ir.PreviousHash = bytes.Clone(parentState[:])
		}
		rootRound := uint64(4 + number)
		if timeouts {
			rootRound += uint64(number - 1)
		}
		resultUC, resultTR := signWiring(t, chain, ir, uint64(number+1), rootRound)
		admit(resultUC, resultTR)
		parentUC, parentTR = resultUC, resultTR
		if timeouts {
			// A timeout can repeat the same certified input record at the next
			// root round before the next block is certified.
			parentUC, parentTR = signWiring(t, chain, ir, uint64(number+1), rootRound+1)
			admit(parentUC, parentTR)
		}
		parentHash, parentState = hash, state
	}
	subject, err := ContextFrom(c, identity)
	require.NoError(t, err)
	image, err := store.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	return &wiringFixture{store: store, path: path, context: c, limits: limits, subject: subject, entries: image.Candidates, chain: chain}
}

func (f *wiringFixture) record(t *testing.T, index int) (archive.Request, *archive.Record) {
	t.Helper()
	q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, f.entries[index])
	require.NoError(t, err)
	return q, rec
}

func TestWiringFixtureBuildsCertifiedArchiveRecord(t *testing.T) {
	f := newWiringFixture(t, 6)
	_, _ = f.record(t, 0)
	_, _ = f.record(t, 5)
}
