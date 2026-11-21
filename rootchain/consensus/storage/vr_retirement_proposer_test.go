package storage_test

import (
	"context"
	"crypto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/rootchain/posretire"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vrschema"
)

const retirementRequestBlock = 1351

type retirementLogRPC struct {
	registry  [20]byte
	proofRoot [32]byte
	proofHash [32]byte
}

func (r retirementLogRPC) BlockNumber() hexutil.Uint64 { return 1400 }

func (r retirementLogRPC) GetBlockByNumber(tag string, full bool) map[string]common.Hash {
	if tag != "finalized" || full {
		return nil
	}
	return map[string]common.Hash{"hash": r.proofHash, "stateRoot": r.proofRoot}
}

func (r retirementLogRPC) Call(args map[string]string, block string) hexutil.Bytes {
	if args["to"] != hexutil.Encode(r.registry[:]) || args["data"] != "0xaa280583"+strings.Repeat("0", 64) || block != "latest" {
		return nil
	}
	holder := make([]byte, 128)
	copy(holder[12:32], vxHolderAt[:])
	return holder
}

func (r retirementLogRPC) GetLogs(filter struct {
	Address common.Address  `json:"address"`
	From    hexutil.Uint64  `json:"fromBlock"`
	To      hexutil.Uint64  `json:"toBlock"`
	Topics  []hexutil.Bytes `json:"topics"`
}) []map[string]any {
	// Frozen topic from testvectors/validator-registry/vr-layout.json. The deployed
	// receipt has id and generation indexed, so both are topics and data is empty.
	const topic = "0x1c365a570b27d3752591f304a03ab5f06fecb66c11b0f7e38b73050e479e8903"
	if filter.Address != vxHolderAt || filter.From > retirementRequestBlock || filter.To < retirementRequestBlock ||
		len(filter.Topics) != 1 || hexutil.Encode(filter.Topics[0]) != topic {
		return nil
	}
	id, generation := vrschema.U64(5), vrschema.U64(1)
	return []map[string]any{{
		"topics": []string{topic, hexutil.Encode(id[:]), hexutil.Encode(generation[:])},
		"data":   "0x", "blockNumber": hexutil.EncodeUint64(retirementRequestBlock), "removed": false,
	}}
}

func TestVRRetirementRediscoversHistoricalRequestAndExecutesAfterClosure(t *testing.T) {
	ctx := context.Background()
	f := newVXFixture(t)
	h := vrschema.HolderRetirement{ID: 5, Generation: 1, RefDigest: vrschema.Keccak([]byte("closed exposure"))}

	// Committee 1–4 has excluded identity 5 and the old assignment's Closure
	// is already ordered. The certified EVM state has applied the record prefix.
	state, err := rootrecords.NewState(0, 1).Commit(5, 1, 6, true, [32]byte{1})
	require.NoError(t, err)
	state, err = state.Block(1, 6)
	require.NoError(t, err)
	state, rec, err := state.Close(0, (storage.ClosureData{AssignmentID: [32]byte{1}, HRound: 5}).Encode(), 10, 1000)
	require.NoError(t, err)
	require.Equal(t, rootrecords.KindClosure, rec.Kind)
	state, ack, err := state.AckBoundary(10, 1000, f.r, [32]byte{1}, f.current.Epoch, 0)
	require.NoError(t, err)
	require.Equal(t, rootrecords.KindBoundary, ack[1].Kind)

	holderCode := vrschema.Keccak([]byte("holder code"))
	hw, err := (vrschema.Holder{Holder: vxHolderAt, CodeHash: holderCode, Module: [20]byte{1}, RegisteredEpoch: 1}).Words()
	require.NoError(t, err)
	f.state.Status.HolderCount = 1
	f.vrExtra = map[[32]byte][32]byte{}
	for i, word := range hw {
		f.vrExtra[vrschema.HolderSlot(h.Holder, uint64(i))] = word
	}
	count := vrschema.U64(state.Count)
	f.sealExtra = map[[32]byte][32]byte{vrstate.SealRecordCount: count, vrstate.SealTargetCount: count}
	words, err := (vrschema.LiabilityFacts{Requested: true, RefDigest: h.RefDigest, MaxLiabilityAnchor: 5}).Words()
	require.NoError(t, err)
	f.holder = &evmstatetest.Contract{Addr: vxHolderAt, CodeHash: holderCode, Storage: map[[32]byte][32]byte{
		vrschema.LiabilityCursorSlot():                     count,
		vrschema.LiabilityFactsSlot(h.ID, h.Generation, 0): words[0],
		vrschema.LiabilityFactsSlot(h.ID, h.Generation, 1): words[1],
	}}
	f.writeWorld()
	parent := f.genesis()
	parent.ShardState.Control.Pos = state.Bytes()
	ir := parent.ShardState.States[vxShard].IR
	ir.BlockHash, ir.PreviousHash = nil, ir.Hash
	tree, _, err := parent.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	parent.RootHash = tree.RootHash()
	evmParent := storage.EVMParent{StateRoot: f.world.Root()}
	proofBlock := [32]byte(f.parentEV)

	server := rpc.NewServer()
	require.NoError(t, server.RegisterName("eth", retirementLogRPC{registry: f.pins.Registry, proofRoot: evmParent.StateRoot, proofHash: proofBlock}))
	t.Cleanup(server.Stop)
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)
	chain := posretire.RPCChain{Client: client, Registry: f.pins.Registry}
	cfg := posretire.Config{
		Deployment: storage.PosDeployment{RootNetwork: f.dep.RootNetwork,
			Deployment: evmassign.Deployment{NetworkWord: f.dep.NetworkWord, ChainID: f.dep.ChainID, Custody: f.dep.Registry}},
		VR:    &f.pins,
		Chain: chain,
		Proofs: func(blockHash [32]byte) evmstate.ProofSource {
			if blockHash != proofBlock {
				t.Errorf("proof read at %x, want %x", blockHash, proofBlock)
			}
			return f.world
		},
		StatePath: filepath.Join(t.TempDir(), "vr-retirement-requests.json"),
	}
	discovery, err := posretire.New(cfg)
	require.NoError(t, err)
	require.NoError(t, discovery.Poll(ctx), "an upgraded root scans a request already in history")
	discovery.Flush()

	proposer, err := posretire.New(cfg)
	require.NoError(t, err)
	require.Equal(t, []storage.RetirementKey{{ID: h.ID, Generation: h.Generation}}, proposer.Pending(),
		"after restart the original indexed request is ready to be proved")
	proposer.Prepare(evmParent)
	var prepared []storage.PreparedRetirement
	require.Eventually(t, func() bool {
		prepared = proposer.Ready(evmParent, 1)
		return len(prepared) == 1
	}, time.Second, time.Millisecond)
	p := prepared[0]
	require.True(t, p.Control.Registry)
	require.Equal(t, evmParent.StateRoot, p.Control.Retire.EVMStateRoot)
	require.Zero(t, p.Control.Retire.EVMBlockHash, "the quiet certificate has a zero block hash")
	require.Equal(t, h.Encode(), p.Control.Data)
	f.witnesses[p.Control.WitnessHash] = p.Witness
	p.Control.OrderingEpoch, p.Control.OrderingRound = 1, 11

	proposal := f.block(parent, 11, 1010, nil, p.Control)
	require.NoError(t, proposal.Payload.IsValid())
	b := f.must(parent, proposal)
	require.Len(t, b.ShardState.Records, 1)
	require.Equal(t, rootrecords.KindHolderRetirement, b.ShardState.Records[0].Kind)
	require.Equal(t, h.Encode(), b.ShardState.Records[0].Data)
	ref, ok := posState(t, b).IsHolderRetired(h.Holder, h.ID, h.Generation)
	require.True(t, ok)
	require.Equal(t, h.RefDigest, ref)

	// A still-cached witness from before SealRegistry imports the record cannot
	// project another record on a child of the block that already ordered it.
	p.Control.OrderingRound++
	again := f.must(b, f.block(b, 12, 1020, nil, p.Control))
	require.Empty(t, again.ShardState.Records)
}
