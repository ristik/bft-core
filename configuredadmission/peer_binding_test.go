package configuredadmission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

type realBindingExecutor struct {
	*replayExecutor
	binder *engineapi.Adapter
}

func (e *realBindingExecutor) CheckBlockBinding(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) error {
	return e.binder.CheckBlockBinding(ctx, b, p)
}

func TestPeerEntryWithLinkedParentButForgedRawHashUsesRealBinding(t *testing.T) {
	chain, origin, journalCtx, _ := adapterFixture(t)
	bootstrap, bootTR := journalBootstrap(t, chain)
	resulting, resultingTR := signAdapterObservation(t, chain)
	snapshot, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	require.NoError(t, err)
	observed, err := rootinput.AuthenticateObservationV2(context.Background(), journalCtx.Observation, bootstrap, bootTR)
	require.NoError(t, err)
	derived, err := rootinput.DeriveV2(rootinput.ContextV2{Genesis: origin, Parent: snapshot, Round: 1, ParentHash: origin.BlockHash().Bytes()}, observed)
	require.NoError(t, err)
	verifier := &engineapi.VerifierContext{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: journalCtx.Observation.TrustBases, GenesisOrigin: origin, BootstrapSnapshot: snapshot}
	eth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"number": "0x0", "hash": fmt.Sprintf("0x%x", origin.BlockHash().Bytes()), "parentHash": fmt.Sprintf("0x%064x", 0), "stateRoot": fmt.Sprintf("0x%x", origin.StateRoot().Bytes()), "timestamp": "0x0"}})
	}))
	defer eth.Close()
	binder := engineapi.NewAdapter(engineapi.Config{EthURL: eth.URL, Verifier: verifier}, nil)
	attrs := engineapi.DeriveAttributesV2(derived.Input, engineapi.ParentHeader{}, [20]byte{})
	b1 := chain.Blocks[1]
	payload := engineapi.ExecutionPayloadV3{ParentHash: [32]byte(common.BytesToHash(origin.BlockHash().Bytes())), StateRoot: [32]byte(common.BytesToHash(b1.StateRoot.Bytes())), BlockHash: [32]byte(common.BytesToHash(b1.Hash.Bytes())), Timestamp: attrs.Timestamp, PrevRandao: attrs.PrevRandao, FeeRecipient: attrs.SuggestedFeeRecipient, BlockNumber: 1, GasLimit: 30_000_000, BaseFeePerGas: 1_000_000_000, ExtraData: derived.Commitment[:], LogsBloom: make([]byte, 256)}
	ub, err := types.Cbor.Marshal(bootstrap)
	require.NoError(t, err)
	tb, err := types.Cbor.Marshal(bootTR)
	require.NoError(t, err)
	var companion engineapi.SealCompanion
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"rootInput":"0x%x","witnesses":["0x%x","0x%x"],"provenance":"build"}`, derived.Encoded, ub, tb)), &companion))
	block, err := engineapi.EncodeBlockWithSealCompanion(payload, &companion)
	require.NoError(t, err)
	genesis := shardnode.BlockRef{Number: 0, Hash: origin.BlockHash().Bytes(), StateRoot: origin.StateRoot().Bytes()}
	require.Equal(t, genesis.Hash, block.ParentHash, "the malicious peer's parent link is correct")
	limits := configuredprogress.JournalLimits{Candidates: 4, Observations: 4, Bytes: 16 << 20}
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 4})
	require.NoError(t, err)
	defer store.Close()
	_, _, err = store.Initialize(context.Background(), journalCtx)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(context.Background(), journalCtx, limits))
	exec := &realBindingExecutor{replayExecutor: &replayExecutor{head: genesis, finalized: genesis, refs: []shardnode.BlockRef{genesis}, known: map[string]bool{string(genesis.Hash): true}}, binder: binder}
	recovery := &ExecutionRecovery{Store: store, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Genesis: genesis, Limits: RecoveryLimits{Blocks: 4, Bytes: 1 << 20, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"malicious"}}
	recovery.fetch = func(context.Context, peer.ID, shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		return []shardnode.JournalFetchEntry{{Block: block, ParentState: genesis.StateRoot, Round: 1, AuthorizingUC: bootstrap, AuthorizingTR: bootTR, ResultingUC: resulting, ResultingTR: resultingTR}}, nil
	}
	err = recovery.fetchFromPeers(context.Background(), genesis, block.Hash, false, nil)
	require.ErrorIs(t, err, ErrRecoveryUnavailable, "a Byzantine peer is unavailable, not a terminal local conflict")
	require.ErrorContains(t, err, "computed header hash")
	require.False(t, recovery.Terminal(err))
	image, err := store.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	require.Empty(t, image.Candidates, "raw-hash mismatch is rejected before durable admission")
}
