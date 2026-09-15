package registryproof

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

/*
testdata/anvil-registry-proof.json comes from anvil (Foundry: alloy-trie and revm), which shares no trie
code with go-ethereum. testdata/anvil-vector.sh installed the merged registry runtime code at a_sr with the
§9.4 post-state words, mined one Cancun block, and recorded that block's raw header and the eth_getProof
result for the 22 keys, requested by block hash. It is proof-format evidence. It is not evidence that a
reth node serves proofs for historical blocks.
*/

type anvilVector struct {
	Generator        string                 `json:"generator"`
	RegistryCodeHash common.Hash            `json:"registryCodeHash"`
	BlockHash        common.Hash            `json:"blockHash"`
	BlockNumber      hexutil.Uint64         `json:"blockNumber"`
	Header           hexutil.Bytes          `json:"header"`
	Words            map[string]common.Hash `json:"words"`
	Proof            json.RawMessage        `json:"proof"`
}

func loadAnvilVector(t *testing.T) anvilVector {
	raw, err := os.ReadFile("testdata/anvil-registry-proof.json")
	require.NoError(t, err)
	var v anvilVector
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func anvilContext() Context {
	return Context{
		RegistryAddress: RegistryAddress, RegistryCodeHash: registryCodeHash, GenesisCommitment: genesisCommitment,
		FullShardConfHash: fullShardConfHash, ShardEpoch: 0, RootEpoch: 1,
		EVMGenesisHash: named("the anvil vector's block is not the configured genesis"),
	}
}

func anvilEvidence(t *testing.T, v anvilVector, proof json.RawMessage) Evidence {
	var r GetProofResult
	require.NoError(t, json.Unmarshal(proof, &r))
	ev, err := EvidenceFromGetProof(v.Header, r)
	require.NoError(t, err)
	return ev
}

func TestAnvilVectorVerifies(t *testing.T) {
	v := loadAnvilVector(t)
	t.Logf("generator: %s", v.Generator)
	require.Equal(t, registryCodeHash, v.RegistryCodeHash, "the vector carries the merged registry runtime code")

	s, err := Verify(anvilContext(), v.BlockHash, anvilEvidence(t, v, v.Proof))
	require.NoError(t, err)
	require.Equal(t, uint64(v.BlockNumber), s.Fields().Number)
	require.False(t, s.Fields().Genesis)

	got := map[string]common.Hash{
		"layoutVersion": num(s.Fields().LayoutVersion), "genesisCommitment": s.Fields().GenesisCommitment, "config.shardConfHash": s.Fields().ShardConfHash,
		"assignment.epoch": num(s.Fields().ShardEpoch), "assignment.rootEpoch": num(s.Fields().RootEpoch), "clock.rootRound": num(s.Fields().ClockRootRound),
		"origin.rootEpoch": num(s.Fields().OriginRootEpoch), "origin.timestamp": num(s.Fields().OriginTimestamp), "origin.treeRoot": s.Fields().OriginTreeRoot,
		"origin.identity": s.Fields().OriginIdentity, "origin.trHash": s.Fields().OriginTRHash, "round.authorized": num(s.Fields().RoundAuthorized),
		"input.commitment": s.Fields().InputCommitment, "certified.round": num(s.Fields().CertifiedRound), "certified.stateHash": s.Fields().CertifiedStateHash,
		"certified.hasBlockHash": num(map[bool]uint64{false: 0, true: 1}[s.Fields().HasBlockHash]), "certified.blockHash": s.Fields().CertifiedBlockHash,
		"phase": num(s.Fields().Phase), "outcomes.round": num(s.Fields().OutcomesRound), "outcomes.commitment": s.Fields().OutcomesCommitment,
		"transition.cursor": num(s.Fields().TransitionCursor), "inbox.consumed": num(s.Fields().InboxConsumed),
	}
	for _, name := range SlotNames {
		require.Equal(t, v.Words[name], got[name], name)
	}
	require.Equal(t, uint64(9), s.LastAppliedRootRound())
	require.Equal(t, named("B2"), s.Fields().CertifiedBlockHash)
}

// The response's summary fields are rewritten to claim different values. Decoding drops them and the
// nodes decide, so the result is unchanged.
func TestAnvilVectorSummaryFieldsChangeNothing(t *testing.T) {
	v := loadAnvilVector(t)
	want, err := Verify(anvilContext(), v.BlockHash, anvilEvidence(t, v, v.Proof))
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(v.Proof, &m))
	m["balance"] = "0x1"
	m["nonce"] = "0x7"
	m["codeHash"] = common.Hash{}.Hex()
	m["storageHash"] = named("another storage root").Hex()
	for _, sp := range m["storageProof"].([]any) {
		sp.(map[string]any)["value"] = "0x63"
	}
	lying, err := json.Marshal(m)
	require.NoError(t, err)

	got, err := Verify(anvilContext(), v.BlockHash, anvilEvidence(t, v, lying))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestAnvilVectorOneElementChanges(t *testing.T) {
	v := loadAnvilVector(t)
	base := anvilEvidence(t, v, v.Proof)
	for name, tc := range map[string]struct {
		change func(e *Evidence)
		want   error
	}{
		"header byte":             {func(e *Evidence) { e.Header[20] ^= 1 }, ErrHeaderHash},
		"account proof root":      {func(e *Evidence) { e.AccountProof[0][5] ^= 1 }, ErrAccountProof},
		"account proof leaf":      {func(e *Evidence) { l := e.AccountProof[len(e.AccountProof)-1]; l[len(l)-1] ^= 1 }, ErrAccountProof},
		"account proof truncated": {func(e *Evidence) { e.AccountProof = e.AccountProof[:len(e.AccountProof)-1] }, ErrAccountProof},
		"storage proof leaf": {func(e *Evidence) {
			p := e.StorageProofs[fOutcomesCommitment]
			l := p[len(p)-1]
			l[len(l)-1] ^= 1
		}, ErrStorageProof},
		"storage proof truncated": {func(e *Evidence) {
			p := e.StorageProofs[fPhase]
			e.StorageProofs[fPhase] = p[:len(p)-1]
		}, ErrStorageProof},
	} {
		t.Run(name, func(t *testing.T) {
			e := cloneEvidence(base)
			tc.change(&e)
			_, err := Verify(anvilContext(), v.BlockHash, e)
			require.ErrorIs(t, err, tc.want)
		})
	}
}
