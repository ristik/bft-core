package evmassign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/h3-vectors.json")

// vectorFile is the cross-language vector set: the byte-level preimages and digests the Go, Rust and
// Solidity halves of H3 must agree on, with fixed keys so signatures (RFC 6979) are reproducible.
type vectorFile struct {
	Description string            `json:"description"`
	Keys        map[string]string `json:"privateKeys"`
	Context     map[string]any    `json:"popContext"`
	Hashes      map[string]string `json:"hashes"`
	Messages    map[string]string `json:"messages"`
	PoPs        map[string]string `json:"popSignatures"`
	Candidate   string            `json:"candidate"`
	Chain       map[string]string `json:"chainCommit"`
	Mutations   []vectorMutation  `json:"negativeMutations"`
}

type vectorMutation struct {
	Name     string `json:"name"`
	Mutates  string `json:"mutates"`
	Refusal  string `json:"refusal"`
	Checkpt  string `json:"firstCheck"`
	Independ string `json:"isolation"`
}

func fixedKey(t *testing.T, seed byte) (abcrypto.Signer, *types.NodeInfo, string) {
	t.Helper()
	key := bytes.Repeat([]byte{seed}, 32)
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(key)
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return s, &types.NodeInfo{NodeID: "validator-" + string(rune('a'+seed-1)), SigKey: pub, Stake: 1}, hex.EncodeToString(key)
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	genesis := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1,
		PartitionParams: map[string]string{"chain_id": "1337", "seal_registry_genesis": "7b8d3c4a1f2e5d6c9b0a8f7e6d5c4b3a291807f6e5d4c3b2a19087f6e5d4c3b2"}}
	signers := map[string]abcrypto.Signer{}
	var infos []*types.NodeInfo
	out := vectorFile{Description: "H3 EVM assignment vectors (bft-core evmassign); regenerate with go test ./evmassign -run TestVectors -update-vectors",
		Keys: map[string]string{}, PoPs: map[string]string{}, Hashes: map[string]string{}, Messages: map[string]string{}, Chain: map[string]string{}}
	for seed := byte(1); seed <= 3; seed++ {
		s, info, key := fixedKey(t, seed)
		signers[info.NodeID] = s
		infos = append(infos, info)
		out.Keys[info.NodeID] = key
	}
	old := *genesis
	old.Validators = []*types.NodeInfo{infos[0]}
	succ, err := NewSuccessor(&old, infos)
	require.NoError(t, err)
	ctx := PoPContext{Network: 5, Attempt: 1, Predecessor: [32]byte(bytes.Repeat([]byte{0x11}, 32)), Parent: [32]byte(bytes.Repeat([]byte{0x22}, 32))}
	out.Context = map[string]any{"network": ctx.Network, "attempt": ctx.Attempt, "predecessor": hex.EncodeToString(ctx.Predecessor[:]), "parent": hex.EncodeToString(ctx.Parent[:])}

	cfg, err := ConfigHash(succ)
	require.NoError(t, err)
	ah, err := AssignmentHash(succ)
	require.NoError(t, err)
	oldHash, err := PDRHash(&old)
	require.NoError(t, err)
	activated, err := Activate(succ, 40)
	require.NoError(t, err)
	activeHash, err := PDRHash(activated)
	require.NoError(t, err)
	out.Hashes["configHash"] = hex.EncodeToString(cfg[:])
	out.Hashes["assignmentHash"] = hex.EncodeToString(ah[:])
	out.Hashes["installedPDRHash"] = hex.EncodeToString(oldHash[:])
	out.Hashes["activatedPDRHash"] = hex.EncodeToString(activeHash[:])

	var pops []PoP
	for _, v := range succ.Validators {
		msg, err := PoPMessage(ctx, succ, v.NodeID)
		require.NoError(t, err)
		out.Messages[v.NodeID] = hex.EncodeToString(msg)
		p, err := SignPoP(signers[v.NodeID], ctx, succ, v.NodeID)
		require.NoError(t, err)
		out.PoPs[v.NodeID] = hex.EncodeToString(p.Signature)
		pops = append(pops, p)
	}
	root := []RootMember{{NodeID: "root-a", Key: bytes.Repeat([]byte{2}, 33), Weight: 1}, {NodeID: "root-b", Key: bytes.Repeat([]byte{3}, 33), Weight: 1}, {NodeID: "root-c", Key: bytes.Repeat([]byte{4}, 33), Weight: 1}}
	c, err := NewCandidate(ctx, root, &old, succ, pops, nil, bindingsFor(root, succ))
	require.NoError(t, err)
	raw, err := c.Encode()
	require.NoError(t, err)
	digest, err := c.Digest()
	require.NoError(t, err)
	out.Candidate = hex.EncodeToString(raw)
	out.Hashes["candidateDigest"] = hex.EncodeToString(digest[:])

	steps := [][]byte{bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xa2}, 32)}
	for name, n := range map[string]int{"oneStep": 1, "twoSteps": 2} {
		commit, err := ChainCommit(1, 0, oldHash[:], steps[:n])
		require.NoError(t, err)
		out.Chain[name] = hex.EncodeToString(commit[:])
	}
	out.Mutations = []vectorMutation{
		{"network", "assignment hash input network", "ErrContext (candidate) / PoP verification failure", "VerifyBinding network", "re-signed PoPs; one field changed"},
		{"predecessor", "PoP context predecessor", "ErrPoP", "VerifyPoPs", "assignment unchanged"},
		{"attempt", "PoP context attempt (replay)", "ErrPoP", "VerifyPoPs", "assignment unchanged"},
		{"parent", "PoP context frozen parent", "ErrPoP", "VerifyPoPs", "assignment unchanged"},
		{"key", "one validator key", "ErrPoP (message and key bound)", "VerifyPoPs", "other validators' proofs valid"},
		{"weight", "a validator stake != 1", "ErrAssignment", "ValidateAssignment/IsValid", "otherwise valid"},
		{"config", "any non-membership PDR field", "ErrConfig", "ValidateSuccessor", "PoPs re-signed over the changed assignment"},
		{"epoch", "successor epoch != installed+1", "ErrEpoch", "ValidateSuccessor", "PoPs re-signed"},
		{"popMissing", "one proof removed", "ErrPoP", "VerifyPoPs", "assignment valid"},
		{"popRecovery", "recovery byte flipped", "ErrPoP", "VerifyPoPs", "signature otherwise valid"},
		{"rootMembers", "successor root members differ from the body", "ErrContext", "VerifyBinding", "assignment valid"},
		{"coupling", "a root member without its delegated EVM key (or a shared key, a weight mismatch)", "ErrCoupling", "VerifyBinding", "assignment valid"},
		{"evmOnly", "EVM validators changed with the root committee unchanged", "ErrEVMOnly", "VerifyInstalled", "assignment valid"},
		{"installedEpoch", "OldShardEpoch != installed", "ErrContext", "VerifyInstalled", "assignment valid"},
		{"installedHash", "OldActiveHash != installed full hash", "ErrContext", "VerifyInstalled", "assignment valid"},
	}
	return out
}

func TestVectors(t *testing.T) {
	got := buildVectors(t)
	encoded, err := json.MarshalIndent(got, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')
	const path = "testdata/h3-vectors.json"
	if *updateVectors {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, encoded, 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run with -update-vectors to create the vector file")
	require.Equal(t, string(want), string(encoded), "the vectors are reproducible; a change is a protocol change")

	// The vector candidate decodes and verifies from its own bytes.
	raw, err := hex.DecodeString(got.Candidate)
	require.NoError(t, err)
	decoded, err := DecodeCandidate(raw)
	require.NoError(t, err)
	require.Len(t, decoded.PoPs, 3)
}
