package evmassign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"sort"
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
	// Lifecycle holds the signed primary/recovery fixtures of #85: the accepted controls and the isolated refusals, each a full
	// candidate encoding and the sentinel its verification must name. The deployment context is fixed by the Context block.
	Lifecycle []vectorLifecycle `json:"lifecycle"`
}

type vectorLifecycle struct {
	Name      string `json:"name"`
	Candidate string `json:"candidate"`
	Check     string `json:"check"`  // the verification that refuses it
	Expect    string `json:"expect"` // "ok" or the sentinel name
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
	root := []RootMember{{NodeID: "root-a", Key: bytes.Repeat([]byte{2}, 33), Weight: 1}, {NodeID: "root-b", Key: bytes.Repeat([]byte{3}, 33), Weight: 1}, {NodeID: "root-c", Key: bytes.Repeat([]byte{4}, 33), Weight: 1}}
	bindings := bindingsFor(root, succ)
	ids := identitiesFor(root, succ, bindings, "")
	idDigest, err := IdentitiesDigest(ids)
	require.NoError(t, err)
	ctx := PoPContext{Network: 5, Attempt: 1, Predecessor: [32]byte(bytes.Repeat([]byte{0x11}, 32)), Identities: idDigest}
	out.Context = map[string]any{"network": ctx.Network, "attempt": ctx.Attempt, "predecessor": hex.EncodeToString(ctx.Predecessor[:]), "identities": hex.EncodeToString(ctx.Identities[:])}

	cfg, err := ConfigHash(succ)
	require.NoError(t, err)
	ah, err := AssignmentHash(succ, ctx.Identities)
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
	incumbentRoot := []RootMember{{NodeID: "old-a", Key: bytes.Repeat([]byte{7}, 33), Weight: 1}}
	incumbent := identitiesFor(incumbentRoot, &old, bindingsFor(incumbentRoot, &old), "")
	baseHash, err := AssignmentHash(&old, mustDigest(t, incumbent))
	require.NoError(t, err)
	auth := authFor(5, bytes.Repeat([]byte{0x10}, 32), baseHash, incumbent)
	out.Hashes["identitiesDigest"] = hex.EncodeToString(idDigest[:])
	authDigest, err := auth.Digest()
	require.NoError(t, err)
	out.Hashes["authorizationDigest"] = hex.EncodeToString(authDigest[:])
	c, err := NewCandidate(ctx, root, &old, succ, pops, nil, bindings, Lifecycle{Kind: KindPrimary, Identities: ids, Authorization: auth}, nil)
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
	out.Lifecycle = lifecycleVectors(t)
	return out
}

// lifecycleVectors builds the fixed-key #85 fixtures: a primary J that replaces one of four incumbents, its derived recovery K, and
// the single-field refusals around them.
func lifecycleVectors(t *testing.T) []vectorLifecycle {
	t.Helper()
	w := newLifecycleWorldWith(t, fixedKeyed(0x41))
	var out []vectorLifecycle
	add := func(name, check string, c Candidate, want error) {
		raw, err := c.Encode()
		require.NoError(t, err, name)
		var got error
		switch check {
		case "VerifyBinding":
			_, _, got = VerifyBinding(raw, w.binding(c))
		case "VerifyAuthorization":
			got = VerifyAuthorization(c)
		default:
			t.Fatal(check)
		}
		expect := "ok"
		if want != nil {
			require.ErrorIs(t, got, want, name)
			expect = want.Error()
		} else {
			require.NoError(t, got, name)
		}
		out = append(out, vectorLifecycle{Name: name, Candidate: hex.EncodeToString(raw), Check: check, Expect: expect})
	}
	rc, _ := w.recovery(t)
	add("primary-accepted", "VerifyBinding", w.j, nil)
	add("recovery-accepted-without-fresh-proofs", "VerifyBinding", rc, nil)
	swapped := w.j
	swapped.Identities = cloneIdentities(w.j.Identities)
	swapped.Identities[2].OperatorPayee = bytes.Repeat([]byte{0xEE}, PayeeLen)
	add("primary-payee-swapped-after-signing", "VerifyBinding", swapped, ErrPoP)
	short := w.j
	short.PoPs = w.j.PoPs[:3]
	add("primary-missing-a-fresh-proof", "VerifyBinding", short, ErrPoP)
	for name, mutate := range map[string]func(*Identity){
		"recovery-changed-payee":    func(i *Identity) { i.OperatorPayee = bytes.Repeat([]byte{0xAB}, PayeeLen) },
		"recovery-changed-exposure": func(i *Identity) { i.ExposureDigest = bytes.Repeat([]byte{0xAB}, DigestLen) },
		"recovery-changed-weight":   func(i *Identity) { i.Weight = 2 },
		"recovery-changed-root-key": func(i *Identity) { i.RootKey = bytes.Repeat([]byte{0xAB}, 33) },
		"recovery-changed-evm-key":  func(i *Identity) { i.EVMKey = bytes.Repeat([]byte{0xAB}, 33) },
	} {
		c := rc
		c.Identities = cloneIdentities(rc.Identities)
		mutate(&c.Identities[0])
		add(name, "VerifyAuthorization", c, ErrNotIncumbent)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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
