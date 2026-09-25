//go:build ignore

// Independent D4 vector generator. It imports only the Go standard library
// and duplicates the pinned CBOR, IMT and Ed25519 preimages deliberately.
// Run: go run ./evmroot/testdata/generate_d4_vectors.go
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
)

type arr []any
type tag struct {
	number uint64
	value  any
}

func head(major byte, n uint64) []byte {
	p := major << 5
	switch {
	case n < 24:
		return []byte{p | byte(n)}
	case n < 256:
		return []byte{p | 24, byte(n)}
	case n < 65536:
		return []byte{p | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		return []byte{p | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{p | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}
func cbor(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte{0xf6}
	case tag:
		return append(head(6, x.number), cbor(x.value)...)
	case uint64:
		return head(0, x)
	case int:
		return head(0, uint64(x))
	case string:
		return append(head(3, uint64(len(x))), []byte(x)...)
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case arr:
		out := head(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, cbor(e)...)
		}
		return out
	default:
		panic("unsupported CBOR type")
	}
}
func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func h(parts ...any) []byte {
	b := []byte{}
	for _, p := range parts {
		b = append(b, cbor(p)...)
	}
	return sum(b)
}
func hx(b []byte) string { return hex.EncodeToString(b) }
func repeated(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}
func key(n uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, n); return b }
func main() {
	pred := repeated(0x11)
	members := arr{}
	for _, x := range []struct {
		id     string
		weight int
	}{{"root-a", 10}, {"root-b", 6}, {"root-c", 5}, {"root-d", 2}, {"root-e", 1}} {
		k := append([]byte{2}, sum([]byte("d3key:"+x.id))...)
		members = append(members, arr{"stake-" + x.id, x.id, k, x.weight})
	}
	prefreeze := sum(cbor(arr{"UNICITY_HANDOFF_PREFREEZE_STATE", 1, 3, pred, 1, 9, repeated(0x88), repeated(0x99)}))
	candidate := sum(cbor(arr{"UNICITY_HANDOFF_CANDIDATE_CONTEXT", 1, 3, pred, 1, repeated(0xaa), 12}))
	body := cbor(arr{2, 3, 8, 12, members, 17, prefreeze, candidate, pred})
	bodyID := sum(body)
	frozen := repeated(0x44)
	tr := repeated(0x55)
	record := cbor(arr{"UNICITY_ORDERED_HANDOFF_RECORD", 1, 3, 7, pred, 1, "commit", 10, arr{frozen, bodyID, 13, tr}})
	recordID := sum(record)
	control := cbor(arr{"UNICITY_ROOT_HANDOFF_STATE", 1, 3, 7, pred, 1, "committed", 10, record, repeated(0x66)})
	digest := sum(control)
	shard := sum(cbor(arr{"UNICITY_D4_SHARD_CHECKPOINT", 1, 1, []byte("IR-H"), []byte("TR-H"), []byte("old-last-cr"), []byte("cfg-next"), []byte("fees")}))
	shard2 := sum(cbor(arr{"UNICITY_D4_SHARD_CHECKPOINT", 1, 2, []byte("IR-2"), []byte("TR-2"), []byte("last-2"), []byte{}, []byte{}}))
	shard3 := sum(cbor(arr{"UNICITY_D4_SHARD_CHECKPOINT", 1, 3, []byte("IR-3"), []byte("TR-3"), []byte("last-3"), []byte{}, []byte{}}))
	// UnicityTreeData.AddToHasher writes the root bytes as CBOR. IMT then
	// writes CBOR(byte{tag}), CBOR(key), CBOR(dataHash) for each leaf.
	shardLeaf := h([]byte{1}, key(1), h(shard))
	shard2Leaf := h([]byte{1}, key(2), h(shard2))
	shard3Leaf := h([]byte{1}, key(3), h(shard3))
	controlLeaf := h([]byte{1}, key(0xffffffff), h(digest))
	leftNode := h([]byte{0}, key(1), shardLeaf, shard2Leaf)
	rightNode := h([]byte{0}, key(3), shard3Leaf, controlLeaf)
	root := h([]byte{0}, key(2), leftNode, rightNode)
	vote := cbor(tag{39007, arr{1, 11, 7, 1700000000, 10, root}})
	voteHash := sum(vote)
	ledger := cbor(tag{39005, arr{1, 3, 10, 7, 1699999999, voteHash, root, nil}})
	seal := ledger
	sigs := map[string]string{}
	pubs := map[string]string{}
	for _, id := range []string{"a", "b", "c"} {
		seed := sum([]byte("d4-model/7/" + id))
		priv := ed25519.NewKeyFromSeed(seed)
		sigs[id] = hx(ed25519.Sign(priv, seal))
		pubs[id] = hx(priv.Public().(ed25519.PublicKey))
	}
	genesis := cbor(arr{"UNICITY_EPOCH_GENESIS", 1, 3, 8, bodyID, 13, recordID, 10, root, digest, frozen, tr})
	names := []string{"suffix_payload_refused", "suffix_payload_no_qc", "leader_c_plus_2_crash", "deterministic_genesis", "new_bootstrap_timeout", "consumer_epoch_and_round", "proof_negatives", "pause_measurement", "minted_late_suffix_uc", "different_c_fixed_start", "next_epoch_carry_over", "payload_bearing_recovered_suffix", "missing_forged_control", "anchor_commit_refused", "mixed_historical_lastcr"}
	sort.Strings(names)
	v := map[string]any{"version": 2, "trace_coverage": names, "crypto": map[string]any{"profile": 2, "scope": "model-crypto-only (Ed25519); runtime secp256k1 vectors are separate", "control_partition": "ffffffff", "record_cbor": hx(record), "record_id": hx(recordID), "control_cbor": hx(control), "control_digest": hx(digest), "shard_root": hx(shard), "root": hx(root), "path": []map[string]string{{"key": "00000003", "hash": hx(shard3Leaf)}, {"key": "00000002", "hash": hx(leftNode)}}, "vote_info_cbor": hx(vote), "vote_info_hash": hx(voteHash), "ledger_commit_info_cbor": hx(ledger), "seal_cbor": hx(seal), "signatures": sigs, "public_keys": pubs, "genesis_cbor": hx(genesis), "genesis_id": hx(sum(genesis)), "pre_freeze_summary": hx(prefreeze), "candidate_context_hash": hx(candidate)}}
	out, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		panic(e)
	}
	out = append(out, '\n')
	if e = os.WriteFile("evmroot/testdata/d4-vectors.json", out, 0644); e != nil {
		panic(e)
	}
}
