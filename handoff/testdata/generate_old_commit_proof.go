//go:build ignore

// Run with go run ./handoff/testdata/generate_old_commit_proof.go.
// This fixture generator deliberately uses neither evmroot nor rootchain code.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

func enc(v any) []byte {
	m, e := cbor.CoreDetEncOptions().EncMode()
	if e != nil {
		panic(e)
	}
	b, e := m.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func hx(b []byte) string  { return hex.EncodeToString(b) }
func record(kind string, round uint64, frozen, body, tr []byte) []byte {
	return enc([]any{"UNICITY_ORDERED_HANDOFF_RECORD", uint64(1), uint64(5), uint64(1), make([]byte, 32), uint64(0), kind, round, []any{frozen, body, uint64(7), tr}})
}
func control(phase string, round uint64, record, prev []byte) []byte {
	if record == nil {
		record = []byte{}
	}
	if prev == nil {
		prev = []byte{}
	}
	return enc([]any{"UNICITY_ROOT_HANDOFF_STATE", uint64(1), uint64(5), uint64(1), make([]byte, 32), uint64(0), phase, round, record, prev})
}
func main() {
	zero := make([]byte, 32)
	frozen := make([]byte, 32)
	body := make([]byte, 32)
	tr := make([]byte, 32)
	for i := range frozen {
		frozen[i] = 2
		body[i] = 3
		tr[i] = 4
	}
	// The genesis control state also carries the root's P85 source state (epoch 1, ordinary rounds from round 2, nothing pending, empty
	// log), after the empty frozen-parent slot. Encoded here from the specification, not with rootrecords.
	source := enc([]any{"UNICITY_P85_ROOT_SOURCE_STATE", uint64(1), uint64(1), uint64(0), uint64(2), false, uint64(0), uint64(0), uint64(0), uint64(0),
		[]any{}, uint64(0), make([]byte, 32), uint64(0), uint64(0)})
	idle := enc([]any{"UNICITY_ROOT_HANDOFF_STATE", uint64(1), uint64(5), uint64(1), make([]byte, 32), uint64(0), "idle", uint64(0), []byte{}, []byte{}, []byte{}, source})
	prep := control("prepared", 2, record("prepare", 2, zero, body, zero), sum(idle))
	freeze := control("frozen", 3, record("freeze", 3, frozen, body, zero), sum(prep))
	commitRecord := record("commit", 4, frozen, body, tr)
	commit := control("committed", 4, commitRecord, sum(freeze))
	digest := sum(commit)
	dataHash := sum(enc(digest))
	key := []byte{255, 255, 255, 255}
	leaf := append(enc([]byte{1}), enc(key)...)
	leaf = append(leaf, enc(dataHash)...)
	root := sum(leaf)
	vote := enc(cbor.Tag{Number: 39007, Content: []any{uint64(1), uint64(5), uint64(1), uint64(1681971085), uint64(4), root}})
	seal := enc(cbor.Tag{Number: 39005, Content: []any{uint64(1), uint64(5), uint64(4), uint64(1), uint64(1681971085), sum(vote), root, nil}})
	out := map[string]any{"record": hx(commitRecord), "control": hx(commit), "digest": hx(digest), "root": hx(root), "vote": hx(vote), "seal": hx(seal)}
	nodes := map[string]string{}
	signatures := map[string]string{}
	for i, id := range []string{"a", "b", "c", "d"} {
		seed := make([]byte, 32)
		seed[31] = byte(i + 1)
		priv := secp256k1.PrivKeyFromBytes(seed)
		nodes[id] = hx(priv.PubKey().SerializeCompressed())
		if i < 3 {
			compact := dcrecdsa.SignCompact(priv, sum(seal), true)
			sig := append([]byte{}, compact[1:]...)
			sig = append(sig, compact[0]-27-4)
			signatures[id] = hx(sig)
		}
	}
	out["nodes"] = nodes
	out["signatures"] = signatures
	b, e := json.MarshalIndent(out, "", "  ")
	if e != nil {
		panic(e)
	}
	b = append(b, '\n')
	if e = os.WriteFile("handoff/testdata/old-commit-proof.json", b, 0644); e != nil {
		panic(e)
	}
}
