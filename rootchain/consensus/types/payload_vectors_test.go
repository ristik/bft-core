package types

import (
	"crypto"
	"crypto/sha256"
	stdhex "encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// payload-vectors.json freezes the wire of the profile-2 root payload and of the proposals that carry it, for Rust and Solidity
// consumers: the payload bytes and their SHA-256, and the proposal block bytes and block hash (the scheme every block id uses), for an
// empty payload, a handoff-bearing one and a control-bearing one, each in the ordinary (parent QC) and the epoch-anchor form.
// PAYLOAD_VECTORS_UPDATE=1 regenerates; the consumers must reproduce every byte independently.
const payloadVectorsPath = "testdata/payload-vectors.json"

type payloadVector struct {
	Name        string `json:"name"`
	Payload     string `json:"payload"`
	PayloadHash string `json:"payloadSha256"`
	Block       string `json:"block"`
	BlockHash   string `json:"blockSha256"`
}

func h(b []byte) string { return "0x" + stdhex.EncodeToString(b) }

func vectorPayloads() map[string]*Payload {
	return map[string]*Payload{
		"empty":    {Version: 2},
		"handoff":  {Version: 2, HandoffRecords: [][]byte{{0x01, 0x02, 0x03}, {0xaa, 0xbb}}},
		"controls": {Version: 2, PosControls: []PosControl{closeControl(1), rejectControl(), retireControl(7, 1)}},
	}
}

func vectorBlocks(p *Payload) map[string]*BlockData {
	qc := &QuorumCert{
		VoteInfo:         &RoundInfo{Version: 1, RoundNumber: 8, Epoch: 2, Timestamp: 1_700_000_000, ParentRoundNumber: 7, CurrentRootHash: word(0x11)},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 8, Epoch: 2, Timestamp: 1_700_000_000, PreviousHash: word(0x22), Hash: word(0x11)},
		Signatures:       map[string]hex.Bytes{"node-a": word(0x33), "node-b": word(0x44)},
	}
	return map[string]*BlockData{
		"parent-qc":    {Version: 2, Author: "node-a", Round: 9, Epoch: 2, Timestamp: 1_700_000_001, Payload: p, Qc: qc},
		"epoch-anchor": {Version: 2, Author: "node-a", Round: 9, Epoch: 2, Timestamp: 1_700_000_001, Payload: p, Anchor: &EpochAnchor{GenesisID: word(0x55), Epoch: 2, Slot: 8, StateRoot: word(0x66)}},
	}
}

func buildPayloadVectors(t *testing.T) []payloadVector {
	t.Helper()
	var out []payloadVector
	for _, pn := range []string{"empty", "handoff", "controls"} {
		p := vectorPayloads()[pn]
		raw, err := p.MarshalCBOR()
		require.NoError(t, err)
		sum := sha256.Sum256(raw)
		for _, bn := range []string{"parent-qc", "epoch-anchor"} {
			b := vectorBlocks(p)[bn]
			blockBytes, err := b.Bytes()
			require.NoError(t, err)
			blockHash, err := b.Hash(crypto.SHA256)
			require.NoError(t, err)
			out = append(out, payloadVector{Name: pn + "/" + bn, Payload: h(raw), PayloadHash: h(sum[:]), Block: h(blockBytes), BlockHash: h(blockHash)})
		}
	}
	return out
}

func TestPayloadVectorsAreFrozen(t *testing.T) {
	want, err := json.MarshalIndent(map[string]any{"format": "UNICITY_ROOT_PAYLOAD_VECTORS/v1", "vectors": buildPayloadVectors(t)}, "", "  ")
	require.NoError(t, err)
	want = append(want, '\n')
	if os.Getenv("PAYLOAD_VECTORS_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(payloadVectorsPath, want, 0o644))
	}
	got, err := os.ReadFile(payloadVectorsPath)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run with PAYLOAD_VECTORS_UPDATE=1 to regenerate")
}

// Every vector decodes to the value it came from, and the empty payload is the specification's 8402808080.
func TestPayloadVectorsDecodeAndRoundTrip(t *testing.T) {
	raw, err := os.ReadFile(payloadVectorsPath)
	require.NoError(t, err)
	var file struct {
		Vectors []payloadVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.Len(t, file.Vectors, 6)
	require.Equal(t, "0x8402808080", file.Vectors[0].Payload)
	for _, v := range file.Vectors {
		pb, err := stdhex.DecodeString(v.Payload[2:])
		require.NoError(t, err)
		var p Payload
		require.NoError(t, p.UnmarshalCBOR(pb), v.Name)
		again, err := p.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, pb, again, v.Name)
		bb, err := stdhex.DecodeString(v.Block[2:])
		require.NoError(t, err)
		var b BlockData
		require.NoError(t, b.UnmarshalCBOR(bb), v.Name)
		reblock, err := b.Bytes()
		require.NoError(t, err)
		require.Equal(t, bb, reblock, v.Name)
		require.NoError(t, b.Payload.IsValid(), v.Name)
	}
}
