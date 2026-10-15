package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/q3format"
)

func runManifest(t *testing.T, args ...string) (string, error) {
	cmd := trustBaseUTBManifestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestManifestIsGeneratedFromTheGenesisTrustBaseAndChecksOut(t *testing.T) {
	dir := t.TempDir()
	tb := writeGenesisTrustBase(t, dir)
	out := filepath.Join(dir, "deployment")
	_, err := runManifest(t, "--trust-base", tb, "--out-dir", out, "--component", "ureth=6e59b68cc29f", "--component", "aggregator=sha256:abc")
	require.NoError(t, err)

	raw, err := os.ReadFile(filepath.Join(out, "utb-manifest.json"))
	require.NoError(t, err)
	var m utbManifest
	require.NoError(t, json.Unmarshal(raw, &m))
	require.Equal(t, utbManifestSchema, m.Schema)
	require.Equal(t, map[string]string{"ureth": "6e59b68cc29f", "aggregator": "sha256:abc"}, m.Components)
	require.EqualValues(t, 3, m.Derived.ProtocolRevision)
	require.EqualValues(t, 3, m.Derived.VoteCodec)
	require.EqualValues(t, 2, m.Derived.SigningScheme)
	require.NotEqual(t, m.Derived.ProtocolConfigID, m.Derived.LegacyProtocolConfig)
	require.Equal(t, []string{"trust-base", "root-genesis-id", "utb-genesis", "utb-genesis-entry-id", "protocol-config"}, m.Order)

	// the three identities are distinct, and the genesis entry file is the one the pin names
	require.NotEqual(t, m.Derived.RootGenesisID, m.Derived.UTBGenesisEntryID)
	genesisRaw, err := os.ReadFile(m.Derived.UTBGenesisFile)
	require.NoError(t, err)
	genesis, err := types.DecodeRootTrustBaseV2(genesisRaw)
	require.NoError(t, err)
	id, _ := genesis.EntryID()
	require.Equal(t, "0x"+string(bytesHex(id[:])), m.Derived.UTBGenesisEntryID)
	// the protocol tuple identity is the one the history plans, rooted in the root genesis identity
	var g [32]byte
	rootRaw, err := hexDecode(m.Derived.RootGenesisID)
	require.NoError(t, err)
	copy(g[:], rootRaw)
	cfg := q3format.Q3ConfigUTB(uint64(m.Inputs.NetworkID), g)
	cid := cfg.Identity()
	require.Equal(t, "0x"+string(bytesHex(cid[:])), m.Derived.ProtocolConfigID)

	msg, err := runManifest(t, "--check", filepath.Join(out, "utb-manifest.json"))
	require.NoError(t, err)
	require.Contains(t, msg, "manifest ok")

	// the same input generates the same artifacts
	again := filepath.Join(dir, "again")
	_, err = runManifest(t, "--trust-base", tb, "--out-dir", again, "--component", "ureth=6e59b68cc29f", "--component", "aggregator=sha256:abc")
	require.NoError(t, err)
	a, _ := os.ReadFile(filepath.Join(out, "utb-genesis.cbor"))
	b, _ := os.ReadFile(filepath.Join(again, "utb-genesis.cbor"))
	require.Equal(t, a, b)
}

func TestManifestCheckReportsEveryDriftedValue(t *testing.T) {
	dir := t.TempDir()
	tb := writeGenesisTrustBase(t, dir)
	out := filepath.Join(dir, "deployment")
	_, err := runManifest(t, "--trust-base", tb, "--out-dir", out)
	require.NoError(t, err)
	path := filepath.Join(out, "utb-manifest.json")
	good, err := os.ReadFile(path)
	require.NoError(t, err)

	t.Run("a hand-edited derived value", func(t *testing.T) {
		var m map[string]any
		require.NoError(t, json.Unmarshal(good, &m))
		m["derived"].(map[string]any)["utbGenesisEntryId"] = "0x" + string(bytesHex(make([]byte, 32)))
		edited, _ := json.Marshal(m)
		require.NoError(t, os.WriteFile(path, edited, 0o644))
		require.ErrorContains(t, checkUTBManifest(path), "utbGenesisEntryId")
		require.NoError(t, os.WriteFile(path, good, 0o644))
	})
	t.Run("a changed genesis entry file", func(t *testing.T) {
		genesis := filepath.Join(out, "utb-genesis.cbor")
		orig, _ := os.ReadFile(genesis)
		require.NoError(t, os.WriteFile(genesis, append(append([]byte(nil), orig...), 0), 0o644))
		require.ErrorContains(t, checkUTBManifest(path), "utbGenesisFile content")
		require.NoError(t, os.WriteFile(genesis, orig, 0o644))
	})
	t.Run("a changed trust base", func(t *testing.T) {
		orig, _ := os.ReadFile(tb)
		require.NoError(t, os.WriteFile(tb, bytes.Replace(orig, []byte(`"epochStartRound"`), []byte(`"epochStartRound" `), 1), 0o644))
		require.ErrorContains(t, checkUTBManifest(path), "trustBaseSha256")
		require.NoError(t, os.WriteFile(tb, orig, 0o644))
	})
	t.Run("another schema", func(t *testing.T) {
		other := bytes.Replace(good, []byte(utbManifestSchema), []byte("something/else"), 1)
		require.NoError(t, os.WriteFile(path, other, 0o644))
		require.ErrorContains(t, checkUTBManifest(path), "schema")
		require.NoError(t, os.WriteFile(path, good, 0o644))
	})
	t.Run("a trust base that is not epoch 1, and a bad component", func(t *testing.T) {
		_, err := runManifest(t, "--trust-base", tb, "--out-dir", out, "--component", "novalue")
		require.ErrorContains(t, err, "name=digest")
		_, err = runManifest(t)
		require.ErrorContains(t, err, "--trust-base")
	})
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)/2)
	s = s[2:]
	for i := 0; i+1 < len(s); i += 2 {
		var b byte
		for _, c := range []byte{s[i], s[i+1]} {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			default:
				b |= c - 'a' + 10
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// A self-contained pack names its files relative to the manifest: it checks out after it is moved, and without the live deployment.
func TestRelativeManifestCheckedAfterTheDirectoryMoves(t *testing.T) {
	dir := t.TempDir()
	tb := writeGenesisTrustBase(t, dir)
	pack := filepath.Join(dir, "pack", "manifest")
	require.NoError(t, os.MkdirAll(pack, 0o755))
	raw, err := os.ReadFile(tb)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(pack, "trust-base.json"), raw, 0o644))
	_, err = runManifest(t, "--trust-base", filepath.Join(pack, "trust-base.json"), "--out-dir", pack, "--relative-paths")
	require.NoError(t, err)
	var m utbManifest
	body, err := os.ReadFile(filepath.Join(pack, "utb-manifest.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &m))
	require.Equal(t, "trust-base.json", m.Inputs.TrustBaseFile)
	require.Equal(t, "utb-genesis.cbor", m.Derived.UTBGenesisFile)

	moved := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.Rename(filepath.Join(dir, "pack"), moved))
	require.NoError(t, os.Remove(tb)) // nothing of the live deployment is left
	_, err = runManifest(t, "--check", filepath.Join(moved, "manifest", "utb-manifest.json"))
	require.NoError(t, err)
	// and a tampered copy of the genesis entry in the pack is caught
	g := filepath.Join(moved, "manifest", "utb-genesis.cbor")
	orig, _ := os.ReadFile(g)
	require.NoError(t, os.WriteFile(g, append(orig, 0), 0o644))
	_, err = runManifest(t, "--check", filepath.Join(moved, "manifest", "utb-manifest.json"))
	require.ErrorContains(t, err, "utbGenesisFile content")
}
