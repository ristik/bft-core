package seed

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/testutils/ucfixture"
)

// fixture is a one-entry history and a certified checkpoint of a fixture network.
type fixture struct {
	manifest []byte
	files    map[string][]byte
	pin      [types.TrustBaseV2IDLen]byte
	dir      string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 0})
	require.NoError(t, err)
	hash := bytes.Repeat([]byte{7}, 32)
	b, err := p.Next(ucfixture.BlockSpec{Round: 2, Timestamp: 1800000000, Changes: []ucfixture.Change{{Shard: 0, Hash: hash}}})
	require.NoError(t, err)
	require.Len(t, b.Responses, 1)
	resp := b.Responses[0]
	ucRaw, err := types.Cbor.Marshal(&resp.UC)
	require.NoError(t, err)
	trRaw, err := types.Cbor.Marshal(&resp.Technical)
	require.NoError(t, err)
	utbRaw, err := p.TrustBaseBundle()
	require.NoError(t, err)
	bundle, err := types.DecodeTrustBaseBundle(utbRaw, types.TrustBaseLimits{MaxBytes: len(utbRaw), MaxEntries: 8})
	require.NoError(t, err)
	tipID, err := bundle.Tip().EntryID()
	require.NoError(t, err)
	m, files := assemble(bundle, tipID, utbRaw, ucRaw, trRaw, &resp.UC, tipID, time.Unix(1, 0))
	raw, err := m.Encode()
	require.NoError(t, err)
	dir := t.TempDir()
	for n, f := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), f, 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o644))
	return &fixture{manifest: raw, files: files, pin: tipID, dir: dir}
}

func (f *fixture) clone() (map[string][]byte, []byte) {
	out := map[string][]byte{}
	for k, v := range f.files {
		out[k] = bytes.Clone(v)
	}
	return out, bytes.Clone(f.manifest)
}

func TestVerifyAccepts(t *testing.T) {
	f := newFixture(t)
	v, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	require.Equal(t, uint64(1), v.Manifest.Network.UTBTipEpoch)
	require.Contains(t, v.Summary(), "checkpoint root epoch 1")
}

// resign rewrites the manifest after a payload change, so the manifest hash check passes and the deeper check is what refuses.
func resign(t *testing.T, f *fixture, files map[string][]byte, edit func(*Manifest)) []byte {
	m, err := DecodeManifest(f.manifest)
	require.NoError(t, err)
	for i, fl := range m.Files {
		m.Files[i] = File{Name: fl.Name, Size: int64(len(files[fl.Name])), SHA256: sum(files[fl.Name])}
	}
	if edit != nil {
		edit(m)
	}
	raw, err := m.Encode()
	require.NoError(t, err)
	return raw
}

func TestVerifyRefusesTampering(t *testing.T) {
	f := newFixture(t)
	t.Run("a flipped checkpoint byte (hash mismatch)", func(t *testing.T) {
		files, m := f.clone()
		files[TipUCFile][len(files[TipUCFile])/2] ^= 1
		_, err := Verify(m, files, Pins{GenesisID: f.pin})
		require.ErrorContains(t, err, "manifest hash")
	})
	t.Run("a flipped checkpoint byte with a re-hashed manifest", func(t *testing.T) {
		files, _ := f.clone()
		files[TipUCFile][len(files[TipUCFile])-3] ^= 1
		_, err := Verify(resign(t, f, files, nil), files, Pins{GenesisID: f.pin})
		require.ErrorIs(t, err, ErrSeed)
	})
	t.Run("a wrong genesis pin", func(t *testing.T) {
		files, m := f.clone()
		pin := f.pin
		pin[0] ^= 1
		_, err := Verify(m, files, Pins{GenesisID: pin})
		require.ErrorContains(t, err, "pinned genesis")
	})
	t.Run("a stale trust-base floor", func(t *testing.T) {
		files, m := f.clone()
		_, err := Verify(m, files, Pins{GenesisID: f.pin, MinTipEpoch: 5})
		require.ErrorContains(t, err, "stale")
	})
	t.Run("a manifest that claims a later tip", func(t *testing.T) {
		files, _ := f.clone()
		_, err := Verify(resign(t, f, files, func(m *Manifest) { m.Network.UTBTipEpoch = 9 }), files, Pins{GenesisID: f.pin})
		require.ErrorContains(t, err, "tip")
	})
	t.Run("a manifest that claims another block", func(t *testing.T) {
		files, _ := f.clone()
		_, err := Verify(resign(t, f, files, func(m *Manifest) { m.Checkpoint.BlockHash = "0x" + strings.Repeat("ab", 32) }), files, Pins{GenesisID: f.pin})
		require.ErrorContains(t, err, "block hash")
	})
	t.Run("a checkpoint of another shard", func(t *testing.T) {
		files, m := f.clone()
		other := types.PartitionID(99)
		_, err := Verify(m, files, Pins{GenesisID: f.pin, Partition: &other})
		require.ErrorContains(t, err, "partition")
	})
	t.Run("an unknown manifest field", func(t *testing.T) {
		_, m := f.clone()
		m = bytes.Replace(m, []byte(`"format"`), []byte(`"extra": 1, "format"`), 1)
		_, err := DecodeManifest(m)
		require.ErrorIs(t, err, ErrSeed)
	})
}

func serve(t *testing.T, dir string) string {
	s := httptest.NewServer(Handler(dir))
	t.Cleanup(s.Close)
	return s.URL
}

func TestFetchAgreesAndRefusesDisagreement(t *testing.T) {
	f := newFixture(t)
	a, b := serve(t, f.dir), serve(t, f.dir)
	got, err := Fetch(context.Background(), []string{a, b + "/"}, FetchOptions{Pins: Pins{GenesisID: f.pin}, MinSources: 2})
	require.NoError(t, err)
	require.Len(t, got.Sources, 2)

	// a second directory whose manifest differs (another export time): the sources disagree
	other := t.TempDir()
	for n, data := range f.files {
		require.NoError(t, os.WriteFile(filepath.Join(other, n), data, 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(other, ManifestName), bytes.Replace(f.manifest, []byte(`"created": "1970`), []byte(`"created": "1971`), 1), 0o644))
	_, err = Fetch(context.Background(), []string{a, serve(t, other)}, FetchOptions{Pins: Pins{GenesisID: f.pin}})
	require.ErrorContains(t, err, "disagree")

	// a single source that is the only one reachable does not satisfy --min-sources 2
	_, err = Fetch(context.Background(), []string{a, "http://127.0.0.1:1"}, FetchOptions{Pins: Pins{GenesisID: f.pin}, MinSources: 2})
	require.ErrorContains(t, err, "required")
	got, err = Fetch(context.Background(), []string{a, "http://127.0.0.1:1"}, FetchOptions{Pins: Pins{GenesisID: f.pin}})
	require.NoError(t, err)
	require.Len(t, got.Unreachable, 1)
}

func TestFetchRefusesATamperedPayloadAndWrongPin(t *testing.T) {
	f := newFixture(t)
	bad := t.TempDir()
	for n, data := range f.files {
		d := bytes.Clone(data)
		if n == TipUCFile {
			d[len(d)/2] ^= 1
		}
		require.NoError(t, os.WriteFile(filepath.Join(bad, n), d, 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(bad, ManifestName), f.manifest, 0o644))
	_, err := Fetch(context.Background(), []string{serve(t, bad)}, FetchOptions{Pins: Pins{GenesisID: f.pin}})
	require.ErrorContains(t, err, "manifest")

	pin := f.pin
	pin[5] ^= 1
	_, err = Fetch(context.Background(), []string{serve(t, f.dir)}, FetchOptions{Pins: Pins{GenesisID: pin}})
	require.ErrorContains(t, err, "pinned genesis")
}

func TestHandlerIsReadOnlyAndNarrow(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "secret.txt"), []byte("x"), 0o644))
	h := Handler(f.dir)
	for _, c := range []struct {
		method, path string
		code         int
	}{{"GET", "/manifest.json", 200}, {"HEAD", "/" + UTBFile, 200}, {"GET", "/secret.txt", 404}, {"GET", "/", 404}, {"GET", "/../manifest.json", 404},
		{"POST", "/manifest.json", http.StatusMethodNotAllowed}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		require.Equal(t, c.code, rec.Code, "%s %s", c.method, c.path)
	}
}

func TestImportRefusesOverwriteAndRecords(t *testing.T) {
	f := newFixture(t)
	v, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	home := filepath.Join(t.TempDir(), "joiner")
	rec, err := Import(v, home, []string{"http://a"}, false, time.Unix(5, 0))
	require.NoError(t, err)
	got, err := ReadImportRecord(home)
	require.NoError(t, err)
	require.Equal(t, rec, got)
	// the imported directory verifies again
	_, err = VerifyDir(filepath.Join(home, ImportDir), Pins{GenesisID: f.pin})
	require.NoError(t, err)
	_, err = Import(v, home, nil, false, time.Now())
	require.ErrorContains(t, err, "already holds")
	_, err = Import(v, home, nil, true, time.Now())
	require.NoError(t, err)
}
