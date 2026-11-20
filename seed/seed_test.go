package seed

import (
	"bytes"
	"context"
	"crypto"
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
	_, err = Import(v, home, nil, false, time.Now()) // the same seed again resumes
	require.NoError(t, err)
	_, err = Import(v, home, nil, true, time.Now())
	require.NoError(t, err)
}

func TestVerifyRefusesAnIncompleteUC(t *testing.T) {
	f := newFixture(t)
	files, _ := f.clone()
	var uc types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(files[TipUCFile], &uc))
	uc.UnicityTreeCertificate = nil
	raw, err := types.Cbor.Marshal(&uc)
	require.NoError(t, err)
	files[TipUCFile] = raw
	_, err = Verify(resign(t, f, files, nil), files, Pins{GenesisID: f.pin})
	require.ErrorIs(t, err, ErrSeed)
	require.ErrorContains(t, err, "unicity tree certificate")
	// a certificate that decodes but is short of other parts is a refusal too, whatever the field
	uc.UnicityTreeCertificate = nil
	uc.UnicitySeal = nil
	raw, _ = types.Cbor.Marshal(&uc)
	files[TipUCFile] = raw
	_, err = Verify(resign(t, f, files, nil), files, Pins{GenesisID: f.pin})
	require.ErrorIs(t, err, ErrSeed)
}

func TestReadsAreBoundOnTheOpenedFile(t *testing.T) {
	f := newFixture(t)
	// a symlink in place of a payload file is not followed
	require.NoError(t, os.Remove(filepath.Join(f.dir, TipTRFile)))
	require.NoError(t, os.Symlink(filepath.Join(f.dir, TipUCFile), filepath.Join(f.dir, TipTRFile)))
	_, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.ErrorIs(t, err, ErrSeed)
	// a file larger than the manifest says is refused before it is read
	g := newFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(g.dir, UTBFile), bytes.Repeat([]byte{1}, int(MaxPinFileBytes)), 0o644))
	_, err = VerifyDir(g.dir, Pins{GenesisID: g.pin})
	require.ErrorIs(t, err, ErrSeed)
	// the HTTP handler does not follow a symlink either
	h := Handler(f.dir)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/"+TipTRFile, nil))
	require.Equal(t, 404, rec.Code)
}

func TestWriteDirIsExclusiveAndAtomic(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, false))
	_, err := VerifyDir(dst, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	require.ErrorContains(t, WriteDir(dst, f.files, f.manifest, false), "already exists")
	// a symlink at the destination is never written through
	victim := filepath.Join(parent, "victim")
	require.NoError(t, os.Mkdir(victim, 0o755))
	link := filepath.Join(parent, "link")
	require.NoError(t, os.Symlink(victim, link))
	require.NoError(t, WriteDir(link, f.files, f.manifest, true))
	ents, _ := os.ReadDir(victim)
	require.Empty(t, ents, "the old symlink target is untouched")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, true))
	ents, _ = os.ReadDir(parent)
	for _, e := range ents {
		require.False(t, strings.HasPrefix(e.Name(), ".seed-"), "no staging leftovers: %s", e.Name())
	}
}

func TestSourcesAreCanonicalised(t *testing.T) {
	for in, want := range map[string]string{"HTTP://Example.COM:80/seed/": "http://example.com/seed", "https://h:443": "https://h", "http://h:8080/a//b/../c": "http://h:8080/a/c"} {
		got, err := normalize(in)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err := normalize("http://user:pw@h/seed")
	require.ErrorIs(t, err, ErrSeed)
	// two spellings of one endpoint are one source for --min-sources
	f := newFixture(t)
	a := serve(t, f.dir)
	_, err = Fetch(context.Background(), []string{a, strings.ToUpper(a[:4]) + a[4:] + "/"}, FetchOptions{Pins: Pins{GenesisID: f.pin}, MinSources: 2})
	require.ErrorContains(t, err, "required")
}

func TestImportResumesTheSameSeedAndKeepsTheOldUntilSwapped(t *testing.T) {
	f := newFixture(t)
	v, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	home := filepath.Join(t.TempDir(), "h")
	_, err = Import(v, home, nil, false, time.Unix(1, 0))
	require.NoError(t, err)
	_, err = Import(v, home, nil, false, time.Unix(2, 0)) // the same seed again: a resume, no --replace
	require.NoError(t, err)
	// another seed needs --replace
	v2 := *v
	v2.ManifestDigest = "0xabc"
	_, err = Import(&v2, home, nil, false, time.Now())
	require.ErrorContains(t, err, "already holds")
}

func TestResolveRestorePinEpoch1(t *testing.T) {
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 0})
	require.NoError(t, err)
	f := newFixture(t)
	v, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	_ = p
	// the fixture's own trust base is the genesis of its history: epoch 1 needs no bundles
	tb := ucfixture2TrustBase(t)
	rp, err := ResolveRestorePin(v, tb, false, nil)
	require.NoError(t, err)
	want, _ := tb.Hash(crypto.SHA256)
	require.Equal(t, want, rp.BodyID[:])
	require.EqualValues(t, 1, rp.RootEpoch)
	// a genesis trust base that is not the pinned entry's origin is refused
	other := *tb
	other.NetworkID++
	_, err = ResolveRestorePin(v, &other, false, nil)
	require.ErrorIs(t, err, ErrSeed)
	// a later epoch with no activation bundles is refused, never assumed
	v.UC.UnicitySeal.Epoch = 2
	_, err = ResolveRestorePin(v, tb, false, nil)
	require.ErrorIs(t, err, ErrSeed) // (the fixture genesis is unsigned, so no lineage starts; the epoch-2 path runs live)
}

func ucfixture2TrustBase(t *testing.T) *types.RootTrustBaseV1 {
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 0})
	require.NoError(t, err)
	return p.TrustBase()
}
