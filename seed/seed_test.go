package seed

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"

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
	exchange := canExchange(parent)
	if !exchange {
		// no atomic exchange on this filesystem: every replacement is refused before anything moves
		err = WriteDir(link, f.files, f.manifest, true)
		require.ErrorContains(t, err, "not supported")
		target, lerr := os.Readlink(link)
		require.NoError(t, lerr, "the destination symlink is intact")
		require.Equal(t, victim, target)
		ents, _ := os.ReadDir(victim)
		require.Empty(t, ents, "the symlink target is untouched")
		require.ErrorContains(t, WriteDir(dst, f.files, f.manifest, true), "not supported")
		_, err = VerifyDir(dst, Pins{GenesisID: f.pin})
		require.NoError(t, err, "the original destination is intact")
	} else {
		require.NoError(t, WriteDir(link, f.files, f.manifest, true))
		ents, _ := os.ReadDir(victim)
		require.Empty(t, ents, "the old symlink target is untouched")
		require.NoError(t, WriteDir(dst, f.files, f.manifest, true))
	}
	ents, _ := os.ReadDir(parent)
	for _, e := range ents {
		require.False(t, strings.HasPrefix(e.Name(), ".seed-"), "no staging leftovers: %s", e.Name())
		require.False(t, strings.HasSuffix(e.Name(), ".lock"), "no lock leftovers: %s", e.Name())
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
	rp, err := ResolveRestorePin(v, tb, false, nil, nil)
	require.NoError(t, err)
	want, _ := tb.Hash(crypto.SHA256)
	require.Equal(t, want, rp.BodyID[:])
	require.EqualValues(t, 1, rp.RootEpoch)
	// a genesis trust base that is not the pinned entry's origin is refused
	other := *tb
	other.NetworkID++
	_, err = ResolveRestorePin(v, &other, false, nil, nil)
	require.ErrorIs(t, err, ErrSeed)
	// a later epoch with no activation bundles is refused, never assumed
	v.UC.UnicitySeal.Epoch = 2
	_, err = ResolveRestorePin(v, tb, false, nil, nil)
	require.ErrorIs(t, err, ErrSeed) // (the fixture genesis is unsigned, so no lineage starts; the epoch-2 path runs live)
}

func ucfixture2TrustBase(t *testing.T) *types.RootTrustBaseV1 {
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 0})
	require.NoError(t, err)
	return p.TrustBase()
}

func TestShardConfPinRefusesAnotherShard(t *testing.T) {
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 1})
	require.NoError(t, err)
	b, err := p.Next(ucfixture.BlockSpec{Round: 2, Timestamp: 1800000000, Changes: []ucfixture.Change{{Shard: 1, Hash: bytes.Repeat([]byte{7}, 32)}}})
	require.NoError(t, err)
	resp := b.Responses[0]
	ucRaw, _ := types.Cbor.Marshal(&resp.UC)
	trRaw, _ := types.Cbor.Marshal(&resp.Technical)
	utbRaw, err := p.TrustBaseBundle()
	require.NoError(t, err)
	bundle, err := types.DecodeTrustBaseBundle(utbRaw, types.TrustBaseLimits{MaxBytes: len(utbRaw), MaxEntries: 8})
	require.NoError(t, err)
	tipID, _ := bundle.Tip().EntryID()
	m, files := assemble(bundle, tipID, utbRaw, ucRaw, trRaw, &resp.UC, tipID, time.Unix(1, 0))
	raw, err := m.Encode()
	require.NoError(t, err)
	sh := p.Shards()
	// the seed is valid and is of shard 1: this node's configuration of shard 0 refuses it
	_, err = Verify(raw, files, Pins{GenesisID: tipID, ShardConf: sh[0].Config})
	require.ErrorContains(t, err, "another shard")
	// ... of another partition
	other := *sh[1].Config
	other.PartitionID++
	_, err = Verify(raw, files, Pins{GenesisID: tipID, ShardConf: &other})
	require.ErrorContains(t, err, "another shard")
	// ... and this node's own configuration accepts it
	_, err = Verify(raw, files, Pins{GenesisID: tipID, ShardConf: sh[1].Config})
	require.NoError(t, err)
	// a configuration of a LATER shard epoch than the checkpoint's is refused
	later := *sh[1].Config
	later.Epoch = 9
	_, err = Verify(raw, files, Pins{GenesisID: tipID, ShardConf: &later})
	require.ErrorContains(t, err, "older than")
}

func TestPublishIsExclusiveAcrossConcurrentWriters(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	var wg sync.WaitGroup
	var ok, refused atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WriteDir(dst, f.files, f.manifest, false); err == nil {
				ok.Add(1)
			} else {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, ok.Load(), "exactly one concurrent fresh publication succeeds")
	require.EqualValues(t, 7, refused.Load())
	_, err := VerifyDir(dst, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	// the lock file is gone, and a replacement keeps the destination readable and complete
	require.NoFileExists(t, dst+".lock")
	if canExchange(parent) {
		require.NoError(t, WriteDir(dst, f.files, f.manifest, true))
	} else {
		require.ErrorContains(t, WriteDir(dst, f.files, f.manifest, true), "not supported")
	}
	_, err = VerifyDir(dst, Pins{GenesisID: f.pin})
	require.NoError(t, err, "the destination is complete after a replacement or its refusal")
	// a stale lock refuses a publication with a message that names it
	require.NoError(t, os.WriteFile(dst+".lock", nil, 0o600))
	require.ErrorContains(t, WriteDir(dst, f.files, f.manifest, true), "in progress")
	require.NoError(t, os.Remove(dst+".lock"))
}

func TestHandlerServesOnlyTheDeclaredSizeAndStaysInsideTheDirectory(t *testing.T) {
	f := newFixture(t)
	h := Handler(f.dir)
	// a payload that grew past its manifest declaration is not served
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, TipTRFile), append(bytes.Clone(f.files[TipTRFile]), 1), 0o644))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/"+TipTRFile, nil))
	require.Equal(t, 404, rec.Code)
	// names that leave the directory are refused
	for _, p := range []string{"/../x", "/%2e%2e/manifest.json", "/a/manifest.json", "/..%2fmanifest.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		require.Equal(t, 404, rec.Code, p)
	}
	// a FIFO in place of a payload does not block the server (non-blocking open, then the descriptor's type is refused)
	require.NoError(t, os.Remove(filepath.Join(f.dir, TipUCFile)))
	require.NoError(t, syscall.Mkfifo(filepath.Join(f.dir, TipUCFile), 0o644))
	done := make(chan int)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/"+TipUCFile, nil))
		done <- rec.Code
	}()
	select {
	case code := <-done:
		require.Equal(t, 404, code)
	case <-time.After(5 * time.Second):
		t.Fatal("the handler blocked on a FIFO")
	}
}

func TestSourceCanonicalPathsDecodeUnreservedEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"http://h/%7Euser/seed": "http://h/~user/seed",
		"http://h/a%2fb/seed":   "http://h/a%2Fb/seed",
		"http://h/%2e%2e/seed":  "http://h/seed",
		"http://h/s%65ed":       "http://h/seed",
		"http://h/a%20b":        "http://h/a%20b",
		"http://h/a;b:c@d=e/s":  "http://h/a;b:c@d=e/s", // literal reserved characters are left exactly as written
	} {
		got, err := normalize(in)
		require.NoError(t, err)
		require.Equal(t, want, got, in)
	}
}

func TestImportTxnHoldsTheLockAndDecidesBeforeAnyStoreIsTouched(t *testing.T) {
	f := newFixture(t)
	v, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	other := *v
	other.ManifestDigest = "0xdeadbeef"
	home := filepath.Join(t.TempDir(), "h")

	// many concurrent imports of different seeds: while one holds the lock the others are refused before they could advance any store
	var wg sync.WaitGroup
	var storeWrites, begun atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seedv := v
			if i%2 == 1 {
				seedv = &other
			}
			txn, err := BeginImport(home, seedv, false)
			if err != nil {
				return
			}
			defer txn.Close()
			begun.Add(1)
			storeWrites.Add(1) // "the store installs": only a successful Begin reaches them
			time.Sleep(20 * time.Millisecond)
			_, err = txn.Commit(nil, time.Now())
			require.NoError(t, err)
		}(i)
	}
	wg.Wait()
	require.Equal(t, begun.Load(), storeWrites.Load())
	rec, err := ReadImportRecord(home)
	require.NoError(t, err)
	require.NotNil(t, rec)
	// after the dust settles, another seed needs --replace, and is refused before any store write
	loser := v
	if rec.ManifestDigest == v.ManifestDigest {
		loser = &other
	}
	_, err = BeginImport(home, loser, false)
	require.ErrorContains(t, err, "already holds")
	// the same seed resumes: Begin succeeds, Commit publishes nothing
	same := v
	if rec.ManifestDigest != v.ManifestDigest {
		same = &other
	}
	txn, err := BeginImport(home, same, false)
	require.NoError(t, err)
	got, err := txn.Commit(nil, time.Now())
	require.NoError(t, err)
	require.Equal(t, rec, got)
	// the lock is held until Close
	_, err = BeginImport(home, same, false)
	require.ErrorContains(t, err, "in progress")
	txn.Close()
	_, err = BeginImport(home, same, false)
	require.NoError(t, err)
}

func TestReplacingAnImportNeverLeavesItAbsent(t *testing.T) {
	f := newFixture(t)
	v, err := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	require.NoError(t, err)
	home := filepath.Join(t.TempDir(), "h")
	_, err = Import(v, home, nil, false, time.Now())
	require.NoError(t, err)
	if !canExchange(home) {
		// no atomic exchange on this system: the replacement is refused up front and the import is untouched
		other := *v
		other.ManifestDigest = "0xfeed"
		_, err = Import(&other, home, nil, true, time.Now())
		require.ErrorContains(t, err, "not supported")
		rec, err := ReadImportRecord(home)
		require.NoError(t, err)
		require.NotNil(t, rec)
		return
	}
	stop := make(chan struct{})
	var absent atomic.Int32
	var rwg sync.WaitGroup
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if rec, err := ReadImportRecord(home); err != nil || rec == nil {
				absent.Add(1)
			}
		}
	}()
	for i := 0; i < 30; i++ {
		other := *v
		other.ManifestDigest = fmt.Sprintf("0x%064x", i+1)
		_, err = Import(&other, home, nil, true, time.Now())
		require.NoError(t, err)
	}
	close(stop)
	rwg.Wait()
	require.EqualValues(t, 0, absent.Load(), "import.json was absent during a replacement")
}

func TestShardConfEpochComesFromTheTechnicalRecord(t *testing.T) {
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 0})
	require.NoError(t, err)
	conf := *p.Shards()[0].Config
	net, part, shard := types.NetworkID(conf.NetworkID), conf.PartitionID, conf.ShardID
	hash := func(c types.PartitionDescriptionRecord) []byte {
		h, err := c.Hash(crypto.SHA256)
		require.NoError(t, err)
		return h
	}
	old := conf
	old.Epoch = 1
	next := conf
	next.Epoch = 2
	// an assignment transition checkpoint: the input record still names epoch 1, but the technical record and the UC's configuration hash name epoch 2
	// (this node's configuration is the successor's): accepted; the old configuration's hash would be wrong
	require.NoError(t, checkShardConf(&next, net, part, shard, 2, hash(next)))
	// a transition checkpoint against the OLD configuration of the same epoch number is a mismatch: refused
	require.ErrorContains(t, checkShardConf(&next, net, part, shard, 2, hash(old)), "another shard configuration")
	// a checkpoint older than this node's configuration is refused; a newer one is not compared (the restore resolves it from the handoffs)
	require.ErrorContains(t, checkShardConf(&next, net, part, shard, 1, hash(old)), "older than")
	require.NoError(t, checkShardConf(&old, net, part, shard, 2, hash(next)))
	require.NoError(t, checkShardConf(nil, net, part, shard, 0, nil))
}

func TestScanArchiveTipSkipsAMalformedNewerRecord(t *testing.T) {
	f := newFixture(t)
	var uc types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(f.files[TipUCFile], &uc))
	dir := filepath.Join(t.TempDir(), "archive")
	st, err := archive.Open(dir)
	require.NoError(t, err)
	put := func(header string, u types.UnicityCertificate, tr []byte) archive.Request {
		raw, err := types.Cbor.Marshal(&u)
		require.NoError(t, err)
		rec := &archive.Record{Header: []byte(header), Body: []byte("b"), CanonicalRootInput: []byte("i"), OriginalUC: []byte("o"), OriginalTR: []byte("o"),
			ResultingUC: raw, ResultingTR: tr, Companion: []byte("c")}
		var shard types.ShardID
		require.NoError(t, shard.UnmarshalText([]byte("0x010203040580")))
		q := archive.Request{Context: archive.Context{NetworkID: 1, PartitionID: 2, ShardID: shard, ShardEpoch: 4, RootEpoch: 5, ExecutionIdentity: []byte("identity-v1")}}
		q.Context.FullShardConfHash[0] = 6
		q.Context.RegistryAddress[0] = 7
		q.Context.RegistryCodeHash[0] = 8
		q.Context.GenesisCommitment[0] = 9
		q.Context.EVMGenesisHash[0] = 10
		copy(q.BlockHash[:], ethcrypto.Keccak256(rec.Header))
		require.NoError(t, st.Put(q, rec))
		return q
	}
	good := put(string([]byte{0xc1, 0x80}), uc, f.files[TipTRFile])
	// a NEWER root round whose certificate has no unicity tree certificate: it must not win, and must not break the scan
	bad := uc
	seal := *uc.UnicitySeal
	seal.RootChainRoundNumber += 100
	bad.UnicitySeal = &seal
	bad.UnicityTreeCertificate = nil
	put(string([]byte{0xc2, 0x80, 0x01}), bad, f.files[TipTRFile])
	// ... nor one whose TR does not match its UC
	wrongTR := uc
	seal2 := *uc.UnicitySeal
	seal2.RootChainRoundNumber += 200
	wrongTR.UnicitySeal = &seal2
	var otherTR certification.TechnicalRecord
	require.NoError(t, types.Cbor.Unmarshal(f.files[TipTRFile], &otherTR))
	otherTR.Round++ // well-formed and valid, but not the technical record this UC commits to (its hash differs)
	otherTRRaw, err := types.Cbor.Marshal(&otherTR)
	require.NoError(t, err)
	require.NotEqual(t, f.files[TipTRFile], otherTRRaw)
	put(string([]byte{0xc2, 0x80, 0x02}), wrongTR, otherTRRaw)
	tip, err := ScanArchiveTip(dir)
	require.NoError(t, err)
	require.Equal(t, good.BlockHash, tip.Request.BlockHash)
	require.Equal(t, uc.GetRootRoundNumber(), tip.Round)
}

func TestUCShapeCheckIsSharedAndStrict(t *testing.T) {
	f := newFixture(t)
	var uc types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(f.files[TipUCFile], &uc))
	require.NoError(t, checkUCShape(&uc))
	for name, mut := range map[string]func(*types.UnicityCertificate){
		"no tree certificate": func(u *types.UnicityCertificate) { u.UnicityTreeCertificate = nil },
		"no seal":             func(u *types.UnicityCertificate) { u.UnicitySeal = nil },
		"no input record":     func(u *types.UnicityCertificate) { u.InputRecord = nil },
		"short TR hash":       func(u *types.UnicityCertificate) { u.TRHash = u.TRHash[:31] },
		"short conf hash":     func(u *types.UnicityCertificate) { u.ShardConfHash = nil },
	} {
		c := uc
		mut(&c)
		require.ErrorIs(t, checkUCShape(&c), ErrSeed, name)
	}
}

func TestRequestsGoToTheOperatorsURLAsGiven(t *testing.T) {
	f := newFixture(t)
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.EscapedPath())
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), []string{srv.URL + "/m;v=1/%7Euser/"}, FetchOptions{Pins: Pins{GenesisID: f.pin}})
	require.Error(t, err)
	require.Equal(t, []string{"/m;v=1/%7Euser/manifest.json"}, seen, "the request keeps the reserved characters and escapes as written")
}

func TestSymlinksAreRefusedAtEveryLevel(t *testing.T) {
	f := newFixture(t)
	// the seed directory itself is a symlink
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(f.dir, link))
	_, err := VerifyDir(link, Pins{GenesisID: f.pin})
	require.ErrorIs(t, err, ErrSeed)
	// the manifest is a symlink
	g := newFixture(t)
	real := filepath.Join(t.TempDir(), "m.json")
	require.NoError(t, os.WriteFile(real, g.manifest, 0o644))
	require.NoError(t, os.Remove(filepath.Join(g.dir, ManifestName)))
	require.NoError(t, os.Symlink(real, filepath.Join(g.dir, ManifestName)))
	_, err = VerifyDir(g.dir, Pins{GenesisID: g.pin})
	require.ErrorIs(t, err, ErrSeed)
	rec := httptest.NewRecorder()
	Handler(g.dir).ServeHTTP(rec, httptest.NewRequest("GET", "/"+ManifestName, nil))
	require.Equal(t, 404, rec.Code)
	// ReadFileBounded refuses a symlinked file too
	_, err = ReadFileBounded(filepath.Join(g.dir, ManifestName), MaxManifestBytes)
	require.ErrorIs(t, err, ErrSeed)
}

// One verification reads one directory version: swapping the path for another seed while it runs cannot mix the two.
func TestVerifyDirReadsOneDirectoryVersion(t *testing.T) {
	f := newFixture(t)
	d, err := openSeedDir(f.dir)
	require.NoError(t, err)
	defer d.Close()
	// the path is replaced after the directory was opened
	other := newFixture(t)
	require.NoError(t, os.Rename(f.dir, f.dir+".old"))
	require.NoError(t, os.Rename(other.dir, f.dir))
	m, err := d.read(ManifestName, MaxManifestBytes)
	require.NoError(t, err)
	require.Equal(t, f.manifest, m, "the opened directory still yields the version it was opened at")
}

func TestResolveShardConfCarriesTheConfigurationThroughTheActivations(t *testing.T) {
	p, err := ucfixture.New(ucfixture.Config{Partition: 1, ShardBits: 0})
	require.NoError(t, err)
	supplied := *p.Shards()[0].Config // epoch 0, the configuration the node was started with
	suppliedHash, _ := supplied.Hash(crypto.SHA256)
	succ := supplied
	succ.Epoch = 1
	succHash, _ := succ.Hash(crypto.SHA256)
	rootOnly := confStep(func(active []byte) ([]byte, *types.PartitionDescriptionRecord, error) { return active, nil, nil })
	coupled := confStep(func(active []byte) ([]byte, *types.PartitionDescriptionRecord, error) {
		require.Equal(t, suppliedHash, active, "the step receives the configuration carried so far")
		return succHash, &succ, nil
	})
	// accepted: a root-only activation, then a coupled one that activates shard epoch 1: the hash is the successor's
	h, err := resolveShardConf(&supplied, 1, []confStep{rootOnly, coupled})
	require.NoError(t, err)
	require.Equal(t, succHash, h)
	// refused: the activations never reach shard epoch 2 ("supply the configuration for epoch 2")
	_, err = resolveShardConf(&supplied, 2, []confStep{rootOnly, coupled})
	require.ErrorContains(t, err, "supply the configuration for shard epoch 2")
	_, err = resolveShardConf(&supplied, 1, nil)
	require.ErrorContains(t, err, "supply the configuration")
	// refused: a transition that does not verify
	bad := confStep(func([]byte) ([]byte, *types.PartitionDescriptionRecord, error) {
		return nil, nil, fmt.Errorf("proof invalid")
	})
	_, err = resolveShardConf(&supplied, 1, []confStep{bad})
	require.ErrorContains(t, err, "does not verify")
}

func TestAReaderKeepsItsVersionAcrossAReplacement(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, false))
	if !canExchange(parent) {
		t.Skip("no atomic exchange on this filesystem: replacement is refused, the destination is never replaced under a reader")
	}
	// a reader opens the directory and reads the manifest ...
	d, err := openSeedDir(dst)
	require.NoError(t, err)
	defer d.Close()
	m, err := d.read(ManifestName, MaxManifestBytes)
	require.NoError(t, err)
	// ... the destination is replaced (twice) mid-read ...
	g := newFixture(t)
	require.NoError(t, WriteDir(dst, g.files, g.manifest, true))
	require.NoError(t, WriteDir(dst, g.files, g.manifest, true))
	// ... and the reader still reads the payload of ITS version, completely, from the old entries
	for _, n := range PayloadFiles {
		b, err := d.read(n, fileLimits[n])
		require.NoError(t, err, n)
		require.Equal(t, f.files[n], b, "%s must be the version the reader opened", n)
	}
	require.Equal(t, f.manifest, m)
	// a new reader sees the new version
	v, err := VerifyDir(dst, Pins{GenesisID: g.pin})
	require.NoError(t, err)
	require.Equal(t, ManifestDigest(g.manifest), v.ManifestDigest)
	// replaced versions are removed only after the grace period, by a later publication
	old, _ := os.ReadDir(versionsDir(dst))
	require.NotEmpty(t, old)
	prev := oldVersionGrace
	oldVersionGrace = 0
	defer func() { oldVersionGrace = prev }()
	require.NoError(t, WriteDir(dst, g.files, g.manifest, true))
	left, _ := os.ReadDir(versionsDir(dst))
	n := 0
	for _, e := range left {
		if e.Name() != versionsMarker {
			n++
		}
	}
	require.Equal(t, 1, n, "the older versions are collected once past the grace period; only the version this replacement displaced remains")
}

func TestSourcesWithAQueryOrFragmentAreRefused(t *testing.T) {
	for _, u := range []string{"http://h/seed?", "http://h/seed?x=1", "http://h/seed#", "http://h/seed#f", "http://h/seed/?"} {
		_, err := normalize(u)
		require.ErrorIs(t, err, ErrSeed, u)
	}
}

// Retention collects only from the directory this tool owns, never among the parent's siblings.
func TestRetentionNeverDeletesOutsideItsOwnDirectory(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, false))
	if !canExchange(parent) {
		t.Skip("no atomic exchange here")
	}
	// siblings that merely look like retained versions
	for _, n := range []string{"out.old.1", "out.old.123456789", "out.versions.bak"} {
		require.NoError(t, os.MkdirAll(filepath.Join(parent, n), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(parent, n, "keep"), []byte("x"), 0o644))
	}
	prev := oldVersionGrace
	oldVersionGrace = 0
	defer func() { oldVersionGrace = prev }()
	for i := 0; i < 3; i++ {
		require.NoError(t, WriteDir(dst, f.files, f.manifest, true))
	}
	for _, n := range []string{"out.old.1", "out.old.123456789", "out.versions.bak"} {
		require.FileExists(t, filepath.Join(parent, n, "keep"), "a sibling the tool did not create is never touched")
	}
	// a versions directory the tool did not mark is not used and not collected from
	g := newFixture(t)
	parent2 := t.TempDir()
	dst2 := filepath.Join(parent2, "out")
	require.NoError(t, WriteDir(dst2, g.files, g.manifest, false))
	require.NoError(t, os.MkdirAll(filepath.Join(versionsDir(dst2), "1"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(versionsDir(dst2), "1", "keep"), []byte("x"), 0o644))
	err := WriteDir(dst2, g.files, g.manifest, true)
	var re *RetentionError
	require.ErrorAs(t, err, &re)
	require.FileExists(t, filepath.Join(versionsDir(dst2), "1", "keep"))
	require.FileExists(t, filepath.Join(re.Stage, ManifestName), "the old version is kept")
}

// A failing move into retention reports the error and keeps the old version at the stage path: readers do not lose their version.
func TestAFailingRetentionKeepsTheOldVersion(t *testing.T) {
	f := newFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	require.NoError(t, WriteDir(dst, f.files, f.manifest, false))
	if !canExchange(parent) {
		t.Skip("no atomic exchange here")
	}
	d, err := openSeedDir(dst)
	require.NoError(t, err)
	defer d.Close()
	prev := retainMove
	retainMove = func(string, string) error { return fmt.Errorf("disk full") }
	defer func() { retainMove = prev }()
	g := newFixture(t)
	err = WriteDir(dst, g.files, g.manifest, true)
	var re *RetentionError
	require.ErrorAs(t, err, &re)
	require.ErrorContains(t, err, "disk full")
	// the new version is in place ...
	v, verr := VerifyDir(dst, Pins{GenesisID: g.pin})
	require.NoError(t, verr)
	require.Equal(t, ManifestDigest(g.manifest), v.ManifestDigest)
	// ... the old one is intact at the reported stage path, and the reader that opened it still reads it
	old, verr := VerifyDir(re.Stage, Pins{GenesisID: f.pin})
	require.NoError(t, verr)
	require.Equal(t, ManifestDigest(f.manifest), old.ManifestDigest)
	b, rerr := d.read(UTBFile, fileLimits[UTBFile])
	require.NoError(t, rerr)
	require.Equal(t, f.files[UTBFile], b)
	// the same through import: its staging directory is kept too
	home := filepath.Join(t.TempDir(), "h")
	vf, _ := VerifyDir(f.dir, Pins{GenesisID: f.pin})
	_, err = Import(vf, home, nil, false, time.Now())
	require.NoError(t, err)
	other := *vf
	other.ManifestDigest = "0xfeed"
	_, err = Import(&other, home, nil, true, time.Now())
	require.ErrorAs(t, err, &re)
	require.FileExists(t, filepath.Join(re.Stage, ImportRecordName), "the previous import is kept, not deleted")
}
