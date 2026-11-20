package vrschedule

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type headerReader struct {
	*fakeReader
	number map[[32]byte]uint64
	err    error
	calls  int
}

func (h *headerReader) HeaderNumber(_ context.Context, hash [32]byte) (uint64, error) {
	h.calls++
	if h.err != nil {
		return 0, h.err
	}
	return h.number[hash], nil
}

// The recorded source carries the TRUE EVM block number (astra r5): shard round 4 certifying EVM block 3 records 3, so the freshness proof
// from the publication block itself (height 3) is not rejected as older than source.evmBlockNumber. An unavailable header observes
// nothing (the worker retries the same block, with the continuity run restored), including when the output is a cache hit.
func TestTheSourceRecordsTheTrueEVMBlockNumberNotTheShardRound(t *testing.T) {
	r := vrschema.Word{0x52}
	sources, err := NewSources("")
	require.NoError(t, err)
	reader := &headerReader{fakeReader: &fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r)}}, number: map[[32]byte]uint64{{2}: 3}}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	ctx := context.Background()
	require.NoError(t, o.Observe(ctx, cert(10, 1, 1)))
	pub := cert(11, 2, 2)
	pub.ShardRound = 4 // a skipped shard round: round 4 certifies EVM block 3

	reader.err = errors.New("header unavailable")
	require.Error(t, o.Observe(ctx, pub), "nothing is observed without the header")
	_, ok := sources.Get(r)
	require.False(t, ok)
	// the retry (the output is now cached) records, and the continuity run was restored, so the source is still recorded
	reader.err = nil
	require.NoError(t, o.Observe(ctx, pub))
	s, ok := sources.Get(r)
	require.True(t, ok, "the retry of the same block records the source")
	require.EqualValues(t, 3, s.EVMBlockNumber, "the EVM block's number, not the shard round 4")
}

// The header is verified: its recomputed hash must be the certified one.
func TestVerifiedHeaderNumber(t *testing.T) {
	h := &gethtypes.Header{Number: big.NewInt(3), Difficulty: big.NewInt(0), GasLimit: 30_000_000}
	raw, err := json.Marshal(h)
	require.NoError(t, err)
	n, err := VerifiedHeaderNumber(raw, h.Hash())
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	_, err = VerifiedHeaderNumber(raw, [32]byte{1})
	require.ErrorIs(t, err, ErrRead, "another block's hash")
	_, err = VerifiedHeaderNumber([]byte("null"), h.Hash())
	require.ErrorIs(t, err, ErrRead, "a block the client does not hold")
	moved := *h
	moved.Number = big.NewInt(4)
	raw, _ = json.Marshal(&moved)
	_, err = VerifiedHeaderNumber(raw, h.Hash())
	require.ErrorIs(t, err, ErrRead, "an altered number no longer hashes to the certified block")
}

// Hard cutover (astra r9): the VT-07 build requires a fresh generation. A sources file of version 1 (a bare array of shard rounds) or
// version 2 (which could carry an unverified fetched height) REFUSES the start with a clear error, and is neither discarded, backed up nor
// migrated; no file at all is fine; a version 3 file (verified heights only) round-trips.
func TestAnOlderSourcesFileRefusesToStartAndV3RoundTrips(t *testing.T) {
	r := vrschema.Word{0x52}
	entry := `{"resultId":"0x` + hex.EncodeToString(r[:]) + `","evmBlockHash":"0x` + hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32)) + `","evmBlockNumber":4,"certRootRound":12,"outputCommit":"0x` +
		hex.EncodeToString(bytes.Repeat([]byte{0xc0}, 32)) + `","certUcTime":1012}`
	for name, content := range map[string]string{
		"v1 bare array": `[` + entry + `]`,
		"v2 object":     `{"version":2,"sources":[` + entry + `]}`,
		"v2 pending":    `{"version":2,"sources":[` + strings.Replace(entry, `"certUcTime":1012`, `"certUcTime":1012,"pending":true`, 1) + `]}`,
		"unversioned":   `{"sources":[` + entry + `]}`,
	} {
		path := filepath.Join(t.TempDir(), "vr-sources.json")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		_, err := NewSources(path)
		require.ErrorIs(t, err, ErrLegacySources, name)
		require.Contains(t, err.Error(), "requires a fresh generation", name)
		raw, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		require.Equal(t, content, string(raw), name+": the file is left exactly as it was")
		_, serr := os.Stat(path + ".v1.bak")
		require.True(t, os.IsNotExist(serr), name+": no backup is made")
	}

	// no file at all is fine (a fresh generation); a recorded source is written as version 3 and reloads as it is
	path := filepath.Join(t.TempDir(), "vr-sources.json")
	sources, err := NewSources(path)
	require.NoError(t, err)
	reader := &headerReader{fakeReader: &fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r)}}, number: map[[32]byte]uint64{{2}: 3}}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	require.NoError(t, o.Observe(context.Background(), cert(10, 1, 1)))
	pub := cert(11, 2, 2)
	pub.ShardRound = 4
	require.NoError(t, o.Observe(context.Background(), pub))
	got, ok := sources.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 3, got.EVMBlockNumber)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"version": 3`)
	again, err := NewSources(path)
	require.NoError(t, err)
	back, ok := again.Get(r)
	require.True(t, ok)
	require.Equal(t, got, back)
}

// The order and the map change together: recording more than the capacity while lookups are in flight leaves the memory, the order and the
// file in agreement.
func TestEvictionKeepsTheOrderTheMapAndTheFileTogether(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vr-sources.json")
	sources, err := NewSources(path)
	require.NoError(t, err)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for b := 0; b < 20; b++ {
						sources.Get(vrschema.Word{byte(b)})
					}
				}
			}
		}()
	}
	total := maxSources + 5
	for i := 0; i < total; i++ {
		_, err := sources.Record(SourceEntry{Source: vrhandoff.Source{ResultID: bytes.Repeat([]byte{byte(i)}, 32), EVMBlockHash: bytes.Repeat([]byte{1}, 32), EVMBlockNumber: uint64(i),
			CertRootRound: uint64(i + 1), OutputCommit: bytes.Repeat([]byte{2}, 32)}})
		require.NoError(t, err)
	}
	close(stop)
	wg.Wait()
	require.Len(t, sources.order, maxSources)
	require.Len(t, sources.by, maxSources)
	for _, r := range sources.order {
		_, ok := sources.by[r]
		require.True(t, ok, "every retained result is in the map")
	}
	reloaded, err := NewSources(path)
	require.NoError(t, err)
	require.Equal(t, sources.order, reloaded.order, "the file holds exactly the retained results")
	require.Equal(t, sources.by, reloaded.by)
}

// A reader that cannot resolve a block's number records no source: the shard round is never recorded as a height.
func TestNoSourceIsRecordedWithoutAHeaderReader(t *testing.T) {
	r := vrschema.Word{0x52}
	sources, err := NewSources("")
	require.NoError(t, err)
	reader := &plainReader{&fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r)}}}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	require.NoError(t, o.Observe(context.Background(), cert(10, 1, 1)))
	require.Error(t, o.Observe(context.Background(), cert(11, 2, 2)))
	_, ok := sources.Get(r)
	require.False(t, ok)
}

// plainReader exposes only OpenOutput.
type plainReader struct{ f *fakeReader }

func (p *plainReader) OpenOutput(ctx context.Context, b, root [32]byte) (*vrhandoff.Output, error) {
	return p.f.OpenOutput(ctx, b, root)
}

// A fetched source's height is never trusted (sol r5): incumbents of an earlier build agree on the shard round 4, and the root records the
// height it derives itself from the certified hash (3). An unresolvable header leaves the entry unrecorded (retried), and a missing
// resolver refuses.
func TestAFetchedSourceHeightIsRederivedFromTheCertifiedHeader(t *testing.T) {
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{0x77}, 32))
	fetched := SourceEntry{Source: vrhandoff.Source{ResultID: bytes.Repeat([]byte{0x52}, 32), EVMBlockHash: h[:], EVMBlockNumber: 4, CertRootRound: 12,
		OutputCommit: bytes.Repeat([]byte{0xc0}, 32)}, CertUCTime: 1012}
	reader := &headerReader{fakeReader: &fakeReader{}, number: map[[32]byte]uint64{h: 3}}
	got, err := ResolveFetched(context.Background(), reader, fetched)
	require.NoError(t, err)
	require.EqualValues(t, 3, got.EVMBlockNumber, "the incumbents' shard round 4 is replaced by the verified EVM height")
	require.EqualValues(t, 12, got.CertRootRound)
	require.EqualValues(t, 4, fetched.EVMBlockNumber, "the argument is not modified")

	sources, err := NewSources("")
	require.NoError(t, err)
	reader.err = errors.New("header unavailable")
	_, err = ResolveFetched(context.Background(), reader, fetched)
	require.Error(t, err)
	_, ok := sources.Get(vrschema.Word(fetched.ResultID))
	require.False(t, ok, "nothing is recorded while the header is unresolved")
	_, err = ResolveFetched(context.Background(), nil, fetched)
	require.Error(t, err, "without a resolver a fetched height is never trusted")
}

// A restart between a publication's commit and the success of its header read (astra r10): four fresh stores each hold an earlier source
// as version 3, observe the next publication with its header unavailable, restart, and then see four later blocks showing the result. Every
// root recovers the identical source as an uninterrupted observer: the original certifying round, time, hash and the verified height.
func TestARestartBeforeTheHeaderRetryRecoversTheOriginalPublicationBoundary(t *testing.T) {
	r0, r1 := vrschema.Word{0x51}, vrschema.Word{0x52}
	outs := map[[32]byte]*vrhandoff.Output{{2}: published(r0), {3}: published(r0), {4}: published(r1), {5}: published(r1), {6}: published(r1), {7}: published(r1), {8}: published(r1)}
	numbers := map[[32]byte]uint64{{2}: 12, {4}: 33}
	ctx := context.Background()
	drive := func(o *Observer, blocks ...CertifiedEVM) {
		for _, c := range blocks {
			require.NoError(t, o.Observe(ctx, c))
		}
	}
	// the uninterrupted reference
	refSrc, err := NewSources("")
	require.NoError(t, err)
	ref := &Observer{Reader: &headerReader{fakeReader: &fakeReader{at: outs}, number: numbers}, Sources: refSrc, Outputs: NewOutputs()}
	drive(ref, cert(10, 1, 1), cert(11, 2, 2), cert(12, 3, 3), cert(13, 4, 4), cert(14, 5, 5), cert(15, 6, 6), cert(16, 7, 7), cert(17, 8, 8))
	want, ok := refSrc.Get(r1)
	require.True(t, ok)
	require.EqualValues(t, 13, want.CertRootRound)
	require.EqualValues(t, 33, want.EVMBlockNumber)

	for i := 0; i < 4; i++ {
		path := filepath.Join(t.TempDir(), "vr-sources.json")
		src, err := NewSources(path)
		require.NoError(t, err)
		reader := &headerReader{fakeReader: &fakeReader{at: outs}, number: numbers}
		o := &Observer{Reader: reader, Sources: src, Outputs: NewOutputs()}
		drive(o, cert(10, 1, 1), cert(11, 2, 2), cert(12, 3, 3)) // the earlier result is recorded
		_, ok := src.Get(r0)
		require.True(t, ok)
		reader.err = errors.New("header unavailable")
		require.Error(t, o.Observe(ctx, cert(13, 4, 4)), "the publication's header is unavailable")
		_, ok = src.Get(r1)
		require.False(t, ok)

		// the root restarts before the retry: a new store over the same file, a new observer, the header is available now
		restarted, err := NewSources(path)
		require.NoError(t, err)
		require.Len(t, restarted.Awaiting(), 1, "the publication boundary survived the restart as a durable work item")
		o2 := &Observer{Reader: &headerReader{fakeReader: &fakeReader{at: outs}, number: numbers}, Sources: restarted, Outputs: NewOutputs()}
		drive(o2, cert(14, 5, 5), cert(15, 6, 6), cert(16, 7, 7), cert(17, 8, 8)) // four later blocks, all showing r1 Published
		got, ok := restarted.Get(r1)
		require.True(t, ok, "root %d recovers the source", i)
		require.Equal(t, want, got, "root %d: the same source as an uninterrupted observer: round, time, hash and verified height", i)
		require.Empty(t, restarted.Awaiting(), "the work item is consumed with the source")
		again, err := NewSources(path)
		require.NoError(t, err)
		back, ok := again.Get(r1)
		require.True(t, ok)
		require.Equal(t, want, back)
	}
}

// A version 3 source row must carry evmBlockNumber (sol r8): an explicit 0 is kept, a row without it is refused.
func TestAV3RowWithoutEVMBlockNumberIsRefusedAndAnExplicitZeroIsKept(t *testing.T) {
	row := func(extra string) string {
		return `{"version":3,"sources":[{"resultId":"0x` + hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32)) + `","evmBlockHash":"0x` + hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32)) +
			`",` + extra + `"certRootRound":12,"outputCommit":"0x` + hex.EncodeToString(bytes.Repeat([]byte{0xc0}, 32)) + `","certUcTime":1}]}`
	}
	path := filepath.Join(t.TempDir(), "vr-sources.json")
	require.NoError(t, os.WriteFile(path, []byte(row("")), 0o600))
	_, err := NewSources(path)
	require.Error(t, err, "a row without evmBlockNumber is refused")
	require.NoError(t, os.WriteFile(path, []byte(row(`"evmBlockNumber":0,`)), 0o600))
	s, err := NewSources(path)
	require.NoError(t, err)
	got, ok := s.Get(vrschema.Word(bytes.Repeat([]byte{0x52}, 32)))
	require.True(t, ok)
	require.EqualValues(t, 0, got.EVMBlockNumber, "an explicit 0 is kept")
}
