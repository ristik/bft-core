package vrschedule

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
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

// Pre-production simplification (astra r8): a sources file of an earlier build is DISCARDED at startup (never migrated), a copy is kept as
// .v1.bak and the event is logged with the count. Until the source is re-learned the root behaves exactly like a fresh root, and once it
// re-observes the publication it holds the same source (so derives the same intent digest) as a fresh root.
func TestAV1SourcesFileIsDiscardedAndTheRootBehavesLikeAFreshRoot(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	r := vrschema.Word{0x52}
	hash := bytes.Repeat([]byte{0x77}, 32)
	legacy := `[{"resultId":"0x` + hex.EncodeToString(r[:]) + `","evmBlockHash":"0x` + hex.EncodeToString(hash) + `","evmBlockNumber":4,"certRootRound":12,"outputCommit":"0x` +
		hex.EncodeToString(bytes.Repeat([]byte{0xc0}, 32)) + `","certUcTime":1012}]`
	path := filepath.Join(t.TempDir(), "vr-sources.json")
	require.NoError(t, os.WriteFile(path, []byte(legacy), 0o600))

	restarted, err := NewSources(path)
	require.NoError(t, err)
	fresh, err := NewSources("")
	require.NoError(t, err)
	_, ok := restarted.Get(r)
	require.False(t, ok, "the shard-round entry is not served")
	_, ok = fresh.Get(r)
	require.False(t, ok)
	require.Contains(t, logs.String(), "event=vr.sources.legacy_discarded")
	require.Contains(t, logs.String(), "count=1")
	bak, err := os.ReadFile(path + ".v1.bak")
	require.NoError(t, err)
	require.Equal(t, legacy, string(bak), "the old file is kept")

	// both roots observe the same publication (EVM block 3 certified at shard round 4) and hold the identical source
	var h [32]byte
	copy(h[:], hash)
	obs := func(src *Sources) {
		reader := &headerReader{fakeReader: &fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r)}}, number: map[[32]byte]uint64{{2}: 3}}
		o := &Observer{Reader: reader, Sources: src, Outputs: NewOutputs()}
		require.NoError(t, o.Observe(context.Background(), cert(10, 1, 1)))
		pub := cert(11, 2, 2)
		pub.ShardRound = 4
		require.NoError(t, o.Observe(context.Background(), pub))
	}
	obs(restarted)
	obs(fresh)
	a, ok := restarted.Get(r)
	require.True(t, ok)
	b, ok := fresh.Get(r)
	require.True(t, ok)
	require.Equal(t, a, b, "the restarted root and the fresh root hold the same source")
	require.EqualValues(t, 3, a.EVMBlockNumber)
	// and the file the restarted root now writes is a version 2 file it reloads as it is
	again, err := NewSources(path)
	require.NoError(t, err)
	c, ok := again.Get(r)
	require.True(t, ok)
	require.Equal(t, a, c)
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
