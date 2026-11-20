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

// Restart (astra r6): a vr-sources.json written by an earlier build (a bare array whose evmBlockNumber is the shard round 4) is not served
// as it stands; the observer re-resolves it by its certified hash (EVM block 3) before anything else, rewrites the file as version 2, and a
// restarted root then serves 3, like a fresh root. An unavailable header leaves the entry unavailable (never wrong).
func TestRestartedRootReResolvesALegacySourceByItsCertifiedHash(t *testing.T) {
	r := vrschema.Word{0x52}
	hash := bytes.Repeat([]byte{0x77}, 32)
	legacy := `[{"resultId":"` + "0x" + hex.EncodeToString(r[:]) + `","evmBlockHash":"` + "0x" + hex.EncodeToString(hash) + `","evmBlockNumber":4,"certRootRound":12,"outputCommit":"` +
		"0x" + hex.EncodeToString(bytes.Repeat([]byte{0xc0}, 32)) + `","certUcTime":1012}]`
	path := filepath.Join(t.TempDir(), "vr-sources.json")
	require.NoError(t, os.WriteFile(path, []byte(legacy), 0o600))

	sources, err := NewSources(path)
	require.NoError(t, err)
	_, ok := sources.Get(r)
	require.False(t, ok, "a legacy entry is never served with its shard round")
	require.True(t, sources.HasLegacy())

	var h [32]byte
	copy(h[:], hash)
	reader := &headerReader{fakeReader: &fakeReader{at: map[[32]byte]*vrhandoff.Output{}}, number: map[[32]byte]uint64{h: 3}, err: errors.New("header unavailable")}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	require.Error(t, o.Observe(context.Background(), cert(20, 9, 9)), "an unavailable header re-resolves nothing")
	_, ok = sources.Get(r)
	require.False(t, ok)

	reader.err = nil
	require.NoError(t, o.Observe(context.Background(), cert(21, 9, 9)))
	got, ok := sources.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 3, got.EVMBlockNumber, "the verified EVM height, not the shard round")
	require.False(t, sources.HasLegacy())

	// the file is now version 2, and a restarted root serves the same entry as the one that upgraded
	again, err := NewSources(path)
	require.NoError(t, err)
	got2, ok := again.Get(r)
	require.True(t, ok)
	require.Equal(t, got, got2)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"version": 2`)
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
