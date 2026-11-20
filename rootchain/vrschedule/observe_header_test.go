package vrschedule

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
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
