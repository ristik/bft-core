package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"testing"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestRecoverySourceReadsAndVerifiesCertifiedArchiveSuffix(t *testing.T) {
	f := newWiringFixture(t, 1)
	q, rec := f.record(t, 0)
	first := f.entries[0].Candidate
	genesis := shardnode.BlockRef{Number: first.ParentNumber, Hash: first.ParentHash, StateRoot: first.ParentState}
	target := q.BlockHash[:]

	t.Run("archive entry accepted", func(t *testing.T) {
		local, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		require.NoError(t, local.Put(q, rec))
		source := &RecoverySource{Context: f.context, Subject: f.subject, Local: local, Limits: DefaultLimits(), MaxBlocks: 8}
		entries, err := source.FetchSuffix(context.Background(), genesis, target)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.True(t, bytes.Equal(q.BlockHash[:], entries[0].Block.Hash))
		require.True(t, bytes.Equal(recHeaderRoot(t, rec), entries[0].Block.StateRoot))
	})

	t.Run("tampered certificate refused", func(t *testing.T) {
		local, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		altered := *rec

		var result types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &result))
		result.InputRecord.Hash[0] ^= 0xff
		altered.ResultingUC, err = types.Cbor.Marshal(&result)
		require.NoError(t, err)
		require.NoError(t, local.Put(q, &altered))
		source := &RecoverySource{Context: f.context, Subject: f.subject, Local: local, Limits: DefaultLimits(), MaxBlocks: 8}
		_, err = source.FetchSuffix(context.Background(), genesis, target)
		require.ErrorIs(t, err, ErrArchiveRecoveryInvalid)
	})

	t.Run("missing record is retryable unavailable", func(t *testing.T) {
		local, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		source := &RecoverySource{Context: f.context, Subject: f.subject, Local: local, Limits: DefaultLimits(), MaxBlocks: 8}
		_, err = source.FetchSuffix(context.Background(), genesis, target)
		require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
		// The source reports availability only; it never mutates journal state.
		require.False(t, errors.Is(err, ErrArchiveRecoveryInvalid))
	})
}

func recHeaderRoot(t *testing.T, rec *archive.Record) []byte {
	t.Helper()
	var h gethtypes.Header
	if err := rlp.DecodeBytes(rec.Header, &h); err != nil {
		t.Fatal(err)
	}
	return h.Root.Bytes()
}
