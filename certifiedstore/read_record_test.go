package certifiedstore

import (
	"context"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

func TestReadRecordReturnsVerifiedRetainedRecord(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 3)
	path := tempDB(t)
	s := f.open(path, 8)
	f.publishChain(s, 3)
	before := contents(t, s)

	got, err := s.ReadRecord(ctx, f.ctx, f.blocks[1].Round, f.blocks[1].Hash)
	require.NoError(t, err)
	require.Equal(t, f.blocks[1].Hash, got.BlockHash())
	require.Equal(t, f.blocks[1].Number, got.BlockNumber())
	require.Equal(t, f.blocks[1].Round, got.PartitionRound())
	require.Equal(t, before, contents(t, s), "a historical read changes neither the head nor retained records")

	w := got.Witness()
	w.Header[0] ^= 0xff
	require.Equal(t, f.blocks[1].Evidence.Header, got.Witness().Header, "the result owns its witness bytes")

	require.NoError(t, s.Close())
	reopened, err := Open(path, Settings{Retain: 8})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	got, err = reopened.ReadRecord(ctx, f.ctx, f.blocks[1].Round, f.blocks[1].Hash)
	require.NoError(t, err)
	require.Equal(t, f.blocks[1].Hash, got.BlockHash())
}

func TestReadRecordGenesisUsesConfiguredHashAndChecksRound(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 0)
	s := f.open(tempDB(t), 4)
	advanced := f.recordWith(0, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
		ir.RoundNumber, tr.Round, r.PartitionRound = 3, 4, 3
	})
	require.NoError(t, s.Publish(ctx, f.ctx, advanced))

	got, err := s.ReadRecord(ctx, f.ctx, 3, f.ctx.Registry.EVMGenesisHash)
	require.NoError(t, err)
	require.Zero(t, got.BlockNumber())
	require.Equal(t, uint64(3), got.PartitionRound())

	_, err = s.ReadRecord(ctx, f.ctx, 2, f.ctx.Registry.EVMGenesisHash)
	require.ErrorIs(t, err, ErrWrongRound, "a found verified genesis record contradicting the exact request is invalid")
	_, err = s.ReadRecord(ctx, f.ctx, 3, common.HexToHash("0x1234"))
	require.ErrorIs(t, err, ErrNoRecord, "another hash is an ordinary missing locator, not a genesis alias")
}

func TestReadRecordUnavailableLocatorsAndInvalidConfiguration(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 3)
	s := f.open(tempDB(t), 1)
	f.publishChain(s, 3)
	before := contents(t, s)

	for name, locator := range map[string]struct {
		round uint64
		hash  common.Hash
	}{
		"evicted":    {f.blocks[1].Round, f.blocks[1].Hash},
		"wrong hint": {99, f.blocks[3].Hash},
		"wrong hash": {f.blocks[3].Round, common.HexToHash("0x1234")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.ReadRecord(ctx, f.ctx, locator.round, locator.hash)
			require.ErrorIs(t, err, ErrNoRecord)
			require.Equal(t, before, contents(t, s))
		})
	}

	bad := f.ctx
	bad.FullShardConfHash = nil
	_, err := s.ReadRecord(ctx, bad, 99, common.HexToHash("0x1234"))
	require.ErrorIs(t, err, ErrConfig, "configuration is checked before a missing key is called unavailable")
	_, err = s.ReadRecord(ctx, f.ctx, 1, common.Hash{})
	require.ErrorIs(t, err, ErrWrongBlock)

	require.NoError(t, s.Close())
	_, err = s.ReadRecord(ctx, f.ctx, f.blocks[3].Round, f.blocks[3].Hash)
	require.ErrorIs(t, err, bolt.ErrDatabaseNotOpen, "backend read failures keep their cause")
}

func TestReadRecordRefusesInvalidCandidateWithoutChangingStore(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		install func(t *testing.T, f *fixture, s *Store) (uint64, common.Hash)
		want    error
	}{
		"authentic alias": {
			install: func(t *testing.T, f *fixture, s *Store) (uint64, common.Hash) {
				raw := contents(t, s)[string(recordKey(f.record(1)))]
				h := common.HexToHash("0xa11a5")
				putRaw(t, s, string(keyFor(1, 1, h[:])), raw)
				return 1, h
			},
			want: ErrRecordUntrusted,
		},
		"corrupt value": {
			install: func(t *testing.T, f *fixture, s *Store) (uint64, common.Hash) {
				key := string(recordKey(f.record(1)))
				raw := contents(t, s)[key]
				raw[len(raw)/2] ^= 1
				putRaw(t, s, key, raw)
				return f.blocks[1].Round, f.blocks[1].Hash
			},
			want: ErrRecordUntrusted,
		},
		"oversized value": {
			install: func(t *testing.T, f *fixture, s *Store) (uint64, common.Hash) {
				putRaw(t, s, string(recordKey(f.record(1))), make([]byte, MaxRecordBytes+1))
				return f.blocks[1].Round, f.blocks[1].Hash
			},
			want: ErrRecordUntrusted,
		},
		"foreign context": {
			install: func(t *testing.T, f *fixture, s *Store) (uint64, common.Hash) {
				other := newFixtureFor(t, 4, 1)
				enc, _, err := encodeRecord(other.ctx, other.record(1))
				require.NoError(t, err)
				putRaw(t, s, string(recordKey(other.record(1))), enc)
				return other.blocks[1].Round, other.blocks[1].Hash
			},
			want: ErrWrongContext,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			s := f.open(tempDB(t), 8)
			f.publishChain(s, 1)
			round, hash := tc.install(t, f, s)
			before := contents(t, s)
			_, err := s.ReadRecord(ctx, f.ctx, round, hash)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, contents(t, s), "a refused read changes neither head nor records")
		})
	}
}

func TestReadRecordConcurrentEvictionIsAtomic(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 2)

	for i := 0; i < 32; i++ {
		s := f.open(tempDB(t), 1)
		f.publishChain(s, 1)
		var got Loaded
		var readErr, writeErr error
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			got, readErr = s.ReadRecord(ctx, f.ctx, f.blocks[1].Round, f.blocks[1].Hash)
		}()
		go func() {
			defer wg.Done()
			<-start
			writeErr = s.Publish(ctx, f.ctx, f.record(2))
		}()
		close(start)
		wg.Wait()
		require.NoError(t, writeErr)

		if readErr == nil {
			require.Equal(t, f.blocks[1].Hash, got.BlockHash())
			require.Equal(t, f.blocks[1].Evidence.Header, got.Witness().Header,
				"a value copied before eviction remains owned and verified")
		} else {
			require.ErrorIs(t, readErr, ErrNoRecord, "eviction may win before the bounded read")
		}
		require.NoError(t, s.Close())
	}
}
