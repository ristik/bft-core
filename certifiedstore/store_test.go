package certifiedstore

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestPublishAndReloadAcrossReopen(t *testing.T) {
	f := newFixture(t, 3)
	path := tempDB(t)

	s, err := Open(path, Settings{Retain: 8})
	require.NoError(t, err)
	f.publishChain(s, 3)
	require.NoError(t, s.Close())

	reopened := f.open(path, 8)
	l, err := reopened.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	b := f.blocks[3]
	require.Equal(t, b.Hash, l.BlockHash())
	require.Equal(t, b.Number, l.BlockNumber())
	require.Equal(t, b.StateRoot, l.StateRoot())
	require.Equal(t, b.Round, l.PartitionRound())
	require.Equal(t, b.Round, l.Snapshot().Fields().RoundAuthorized)
	uc, err := l.Certificate()
	require.NoError(t, err)
	require.Equal(t, b.Hash.Bytes(), []byte(uc.InputRecord.BlockHash))
	tr, err := l.Technical()
	require.NoError(t, err)
	require.Equal(t, b.Round+1, tr.Round)

	w := l.Witness()
	w.Header[0] ^= 0xff
	require.Equal(t, b.Evidence.Header, l.Witness().Header, "the witness accessor returns a copy")
}

func TestGenesisRecordReloads(t *testing.T) {
	f := newFixture(t, 0)
	s := f.open(tempDB(t), 4)
	require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(0)))
	l, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(0), l.BlockNumber())
	require.True(t, l.Snapshot().Genesis())
	uc, err := l.Certificate()
	require.NoError(t, err)
	require.Empty(t, uc.InputRecord.BlockHash, "the genesis certificate names no block")

	advanced := f.recordWith(0, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
		ir.RoundNumber, tr.Round, r.PartitionRound = 3, 4, 3
	})
	require.NoError(t, s.Publish(context.Background(), f.ctx, advanced), "quiet genesis history advances the certificate round without executing a block")
	l, err = s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(3), l.PartitionRound())
	require.Equal(t, uint64(0), l.Snapshot().Fields().RoundAuthorized)
}

func TestAuthenticatedRootEpochIsBoundToConfiguration(t *testing.T) {
	f := newFixture(t, 2)
	stranger, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	c := f.ctx
	c.TrustBases = multiTrust{f.trust.tb, mustTrustBaseAtEpoch(t, f, 2)}
	atRootEpoch2 := func(signer abcrypto.Signer) Record {
		return f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
			r.Certificate = f.reseal(f.certify(f.signer, ir, tr, 6), 2, signer)
		})
	}
	cases := map[string]struct {
		record Record
		want   error
	}{
		"an authenticated certificate at another root epoch": {atRootEpoch2(f.signer), ErrEpoch},
		"a forged certificate at another root epoch":         {atRootEpoch2(stranger), ErrCertificate},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := f.open(tempDB(t), 4)
			for i := 0; i <= 1; i++ {
				require.NoError(t, s.Publish(context.Background(), c, f.record(i)), "the configured root epoch is accepted with several trust bases")
			}
			before := contents(t, s)
			err := s.Publish(context.Background(), c, tc.record)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, contents(t, s), "a refused publication changes nothing")

			enc, _, err := encodeRecord(c, tc.record)
			require.NoError(t, err)
			putRaw(t, s, string(recordKey(f.record(1))), enc)
			_, err = s.Load(context.Background(), c)
			require.ErrorIs(t, err, tc.want, "the same record stored directly is refused on load")
		})
	}
}

type fixedEpochAuthority struct {
	epoch uint64
	ready bool
}

func (a fixedEpochAuthority) CurrentRootEpoch() (uint64, bool) { return a.epoch, a.ready }

func TestCertifiedRecordRequiresInstalledRootEpoch(t *testing.T) {
	f := newFixture(t, 2)
	base := f.ctx
	base.TrustBases = multiTrust{f.trust.tb, mustTrustBaseAtEpoch(t, f, 2)}
	newEpoch := f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
		r.Certificate = f.reseal(f.certify(f.signer, ir, tr, 6), 2, f.signer)
	})
	for _, tc := range []struct {
		name      string
		context   Context
		record    Record
		wantError error
	}{
		{"installed successor", func() Context { c := base; c.EpochAuthority = fixedEpochAuthority{2, true}; return c }(), newEpoch, nil},
		{"successor not installed", func() Context { c := base; c.EpochAuthority = fixedEpochAuthority{1, true}; return c }(), newEpoch, ErrEpoch},
		{"authority not ready", func() Context { c := base; c.EpochAuthority = fixedEpochAuthority{2, false}; return c }(), f.record(2), ErrEpoch},
		{"authority below configured origin", func() Context { c := base; c.EpochAuthority = fixedEpochAuthority{0, true}; return c }(), f.record(2), ErrEpoch},
		{"certificate before configured origin", func() Context {
			c := base
			c.Registry.RootEpoch = 2
			c.EpochAuthority = fixedEpochAuthority{3, true}
			return c
		}(), f.record(2), ErrEpoch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, encoded, err := encodeRecord(tc.context, tc.record)
			require.NoError(t, err)
			_, err = verify(context.Background(), tc.context, encoded)
			if tc.wantError == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantError)
			}
		})
	}
}

func TestPublishRefusesARecordThatDoesNotVerify(t *testing.T) {
	f := newFixture(t, 2)
	other := newFixtureFor(t, 4, 2)
	stranger, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)

	cases := map[string]struct {
		record Record
		want   error
	}{
		"another block's witness": {f.recordWith(2, func(_ *types.InputRecord, _ *certification.TechnicalRecord, r *Record) {
			r.Witness = f.blocks[1].Evidence
		}), ErrWitness},
		"a certificate the configured root chain did not sign": {f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
			r.Certificate = f.certify(stranger, ir, tr, 6)
		}), ErrCertificate},
		"a record for another deployment's configuration": {other.record(2), ErrWrongContext},
		"a technical record the certificate does not commit to": {f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
			r.Certificate = f.certify(f.signer, ir, tr, 6)
			r.Technical = technicalFor(9)
		}), ErrTechnicalRecord},
		"an ordinary record whose certificate names no block": {f.recordWith(2, func(ir *types.InputRecord, _ *certification.TechnicalRecord, _ *Record) {
			ir.PreviousHash, ir.BlockHash = ir.Hash, nil
		}), ErrWrongBlock},
		"a genesis record whose certificate names a block": {f.recordWith(0, func(ir *types.InputRecord, _ *certification.TechnicalRecord, _ *Record) {
			ir.PreviousHash, ir.BlockHash = common.Hash{9}.Bytes(), f.blocks[0].Hash.Bytes()
		}), ErrWrongBlock},
		"a block-0 record for a header other than the configured EVM genesis": {f.recordWith(0, func(_ *types.InputRecord, _ *certification.TechnicalRecord, r *Record) {
			r.BlockHash, r.Witness.Header = f.genesisHeaderVariant()
		}), ErrWrongBlock},
		"an authenticated input record for another shard epoch": {f.recordWith(2, func(ir *types.InputRecord, _ *certification.TechnicalRecord, _ *Record) {
			ir.Epoch = 9
		}), ErrEpoch},
		"an authenticated technical record for another shard epoch": {f.recordWith(2, func(_ *types.InputRecord, tr *certification.TechnicalRecord, _ *Record) {
			tr.Epoch = 9
		}), ErrEpoch},
		"an authenticated certificate and technical record for another shard epoch": {f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, _ *Record) {
			ir.Epoch, tr.Epoch = 9, 9
		}), ErrEpoch},
		"a certified round other than the round the witness executed": {f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
			ir.RoundNumber, tr.Round, r.PartitionRound = 9, 10, 9
		}), ErrWrongRound},
		"a record with no certificate": {Record{BlockHash: f.blocks[2].Hash, BlockNumber: 2, StateRoot: f.blocks[2].StateRoot, PartitionRound: 2}, ErrWrongBlock},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := f.open(tempDB(t), 4)
			f.publishChain(s, 1)
			before := contents(t, s)
			err := s.Publish(context.Background(), f.ctx, tc.record)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, contents(t, s), "a refused publication changes nothing")
			l, err := s.Load(context.Background(), f.ctx)
			require.NoError(t, err)
			require.Equal(t, uint64(1), l.BlockNumber())
		})
	}
}

func TestLoadRefusalsAndNoFallback(t *testing.T) {
	f := newFixture(t, 2)
	other := newFixtureFor(t, 4, 2)
	headKeyFor := func(i int) string { return string(recordKey(f.record(i))) }
	// storeAsHead writes r, encoded with a valid digest but not verified, under the head record's key.
	storeAsHead := func(t *testing.T, s *Store, r Record) {
		enc, _, err := encodeRecord(f.ctx, r)
		require.NoError(t, err)
		putRaw(t, s, headKeyFor(2), enc)
	}

	cases := map[string]struct {
		damage func(t *testing.T, s *Store)
		ctx    func() Context
		want   error
	}{
		"the head names a record that is not there": {damage: func(t *testing.T, s *Store) { deleteRaw(t, s, headKeyFor(2)) }, want: ErrRecordUntrusted},
		"a bit flipped in the stored record": {damage: func(t *testing.T, s *Store) {
			raw := contents(t, s)[headKeyFor(2)]
			raw[len(raw)/2] ^= 0x01
			putRaw(t, s, headKeyFor(2), raw)
		}, want: ErrRecordUntrusted},
		"a truncated record": {damage: func(t *testing.T, s *Store) {
			raw := contents(t, s)[headKeyFor(2)]
			putRaw(t, s, headKeyFor(2), raw[:len(raw)/2])
		}, want: ErrRecordUntrusted},
		"an oversized stored value": {damage: func(t *testing.T, s *Store) {
			putRaw(t, s, headKeyFor(2), make([]byte, MaxRecordBytes+1))
		}, want: ErrRecordUntrusted},
		"an oversized envelope that would otherwise decode": {damage: func(t *testing.T, s *Store) {
			putRaw(t, s, headKeyFor(2), envelopeWith(t, RecordVersion+1, make([]byte, MaxRecordBytes)))
		}, want: ErrRecordUntrusted},
		"a payload version that differs from its envelope": {damage: func(t *testing.T, s *Store) {
			sr, err := decodeRecord(contents(t, s)[headKeyFor(2)])
			require.NoError(t, err)
			sr.Version = RecordVersion + 1
			payload, err := types.Cbor.Marshal(sr)
			require.NoError(t, err)
			putRaw(t, s, headKeyFor(2), envelopeWith(t, RecordVersion, payload))
		}, want: ErrRecordUntrusted},
		"a future envelope version": {damage: func(t *testing.T, s *Store) {
			putRaw(t, s, headKeyFor(2), envelopeWith(t, RecordVersion+1, []byte{0xff}))
		}, want: ErrRecordVersion},
		"a record for another deployment": {damage: func(t *testing.T, s *Store) {
			enc, _, err := encodeRecord(other.ctx, other.record(2))
			require.NoError(t, err)
			putRaw(t, s, headKeyFor(2), enc)
		}, want: ErrWrongContext},
		"a stored context naming another network, with a certificate and witness that still verify": {damage: func(t *testing.T, s *Store) {
			raw := contents(t, s)[headKeyFor(2)]
			putRaw(t, s, headKeyFor(2), reencode(t, raw, func(sr *storedRecord) { sr.Context.NetworkID++ }))
		}, want: ErrWrongContext},
		"an authenticated input record for another shard epoch, stored directly": {damage: func(t *testing.T, s *Store) {
			storeAsHead(t, s, f.recordWith(2, func(ir *types.InputRecord, _ *certification.TechnicalRecord, _ *Record) { ir.Epoch = 9 }))
		}, want: ErrEpoch},
		"an authenticated technical record for another shard epoch, stored directly": {damage: func(t *testing.T, s *Store) {
			storeAsHead(t, s, f.recordWith(2, func(_ *types.InputRecord, tr *certification.TechnicalRecord, _ *Record) { tr.Epoch = 9 }))
		}, want: ErrEpoch},
		"a certified round other than the round the witness executed, stored directly": {damage: func(t *testing.T, s *Store) {
			storeAsHead(t, s, f.recordWith(2, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
				ir.RoundNumber, tr.Round, r.PartitionRound = 9, 10, 9
			}))
		}, want: ErrWrongRound},
		"the witness of another block": {damage: func(t *testing.T, s *Store) {
			raw := contents(t, s)[headKeyFor(2)]
			putRaw(t, s, headKeyFor(2), reencode(t, raw, func(sr *storedRecord) {
				ev := f.blocks[1].Evidence
				sr.WitnessHeader, sr.WitnessAccount, sr.WitnessStorage = ev.Header, ev.AccountProof, ev.StorageProofs
			}))
		}, want: ErrWitness},
		"a technical record the certificate does not commit to": {damage: func(t *testing.T, s *Store) {
			raw := contents(t, s)[headKeyFor(2)]
			tr, err := types.Cbor.Marshal(technicalFor(9))
			require.NoError(t, err)
			putRaw(t, s, headKeyFor(2), reencode(t, raw, func(sr *storedRecord) { sr.Technical = tr }))
		}, want: ErrTechnicalRecord},
		"a record claiming another height": {damage: func(t *testing.T, s *Store) {
			raw := contents(t, s)[headKeyFor(2)]
			putRaw(t, s, headKeyFor(2), reencode(t, raw, func(sr *storedRecord) { sr.BlockNumber = 7 }))
		}, want: ErrWrongBlock},
		"the configured trust base has no such root epoch": {ctx: func() Context {
			c := f.ctx
			c.TrustBases = trustStore{tb: mustTrustBaseAtEpoch(t, f, 2)}
			return c
		}, want: ErrCertificate},
		"a configuration with a malformed shard configuration hash": {ctx: func() Context {
			c := f.ctx
			c.FullShardConfHash = c.FullShardConfHash[:31]
			return c
		}, want: ErrConfig},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := tempDB(t)
			s := f.open(path, 4)
			f.publishChain(s, 2)
			if tc.damage != nil {
				tc.damage(t, s)
			}
			ctx := f.ctx
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			before := contents(t, s)
			_, err := s.Load(context.Background(), ctx)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, contents(t, s), "a refused load changes nothing")
			_, older := contents(t, s)[headKeyFor(1)]
			require.True(t, older, "premise: an older record was there to substitute, and was not used")
		})
	}
	t.Run("an empty store has no record", func(t *testing.T) {
		s := f.open(tempDB(t), 4)
		_, err := s.Load(context.Background(), f.ctx)
		require.ErrorIs(t, err, ErrNoRecord)
	})
}

// mustTrustBaseAtEpoch returns a trust base store keyed to another epoch, so the certificate's epoch 1 has
// no configured trust base.
func mustTrustBaseAtEpoch(t *testing.T, f *fixture, epoch uint64) *types.RootTrustBaseV1 {
	tb := *f.trust.tb
	tb.Epoch = epoch
	return &tb
}

func TestRetentionIsBoundedAndTransactional(t *testing.T) {
	f := newFixture(t, 5)
	keysAfter := func(retain, upTo int) []string {
		s := f.open(tempDB(t), retain)
		f.publishChain(s, upTo)
		return keysOf(contents(t, s))
	}
	key := func(i int) string { return string(recordKey(f.record(i))) }

	require.Equal(t, []string{"head", key(4), key(5), "record/genesis"}, keysAfter(2, 5))
	require.Equal(t, []string{"head", key(5), "record/genesis"}, keysAfter(1, 5))
	require.Equal(t, []string{"head", key(1), key(2), key(3), key(4), key(5), "record/genesis"}, keysAfter(8, 5))

	t.Run("republishing the current record does not delete it", func(t *testing.T) {
		s := f.open(tempDB(t), 1)
		f.publishChain(s, 2)
		require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(2)))
		require.Equal(t, []string{"head", key(2), "record/genesis"}, keysOf(contents(t, s)))
		_, err := s.Load(context.Background(), f.ctx)
		require.NoError(t, err)
	})
	t.Run("the genesis record is never deleted", func(t *testing.T) {
		require.Contains(t, keysAfter(1, 5), "record/genesis")
	})
	t.Run("settings are validated", func(t *testing.T) {
		for _, retain := range []int{0, -1, MaxRetain + 1} {
			_, err := Open(tempDB(t), Settings{Retain: retain})
			require.ErrorIs(t, err, ErrSettings)
		}
	})
}

func TestTheStoreHoldsNoSigningState(t *testing.T) {
	forbidden := []string{"sign", "key", "generation", "reserv", "session", "journal", "vote", "cursor"}
	for _, typ := range []reflect.Type{reflect.TypeOf(storedRecord{}), reflect.TypeOf(storedContext{}), reflect.TypeOf(Record{}), reflect.TypeOf(Settings{})} {
		for i := 0; i < typ.NumField(); i++ {
			lower := strings.ToLower(typ.Field(i).Name)
			for _, word := range forbidden {
				require.NotContains(t, lower, word, "%s.%s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	f := newFixture(t, 2)
	s := f.open(tempDB(t), 4)
	f.publishChain(s, 2)
	for _, k := range keysOf(contents(t, s)) {
		require.True(t, k == "head" || strings.HasPrefix(k, "record/"), "unexpected key %q", k)
	}
}

func TestLoadedIsOpaque(t *testing.T) {
	typ := reflect.TypeOf(Loaded{})
	for i := 0; i < typ.NumField(); i++ {
		require.False(t, typ.Field(i).IsExported(), "Loaded.%s", typ.Field(i).Name)
	}
	var zero Loaded
	_, err := zero.Certificate()
	require.True(t, err != nil || errors.Is(err, nil), "the zero value decodes nothing useful")
}
