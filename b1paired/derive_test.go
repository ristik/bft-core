package b1paired_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestOwnPairDerivationAndExactReplay(t *testing.T) {
	f := b1fixture.New(t, 0)
	ctx := context.Background()
	want, err := f.Pair.Derive(ctx, f.Parent, f.Observation)
	require.NoError(t, err)
	u, gas, err := b1state.Admit(want.Update, f.Pair.Profile, f.Pair.Profile.SystemGas)
	require.NoError(t, err)
	require.Equal(t, want.Hash, u.Hash())
	require.Equal(t, gas, want.AdmissionGas)
	require.EqualValues(t, 1, u.BlockNumber)
	require.Equal(t, [32]byte(f.Parent.ParentHash()), u.ParentHash)
	require.Empty(t, u.NewEntries)
	require.Nil(t, u.OldTipEnd)
	require.EqualValues(t, 1, u.PriorTipEpoch)
	for _, mode := range []string{"build", "import", "replay", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			got, err := f.Pair.Compare(ctx, f.Parent, f.Observation, want.Update, want.Hash[:])
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
	for _, field := range []string{"weight", "end", "config", "genesis", "profile", "parent", "height", "origin", "epoch", "prior-tip"} {
		t.Run(field, func(t *testing.T) {
			bad := u
			switch field {
			case "weight":
				bad.NewEntries = make([]b1state.Entry, 1)
			case "end":
				end := uint64(1)
				bad.OldTipEnd = &end
			case "config":
				bad.ExecutionChainID++
			case "genesis":
				bad.RootGenesisID[0] ^= 1
			case "profile":
				bad.ProfileHash[0] ^= 1
			case "parent":
				bad.ParentHash[0] ^= 1
			case "height":
				bad.BlockNumber++
			case "origin":
				bad.OriginIdentity[0] ^= 1
			case "epoch":
				bad.OriginEpoch++
			case "prior-tip":
				bad.PriorTipEpoch++
			}
			_, err := f.Pair.Compare(ctx, f.Parent, f.Observation, bad.Bytes(), want.Hash[:])
			require.ErrorIs(t, err, b1state.ErrBinding)
		})
	}
	_, err = f.Pair.Compare(ctx, f.Parent, f.Observation, want.Update, bytes.Repeat([]byte{1}, 32))
	require.ErrorIs(t, err, b1state.ErrBinding)
}
func TestPairRejectsMissingAuthorityAndParentProof(t *testing.T) {
	f := b1fixture.New(t, 1)
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		mutate      func(*b1paired.Config)
		parent      registryproof.Snapshot
		observation rootinput.VerifiedObservationV2
		want        error
	}{
		{"missing-runtime", func(c *b1paired.Config) { c.Authority = nil }, f.Parent, f.Observation, b1paired.ErrAdmission},
		{"unproven-parent", func(c *b1paired.Config) {}, registryproof.Snapshot{}, f.Observation, b1paired.ErrAdmission},
		{"unauthenticated-origin", func(c *b1paired.Config) {}, f.Parent, rootinput.VerifiedObservationV2{}, b1paired.ErrAdmission},
		{"missing-proof-source", func(c *b1paired.Config) { c.Proofs = nil }, f.Parent, f.Observation, b1paired.ErrAdmission},
		{"missing-proofs", func(c *b1paired.Config) {
			c.Proofs = func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error) { return nil, nil }
		}, f.Parent, f.Observation, registryproof.ErrStorageProof},
		{"unavailable", func(c *b1paired.Config) {
			c.Proofs = func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error) {
				return nil, errors.ErrUnsupported
			}
		}, f.Parent, f.Observation, errors.ErrUnsupported},
		{"profile-window", func(c *b1paired.Config) { c.Profile.WCert = 0 }, f.Parent, f.Observation, b1paired.ErrAdmission},
		{"invalid-profile", func(c *b1paired.Config) { c.Profile.SystemGas-- }, f.Parent, f.Observation, b1state.ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *f.Pair
			tc.mutate(&c)
			_, err := c.Derive(ctx, tc.parent, tc.observation)
			require.ErrorIs(t, err, tc.want)
		})
	}
	// Even a real proof for another addressed word cannot authenticate the expected member/key.
	c := *f.Pair
	c.Proofs = func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		p := f.Genesis.B1Proofs(keys)
		for i := range p {
			if len(p[i]) > 0 {
				p[i] = nil
				break
			}
		}
		return p, nil
	}
	_, err := c.Derive(ctx, f.Parent, f.Observation)
	require.ErrorIs(t, err, registryproof.ErrStorageProof)
}

func TestHonestBodyWithAttackerStorageIsRefused(t *testing.T) {
	f := b1fixture.New(t, 1)
	for _, tc := range []struct {
		name  string
		slot  [32]byte
		value [32]byte
	}{
		{"root-key", b1state.MemberSlot(1, 0, 5), [32]byte{2}},
		{"weight", b1state.MemberSlot(1, 0, 7), b1state.Word(2)},
		{"configuration", b1state.EntrySlot(1, 8), [32]byte{9}},
		{"end", b1state.EntrySlot(1, 5), b1state.Word(1)},
		{"queue", b1state.QueueSlot(0), b1state.Word(9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := f.Genesis.B1Words()
			words[common.Hash(tc.slot)] = common.Hash(tc.value)
			c, h, e, prove := b1fixture.Parent(t, f, words)
			parent, err := registryproof.Verify(c, h, e)
			require.NoError(t, err)
			pair := *f.Pair
			pair.Proofs = func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
				return prove(keys), nil
			}
			_, err = pair.Derive(context.Background(), parent, f.Observation)
			require.ErrorIs(t, err, b1state.ErrHistory)
		})
	}
}

func TestPairRechecksObservationUnderItsOwnRootCommittee(t *testing.T) {
	f := b1fixture.New(t, 0)
	attacker, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	attackerBase := testtrustbase.NewTrustBase(t, attacker).(*types.RootTrustBaseV1)
	full, err := f.Genesis.FullConfig()
	require.NoError(t, err)
	uc := f.Chain.CertifyFor(full, attacker, &types.InputRecord{Version: 1}, f.TR, 5)
	uc.UnicitySeal.NetworkID = 5
	uc.UnicitySeal.Signatures = nil
	verifier, err := attacker.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(key)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), attacker))
	forged, err := rootinput.AuthenticateObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardConfHash: f.Genesis.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: fixedTrust{attackerBase}}, uc, f.TR)
	require.NoError(t, err, "authenticated by a different configured committee")
	_, err = f.Pair.Derive(context.Background(), f.Parent, forged)
	require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
	foreign, err := q3active.New(q3active.Config{DB: memorydb.New(), Genesis: attackerBase})
	require.NoError(t, err)
	pair := *f.Pair
	pair.Authority = foreign.B1Authority()
	_, err = pair.Derive(context.Background(), f.Parent, f.Observation)
	require.ErrorIs(t, err, b1paired.ErrAdmission)
}

type fixedTrust struct{ tb *types.RootTrustBaseV1 }

func (f fixedTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return f.tb, nil
}

func TestParentCountClockAndHeightAreIndependentGates(t *testing.T) {
	f := b1fixture.New(t, 1)
	for _, tc := range []struct {
		name                        string
		number, round, epoch, count uint64
		want                        error
	}{
		{"count", 0, 0, 0, 2, b1paired.ErrAdmission},
		{"origin-epoch", 1, 4, 2, 1, b1paired.ErrAdmission},
		{"clock", 1, 6, 1, 1, b1state.ErrClock},
		{"height", ^uint64(0), 4, 1, 1, b1state.ErrOverflow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := f.Genesis.B1Words()
			set := func(name string, v uint64) {
				words[common.Hash(b1state.FixedSlot(name))] = common.Hash(b1state.Word(v))
			}
			set("b1.count", tc.count)
			if tc.number > 0 {
				set("clock.rootRound", tc.round)
				set("origin.rootEpoch", tc.epoch)
				set("round.authorized", 1)
				set("outcomes.round", 1)
				words[common.Hash(b1state.FixedSlot("outcomes.commitment"))] = common.Hash{9}
			}
			c, h, e, prove := b1fixture.ParentAt(t, f, words, tc.number)
			parent, err := registryproof.Verify(c, h, e)
			require.NoError(t, err)
			pair := *f.Pair
			pair.Proofs = func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
				return prove(keys), nil
			}
			_, err = pair.Derive(context.Background(), parent, f.Observation)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestProofFetcherCannotRewriteAdmissionKeys(t *testing.T) {
	f := b1fixture.New(t, 0)
	c, h, e, prove := b1fixture.Parent(t, f, f.Genesis.B1Words())
	parent, err := registryproof.Verify(c, h, e)
	require.NoError(t, err)
	pair := *f.Pair
	pair.Proofs = func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		for i := range keys {
			keys[i] = common.Hash{}
		}
		return prove(keys), nil
	}
	_, err = pair.Derive(context.Background(), parent, f.Observation)
	require.ErrorIs(t, err, registryproof.ErrStorageProof)
}

func TestEntryStorageRefusesInvalidAuthorityEntry(t *testing.T) {
	f := b1fixture.New(t, 0)
	entries, err := f.History.B1Entries(5)
	require.NoError(t, err)
	_, err = b1state.EntryStorage(entries[0])
	require.NoError(t, err)
	entries[0].Members[0].Weight = 0
	_, err = b1state.EntryStorage(entries[0])
	require.ErrorIs(t, err, b1state.ErrMembers)
}

func TestBootstrapInstallsAuthorityBeforeOperationalClock(t *testing.T) {
	f := b1fixture.NewWithRootStart(t, 0, 2)
	require.Zero(t, f.Parent.Fields().ClockRootRound)
	require.NoError(t, f.History.Ordinary(1, 5))
	result, err := f.Pair.Derive(context.Background(), f.Parent, f.Observation)
	require.NoError(t, err)
	_, _, err = b1state.Admit(result.Update, f.Pair.Profile, f.Pair.Profile.SystemGas)
	require.NoError(t, err)
}
