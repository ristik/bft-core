package storage_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

// otherShard is the fixture's configuration as the genesis configuration of a shard the activation does not touch.
func otherShard(f *q3fixture.Fixture) *types.PartitionDescriptionRecord {
	cp := *f.ShardConf
	cp.PartitionID++
	return &cp
}

func anchorFor(t *testing.T, conf *types.PartitionDescriptionRecord, genesisEpoch uint64, genesisBody []byte) *storage.RequestActivation {
	t.Helper()
	a, err := storage.NewRequestAnchor(conf, crypto.SHA256, genesisEpoch, genesisBody, 1)
	require.NoError(t, err)
	return a
}

// A continuation is the previous activation's assignment under the next root authorization interval, issued only for an activation that
// provably leaves the shard unchanged.
func TestRequestContinuationIsIssuedOnlyForAnActivationThatLeavesTheShardUnchanged(t *testing.T) {
	t.Run("a root-only activation continues every shard without a retained candidate", func(t *testing.T) {
		f := q3fixture.New(t, q3fixture.Options{})
		entry, genesis := verified(t, f)
		gid := genesis.BodyID()
		anchor := anchorFor(t, f.ShardConf, genesis.Epoch(), gid[:])
		cont, err := storage.RequestContinuationFromVerifiedV3(anchor, entry, nil, crypto.SHA256, 1)
		require.NoError(t, err)
		id := entry.BodyID()
		require.Equal(t, id[:], cont.RootBody())
		require.Equal(t, anchor.PDRHash(), cont.PDRHash(), "the configuration is the previous one")
	})

	t.Run("a coupled activation continues a shard it does not designate", func(t *testing.T) {
		f := q3fixture.New(t, q3fixture.Options{Assignment: true})
		entry, genesis := verified(t, f)
		gid := genesis.BodyID()
		other := anchorFor(t, otherShard(f), genesis.Epoch(), gid[:])
		cont, err := storage.RequestContinuationFromVerifiedV3(other, entry, f.Candidate, crypto.SHA256, 1)
		require.NoError(t, err)
		id := entry.BodyID()
		require.Equal(t, id[:], cont.RootBody())

		// the designated shard is changed by it: no continuation
		designated := anchorFor(t, f.ShardConf, genesis.Epoch(), gid[:])
		_, err = storage.RequestContinuationFromVerifiedV3(designated, entry, f.Candidate, crypto.SHA256, 1)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
		require.ErrorContains(t, err, "changes the assignment of this shard")

		// missing candidate bytes are not evidence of non-change
		_, err = storage.RequestContinuationFromVerifiedV3(other, entry, nil, crypto.SHA256, 1)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
		// and a candidate that is not the committed one is refused
		tampered := bytes.Clone(f.Candidate)
		tampered[len(tampered)/2] ^= 1
		_, err = storage.RequestContinuationFromVerifiedV3(other, entry, tampered, crypto.SHA256, 1)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	})

	t.Run("the linkage is checked, each way alone", func(t *testing.T) {
		f := q3fixture.New(t, q3fixture.Options{})
		entry, genesis := verified(t, f)
		gid := genesis.BodyID()
		good := anchorFor(t, f.ShardConf, genesis.Epoch(), gid[:])
		_, err := storage.RequestContinuationFromVerifiedV3(good, entry, nil, crypto.SHA256, 1)
		require.NoError(t, err, "control")

		for name, tc := range map[string]struct {
			previous *storage.RequestActivation
			entry    storage.VerifiedContinuation
			version  uint64
		}{
			"a previous interval of another root body":    {anchorFor(t, f.ShardConf, genesis.Epoch(), bytes.Repeat([]byte{9}, 32)), entry, 1},
			"a previous interval that is not adjacent":    {anchorFor(t, f.ShardConf, genesis.Epoch()+5, gid[:]), entry, 1},
			"another request protocol version":            {good, entry, 2},
			"a genesis entry, which is not an activation": {good, genesis, 1},
			"no previous interval":                        {nil, entry, 1},
			"no entry":                                    {good, nil, 1},
		} {
			_, err := storage.RequestContinuationFromVerifiedV3(tc.previous, tc.entry, nil, crypto.SHA256, tc.version)
			require.Error(t, err, name)
			if name != "no previous interval" && name != "no entry" {
				require.ErrorIs(t, err, storage.ErrAssignmentHistory, name)
			}
		}
	})
}
