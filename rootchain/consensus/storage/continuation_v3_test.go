package storage_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
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

// contStub is a verified continuation entry whose properties are individually overridden over a real one, so that each guard of the
// constructor is exercised with every other property left true.
type contStub struct {
	storage.VerifiedContinuation
	record   func(*evmroot.OrderedHandoffRecord)
	epoch    *uint64
	start    *uint64
	rootOnly *bool
	commit   *[32]byte
}

func (s contStub) Handoff() (evmroot.VerifiedHandoff, evmroot.EpochGenesis, bool) {
	v, g, ok := s.VerifiedContinuation.Handoff()
	if s.record != nil {
		s.record(&v.Record)
	}
	return v, g, ok
}
func (s contStub) ActivationCommitID() [32]byte {
	if s.commit != nil {
		return *s.commit
	}
	v, _, ok := s.Handoff()
	if !ok {
		return s.VerifiedContinuation.ActivationCommitID()
	}
	var id [32]byte
	copy(id[:], v.Record.ID()) // the record the stub presents is the one its commit names, unless a test overrides it
	return id
}
func (s contStub) Epoch() uint64 {
	if s.epoch != nil {
		return *s.epoch
	}
	return s.VerifiedContinuation.Epoch()
}
func (s contStub) Start() uint64 {
	if s.start != nil {
		return *s.start
	}
	return s.VerifiedContinuation.Start()
}
func (s contStub) RootOnly() bool {
	if s.rootOnly != nil {
		return *s.rootOnly
	}
	return s.VerifiedContinuation.RootOnly()
}

func TestRequestContinuationRefusesEachBrokenLink(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	entry, genesis := verified(t, f)
	gid := genesis.BodyID()
	previous := anchorFor(t, f.ShardConf, genesis.Epoch(), gid[:])
	build := func(e storage.VerifiedContinuation) error {
		_, err := storage.RequestContinuationFromVerifiedV3(previous, e, nil, crypto.SHA256, 1)
		return err
	}
	require.NoError(t, build(contStub{VerifiedContinuation: entry}), "control: the stub with nothing overridden")

	t.Run("the record is not the one the entry's commit names", func(t *testing.T) {
		wrong := [32]byte{1}
		require.ErrorIs(t, build(contStub{VerifiedContinuation: entry, commit: &wrong}), storage.ErrRecordNotCommitted)
	})
	for name, mutate := range map[string]func(*evmroot.OrderedHandoffRecord){
		"a record of another next body": func(r *evmroot.OrderedHandoffRecord) { r.NextBodyID = bytes.Repeat([]byte{7}, 32) },
		"a record of another epoch":     func(r *evmroot.OrderedHandoffRecord) { r.Epoch++ },
		"a record of another boundary":  func(r *evmroot.OrderedHandoffRecord) { r.ActivationRound++ },
	} {
		t.Run(name, func(t *testing.T) {
			err := build(contStub{VerifiedContinuation: entry, record: mutate})
			require.ErrorIs(t, err, storage.ErrAssignmentHistory)
			require.ErrorContains(t, err, "does not describe the activation")
		})
	}
	t.Run("a record of another network", func(t *testing.T) {
		err := build(contStub{VerifiedContinuation: entry, record: func(r *evmroot.OrderedHandoffRecord) { r.Network++ }})
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
		require.ErrorContains(t, err, "does not follow the root interval")
	})
	t.Run("an activation that does not start after the previous interval", func(t *testing.T) {
		// the previous interval is the first continuation (start A*); the next entry claims the same first round
		second := q3fixture.New(t, q3fixture.Options{After: f})
		h, err := q3format.NewHistory(f.Old)
		require.NoError(t, err)
		next, err := h.VerifyEnvelope(f.Envelope)
		require.NoError(t, err)
		after, err := next.VerifyEnvelope(second.Envelope)
		require.NoError(t, err)
		first, err := storage.RequestContinuationFromVerifiedV3(previous, next.Tip(), nil, crypto.SHA256, 1)
		require.NoError(t, err)
		_, err = storage.RequestContinuationFromVerifiedV3(first, after.Tip(), nil, crypto.SHA256, 1)
		require.NoError(t, err, "control: the real next entry")
		start := next.Tip().Start()
		_, err = storage.RequestContinuationFromVerifiedV3(first, contStub{VerifiedContinuation: after.Tip(), start: &start,
			record: func(r *evmroot.OrderedHandoffRecord) { r.ActivationRound = start }}, nil, crypto.SHA256, 1)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
		require.ErrorContains(t, err, "does not follow the root interval")
	})
}

// A coupled entry's candidate is inspected for anything that touches the shard, each way alone.
func TestRequestContinuationRefusesACandidateThatTouchesTheShard(t *testing.T) {
	other := func(f *q3fixture.Fixture) (*types.PartitionDescriptionRecord, *types.PartitionDescriptionRecord) {
		current := otherShard(f)
		succ := *current
		succ.Epoch++
		return current, &succ
	}
	for name, tc := range map[string]struct {
		change func(f *q3fixture.Fixture) evmassign.Change
		want   string
	}{
		"an unsupported change kind": {func(*q3fixture.Fixture) evmassign.Change {
			return evmassign.Change{Kind: evmassign.ChangeSplitShard, Payload: []byte{1}}
		},
			"unsupported"},
		"a replacement of this shard's validators": {func(f *q3fixture.Fixture) evmassign.Change {
			cur, succ := other(f)
			ch, err := evmassign.EncodeReplaceShardValidators(cur.PartitionID, cur.ShardID, cur, succ, nil)
			require.NoError(t, err)
			return ch
		}, "replaces the validators of this shard"},
	} {
		t.Run(name, func(t *testing.T) {
			probe := q3fixture.New(t, q3fixture.Options{Assignment: true}) // the shape of the configuration the change names
			f := q3fixture.New(t, q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) {
				c.Changes = append(c.Changes, tc.change(probe))
			}})
			entry, genesis := verified(t, f)
			gid := genesis.BodyID()
			prev := anchorFor(t, otherShard(f), genesis.Epoch(), gid[:])
			_, err := storage.RequestContinuationFromVerifiedV3(prev, entry, f.Candidate, crypto.SHA256, 1)
			require.ErrorIs(t, err, storage.ErrAssignmentHistory)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
