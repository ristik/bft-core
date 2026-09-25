package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

type rejectingBinding struct{}

func (rejectingBinding) VerifyCertified(frontier.Record, *archive.Record) error {
	return frontier.ErrInvalid
}

type rejectingAvailability struct{}

func (rejectingAvailability) VerifyAvailable(string, archive.Request, [32]byte) error {
	return frontier.ErrUnavailable
}

func TestFrontierIsolatedAdvanceGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Store, *frontier.Coverage)
		want   error
	}{
		{"missing binding", func(s *Store, _ *frontier.Coverage) { s.frontier.Binding = nil }, frontier.ErrAcknowledgment},
		{"certified binding", func(s *Store, _ *frontier.Coverage) { s.frontier.Binding = rejectingBinding{} }, frontier.ErrInvalid},
		{"replica read back", func(s *Store, _ *frontier.Coverage) { s.frontier.Availability = rejectingAvailability{} }, frontier.ErrAcknowledgment},
		{"ack manifest", func(_ *Store, c *frontier.Coverage) {
			c.Anchor.Acks[0].ManifestDigest[0] ^= 1
			c.Anchor.Acks[1].ManifestDigest = c.Anchor.Acks[0].ManifestDigest
		}, frontier.ErrAcknowledgment},
		{"ack request", func(_ *Store, c *frontier.Coverage) { c.Anchor.Acks[0].RequestDigest[0] ^= 1 }, frontier.ErrAcknowledgment},
		{"coverage height", func(_ *Store, c *frontier.Coverage) { c.Anchor.Height++ }, frontier.ErrAcknowledgment},
		{"certified association", func(_ *Store, c *frontier.Coverage) {
			var original types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(c.Material.ResultingUC, &original))
			f := newFixture(t, 0)
			alternate := f.observation(original.InputRecord, 2, 6)
			c.Material.ResultingUC, _ = types.Cbor.Marshal(alternate.Certificate())
			c.Anchor.Round = 6
			digest, _ := archive.ManifestDigest(c.Anchor.Subject, c.Material)
			c.Anchor.Acks[0].ManifestDigest, c.Anchor.Acks[1].ManifestDigest = digest, digest
		}, frontier.ErrInvalid},
		{"parent link", func(_ *Store, c *frontier.Coverage) {
			var header gethtypes.Header
			_ = rlp.DecodeBytes(c.Material.Header, &header)
			header.ParentHash[0] ^= 1
			c.Material.Header, _ = rlp.EncodeToBytes(&header)
			c.Anchor.Subject.BlockHash = [32]byte(header.Hash())
			req, _ := archive.EncodeRequest(c.Anchor.Subject)
			ack := sha256.Sum256(req)
			digest, _ := archive.ManifestDigest(c.Anchor.Subject, c.Material)
			for i := range c.Anchor.Acks {
				c.Anchor.Acks[i].RequestDigest, c.Anchor.Acks[i].ManifestDigest = ack, digest
			}
		}, frontier.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
			defer s.Close()
			tc.mutate(s, &item)
			require.ErrorIs(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}), tc.want)
			image, err := s.LoadJournal(context.Background(), c, limits)
			require.NoError(t, err)
			require.Nil(t, image.Frontier)
			require.Len(t, image.Candidates, 1)
		})
	}
}

func TestFrontierRefusesCorruptAndStaleStoredAnchor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*bolt.Bucket) error
		want   error
	}{
		{"checksum", func(b *bolt.Bucket) error {
			raw := bytes.Clone(b.Get(journalFrontierKey))
			raw[len(raw)-1] ^= 1
			return b.Put(journalFrontierKey, raw)
		}, ErrUntrusted},
		{"floor beyond anchor", func(b *bolt.Bucket) error {
			var w journalFrontierWire
			payload, err := decodeEnvelope(b.Get(journalFrontierKey), journalFrontierKind, archive.MaxWireBytes+frontier.MaxBytes+4096)
			if err != nil {
				return err
			}
			if err = decodePayload(payload, &w); err != nil {
				return err
			}
			floor, err := encodeFloor(journalFloorWire{Version: journalVersion, Descriptor: w.Descriptor, Sequence: 2, Round: 2, Height: 2})
			if err != nil {
				return err
			}
			return b.Put(journalFloorKey, floor)
		}, frontier.ErrStale},
		{"copied descriptor", func(b *bolt.Bucket) error {
			payload, err := decodeEnvelope(b.Get(journalFrontierKey), journalFrontierKind, archive.MaxWireBytes+frontier.MaxBytes+4096)
			if err != nil {
				return err
			}
			var w journalFrontierWire
			if err = decodePayload(payload, &w); err != nil {
				return err
			}
			w.Descriptor[0] ^= 1
			raw, err := encodeFrontierState(w)
			if err != nil {
				return err
			}
			return b.Put(journalFrontierKey, raw)
		}, frontier.ErrContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
			defer s.Close()
			require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
			require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { return tc.mutate(tx.Bucket(bucketName)) }))
			_, err := s.LoadJournal(context.Background(), c, limits)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestPrunedJournalRequiresAuthenticatedFrontierOnRestart(t *testing.T) {
	path := t.TempDir() + "/journal.db"
	s, c, policy, item, limits := frontierTestSetup(t, path)
	require.NoError(t, s.AdvanceFrontier(context.Background(), c, limits, []frontier.Coverage{item}))
	require.NoError(t, s.PruneFrontier(context.Background(), c, limits))
	require.NoError(t, s.Close())
	s, err := OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.EnableJournal(context.Background(), c, limits))
	_, err = s.LoadJournal(context.Background(), c, limits)
	require.ErrorIs(t, err, ErrSettings)
	wrong := policy
	wrong.Context.RootEpoch++
	require.ErrorIs(t, s.EnableFrontier(context.Background(), c, limits, wrong), ErrContext)
	require.NoError(t, s.EnableFrontier(context.Background(), c, limits, policy))
	image, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.EqualValues(t, 1, image.Frontier.Floor)
}
