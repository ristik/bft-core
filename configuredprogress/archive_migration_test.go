package configuredprogress

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/frontier"
)

func derivedPolicy(j rotationJournal, encoded string, replicas []string, m ArchiveMigration) frontier.Policy {
	p := j.policy
	p.Replicas = [2]string{}
	p.Eligible, p.PolicyDigest = replicas, sha256.Sum256([]byte(encoded))
	p.Historical, p.Retained = m.Lineage, m.Retained
	p.Availability = &namedAvailability{}
	return p
}

// A policy switch is durable and additive (bft-core#1030): the first adoption reads the lineage from the coverage, each later one keeps
// every earlier replica that may still hold a promised copy as a retained holder until the migration completes, a crash at either commit
// leaves the previous record, the progress never moves backwards nor applies to a replaced policy, and a restart reads it back.
func TestArchiveMigrationLifecycle(t *testing.T) {
	ctx := context.Background()
	j := newRotationJournal(t, true)
	s, err := j.reopen(t, [2]string{"first", "second"}, &namedAvailability{}, nil)
	require.NoError(t, err)
	_, found, err := s.LoadArchiveMigration(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.False(t, found)

	// A node that ran before policies were persisted: the coverage at height 1 names first and second.
	p1 := []string{"first", "third", "fourth"}
	m, err := s.AdoptArchivePolicy(ctx, j.c, j.limits, []byte("p1"), p1)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte("p1")), m.Digest)
	require.Equal(t, []string{"second"}, m.Lineage)
	require.Equal(t, []string{"second"}, m.Retained)
	require.Equal(t, uint64(1), m.Since)
	require.Zero(t, m.Through)
	require.False(t, m.Complete())
	require.Equal(t, uint64(1), m.Backlog())
	again, err := s.AdoptArchivePolicy(ctx, j.c, j.limits, []byte("p1"), p1)
	require.NoError(t, err)
	require.Equal(t, m, again, "the same policy again changes nothing")

	// The frontier decodes under the new policy only with its lineage.
	require.NoError(t, s.ReplaceFrontierPolicy(ctx, j.c, j.limits, derivedPolicy(j, "p1", p1, m)))

	// A crash before the migration commit leaves the record as it was.
	s.SetFaultHook(func(point string) error {
		if point == "before-archive-migration-commit" {
			return errors.New("crash")
		}
		return nil
	})
	_, err = s.AdvanceArchiveMigration(ctx, j.c, j.limits, m.Digest, 1)
	require.Error(t, err)
	s.SetFaultHook(nil)
	m, _, err = s.LoadArchiveMigration(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.Zero(t, m.Through)
	require.Equal(t, []string{"second"}, m.Retained)
	m, err = s.AdvanceArchiveMigration(ctx, j.c, j.limits, m.Digest, 7)
	require.NoError(t, err)
	require.True(t, m.Complete())
	require.Equal(t, uint64(1), m.Through, "clamped to the switch height")
	require.Empty(t, m.Retained, "complete: the retained holders are released")
	require.Equal(t, []string{"second"}, m.Lineage, "the lineage stays: the coverage still names it")
	back, err := s.AdvanceArchiveMigration(ctx, j.c, j.limits, m.Digest, 0)
	require.NoError(t, err)
	require.Equal(t, m, back, "never backwards")

	// After a complete migration only the previous replicas are retained.
	p2 := []string{"third", "fourth", "fifth"}
	m2, err := s.AdoptArchivePolicy(ctx, j.c, j.limits, []byte("p2"), p2)
	require.NoError(t, err)
	require.Equal(t, []string{"first"}, m2.Retained)
	require.Equal(t, []string{"first", "second"}, m2.Lineage)
	// Before that one completes, another switch keeps every holder.
	p3 := []string{"fifth", "sixth", "seventh"}
	m3, err := s.AdoptArchivePolicy(ctx, j.c, j.limits, []byte("p3"), p3)
	require.NoError(t, err)
	require.Equal(t, []string{"first", "fourth", "third"}, m3.Retained)
	require.Equal(t, []string{"first", "fourth", "second", "third"}, m3.Lineage)
	_, err = s.AdvanceArchiveMigration(ctx, j.c, j.limits, m2.Digest, 1)
	require.ErrorIs(t, err, ErrStale, "the verification of a replaced policy does not count")

	// No acknowledger of the anchor (first, second) is eligible: the lineage carries it.
	zero := derivedPolicy(j, "p3", p3, m3)
	zero.Historical, zero.Retained = nil, nil
	require.ErrorIs(t, s.ReplaceFrontierPolicy(ctx, j.c, j.limits, zero), frontier.ErrContext)
	require.NoError(t, s.ReplaceFrontierPolicy(ctx, j.c, j.limits, derivedPolicy(j, "p3", p3, m3)))

	// A crash before the adoption commit keeps the policy in force.
	s.SetFaultHook(func(point string) error {
		if point == "before-archive-policy-commit" {
			return errors.New("crash")
		}
		return nil
	})
	_, err = s.AdoptArchivePolicy(ctx, j.c, j.limits, []byte("p4"), []string{"first", "second"})
	require.Error(t, err)
	s.SetFaultHook(nil)
	got, _, err := s.LoadArchiveMigration(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.Equal(t, m3, got)

	// A restart reads the migration back and the frontier opens under it.
	require.NoError(t, s.Close())
	r, err := OpenConfiguredV2(j.path, Settings{Retain: 3})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.NoError(t, r.EnableJournal(ctx, j.c, j.limits))
	got, found, err = r.LoadArchiveMigration(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, m3, got)
	require.NoError(t, r.EnableFrontier(ctx, j.c, j.limits, derivedPolicy(j, "p3", p3, got)))
	snap, err := r.LoadFrontier(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.True(t, snap.Anchor.Migrated())
	require.Equal(t, snap.Anchor.Height, snap.Floor, "the pruned prefix stays valid")
}

// Nothing below a restored journal's coverage base is this writer's promise: a migration starts at the base and is complete when no
// position above it is covered yet.
func TestArchiveMigrationStartsAtTheCoverageBase(t *testing.T) {
	ctx := context.Background()
	s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
	defer s.Close()
	anchor := RestoreAnchor{Height: item.Anchor.Height, Hash: item.Anchor.Subject.BlockHash, StateRoot: item.Anchor.StateRoot, RootRound: item.Anchor.Round}
	require.NoError(t, s.InstallRestoreAnchor(ctx, c, limits, anchor))
	m, err := s.AdoptArchivePolicy(ctx, c, limits, []byte("p1"), []string{"a", "b", "c"})
	require.NoError(t, err)
	require.Equal(t, anchor.Height, m.Through)
	require.Equal(t, anchor.Height, m.Since)
	require.True(t, m.Complete())
	require.Empty(t, m.Retained)
	m, err = s.AdoptArchivePolicy(ctx, c, limits, []byte("p2"), []string{"a", "b", "d"})
	require.NoError(t, err)
	require.True(t, m.Complete(), "a restored writer has nothing below its base to migrate")
	require.Empty(t, m.Retained)
}
