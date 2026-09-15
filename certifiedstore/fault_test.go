package certifiedstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
Injected failures inside one process, at every named point of Publish. A failure before the transaction
commits must leave the complete prior state, byte for byte: the previous head, its record, and every record
retention was about to delete. A failure reported after commit leaves the complete new state. Nothing in
between is ever observable.

Setup for each case: Retain 3 with blocks 0..3 published (records genesis, 1, 2, 3), then a publication of
block 4 under Retain 1, which puts record 4, moves the head, and deletes records 1, 2 and 3.
*/

type checkpointCase struct {
	name       string
	occurrence int // for points reached more than once in one publication
}

var publishCheckpoints = []checkpointCase{
	{"before-publish", 1},
	{"after-record-put", 1},
	{"after-head-put", 1},
	{"after-retention-delete", 1},
	{"after-retention-delete", 2},
	{"after-retention-delete", 3},
	{"before-commit", 1},
	{"after-commit", 1},
}

func (c checkpointCase) String() string { return fmt.Sprintf("%s#%d", c.name, c.occurrence) }

// failAt returns a checkpoint function that returns errInjected at the case's point, or runs act instead.
func failAt(c checkpointCase, act func()) func(string) error {
	seen := 0
	return func(name string) error {
		if name != c.name {
			return nil
		}
		seen++
		if seen != c.occurrence {
			return nil
		}
		if act != nil {
			act()
		}
		return errInjected
	}
}

// prepared is the state before the publication under test.
func prepared(t *testing.T, f *fixture, path string) map[string][]byte {
	s, err := Open(path, Settings{Retain: 3})
	require.NoError(t, err)
	f.publishChain(s, 3)
	before := contents(t, s)
	require.NoError(t, s.Close())
	return before
}

// expectedAfter is the complete new state, computed by an unfaulted run of the same publication.
func expectedAfter(t *testing.T, f *fixture) map[string][]byte {
	path := tempDB(t)
	prepared(t, f, path)
	s := f.open(path, 1)
	require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(4)))
	return contents(t, s)
}

func assertPriorOrNew(t *testing.T, f *fixture, s *Store, before, after map[string][]byte, wantNew bool) {
	got := contents(t, s)
	l, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	if wantNew {
		require.Equal(t, keysOf(after), keysOf(got), "the complete new state")
		require.Equal(t, got["head"], after["head"])
		require.Equal(t, uint64(4), l.BlockNumber())
		return
	}
	require.Equal(t, before, got, "the complete prior state, byte for byte")
	require.Equal(t, uint64(3), l.BlockNumber())
}

func TestInjectedFailuresLeavePriorOrNewState(t *testing.T) {
	f := newFixture(t, 4)
	after := expectedAfter(t, f)
	require.Equal(t, []string{"head", string(recordKey(f.record(4))), "record/genesis"}, keysOf(after), "premise: publication deletes three records")

	for _, c := range publishCheckpoints {
		t.Run(c.String(), func(t *testing.T) {
			path := tempDB(t)
			before := prepared(t, f, path)
			s := f.open(path, 1)
			s.checkpoint = failAt(c, nil)

			err := s.Publish(context.Background(), f.ctx, f.record(4))
			require.ErrorIs(t, err, errInjected)
			committed := c.name == "after-commit"
			assertPriorOrNew(t, f, s, before, after, committed)

			// Reopen: the state on disk is what the failed process left.
			require.NoError(t, s.Close())
			reopened := f.open(path, 1)
			assertPriorOrNew(t, f, reopened, before, after, committed)

			// The same publication then succeeds and yields the complete new state.
			require.NoError(t, reopened.Publish(context.Background(), f.ctx, f.record(4)))
			assertPriorOrNew(t, f, reopened, before, after, true)
		})
	}
}

func TestEveryCheckpointIsReached(t *testing.T) {
	f := newFixture(t, 4)
	path := tempDB(t)
	prepared(t, f, path)
	s := f.open(path, 1)
	counts := map[string]int{}
	s.checkpoint = func(name string) error { counts[name]++; return nil }
	require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(4)))
	for _, c := range publishCheckpoints {
		require.GreaterOrEqual(t, counts[c.name], c.occurrence, "checkpoint %s is reached", c)
	}
}
