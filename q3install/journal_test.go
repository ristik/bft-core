package q3install

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3format"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

var ctx = context.Background()

func completeReference(t *testing.T) (*stores, q3format.Claim, int) {
	t.Helper()
	s, c := newStores(), claim(5)
	cr := &crasher{n: -1}
	j, err := s.open(t, cr, acceptBundle)
	require.NoError(t, err)
	require.NoError(t, j.Install(ctx, c, bundleFor(c)))
	require.NoError(t, j.Gate(ctx, c))
	return s, c, cr.events
}

func TestInstallOrderAndCompletion(t *testing.T) {
	s, c, _ := completeReference(t)
	require.Equal(t, Steps[:], s.order, "components installed in the section 4 order, once each")
	require.Len(t, s.keys(t), 1+numSteps+1, "stage, one marker per step, completion")
	require.Zero(t, s.deletes)
	for _, k := range Steps {
		require.Equal(t, 1, s.installs[k])
	}
	require.NoError(t, s.mustOpen(t).Gate(ctx, c))
}

// A crash before and after every durable write and every participant install, at every point of the installation, then a restart.
// Whatever was done, the restart completes the exact installation; the result is the uncrashed one and signers were not admitted
// in between.
func TestCrashAtEveryPointThenRestart(t *testing.T) {
	ref, c, total := completeReference(t)
	want, wantKeys := ref.snapshot(), ref.keys(t)
	for _, resume := range []string{"Recover", "Install"} {
		t.Run(resume, func(t *testing.T) {
			partial := map[int]bool{}
			for n := 0; n < total; n++ {
				s := newStores()
				j, err := s.open(t, &crasher{n: n}, acceptBundle)
				require.NoError(t, err)
				err = j.Install(ctx, c, bundleFor(c))
				require.ErrorIs(t, err, errCrash, "crash point %d", n)

				// restart: the process state is gone, only the stores and the journal remain
				live := s.mustOpen(t)
				require.ErrorIs(t, live.Gate(ctx, c), ErrIncomplete, "crash point %d: signers must not start on a partial install", n)
				partial[len(s.held)] = true
				marked := map[Step]int{}
				for _, k := range Steps {
					if s.has(t, key(5, "step/"+strconv.Itoa(int(k)))) {
						marked[k] = s.installs[k]
					}
				}
				if resume == "Recover" && n > 0 {
					require.NoError(t, live.Recover(ctx, lookup(c)), "crash point %d", n)
				} else { // before the stage write nothing is journaled, so there is nothing to recover: the activation begins afresh
					require.NoError(t, live.Install(ctx, c, bundleFor(c)), "crash point %d", n)
				}
				require.NoError(t, live.Gate(ctx, c))
				for k, was := range marked {
					require.Equal(t, was, s.installs[k], "crash point %d: %s was recorded and is not installed again", n, k)
				}
				require.Equal(t, want, s.snapshot(), "crash point %d: same state as the uncrashed install", n)
				if n > 0 { // before the stage write nothing exists; the restart has nothing to resume, Install then starts afresh
					require.Equal(t, wantKeys, s.keys(t), "crash point %d", n)
				}
				require.Zero(t, s.deletes)
			}
			for k := 0; k <= numSteps; k++ {
				require.True(t, partial[k], "no crash left exactly %d components installed", k)
			}
		})
	}
}

func TestCrashDuringRecovery(t *testing.T) {
	_, c, total := completeReference(t)
	for first := 1; first < total; first += 3 {
		var recoverEvents int
		{ // how long a recovery after this first crash takes
			s := newStores()
			j, _ := s.open(t, &crasher{n: first}, acceptBundle)
			require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), errCrash)
			cr := &crasher{n: -1}
			j2, err := s.open(t, cr, acceptBundle)
			require.NoError(t, err)
			require.NoError(t, j2.Recover(ctx, lookup(c)))
			recoverEvents = cr.events
		}
		for second := 0; second < recoverEvents; second++ {
			s := newStores()
			j, _ := s.open(t, &crasher{n: first}, acceptBundle)
			require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), errCrash)
			j2, err := s.open(t, &crasher{n: second}, acceptBundle)
			require.NoError(t, err)
			require.ErrorIs(t, j2.Recover(ctx, lookup(c)), errCrash, "first %d second %d", first, second)
			j3 := s.mustOpen(t)
			require.NoError(t, j3.Recover(ctx, lookup(c)))
			require.NoError(t, j3.Gate(ctx, c))
		}
	}
}

func TestReplayIsIdempotent(t *testing.T) {
	s, c, _ := completeReference(t)
	keys, held, installs := s.keys(t), s.snapshot(), map[Step]int{}
	for k, v := range s.installs {
		installs[k] = v
	}
	for i := 0; i < 3; i++ {
		j := s.mustOpen(t)
		require.NoError(t, j.Recover(ctx, lookup(c)))
		require.NoError(t, j.Install(ctx, c, bundleFor(c)))
		require.NoError(t, j.Gate(ctx, c))
	}
	require.Equal(t, keys, s.keys(t))
	require.Equal(t, held, s.snapshot())
	require.Equal(t, installs, s.installs, "a completed activation is verified, never reinstalled")
	require.Zero(t, s.deletes)
}

// stagedAndCrashed leaves a journal staged for c with no step done.
func stagedAndCrashed(t *testing.T, c q3format.Claim) *stores {
	t.Helper()
	s := newStores()
	j, err := s.open(t, &crasher{n: 1}, acceptBundle) // the stage write, then the first install dies
	require.NoError(t, err)
	require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), errCrash)
	require.Len(t, s.keys(t), 1)
	return s
}

// A journal entry whose record is not the committed record is refused, one field at a time, and nothing is installed or erased.
func TestRecordMismatchRefused(t *testing.T) {
	c := claim(5)
	mutations := map[string]func(*q3format.Claim){
		"start":         func(m *q3format.Claim) { m.Start++ },
		"body":          func(m *q3format.Claim) { m.BodyID[31] ^= 1 },
		"commit":        func(m *q3format.Claim) { m.CommitID[31] ^= 1 },
		"prior version": func(m *q3format.Claim) { m.PriorVersion++ },
		"prior id":      func(m *q3format.Claim) { m.PriorID[31] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := stagedAndCrashed(t, c)
			other := c
			mutate(&other)
			accept := func([]byte, q3format.Claim) error { return nil } // only the record binding is under test
			j, err := s.open(t, &crasher{n: -1}, accept)
			require.NoError(t, err)
			keys := s.keys(t)
			require.ErrorIs(t, j.Recover(ctx, lookup(other)), ErrRecordMismatch)
			require.ErrorIs(t, j.Gate(ctx, other), ErrIncomplete, "an unfinished installation is incomplete whatever is asked")
			require.ErrorIs(t, j.Install(ctx, other, bundleFor(other)), ErrRecordMismatch)
			require.Empty(t, s.installs, "a mismatched entry installs nothing")
			require.Equal(t, keys, s.keys(t))
			require.Zero(t, s.deletes)
		})
	}
	t.Run("gate on a completed journal", func(t *testing.T) {
		for name, mutate := range mutations {
			s, c, _ := completeReference(t)
			other := c
			mutate(&other)
			require.ErrorIs(t, s.mustOpen(t).Gate(ctx, other), ErrRecordMismatch, name)
		}
	})
	t.Run("epoch absent from the committed history", func(t *testing.T) {
		s := stagedAndCrashed(t, c)
		require.ErrorIs(t, s.mustOpen(t).Recover(ctx, lookup(claim(4))), ErrRecordMismatch)
		require.Empty(t, s.installs)
	})
	t.Run("zero record is not a lookup hit", func(t *testing.T) {
		z := q3format.Claim{}
		s := newStores()
		accept := func([]byte, q3format.Claim) error { return nil }
		j, err := s.open(t, &crasher{n: 1}, accept)
		require.NoError(t, err)
		require.ErrorIs(t, j.Install(ctx, z, []byte("b")), errCrash)
		live, err := s.open(t, &crasher{n: -1}, accept)
		require.NoError(t, err)
		require.ErrorIs(t, live.Recover(ctx, lookup()), ErrRecordMismatch, "a journaled epoch the history does not hold")
		require.Empty(t, s.installs)
	})
	t.Run("same record, other bundle", func(t *testing.T) {
		s := stagedAndCrashed(t, c)
		j, err := s.open(t, &crasher{n: -1}, func([]byte, q3format.Claim) error { return nil })
		require.NoError(t, err)
		require.ErrorIs(t, j.Install(ctx, c, append(bundleFor(c), 'x')), ErrRecordMismatch)
		require.Empty(t, s.installs)
	})
	t.Run("matching record", func(t *testing.T) {
		s := stagedAndCrashed(t, c)
		require.NoError(t, s.mustOpen(t).Recover(ctx, lookup(c)))
	})
}

func TestBundleMustAuthenticate(t *testing.T) {
	c := claim(5)
	bad := func([]byte, q3format.Claim) error { return errors.New("forged") }
	s := newStores()
	j, err := s.open(t, &crasher{n: -1}, bad)
	require.NoError(t, err)
	require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), ErrBundle)
	require.Empty(t, s.keys(t), "an unauthenticated bundle is never journaled")
	for _, size := range []int{0, MaxBundle + 1} { // a verifier that accepts anything: the bound is the journal's own
		j, err := s.open(t, &crasher{n: -1}, func([]byte, q3format.Claim) error { return nil })
		require.NoError(t, err)
		require.ErrorIs(t, j.Install(ctx, c, make([]byte, size)), ErrBundle)
		require.Empty(t, s.keys(t))
	}
	staged := stagedAndCrashed(t, c) // staged under a good verifier, restarted under one that now refuses
	j, err = staged.open(t, &crasher{n: -1}, bad)
	require.NoError(t, err)
	require.ErrorIs(t, j.Recover(ctx, lookup(c)), ErrBundle)
	require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), ErrBundle)
	require.Empty(t, staged.installs)
	_, err = Open(Config{DB: s.db, Components: nil, Bundles: acceptBundle})
	require.ErrorIs(t, err, ErrComponents)
	comps := map[Step]Component{}
	for _, k := range Steps {
		comps[k] = fakeComponent{s, &crasher{n: -1}, k}
	}
	_, err = Open(Config{DB: s.db, Components: comps})
	require.ErrorIs(t, err, ErrComponents, "no verifier")
	comps[Step(9)] = comps[StepRoot]
	_, err = Open(Config{DB: s.db, Components: comps, Bundles: acceptBundle})
	require.ErrorIs(t, err, ErrComponents, "an extra component")
	delete(comps, StepShard)
	_, err = Open(Config{DB: s.db, Components: comps, Bundles: acceptBundle})
	require.ErrorIs(t, err, ErrComponents, "right count, wrong steps")
	delete(comps, Step(9))
	comps[StepShard] = fakeComponent{s, &crasher{n: -1}, StepShard}
	_, err = Open(Config{Components: comps, Bundles: acceptBundle})
	require.ErrorIs(t, err, ErrComponents, "no db")
}

func TestGateRequiresCompletion(t *testing.T) {
	c := claim(5)
	s := newStores()
	require.ErrorIs(t, s.mustOpen(t).Gate(ctx, c), ErrIncomplete, "nothing journaled")
	staged := stagedAndCrashed(t, c)
	require.ErrorIs(t, staged.mustOpen(t).Gate(ctx, c), ErrIncomplete, "staged, not installed")
	// all steps recorded and installed, the completion marker not yet written
	s = newStores()
	j, err := s.open(t, &crasher{n: 1 + 2*numSteps + numSteps}, acceptBundle)
	require.NoError(t, err)
	require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), errCrash)
	require.Len(t, s.keys(t), 1+numSteps)
	require.ErrorIs(t, s.mustOpen(t).Gate(ctx, c), ErrIncomplete)
}

func TestStoreConflict(t *testing.T) {
	c := claim(5)
	t.Run("verify fails after install", func(t *testing.T) {
		for _, k := range Steps {
			s := newStores()
			s.verifyErr[k] = errors.New("disagrees")
			err := s.mustOpen(t).Install(ctx, c, bundleFor(c))
			require.ErrorIs(t, err, ErrStoreConflict, k.String())
			require.NotContains(t, s.keys(t), string(key(5, "done")), "no completion over a disagreeing store")
			require.ErrorIs(t, s.mustOpen(t).Gate(ctx, c), ErrIncomplete)
		}
	})
	t.Run("store changes after completion", func(t *testing.T) {
		for _, k := range Steps {
			s, c, _ := completeReference(t)
			s.held[heldKey{k, 5}] = []byte("something else")
			j := s.mustOpen(t)
			require.ErrorIs(t, j.Gate(ctx, c), ErrStoreConflict, k.String())
			require.ErrorIs(t, j.Recover(ctx, lookup(c)), ErrStoreConflict, k.String())
			require.ErrorIs(t, j.Install(ctx, c, bundleFor(c)), ErrStoreConflict, k.String())
			require.Zero(t, s.deletes)
		}
	})
	t.Run("a store refuses to install", func(t *testing.T) {
		s := newStores()
		s.held[heldKey{StepSafety, 5}] = []byte("a different activation's decisions")
		err := s.mustOpen(t).Install(ctx, c, bundleFor(c))
		require.ErrorIs(t, err, errHoldsAnother)
		require.Equal(t, []Step{StepRoot, StepSafety}, s.order, "later steps do not run")
		require.NotContains(t, s.keys(t), string(key(5, "step/2")))
		require.ErrorIs(t, s.mustOpen(t).Gate(ctx, c), ErrIncomplete)
	})
}

func TestOnlyOneActivationInFlight(t *testing.T) {
	s := newStores()
	down := errors.New("down")
	s.installErr[StepShard] = down
	require.ErrorIs(t, s.mustOpen(t).Install(ctx, claim(5), bundleFor(claim(5))), down)
	delete(s.installErr, StepShard)
	require.ErrorIs(t, s.mustOpen(t).Install(ctx, claim(6), bundleFor(claim(6))), ErrBusy)
	require.NoError(t, s.mustOpen(t).Recover(ctx, lookup(claim(5))))
	require.NoError(t, s.mustOpen(t).Install(ctx, claim(6), bundleFor(claim(6))), "the next epoch follows a completed one")
	j := s.mustOpen(t)
	require.NoError(t, j.Gate(ctx, claim(5)))
	require.NoError(t, j.Gate(ctx, claim(6)))
	require.NoError(t, j.Recover(ctx, lookup(claim(5), claim(6))))
}

func damaged(t *testing.T, edit func(s *stores, c q3format.Claim)) error {
	t.Helper()
	c := claim(5)
	s := newStores()
	require.NoError(t, s.mustOpen(t).Install(ctx, c, bundleFor(c)))
	edit(s, c)
	_, err := s.open(t, &crasher{n: -1}, acceptBundle)
	return err
}

func (s *stores) put(t *testing.T, k string, v []byte) {
	t.Helper()
	require.NoError(t, s.db.Write([]byte(k), v))
}

func (s *stores) get(t *testing.T, k string) []byte {
	t.Helper()
	var v []byte
	ok, err := s.db.Read([]byte(k), &v)
	require.NoError(t, err)
	require.True(t, ok, k)
	return v
}

// Every damaged journal refuses startup, each case altering one thing in an otherwise complete journal.
func TestDamagedJournalRefusesOpen(t *testing.T) {
	stage := string(key(5, "stage"))
	step := func(n int) string { return string(key(5, "step/"+strconv.Itoa(n))) }
	cases := map[string]func(*stores, q3format.Claim){
		"key without a marker name": func(s *stores, _ q3format.Claim) { s.put(t, prefix+"0000000000000005", []byte{1}) },
		"key with an empty marker":  func(s *stores, _ q3format.Claim) { s.put(t, prefix+"0000000000000005/", []byte{1}) },
		"stray key":                 func(s *stores, _ q3format.Claim) { s.put(t, prefix+"junk", []byte{1}) },
		"unknown suffix": func(s *stores, c q3format.Claim) {
			s.put(t, string(key(5, "extra")), s.get(t, step(1)))
		},
		"step zero": func(s *stores, _ q3format.Claim) { s.put(t, string(key(5, "step/0")), s.get(t, step(1))) },
		"step past end": func(s *stores, _ q3format.Claim) {
			s.put(t, string(key(5, "step/6")), s.get(t, step(1)))
		},
		"step not canonical": func(s *stores, _ q3format.Claim) { s.put(t, string(key(5, "step/01")), s.get(t, step(1))) },
		"epoch not canonical": func(s *stores, _ q3format.Claim) {
			s.put(t, prefix+"5/stage", s.get(t, stage))
		},
		"epoch key without separator": func(s *stores, _ q3format.Claim) {
			s.put(t, prefix+"0000000000000005xstage", s.get(t, stage))
		},
		"stage under another epoch": func(s *stores, _ q3format.Claim) { s.put(t, string(key(6, "stage")), s.get(t, stage)) },
		"marker without stage": func(s *stores, _ q3format.Claim) {
			s.put(t, string(key(9, "step/1")), s.get(t, step(1)))
		},
		"marker of another activation": func(s *stores, _ q3format.Claim) { s.put(t, step(3), make([]byte, 32)) },
		"marker gap": func(s *stores, _ q3format.Claim) {
			s.rebuildWithout(t, "step/2", "done") // later steps remain, the completion marker does not
		},
		"stage not canonical": func(s *stores, _ q3format.Claim) { s.put(t, stage, append(s.get(t, stage), 0)) },
		"stage identity": func(s *stores, c q3format.Claim) {
			var d stageDisk
			require.NoError(t, bfttypes.Cbor.Unmarshal(s.get(t, stage), &d))
			d.Bundle = append(d.Bundle, 'x') // contents changed, identity kept
			raw, err := bfttypes.Cbor.Marshal(d)
			require.NoError(t, err)
			s.put(t, stage, raw)
		},
		"stage fields": func(s *stores, _ q3format.Claim) {
			var d stageDisk
			require.NoError(t, bfttypes.Cbor.Unmarshal(s.get(t, stage), &d))
			d.BodyID = d.BodyID[:31] // short field, identity recomputed so that it is the only defect
			id := ActivationID(d.claim(), d.Bundle)
			d.ID = id[:]
			for _, m := range []string{"step/1", "step/2", "step/3", "step/4", "step/5", "done"} {
				s.put(t, string(key(5, m)), d.ID) // the markers follow, so that nothing else is wrong
			}
			raw, err := bfttypes.Cbor.Marshal(d)
			require.NoError(t, err)
			s.put(t, stage, raw)
		},
		"stage field order": func(s *stores, _ q3format.Claim) { // the same content, encoded without the deterministic key order
			var d stageDisk
			require.NoError(t, bfttypes.Cbor.Unmarshal(s.get(t, stage), &d))
			raw, err := cbor.Marshal(d)
			require.NoError(t, err)
			require.NotEqual(t, s.get(t, stage), raw)
			s.put(t, stage, raw)
		},
		"stage garbage": func(s *stores, _ q3format.Claim) { s.put(t, stage, []byte("not cbor at all")) },
		"complete with a step missing": func(s *stores, _ q3format.Claim) {
			s.rebuildWithout(t, "step/5")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			err := damaged(t, edit)
			require.ErrorIs(t, err, ErrJournal)
			if name == "marker gap" {
				require.ErrorContains(t, err, "records shard without safety")
			}
		})
	}
	t.Run("epoch key not lowercase hex", func(t *testing.T) { // epoch 10 so the spelling is the only defect
		s, c := newStores(), claim(10)
		require.NoError(t, s.mustOpen(t).Install(ctx, c, bundleFor(c)))
		s.put(t, prefix+"000000000000000A/stage", s.get(t, string(key(10, "stage"))))
		_, err := s.open(t, &crasher{n: -1}, acceptBundle)
		require.ErrorIs(t, err, ErrJournal)
	})
	t.Run("two unfinished", func(t *testing.T) {
		s := newStores()
		down := errors.New("down")
		s.installErr[StepShard] = down
		require.ErrorIs(t, s.mustOpen(t).Install(ctx, claim(5), bundleFor(claim(5))), down)
		other := claim(6)
		id := ActivationID(other, bundleFor(other))
		raw, err := bfttypes.Cbor.Marshal(stageDisk{Epoch: 6, Start: other.Start, BodyID: other.BodyID[:], CommitID: other.CommitID[:],
			PriorVersion: other.PriorVersion, PriorID: other.PriorID[:], ID: id[:], Bundle: bundleFor(other)})
		require.NoError(t, err)
		s.put(t, string(key(6, "stage")), raw)
		_, err = s.open(t, &crasher{n: -1}, acceptBundle)
		require.ErrorIs(t, err, ErrJournal)
	})
	t.Run("intact", func(t *testing.T) { require.NoError(t, damaged(t, func(*stores, q3format.Claim) {})) })
}

// rebuildWithout recreates the db without the named markers. Only the test may do this; the journal never deletes.
func (s *stores) rebuildWithout(t *testing.T, suffixes ...string) {
	t.Helper()
	skip := map[string]bool{}
	for _, x := range suffixes {
		skip[string(key(5, x))] = true
	}
	old := s.db
	it := old.First()
	kept := map[string][]byte{}
	for ; it.Valid(); it.Next() {
		var v []byte
		require.NoError(t, it.Value(&v))
		if !skip[string(it.Key())] {
			kept[string(it.Key())] = append([]byte(nil), v...)
		}
	}
	require.NoError(t, it.Close())
	s.db = newDBWith(t, kept)
}

func TestStepNames(t *testing.T) {
	for i, want := range []string{"root", "safety", "shard", "authority", "snapshot"} {
		require.Equal(t, Step(i+1), Steps[i])
		require.Equal(t, want, Steps[i].String())
	}
	require.Equal(t, "step(9)", Step(9).String())
}

// The bundle bound is inclusive: a bundle of exactly MaxBundle is journaled and reloaded, one byte more is not.
func TestBundleBoundIsInclusive(t *testing.T) {
	c, accept := claim(5), func([]byte, q3format.Claim) error { return nil }
	s := newStores()
	j, err := s.open(t, &crasher{n: -1}, accept)
	require.NoError(t, err)
	big := make([]byte, MaxBundle)
	require.NoError(t, j.Install(ctx, c, big))
	j, err = s.open(t, &crasher{n: -1}, accept)
	require.NoError(t, err, "the stored stage is read back at the bound")
	require.NoError(t, j.Gate(ctx, c))
	// a stage on disk one byte over the bound is damage, even with a consistent identity
	d := stageDisk{Epoch: 6, Start: 600, BodyID: c.BodyID[:], CommitID: c.CommitID[:], PriorVersion: 2, PriorID: c.PriorID[:], Bundle: make([]byte, MaxBundle+1)}
	over := c
	over.Epoch, over.Start = 6, 600
	id := ActivationID(over, d.Bundle)
	d.ID = id[:]
	raw, err := bfttypes.Cbor.Marshal(d)
	require.NoError(t, err)
	s.put(t, string(key(6, "stage")), raw)
	_, err = s.open(t, &crasher{n: -1}, accept)
	require.ErrorIs(t, err, ErrJournal)
}

func TestRecoverVisitsEpochsInOrder(t *testing.T) {
	s := newStores()
	for _, e := range []uint64{7, 5, 6} {
		require.NoError(t, s.mustOpen(t).Install(ctx, claim(e), bundleFor(claim(e))))
	}
	var seen []uint64
	require.NoError(t, s.mustOpen(t).Recover(ctx, func(e uint64) (q3format.Claim, bool) { seen = append(seen, e); return claim(e), true }))
	require.Equal(t, []uint64{5, 6, 7}, seen)
}

func TestEveryCrashPointIsCountedOnce(t *testing.T) {
	// 1 stage write + (before, after) per component install + 1 marker per step + 1 completion write
	_, _, total := completeReference(t)
	require.Equal(t, 1+2*numSteps+numSteps+1, total, fmt.Sprint("events: ", total))
}
