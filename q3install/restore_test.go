package q3install

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3format"
)

// volatileComponent is a participant whose installed state is lost on restart: its Verify holds only after Install or Restore ran in
// this process.
type volatileComponent struct {
	fakeComponent
	restored   []uint64
	live       map[uint64]bool
	restoreErr error
	events     *[]string
}

func (v *volatileComponent) Install(ctx context.Context, a Activation) error {
	if err := v.fakeComponent.Install(ctx, a); err != nil {
		return err
	}
	v.live[a.Claim.Epoch] = true
	*v.events = append(*v.events, fmt.Sprintf("install %d", a.Claim.Epoch))
	return nil
}

func (v *volatileComponent) Restore(_ context.Context, a Activation) error {
	if v.restoreErr != nil {
		return v.restoreErr
	}
	v.restored = append(v.restored, a.Claim.Epoch)
	v.live[a.Claim.Epoch] = true
	*v.events = append(*v.events, fmt.Sprintf("restore %d", a.Claim.Epoch))
	return nil
}

func (v *volatileComponent) Verify(ctx context.Context, a Activation) error {
	if !v.live[a.Claim.Epoch] {
		return errors.New("the volatile state is gone")
	}
	*v.events = append(*v.events, fmt.Sprintf("verify %d", a.Claim.Epoch))
	return v.fakeComponent.Verify(ctx, a)
}

func (s *stores) openVolatile(t *testing.T, v *volatileComponent) (*Journal, error) {
	t.Helper()
	comps := map[Step]Component{}
	for _, k := range Steps {
		comps[k] = fakeComponent{s, &crasher{n: -1}, k}
	}
	comps[StepSnapshot] = v
	return Open(Config{DB: crashDB{s.db, &crasher{n: -1}, &s.deletes}, Components: comps, Bundles: acceptBundle})
}

func newVolatile(s *stores, events *[]string) *volatileComponent {
	return &volatileComponent{fakeComponent: fakeComponent{s, &crasher{n: -1}, StepSnapshot}, live: map[uint64]bool{}, events: events}
}

func TestStagedListsEveryActivationInEpochOrder(t *testing.T) {
	s := newStores()
	j := s.mustOpen(t)
	got, err := j.Staged()
	require.NoError(t, err)
	require.Empty(t, got)
	for _, e := range []uint64{7, 3, 5} {
		c := claim(e)
		require.NoError(t, j.Install(ctx, c, bundleFor(c)))
	}
	got, err = j.Staged()
	require.NoError(t, err)
	require.Len(t, got, 3)
	for i, e := range []uint64{3, 5, 7} {
		c := claim(e)
		require.Equal(t, c, got[i].Claim)
		require.Equal(t, bundleFor(c), got[i].Bundle)
		require.Equal(t, ActivationID(c, bundleFor(c)), got[i].ID)
	}
	got[0].Bundle[0] ^= 0xFF
	again, err := j.Staged()
	require.NoError(t, err)
	require.Equal(t, bundleFor(claim(3)), again[0].Bundle, "the returned bundles are copies")
	require.Zero(t, s.deletes)
}

func TestStagedRefusesADamagedJournal(t *testing.T) {
	s := newStores()
	j := s.mustOpen(t)
	c := claim(5)
	require.NoError(t, j.Install(ctx, c, bundleFor(c)))
	require.NoError(t, s.db.Write([]byte("q3install/zzz"), []byte{1}))
	_, err := j.Staged()
	require.ErrorIs(t, err, ErrJournal)
}

func TestRecoverRestoresVolatileStateOfFinishedActivationsBeforeVerifying(t *testing.T) {
	s := newStores()
	var events []string
	v := newVolatile(s, &events)
	j, err := s.openVolatile(t, v)
	require.NoError(t, err)
	c := claim(5)
	require.NoError(t, j.Install(ctx, c, bundleFor(c)))
	require.Empty(t, v.restored, "an installation does not restore: it installs")
	require.NoError(t, j.Gate(ctx, c))

	// restart: the volatile state is gone; the journal is complete
	events = nil
	v2 := newVolatile(s, &events)
	j, err = s.openVolatile(t, v2)
	require.NoError(t, err)
	require.ErrorIs(t, j.Gate(ctx, c), ErrStoreConflict, "before recovery the volatile participant does not hold the activation")
	require.NoError(t, j.Recover(ctx, lookup(c)))
	require.Equal(t, []uint64{5}, v2.restored)
	require.Equal(t, []string{"restore 5", "verify 5"}, events, "restored, then verified")
	require.NoError(t, j.Gate(ctx, c))
	require.Equal(t, 1, s.installs[StepSnapshot], "the finished install is not repeated")
}

func TestRecoverDoesNotRestoreAnUnfinishedActivation(t *testing.T) {
	s := newStores()
	var events []string
	v := newVolatile(s, &events)
	// the shard step fails: the journal stays unfinished
	s.installErr[StepShard] = errors.New("down")
	j, err := s.openVolatile(t, v)
	require.NoError(t, err)
	c := claim(5)
	require.Error(t, j.Install(ctx, c, bundleFor(c)))

	delete(s.installErr, StepShard)
	events = nil
	v2 := newVolatile(s, &events)
	j, err = s.openVolatile(t, v2)
	require.NoError(t, err)
	require.NoError(t, j.Recover(ctx, lookup(c)))
	require.Empty(t, v2.restored, "an unfinished activation installs, it is not restored")
	require.Equal(t, []string{"install 5", "verify 5"}, events)
	require.NoError(t, j.Gate(ctx, c))
}

func TestRestoreFailureRefusesRecovery(t *testing.T) {
	s := newStores()
	var events []string
	v := newVolatile(s, &events)
	j, err := s.openVolatile(t, v)
	require.NoError(t, err)
	c := claim(5)
	require.NoError(t, j.Install(ctx, c, bundleFor(c)))

	boom := errors.New("cannot rebuild the snapshot")
	v2 := newVolatile(s, &events)
	v2.restoreErr = boom
	j, err = s.openVolatile(t, v2)
	require.NoError(t, err)
	require.ErrorIs(t, j.Recover(ctx, lookup(c)), boom)
	require.ErrorIs(t, j.Gate(ctx, c), ErrStoreConflict)
	require.Zero(t, s.deletes, "nothing is erased to repair a failed restore")
}

var _ = q3format.Claim{}
