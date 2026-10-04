package q3active

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3install"
	"github.com/unicitynetwork/bft-go-base/types"
)

func internalRuntime(t *testing.T, f *q3fixture.Fixture) *Runtime {
	t.Helper()
	rt, err := New(Config{DB: memorydb.New(), Genesis: f.Old})
	require.NoError(t, err)
	return rt
}

func bundleBytes(t *testing.T, f *q3fixture.Fixture) []byte {
	t.Helper()
	raw, err := EncodeBundle(Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot})
	require.NoError(t, err)
	return raw
}

// verify is the journal's check of a bundle against the record it is asked to stage: the envelope's last link must be that record,
// and the verified history must derive that record for the epoch.
func TestVerifyBindsTheBundleToTheRecordItIsStagedFor(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	rt := internalRuntime(t, f)
	raw := bundleBytes(t, f)
	require.NoError(t, rt.verify(raw, f.Claim), "acceptance control")

	for name, mutate := range map[string]func(*q3format.Claim){
		"another boundary": func(c *q3format.Claim) { c.Start++ },
		"another body":     func(c *q3format.Claim) { c.BodyID[0] ^= 0xFF },
		"another commit":   func(c *q3format.Claim) { c.CommitID[0] ^= 0xFF },
		"another epoch":    func(c *q3format.Claim) { c.Epoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.Claim
			mutate(&c)
			require.ErrorIs(t, rt.verify(raw, c), ErrBundle)
		})
	}
	t.Run("not a bundle", func(t *testing.T) {
		require.ErrorIs(t, rt.verify([]byte{1, 2, 3}, f.Claim), ErrBundle)
	})
}

// resolve turns a journaled activation into the verified entry: the activation's record must be the envelope's last link and the
// one the history holds.
func TestResolveTakesTheEntryFromTheHistoryAndNothingElse(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	raw := bundleBytes(t, f)
	rt := internalRuntime(t, f)
	activation := q3install.Activation{Claim: f.Claim, Bundle: raw}

	_, _, _, err := rt.resolve(activation)
	require.ErrorIs(t, err, ErrHistory, "the history does not hold the epoch yet")
	env, err := q3format.DecodeEnvelope(f.EnvelopeBytes)
	require.NoError(t, err)
	require.NoError(t, rt.adopt(env))
	e, proof, b, err := rt.resolve(activation)
	require.NoError(t, err)
	require.Equal(t, f.Claim, e.Claim())
	require.Equal(t, f.Proof.Record, proof.Record)
	require.NotNil(t, b.Snapshot)

	other := f.Claim
	other.Start++
	_, _, _, err = rt.resolve(q3install.Activation{Claim: other, Bundle: raw})
	require.ErrorIs(t, err, ErrBundle, "the activation is not the envelope's last link")

	// another chain's activation, whose last link does name its own record: the history holds a different one for the epoch
	foreign := q3fixture.New(t, q3fixture.Options{})
	_, _, _, err = rt.resolve(q3install.Activation{Claim: foreign.Claim, Bundle: bundleBytes(t, foreign)})
	require.ErrorIs(t, err, ErrHistory)

	_, _, _, err = rt.resolve(q3install.Activation{Claim: f.Claim, Bundle: []byte("junk")})
	require.ErrorIs(t, err, ErrBundle)
}

// The snapshot step's check: the published snapshot must be this activation's, or a later epoch's.
func TestSnapshotStepVerifiesWhatIsPublished(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	rt := internalRuntime(t, f)
	env, err := q3format.DecodeEnvelope(f.EnvelopeBytes)
	require.NoError(t, err)
	require.NoError(t, rt.adopt(env))
	entry, ok := rt.Activated(2)
	require.True(t, ok)
	step := &snapshotComponent{r: rt}
	activation := q3install.Activation{Claim: f.Claim, Bundle: bundleBytes(t, f)}
	ctx := context.Background()

	require.Error(t, step.Verify(ctx, activation), "nothing is published")
	require.NoError(t, rt.publish(entry))
	require.NoError(t, step.Verify(ctx, activation))

	later := activation
	later.Claim.Epoch = 3
	require.Error(t, step.Verify(ctx, later), "epoch 3 is not published")
	earlier := activation
	earlier.Claim.Epoch = 1
	require.NoError(t, step.Verify(ctx, earlier), "a later epoch's snapshot covers an earlier activation")
	other := activation
	other.Claim.CommitID[0] ^= 0xFF
	require.Error(t, step.Verify(ctx, other), "the snapshot of epoch 2 is another record's")
	require.NoError(t, step.Restore(ctx, activation), "a restart publishes the same snapshot again")
}

func TestDecodeBundleRefusals(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	raw := bundleBytes(t, f)
	b, env, err := DecodeBundle(raw)
	require.NoError(t, err)
	require.Len(t, env.Links, 1)
	require.NotNil(t, b.Snapshot)

	for name, in := range map[string][]byte{
		"empty":            nil,
		"trailing bytes":   append(append([]byte(nil), raw...), 0),
		"not canonical":    nonCanonical(t, raw),
		"truncated":        raw[:len(raw)/2],
		"oversize":         oversize(t, f),
		"an unknown shape": {0x80},
		"no checkpoint":    rawBundle(t, Bundle{Envelope: f.EnvelopeBytes}),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := DecodeBundle(in)
			require.ErrorIs(t, err, ErrBundle)
		})
	}
	t.Run("an envelope without a link", func(t *testing.T) {
		empty, err := q3format.Envelope{RootInput: []byte{1}, TargetParent: make([]byte, 32)}.Encode()
		require.NoError(t, err)
		noLink, err := EncodeBundle(Bundle{Envelope: empty, Snapshot: f.Snapshot})
		require.NoError(t, err)
		_, _, err = DecodeBundle(noLink)
		require.ErrorIs(t, err, ErrBundle)
	})
	t.Run("a bundle without an envelope or checkpoint cannot be encoded", func(t *testing.T) {
		_, err := EncodeBundle(Bundle{Snapshot: f.Snapshot})
		require.ErrorIs(t, err, ErrBundle)
		_, err = EncodeBundle(Bundle{Envelope: f.EnvelopeBytes})
		require.ErrorIs(t, err, ErrBundle)
	})
}

// nonCanonical is the bundle with its top-level array in indefinite-length form: the same value, another encoding.
func nonCanonical(t *testing.T, raw []byte) []byte {
	t.Helper()
	require.Equal(t, byte(0x83), raw[0], "a three-element definite array")
	return append(append([]byte{0x9f}, raw[1:]...), 0xff)
}

// oversize is a well-formed canonical bundle that is larger than a bundle may be.
func oversize(t *testing.T, f *q3fixture.Fixture) []byte {
	t.Helper()
	raw, err := EncodeBundle(Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: make([]byte, q3format.MaxEnvelopeBytes)})
	require.NoError(t, err)
	return raw
}

// rawBundle is a canonical encoding that EncodeBundle would refuse to write.
func rawBundle(t *testing.T, b Bundle) []byte {
	t.Helper()
	raw, err := types.Cbor.Marshal(b)
	require.NoError(t, err)
	return raw
}
