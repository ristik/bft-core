package cmd

// The execution-revision boundary of bft-core#1199 at the CLI level (astra-design-1199 section 6): the new binary refuses every profile, genesis and
// shard configuration of the legacy generation before anything can participate, and the generations cannot be mixed.
// testdata/vr-genesis-legacy is the pre-#1199 generation (the profile without executionRevision hashed under the V1 domain, its finalized genesis,
// full shard configuration and ureth flags): kept as rejection fixtures, never as accepted input.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
)

func legacyTestdata(name string) string { return filepath.Join("testdata", "vr-genesis-legacy", name) }

func writeProfileEdit(t *testing.T, from string, edit func(m map[string]any)) string {
	raw, err := os.ReadFile(from)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	edit(m)
	b, err := json.Marshal(m)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "p.json")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path
}

func TestTheProfileReaderRequiresTheCurrentExecutionRevision(t *testing.T) {
	cur := vrTestdata(t, "b1-profile.json")
	p, err := readB1Profile(cur)
	require.NoError(t, err)
	require.Equal(t, b1state.CurrentExecutionRevision, p.ExecutionRevision)

	for name, edit := range map[string]func(map[string]any){
		"stripped":       func(m map[string]any) { delete(m, "executionRevision") },
		"zero":           func(m map[string]any) { m["executionRevision"] = 0 },
		"previous":       func(m map[string]any) { m["executionRevision"] = 1 },
		"unknown future": func(m map[string]any) { m["executionRevision"] = 3 },
		"string":         func(m map[string]any) { m["executionRevision"] = "1" },
	} {
		_, err := readB1Profile(writeProfileEdit(t, cur, edit))
		require.Error(t, err, name)
	}
	_, err = readB1Profile(legacyTestdata("b1-profile.json"))
	require.ErrorIs(t, err, ErrB1Profile, "the legacy profile file")
	require.ErrorContains(t, err, "executionRevision")
	// An unknown spelling is refused by the strict reader, and does not default the revision.
	_, err = readB1Profile(writeProfileEdit(t, cur, func(m map[string]any) { delete(m, "executionRevision"); m["execRevision"] = 1 }))
	require.Error(t, err)
}

// The profile file `engine-api b1-profile` writes round-trips with its revision, canonically.
func TestTheProfileFileRoundTripsItsExecutionRevision(t *testing.T) {
	p, err := readB1Profile(vrTestdata(t, "b1-profile.json"))
	require.NoError(t, err)
	f := b1ProfileFileOf(p)
	require.EqualValues(t, b1state.CurrentExecutionRevision, f.ExecutionRevision)
	require.Equal(t, p, f.profile())
	b, err := json.Marshal(f)
	require.NoError(t, err)
	require.Contains(t, string(b), `"executionRevision":2`)
}

func TestBindB1ProfileRefusesAnotherRevision(t *testing.T) {
	v := vrFixtureInput(t)
	_, err := bindB1Profile(v.profile, v.tb, v.full)
	require.NoError(t, err)
	for _, rev := range []uint64{0, 1, 3} {
		p := v.profile
		p.ExecutionRevision = rev
		_, err := bindB1Profile(p, v.tb, v.full)
		require.ErrorIs(t, err, ErrB1Profile, "revision %d", rev)
	}
}

// New and legacy generations: every pairing of one generation's profile with the other's genesis, shard configuration or ureth flags is refused by
// the complete verify, and the current revision added by hand to the legacy profile does not make the legacy genesis or PDR match.
func TestTheGenerationsCannotBeMixedInVRVerify(t *testing.T) {
	_, err := vrVerify(vrFixtureInput(t))
	require.NoError(t, err, "the current generation verifies")

	legacyGenesis, err := os.ReadFile(legacyTestdata("genesis.json"))
	require.NoError(t, err)
	legacyFull, err := readShardConf(legacyTestdata("full-shard-conf.json"))
	require.NoError(t, err)
	legacyFlags, err := os.ReadFile(legacyTestdata("ureth-flags.txt"))
	require.NoError(t, err)

	t.Run("new profile with the legacy genesis", func(t *testing.T) {
		v := vrFixtureInput(t)
		v.genesis = legacyGenesis
		_, err := vrVerify(v)
		require.Error(t, err)
	})
	t.Run("new profile with the legacy PDR", func(t *testing.T) {
		v := vrFixtureInput(t)
		v.full = legacyFull
		_, err := vrVerify(v)
		require.Error(t, err)
	})
	t.Run("new profile with the legacy ureth flags", func(t *testing.T) {
		v := vrFixtureInput(t)
		v.urethFlags = string(legacyFlags)
		_, err := vrVerify(v)
		require.Error(t, err)
	})
	t.Run("the legacy profile file is refused outright", func(t *testing.T) {
		_, _, err := readB1ProfileFile(legacyTestdata("b1-profile.json"))
		require.ErrorIs(t, err, ErrB1Profile)
	})
	t.Run("the current revision added by hand to the legacy profile, with the legacy genesis and PDR", func(t *testing.T) {
		// the legacy profile names the registry runtime of its time; the current pin is set too, so the refusal is the V1 profile hash alone
		p := writeProfileEdit(t, legacyTestdata("b1-profile.json"), func(m map[string]any) {
			m["executionRevision"] = b1state.CurrentExecutionRevision
			m["runtimeHash"] = b1registry.CodeHashHex
		})
		profile, file, err := readB1ProfileFile(p)
		require.NoError(t, err)
		v := vrFixtureInput(t)
		v.profile, v.profileFile, v.genesis, v.full, v.urethFlags = profile, file, legacyGenesis, legacyFull, string(legacyFlags)
		_, err = vrVerify(v)
		require.Error(t, err, "the legacy artifacts commit the V1 profile hash, which no revision-carrying profile reproduces")
	})
}

// The identities differ between the generations: same inputs, different profile hash and so a different seal-registry genesis commitment (the
// PDR's seal_registry_genesis, hence the full shard-conf hash) and genesis block.
func TestTheGenerationIdentitiesDiffer(t *testing.T) {
	cur, err := readShardConf(vrTestdata(t, "full-shard-conf.json"))
	require.NoError(t, err)
	old, err := readShardConf(legacyTestdata("full-shard-conf.json"))
	require.NoError(t, err)
	require.NotEqual(t, cur.PartitionParams["seal_registry_genesis"], old.PartitionParams["seal_registry_genesis"])
	cg, err := os.ReadFile(vrTestdata(t, "genesis.json"))
	require.NoError(t, err)
	og, err := os.ReadFile(legacyTestdata("genesis.json"))
	require.NoError(t, err)
	require.NotEqual(t, cg, og)
}
