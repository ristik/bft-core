package trustbase

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Every change of what a verification reads advances the generation: an installed trust base, the pin, the UTB profile and a signing
// activation. A no-op (the same activation record again) does not.
func TestVerifyGenerationAdvancesOnEveryPublishedContextChange(t *testing.T) {
	s := threeEpochStore(t)
	require.GreaterOrEqual(t, s.VerifyGeneration(), uint64(3), "three installed trust bases")

	step := func(name string, f func() error) {
		before := s.VerifyGeneration()
		require.NoError(t, f(), name)
		require.Greater(t, s.VerifyGeneration(), before, name)
	}
	step("genesis pin", func() error { s.SetGenesisPin(&GenesisPin{VoteInfoHash: []byte{1}}); return nil })
	step("genesis pin removed", func() error { s.SetGenesisPin(nil); return nil })
	step("utb profile", func() error { s.EnableUTBProfile(); return nil })
	step("signing activation", func() error { return s.ActivateSigning(2, cfg2()) })

	before := s.VerifyGeneration()
	require.NoError(t, s.ActivateSigning(2, cfg2()), "the same record again is a no-op")
	require.Equal(t, before, s.VerifyGeneration())
}

func TestCertContextResolvesEveryEpochAndRefusesUnknownOnes(t *testing.T) {
	s := threeEpochStore(t)
	ctx, ok := s.CertContextFor(2, 1, 2)
	require.True(t, ok)
	require.Equal(t, 2, ctx.N, "duplicate epochs are one, in order")
	require.EqualValues(t, []uint64{1, 2}, ctx.Epochs[:2])
	_, ok = s.CertContextFor(1, 9)
	require.False(t, ok, "an epoch with no trust base has no context: the certificate is verified without the cache")
	_, ok = s.CertContextFor(1, 2, 3, 3, 4, 5)
	require.False(t, ok, "more than four distinct epochs")

	require.NoError(t, s.ActivateSigning(2, cfg2()))
	again, ok := s.CertContextFor(1, 2)
	require.True(t, ok)
	require.NotEqual(t, ctx.Cfgs[1], again.Cfgs[1], "a changed signing configuration is a different context")
	require.Equal(t, ctx.Cfgs[0], again.Cfgs[0])
}

func TestCertCacheStoresPerGenerationAndRefusesAStaleInsert(t *testing.T) {
	s := threeEpochStore(t)
	k := CertKey{Kind: CertQC, Digest: [32]byte{1}}
	gen := s.VerifyGeneration()
	s.RememberCert(k, gen)
	require.True(t, s.CertVerified(k))
	s.SetGenesisPin(nil) // a context change
	require.False(t, s.CertVerified(k), "an entry of the old generation is no hit")
	s.RememberCert(k, gen) // a verification that began before the change
	require.False(t, s.CertVerified(k))
	require.Equal(t, 1, s.TakeCertCacheStats().StaleInsertsRefused)
	s.RememberCert(k, s.VerifyGeneration())
	require.True(t, s.CertVerified(k))
}

// A live reinstall: a projection installed through either entry point advances the generation, an idempotent reinstall of the same one does not, and
// a bound authority's answer is re-read on every lookup (the context follows it without any mutator running).
func TestVerifyGenerationOnProjectionInstallsAndAuthorityAnswers(t *testing.T) {
	s := threeEpochStore(t)
	old, err := s.GetByEpoch(3)
	require.NoError(t, err)
	next := successorOf(t, old, 4)

	before := s.VerifyGeneration()
	_, err = s.InstallV2Projection(next)
	require.NoError(t, err)
	installed := s.VerifyGeneration()
	require.Greater(t, installed, before, "InstallV2Projection of a new epoch")
	_, err = s.InstallV2Projection(next)
	require.NoError(t, err)
	require.Equal(t, installed, s.VerifyGeneration(), "the identical projection again changes nothing")

	// through the verified-history entry point
	s2 := threeEpochStore(t)
	history := historyOf{1: legacy(), 2: legacy(), 3: legacy(), 4: cfg2()}
	require.NoError(t, s2.BindSigningAuthority(history))
	genAfterBind := s2.VerifyGeneration()
	old2, err := s2.GetByEpoch(3)
	require.NoError(t, err)
	_, err = s2.InstallVerified(successorOf(t, old2, 4), cfg2())
	require.NoError(t, err)
	require.Greater(t, s2.VerifyGeneration(), genAfterBind, "InstallVerified")

	// the bound history answers for itself: a changed answer is a different context at the next lookup, with no generation change
	ctx1, ok := s2.CertContextFor(4)
	require.True(t, ok)
	genBefore := s2.VerifyGeneration()
	changed := cfg2()
	changed.Genesis = [32]byte{42}
	history[4] = changed
	ctx2, ok := s2.CertContextFor(4)
	require.True(t, ok)
	require.NotEqual(t, ctx1, ctx2)
	require.Equal(t, genBefore, s2.VerifyGeneration())
}
