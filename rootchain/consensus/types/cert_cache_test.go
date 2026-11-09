package types

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	base "github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

func recodeQC(t *testing.T, qc *QuorumCert) *QuorumCert {
	t.Helper()
	raw, err := base.Cbor.Marshal(qc)
	require.NoError(t, err)
	c := &QuorumCert{}
	require.NoError(t, base.Cbor.Unmarshal(raw, c))
	return c
}

func recodeTC(t *testing.T, tc *TimeoutCert) *TimeoutCert {
	t.Helper()
	raw, err := base.Cbor.Marshal(tc)
	require.NoError(t, err)
	c := &TimeoutCert{}
	require.NoError(t, base.Cbor.Unmarshal(raw, c))
	return c
}

func keyOf(t *testing.T, tbs *trustbase.TrustBaseStore, qc *QuorumCert) trustbase.CertKey {
	t.Helper()
	k, ok := certCacheKey(tbs, trustbase.CertQC, qc, qc.VoteInfo.Version, qc.Scheme, qc.VoteInfo.Epoch)
	require.True(t, ok)
	return k
}

// A certificate that verified is not verified again, whether it is the same object or a decoded copy; the counters say what happened.
func TestCertCacheHitsAnIdenticalCertificateAndItsDecodedCopy(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	qc := sb.QC(t, 42)
	require.NoError(t, qc.VerifyWith(tbs))
	s := tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.Misses[trustbase.CertQC])
	require.Equal(t, 1, s.Inserts)

	require.NoError(t, qc.VerifyWith(tbs))
	require.NoError(t, recodeQC(t, qc).VerifyWith(tbs))
	s = tbs.TakeCertCacheStats()
	require.Equal(t, 2, s.Hits[trustbase.CertQC])
	require.Zero(t, s.Misses[trustbase.CertQC])
}

// QC and TC are separate in the key, and a certificate of another content is another key.
func TestCertCacheKeyIsDomainSeparatedAndCoversTheWholeEncoding(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	qc := sb.QC(t, 42)
	k := keyOf(t, tbs, qc)
	tbs.RememberCert(k, tbs.VerifyGeneration())
	require.True(t, tbs.CertVerified(k))
	other := k
	other.Kind = trustbase.CertTC
	require.False(t, tbs.CertVerified(other), "a TC key with the same digest is another entry")

	variants := map[string]func(c *QuorumCert){
		"timestamp":      func(c *QuorumCert) { c.VoteInfo.Timestamp++ },
		"root hash":      func(c *QuorumCert) { c.VoteInfo.CurrentRootHash = append([]byte{0}, c.VoteInfo.CurrentRootHash...) },
		"round":          func(c *QuorumCert) { c.VoteInfo.RoundNumber++ },
		"epoch":          func(c *QuorumCert) { c.VoteInfo.Epoch++ },
		"commit info":    func(c *QuorumCert) { c.LedgerCommitInfo.Timestamp++ },
		"a signature":    func(c *QuorumCert) { c.Signatures[sb.RandomPeerID(t)] = hex.Bytes{1, 2, 3} },
		"signature gone": func(c *QuorumCert) { delete(c.Signatures, sb.RandomPeerID(t)) },
		"seal signature": func(c *QuorumCert) {
			c.Scheme, c.VoteInfo.Version = votesig.SchemeDomainBound, 1
			c.SealSignatures = map[string]hex.Bytes{"x": {1}}
		},
		"scheme 2":     func(c *QuorumCert) { c.Scheme, c.VoteInfo.Version = votesig.SchemeDomainBound, 1 },
		"utb envelope": func(c *QuorumCert) { c.Envelope, c.UTB = votesig.EnvelopeUTB, &UTBCertificate{Unsigned: hex.Bytes{1}} },
	}
	for name, mutate := range variants {
		c := recodeQC(t, qc)
		mutate(c)
		raw, err := base.Cbor.Marshal(c)
		require.NoError(t, err, name)
		base0, _ := base.Cbor.Marshal(qc)
		require.NotEqual(t, base0, raw, "%s changes the encoding", name)
		if kk, ok := certCacheKey(tbs, trustbase.CertQC, c, c.VoteInfo.Version, c.Scheme, c.VoteInfo.Epoch); ok {
			require.NotEqual(t, k.Digest, kk.Digest, "%s changes the key", name)
		}
	}
}

// A changed witness set misses and the cached verifier agrees with the uncached one for every variant (valid or not).
func TestCertCacheAgreesWithTheUncachedVerifierOnVariants(t *testing.T) {
	sb := newStructBuilder(t, 5)
	cached := sb.trustBaseStore // the uncached verifier is the same store with its cache switched off for the comparison
	qc := sb.QC(t, 42)
	require.NoError(t, qc.VerifyWith(cached))

	fewer := recodeQC(t, qc) // 4 of 5 signatures: still a quorum, still valid, a different encoding
	for id := range fewer.Signatures {
		delete(fewer.Signatures, id)
		break
	}
	badTime := recodeQC(t, qc)
	badTime.VoteInfo.Timestamp++
	tooFew := recodeQC(t, fewer)
	for id := range tooFew.Signatures {
		delete(tooFew.Signatures, id)
		break
	}
	for name, v := range map[string]*QuorumCert{"fewer": fewer, "badTime": badTime, "tooFew": tooFew} {
		cachedErr := v.VerifyWith(cached)
		cached.SetCertCacheCapacity(0) // the same store, cache off: the verifier itself
		plainErr := v.VerifyWith(cached)
		cached.SetCertCacheCapacity(4096)
		require.Equal(t, plainErr == nil, cachedErr == nil, name)
	}
	require.NoError(t, fewer.VerifyWith(cached), "a valid variant is accepted, not rejected for being different")
	require.Error(t, badTime.VerifyWith(cached))
	require.Error(t, tooFew.VerifyWith(cached))
}

// Failures are never remembered; the valid certificate afterwards verifies for real and is then remembered.
func TestCertCacheNeverRemembersAFailure(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	qc := sb.QC(t, 42)
	bad := recodeQC(t, qc)
	for id := range bad.Signatures {
		delete(bad.Signatures, id)
		break
	}
	require.Error(t, bad.VerifyWith(tbs))
	require.Error(t, bad.VerifyWith(tbs))
	s := tbs.TakeCertCacheStats()
	require.Equal(t, 2, s.Misses[trustbase.CertQC])
	require.Zero(t, s.Inserts)
	require.Zero(t, s.Hits[trustbase.CertQC])
	require.NoError(t, qc.VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Inserts)
}

// A TC hit covers the nested high QC; a nested QC that verified is remembered even when the enclosing TC then fails, and the TC is not.
func TestCertCacheTimeoutCertificateAndItsNestedQC(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	tc := sb.TimeoutCert(t)
	require.NoError(t, tc.Verify(tbs))
	s := tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.Inserts-1, "the TC and its nested QC were both remembered")
	require.NoError(t, recodeTC(t, tc).Verify(tbs))
	s = tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.Hits[trustbase.CertTC])
	require.Zero(t, s.Hits[trustbase.CertQC]+s.Misses[trustbase.CertQC], "a TC hit does not look at the nested QC")

	bad := sb.TimeoutCert(t) // a new random QC
	for id := range bad.Signatures {
		delete(bad.Signatures, id) // no TC quorum
		break
	}
	require.Error(t, bad.Verify(tbs))
	s = tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.Inserts, "only the nested QC, which verified on its own")
	require.NoError(t, bad.Timeout.HighQc.VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])
	require.Error(t, bad.Verify(tbs), "the failing TC is verified again, never a hit")
	require.Zero(t, tbs.TakeCertCacheStats().Hits[trustbase.CertTC])
}

// A certificate of another committee is not accepted through the cache of a store that never verified it.
func TestCertCacheIsPerStore(t *testing.T) {
	a, b := newStructBuilder(t, 3), newStructBuilder(t, 3)
	qc := a.QC(t, 42)
	require.NoError(t, qc.VerifyWith(a.trustBaseStore))
	require.NoError(t, qc.VerifyWith(a.trustBaseStore))
	require.Error(t, qc.VerifyWith(b.trustBaseStore), "another committee: no shared cache")
}

// The genesis pin is part of the context: after it changes, a remembered genesis QC is verified again, and refused.
func TestCertCacheGenesisPinChangeInvalidates(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	local := genesisQC(t, []byte{1, 2, 3})
	pin, err := GenesisPinOf(local)
	require.NoError(t, err)
	tbs.SetGenesisPin(pin)
	require.NoError(t, local.VerifyWith(tbs))
	require.NoError(t, local.VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])

	other, err := GenesisPinOf(genesisQC(t, []byte{9, 9, 9}))
	require.NoError(t, err)
	tbs.SetGenesisPin(other)
	require.ErrorIs(t, local.VerifyWith(tbs), ErrNotGenesisQC)
	tbs.SetGenesisPin(nil)
	require.ErrorIs(t, local.VerifyWith(tbs), ErrNotGenesisQC, "a nil pin too")
	tbs.SetGenesisPin(pin)
	require.NoError(t, local.VerifyWith(tbs))
}

// The in-flight case: a verification that began before a context change finishes after it and must not leave a success behind.
func TestCertCacheInFlightVerificationCannotPopulateAChangedContext(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	local := genesisQC(t, []byte{1, 2, 3})
	pin, err := GenesisPinOf(local)
	require.NoError(t, err)
	other, err := GenesisPinOf(genesisQC(t, []byte{9, 9, 9}))
	require.NoError(t, err)
	tbs.SetGenesisPin(pin)

	verifyCertHook = func() { tbs.SetGenesisPin(other) } // the pin changes after the old verification succeeded and before it is remembered
	defer func() { verifyCertHook = func() {} }()
	require.NoError(t, local.VerifyWith(tbs), "the verification that began under the old pin succeeds")
	verifyCertHook = func() {}
	s := tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.StaleInsertsRefused)
	require.Zero(t, s.Inserts)

	require.ErrorIs(t, local.VerifyWith(tbs), ErrNotGenesisQC, "retried under the new pin: verified for real, not served from the old context")
}

// Eviction at the bound: the oldest entry goes, and verifying it again is an ordinary miss.
func TestCertCacheEvictsAtTheBound(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	tbs.SetCertCacheCapacity(2)
	q1, q2, q3 := sb.QC(t, 10), sb.QC(t, 11), sb.QC(t, 12)
	for _, q := range []*QuorumCert{q1, q2, q3} {
		require.NoError(t, q.VerifyWith(tbs))
	}
	s := tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.Evictions)
	require.Equal(t, 2, s.Entries)
	require.NoError(t, q1.VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Misses[trustbase.CertQC], "q1 was evicted")
}

// Verification under -race: concurrent verifiers while the pin keeps changing.
func TestCertCacheConcurrentUseWithContextChanges(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	qcs := []*QuorumCert{sb.QC(t, 20), sb.QC(t, 21), sb.QC(t, 22)}
	tc := sb.TimeoutCert(t)
	pinA, _ := GenesisPinOf(genesisQC(t, []byte{1}))
	pinB, _ := GenesisPinOf(genesisQC(t, []byte{2}))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				require.NoError(t, qcs[i%3].VerifyWith(tbs))
				require.NoError(t, tc.Verify(tbs))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			tbs.SetGenesisPin([]*trustbase.GenesisPin{pinA, pinB, nil}[i%3])
		}
	}()
	wg.Wait()
}

// A real context change through the verifier: a legacy QC remembered under the legacy configuration is refused once its epoch activates the
// domain-bound scheme, never served from the old context.
func TestCertCacheSigningActivationInvalidatesALegacyResult(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	qc := sb.QC(t, 42)
	require.NoError(t, qc.VerifyWith(tbs))
	require.NoError(t, qc.VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])

	require.NoError(t, tbs.ActivateSigning(1, votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: [32]byte{1}}))
	require.ErrorIs(t, qc.VerifyWith(tbs), votesig.ErrScheme)
	require.Zero(t, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])
}
