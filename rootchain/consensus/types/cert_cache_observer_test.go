package types

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

// countingObserver is the shadow's side of the contract: it counts the calls it is told about and, at each call, whether the certificate was
// already in the cache (a call must come after the cache learned of the verification, never between CertVerified and RememberCert).
type countingObserver struct {
	mu          sync.Mutex
	calls       map[string]int
	tbs         *trustbase.TrustBaseStore
	remembered  func(cert any) bool
	notYetKnown int
}

func (o *countingObserver) ObserveCert(kind string, cert any, _, _, _ uint64, _ int, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls[kind]++
	if o.remembered != nil && !o.remembered(cert) {
		o.notYetKnown++
	}
}

func newCountingObserver(tbs *trustbase.TrustBaseStore) *countingObserver {
	o := &countingObserver{calls: map[string]int{}, tbs: tbs}
	o.remembered = func(cert any) bool {
		switch c := cert.(type) {
		case *QuorumCert:
			k, ok := certCacheKey(tbs, trustbase.CertQC, c, c.VoteInfo.Version, c.Scheme, c.VoteInfo.Epoch)
			return !ok || tbs.CertVerified(k)
		case *TimeoutCert:
			k, ok := timeoutCertCacheKey(tbs, c)
			return !ok || tbs.CertVerified(k)
		}
		return false
	}
	tbs.SetCertObserver(o)
	return o
}

// Cache and shadow observer on together: a miss is one real verification and is observed exactly once; a hit (the same object or a decoded copy)
// is not a verification and is not observed; a failed verification is neither observed nor remembered; and when the observer is told, the cache
// already holds the certificate.
func TestCertCacheAndObserverTogether_QC(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	obs := newCountingObserver(tbs)
	qc := sb.QC(t, 42)

	require.NoError(t, qc.VerifyWith(tbs))
	require.Equal(t, 1, obs.calls["QC"], "a miss counts once")
	st := tbs.TakeCertCacheStats()
	require.Equal(t, 1, st.Misses[trustbase.CertQC])
	require.Equal(t, 1, st.Inserts)

	require.NoError(t, qc.VerifyWith(tbs))
	require.NoError(t, recodeQC(t, qc).VerifyWith(tbs))
	require.Equal(t, 1, obs.calls["QC"], "two hits add no shadow verification")
	require.Equal(t, 2, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])

	bad := recodeQC(t, qc)
	bad.VoteInfo.Timestamp++
	require.Error(t, bad.VerifyWith(tbs))
	require.Equal(t, 1, obs.calls["QC"], "a failed verification is not observed")
	require.Zero(t, tbs.TakeCertCacheStats().Inserts, "nor remembered")

	require.Zero(t, obs.notYetKnown, "the observer is never called before the cache holds the certificate")
}

// The same for a timeout certificate and its nested QC: a miss observes the TC once and its nested QC once; a hit on the TC observes nothing
// (the nested QC is not looked at); the observer is not what makes the cache decide.
func TestCertCacheAndObserverTogether_TC(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	obs := newCountingObserver(tbs)
	tc := sb.TimeoutCert(t)

	require.NoError(t, tc.Verify(tbs))
	require.Equal(t, 1, obs.calls["TC"])
	require.Equal(t, 1, obs.calls["QC"], "the nested QC, a real verification of its own")
	tbs.TakeCertCacheStats()

	require.NoError(t, recodeTC(t, tc).Verify(tbs))
	require.Equal(t, 1, obs.calls["TC"], "a TC hit is not observed")
	require.Equal(t, 1, obs.calls["QC"], "and does not verify, or observe, the nested QC")
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertTC])
	require.Zero(t, obs.notYetKnown)

	// the same behaviour with no observer installed: the cache decides alone
	tbs.SetCertObserver(nil)
	require.NoError(t, recodeTC(t, tc).Verify(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertTC])
}

// With the cache off every call is a real verification and every call is observed (the baseline the shadow's repeat counters need).
func TestObserverSeesEveryCallWithTheCacheOff(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tbs := sb.trustBaseStore
	tbs.SetCertCacheCapacity(0)
	obs := newCountingObserver(tbs)
	qc := sb.QC(t, 42)
	for i := 0; i < 3; i++ {
		require.NoError(t, qc.VerifyWith(tbs))
	}
	require.Equal(t, 3, obs.calls["QC"])
}
