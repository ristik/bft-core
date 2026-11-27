package consensus

import "time"

// reportCertCache logs, every loopProfileInterval, what the verified-certificate cache of the trust base store did (hits and misses by kind,
// inserts, evictions, results refused because the context changed meanwhile, entries, and the cost of building keys). Counters only.
func (x *ConsensusManager) reportCertCache(now time.Time) {
	if x.certCacheStart.IsZero() {
		x.certCacheStart = now
		return
	}
	if now.Sub(x.certCacheStart) < loopProfileInterval {
		return
	}
	s := x.trustBaseStore.TakeCertCacheStats()
	if s.Hits[1]+s.Misses[1]+s.Hits[2]+s.Misses[2] == 0 {
		x.certCacheStart = now
		return
	}
	x.log.Info("consensus cert cache", "qcHits", s.Hits[1], "qcMisses", s.Misses[1], "tcHits", s.Hits[2], "tcMisses", s.Misses[2],
		"inserts", s.Inserts, "evictions", s.Evictions, "staleRefused", s.StaleInsertsRefused, "entries", s.Entries,
		"keyBuilds", s.KeyBuilds, "keyBuildUs", s.KeyBuildTime.Microseconds(), "intervalMs", now.Sub(x.certCacheStart).Milliseconds())
	x.certCacheStart = now
}
