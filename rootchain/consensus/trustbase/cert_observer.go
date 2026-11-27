package trustbase

import "time"

// CertObserver is a MEASUREMENT hook (briefs/dev2-timeout-backoff-design.md, shadow counters): it is told about every certificate verification
// that SUCCEEDED, with the certificate itself, so a recorder can count repeats of the same certificate without anything being skipped. A failed
// verification is never reported. It must be safe for concurrent use and must not retain or change the certificate.
type CertObserver interface {
	// ObserveCert: kind is "QC" or "TC", cert the verified certificate (*QuorumCert or *TimeoutCert), epoch/round/scheme/signatures its own
	// fields, selfDur the time its verification took without the nested certificates it verified (a TC's own high QC is reported separately as
	// a QC call).
	ObserveCert(kind string, cert any, epoch, round, scheme uint64, signatures int, selfDur time.Duration)
}

type certObserverBox struct{ o CertObserver }

// SetCertObserver installs the observer of this store; nil removes it. The default is none, and then the verification paths do nothing extra.
func (s *TrustBaseStore) SetCertObserver(o CertObserver) {
	if o == nil {
		s.certObserver.Store(nil)
		return
	}
	s.certObserver.Store(&certObserverBox{o: o})
}

// CertObserver returns the installed observer, or nil.
func (s *TrustBaseStore) CertObserver() CertObserver {
	if s == nil {
		return nil
	}
	if b := s.certObserver.Load(); b != nil {
		return b.o
	}
	return nil
}
