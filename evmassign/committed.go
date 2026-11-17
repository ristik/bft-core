package evmassign

import "sync"

// A committed successor body binds the SHA-256 of the canonical candidate bytes it was frozen with. On a P85 chain those are this package's
// candidate (version 5); on a validator-registry (VR) chain they are the candidate v6 of vrschema, which this package cannot import. A reader
// that holds committed candidate bytes and needs the evmassign view of them (its successor assignment, identities, root members and
// authorization) decodes them with DecodeCommittedCandidate, which accepts the v5 encoding and every view a later generation registered; the
// digest it binds stays the SHA-256 of the bytes it was given (VT-05b, ristik/bft-core#1159).

// CandidateView decodes committed candidate bytes of another generation into their evmassign view. ok is false when the bytes are not of
// its generation; an error is a malformed encoding of it.
type CandidateView func(data []byte) (c Candidate, ok bool, err error)

var (
	viewsMu sync.RWMutex
	views   []CandidateView
)

// RegisterCandidateView adds the view decoder of a candidate generation (vradmit registers candidate v6 at init).
func RegisterCandidateView(v CandidateView) {
	viewsMu.Lock()
	defer viewsMu.Unlock()
	views = append(views, v)
}

// DecodeCommittedCandidate is DecodeCandidate for committed candidate bytes of any registered generation: the canonical v5 encoding itself,
// or the evmassign view of a registered later one (a VR chain's candidate v6). Anything else is ErrCandidate.
func DecodeCommittedCandidate(data []byte) (Candidate, error) {
	if c, err := DecodeCandidate(data); err == nil {
		return c, nil
	}
	viewsMu.RLock()
	defer viewsMu.RUnlock()
	for _, v := range views {
		if c, ok, err := v(data); ok {
			if err != nil {
				return Candidate{}, err
			}
			return c, nil
		}
	}
	return Candidate{}, ErrCandidate
}
