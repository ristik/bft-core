package vradmit

import (
	"errors"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The committed candidate of a VR handoff is its candidate v6 (the successor body binds SHA-256 of the v6 bytes). Every reader outside the
// root's storage that decodes committed candidate bytes (the Q3 history's readiness selector, activation proofs, the shard's staging, the
// handoff delivery and the request history) reads them with evmassign.DecodeCommittedCandidate, which this registration teaches the v6
// encoding: its view is V5Of, the fields the H3 install and lifecycle paths read.
func init() {
	evmassign.RegisterCandidateView(func(data []byte) (evmassign.Candidate, bool, error) {
		c, err := vrschema.DecodeCandidateV6(data)
		if err != nil {
			return evmassign.Candidate{}, false, nil
		}
		if c.Version != vrschema.CandidateV6Version {
			return evmassign.Candidate{}, true, errors.Join(evmassign.ErrCandidate, errors.New("not a candidate v6"))
		}
		return V5Of(c), true, nil
	})
}
