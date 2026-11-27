package evmassign

import (
	"bytes"
	"errors"

	"github.com/unicitynetwork/bft-go-base/types"
)

// A committed successor body binds the SHA-256 of the canonical candidate bytes it was frozen with. On a P85 chain those are this package's
// candidate (version 5); on a validator-registry (VR) chain they are the candidate v6 (schema-v1 section 9, vrschema.CandidateV6): the same
// fields with Version 6, Changes null, then SourceRef and RegistryChanges. A reader that holds committed candidate bytes and needs their
// evmassign view (the successor assignment, identities, root members and authorization) decodes them with DecodeCommittedCandidate. The
// digest it binds stays the SHA-256 of the bytes it was given (VT-05b, ristik/bft-core#1159).
//
// The v6 encoding is read here directly (this package cannot import vrschema, which imports it): a canonical-only decode whose re-encoding
// must be exactly the bytes read, the same canonical lists vrschema.CandidateV6.Encode writes. It checks the encoding, not the registry
// changes' rules, which admission applied before any body bound these bytes; vradmit's tests hold the two decoders equal on every
// canonical v6 encoding.

// RegistryChangeView is one RegistryChanges entry of a candidate v6, as its encoding carries it.
type RegistryChangeView struct {
	_       struct{} `cbor:",toarray"`
	ID      uint64
	Kind    uint64
	Payload []byte
	Verdict uint64
}

type candidateV6Wire struct {
	_                  struct{} `cbor:",toarray"`
	Version            uint64
	Kind               uint64
	Network            uint64
	Predecessor        []byte
	Attempt            uint64
	RootMembers        []RootMember
	OldShardEpoch      uint64
	OldActiveHash      []byte
	Assignment         []byte
	PoPs               []PoP
	Supersedes         *Supersession
	Bindings           []Binding
	Identities         []Identity
	Authorization      *Authorization
	ReplacedAssignment []byte
	Changes            []Change
	SourceRef          []byte
	RegistryChanges    []RegistryChangeView
}

// candidateV6Version is the candidate version of a VR chain (vrschema.CandidateV6Version).
const candidateV6Version = 6

// ErrCandidateV6 reports bytes that are not a canonical candidate v6.
var ErrCandidateV6 = errors.New("evmassign: not a canonical candidate v6")

// DecodeCandidateV6View reads a canonical candidate v6 and returns its evmassign view (the same fields, Version 5, no Changes) with its
// source reference and registry changes.
func DecodeCandidateV6View(data []byte) (Candidate, []byte, []RegistryChangeView, error) {
	var w struct {
		_      struct{} `cbor:",toarray"`
		Domain string
		Body   candidateV6Wire
	}
	if len(data) == 0 || len(data) > MaxCandidateBytes {
		return Candidate{}, nil, nil, ErrCandidateV6
	}
	if err := types.Cbor.Unmarshal(data, &w); err != nil || w.Domain != candidateDomain {
		return Candidate{}, nil, nil, ErrCandidateV6
	}
	c := w.Body
	if c.Version != candidateV6Version || len(c.SourceRef) != DigestLen || isZero(c.SourceRef) || c.Changes != nil {
		return Candidate{}, nil, nil, ErrCandidateV6
	}
	canon := c
	if canon.RootMembers == nil {
		canon.RootMembers = []RootMember{}
	}
	if canon.PoPs == nil {
		canon.PoPs = []PoP{}
	}
	if canon.Bindings == nil {
		canon.Bindings = []Binding{}
	}
	if canon.Identities == nil {
		canon.Identities = []Identity{}
	}
	if canon.RegistryChanges == nil {
		canon.RegistryChanges = []RegistryChangeView{}
	}
	again, err := types.Cbor.Marshal([]any{candidateDomain, canon})
	if err != nil || !bytes.Equal(again, data) {
		return Candidate{}, nil, nil, ErrCandidateV6
	}
	view := Candidate{Version: CandidateVersion, Kind: c.Kind, Network: c.Network, Predecessor: c.Predecessor, Attempt: c.Attempt, RootMembers: c.RootMembers,
		OldShardEpoch: c.OldShardEpoch, OldActiveHash: c.OldActiveHash, Assignment: c.Assignment, PoPs: c.PoPs, Supersedes: c.Supersedes, Bindings: c.Bindings,
		Identities: c.Identities, Authorization: c.Authorization, ReplacedAssignment: c.ReplacedAssignment}
	return view, c.SourceRef, c.RegistryChanges, nil
}

// DecodeCommittedCandidate is DecodeCandidate for committed candidate bytes of either generation: the canonical v5 encoding itself, or the
// evmassign view of a canonical candidate v6. Anything else is ErrCandidate.
func DecodeCommittedCandidate(data []byte) (Candidate, error) {
	if c, err := DecodeCandidate(data); err == nil {
		return c, nil
	}
	if c, _, _, err := DecodeCandidateV6View(data); err == nil {
		return c, nil
	}
	return Candidate{}, ErrCandidate
}
