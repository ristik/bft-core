// Package votesig is the domain-bound signing scheme (SigningScheme 2) of root votes and timeouts: the exact bytes that are
// signed, the identity (network, root-chain genesis, kind) they are bound to, and the signature shape. It has no dependency on
// the consensus types, so the encoders are the one oracle that the verifiers, the signers and the cross-language vectors share.
//
// The bytes are definite-length deterministic CBOR written by the minimal encoder in this package (shortest unsigned
// integers, text, byte strings, null, fixed-arity arrays; no tags, floats, maps or indefinite lengths). Scheme 1 is the
// legacy format, which this package does not produce: legacy bytes stay with their existing encoders and are never
// reinterpreted as scheme 2.
package votesig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// The signing schemes. SchemeLegacy is every message signed before the activation boundary; SchemeDomainBound is this package.
const (
	SchemeLegacy      uint64 = 1
	SchemeDomainBound uint64 = 2
)

const (
	// VoteTag opens every scheme 2 vote preimage (D5 section 2).
	VoteTag = "UNICITY_POS_VOTE"
	// TimeoutTag opens every scheme 2 timeout preimage.
	TimeoutTag = "UNICITY_POS_TIMEOUT"
	votePrefix = "root-vote/"
	timeoutPfx = "root-timeout/"
)

var (
	// ErrScheme is returned for a signing scheme that is not 1 or 2, or that differs from the one the epoch requires.
	ErrScheme = errors.New("signing scheme mismatch")
	// ErrConfig is returned for an invalid signing configuration.
	ErrConfig = errors.New("invalid signing configuration")
	// ErrStatement is returned for a vote or timeout statement that violates the consensus relations the preimage assumes.
	ErrStatement = errors.New("invalid signing statement")
	// ErrSignatureShape is returned for a signature that is not 64 bytes, or 65 bytes with recovery byte 0 or 1.
	ErrSignatureShape = errors.New("invalid signature shape")
	// ErrSignerSets is returned for a committing scheme 2 certificate whose vote signatures and seal signatures are not made by
	// exactly the same signers, or for any other pairing of the two signature maps that is not one-to-one.
	ErrSignerSets = errors.New("vote and seal signer sets differ")
	// ErrNotCanonical is returned by Decode for bytes that are not the canonical encoding of the supported value types.
	ErrNotCanonical = errors.New("not canonical CBOR")
)

// Config is the authenticated signing configuration of one root epoch: the scheme, the network and the fixed root-chain
// genesis identity G. G is pinned by the genesis configuration and is not the changing epoch-anchor GenesisID.
type Config struct {
	Scheme  uint64
	Network uint64
	Genesis [32]byte
}

// Validate refuses an unknown scheme and, for scheme 2, an empty genesis identity.
func (c Config) Validate() error {
	switch c.Scheme {
	case SchemeLegacy:
		return nil
	case SchemeDomainBound:
		if c.Genesis == ([32]byte{}) {
			return fmt.Errorf("%w: scheme 2 needs a root-chain genesis identity", ErrConfig)
		}
		return nil
	}
	return fmt.Errorf("%w: unknown scheme %d", ErrScheme, c.Scheme)
}

// VoteDomain is Dv = "root-vote/" + lowercase hex(G); TimeoutDomain is Dt = "root-timeout/" + lowercase hex(G).
func (c Config) VoteDomain() string    { return votePrefix + hex.EncodeToString(c.Genesis[:]) }
func (c Config) TimeoutDomain() string { return timeoutPfx + hex.EncodeToString(c.Genesis[:]) }

func (c Config) requireV2() error {
	if c.Scheme != SchemeDomainBound {
		return fmt.Errorf("%w: configuration is scheme %d", ErrScheme, c.Scheme)
	}
	return c.Validate()
}

// VoteInfo is the signed consensus round data, VI = C([N, Dv, votingEpoch, votingRound, parentRound, execStateHash]).
type VoteInfo struct {
	Epoch  uint64
	Round  uint64
	Parent uint64
	Exec   [32]byte
}

// Commit is the commit side of a vote: the committed state hash and root round of the vote's LedgerCommitInfo. A
// non-committing vote has a nil Hash and Round 0; a half-empty pair is refused.
type Commit struct {
	Hash  []byte
	Round uint64
}

func (v VoteInfo) validate() error {
	if v.Round == 0 {
		return fmt.Errorf("%w: voting round is zero", ErrStatement)
	}
	if v.Parent >= v.Round {
		return fmt.Errorf("%w: parent round %d is not below voting round %d", ErrStatement, v.Parent, v.Round)
	}
	return nil
}

func (m Commit) validate(votingRound uint64) error {
	switch {
	case m.Hash == nil && m.Round == 0:
		return nil
	case len(m.Hash) != 32 || m.Round == 0:
		return fmt.Errorf("%w: half-empty commit pair", ErrStatement)
	case m.Round >= votingRound:
		return fmt.Errorf("%w: commit round %d is not below voting round %d", ErrStatement, m.Round, votingRound)
	}
	return nil
}

// VoteInfoBytes is VI.
func (c Config) VoteInfoBytes(v VoteInfo) ([]byte, error) {
	if err := c.requireV2(); err != nil {
		return nil, err
	}
	if err := v.validate(); err != nil {
		return nil, err
	}
	var e encoder
	e.array(6).uint(c.Network).text(c.VoteDomain()).uint(v.Epoch).uint(v.Round).uint(v.Parent).bytes(v.Exec[:])
	return e.b, nil
}

// VoteInfoHash is VH = SHA-256(VI), the value LedgerCommitInfo.PreviousHash must carry.
func (c Config) VoteInfoHash(v VoteInfo) ([32]byte, error) {
	vi, err := c.VoteInfoBytes(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(vi), nil
}

// VotePreimage is PV = C(["UNICITY_POS_VOTE", N, Dv, VH, commitStateHash|null, commitRound]). The vote signature is the
// secp256k1 signature of this byte string (the signer hashes it with SHA-256 itself); the epoch and the round are bound
// through VH, not through extra fields.
func (c Config) VotePreimage(v VoteInfo, m Commit) ([]byte, error) {
	vh, err := c.VoteInfoHash(v)
	if err != nil {
		return nil, err
	}
	if err := m.validate(v.Round); err != nil {
		return nil, err
	}
	var e encoder
	e.array(6).text(VoteTag).uint(c.Network).text(c.VoteDomain()).bytes(vh[:])
	if m.Hash == nil {
		e.null()
	} else {
		e.bytes(m.Hash)
	}
	e.uint(m.Round)
	return e.b, nil
}

// Anchor is the epoch anchor a timeout of the first round after an epoch change names.
type Anchor struct {
	GenesisID [32]byte
	Epoch     uint64
	Slot      uint64
}

// Timeout is the signed timeout statement. Anchor is nil for a normal timeout, whose HighQcRound is the verified round of
// the signer's high QC; for an anchor timeout Epoch is the anchor epoch and HighQcRound is the anchor slot.
type Timeout struct {
	Epoch       uint64
	Round       uint64
	HighQcRound uint64
	Anchor      *Anchor
	Author      string
}

// TimeoutPreimage is PT = C(["UNICITY_POS_TIMEOUT", N, Dt, epoch, round, signerHighQCRound, A, author]) with A = null or
// [anchor.GenesisID, anchor.Epoch, anchor.Slot] as a nested value. It preserves every field the legacy timeout signs
// (round, epoch, high QC round, anchor, author) and adds the network, root and kind separation. It is a timeout, not a
// vote on a new execution state, so it has no VoteInfo or commit info.
func (c Config) TimeoutPreimage(t Timeout) ([]byte, error) {
	if err := c.requireV2(); err != nil {
		return nil, err
	}
	if t.Author == "" {
		return nil, fmt.Errorf("%w: timeout author is empty", ErrStatement)
	}
	if t.Round <= t.HighQcRound {
		return nil, fmt.Errorf("%w: timeout round %d does not exceed high QC round %d", ErrStatement, t.Round, t.HighQcRound)
	}
	if a := t.Anchor; a != nil && (a.Epoch != t.Epoch || a.Slot != t.HighQcRound) {
		return nil, fmt.Errorf("%w: anchor timeout must carry the anchor epoch and slot", ErrStatement)
	}
	var e encoder
	e.array(8).text(TimeoutTag).uint(c.Network).text(c.TimeoutDomain()).uint(t.Epoch).uint(t.Round).uint(t.HighQcRound)
	if t.Anchor == nil {
		e.null()
	} else {
		e.array(3).bytes(t.Anchor.GenesisID[:]).uint(t.Anchor.Epoch).uint(t.Anchor.Slot)
	}
	e.text(t.Author)
	return e.b, nil
}

// CheckSignatureShape accepts a 64-byte signature or a 65-byte one whose recovery byte is 0 or 1. The signer APIs
// hash the preimage internally, so SignBytes/VerifyBytes take PV or PT directly and never a digest of it.
func CheckSignatureShape(sig []byte) error {
	switch {
	case len(sig) == 64:
		return nil
	case len(sig) == 65 && sig[64] <= 1:
		return nil
	}
	return fmt.Errorf("%w: length %d", ErrSignatureShape, len(sig))
}

// Digest is H(preimage), the value a digest-taking signer API receives.
func Digest(preimage []byte) [32]byte { return sha256.Sum256(preimage) }

// ErrBadSignature is matched (errors.Is) by every refusal of a vote, timeout or timeout-certificate signature that does not
// verify, in either scheme. BadSignature adds it to an error without changing the error's text, so the legacy messages stay
// byte-for-byte what they were.
var ErrBadSignature = errors.New("signature does not verify")

type badSignature struct{ err error }

func (e badSignature) Error() string        { return e.err.Error() }
func (e badSignature) Unwrap() error        { return e.err }
func (e badSignature) Is(target error) bool { return target == ErrBadSignature }

// BadSignature marks err as a signature that does not verify.
func BadSignature(err error) error { return badSignature{err} }
