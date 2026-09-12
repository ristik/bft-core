package evmroot

import "crypto/sha256"

// D5 part 1: the slashable vote domain and the VoteInfo -> LedgerCommitInfo
// hash binding.
//
// Normative source: docs/design/d5-accountability-retirement-inbox.md §2,
// docs/pos/specification/appendix-evm.tex §"Evidence". Issue:
// https://github.com/ristik/bft-core/issues/7

// VoteDomainTag is the fixed ASCII domain separator that opens every PoS
// vote-signing preimage. It is part of the signed bytes, not a parameter.
const VoteDomainTag = "UNICITY_POS_VOTE"

// VoteInfo is the consensus round data a validator signs over. For a
// non-committing vote the commit-side fields (see LedgerCommitInfo) may be
// empty, but VoteInfo itself, and therefore the accountable voting epoch
// and round, are always present.
type VoteInfo struct {
	Network       uint64
	MessageDomain string // e.g. "root-vote", "root-timeout" — a signed field, never a builtin argument
	VotingEpoch   uint64
	VotingRound   uint64
	ParentRound   uint64
	ExecStateHash []byte
}

// canonical returns the deterministic CBOR body of a VoteInfo.
func (v VoteInfo) canonical() cArray {
	return cArray{
		cUint(v.Network),
		cText(v.MessageDomain),
		cUint(v.VotingEpoch),
		cUint(v.VotingRound),
		cUint(v.ParentRound),
		optBytes(v.ExecStateHash),
	}
}

// Hash is H(CBOR(VoteInfo)) — the canonical VoteInfo hash that
// LedgerCommitInfo binds.
func (v VoteInfo) Hash() Hash32 { return sha256.Sum256(marshalCBOR(v.canonical())) }

// LedgerCommitInfo is the commit-side statement. VoteInfoHash MUST equal
// VoteInfo.Hash(); CommitStateHash/CommitRound are empty for a
// non-committing vote.
type LedgerCommitInfo struct {
	VoteInfoHash    []byte
	CommitStateHash []byte // empty for a non-committing vote
	CommitRound     uint64 // 0 for a non-committing vote
}

// BindsVoteInfo reports whether this LedgerCommitInfo correctly binds vi:
// its VoteInfoHash is exactly H(CBOR(vi)). A mismatch means the two halves
// are not one statement and the vote is not accountable through this
// commit info.
func (l LedgerCommitInfo) BindsVoteInfo(vi VoteInfo) bool {
	want := vi.Hash()
	return len(l.VoteInfoHash) == 32 && string(l.VoteInfoHash) == string(want[:])
}

// SigningPreimage is the exact byte string a PoS vote signs. It always
// opens with VoteDomainTag and the network id, then binds the message
// domain and the canonical VoteInfo — even for a non-committing vote. A
// caller-supplied domain argument to a verification builtin is NOT part of
// this preimage and never authenticates anything.
func SigningPreimage(vi VoteInfo, commit LedgerCommitInfo) []byte {
	body := cArray{
		cText(VoteDomainTag),
		cUint(vi.Network),
		cText(vi.MessageDomain),
		cBytes(hashSlice(vi.Hash())),
		optBytes(commit.CommitStateHash),
		cUint(commit.CommitRound),
	}
	return marshalCBOR(body)
}

func hashSlice(h Hash32) []byte { return h[:] }

// VoteStatement is one authenticated vote for conflict analysis: the
// accountable key, the signed preimage, and the metadata extracted from the
// authenticated VoteInfo (never from the seal's older committed round).
type VoteStatement struct {
	AccountableKey string
	Preimage       []byte
	Network        uint64
	MessageDomain  string
	VotingEpoch    uint64
	VotingRound    uint64
	Legacy         bool // a legacy vote uses its explicit legacy rules; never reinterpreted as domain-bound PoS
}

// SlashableConflict reports whether a and b are the objective
// double-signing offense: the same network, message/protocol domain,
// accountable key, voting epoch and voting round, with *different* canonical
// signed vote statements that the root safety rules prohibit signing
// together.
//
// Not this offense: a repeated encoding or duplicate delivery of one
// statement (identical preimage), a different message domain, a different
// voting round, or a legacy vote.
func SlashableConflict(a, b VoteStatement) bool {
	if a.Legacy || b.Legacy {
		return false
	}
	if a.AccountableKey != b.AccountableKey {
		return false
	}
	if a.Network != b.Network || a.MessageDomain != b.MessageDomain {
		return false
	}
	if a.VotingEpoch != b.VotingEpoch || a.VotingRound != b.VotingRound {
		return false
	}
	// Same (key, network, domain, epoch, round): an offense only if the
	// signed statements actually differ. Identical preimage = one vote
	// delivered twice / re-encoded / malleable signature — not two votes.
	return string(a.Preimage) != string(b.Preimage)
}
