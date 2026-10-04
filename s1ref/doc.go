// Package s1ref is the Go reference verifier ("oracle") for the S1 vote-signature
// builtin reserved at 0x0000000000000000000000000000000000000103 (design note
// s1-design.md). It takes the raw builtin input bytes and an explicit,
// injected authenticated Context and returns a Verdict with the malformed-
// versus-false split: a malformed input is an error wrapping ErrMalformed, a
// well-formed but wrong one is a Verdict with Valid=false and a reason that
// wraps ErrInvalid. Only a true verdict carries an Offence, derived after every
// authentication step succeeded.
//
// The relation proves signed statements and their conflict: that one named
// root consensus key signed the real Q1 vote preimage (scheme 1: native
// LedgerCommitInfo.SigBytes; scheme 2: votesig.VotePreimage), with the voting
// epoch and round taken only from the authenticated VoteInfo, and, for a pair,
// that the same key signed two different scheme 2 statements for one slot. It
// does not prove consensus message acceptance, quorum, stake liability,
// evidence timeliness or a slash transaction.
//
// The signing arithmetic is the native code: types.UnicitySeal.SigBytes,
// drctypes.RoundInfo.Hash/IsValid, votesig.Config.VoteInfoHash/VotePreimage and
// the secp256k1 verifier. This package adds the bounded strict CBOR scan, the
// byte contract, the injected-context admission rules and the offence
// derivation. The context is a precondition asserted by the caller, never
// authority established here; a Context built by a test simulates it.
//
// Differences from the b1ref conventions are deliberate and follow the B1 v2
// classification: unsorted, empty or duplicate view members, non-unit weights
// and keys that are not curve points are false, not malformed.
//
// Gas figures are results of the candidate formula, not benchmarked values.
// Nothing here activates a builtin.
package s1ref
