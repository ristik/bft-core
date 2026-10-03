// Package b1ref is the Go reference verifier ("oracle") for the B1 certificate
// and inclusion builtins UC_V1, SHARED_SEAL_V1 and RSMT_MEMBER_V1 (design note
// b1-design.md, sections 2 and 4). It takes the raw builtin input bytes and an
// explicit registry context and returns a verdict with the malformed-versus-
// false split: a malformed input is an error wrapping ErrMalformed, a
// well-formed but wrong one is a Verdict with Valid=false and a reason that
// wraps ErrInvalid.
//
// The certificate and tree arithmetic is the native bft-go-base code
// (types.UnicityCertificate.IsValid, ShardTreeCertificate.ComputeCertificateHash,
// UnicityTreeCertificate.EvalAuthPath, UnicitySeal.SigBytes and the secp256k1
// verifier); this package adds only the bounded strict CBOR scan, the byte
// contract, the registry admission rules and the quorum count.
//
// Quorum is derived here, not by the native trust base. The native
// UnicityCertificate.Verify / RootTrustBaseV1.VerifyQuorumSignatures sum the
// valid signatures and ignore invalid or unknown extra ones; B1 rejects them,
// so each signature is checked by a strict per-signer wrapper around the
// native secp256k1 verifier and the threshold is counted afterwards. The
// recovery byte of a 65-byte signature must be 0 or 1: that is B1 profile
// policy, not native behaviour (the native verifier drops the byte unchecked).
//
// Gas figures are results of the candidate formula, not benchmarked values.
// Cases the design leaves ambiguous are listed in OpenItems and their vectors
// are marked provisional.
//
// Nothing here activates a builtin: the layout-3 registry history and the
// transition-v4 projection are out of scope for this package.
package b1ref
