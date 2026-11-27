// Package s1gen is the independent vector generator for the S1 builtin. It
// builds every new byte itself from explicit seeds: its own CBOR writer, its
// own hashing of the signing preimages and real low-s secp256k1 signatures from
// dcrd (RFC 6979, plus explicit-nonce alternates). It imports neither s1ref nor
// the bft-go-base types, so a vector the oracle accepts is two independent
// constructions agreeing.
//
// The one reuse is deliberate: the Q1 vectors file
// (network/protocol/abdrc/testdata/domain_bound_vectors.json) is read as
// published, its wire votes are decoded with the node's own VoteMsg codec and
// re-framed as S1 evidence without re-signing, and every signed byte string the
// file publishes is re-derived here and compared before it is used.
//
// Output is a JSON manifest (Manifest); a generator run is a pure function of
// the seed and the vectors file.
//
// The post-term seal corpus (BuildPostTermCorpus, #1297) is the exception to
// the independence rule, on purpose: it pins what a running root signs, so its
// bytes come from the native paths (votesig, types.UnicitySeal,
// types.RootTrustBaseV2, the in-memory secp256k1 signer, b1state), and its test
// re-derives every byte with this package's CBOR writer and every signature
// verdict with dcrd. The S1 vectors never use those paths.
package s1gen
